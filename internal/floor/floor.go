package floor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"time"
)

// decoyPath is a route no real service serves. A real service 404s; a
// catch-all portspoof returns its canned banner with 200 (or uniform code).
const decoyPath = "/galleria-decoy-9f3a2c"

// junkPorts are ports that should never have a real HTTP service. If the host
// SYN-ACKs AND returns an HTTP response here, it is a portspoof.
var junkPorts = []int{7, 13, 19, 37, 79}

// canaryPorts are high ports that should never be open on any real service.
// Portspoof listens on all ports; a real host RSTs these.
var canaryPorts = []int{64998, 64997, 64996}

// Signature is the noise floor of a portspoof host.
type Signature struct {
	Active         bool    // host responds on junk/canary port or cross-port identical
	BodySize       int     // byte size of catch-all response
	HTTPCode       int     // HTTP code of catch-all
	Issuer         string  // TLS issuer common to all ports (if any)
	TimingUniform  bool    // response latencies across ports have stddev < 15ms (portspoof signal)
	TimingStddevMs float64 // measured latency stddev in milliseconds
	HowDetected    string  // which stage triggered: "junk-port", "canary", "decoy-path", "cross-port", "timing", "malformed-verb"
}

// Characterize probes the host to establish its noise floor using five parallel stages.
// Returns a Signature. If Active is false, the host is not a portspoof.
//
// Stages run concurrently; first positive result wins:
//  1. Junk ports (7,13,19,37,79) — SYN-ACK on a port that shouldn't exist = portspoof
//  2. Canary ports (64998-64996) — high ports no real service uses; portspoof listens everywhere
//  3. Decoy path probe — catch-all returns 200 on any path; real services 404
//  4. Cross-port sampling + timing — ≥3 identical responses OR timing stddev <15ms = portspoof
//  5. Malformed HTTP verb — portspoof returns 200; real HTTP returns 400/405/501
func Characterize(ip string, knownPorts []int) *Signature {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	type result struct{ sig *Signature }
	ch := make(chan result, 5)

	// Stage 1: junk port probes (parallel).
	go func() {
		for _, jp := range junkPorts {
			if inList(jp, knownPorts) {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			r := probeHTTPCtx(ctx, ip, jp, "/")
			if r != nil {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer, HowDetected: "junk-port"}}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 2: high-port canary. Real hosts RST; portspoof listens everywhere.
	go func() {
		for _, cp := range canaryPorts {
			if ctx.Err() != nil {
				break
			}
			r := probeHTTPCtx(ctx, ip, cp, "/")
			if r != nil {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer, HowDetected: "canary"}}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 3: decoy path on web ports.
	go func() {
		for _, port := range []int{80, 443, 8080, 8443} {
			if !inList(port, knownPorts) {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			r := probeHTTPCtx(ctx, ip, port, decoyPath)
			if r != nil && r.code == 200 {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer, HowDetected: "decoy-path"}}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 4: cross-port sampling + timing uniformity.
	// Identical response across ≥3 ports = catch-all.
	// Timing stddev < 15ms across ≥5 ports = portspoof (all traffic hits one process).
	go func() {
		sample := samplePorts(knownPorts, 7)
		if len(sample) < 3 {
			ch <- result{nil}
			return
		}
		type portResult struct {
			r       *probeResponse
			latency time.Duration
		}
		results := make([]portResult, len(sample))
		var wg sync.WaitGroup
		for i, port := range sample {
			i, port := i, port
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ctx.Err() != nil {
					return
				}
				t0 := time.Now()
				r := probeHTTPCtx(ctx, ip, port, "/")
				results[i] = portResult{r, time.Since(t0)}
			}()
		}
		wg.Wait()

		var sizes, codes []int
		var latencies []float64
		var lastR *probeResponse
		for _, pr := range results {
			if pr.r == nil {
				continue
			}
			sizes = append(sizes, pr.r.bodySize)
			codes = append(codes, pr.r.code)
			latencies = append(latencies, float64(pr.latency.Milliseconds()))
			lastR = pr.r
		}

		if len(sizes) >= 3 && allSame(sizes) && allSame(codes) {
			ch <- result{&Signature{Active: true, BodySize: lastR.bodySize, HTTPCode: lastR.code, Issuer: lastR.issuer, HowDetected: "cross-port"}}
			return
		}

		// Timing uniformity: portspoof routes all ports through the same listener,
		// producing near-identical latencies. Real multi-service hosts vary widely.
		if len(latencies) >= 5 {
			stddev := stddevFloat(latencies)
			if stddev < 15.0 {
				sig := &Signature{HowDetected: "timing", TimingUniform: true, TimingStddevMs: stddev}
				if lastR != nil {
					sig.Active = true
					sig.BodySize = lastR.bodySize
					sig.HTTPCode = lastR.code
					sig.Issuer = lastR.issuer
				}
				ch <- result{sig}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 5: malformed HTTP verb on first available known port.
	// Real HTTP servers return 400/405/501 for an unknown method.
	// Portspoof returns 200 with its canned banner for any input.
	go func() {
		for _, port := range []int{80, 8080, 443, 8443} {
			if !inList(port, knownPorts) {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			r := probeRawHTTPCtx(ctx, ip, port, "XYZZY-GALLERIA / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
			if r != nil && r.code == 200 {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer, HowDetected: "malformed-verb"}}
				return
			}
			break // only probe first port found
		}
		ch <- result{nil}
	}()

	// Collect: first positive wins; need all five negatives to declare no floor.
	negatives := 0
	for negatives < 5 {
		r := <-ch
		if r.sig != nil {
			return r.sig
		}
		negatives++
	}
	return &Signature{}
}

// IsFloor returns true if the given response matches the noise floor signature.
// A match means: same byte size AND same HTTP code.
// Timing-only floor detections still match by size+code when available,
// otherwise any response is considered floor (uniform timing = all ports are noise).
func (s *Signature) IsFloor(bodySize, httpCode int) bool {
	if !s.Active {
		return false
	}
	if s.HowDetected == "timing" && s.BodySize == 0 && s.HTTPCode == 0 {
		// Timing-only: no reference body — treat everything as floor.
		return true
	}
	return bodySize == s.BodySize && httpCode == s.HTTPCode
}

type probeResponse struct {
	code     int
	bodySize int
	issuer   string
	tlsConn  bool // true if TLS handshake succeeded (even if body empty)
}

// probeRawHTTPCtx sends a fully-formed raw HTTP request string (not a path) to the target port.
// Used for malformed-verb detection where the verb itself is injected.
func probeRawHTTPCtx(ctx context.Context, ip string, port int, rawRequest string) *probeResponse {
	addr := fmt.Sprintf("%s:%d", ip, port)
	timeout := 3 * time.Second

	dialer := &net.Dialer{Timeout: timeout}

	// Try TLS first.
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		conn.Write([]byte(rawRequest))
		body, _ := io.ReadAll(io.LimitReader(conn, 32768))
		r := &probeResponse{bodySize: len(body), code: parseCode(body), tlsConn: true}
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			r.issuer = certs[0].Issuer.CommonName
		}
		return r
	}
	if ctx.Err() != nil {
		return nil
	}
	pconn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer pconn.Close()
	pconn.SetDeadline(time.Now().Add(timeout))
	pconn.Write([]byte(rawRequest))
	body, _ := io.ReadAll(io.LimitReader(pconn, 32768))
	if len(body) == 0 {
		return nil
	}
	return &probeResponse{bodySize: len(body), code: parseCode(body)}
}

func probeHTTPCtx(ctx context.Context, ip string, port int, path string) *probeResponse {
	addr := fmt.Sprintf("%s:%d", ip, port)
	timeout := 3 * time.Second // fast timeout for floor detection

	dialer := &net.Dialer{Timeout: timeout}

	// Try TLS.
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	if err == nil {
		defer conn.Close()
		deadline := time.Now().Add(timeout)
		conn.SetDeadline(deadline)
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, ip)
		conn.Write([]byte(req))
		body, _ := io.ReadAll(io.LimitReader(conn, 32768))
		r := &probeResponse{bodySize: len(body), code: parseCode(body), tlsConn: true}
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			r.issuer = certs[0].Issuer.CommonName
		}
		return r // always return on TLS success, even with 0-byte body
	}

	if ctx.Err() != nil {
		return nil
	}

	// Fall back to plain TCP.
	pconn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil
	}
	defer pconn.Close()
	pconn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, ip)
	pconn.Write([]byte(req))
	body, _ := io.ReadAll(io.LimitReader(pconn, 32768))
	if len(body) == 0 {
		return nil // plain TCP with no response = truly closed/filtered
	}
	return &probeResponse{bodySize: len(body), code: parseCode(body)}
}

func parseCode(body []byte) int {
	if len(body) < 12 {
		return 0
	}
	var code int
	fmt.Sscanf(string(body[:12]), "HTTP/1.%*d %d", &code)
	if code == 0 {
		fmt.Sscanf(string(body[:12]), "HTTP/2 %d", &code)
	}
	return code
}

func inList(val int, list []int) bool {
	for _, v := range list {
		if v == val {
			return true
		}
	}
	return false
}

// samplePorts returns up to n ports from list, spread across the range.
func samplePorts(list []int, n int) []int {
	if len(list) <= n {
		return list
	}
	step := len(list) / n
	out := make([]int, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, list[i*step])
	}
	return out
}

func stddevFloat(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var variance float64
	for _, v := range vals {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(vals))
	return math.Sqrt(variance)
}

func allSame(vals []int) bool {
	if len(vals) == 0 {
		return false
	}
	first := vals[0]
	for _, v := range vals[1:] {
		if v != first {
			return false
		}
	}
	return true
}

