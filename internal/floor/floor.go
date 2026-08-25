package floor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
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

// Signature is the noise floor of a portspoof host.
type Signature struct {
	Active    bool   // host responds on junk port
	BodySize  int    // byte size of catch-all response
	HTTPCode  int    // HTTP code of catch-all
	Issuer    string // TLS issuer common to all ports (if any)
}

// Characterize probes the host to establish its noise floor using three parallel stages.
// Returns a Signature. If Active is false, the host is not a portspoof.
//
// Stages run concurrently; first positive result wins:
//  1. Junk ports (7,13,19,37,79) — SYN-ACK on a port that shouldn't exist = portspoof
//  2. Decoy path probe — catch-all returns 200 on any path; real services 404
//  3. Cross-port sampling — ≥3 identical responses (including all-zero TLS) = portspoof
func Characterize(ip string, knownPorts []int) *Signature {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	type result struct{ sig *Signature }
	ch := make(chan result, 3)

	// Stage 1: junk port probes (parallel).
	go func() {
		for _, jp := range junkPorts {
			if inList(jp, knownPorts) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			r := probeHTTPCtx(ctx, ip, jp, "/")
			if r != nil {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer}}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 2: decoy path on web ports.
	go func() {
		for _, port := range []int{80, 443, 8080, 8443} {
			if !inList(port, knownPorts) {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			r := probeHTTPCtx(ctx, ip, port, decoyPath)
			if r != nil && r.code == 200 {
				ch <- result{&Signature{Active: true, BodySize: r.bodySize, HTTPCode: r.code, Issuer: r.issuer}}
				return
			}
		}
		ch <- result{nil}
	}()

	// Stage 3: cross-port sampling.
	// Identical response (any size, including 0 via TLS) across ≥3 ports = catch-all.
	go func() {
		sample := samplePorts(knownPorts, 7)
		if len(sample) < 3 {
			ch <- result{nil}
			return
		}
		type portResult struct{ r *probeResponse }
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
				results[i] = portResult{probeHTTPCtx(ctx, ip, port, "/")}
			}()
		}
		wg.Wait()

		var sizes, codes []int
		var lastR *probeResponse
		for _, pr := range results {
			if pr.r == nil {
				continue
			}
			sizes = append(sizes, pr.r.bodySize)
			codes = append(codes, pr.r.code)
			lastR = pr.r
		}
		// Accept all-zero TLS responses as floor signal (portspoof TLS-only mode).
		if len(sizes) >= 3 && allSame(sizes) && allSame(codes) {
			ch <- result{&Signature{Active: true, BodySize: lastR.bodySize, HTTPCode: lastR.code, Issuer: lastR.issuer}}
			return
		}
		ch <- result{nil}
	}()

	// Collect: first positive wins; need all three negatives to declare no floor.
	negatives := 0
	for negatives < 3 {
		r := <-ch
		if r.sig != nil {
			return r.sig
		}
		negatives++
	}
	return &Signature{}
}

// IsFloor returns true if the given response matches the noise floor signature.
// A match means: same byte size AND same HTTP code. Both must match.
func (s *Signature) IsFloor(bodySize, httpCode int) bool {
	if !s.Active {
		return false
	}
	return bodySize == s.BodySize && httpCode == s.HTTPCode
}

type probeResponse struct {
	code     int
	bodySize int
	issuer   string
	tlsConn  bool // true if TLS handshake succeeded (even if body empty)
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
