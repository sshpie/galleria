package floor

import (
	"fmt"
	"io"
	"net"
	"time"
	"crypto/tls"
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

// Characterize probes the host to establish its noise floor.
// Returns a Signature. If Active is false, the host is not a portspoof.
//
// Detection order (most reliable first):
//  1. Junk ports (7,13,19,37,79) - if host SYN-ACKs a port that should never exist, it's portspoof
//  2. Decoy path probe - portspoof returns 200 on any path; real services 404
//  3. Cross-port sampling - if ≥3 provided ports return byte-identical responses, it's portspoof
func Characterize(ip string, knownPorts []int) *Signature {
	sig := &Signature{}

	// Step 1: probe junk ports not in the known set.
	for _, jp := range junkPorts {
		if inList(jp, knownPorts) {
			continue
		}
		r := probeHTTP(ip, jp, "/")
		if r != nil {
			sig.Active = true
			sig.BodySize = r.bodySize
			sig.HTTPCode = r.code
			sig.Issuer = r.issuer
			return sig
		}
	}

	// Step 2: decoy path probe on web ports.
	// A real service returns 404; a catch-all returns its canned 200.
	for _, port := range []int{80, 443, 8080, 8443} {
		if !inList(port, knownPorts) {
			continue
		}
		r := probeHTTP(ip, port, decoyPath)
		if r != nil && r.code == 200 {
			sig.Active = true
			sig.BodySize = r.bodySize
			sig.HTTPCode = r.code
			sig.Issuer = r.issuer
			return sig
		}
	}

	// Step 3: cross-port sampling.
	// Sample up to 5 ports from the known list, probe GET /,
	// compare byte sizes. If ≥3 are identical, it's a catch-all.
	sample := samplePorts(knownPorts, 5)
	if len(sample) >= 3 {
		sizes := make([]int, 0, len(sample))
		codes := make([]int, 0, len(sample))
		var lastR *probeResponse
		for _, port := range sample {
			r := probeHTTP(ip, port, "/")
			if r == nil {
				continue
			}
			sizes = append(sizes, r.bodySize)
			codes = append(codes, r.code)
			lastR = r
		}
		if len(sizes) >= 3 && allSame(sizes) && allSame(codes) && sizes[0] > 0 {
			sig.Active = true
			sig.BodySize = lastR.bodySize
			sig.HTTPCode = lastR.code
			sig.Issuer = lastR.issuer
			return sig
		}
	}

	return sig
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
}

func probeHTTP(ip string, port int, path string) *probeResponse {
	addr := fmt.Sprintf("%s:%d", ip, port)
	timeout := 5 * time.Second

	// Try TLS.
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err == nil {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, ip)
		conn.Write([]byte(req))
		body, _ := io.ReadAll(io.LimitReader(conn, 32768))

		r := &probeResponse{bodySize: len(body), code: parseCode(body)}
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			r.issuer = certs[0].Issuer.CommonName
		}
		return r
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
		return nil
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
