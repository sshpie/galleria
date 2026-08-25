package handshake

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

const defaultTimeout = 6 * time.Second

// Result is the outcome of a single TCP+TLS probe.
type Result struct {
	IP       string
	Port     int
	Open     bool
	TLS      bool
	Banner   string
	BodySize int
	HTTPCode int
	Issuer   string
	Subject  string
	Expired  bool
}

// Probe performs a full TCP (+TLS if applicable) handshake and returns the result.
// It sends an HTTP GET probe and reads the response body up to maxRead bytes.
func Probe(ip string, port int, path string) *Result {
	addr := fmt.Sprintf("%s:%d", ip, port)
	r := &Result{IP: ip, Port: port}

	// Try TLS first.
	if tlsResult := probeTLS(addr, path, ip); tlsResult != nil {
		tlsResult.IP = ip
		tlsResult.Port = port
		tlsResult.TLS = true
		return tlsResult
	}

	// Plain TCP.
	conn, err := net.DialTimeout("tcp", addr, defaultTimeout)
	if err != nil {
		return r
	}
	defer conn.Close()
	r.Open = true

	conn.SetDeadline(time.Now().Add(defaultTimeout))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, ip)
	conn.Write([]byte(req))

	body, _ := io.ReadAll(io.LimitReader(conn, 16384))
	r.Banner = string(body[:min(len(body), 500)])
	r.BodySize = len(body)
	r.HTTPCode = parseHTTPCode(body)
	return r
}

func probeTLS(addr, path, ip string) *Result {
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: defaultTimeout}, "tcp", addr, cfg)
	if err != nil {
		return nil
	}
	defer conn.Close()

	r := &Result{Open: true}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		cert := certs[0]
		r.Issuer = cert.Issuer.String()
		r.Subject = cert.Subject.String()
		r.Expired = time.Now().After(cert.NotAfter)
	}

	conn.SetDeadline(time.Now().Add(defaultTimeout))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, ip)
	conn.Write([]byte(req))

	body, _ := io.ReadAll(io.LimitReader(conn, 16384))
	r.Banner = string(body[:min(len(body), 500)])
	r.BodySize = len(body)
	r.HTTPCode = parseHTTPCode(body)
	return r
}

func parseHTTPCode(body []byte) int {
	if len(body) < 12 {
		return 0
	}
	s := string(body[:12])
	var code int
	fmt.Sscanf(s, "HTTP/1.%*d %d", &code)
	if code == 0 {
		fmt.Sscanf(s, "HTTP/2 %d", &code)
	}
	return code
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
