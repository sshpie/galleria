package probe

import (
	"fmt"
	"io"
	"net"
	"crypto/tls"
	"strings"
	"time"
)

const timeout = 7 * time.Second

// Result is the outcome of a protocol-native probe.
type Result struct {
	Port     int
	Path     string
	Code     int
	BodySize int
	Body     string // first 2KB
	Issuer   string
	Open     bool
}

// HTTP sends an HTTP(S) GET to the target port+path and returns the result.
func HTTP(ip string, port int, path string) *Result {
	r := &Result{Port: port, Path: path}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Try TLS.
	cfg := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err == nil {
		defer conn.Close()
		r.Open = true
		conn.SetDeadline(time.Now().Add(timeout))
		certs := conn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			r.Issuer = certs[0].Issuer.CommonName
		}
		writeAndRead(conn, ip, path, r)
		return r
	}

	// Plain TCP.
	pconn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return r
	}
	defer pconn.Close()
	r.Open = true
	pconn.SetDeadline(time.Now().Add(timeout))
	writeAndRead(pconn, ip, path, r)
	return r
}

// Raw sends a raw byte payload to the target port and returns the response.
// Used for binary protocols (Redis PING, Memcached stats, etc).
func Raw(ip string, port int, payload []byte) ([]byte, bool) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	conn.Write(payload)
	buf, _ := io.ReadAll(io.LimitReader(conn, 4096))
	return buf, len(buf) > 0
}

// Redis checks if a real Redis is responding (not a catch-all).
// A real Redis responds to PING with +PONG. A catch-all returns HTTP.
func Redis(ip string, port int) (bool, string) {
	resp, ok := Raw(ip, port, []byte("PING\r\n"))
	if !ok {
		return false, ""
	}
	s := string(resp)
	if strings.HasPrefix(s, "+PONG") {
		return true, "OPEN"
	}
	if strings.HasPrefix(s, "-") && strings.Contains(s, "NOAUTH") {
		return true, "AUTH_REQUIRED"
	}
	return false, ""
}

// Memcached checks for a real Memcached (stats response vs HTTP catch-all).
func Memcached(ip string, port int) bool {
	resp, ok := Raw(ip, port, []byte("stats\r\n"))
	if !ok {
		return false
	}
	return strings.HasPrefix(string(resp), "STAT ")
}

// Ollama checks for a real Ollama instance at /api/tags.
// Real Ollama returns {"models":[...]}. Catch-all returns uniform HTTP.
func Ollama(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/api/tags")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, `"models"`) {
		return true, r.Body
	}
	return false, ""
}

// Qdrant checks for a real Qdrant instance.
func Qdrant(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, "qdrant") && strings.Contains(r.Body, "version") {
		return true, r.Body
	}
	return false, ""
}

// Kokoro checks for a real Kokoro TTS instance.
func Kokoro(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/voices")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, `"voice"`) || strings.Contains(r.Body, `"name"`) {
		return true, r.Body
	}
	return false, ""
}

// Whisper checks for a real Whisper ASR instance.
func Whisper(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, "whisper") || strings.Contains(r.Body, "transcri") {
		return true, r.Body
	}
	return false, ""
}

// Chroma checks for a real ChromaDB instance.
func Chroma(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/api/v1/heartbeat")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, "nanosecond") || strings.Contains(r.Body, "heartbeat") {
		return true, r.Body
	}
	return false, ""
}

// Milvus checks for a real Milvus instance.
func Milvus(ip string, port int) (bool, string) {
	r := HTTP(ip, port, "/v1/vector/collections")
	if !r.Open {
		return false, ""
	}
	if strings.Contains(r.Body, "data") || strings.Contains(r.Body, "collections") {
		return true, r.Body
	}
	return false, ""
}

// Generic probes an arbitrary path and returns the result for corpus marker matching.
func Generic(ip string, port int, path string, markers []string) (bool, string) {
	r := HTTP(ip, port, path)
	if !r.Open {
		return false, ""
	}
	for _, marker := range markers {
		if strings.Contains(strings.ToLower(r.Body), strings.ToLower(marker)) {
			return true, r.Body
		}
	}
	return false, r.Body
}

func writeAndRead(conn net.Conn, ip, path string, r *Result) {
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json, */*\r\nConnection: close\r\n\r\n", path, ip)
	conn.Write([]byte(req))
	body, _ := io.ReadAll(io.LimitReader(conn, 16384))
	r.BodySize = len(body)
	r.Code = parseCode(body)
	if len(body) > 2048 {
		body = body[:2048]
	}
	r.Body = string(body)
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
