// Package fingerprint implements behavioral honeypot fingerprinting.
// It goes beyond floor detection by testing whether a port responds like a real
// service implementation or like a honeypot emulator.
//
// Core insight: real protocol parsers have their own error dialect.
// A Python-based honeypot serving "SSH" will not respond to SSH commands the
// way OpenSSH does. A portspoof faking Redis will not handle INVALIDCMD the
// way real Redis does. These implementation gaps are the discriminators.
package fingerprint

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const probeTimeout = 4 * time.Second

// HoneypotType classifies the detected honeypot software.
type HoneypotType string

const (
	TypeUnknown   HoneypotType = "UNKNOWN"
	TypeReal      HoneypotType = "REAL"
	TypePortspoof HoneypotType = "PORTSPOOF"
	TypeCowrie    HoneypotType = "COWRIE"       // SSH/Telnet honeypot
	TypeOpenCanary HoneypotType = "OPENCANARY"  // multi-protocol Python honeypot
	TypeHoneyd    HoneypotType = "HONEYD"       // virtual honeypot daemon
	TypeDionaea   HoneypotType = "DIONAEA"      // malware-catching honeypot
	TypeGlastopf  HoneypotType = "GLASTOPF"    // web application honeypot
	TypeGenericPython HoneypotType = "GENERIC_PYTHON" // Python honeypot (unidentified)
)

// Result is the outcome of behavioral fingerprinting on a port.
type Result struct {
	Port        int
	HoneypotType HoneypotType
	Confidence  int    // 0-100
	Evidence    string // what gave it away
	IsHoneypot  bool
}

// HTTP runs behavioral fingerprinting on an HTTP-speaking port.
// It sends language-injection probes, HTTP verb confusion, and
// persistent-connection tests.
func HTTP(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}

	addr := fmt.Sprintf("%s:%d", ip, port)

	// Test 1: HTTP verb confusion.
	// Real servers: 400 Bad Request or 405 Method Not Allowed.
	// Portspoof / simple honeypots: return canned 200 regardless of verb.
	badVerbResp := rawHTTP(addr, "BADVERB / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if badVerbResp != "" {
		code := httpCode(badVerbResp)
		if code == 200 {
			r.HoneypotType = TypePortspoof
			r.Confidence = 80
			r.Evidence = "BADVERB → 200 (catch-all; real servers return 400/405)"
			r.IsHoneypot = true
			return r
		}
	}

	// Test 2: Language-injection probe.
	// Send Java-like syntax in the HTTP request line.
	// Python honeypots may expose SyntaxError or garbled output.
	// Real servers parse at the HTTP protocol layer and return 400.
	javaProbe := "public static void main(String[] args){}\r\n\r\n"
	javaResp := rawTCP(addr, javaProbe)
	if javaResp != "" {
		lower := strings.ToLower(javaResp)
		if strings.Contains(lower, "syntaxerror") ||
			strings.Contains(lower, "traceback") ||
			strings.Contains(lower, "file \"") ||
			strings.Contains(lower, "line 1, in") {
			r.HoneypotType = TypeGenericPython
			r.Confidence = 90
			r.Evidence = "Java-syntax probe triggered Python traceback"
			r.IsHoneypot = true
			return r
		}
	}

	// Test 3: Persistent connection test.
	// Send two HTTP GET requests on one TCP connection.
	// Real HTTP/1.1 servers handle pipelining or at least read the second request.
	// Simple honeypots close the connection after the first response.
	pipedResp := rawTCP(addr,
		"GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: keep-alive\r\n\r\n"+
			"GET /galleria-probe-2 HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if pipedResp != "" {
		// Count HTTP response headers in the reply.
		count := strings.Count(pipedResp, "HTTP/1.")
		if count < 2 {
			// Only one response — may indicate honeypot closing early.
			// Don't flag alone; combine with other signals.
			r.Evidence += " [single-response to pipelined request]"
		}
	}

	// Test 4: Known honeypot signatures in Server header.
	normalResp := rawHTTP(addr, "GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if normalResp != "" {
		checkHTTPSignatures(r, normalResp)
		if r.IsHoneypot {
			return r
		}
	}

	return r
}

// SSH runs behavioral fingerprinting on an SSH-speaking port.
// Differentiates real OpenSSH from Cowrie and other SSH honeypots.
func SSH(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	banner := rawTCPRead(addr)
	if banner == "" {
		return r
	}

	// Cowrie-specific tells in SSH banner.
	// Cowrie typically presents as SSH-2.0-OpenSSH_6.0p1 or SSH-2.0-OpenSSH_5.1p1
	// on ports that would never run those ancient versions on modern infrastructure.
	lbanner := strings.ToLower(banner)
	if strings.Contains(lbanner, "ssh-2.0-openssh_6.0p1") ||
		strings.Contains(lbanner, "ssh-2.0-openssh_5.1p1") ||
		strings.Contains(lbanner, "ssh-2.0-openssh_5.3") {
		r.HoneypotType = TypeCowrie
		r.Confidence = 75
		r.Evidence = fmt.Sprintf("SSH banner matches Cowrie default: %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
		r.IsHoneypot = true
		return r
	}

	// Honeyd SSH emulation produces a specific banner format.
	if strings.Contains(lbanner, "ssh-1.99-openssl") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 70
		r.Evidence = "SSH banner matches Honeyd OpenSSL emulation"
		r.IsHoneypot = true
		return r
	}

	r.HoneypotType = TypeReal
	r.Evidence = strings.TrimSpace(banner[:min(len(banner), 80)])
	return r
}

// Redis runs multi-step behavioral fingerprinting on a Redis-speaking port.
// A real Redis handles PING, INVALIDCMD, and pipelining.
// A honeypot typically only handles the first command.
func Redis(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Step 1: standard PING.
	pingResp, _ := rawTCPExchange(addr, "PING\r\n")
	if pingResp == "" {
		return r
	}
	if !strings.HasPrefix(pingResp, "+PONG") && !strings.HasPrefix(pingResp, "-") {
		// Not Redis protocol at all.
		return r
	}

	// Step 2: send an invalid command. Real Redis returns -ERR unknown command.
	// Honeypot Redis emulators often return +PONG again or nothing.
	badResp, _ := rawTCPExchange(addr, "GALLERIA_INVALID_CMD_9F3A\r\n")
	if badResp == "" {
		// No response to invalid command — honeypot tell.
		r.HoneypotType = TypePortspoof
		r.Confidence = 70
		r.Evidence = "Redis: PING→+PONG but INVALIDCMD returned no response"
		r.IsHoneypot = true
		return r
	}
	if strings.HasPrefix(badResp, "+PONG") {
		// Still returning PONG to invalid input — clear honeypot.
		r.HoneypotType = TypePortspoof
		r.Confidence = 85
		r.Evidence = "Redis: INVALIDCMD → +PONG (should be -ERR)"
		r.IsHoneypot = true
		return r
	}
	if strings.HasPrefix(badResp, "-ERR") || strings.HasPrefix(badResp, "-WRONGTYPE") {
		// Correct Redis error handling.
		r.HoneypotType = TypeReal
		r.Confidence = 90
		r.Evidence = fmt.Sprintf("Redis: INVALIDCMD → %s (correct -ERR dialect)", strings.TrimSpace(badResp[:min(len(badResp), 60)]))
		return r
	}

	return r
}

// Generic runs language-injection and malformed-data probes against any TCP port.
// Returns a result if honeypot behavior is detected.
func Generic(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Send C++ syntax — no real service should echo Python errors.
	cppProbe := "int main() { return 0; }\n"
	resp := rawTCP(addr, cppProbe)
	if resp != "" {
		lower := strings.ToLower(resp)
		if strings.Contains(lower, "syntaxerror") ||
			strings.Contains(lower, "traceback") ||
			strings.Contains(lower, "nameerror") {
			r.HoneypotType = TypeGenericPython
			r.Confidence = 85
			r.Evidence = "C++ syntax probe triggered Python runtime error"
			r.IsHoneypot = true
			return r
		}
		// Dionaea exposes its Python shell on some ports.
		if strings.Contains(lower, "dionaea") || strings.Contains(lower, "dionaea.capture") {
			r.HoneypotType = TypeDionaea
			r.Confidence = 95
			r.Evidence = "Dionaea identifier in response"
			r.IsHoneypot = true
			return r
		}
	}

	return r
}

// known HTTP server signatures for honeypot software.
func checkHTTPSignatures(r *Result, resp string) {
	lower := strings.ToLower(resp)

	// Glastopf web honeypot signature.
	if strings.Contains(lower, "glastopf") {
		r.HoneypotType = TypeGlastopf
		r.Confidence = 95
		r.Evidence = "Glastopf honeypot identifier in HTTP response"
		r.IsHoneypot = true
		return
	}
	// OpenCanary typically exposes itself via specific server headers.
	if strings.Contains(lower, "opencanary") || strings.Contains(lower, "server: apache/2.0.52") {
		r.HoneypotType = TypeOpenCanary
		r.Confidence = 80
		r.Evidence = "OpenCanary signature in HTTP Server header"
		r.IsHoneypot = true
		return
	}
	// Honeyd HTTP emulation — sends specific dates or server strings.
	if strings.Contains(resp, "Server: Microsoft-IIS/5.0") && strings.Contains(resp, "Date:") {
		// Honeyd commonly fakes IIS 5.0 — extremely rare on modern internet.
		r.HoneypotType = TypeHoneyd
		r.Confidence = 65
		r.Evidence = "Honeyd IIS 5.0 emulation signature"
		r.IsHoneypot = true
		return
	}
}

// rawHTTP sends an HTTP request string and returns the response.
func rawHTTP(addr, req string) string {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	conn.Write([]byte(req))
	body, _ := io.ReadAll(io.LimitReader(conn, 8192))
	return string(body)
}

// rawTCP sends a raw payload and returns the response.
func rawTCP(addr, payload string) string {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	conn.Write([]byte(payload))
	body, _ := io.ReadAll(io.LimitReader(conn, 4096))
	return string(body)
}

// rawTCPRead connects and reads the server's greeting (first-speaker protocol).
func rawTCPRead(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	body, _ := io.ReadAll(io.LimitReader(conn, 512))
	return string(body)
}

// rawTCPExchange sends payload and reads response on same connection.
func rawTCPExchange(addr, payload string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	conn.Write([]byte(payload))
	body, err := io.ReadAll(io.LimitReader(conn, 512))
	return string(body), err
}

func httpCode(resp string) int {
	if len(resp) < 12 {
		return 0
	}
	var code int
	fmt.Sscanf(resp[:12], "HTTP/1.%*d %d", &code)
	return code
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
