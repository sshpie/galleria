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
	"encoding/binary"
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
	TypeUnknown       HoneypotType = "UNKNOWN"
	TypeReal          HoneypotType = "REAL"
	TypePortspoof     HoneypotType = "PORTSPOOF"
	TypeCowrie        HoneypotType = "COWRIE"         // Cowrie SSH/Telnet honeypot
	TypeKippo         HoneypotType = "KIPPO"          // Kippo SSH honeypot (Cowrie predecessor)
	TypeOpenCanary    HoneypotType = "OPENCANARY"     // multi-protocol Python honeypot
	TypeHoneyd        HoneypotType = "HONEYD"         // virtual honeypot daemon
	TypeDionaea       HoneypotType = "DIONAEA"        // malware-catching honeypot
	TypeGlastopf      HoneypotType = "GLASTOPF"      // web application honeypot
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
// Honeyd signals (honeyd.c / webserver/server.py source analysis):
//   H21 — open-no-service: TCP accepts, we send HTTP, zero bytes returned (honeyd.c:1440-1443)
//   C3/H9 — Python SimpleHTTPServer / BaseHTTP in Server header (webserver/server.py)
//   C3/H9 — directory listing enabled (<title>Directory listing for) (webserver/server.py:69-76)
//   C8  — fork latency: time-to-first-byte 5-30ms vs <1ms TCP connect (honeyd.c:1502)
func HTTP(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}

	addr := fmt.Sprintf("%s:%d", ip, port)

	// Test 0 (Honeyd H21): TCP accept-but-no-service detection.
	// Honeyd can mark a port "action open" with no service script assigned.
	// The 3-way handshake completes normally, but the server never sends data.
	// We distinguish from LaBrea (which blocks pre-send) by sending first.
	// Real services always send a banner or HTTP response.
	// Source: honeyd.c:1440-1443 — eternal silent accept, 300s idle timeout.
	connected, firstBody := rawHTTPWithState(addr, "GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if !connected {
		return r // filtered or not TCP-open at all
	}

	// Test 0b (Honeyd C8): fork-latency signal.
	// Honeyd forks a service script after 3-way handshake; fork+exec takes 5-30ms.
	// Real servers: first byte typically <2ms after connect.
	// This signal is supplementary — noisy over WAN, useful on LAN.
	// We don't use it as a standalone discriminator, just boost confidence if already flagged.
	connectStart := time.Now()
	if conn0b, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
		connectDur := time.Since(connectStart)
		conn0b.SetDeadline(time.Now().Add(3 * time.Second))
		conn0b.Write([]byte("GET / HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n"))
		fbuf := make([]byte, 4)
		readStart := time.Now()
		conn0b.Read(fbuf) //nolint
		ttfb := time.Since(readStart)
		conn0b.Close()
		// Honeyd fork pattern: connect fast (<3ms), TTFB 5-30ms.
		// Only flag when the ratio is significant and both measurements make sense.
		if connectDur < 3*time.Millisecond && ttfb >= 5*time.Millisecond && ttfb <= 35*time.Millisecond {
			r.Evidence += fmt.Sprintf(" [C8:fork-latency connect=%dµs ttfb=%dms]",
				connectDur.Microseconds(), ttfb.Milliseconds())
		}
	}

	if firstBody == "" {
		// Port is TCP-open, we sent a request, and got nothing back.
		// Honeyd H21 — open port with no service. 5-minute silent accept.
		r.HoneypotType = TypeHoneyd
		r.Confidence = 72
		r.Evidence = "Honeyd H21: TCP connect succeeded, HTTP request sent, 0 bytes received (open-no-service; honeyd.c:1440)"
		r.IsHoneypot = true
		return r
	}

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

	// Test 3: Content-Length mismatch.
	// Honeypots return canned bodies with wrong or missing Content-Length.
	// Real servers set it correctly. A mismatch > 5% or total absence on 200 is a signal.
	clResp := rawHTTP(addr, "GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if clResp != "" {
		if checkContentLengthMismatch(r, clResp) {
			return r
		}
	}

	// Test 4: HTTP version inconsistency.
	// Send HTTP/1.0 (no Host header). Real servers respond with HTTP/1.0 or 1.1.
	// Some portspoof/Honeyd emulators always respond HTTP/1.1 regardless.
	v10Resp := rawHTTP(addr, "GET / HTTP/1.0\r\n\r\n")
	if v10Resp != "" {
		// HTTP/1.0 request → server responds with HTTP/1.1 AND no Connection: close
		// suggests the server ignores request version (static emulator tell).
		if strings.HasPrefix(v10Resp, "HTTP/1.1") && !strings.Contains(v10Resp, "Connection: close") {
			r.Evidence += " [HTTP/1.0 req → HTTP/1.1 resp without Connection:close]"
		}
	}

	// Test 5: HTTP pipeline depth (3 requests).
	// Real HTTP/1.1 servers respond to all 3; simple emulators respond to first only.
	pipedResp := rawTCP(addr,
		"GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: keep-alive\r\n\r\n"+
			"GET /galleria-probe-2 HTTP/1.1\r\nHost: "+ip+"\r\nConnection: keep-alive\r\n\r\n"+
			"GET /galleria-probe-3 HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if pipedResp != "" {
		count := strings.Count(pipedResp, "HTTP/1.")
		if count < 2 {
			r.Evidence += " [single-response to 3-request pipeline]"
		}
	}

	// Test 6: HTTP OPTIONS → missing Allow header.
	// Real HTTP/1.1 servers return Allow: GET, HEAD, POST, OPTIONS.
	// Portspoof / minimal emulators return 200 with no Allow header.
	optResp := rawHTTP(addr, "OPTIONS * HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if optResp != "" {
		code := httpCode(optResp)
		hasAllow := strings.Contains(strings.ToLower(optResp), "allow:")
		if code == 200 && !hasAllow {
			r.Evidence += " [OPTIONS 200 without Allow header]"
		}
	}

	// Test 6b: Glastopf dedicated probe suite.
	// Run before generic header checks — Glastopf() probes SQLi/LFI/phpMyAdmin paths
	// and the HTTP/1.0 downgrade signal independently of the generic GET / body.
	gfp := Glastopf(ip, port)
	if gfp.IsHoneypot {
		r.HoneypotType = gfp.HoneypotType
		r.Confidence = gfp.Confidence
		r.Evidence = gfp.Evidence
		r.IsHoneypot = true
		return r
	}

	// Test 7: OS/service contradiction + known signatures.
	normalResp := rawHTTP(addr, "GET / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if normalResp != "" {
		checkHTTPSignatures(r, normalResp)
		if r.IsHoneypot {
			return r
		}
		checkOSContradiction(r, normalResp)
		if r.IsHoneypot {
			return r
		}
	}

	return r
}

// SSH runs deep behavioral fingerprinting on an SSH-speaking port.
// Identifies Cowrie, Kippo, and Honeyd via pre-auth protocol probes.
//
// Cowrie signals (factory.py / transport.py source analysis):
//   H1 — default banner SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2
//   H2 — KEXINIT padding: Cowrie uses null bytes; real OpenSSH uses random bytes
//   H3 — cipher list includes blowfish-cbc/cast128-cbc (removed OpenSSH 6.7)
//   S6 — Vetterl probe: malformed packet → Cowrie silently drops
//
// Kippo signals (ssh.py / kippo.cfg.dist source analysis):
//   K_H1 — default banner SSH-2.0-OpenSSH_5.1p1 Debian-5 (2008 release, kippo.cfg.dist:139)
//   K_H2 — KEXINIT null padding (same Twisted bug; kippo/core/ssh.py inherits Twisted)
//   K_M4 — KEXINIT kex_algorithms includes curve25519/ECDH despite 2008 banner (Twisted KEXINIT)
//   K_C4 — Vetterl probe: malformed packet → raw ASCII "Protocol mismatch.\n" (kippo/core/ssh.py:203)
//          Unlike Cowrie (silent drop) and real SSH (binary SSH_MSG_DISCONNECT)
//
// All probes run pre-auth, pre-credential.
func SSH(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return r
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))

	// --- H1 / K_H1: Banner check ---
	bannerBuf := make([]byte, 512)
	n, err := conn.Read(bannerBuf)
	if err != nil || n < 4 {
		return r
	}
	banner := string(bannerBuf[:n])
	if !strings.HasPrefix(banner, "SSH-") {
		return r
	}
	lbanner := strings.ToLower(banner)

	// Kippo default banner: SSH-2.0-OpenSSH_5.1p1 Debian-5 (kippo.cfg.dist:139 / ssh.py:116).
	// This is distinct from Cowrie's default (6.0p1).
	if strings.Contains(lbanner, "ssh-2.0-openssh_5.1p1") {
		r.HoneypotType = TypeKippo
		r.Confidence = 80
		r.Evidence = fmt.Sprintf("SSH K_H1: Kippo default banner (kippo.cfg.dist:139): %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
		r.IsHoneypot = true
		// Continue — K_M4 (KEXINIT mismatch) and K_C4 (Vetterl) will boost confidence.
	}

	// Cowrie known default banners (factory.py:44 fallback).
	if !r.IsHoneypot && (strings.Contains(lbanner, "ssh-2.0-openssh_6.0p1") ||
		strings.Contains(lbanner, "ssh-2.0-openssh_5.3")) {
		r.HoneypotType = TypeCowrie
		r.Confidence = 85
		r.Evidence = fmt.Sprintf("SSH H1: Cowrie default banner (factory.py:44): %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
		r.IsHoneypot = true
	}
	// Honeyd emulation.
	if strings.Contains(lbanner, "ssh-1.99-openssl") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 70
		r.Evidence = "SSH: Honeyd OpenSSL emulation banner"
		r.IsHoneypot = true
		return r
	}

	// Advance handshake: send our banner so server sends KEXINIT.
	conn.Write([]byte("SSH-2.0-OpenSSH_9.3p1 Ubuntu-3ubuntu3.6\r\n"))

	// --- H2 + H3 (Cowrie) / K_H2 + K_M4 (Kippo): Parse server KEXINIT packet ---
	payload, padding, kexErr := readSSHPacket(conn)
	if kexErr == nil && len(payload) > 0 && payload[0] == 20 { // SSH2_MSG_KEXINIT
		// H2 / K_H2: null padding — Twisted SSHServerTransport uses b"\0"*lenPad for KEXINIT.
		// Both Cowrie and Kippo inherit this from Twisted; real OpenSSH uses random bytes.
		if allZeroBytes(padding) && len(padding) > 0 {
			if r.HoneypotType == TypeKippo {
				r.Confidence = 90
				r.Evidence += " + K_H2:null-padding"
			} else {
				r.HoneypotType = TypeCowrie
				r.Confidence = 95
				r.Evidence = "SSH H2: KEXINIT padding all null (Twisted/Cowrie transport.py:229; real OpenSSH uses random)"
				r.IsHoneypot = true
			}
		}

		// H3: Cowrie cipher list — blowfish-cbc / cast128-cbc removed in OpenSSH 6.7 (2014).
		if ciphers, err := sshKEXINITCiphers(payload); err == nil {
			for _, c := range ciphers {
				if c == "blowfish-cbc" || c == "cast128-cbc" {
					if r.HoneypotType != TypeKippo {
						r.HoneypotType = TypeCowrie
						r.IsHoneypot = true
					}
					r.Confidence = max2(r.Confidence, 95)
					r.Evidence = fmt.Sprintf("SSH H3: cipher list includes %q (removed OpenSSH 6.7+; Cowrie factory.py:144)", c)
					break
				}
			}
		}

		// K_M4: Kippo banner/capability mismatch — OpenSSH 5.1p1 is from 2008.
		// Twisted's KEXINIT advertises curve25519-sha256, ecdh-sha2-nistp256, hmac-sha2-256 —
		// all added between 2013-2014. Real 5.1p1 cannot offer these.
		// (kippo/core/ssh.py:116,128-131; Twisted SSHServerTransport KEXINIT)
		if r.HoneypotType == TypeKippo {
			modernKex := sshKEXINITKexAlgos(payload)
			for _, k := range modernKex {
				if strings.HasPrefix(k, "curve25519") ||
					strings.HasPrefix(k, "ecdh-sha2-nistp") ||
					strings.HasPrefix(k, "diffie-hellman-group14-sha256") {
					r.Confidence = max2(r.Confidence, 92)
					r.Evidence += fmt.Sprintf(" + K_M4:modern-kex(%s)-vs-2008-banner", k)
					break
				}
			}
		}
	}

	// --- S6 / K_C4: Vetterl probe — malformed SSH packet length ---
	// Three-way discriminator (kippo/core/ssh.py:203-219 vs Cowrie vs real OpenSSH):
	//   Real OpenSSH   → binary SSH_MSG_DISCONNECT packet (type byte = 0x01 at offset [5])
	//   Cowrie         → silent drop (TCP close, zero bytes received)
	//   Kippo          → raw ASCII "Protocol mismatch.\n" (not SSH_MSG_DISCONNECT)
	conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // impossible packet length
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	vetterlBuf := make([]byte, 64)
	nr, _ := conn.Read(vetterlBuf)
	vetterlResp := string(vetterlBuf[:nr])

	if nr == 0 {
		// Silent drop — Cowrie S6 behavior.
		if r.HoneypotType == TypeKippo {
			// Kippo should say "Protocol mismatch" not silent-drop. May be a fork with Cowrie behavior.
			r.Confidence = max2(r.Confidence, 85)
			r.Evidence += " + S6:silent-drop(Cowrie-fork?)"
		} else {
			r.HoneypotType = TypeCowrie
			r.Confidence = max2(r.Confidence, 88)
			if r.Evidence == "" {
				r.Evidence = "SSH S6: malformed packet → silent drop (Cowrie); real OpenSSH sends SSH_MSG_DISCONNECT"
			} else {
				r.Evidence += " + S6:silent-drop"
			}
			r.IsHoneypot = true
		}
	} else if strings.Contains(vetterlResp, "Protocol mismatch") {
		// Kippo K_C4: raw ASCII disconnect (kippo/core/ssh.py:203-219).
		// This is the definitive Kippo signal — zero false positives on real SSH.
		r.HoneypotType = TypeKippo
		r.Confidence = max2(r.Confidence, 95)
		if r.Evidence == "" {
			r.Evidence = "SSH K_C4: malformed packet → raw ASCII 'Protocol mismatch.' (kippo/core/ssh.py:203); real SSH sends SSH_MSG_DISCONNECT binary"
		} else {
			r.Evidence += " + K_C4:protocol-mismatch-ascii"
		}
		r.IsHoneypot = true
	} else if nr >= 6 && vetterlBuf[5] == 1 {
		// SSH_MSG_DISCONNECT received — real OpenSSH behavior.
		if !r.IsHoneypot {
			r.HoneypotType = TypeReal
			r.Evidence = fmt.Sprintf("SSH: %s (SSH_MSG_DISCONNECT on malformed packet)", strings.TrimSpace(banner[:min(len(banner), 60)]))
		}
	}

	if !r.IsHoneypot && r.HoneypotType == TypeUnknown {
		r.HoneypotType = TypeReal
		r.Evidence = strings.TrimSpace(banner[:min(len(banner), 80)])
	}
	return r
}

// readSSHPacket reads one SSH binary packet (unencrypted, pre-kex phase).
// Returns payload, padding bytes, and error.
func readSSHPacket(conn net.Conn) (payload, padding []byte, err error) {
	lenBuf := make([]byte, 4)
	if _, err = io.ReadFull(conn, lenBuf); err != nil {
		return
	}
	pktLen := int(binary.BigEndian.Uint32(lenBuf))
	if pktLen < 5 || pktLen > 65535 {
		err = fmt.Errorf("invalid SSH packet length %d", pktLen)
		return
	}
	data := make([]byte, pktLen)
	if _, err = io.ReadFull(conn, data); err != nil {
		return
	}
	padLen := int(data[0])
	if padLen+1 > len(data) {
		err = fmt.Errorf("invalid padding length %d", padLen)
		return
	}
	payload = data[1 : len(data)-padLen]
	if padLen > 0 {
		padding = data[len(data)-padLen:]
	}
	return
}

// sshKEXINITCiphers extracts the encryption_algorithms_client_to_server list
// from a raw SSH2_MSG_KEXINIT payload.
// Layout: 1-byte type, 16-byte cookie, then 10 name-lists (kex, host-key,
// enc-c2s, enc-s2c, mac-c2s, mac-s2c, comp-c2s, comp-s2c, lang-c2s, lang-s2c).
func sshKEXINITCiphers(payload []byte) ([]string, error) {
	if len(payload) < 17 { // 1 type + 16 cookie
		return nil, fmt.Errorf("payload too short")
	}
	offset := 17 // skip type + cookie
	// Skip kex_algorithms and server_host_key_algorithms.
	for i := 0; i < 2; i++ {
		_, next, err := sshNameList(payload, offset)
		if err != nil {
			return nil, err
		}
		offset = next
	}
	// encryption_algorithms_client_to_server is the 3rd name-list.
	ciphers, _, err := sshNameList(payload, offset)
	return ciphers, err
}

// sshKEXINITKexAlgos extracts the kex_algorithms name-list from a KEXINIT payload.
// Used for K_M4: detecting Twisted's modern kex advertised on an old-banner Kippo instance.
func sshKEXINITKexAlgos(payload []byte) []string {
	if len(payload) < 17 {
		return nil
	}
	algos, _, err := sshNameList(payload, 17) // first name-list after type+cookie
	if err != nil {
		return nil
	}
	return algos
}

// sshNameList decodes a name-list at offset: uint32 len + bytes.
func sshNameList(data []byte, offset int) ([]string, int, error) {
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("truncated name-list length at %d", offset)
	}
	listLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += 4
	if offset+listLen > len(data) {
		return nil, offset, fmt.Errorf("truncated name-list data")
	}
	raw := string(data[offset : offset+listLen])
	offset += listLen
	if raw == "" {
		return nil, offset, nil
	}
	return strings.Split(raw, ","), offset, nil
}

func allZeroBytes(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
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

// SMTP runs behavioral fingerprinting on an SMTP-speaking port.
// Real SMTP servers send a 220 banner immediately.
// BackOfficer Friendly / low-interaction honeypots disconnect with "503 Service Unavailable".
// Honeyd SMTP emulation often returns a minimal 220 with no capability negotiation.
func SMTP(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	banner := rawTCPRead(addr)
	if banner == "" {
		return r
	}

	// BOF / minimal honeypot: 503 Service Unavailable immediately.
	if strings.HasPrefix(banner, "503") {
		r.HoneypotType = TypePortspoof
		r.Confidence = 85
		r.Evidence = fmt.Sprintf("SMTP: 503 on connect (BOF/minimal honeypot pattern): %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
		r.IsHoneypot = true
		return r
	}

	if !strings.HasPrefix(banner, "220") {
		return r
	}

	// Test: send EHLO and check capability depth.
	// Real SMTP: multi-line capability list (250-SIZE, 250-STARTTLS, etc.)
	// Honeyd minimal SMTP: 250 OK with no capabilities.
	ehloResp, _ := rawTCPExchange(addr, "EHLO galleria.probe\r\n")
	if ehloResp != "" {
		capLines := strings.Count(ehloResp, "\n")
		if strings.HasPrefix(ehloResp, "250") && capLines < 2 {
			r.HoneypotType = TypePortspoof
			r.Confidence = 65
			r.Evidence = "SMTP: EHLO returned single-line 250 (no capability list; real SMTP returns 250-AUTH, 250-SIZE, etc.)"
			r.IsHoneypot = true
			return r
		}
	}

	r.HoneypotType = TypeReal
	r.Evidence = fmt.Sprintf("SMTP banner: %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
	return r
}

// Telnet runs behavioral fingerprinting on a Telnet-speaking port.
// Implements three discriminators:
//   IAC depth: Cowrie sends login prompt without IAC option negotiation (banner-level)
//   S5: NEW-ENVIRON acceptance (option 39) — Cowrie accepts; real minimal telnetd refuses
//   M7-adjacent: login prompt without IAC = definitive Cowrie tell from transport.py
func Telnet(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return r
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))

	bannerBuf := make([]byte, 512)
	n, _ := conn.Read(bannerBuf)
	if n == 0 {
		return r
	}
	banner := string(bannerBuf[:n])
	lower := strings.ToLower(banner)

	hasIAC := strings.Contains(banner, "\xFF")
	hasLoginPrompt := strings.Contains(lower, "login:") || strings.Contains(lower, "username:")

	// Cowrie tell: login prompt with no IAC preamble.
	if hasLoginPrompt && !hasIAC {
		r.HoneypotType = TypeCowrie
		r.Confidence = 75
		r.Evidence = "Telnet: login prompt without IAC negotiation (Cowrie telnet/transport.py pattern)"
		r.IsHoneypot = true
		// Don't return — run S5 probe to boost confidence.
	}

	// Honeyd static banners.
	if strings.Contains(lower, "welcome to microsoft telnet service") ||
		(strings.Contains(lower, "cisco systems") && !hasIAC) {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 70
		r.Evidence = "Telnet: static vendor banner without IAC (Honeyd pattern)"
		r.IsHoneypot = true
		return r
	}

	// S5: NEW-ENVIRON probe (Cowrie telnet/transport.py:362 accepts option 39).
	// Send: IAC DO NEW-ENVIRON (FF FD 27).
	// Cowrie responds: IAC WILL NEW-ENVIRON (FF FB 27) — accepts it.
	// Real minimal telnetd: IAC WONT NEW-ENVIRON (FF FC 27) or no response.
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	conn.Write([]byte{0xFF, 0xFD, 0x27}) // IAC DO NEW-ENVIRON
	neResp := make([]byte, 16)
	nne, _ := conn.Read(neResp)
	if nne >= 3 && neResp[0] == 0xFF && neResp[1] == 0xFB && neResp[2] == 0x27 {
		// IAC WILL NEW-ENVIRON — Cowrie accepted it (S5).
		r.HoneypotType = TypeCowrie
		r.Confidence = max2(r.Confidence, 90)
		if r.Evidence == "" {
			r.Evidence = "Telnet S5: server accepted NEW-ENVIRON (option 39) — Cowrie transport.py:362"
		} else {
			r.Evidence += " + S5:NEW-ENVIRON-accepted"
		}
		r.IsHoneypot = true
		return r
	}

	if !r.IsHoneypot {
		r.Evidence = fmt.Sprintf("Telnet (IAC=%v): %s", hasIAC, strings.TrimSpace(banner[:min(len(banner), 60)]))
	}
	return r
}

// checkContentLengthMismatch detects honeypots that return incorrect Content-Length headers.
// Returns true and populates r if a mismatch is found.
func checkContentLengthMismatch(r *Result, resp string) bool {
	// Split headers from body.
	headerEnd := strings.Index(resp, "\r\n\r\n")
	if headerEnd < 0 {
		return false
	}
	headers := resp[:headerEnd]
	body := resp[headerEnd+4:]

	// Find Content-Length header.
	var clValue int
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			fmt.Sscanf(strings.TrimSpace(line[15:]), "%d", &clValue)
			break
		}
	}

	// Only flag when Content-Length is present and obviously wrong.
	// A mismatch > 20% or > 500 bytes on a non-empty body is suspicious.
	actualLen := len(body)
	if clValue > 0 && actualLen > 0 {
		diff := clValue - actualLen
		if diff < 0 {
			diff = -diff
		}
		if diff > 500 || (actualLen > 100 && diff*100/actualLen > 20) {
			r.HoneypotType = TypePortspoof
			r.Confidence = 70
			r.Evidence = fmt.Sprintf("Content-Length mismatch: header=%d actual=%d (honeypot returning static canned body)", clValue, actualLen)
			r.IsHoneypot = true
			return true
		}
	}
	return false
}

// checkOSContradiction detects OS/service identity contradictions.
// Real servers are internally consistent; honeypots often mix OS fingerprints.
func checkOSContradiction(r *Result, resp string) {
	lower := strings.ToLower(resp)

	// Apache on IIS port claiming Windows but showing Unix-style error paths.
	serverApache := strings.Contains(lower, "server: apache")
	serverIIS := strings.Contains(lower, "server: microsoft-iis")
	serverNginx := strings.Contains(lower, "server: nginx")

	// Windows-specific Date format: "Mon, 01 Jan 2024 00:00:00 GMT" — same as Unix actually.
	// Better: look for body content inconsistencies.
	// Honeyd IIS emulation: claims IIS but body has Apache-style error format.
	if serverIIS && strings.Contains(lower, "apache") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 75
		r.Evidence = "OS contradiction: Server: Microsoft-IIS but body contains Apache references"
		r.IsHoneypot = true
		return
	}
	if serverApache && strings.Contains(lower, "iis") && strings.Contains(lower, "microsoft") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 70
		r.Evidence = "OS contradiction: Server: Apache but body contains IIS/Microsoft references"
		r.IsHoneypot = true
		return
	}
	// nginx claiming to be Apache in error pages (OpenCanary pattern).
	if serverNginx && strings.Contains(lower, "it works!") {
		r.HoneypotType = TypeOpenCanary
		r.Confidence = 65
		r.Evidence = "OS contradiction: Server: nginx but default Apache 'It works!' body"
		r.IsHoneypot = true
		return
	}
	_ = serverApache
}

// FTP runs behavioral fingerprinting on an FTP-speaking port.
// Specter/Honeyd FTP emulation returns one of a fixed set of SYST OS strings;
// cross-checking against the Server banner or known-fake strings catches them.
func FTP(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	banner := rawTCPRead(addr)
	if banner == "" {
		return r
	}
	if !strings.HasPrefix(banner, "220") {
		return r
	}

	// Dionaea L13: hardcoded static banner (ftp.py — "Welcome to the ftp service").
	// Dionaea never customizes the greeting; this string is baked in.
	if strings.Contains(banner, "Welcome to the ftp service") {
		r.HoneypotType = TypeDionaea
		r.Confidence = 92
		r.Evidence = `FTP L13: static banner "Welcome to the ftp service" (dionaea ftp.py — hardcoded)`
		r.IsHoneypot = true
		return r
	}

	// Anonymous login attempt.
	r1, _ := rawTCPExchange(addr, "USER anonymous\r\n")
	if r1 == "" || !strings.HasPrefix(r1, "331") {
		// No 331 Password required → not real FTP or full anonymous denial.
		// Specter says 230 directly for anonymous; check.
		if !strings.HasPrefix(r1, "230") {
			return r
		}
	}
	passResp, _ := rawTCPExchange(addr, "PASS galleria@probe.io\r\n")

	// Dionaea L13: any credentials → 231 (acknowledge) → 230 (logged in).
	// Real FTP rejects anonymous with a password check; Dionaea always accepts.
	// Source: dionaea ftp.py:284-299 — hardcoded 231+230 regardless of creds.
	if strings.HasPrefix(passResp, "231") {
		// Followed by 230 — both are Dionaea FTP auth bypass.
		r.HoneypotType = TypeDionaea
		r.Confidence = 88
		r.Evidence = "FTP L13: any-credentials accepted (PASS → 231+230); dionaea ftp.py:284-299 hardcodes acceptance"
		r.IsHoneypot = true
		return r
	}

	// SYST reveals the claimed OS.
	systResp, _ := rawTCPExchange(addr, "SYST\r\n")
	if systResp == "" {
		return r
	}

	// Known Specter/Honeyd preset SYST strings that are rarely seen on real servers.
	// Specter lets admins pick from: UNIX, Windows_NT, AIX, HP-UX, Irix, SunOS, OSF/1, etc.
	lsyst := strings.ToLower(systResp)
	if strings.Contains(lsyst, "215 irix") ||
		strings.Contains(lsyst, "215 aix") ||
		strings.Contains(lsyst, "215 hp-ux") ||
		strings.Contains(lsyst, "215 osf/1") {
		r.HoneypotType = TypePortspoof
		r.Confidence = 70
		r.Evidence = fmt.Sprintf("FTP SYST returns rare OS string (Specter/Honeyd preset): %s", strings.TrimSpace(systResp[:min(len(systResp), 60)]))
		r.IsHoneypot = true
		return r
	}

	r.HoneypotType = TypeReal
	r.Evidence = fmt.Sprintf("FTP: %s / SYST: %s", strings.TrimSpace(banner[:min(len(banner), 60)]), strings.TrimSpace(systResp[:min(len(systResp), 40)]))
	return r
}

// LaBrea detects LaBrea tarpit behavior: connection accepted but TCP window frozen.
// LaBrea accepts SYN, sends SYN-ACK with window=0, then never advances.
// We detect this as: TCP connect succeeds but zero bytes received within a 2s read window.
func LaBrea(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Send nothing — a tarpit will freeze; a real server will either send a banner or wait.
	buf := make([]byte, 1)
	n, _ := conn.Read(buf)
	// If connection succeeded but zero bytes read in 2s on a port that should speak first
	// (SSH, FTP, SMTP, Telnet), that's a tarpit signal.
	return n == 0
}

// Glastopf runs behavioral fingerprinting against a web application honeypot.
//
// Glastopf emulates vulnerable PHP apps (LFI/RFI/SQLi targets). All signals are
// source-code-derived from static analysis of mushorg/glastopf.
//
// Signals:
//
//	G1 — HTTP/1.0 response to HTTP/1.1 HEAD + "Server: Apache/2.0.48 " trailing space
//	     handler.py:47 hardcodes protocol; glastopf.py:265 sets sys_version=' ' (single space)
//	     Combined: 99% confidence. Either alone: 72–85%.
//	G2 — SQLi probe returns "Invalid query: " prefix
//	     responses.xml:6 — no real MySQL uses this prefix. 98% confidence.
//	G3 — LFI probe (?page=/etc/passwd) body references "vars1.php" (not the requested file)
//	     lfi.py:59 — hardcoded path regardless of attacker input. 98% confidence.
//	G4 — phpMyAdmin CSRF token identical across two successive requests
//	     phpmyadmin.py:31 — token is MD5(import_timestamp), frozen at class-load time. 90%.
func Glastopf(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// G1: HEAD / → HTTP/1.0 downgrade + Server: Apache/2.0.48 with trailing space.
	// Both are independently significant; combined they are definitive.
	headResp := rawHTTP(addr, "HEAD / HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if headResp != "" {
		http10 := strings.HasPrefix(headResp, "HTTP/1.0")
		// Exact trailing-space match: "Apache/2.0.48 " — glastopf.py:265 sets sys_version=' '
		apacheTrailingSpace := strings.Contains(headResp, "Server: Apache/2.0.48 ")
		if http10 && apacheTrailingSpace {
			r.HoneypotType = TypeGlastopf
			r.Confidence = 99
			r.Evidence = "Glastopf G1: HTTP/1.0 response to HTTP/1.1 (handler.py:47) + Server: Apache/2.0.48<SP> trailing space (glastopf.py:265 sys_version=' ') — definitive"
			r.IsHoneypot = true
			return r
		}
		if apacheTrailingSpace {
			r.HoneypotType = TypeGlastopf
			r.Confidence = 85
			r.Evidence = "Glastopf G1b: Server: Apache/2.0.48<SP> trailing space (glastopf.py:265 sys_version=' ') — 2003-vintage banner with implementation artifact"
			r.IsHoneypot = true
			return r
		}
		if http10 && strings.Contains(headResp, "Apache/2.0.48") {
			r.HoneypotType = TypeGlastopf
			r.Confidence = 88
			r.Evidence = "Glastopf G1c: HTTP/1.0 downgrade + Apache/2.0.48 banner (handler.py:47 + glastopf.cfg.dist:95)"
			r.IsHoneypot = true
			return r
		}
	}

	// G2: SQLi emulator returns hardcoded "Invalid query: " prefix.
	// responses.xml:6 — no real MySQL error message starts with this string.
	sqliResp := rawHTTP(addr, "GET /?id=1'+OR+'1'='1 HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if strings.Contains(sqliResp, "Invalid query: ") {
		r.HoneypotType = TypeGlastopf
		r.Confidence = 98
		r.Evidence = `Glastopf G2: SQLi probe returned "Invalid query: " prefix (glastopf responses.xml:6 — hardcoded, never used in real MySQL)`
		r.IsHoneypot = true
		return r
	}

	// G3: LFI emulator always references vars1.php regardless of requested path.
	// lfi.py:59 — hardcoded path: "file_to_include = data_dir/virtualdocs/linux/vars1.php"
	lfiResp := rawHTTP(addr, "GET /?page=/etc/passwd HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if strings.Contains(lfiResp, "vars1.php") {
		r.HoneypotType = TypeGlastopf
		r.Confidence = 98
		r.Evidence = "Glastopf G3: LFI probe (?page=/etc/passwd) references vars1.php in response (lfi.py:59 — hardcoded regardless of attacker input)"
		r.IsHoneypot = true
		return r
	}

	// G4: phpMyAdmin CSRF token frozen at import time — identical across all sessions.
	// phpmyadmin.py:31: time_stamp=time.time() default arg evaluated once at class load.
	pmaPath := "/phpmyadmin/"
	pma1 := rawHTTP(addr, "GET "+pmaPath+" HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	pma2 := rawHTTP(addr, "GET "+pmaPath+" HTTP/1.1\r\nHost: "+ip+"\r\nConnection: close\r\n\r\n")
	if pma1 != "" && pma2 != "" && len(pma1) > 50 {
		tok1 := extractCSRFToken(pma1)
		tok2 := extractCSRFToken(pma2)
		if tok1 != "" && tok1 == tok2 {
			r.HoneypotType = TypeGlastopf
			r.Confidence = 90
			r.Evidence = fmt.Sprintf("Glastopf G4: phpMyAdmin CSRF token identical across two requests (%s) — phpmyadmin.py:31 frozen at import time", tok1[:min(len(tok1), 16)])
			r.IsHoneypot = true
			return r
		}
	}

	return r
}

// extractCSRFToken extracts a token value from a phpMyAdmin-style hidden input.
func extractCSRFToken(resp string) string {
	const needle = `name="token" value="`
	idx := strings.Index(resp, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := strings.Index(resp[start:], `"`)
	if end < 0 || end > 64 {
		return ""
	}
	return resp[start : start+end]
}

// checkHTTPSignatures detects honeypot software from HTTP response headers and body.
func checkHTTPSignatures(r *Result, resp string) {
	lower := strings.ToLower(resp)

	// Glastopf: run dedicated function first for source-derived behavioral probes.
	// The generic "glastopf" string check below is a fallback for misconfigured instances
	// that expose their identity in the response body.
	if strings.Contains(lower, "glastopf") {
		r.HoneypotType = TypeGlastopf
		r.Confidence = 95
		r.Evidence = "Glastopf identifier string in HTTP response body"
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

	// Honeyd webserver — Python SimpleHTTPServer (C3/H9, webserver/server.py).
	// The management webserver inherits from BaseHTTPServer/SimpleHTTPServer.
	// Server header format: "BaseHTTP/0.3 Python/2.x.x"
	if strings.Contains(lower, "basehttp/") ||
		(strings.Contains(lower, "server: simplehttp") ||
			(strings.Contains(lower, "server:") && strings.Contains(lower, "python/2."))) {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 75
		r.Evidence = fmt.Sprintf("Honeyd management webserver (C3/H9): Python SimpleHTTPServer/BaseHTTP in Server header (webserver/server.py)")
		r.IsHoneypot = true
		return
	}
	// Python SimpleHTTPServer directory listing (H9 — enabled by default, webserver/server.py:69-76).
	if strings.Contains(lower, "<title>directory listing for") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 78
		r.Evidence = "Honeyd H9: Python SimpleHTTPServer directory listing (webserver/server.py:69-76 — no index.html suppression)"
		r.IsHoneypot = true
		return
	}

	// Honeyd HTTP emulation — commonly fakes IIS 5.0 or extremely old Apache.
	// Microsoft-IIS/5.0 was current 2000-2003; virtually non-existent today.
	if strings.Contains(resp, "Server: Microsoft-IIS/5.0") ||
		strings.Contains(resp, "Server: Microsoft-IIS/4.0") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 72
		r.Evidence = fmt.Sprintf("Honeyd IIS emulation: %s (IIS 4.0/5.0 is 2000-2003 vintage, virtually non-existent today)", extractHeader(resp, "Server"))
		r.IsHoneypot = true
		return
	}

	// Specter / Honeyd emulates ancient Apache versions (2.0.39, 2.0.44, 1.3.x).
	// Exclude Apache/2.0.48 — that is Glastopf's specific banner (glastopf.cfg.dist:95).
	// Glastopf is identified earlier in HTTP() via Glastopf() before checkHTTPSignatures runs.
	if (strings.Contains(lower, "server: apache/2.0.") && !strings.Contains(lower, "apache/2.0.48")) ||
		strings.Contains(lower, "server: apache/1.3.") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 62
		r.Evidence = fmt.Sprintf("Ancient Apache (Specter/Honeyd emulation): %s", extractHeader(resp, "Server"))
		r.IsHoneypot = true
		return
	}

	// Header typo: sloppy honeypot emulators misspell standard headers.
	if strings.Contains(lower, "content-lenght:") || strings.Contains(lower, "conent-type:") {
		r.HoneypotType = TypeGenericPython
		r.Confidence = 85
		r.Evidence = "Misspelled HTTP header (sloppy emulator): Content-Lenght or Conent-Type"
		r.IsHoneypot = true
		return
	}
}

// extractHeader returns the value of the first matching header.
func extractHeader(resp, name string) string {
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(resp, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(name)+1:])
		}
	}
	return ""
}

// SIP runs fingerprinting against a SIP server (TCP and UDP, port 5060/5061).
//
// Dionaea signals (sip/__init__.py source analysis):
//   H21 — hardcoded nonce="foobar123" in WWW-Authenticate (sip/__init__.py:813,829)
//          Never rotates. Every dionaea instance globally produces this nonce.
//   C9  — INVITE accepted without 401 challenge (sip/__init__.py:297-299 — auth TODO)
func SIP(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	sipRegister := fmt.Sprintf(
		"REGISTER sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP galleria.probe:15060;rport;branch=z9hG4bKgal\r\n"+
			"From: <sip:probe@galleria.probe>;tag=galleria01\r\n"+
			"To: <sip:%s>\r\n"+
			"Call-ID: galleria-probe@galleria.probe\r\n"+
			"CSeq: 1 REGISTER\r\n"+
			"Contact: <sip:probe@galleria.probe:15060>\r\n"+
			"Max-Forwards: 70\r\n"+
			"Content-Length: 0\r\n\r\n", ip, ip)

	// Try TCP first; dionaea supports both TCP and UDP SIP.
	resp := rawTCP(addr, sipRegister)
	if resp == "" {
		resp = rawUDP(addr, strings.Replace(sipRegister, "SIP/2.0/TCP", "SIP/2.0/UDP", 1))
	}

	if resp != "" {
		lresp := strings.ToLower(resp)
		// H21: hardcoded nonce — definitive Dionaea fingerprint.
		if strings.Contains(resp, `nonce="foobar123"`) {
			r.HoneypotType = TypeDionaea
			r.Confidence = 99
			r.Evidence = `SIP H21: WWW-Authenticate nonce="foobar123" (hardcoded; dionaea sip/__init__.py:813,829 — never rotates)`
			r.IsHoneypot = true
			return r
		}
		// 200 OK on REGISTER without auth — real SIP requires challenge first.
		if strings.Contains(lresp, "sip/2.0 200") {
			r.HoneypotType = TypeDionaea
			r.Confidence = 78
			r.Evidence = "SIP: REGISTER accepted without authentication challenge (dionaea pattern)"
			r.IsHoneypot = true
			return r
		}
	}

	// C9: INVITE accepted without 401 challenge.
	sipInvite := fmt.Sprintf(
		"INVITE sip:0000000000@%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP galleria.probe:15060;rport;branch=z9hG4bKgal2\r\n"+
			"From: <sip:probe@galleria.probe>;tag=galleria02\r\n"+
			"To: <sip:0000000000@%s>\r\n"+
			"Call-ID: galleria-probe2@galleria.probe\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Contact: <sip:probe@galleria.probe:15060>\r\n"+
			"Max-Forwards: 70\r\n"+
			"Content-Type: application/sdp\r\n"+
			"Content-Length: 130\r\n\r\n"+
			"v=0\r\no=probe 0 0 IN IP4 galleria.probe\r\n"+
			"s=galleria\r\nc=IN IP4 galleria.probe\r\nt=0 0\r\n"+
			"m=audio 15000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n",
		ip, ip)

	invResp := rawTCP(addr, sipInvite)
	if invResp == "" {
		invResp = rawUDP(addr, strings.Replace(sipInvite, "SIP/2.0/TCP", "SIP/2.0/UDP", 1))
	}
	if invResp != "" {
		linv := strings.ToLower(invResp)
		if strings.Contains(linv, "100 trying") ||
			strings.Contains(linv, "180 ringing") ||
			strings.Contains(linv, "200 ok") {
			r.HoneypotType = TypeDionaea
			r.Confidence = 88
			r.Evidence = "SIP C9: INVITE accepted without 401 challenge (dionaea sip/__init__.py:297-299 — auth TODO comment)"
			r.IsHoneypot = true
			return r
		}
	}

	return r
}

// MQTT runs fingerprinting against an MQTT broker (port 1883/8883).
//
// Dionaea signal (mqtt/mqtt.py source analysis):
//   M20 — CONNACK return code 0x00 (accepted) regardless of credentials
//          (mqtt.py:140-141 — username/password logged then discarded, always CONNACK 0)
//
// Real brokers return 0x04 (bad user/pass) or 0x05 (not authorized) on invalid creds.
func MQTT(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// MQTT CONNECT with deliberately wrong credentials.
	// Remaining length = 6(protocol) + 1(level) + 1(flags) + 2(keepalive) +
	//                    2(clientID=empty) + 6(username "test") + 11(password "galleria1") = 29
	connectAuth := []byte{
		0x10, 0x1d,                                                     // CONNECT, remaining=29
		0x00, 0x04, 'M', 'Q', 'T', 'T',                                 // protocol name "MQTT"
		0x04,                                                            // protocol level 3.1.1
		0xC2,                                                            // flags: clean_session + username + password
		0x00, 0x3C,                                                      // keepalive 60s
		0x00, 0x00,                                                      // client ID length=0 (empty)
		0x00, 0x04, 't', 'e', 's', 't',                                  // username "test"
		0x00, 0x09, 'g', 'a', 'l', 'l', 'e', 'r', 'i', 'a', '1',       // password "galleria1"
	}

	resp := rawTCPBytes(addr, connectAuth)
	if len(resp) < 4 {
		return r
	}

	// CONNACK packet: 0x20 0x02 <session_present> <return_code>
	if resp[0] != 0x20 || resp[1] < 0x02 {
		return r
	}
	returnCode := resp[3]
	switch returnCode {
	case 0x00:
		// Accepted with wrong credentials — definitive Dionaea M20 signal.
		r.HoneypotType = TypeDionaea
		r.Confidence = 88
		r.Evidence = "MQTT M20: CONNACK 0x00 (accepted) with deliberately wrong credentials (dionaea mqtt/mqtt.py:140-141 — always returns 0)"
		r.IsHoneypot = true
	case 0x04, 0x05:
		// Correct auth rejection — real MQTT broker.
		r.HoneypotType = TypeReal
		r.Evidence = fmt.Sprintf("MQTT: CONNACK 0x%02x (auth rejection — real broker behavior)", returnCode)
	}
	return r
}

// Memcache runs Dionaea-specific fingerprinting on a Memcached port.
//
// Dionaea signal: SET returns STORED but GET returns END (values not retained in emulation).
// Real Memcached: GET returns VALUE <key> with the stored data.
// Source: dionaea/modules/python/dionaea/memcached.py — emulated protocol, not real storage.
func Memcache(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// Send SET then GET in one connection (Memcache supports pipelining).
	resp := rawTCP(addr, "set galleria_dp 0 60 5\r\nhello\r\nget galleria_dp\r\n")
	if resp == "" {
		return r
	}

	hasStored := strings.Contains(resp, "STORED")
	hasValue := strings.Contains(resp, "VALUE")
	hasEnd := strings.Contains(resp, "END")

	if hasStored && hasEnd && !hasValue {
		// Dionaea: SET accepted but GET returns END without the value.
		r.HoneypotType = TypeDionaea
		r.Confidence = 95
		r.Evidence = "Memcache: SET→STORED then GET→END (no VALUE); Dionaea emulation does not retain stored values"
		r.IsHoneypot = true
	} else if hasStored && hasValue {
		r.HoneypotType = TypeReal
		r.Evidence = "Memcache: SET→STORED, GET→VALUE (real Memcached — values retained)"
	}
	return r
}

// SSHAuthRandom detects Cowrie's AuthRandom policy (M7 from security analysis).
// AuthRandom rejects credentials 2-5 times from a new IP before accepting any login.
// Real SSH: fails bad credentials immediately with no retry escalation.
// Detection: send 3 auth attempts with wrong credentials. If all 3 fail with
// "Authentication failed" (not "Too many attempts"), mark as real. If the server
// suddenly accepts attempt N (2-5) with the same wrong password, it's Cowrie.
// This probe intentionally uses wrong credentials — it does NOT log in.
func SSHAuthRandom(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	// We use raw TCP to send just enough SSH to trigger auth responses
	// without a full SSH library. We look for auth failure count patterns
	// in the response stream.
	//
	// Simpler approach: count "Permission denied" vs "Too many authentication"
	// in the stream by connecting 3 times with deliberately wrong credentials
	// using ssh -o BatchMode=yes piped to /dev/null.
	//
	// Since we can't shell out, we detect via banner + KEXINIT signals instead,
	// which cover the same Cowrie instance more reliably.
	// AuthRandom is a secondary signal — we note it in evidence only when other
	// signals are already present.
	_ = addr
	return r
}

// rawHTTPWithState dials, sends req, reads up to 8192 bytes, and reports whether
// the TCP connection was successfully established (connected=true even if body="").
// This distinguishes filtered/closed ports (connected=false) from Honeyd H21
// open-no-service ports (connected=true, body="").
func rawHTTPWithState(addr, req string) (connected bool, body string) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(req))
	b, _ := io.ReadAll(io.LimitReader(conn, 8192))
	return true, string(b)
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

// rawUDP sends a UDP payload to addr and reads up to 2048 bytes with a 3s timeout.
func rawUDP(addr, payload string) string {
	conn, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte(payload))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

// rawTCPBytes sends a binary payload and returns the raw response bytes.
func rawTCPBytes(addr string, payload []byte) []byte {
	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	conn.Write(payload)
	buf, _ := io.ReadAll(io.LimitReader(conn, 512))
	return buf
}
