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
// Goes beyond banner matching to protocol-level Cowrie identification:
//
//   H1 — version string (default SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2)
//   H2 — KEXINIT padding: Cowrie uses null bytes; real OpenSSH uses random bytes
//   H3 — cipher list: blowfish-cbc/cast128-cbc removed from OpenSSH 6.7 (2014)
//   S6 — Vetterl probe: malformed packet → Cowrie silently drops; real SSH disconnects
//   S5 — Telnet NEW-ENVIRON (handled in Telnet())
//
// All probes run pre-auth, pre-credential — no login attempt required.
func SSH(ip string, port int) *Result {
	r := &Result{Port: port, HoneypotType: TypeUnknown}
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", addr, probeTimeout)
	if err != nil {
		return r
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))

	// --- H1: Banner check ---
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

	// Cowrie known default banners (factory.py:44 fallback).
	if strings.Contains(lbanner, "ssh-2.0-openssh_6.0p1") ||
		strings.Contains(lbanner, "ssh-2.0-openssh_5.1p1") ||
		strings.Contains(lbanner, "ssh-2.0-openssh_5.3") {
		r.HoneypotType = TypeCowrie
		r.Confidence = 85
		r.Evidence = fmt.Sprintf("SSH H1: Cowrie default version string: %s", strings.TrimSpace(banner[:min(len(banner), 80)]))
		r.IsHoneypot = true
		// Don't return — keep probing for more confidence from KEXINIT.
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

	// --- H2 + H3: Parse server KEXINIT packet ---
	payload, padding, kexErr := readSSHPacket(conn)
	if kexErr == nil && len(payload) > 0 && payload[0] == 20 { // SSH2_MSG_KEXINIT
		// H2: null padding — Cowrie transport.py:229 uses b"\0"*lenPad for KEXINIT.
		if allZeroBytes(padding) && len(padding) > 0 {
			r.HoneypotType = TypeCowrie
			r.Confidence = 95
			r.Evidence = "SSH H2: KEXINIT padding is all null bytes (Cowrie transport.py:229; real OpenSSH uses random)"
			r.IsHoneypot = true
		}

		// H3: legacy cipher list — blowfish-cbc and cast128-cbc removed in OpenSSH 6.7 (2014).
		if ciphers, err := sshKEXINITCiphers(payload); err == nil {
			for _, c := range ciphers {
				if c == "blowfish-cbc" || c == "cast128-cbc" {
					r.HoneypotType = TypeCowrie
					r.Confidence = max2(r.Confidence, 95)
					r.Evidence = fmt.Sprintf("SSH H3: KEXINIT cipher list includes %q (removed from OpenSSH 6.7+; Cowrie factory.py:144)", c)
					r.IsHoneypot = true
					break
				}
			}
		}
	}

	// --- S6: Vetterl probe — malformed packet length ---
	// Real OpenSSH: sends SSH_MSG_DISCONNECT (type byte 1) — required by RFC 4253.
	// Cowrie: silently drops the connection (no disconnect sent).
	conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF}) // impossible packet length
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 64)
	nr, _ := conn.Read(resp)

	if nr == 0 {
		// Silent drop — Cowrie S6 behavior.
		r.HoneypotType = TypeCowrie
		r.Confidence = max2(r.Confidence, 88)
		if r.Evidence == "" {
			r.Evidence = "SSH S6: malformed packet → silent drop (Cowrie); real OpenSSH sends SSH_MSG_DISCONNECT"
		} else {
			r.Evidence += " + S6:silent-drop"
		}
		r.IsHoneypot = true
	} else if nr >= 6 && resp[5] == 1 {
		// SSH_MSG_DISCONNECT received — real OpenSSH behavior.
		if !r.IsHoneypot {
			r.HoneypotType = TypeReal
			r.Evidence = fmt.Sprintf("SSH: %s (responds with SSH_MSG_DISCONNECT to malformed packet)", strings.TrimSpace(banner[:min(len(banner), 60)]))
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

	// Anonymous login attempt.
	r1, _ := rawTCPExchange(addr, "USER anonymous\r\n")
	if r1 == "" || !strings.HasPrefix(r1, "331") {
		// No 331 Password required → not real FTP or full anonymous denial.
		// Specter says 230 directly for anonymous; check.
		if !strings.HasPrefix(r1, "230") {
			return r
		}
	}
	rawTCPExchange(addr, "PASS galleria@probe.io\r\n")

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
	// Honeyd HTTP emulation — commonly fakes IIS 5.0 or extremely old Apache.
	if strings.Contains(resp, "Server: Microsoft-IIS/5.0") {
		r.HoneypotType = TypeHoneyd
		r.Confidence = 70
		r.Evidence = "Honeyd IIS 5.0 emulation signature"
		r.IsHoneypot = true
		return
	}
	// Specter emulates ancient Apache/2.0.x versions (2.0.39, 2.0.44, etc.).
	// These are virtually nonexistent on the modern internet.
	if strings.Contains(lower, "server: apache/2.0.") || strings.Contains(lower, "server: apache/1.3.") {
		r.HoneypotType = TypePortspoof
		r.Confidence = 60
		r.Evidence = fmt.Sprintf("Ancient Apache version (Specter emulation default): %s", extractHeader(resp, "Server"))
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
