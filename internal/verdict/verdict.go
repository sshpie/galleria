package verdict

import (
	"strings"

	"github.com/sshpie/galleria/internal/corpus"
	"github.com/sshpie/galleria/internal/fingerprint"
	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/probe"
)

// Verdict is the conclusion for a single port.
type Verdict struct {
	Port         int
	State        string // REAL, UNKNOWN, FLOOR, HONEYPOT
	Platform     string // corpus match, if any
	AuthOff      bool   // true if no authentication observed
	Evidence     string // response excerpt or probe detail
	Issuer       string // TLS issuer, if any
	HoneypotType string // populated when State == HONEYPOT
	Confidence   int    // 0-100, populated when honeypot type known
}

// Classify probes a single port against the noise floor and corpus.
// When doFingerprint is true, behavioral honeypot fingerprinting runs on candidates.
func Classify(ip string, port int, sig *floor.Signature, doFingerprint bool) *Verdict {
	v := &Verdict{Port: port}

	// Binary protocols first — bypass HTTP floor matching.
	// A catch-all portspoof that only speaks HTTP cannot fake these.
	if port == 6379 || port == 6380 {
		if ok, auth := probe.Redis(ip, port); ok {
			v.State = "REAL"
			v.Platform = "redis"
			v.AuthOff = auth == "OPEN"
			v.Evidence = "Redis PING→+PONG"
			if doFingerprint {
				// OpenCanary Redis: wrong auth error string.
				ocfp := fingerprint.OpenCanary(ip, port)
				if ocfp.IsHoneypot {
					v.State = "HONEYPOT"
					v.HoneypotType = string(ocfp.HoneypotType)
					v.Confidence = ocfp.Confidence
					v.Evidence = ocfp.Evidence
					return v
				}
				// Multi-step Redis depth test: INVALIDCMD after PING.
				fp := fingerprint.Redis(ip, port)
				if fp.IsHoneypot {
					v.State = "HONEYPOT"
					v.HoneypotType = string(fp.HoneypotType)
					v.Confidence = fp.Confidence
					v.Evidence = fp.Evidence
				}
			}
			return v
		}
	}
	if port == 11211 {
		// Dionaea Memcache emulation: SET returns STORED but GET returns END (values not retained).
		if doFingerprint {
			fp := fingerprint.Memcache(ip, port)
			if fp.IsHoneypot {
				v.State = "HONEYPOT"
				v.HoneypotType = string(fp.HoneypotType)
				v.Confidence = fp.Confidence
				v.Evidence = fp.Evidence
				return v
			}
			if fp.HoneypotType == fingerprint.TypeReal {
				v.State = "REAL"
				v.Platform = "memcached"
				v.AuthOff = true
				v.Evidence = fp.Evidence
				return v
			}
		}
		if probe.Memcached(ip, port) {
			v.State = "REAL"
			v.Platform = "memcached"
			v.AuthOff = true
			v.Evidence = "Memcached stats→STAT"
			return v
		}
	}

	// SIP: Dionaea hardcodes nonce="foobar123" and accepts INVITE without challenge.
	if port == 5060 || port == 5061 {
		fp := fingerprint.SIP(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
		if fp.HoneypotType == fingerprint.TypeReal {
			v.State = "REAL"
			v.Platform = "sip"
			v.Evidence = fp.Evidence
			return v
		}
	}

	// MQTT: Dionaea always returns CONNACK 0x00 (accepted) regardless of credentials.
	if port == 1883 || port == 8883 {
		fp := fingerprint.MQTT(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
		if fp.HoneypotType == fingerprint.TypeReal {
			v.State = "REAL"
			v.Platform = "mqtt"
			v.Evidence = fp.Evidence
			return v
		}
	}

	// MySQL: OpenCanary hardcodes capability bytes 0xff 0xf7 0x08 0x02 in greeting.
	if port == 3306 {
		fp := fingerprint.OpenCanary(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// MSSQL: OpenCanary embeds "thinkst.com" in hardcoded NTLM challenge blob.
	if port == 1433 {
		fp := fingerprint.OpenCanary(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// SAP Cloud Active Defense clone app (2000), Keycloak (8080), control panel API (3000).
	if port == 2000 || port == 8080 || port == 3000 {
		fp := fingerprint.CloudActiveDefense(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// Modbus TCP (502): Conpot FC17 stub detection.
	if port == 502 {
		fp := fingerprint.Conpot(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// Guardian AST fuel monitor (10001): Conpot hardcodes "STATOIL STATION".
	if port == 10001 {
		fp := fingerprint.Conpot(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// SNMP UDP (161): Conpot hardcodes sysLocation = "Venus".
	if port == 161 {
		fp := fingerprint.Conpot(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// S7comm ISO-on-TCP (102): Conpot COTP 0x62 stripping behavioral probe.
	if port == 102 {
		fp := fingerprint.Conpot(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// IMAP: Amun hardcodes "Lotus Domino 6.5.4 7.0.2 IMAP4" banner.
	if port == 143 {
		fp := fingerprint.Amun(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// POP3: Amun uses 220 greeting (RFC 1939 requires +OK).
	if port == 110 {
		fp := fingerprint.Amun(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// VNC: Amun's realvnc_modul.py:28 omits the trailing \n from the RFB banner.
	if port == 5900 {
		fp := fingerprint.Amun(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// FTP: Amun banner check runs first; fallthrough to Honeyd/Specter SYST check.
	if port == 21 {
		cfp := fingerprint.Conpot(ip, port)
		if cfp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(cfp.HoneypotType)
			v.Confidence = cfp.Confidence
			v.Evidence = cfp.Evidence
			return v
		}
		afp := fingerprint.Amun(ip, port)
		if afp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(afp.HoneypotType)
			v.Confidence = afp.Confidence
			v.Evidence = afp.Evidence
			return v
		}
		fp := fingerprint.FTP(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
		if fp.HoneypotType == fingerprint.TypeReal {
			v.State = "REAL"
			v.Platform = "ftp"
			v.Evidence = fp.Evidence
			return v
		}
	}

	// LaBrea tarpit: first-speaker ports that accept TCP but send nothing.
	if port == 22 || port == 23 || port == 21 || port == 25 || port == 110 {
		if fingerprint.LaBrea(ip, port) {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fingerprint.TypePortspoof)
			v.Confidence = 75
			v.Evidence = "LaBrea tarpit: TCP connect accepted but zero bytes received in 2s"
			return v
		}
	}

	// SMTP ports: BOF/minimal honeypots disconnect with 503; real SMTP sends 220 + capabilities.
	if port == 25 || port == 465 || port == 587 || port == 2525 {
		fp := fingerprint.SMTP(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
		if fp.HoneypotType == fingerprint.TypeReal {
			v.State = "REAL"
			v.Platform = "smtp"
			v.Evidence = fp.Evidence
			return v
		}
	}

	// Telnet: Cowrie sends login prompt without IAC negotiation.
	if port == 23 {
		fp := fingerprint.Telnet(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
	}

	// SSH ports: behavioral fingerprinting catches Cowrie and Honeyd.
	if port == 22 || port == 2222 || port == 2200 {
		fp := fingerprint.SSH(ip, port)
		if fp.IsHoneypot {
			v.State = "HONEYPOT"
			v.HoneypotType = string(fp.HoneypotType)
			v.Confidence = fp.Confidence
			v.Evidence = fp.Evidence
			return v
		}
		if fp.Evidence != "" {
			v.State = "REAL"
			v.Platform = "ssh"
			v.Evidence = fp.Evidence
			return v
		}
	}

	// Corpus probe targets for this port.
	targets := corpus.ProbeTargets([]int{port})
	if len(targets) == 0 {
		r := probe.HTTP(ip, port, "/")
		if !r.Open {
			return v
		}
		if sig.Active && sig.IsFloor(r.BodySize, r.Code) {
			v.State = "FLOOR"
			return v
		}
		if doFingerprint {
			fp := fingerprint.HTTP(ip, port)
			if fp.IsHoneypot {
				v.State = "HONEYPOT"
				v.HoneypotType = string(fp.HoneypotType)
				v.Confidence = fp.Confidence
				v.Evidence = fp.Evidence
				return v
			}
		}
		v.State = "UNKNOWN"
		v.Evidence = excerpt(r.Body)
		v.Issuer = r.Issuer
		return v
	}

	// Try corpus-derived probes.
	for _, t := range targets {
		matched, body := probe.Generic(ip, t.Port, t.Path, t.Markers)
		if !matched {
			r := probe.HTTP(ip, port, t.Path)
			if !r.Open || (sig.Active && sig.IsFloor(r.BodySize, r.Code)) {
				continue
			}
			v.State = "UNKNOWN"
			v.Evidence = excerpt(r.Body)
			v.Issuer = r.Issuer
			continue
		}
		// Marker matched — run fingerprinting on confirmed candidates to rule out honeypot.
		if doFingerprint {
			fp := fingerprint.HTTP(ip, port)
			if fp.IsHoneypot {
				v.State = "HONEYPOT"
				v.Platform = t.Platform
				v.HoneypotType = string(fp.HoneypotType)
				v.Confidence = fp.Confidence
				v.Evidence = fp.Evidence
				return v
			}
		}
		v.State = "REAL"
		v.Platform = t.Platform
		v.AuthOff = isOpen(body)
		v.Evidence = excerpt(body)
		return v
	}

	if v.State == "" {
		if sig.Active {
			v.State = "FLOOR"
		} else {
			if doFingerprint {
				fp := fingerprint.Generic(ip, port)
				if fp.IsHoneypot {
					v.State = "HONEYPOT"
					v.HoneypotType = string(fp.HoneypotType)
					v.Confidence = fp.Confidence
					v.Evidence = fp.Evidence
					return v
				}
			}
			v.State = "UNKNOWN"
		}
	}
	return v
}

func isOpen(body string) bool {
	body = strings.ToLower(body)
	return !strings.Contains(body, "401") &&
		!strings.Contains(body, "403") &&
		!strings.Contains(body, "unauthorized") &&
		!strings.Contains(body, "forbidden") &&
		len(body) > 50
}

func excerpt(body string) string {
	body = strings.TrimSpace(body)
	if idx := strings.Index(body, "\r\n\r\n"); idx >= 0 {
		body = body[idx+4:]
	}
	if len(body) > 300 {
		body = body[:300]
	}
	return strings.TrimSpace(body)
}
