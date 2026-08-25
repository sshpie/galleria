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
		if probe.Memcached(ip, port) {
			v.State = "REAL"
			v.Platform = "memcached"
			v.AuthOff = true
			v.Evidence = "Memcached stats→STAT"
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
