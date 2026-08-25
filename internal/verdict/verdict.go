package verdict

import (
	"strings"

	"github.com/sshpie/galleria/internal/corpus"
	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/probe"
)

// Verdict is the conclusion for a single port.
type Verdict struct {
	Port     int
	State    string // REAL, UNKNOWN, FLOOR
	Platform string // corpus match, if any
	AuthOff  bool   // true if no authentication observed
	Evidence string // response excerpt or probe detail
	Issuer   string // TLS issuer, if any
}

// Classify probes a single port against the noise floor and corpus.
// Returns a Verdict.
func Classify(ip string, port int, sig *floor.Signature) *Verdict {
	v := &Verdict{Port: port}

	// Check known binary protocols first — they bypass floor matching because
	// a catch-all that only speaks HTTP will never return +PONG.
	if port == 6379 || port == 6380 {
		if ok, auth := probe.Redis(ip, port); ok {
			v.State = "REAL"
			v.Platform = "redis"
			v.AuthOff = auth == "OPEN"
			v.Evidence = "Redis PING→PONG"
			return v
		}
	}
	if port == 11211 {
		if probe.Memcached(ip, port) {
			v.State = "REAL"
			v.Platform = "memcached"
			v.AuthOff = true
			v.Evidence = "Memcached STAT response"
			return v
		}
	}

	// Look up corpus probe targets for this port.
	targets := corpus.ProbeTargets([]int{port})
	if len(targets) == 0 {
		// No corpus entry — do a plain GET and check against floor.
		r := probe.HTTP(ip, port, "/")
		if !r.Open {
			return v
		}
		if sig.Active && sig.IsFloor(r.BodySize, r.Code) {
			v.State = "FLOOR"
			return v
		}
		v.State = "UNKNOWN"
		v.Evidence = excerpt(r.Body)
		v.Issuer = r.Issuer
		return v
	}

	// Try each corpus-derived probe.
	for _, t := range targets {
		matched, body := probe.Generic(ip, t.Port, t.Path, t.Markers)
		if !matched {
			r := probe.HTTP(ip, port, t.Path)
			if !r.Open || (sig.Active && sig.IsFloor(r.BodySize, r.Code)) {
				continue
			}
			// Different size from floor — potential real service even without marker match.
			v.State = "UNKNOWN"
			v.Evidence = excerpt(r.Body)
			v.Issuer = r.Issuer
			continue
		}
		// Marker matched.
		v.State = "REAL"
		v.Platform = t.Platform
		v.AuthOff = isOpen(body)
		v.Evidence = excerpt(body)
		return v
	}

	// Corpus probes ran — best state is what was accumulated.
	if v.State == "" {
		// All probes were floor matches or closed.
		if sig.Active {
			v.State = "FLOOR"
		} else {
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
	// Strip HTTP header block.
	if idx := strings.Index(body, "\r\n\r\n"); idx >= 0 {
		body = body[idx+4:]
	}
	if len(body) > 300 {
		body = body[:300]
	}
	return strings.TrimSpace(body)
}
