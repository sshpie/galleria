package corpus

import (
	"embed"
	"encoding/json"
	"io/fs"
	"path/filepath"
)

//go:embed platforms/*.json
var platformFS embed.FS

var platforms []Platform

func init() {
	entries, err := fs.Glob(platformFS, "platforms/*.json")
	if err != nil {
		return
	}
	for _, path := range entries {
		data, err := platformFS.ReadFile(path)
		if err != nil {
			continue
		}
		var p Platform
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		if len(p.DefaultPorts) > 0 {
			platforms = append(platforms, p)
		}
	}
}

// All returns every platform in the corpus.
func All() []Platform {
	return platforms
}

// MatchPort returns platforms that include the given port in their default_ports.
func MatchPort(port int) []Platform {
	var out []Platform
	for _, p := range platforms {
		for _, dp := range p.DefaultPorts {
			if dp == port {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// PriorityPorts returns the deduplicated set of all default_ports across the
// entire corpus, ordered by frequency of appearance (most common first).
func PriorityPorts() []int {
	counts := make(map[int]int)
	for _, p := range platforms {
		for _, port := range p.DefaultPorts {
			counts[port]++
		}
	}
	// Simple insertion into slice ordered by count desc
	type kv struct {
		port  int
		count int
	}
	var pairs []kv
	for port, count := range counts {
		pairs = append(pairs, kv{port, count})
	}
	// Sort by count descending
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[j].count > pairs[i].count {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	out := make([]int, len(pairs))
	for i, p := range pairs {
		out[i] = p.port
	}
	return out
}

// ProbeTargets builds the set of (port, path) pairs worth probing for a host
// given a known open port list. If knownPorts is empty, uses full priority list.
func ProbeTargets(knownPorts []int) []ProbeTarget {
	portSet := make(map[int]bool)
	for _, p := range knownPorts {
		portSet[p] = true
	}

	seen := make(map[string]bool)
	var out []ProbeTarget

	for _, plat := range platforms {
		for _, port := range plat.DefaultPorts {
			if len(knownPorts) > 0 && !portSet[port] {
				continue
			}
			path := plat.Fingerprint.ActiveProbe.Path
			if path == "" {
				path = "/"
			}
			method := plat.Fingerprint.ActiveProbe.Method
			if method == "" {
				method = "GET"
			}
			key := filepath.Join(string(rune(port+'0')), path)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ProbeTarget{
				Port:     port,
				Path:     path,
				Method:   method,
				Platform: plat.Platform,
				Markers:  plat.Fingerprint.ActiveProbe.ResponseMarkers,
			})
		}
	}
	return out
}

// ProbeTarget is a single (port, path) probe derived from the corpus.
type ProbeTarget struct {
	Port     int
	Path     string
	Method   string
	Platform string
	Markers  []string
}
