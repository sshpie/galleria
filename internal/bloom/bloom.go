// Package bloom provides a minimal in-memory bloom filter used to track
// floor signatures across multiple hosts in a single galleria run.
// When a floor signature (issuer+bodySize+code) has been seen before and
// classified as a portspoof floor, subsequent hosts matching the same
// signature skip per-port HTTP probing and go straight to binary-protocol checks.
package bloom

import (
	"fmt"
	"hash/fnv"
	"sync"
)

const (
	m = 1 << 20 // 1M bits
	k = 4       // hash functions
)

var (
	mu   sync.Mutex
	bits [m / 8]byte
)

// Add inserts a floor signature key into the filter.
func Add(issuer string, bodySize, httpCode int) {
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hashes(key(issuer, bodySize, httpCode)) {
		idx := h % m
		bits[idx/8] |= 1 << (idx % 8)
	}
}

// Seen returns true if this signature was previously seen and added.
func Seen(issuer string, bodySize, httpCode int) bool {
	mu.Lock()
	defer mu.Unlock()
	for _, h := range hashes(key(issuer, bodySize, httpCode)) {
		idx := h % m
		if bits[idx/8]&(1<<(idx%8)) == 0 {
			return false
		}
	}
	return true
}

func key(issuer string, bodySize, httpCode int) string {
	return fmt.Sprintf("%s|%d|%d", issuer, bodySize, httpCode)
}

func hashes(s string) [k]uint32 {
	var out [k]uint32
	h := fnv.New32a()
	for i := range out {
		h.Write([]byte(fmt.Sprintf("%d:%s", i, s)))
		out[i] = h.Sum32()
		h.Reset()
	}
	return out
}
