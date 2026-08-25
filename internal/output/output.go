package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/verdict"
)

// Record is a single JSONL line written to output.
type Record struct {
	Timestamp string            `json:"ts"`
	IP        string            `json:"ip"`
	Port      int               `json:"port"`
	State     string            `json:"state"`
	Platform  string            `json:"platform,omitempty"`
	AuthOff   bool              `json:"auth_off,omitempty"`
	Evidence  string            `json:"evidence,omitempty"`
	Issuer    string            `json:"issuer,omitempty"`
	Floor     *FloorSummary     `json:"floor,omitempty"`
}

// FloorSummary captures the noise-floor characterization for the host.
type FloorSummary struct {
	Active   bool   `json:"active"`
	BodySize int    `json:"body_size"`
	HTTPCode int    `json:"http_code"`
	Issuer   string `json:"issuer,omitempty"`
}

// Writer outputs JSONL records to a file (or stdout if path is "-").
type Writer struct {
	w *os.File
}

// NewWriter opens the output file. Pass "-" for stdout.
func NewWriter(path string) (*Writer, error) {
	if path == "-" {
		return &Writer{w: os.Stdout}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &Writer{w: f}, nil
}

// Close closes the writer.
func (w *Writer) Close() {
	if w.w != os.Stdout {
		w.w.Close()
	}
}

// Write emits a single record.
func (w *Writer) Write(ip string, v *verdict.Verdict, sig *floor.Signature) error {
	r := Record{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        ip,
		Port:      v.Port,
		State:     v.State,
		Platform:  v.Platform,
		AuthOff:   v.AuthOff,
		Evidence:  v.Evidence,
		Issuer:    v.Issuer,
	}
	if sig != nil {
		r.Floor = &FloorSummary{
			Active:   sig.Active,
			BodySize: sig.BodySize,
			HTTPCode: sig.HTTPCode,
			Issuer:   sig.Issuer,
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w.w, "%s\n", b)
	return err
}

// PrintSummary prints a human-readable summary to stderr.
func PrintSummary(ip string, verdicts []*verdict.Verdict, sig *floor.Signature) {
	real := 0
	unknown := 0
	floor := 0
	for _, v := range verdicts {
		switch v.State {
		case "REAL":
			real++
		case "UNKNOWN":
			unknown++
		case "FLOOR":
			floor++
		}
	}
	fmt.Fprintf(os.Stderr, "[galleria] %s  floor=%v  REAL=%d  UNKNOWN=%d  FLOOR=%d\n",
		ip, sig.Active, real, unknown, floor)

	for _, v := range verdicts {
		if v.State == "REAL" || v.State == "UNKNOWN" {
			tag := ""
			if v.Platform != "" {
				tag = " [" + v.Platform + "]"
			}
			auth := ""
			if v.AuthOff {
				auth = " UNAUTH"
			}
			fmt.Fprintf(os.Stderr, "  :%d  %s%s%s\n", v.Port, v.State, tag, auth)
		}
	}
}
