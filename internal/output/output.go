package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/verdict"
)

// BufWriter wraps an io.Writer for MCP/programmatic use (no file handles).
type BufWriter struct {
	W io.Writer
}

func (b *BufWriter) WriteVerdict(ip string, v *verdict.Verdict, sig *floor.Signature) {
	r := Record{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		IP:           ip,
		Port:         v.Port,
		State:        v.State,
		Platform:     v.Platform,
		AuthOff:      v.AuthOff,
		Evidence:     v.Evidence,
		Issuer:       v.Issuer,
		HoneypotType: v.HoneypotType,
		Confidence:   v.Confidence,
	}
	if sig != nil {
		r.Floor = &FloorSummary{
			Active:         sig.Active,
			BodySize:       sig.BodySize,
			HTTPCode:       sig.HTTPCode,
			Issuer:         sig.Issuer,
			HowDetected:    sig.HowDetected,
			TimingStddevMs: sig.TimingStddevMs,
		}
	}
	data, err := json.Marshal(r)
	if err == nil {
		fmt.Fprintf(b.W, "%s\n", data)
	}
}

func (b *BufWriter) WriteSummaryRecord(sr SummaryRecord) {
	data, err := json.Marshal(sr)
	if err == nil {
		fmt.Fprintf(b.W, "%s\n", data)
	}
}

// WriteSummary writes the structured summary record to a BufWriter (MCP path).
func WriteSummary(bw *BufWriter, ip string, verdicts []*verdict.Verdict, sig *floor.Signature) {
	real, unknown, floorCount, honeypot := 0, 0, 0, 0
	var hpDetails []HoneypotDetail
	for _, v := range verdicts {
		switch v.State {
		case "REAL":
			real++
		case "UNKNOWN":
			unknown++
		case "FLOOR":
			floorCount++
		case "HONEYPOT":
			honeypot++
			hpDetails = append(hpDetails, HoneypotDetail{
				Port:         v.Port,
				HoneypotType: v.HoneypotType,
				Confidence:   v.Confidence,
				Evidence:     v.Evidence,
			})
		}
	}
	sr := SummaryRecord{
		Type:        "summary",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		IP:          ip,
		FloorActive: sig.Active,
		FloorHow:    sig.HowDetected,
		Real:        real,
		Unknown:     unknown,
		Honeypot:    honeypot,
		Floor:       floorCount,
		HoneypotIDs: hpDetails,
	}
	bw.WriteSummaryRecord(sr)
}


// Record is a single JSONL line written to output.
type Record struct {
	Timestamp    string        `json:"ts"`
	IP           string        `json:"ip"`
	Port         int           `json:"port"`
	State        string        `json:"state"`
	Platform     string        `json:"platform,omitempty"`
	AuthOff      bool          `json:"auth_off,omitempty"`
	Evidence     string        `json:"evidence,omitempty"`
	Issuer       string        `json:"issuer,omitempty"`
	HoneypotType string        `json:"honeypot_type,omitempty"`
	Confidence   int           `json:"confidence,omitempty"`
	Floor        *FloorSummary `json:"floor,omitempty"`
}

// FloorSummary captures the noise-floor characterization for the host.
type FloorSummary struct {
	Active         bool    `json:"active"`
	BodySize       int     `json:"body_size"`
	HTTPCode       int     `json:"http_code"`
	Issuer         string  `json:"issuer,omitempty"`
	HowDetected    string  `json:"how_detected,omitempty"`
	TimingStddevMs float64 `json:"timing_stddev_ms,omitempty"`
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
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		IP:           ip,
		Port:         v.Port,
		State:        v.State,
		Platform:     v.Platform,
		AuthOff:      v.AuthOff,
		Evidence:     v.Evidence,
		Issuer:       v.Issuer,
		HoneypotType: v.HoneypotType,
		Confidence:   v.Confidence,
	}
	if sig != nil {
		r.Floor = &FloorSummary{
			Active:         sig.Active,
			BodySize:       sig.BodySize,
			HTTPCode:       sig.HTTPCode,
			Issuer:         sig.Issuer,
			HowDetected:    sig.HowDetected,
			TimingStddevMs: sig.TimingStddevMs,
		}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w.w, "%s\n", b)
	return err
}

// SummaryRecord is the final structured record written to stdout after all per-port records.
// type = "summary" distinguishes it from per-port records (type field absent on those).
// LLM agents should parse this record to get aggregate verdict counts.
type SummaryRecord struct {
	Type        string            `json:"type"`       // always "summary"
	Timestamp   string            `json:"ts"`
	IP          string            `json:"ip"`
	FloorActive bool              `json:"floor_active"`
	FloorHow    string            `json:"floor_how,omitempty"`
	Real        int               `json:"real"`
	Unknown     int               `json:"unknown"`
	Honeypot    int               `json:"honeypot"`
	Floor       int               `json:"floor"`
	HoneypotIDs []HoneypotDetail  `json:"honeypot_ids,omitempty"` // named honeypots found
}

// HoneypotDetail captures name + confidence for one identified honeypot port.
type HoneypotDetail struct {
	Port         int    `json:"port"`
	HoneypotType string `json:"honeypot_type"`
	Confidence   int    `json:"confidence"`
	Evidence     string `json:"evidence,omitempty"`
}

// PrintSummary prints a human-readable summary to stderr and a structured
// SummaryRecord JSON line to the output writer (stdout or file).
// The SummaryRecord is always the last line written — LLM agents can tail it.
func PrintSummary(w *Writer, ip string, verdicts []*verdict.Verdict, sig *floor.Signature) {
	real := 0
	unknown := 0
	floorCount := 0
	honeypot := 0
	var hpDetails []HoneypotDetail

	for _, v := range verdicts {
		switch v.State {
		case "REAL":
			real++
		case "UNKNOWN":
			unknown++
		case "FLOOR":
			floorCount++
		case "HONEYPOT":
			honeypot++
			hpDetails = append(hpDetails, HoneypotDetail{
				Port:         v.Port,
				HoneypotType: v.HoneypotType,
				Confidence:   v.Confidence,
				Evidence:     v.Evidence,
			})
		}
	}

	fmt.Fprintf(os.Stderr, "[galleria] %s  floor=%v  REAL=%d  UNKNOWN=%d  HONEYPOT=%d  FLOOR=%d\n",
		ip, sig.Active, real, unknown, honeypot, floorCount)
	for _, v := range verdicts {
		if v.State == "REAL" || v.State == "UNKNOWN" || v.State == "HONEYPOT" {
			tag := ""
			if v.Platform != "" {
				tag = " [" + v.Platform + "]"
			}
			auth := ""
			if v.AuthOff {
				auth = " UNAUTH"
			}
			hp := ""
			if v.HoneypotType != "" {
				hp = fmt.Sprintf(" {%s/%d%%}", v.HoneypotType, v.Confidence)
			}
			fmt.Fprintf(os.Stderr, "  :%d  %s%s%s%s\n", v.Port, v.State, tag, auth, hp)
		}
	}

	// Structured summary record to stdout — always last line.
	sr := SummaryRecord{
		Type:        "summary",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		IP:          ip,
		FloorActive: sig.Active,
		FloorHow:    sig.HowDetected,
		Real:        real,
		Unknown:     unknown,
		Honeypot:    honeypot,
		Floor:       floorCount,
		HoneypotIDs: hpDetails,
	}
	b, err := json.Marshal(sr)
	if err == nil {
		fmt.Fprintf(w.w, "%s\n", b)
	}
}
