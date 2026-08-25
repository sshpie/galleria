package corpus

// Platform is a single entry from the embedded tome corpus.
type Platform struct {
	Platform     string   `json:"platform"`
	DisplayName  string   `json:"display_name"`
	Category     string   `json:"category"`
	DefaultPorts []int    `json:"default_ports"`
	APIPaths     []string `json:"api_paths"`
	AuthDefault  string   `json:"auth_default"`
	Fingerprint  struct {
		Passive     []string `json:"passive"`
		ActiveProbe struct {
			Path            string   `json:"path"`
			Method          string   `json:"method"`
			Port            int      `json:"port"`
			ResponseMarkers []string `json:"response_markers"`
		} `json:"active_probe"`
	} `json:"fingerprint"`
	ShodanDorks struct {
		Basic  string `json:"basic"`
		Strict string `json:"strict"`
	} `json:"shodan_dorks"`
}
