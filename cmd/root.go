package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/sshpie/galleria/internal/bloom"
	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/output"
	"github.com/sshpie/galleria/internal/verdict"
)

var (
	flagPorts       string
	flagOut         string
	flagConcurrency int
	flagFloorOnly   bool
)

var rootCmd = &cobra.Command{
	Use:   "galleria <ip>",
	Short: "Sift real AI/ML services from honeypot port noise",
	Long: `galleria takes a host IP and its full port list (from Shodan or any scanner)
and identifies which ports carry real AI/ML services versus honeypot catch-all noise.

It characterizes the host's noise floor first, then sends corpus-guided protocol-native
probes to priority ports, measuring deviation from the baseline.

Examples:
  galleria 85.9.205.64 --ports 80,443,8080,11434,6333,9200
  galleria 85.9.205.64 --ports "$(cat ports.txt | tr '\n' ',')" --out findings.jsonl
  shodan host 85.9.205.64 -j | jq -r '.ports[]' | tr '\n' ',' | xargs galleria 85.9.205.64 --ports`,
	Args: cobra.ExactArgs(1),
	RunE: run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&flagPorts, "ports", "p", "", "Comma-separated port list (required)")
	rootCmd.Flags().StringVarP(&flagOut, "out", "o", "-", "Output file path (default: stdout)")
	rootCmd.Flags().IntVarP(&flagConcurrency, "concurrency", "c", 40, "Max concurrent port probes")
	rootCmd.Flags().BoolVar(&flagFloorOnly, "floor-only", false, "Only characterize and print the noise floor, then exit")
	rootCmd.MarkFlagRequired("ports")
}

func run(cmd *cobra.Command, args []string) error {
	ip := args[0]
	ports, err := parsePorts(flagPorts)
	if err != nil {
		return fmt.Errorf("--ports: %w", err)
	}
	if len(ports) == 0 {
		return fmt.Errorf("--ports: at least one port required")
	}

	fmt.Fprintf(os.Stderr, "[galleria] target=%s  ports=%d  concurrency=%d\n",
		ip, len(ports), flagConcurrency)

	// Phase 1: noise floor characterization.
	fmt.Fprintf(os.Stderr, "[galleria] characterizing noise floor...\n")
	sig := floor.Characterize(ip, ports)
	if sig.Active {
		fmt.Fprintf(os.Stderr, "[galleria] floor detected: code=%d size=%d issuer=%q\n",
			sig.HTTPCode, sig.BodySize, sig.Issuer)
		bloom.Add(sig.Issuer, sig.BodySize, sig.HTTPCode)
	} else if bloom.Seen(sig.Issuer, sig.BodySize, sig.HTTPCode) {
		fmt.Fprintf(os.Stderr, "[galleria] floor matched bloom filter (cached portspoof signature)\n")
		sig.Active = true
	} else {
		fmt.Fprintf(os.Stderr, "[galleria] no portspoof floor detected\n")
	}

	if flagFloorOnly {
		return nil
	}

	// Phase 2: per-port verdict fan-out.
	w, err := output.NewWriter(flagOut)
	if err != nil {
		return err
	}
	defer w.Close()

	sem := make(chan struct{}, flagConcurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	var verdicts []*verdict.Verdict

	for _, port := range ports {
		port := port
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			v := verdict.Classify(ip, port, sig)
			mu.Lock()
			verdicts = append(verdicts, v)
			if v.State == "REAL" || v.State == "UNKNOWN" {
				w.Write(ip, v, sig)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	output.PrintSummary(ip, verdicts, sig)
	return nil
}

func parsePorts(raw string) ([]int, error) {
	var out []int
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", s, err)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("port %d out of range", n)
		}
		out = append(out, n)
	}
	return out, nil
}
