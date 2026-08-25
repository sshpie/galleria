package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/sshpie/galleria/internal/bloom"
	"github.com/sshpie/galleria/internal/corpus"
	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/output"
	"github.com/sshpie/galleria/internal/verdict"
)

var (
	flagPorts       string
	flagOut         string
	flagConcurrency int
	flagFloorOnly   bool
	flagAllTiers    bool
	flagFingerprint bool
)

var rootCmd = &cobra.Command{
	Use:   "galleria <ip>",
	Short: "Sift real AI/ML services from honeypot port noise",
	Long: `galleria takes a host IP and its full port list (from Shodan or any scanner)
and identifies which ports carry real AI/ML services versus honeypot catch-all noise.

Ports are grouped into priority tiers before probing:
  Tier 1: AI inference, vector DBs, voice AI, agent frameworks  (probed first)
  Tier 2: ML platforms, AI gateways, observability
  Tier 3: Databases, messaging, storage
  Tier 4: ICS/SCADA
  Binary: Redis, Kafka, MQTT, Modbus — bypass floor matching, always probed

If a portspoof floor is detected and a tier contains no binary-protocol ports,
that tier is skipped (all ports marked FLOOR without individual probes).

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
	rootCmd.Flags().BoolVar(&flagAllTiers, "all-tiers", false, "Probe all tiers even when floor is confirmed (slower, exhaustive)")
	rootCmd.Flags().BoolVar(&flagFingerprint, "fingerprint", false, "Run behavioral honeypot fingerprinting on candidates (language-injection, verb confusion, multi-step protocol depth)")
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
		if sig.TimingUniform {
			fmt.Fprintf(os.Stderr, "[galleria] floor detected via=%s timing_stddev=%.1fms code=%d size=%d issuer=%q\n",
				sig.HowDetected, sig.TimingStddevMs, sig.HTTPCode, sig.BodySize, sig.Issuer)
		} else {
			fmt.Fprintf(os.Stderr, "[galleria] floor detected via=%s code=%d size=%d issuer=%q\n",
				sig.HowDetected, sig.HTTPCode, sig.BodySize, sig.Issuer)
		}
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

	// Phase 2: group ports into tiers, probe in priority order.
	w, err := output.NewWriter(flagOut)
	if err != nil {
		return err
	}
	defer w.Close()

	groups := corpus.GroupPortsByTier(ports)

	// Print tier breakdown.
	for _, tier := range corpus.DefaultTiers {
		pts := groups[tier.Name]
		if len(pts) > 0 {
			fmt.Fprintf(os.Stderr, "[galleria] tier=%s  ports=%d\n", tier.Name, len(pts))
		}
	}
	if bPorts := groups["binary"]; len(bPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[galleria] tier=binary  ports=%d  (bypass floor)\n", len(bPorts))
	}
	if uPorts := groups["unknown"]; len(uPorts) > 0 {
		fmt.Fprintf(os.Stderr, "[galleria] tier=unknown  ports=%d\n", len(uPorts))
	}

	var allVerdicts []*verdict.Verdict
	var mu sync.Mutex

	probePorts := func(tierPorts []int, tierName string) {
		if len(tierPorts) == 0 {
			return
		}
		sem := make(chan struct{}, flagConcurrency)
		var wg sync.WaitGroup
		for _, port := range tierPorts {
			port := port
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				v := verdict.Classify(ip, port, sig, flagFingerprint)
				mu.Lock()
				allVerdicts = append(allVerdicts, v)
				if v.State == "REAL" || v.State == "UNKNOWN" || v.State == "HONEYPOT" {
					w.Write(ip, v, sig)
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
	}

	// Binary protocol ports always run — floor can't fake them.
	probePorts(groups["binary"], "binary")

	// Tier 1 always runs (this is the money tier for AI/ML).
	probePorts(groups["ai-inference"], "ai-inference")

	// Remaining tiers: skip HTTP tiers if floor is confirmed and --all-tiers not set.
	remainingTiers := []string{"ml-platform", "data-infra", "ics-scada", "unknown"}
	for _, tierName := range remainingTiers {
		tierPorts := groups[tierName]
		if len(tierPorts) == 0 {
			continue
		}
		if sig.Active && !flagAllTiers {
			// Floor confirmed — mark all these HTTP ports as FLOOR without probing.
			fmt.Fprintf(os.Stderr, "[galleria] tier=%s skipped (floor confirmed, %d ports → FLOOR)\n",
				tierName, len(tierPorts))
			mu.Lock()
			for _, port := range tierPorts {
				allVerdicts = append(allVerdicts, &verdict.Verdict{Port: port, State: "FLOOR"})
			}
			mu.Unlock()
			continue
		}
		probePorts(tierPorts, tierName)
	}

	output.PrintSummary(ip, allVerdicts, sig)
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
