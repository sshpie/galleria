package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sshpie/galleria/internal/bloom"
	"github.com/sshpie/galleria/internal/corpus"
	"github.com/sshpie/galleria/internal/floor"
	"github.com/sshpie/galleria/internal/output"
	"github.com/sshpie/galleria/internal/verdict"
	"sync"
)

func init() {
	rootCmd.AddCommand(mcpCmd)
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Start MCP server (stdio transport) for LLM tool use",
	Long: `Start a Model Context Protocol server over stdio.
Exposes a single tool: scan.

Add to your Claude Code MCP config (~/.claude/mcp.json):
  {"mcpServers":{"galleria":{"command":"galleria","args":["mcp"]}}}

Then any LLM can say: "use galleria to scan 47.123.220.240"`,
	RunE: runMCP,
}

// JSON-RPC 2.0 envelope types.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func runMCP(_ *cobra.Command, _ []string) error {
	enc := json.NewEncoder(os.Stdout)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeError(enc, nil, -32700, "parse error")
			continue
		}

		switch req.Method {
		case "initialize":
			enc.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"protocolVersion": "2024-11-05",
					"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
					"serverInfo":      map[string]interface{}{"name": "galleria", "version": "0.7.0"},
				},
			})

		case "notifications/initialized":
			// No response for notifications.

		case "tools/list":
			enc.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"tools": []map[string]interface{}{
						{
							"name": "scan",
							"description": "Scan a host for real AI/ML services vs honeypot noise. " +
								"Identifies portspoof floors, names specific honeypot software (Cowrie, Kippo, Honeyd, etc.), " +
								"and fingerprints real AI platforms (Ollama, Qdrant, ChromaDB, and 336 others). " +
								"Returns JSONL per-port verdicts plus a structured summary record.",
							"inputSchema": map[string]interface{}{
								"type": "object",
								"properties": map[string]interface{}{
									"ip": map[string]interface{}{
										"type":        "string",
										"description": "Target IPv4 address to scan",
									},
									"ports": map[string]interface{}{
										"type":        "string",
										"description": "Comma-separated port list. If omitted, scans common AI/ML ports (80,443,22,11434,6333,8000,9200,8080,3000,5000,7860,8188,19530,5601,3306,5432,6379,27017).",
									},
									"fingerprint": map[string]interface{}{
										"type":        "boolean",
										"description": "Run behavioral honeypot fingerprinting. Identifies honeypot by name (cowrie, kippo, honeyd, etc.) using source-derived protocol probes. Recommended when host has ≥400 ports or unusual port distribution.",
									},
									"concurrency": map[string]interface{}{
										"type":        "integer",
										"description": "Max concurrent port probes (default 40).",
									},
								},
								"required": []string{"ip"},
							},
						},
					},
				},
			})

		case "tools/call":
			result, err := handleScan(req.Params)
			if err != nil {
				writeError(enc, req.ID, -32603, err.Error())
				continue
			}
			enc.Encode(rpcResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Result: map[string]interface{}{
					"content": []map[string]interface{}{
						{"type": "text", "text": result},
					},
				},
			})

		default:
			writeError(enc, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
		}
	}
	return scanner.Err()
}

func handleScan(params json.RawMessage) (string, error) {
	var args struct {
		IP          string `json:"ip"`
		Ports       string `json:"ports"`
		Fingerprint bool   `json:"fingerprint"`
		Concurrency int    `json:"concurrency"`
	}
	if err := json.Unmarshal(params, &args); err != nil {
		// params wrapped in {"name":"scan","arguments":{...}}
		var wrapper struct {
			Arguments json.RawMessage `json:"arguments"`
		}
		if err2 := json.Unmarshal(params, &wrapper); err2 != nil {
			return "", fmt.Errorf("invalid params: %v", err)
		}
		if err3 := json.Unmarshal(wrapper.Arguments, &args); err3 != nil {
			return "", fmt.Errorf("invalid arguments: %v", err3)
		}
	}

	if args.IP == "" {
		return "", fmt.Errorf("ip is required")
	}
	if args.Concurrency <= 0 {
		args.Concurrency = 40
	}
	if args.Ports == "" {
		args.Ports = "80,443,22,23,25,11434,6333,8000,9200,8080,3000,5000,7860,8188,19530,5601,3306,5432,6379,27017,2181,9092,1883,4222"
	}

	ports, err := parsePorts(args.Ports)
	if err != nil {
		return "", fmt.Errorf("ports: %v", err)
	}

	// Capture output in a buffer so we can return it as a string.
	var buf bytes.Buffer
	sig := floor.Characterize(args.IP, ports)
	if sig.Active {
		bloom.Add(sig.Issuer, sig.BodySize, sig.HTTPCode)
	} else if bloom.Seen(sig.Issuer, sig.BodySize, sig.HTTPCode) {
		sig.Active = true
	}

	w := &output.BufWriter{W: &buf}

	groups := corpus.GroupPortsByTier(ports)
	var allVerdicts []*verdict.Verdict
	var mu sync.Mutex

	probe := func(tierPorts []int) {
		if len(tierPorts) == 0 {
			return
		}
		sem := make(chan struct{}, args.Concurrency)
		var wg sync.WaitGroup
		for _, port := range tierPorts {
			port := port
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				v := verdict.Classify(args.IP, port, sig, args.Fingerprint)
				mu.Lock()
				allVerdicts = append(allVerdicts, v)
				if v.State == "REAL" || v.State == "UNKNOWN" || v.State == "HONEYPOT" {
					w.WriteVerdict(args.IP, v, sig)
				}
				mu.Unlock()
			}()
		}
		wg.Wait()
	}

	probe(groups["binary"])
	probe(groups["ai-inference"])
	for _, tier := range []string{"ml-platform", "data-infra", "ics-scada", "unknown"} {
		pts := groups[tier]
		if sig.Active {
			for _, port := range pts {
				allVerdicts = append(allVerdicts, &verdict.Verdict{Port: port, State: "FLOOR"})
			}
			continue
		}
		probe(pts)
	}

	output.WriteSummary(w, args.IP, allVerdicts, sig)
	return strings.TrimRight(buf.String(), "\n"), nil
}

func writeError(enc *json.Encoder, id json.RawMessage, code int, msg string) {
	enc.Encode(rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: msg},
	})
}
