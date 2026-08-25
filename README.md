# galleria

Honeypot detector and AI scanner.

## Detects

- Cowrie
- Kippo
- Honeyd
- Dionaea
- Glastopf
- Portspoof

Also identifies 339 real AI/ML platforms (Ollama, Qdrant, ChromaDB, Milvus, MLflow, and others).

## Install

```bash
go install github.com/sshpie/galleria@latest
```

Or grab a release binary from [releases](https://github.com/sshpie/galleria/releases).

## Usage

```bash
galleria <ip> --ports <port-list> [flags]

galleria 85.9.205.64 --ports 80,443,8080,11434,6333,9200
galleria 47.123.220.240 --ports 22,23,80,443,5060,1883 --fingerprint
galleria 85.9.205.64 --ports "$(cat ports.txt | tr '\n' ',')" -c 80 --out findings.jsonl

# Pipe from shodan
shodan host 85.9.205.64 -j | jq -r '.ports[]' | tr '\n' ',' | xargs galleria 85.9.205.64 --ports
```

## Flags

```
  -p, --ports string       Comma-separated port list (required)
  -o, --out string         Output file path; - for stdout (default: -)
  -c, --concurrency int    Max concurrent port probes (default: 40)
      --floor-only         Characterize noise floor, then exit
      --fingerprint        Behavioral honeypot fingerprinting on all candidates
      --all-tiers          Probe all tiers even when floor is confirmed

Subcommands:
  mcp                      Start MCP server (stdio) for LLM/Claude Code tool use
```

## Output

JSONL to stdout (or `--out`). Progress to stderr. Last stdout line is always a `summary` record.

```json
{"ts":"...","ip":"47.123.220.240","port":22,"state":"HONEYPOT","honeypot_type":"kippo","confidence":95,"evidence":"SSH K_C4: ASCII Protocol mismatch response to malformed packet"}
{"type":"summary","ts":"...","ip":"47.123.220.240","floor_active":true,"real":0,"unknown":0,"honeypot":3,"floor":412,"honeypot_ids":[{"port":22,"honeypot_type":"kippo","confidence":95}]}
```

States: `REAL` / `UNKNOWN` / `FLOOR` / `HONEYPOT`

## MCP / LLM integration

```bash
claude mcp add galleria -- galleria mcp
```

Any LLM with Claude Code can then say "scan 47.123.220.240 with galleria" and it runs natively. Tool `scan` accepts `ip`, `ports`, `fingerprint`, `concurrency`.
