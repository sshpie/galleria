# galleria

[![Release](https://img.shields.io/github/v/release/sshpie/galleria)](https://github.com/sshpie/galleria/releases)
[![Go](https://img.shields.io/badge/go-%3E%3D1.21-blue?logo=go)](https://go.dev)
[![MCP](https://img.shields.io/badge/Claude%20Code-MCP%20server-blueviolet?logo=anthropic)](https://modelcontextprotocol.io)

Port Verification Blue Team Asset
## Detects

| Honeypot | Description |
|----------|-------------|
| Cowrie | Fake SSH server, logs attackers |
| Kippo | SSH trap, captures brute-force |
| Honeyd | Emulates networks and services |
| Dionaea | Catches malware via fake services |
| Glastopf | Fake web app, traps scanners |
| OpenCanary | Multi-protocol network trap |
| Canarytokens | Tripwire tokens, detects access |
| Amun | Fake Windows exploit targets |
| Conpot | Fake industrial control systems |
| Krawl | Fake login pages, captures creds |
| express-honeypot | Fake PHP LFI/RFI targets |
| EoHoneypotBundle | Hidden form fields catch bots |
| msurguy/Honeypot | Hidden fields trap Laravel form bots |
| Pasithea | Fake REST API, logs all traffic |
| SAP Cloud Active Defense | Kubernetes-based deception platform |
| FCaptcha | Bot-detection CAPTCHA server |
| GHH | Fake PHP shell, traps dork scanners |
| HellPot | Endless page that traps web crawlers |
| Portspoof | Makes every port look open |

Also identifies 339 AI/ML platforms including:

- **LLM servers** — Ollama, vLLM, LM Studio, LlamaCpp, TGI, LocalAI, LiteLLM, OpenLLM, SGLang, LMDeploy
- **Vector databases** — Qdrant, ChromaDB, Milvus, Weaviate, LanceDB, Pinecone, Marqo, Vald, Vespa, SemaDB
- **AI gateways / proxies** — LiteLLM, Portkey, Helicone, Kong AI Gateway, Javelin, Bifrost
- **MLOps / experiment tracking** — MLflow, Weights & Biases, Aim, Determined AI, Kubeflow, NVFlare
- **Agent frameworks** — LangFlow, LangGraph, AutoGen Studio, CrewAI Studio, Flowise, Dify, AnythingLLM
- **Voice / TTS / ASR** — Whisper, Kokoro TTS, Coqui TTS, Piper, Bark, F5-TTS, XTTS, Vosk
- **Data / storage** — Kafka, Redis, MinIO, Elasticsearch, ClickHouse, MongoDB, Weaviate, Cassandra

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
