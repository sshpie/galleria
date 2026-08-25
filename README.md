# galleria

**galleria** (*Galleria mellonella* — the wax moth) is a Go binary that finds real AI/ML services hidden inside honeypot port noise.

When a honeypot runs portspoof across hundreds of ports, scanners see everything as "open." galleria characterizes the noise floor first, then sends corpus-guided protocol-native probes to determine which ports deviate — and what is actually running there.

## How it works

1. **Noise floor** — probes a junk port + decoy path to record the catch-all response signature (byte size, HTTP code, TLS issuer)
2. **Priority probes** — uses an embedded corpus of 339 AI/ML platform fingerprints (from [sshpie/tome](https://github.com/sshpie/tome)) to select the right probe path for each port
3. **Deviation detection** — any response that differs in size or code from the noise floor is a candidate
4. **Protocol-native verification** — for known binary protocols (Redis PING, Memcached stats) and typed AI services (Ollama `/api/tags`, Qdrant `/`, Chroma `/api/v1/heartbeat`), the check bypasses HTTP floor matching entirely

## Install

```bash
go install github.com/sshpie/galleria@latest
```

Or download a release binary.

## Usage

```bash
# Probe a host's known ports from Shodan
galleria 85.9.205.64 --ports 80,443,8080,11434,6333,9200

# Feed ports from a file
galleria 85.9.205.64 --ports "$(cat ports.txt | tr '\n' ',')"

# Pipe from shodan CLI
shodan host 85.9.205.64 -j | jq -r '.ports[]' | tr '\n' ',' | \
  xargs galleria 85.9.205.64 --ports

# Write JSONL to file
galleria 192.0.2.1 --ports 80,443,11434 --out findings.jsonl

# Characterize the noise floor only (no per-port probing)
galleria 85.9.205.64 --ports 80,443 --floor-only

# Higher concurrency for large port lists
galleria 192.0.2.1 --ports "$(cat big-ports.txt | tr '\n' ',')" -c 80
```

## Output

JSONL to stdout (or `--out` file). Summary to stderr.

```json
{"ts":"2026-08-25T22:00:00Z","ip":"192.0.2.1","port":11434,"state":"REAL","platform":"ollama","auth_off":true,"evidence":"{\"models\":[...]}","floor":{"active":true,"body_size":259,"http_code":200}}
```

**States:**

| State | Meaning |
|-------|---------|
| `REAL` | Protocol-native probe confirmed a live service; corpus match found |
| `UNKNOWN` | Response deviates from floor but no corpus marker matched |
| `FLOOR` | Response matches catch-all signature; portspoof |

Only `REAL` and `UNKNOWN` records are written. `FLOOR` results are counted in the summary.

## Corpus

339 AI/ML platform fingerprints are embedded at compile time via `go:embed`. Source: [sshpie/tome](https://github.com/sshpie/tome). No runtime dependencies.

Platforms include: Ollama, Qdrant, ChromaDB, Milvus, Weaviate, Pinecone, MLflow, Hugging Face inference, Kokoro TTS, Whisper ASR, OpenAI-compatible proxies, and ~330 others.

## Flags

```
  -p, --ports string       Comma-separated port list (required)
  -o, --out string         Output file path; - for stdout (default: -)
  -c, --concurrency int    Max concurrent port probes (default: 40)
      --floor-only         Characterize noise floor only, then exit
```
