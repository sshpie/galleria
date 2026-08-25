# galleria

**galleria** (*Galleria mellonella* — the wax moth) is a Go binary that finds real AI/ML services hidden inside honeypot port noise.

When a honeypot runs portspoof across hundreds of ports, scanners see everything as "open." galleria characterizes the noise floor first, then sends corpus-guided protocol-native probes to determine which ports deviate — and what is actually running there.

## How it works

1. **Noise floor** — probes junk ports, canary ports, decoy paths, cross-port response identity, timing uniformity, and malformed HTTP verbs to characterize the catch-all signature
2. **Priority probes** — uses an embedded corpus of 339 AI/ML platform fingerprints (from [sshpie/tome](https://github.com/sshpie/tome)) to select the right probe path for each port
3. **Deviation detection** — any response that differs in size or code from the noise floor is a candidate
4. **Protocol-native verification** — binary protocols (Redis PING, Memcached stats) and typed AI services (Ollama, Qdrant, Chroma) bypass HTTP floor matching entirely
5. **Honeypot fingerprinting** — when `--fingerprint` is set, behavioral probes run on every candidate to identify and classify deceptive infrastructure

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

# Full honeypot fingerprinting (Cowrie, Honeyd, OpenCanary, portspoof variants)
galleria 47.123.220.240 --ports 22,23,25,80,443,2222 --fingerprint

# Higher concurrency for large port lists
galleria 192.0.2.1 --ports "$(cat big-ports.txt | tr '\n' ',')" -c 80
```

## Output

JSONL to stdout (or `--out` file). Summary to stderr.

```json
{"ts":"2026-08-25T22:00:00Z","ip":"192.0.2.1","port":11434,"state":"REAL","platform":"ollama","auth_off":true,"evidence":"{\"models\":[...]}","floor":{"active":true,"body_size":259,"http_code":200,"how_detected":"junk-port"}}
```

```json
{"ts":"2026-08-25T22:01:00Z","ip":"47.123.220.240","port":22,"state":"HONEYPOT","honeypot_type":"cowrie","confidence":90,"evidence":"H1:banner=SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2; H2:null-padding; H3:cipher=blowfish-cbc"}
```

**States:**

| State | Meaning |
|-------|---------|
| `REAL` | Protocol-native probe confirmed a live service; corpus match found |
| `UNKNOWN` | Response deviates from floor but no corpus marker matched |
| `FLOOR` | Response matches catch-all signature; portspoof |
| `HONEYPOT` | Behavioral fingerprinting identified deceptive infrastructure |

Only `REAL`, `UNKNOWN`, and `HONEYPOT` records are written. `FLOOR` results are counted in the summary.

## Honeypot Fingerprinter

Enable with `--fingerprint`. Runs protocol-behavioral probes to discriminate real services from deceptive infrastructure. Produces a `HONEYPOT` verdict with `honeypot_type` and `confidence` (0–100).

### Floor detection (always active)

Five stages run in parallel before any per-port probing. First positive wins:

| Stage | Method | Signal |
|-------|--------|--------|
| Junk ports | TCP connect to ports 7, 13, 19, 37, 79 | SYN-ACK on a port that should never exist |
| Canary ports | Probe ports 64998–64996 | No real service uses these; portspoof listens everywhere |
| Decoy path | GET `/galleria-decoy-9f3a2c` on web ports | Catch-all returns 200; real services 404 |
| Cross-port | Sample 7 ports; compare body size + code | ≥3 identical responses = one listener |
| Timing | Latency stddev across ≥5 ports | stddev < 15ms = single process routing all traffic |
| Malformed verb | `XYZZY-GALLERIA / HTTP/1.1` | Portspoof returns 200; real HTTP returns 400/405/501 |

Floor detection sets `how_detected` in the output and short-circuits per-port probing for floor-matched ports.

### Cowrie SSH fingerprinting (`--fingerprint`, port 22/2222/2200)

Signals derived from static analysis of [cowrie/cowrie](https://github.com/cowrie/cowrie) source code. All four probes run over a single persistent TCP connection.

| Signal | Method | Source |
|--------|--------|--------|
| **H1** Banner | Default version string `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` | `factory.py:44` |
| **H2** Null padding | KEXINIT packet: padding bytes all zero (real OpenSSH randomizes) | `transport.py:229` |
| **H3** Cipher list | Includes `blowfish-cbc` / `cast128-cbc` (removed in real OpenSSH 6.7) | `factory.py:144-154` |
| **S6** Vetterl probe | Send malformed packet `0xDEADBEEF` — real SSH sends `SSH_MSG_DISCONNECT`; Cowrie drops silently | Vetterl 2018 |

Each matched signal raises confidence. H2+H3 together reach 90%. S6 adds a further boost.

### Telnet fingerprinting (`--fingerprint`, port 23)

| Signal | Method |
|--------|--------|
| **S5** NEW-ENVIRON | Send `IAC DO NEW-ENVIRON` (0xFF 0xFD 0x27) — Cowrie responds `IAC WILL NEW-ENVIRON`; real telnetd sends WONT or ignores |
| IAC negotiation absent | Cowrie sends login prompt without any IAC negotiation; real telnetd negotiates terminal options first |

### SMTP fingerprinting (`--fingerprint`, ports 25/465/587/2525)

Minimal honeypots disconnect with `503` immediately. Real SMTP servers send `220` followed by EHLO capabilities. galleria sends EHLO and checks for multi-line capability response.

### FTP fingerprinting (`--fingerprint`, port 21)

Sends `SYST` after banner. Real FTP reports OS type (`UNIX Type: L8`). Honeyd and Specter emulators often return implausible or contradictory OS strings that don't match the banner.

### LaBrea tarpit detection (`--fingerprint`, ports 21/22/23/25/110)

TCP connect accepted but zero bytes received within 2 seconds on a first-speaker port = LaBrea tarpit. Logged as `portspoof` type at 75% confidence.

### HTTP behavioral probes (`--fingerprint`)

| Signal | Method |
|--------|--------|
| Ancient version strings | `Apache/1.3`, `IIS/4.0`, `IIS/5.0` in `Server:` header |
| Header typos | `Conent-Length`, `X-Powored-By`, `Cotent-Type` |
| Content-Length mismatch | Declared `Content-Length` differs from actual body by >50 bytes |
| OS contradiction | `Windows` in banner + `Apache` in header, or `Linux` + `IIS` |

### Honeypot types

| Type | Description |
|------|-------------|
| `cowrie` | Cowrie SSH/Telnet medium-interaction honeypot |
| `opencanary` | OpenCanary network deception framework |
| `honeyd` | Honeyd virtual honeypot daemon |
| `dionaea` | Dionaea malware-capture honeypot |
| `glastopf` | Glastopf web application honeypot |
| `portspoof` | Generic portspoof catch-all (floor-detected) |
| `generic-python` | Python-based DIY honeypot |

## Corpus

339 AI/ML platform fingerprints are embedded at compile time via `go:embed`. Source: [sshpie/tome](https://github.com/sshpie/tome). No runtime dependencies.

Platforms include: Ollama, Qdrant, ChromaDB, Milvus, Weaviate, Pinecone, MLflow, Hugging Face inference, Kokoro TTS, Whisper ASR, OpenAI-compatible proxies, and ~330 others.

## Flags

```
  -p, --ports string       Comma-separated port list (required)
  -o, --out string         Output file path; - for stdout (default: -)
  -c, --concurrency int    Max concurrent port probes (default: 40)
      --floor-only         Characterize noise floor only, then exit
      --fingerprint        Run behavioral honeypot fingerprinting on all candidates
```
