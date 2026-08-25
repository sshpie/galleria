# galleria

**galleria** (*Galleria mellonella* — the wax moth) is a Go binary that finds real AI/ML services hidden inside honeypot port noise.

When a honeypot runs portspoof across hundreds of ports, scanners see everything as "open." galleria characterizes the noise floor first, then sends corpus-guided protocol-native probes to determine which ports deviate — and what is actually running there.

## How it works

1. **Noise floor** — probes junk ports, canary ports, decoy paths, cross-port response identity, timing uniformity, and malformed HTTP verbs to characterize the catch-all signature
2. **Priority probes** — uses an embedded corpus of 339 AI/ML platform fingerprints (from [sshpie/tome](https://github.com/sshpie/tome)) to select the right probe path for each port
3. **Deviation detection** — any response that differs in size or code from the noise floor is a candidate
4. **Protocol-native verification** — binary protocols (Redis PING, Memcached stats) and typed AI services (Ollama, Qdrant, Chroma) bypass HTTP floor matching entirely
5. **Honeypot fingerprinting** — when `--fingerprint` is set, behavioral probes run on every candidate to identify and classify deceptive infrastructure

## LLM / Claude Code integration (MCP)

galleria ships a built-in MCP server. Once configured, any LLM with Claude Code can just say **"use galleria to scan 47.123.220.240"** and it runs.

**1. Install galleria:**
```bash
go install github.com/sshpie/galleria@latest
```

**2. Add to your Claude Code MCP config** (`~/.claude/mcp.json` or via `claude mcp add`):
```json
{
  "mcpServers": {
    "galleria": {
      "command": "galleria",
      "args": ["mcp"]
    }
  }
}
```

Or via CLI:
```bash
claude mcp add galleria -- galleria mcp
```

**3. Use it:**
```
You: scan 47.123.220.240 with galleria, fingerprint mode
Claude: [calls galleria.scan({ip: "47.123.220.240", fingerprint: true})]
        → "port 22: HONEYPOT [kippo/95%] — K_C4: Protocol mismatch ASCII response"
        → "port 11434: REAL [ollama] — UNAUTH"
```

The `scan` tool accepts: `ip` (required), `ports` (comma-separated, defaults to common AI/ML ports), `fingerprint` (bool), `concurrency` (int).

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

JSONL to stdout (or `--out` file). Progress to stderr. The last stdout line is always a structured `summary` record — LLM agents should parse this for aggregate verdicts.

**Per-port record** (state = REAL / UNKNOWN / HONEYPOT — FLOOR ports are counted but not emitted):
```json
{"ts":"2026-08-25T22:00:00Z","ip":"192.0.2.1","port":11434,"state":"REAL","platform":"ollama","auth_off":true,"evidence":"{\"models\":[...]}","floor":{"active":true,"body_size":259,"http_code":200,"how_detected":"junk-port"}}
```

**Honeypot record** (with named type and confidence):
```json
{"ts":"2026-08-25T22:01:00Z","ip":"47.123.220.240","port":22,"state":"HONEYPOT","honeypot_type":"kippo","confidence":95,"evidence":"SSH K_H1: Kippo default banner (kippo.cfg.dist:139) + K_C4:protocol-mismatch-ascii"}
```

**Summary record** (always last line, `type = "summary"`, useful for LLM agents):
```json
{"type":"summary","ts":"2026-08-25T22:01:05Z","ip":"47.123.220.240","floor_active":true,"floor_how":"junk-port","real":0,"unknown":0,"honeypot":3,"floor":412,"honeypot_ids":[{"port":22,"honeypot_type":"kippo","confidence":95,"evidence":"..."},{"port":23,"honeypot_type":"cowrie","confidence":90,"evidence":"..."}]}
```

**States:**

| State | Meaning |
|-------|---------|
| `REAL` | Protocol-native probe confirmed a live service; corpus match found |
| `UNKNOWN` | Response deviates from floor but no corpus marker matched |
| `FLOOR` | Response matches catch-all signature; portspoof |
| `HONEYPOT` | Behavioral fingerprinting identified deceptive infrastructure |

## JSON Schema (for LLM tool use)

galleria is designed to be called by LLM agents and AI pipelines. Every field is machine-readable and self-describing.

**Per-port record fields:**

| Field | Type | Description |
|-------|------|-------------|
| `ts` | string (RFC3339) | Probe timestamp |
| `ip` | string | Target IP |
| `port` | int | Port number |
| `state` | string | `REAL` / `UNKNOWN` / `HONEYPOT` |
| `platform` | string | Matched corpus platform (e.g. `ollama`, `qdrant`) |
| `auth_off` | bool | True if no authentication observed on a REAL service |
| `evidence` | string | Human + LLM readable explanation of the verdict |
| `issuer` | string | TLS issuer common name, if any |
| `honeypot_type` | string | Named honeypot software (`cowrie`, `kippo`, `honeyd`, etc.) |
| `confidence` | int | 0–100 confidence in honeypot identification |
| `floor.active` | bool | True if portspoof floor was detected |
| `floor.how_detected` | string | Which floor-detection stage fired |
| `floor.body_size` | int | Catch-all response body size in bytes |
| `floor.http_code` | int | Catch-all HTTP status code |

**Summary record fields (`type = "summary"`):**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"summary"` — use to identify the final record |
| `ip` | string | Target IP |
| `floor_active` | bool | Whether portspoof floor was detected |
| `floor_how` | string | Floor detection method (`junk-port`, `canary`, `decoy-path`, `cross-port`, `timing`, `malformed-verb`) |
| `real` | int | Count of REAL ports |
| `unknown` | int | Count of UNKNOWN ports |
| `honeypot` | int | Count of HONEYPOT ports |
| `floor` | int | Count of FLOOR (portspoof) ports |
| `honeypot_ids` | array | Named honeypots: `[{port, honeypot_type, confidence, evidence}]` |

**LLM usage pattern:**
```bash
# Pipe all output and ask an LLM to analyze
galleria 47.123.220.240 --ports "$(cat ports.txt | tr '\n' ',')" --fingerprint | \
  claude "Is this host a real AI/ML deployment or a honeypot? What software is running?"

# Parse summary record only
galleria 47.123.220.240 --ports 22,23,80,443 --fingerprint | \
  grep '"type":"summary"' | jq .
```

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
| **S6** Vetterl probe | Send malformed packet `0xDEADBEEF` — Cowrie drops silently; Kippo sends ASCII; real SSH sends binary `SSH_MSG_DISCONNECT` | Vetterl 2018 |

Each matched signal raises confidence. H2+H3 together reach 90%. S6 adds a further boost.

### Kippo SSH fingerprinting (`--fingerprint`, port 22/2222/2200)

Signals derived from static analysis of [desaster/kippo](https://github.com/desaster/kippo) source code (Cowrie's predecessor). Runs on the same persistent connection as Cowrie probes — the Vetterl probe is a three-way discriminator.

| Signal | Method | Source |
|--------|--------|--------|
| **K_H1** Banner | Default `SSH-2.0-OpenSSH_5.1p1 Debian-5` (2008 release) | `kippo.cfg.dist:139` / `ssh.py:116` |
| **K_H2** Null padding | KEXINIT null padding bytes (same Twisted SSHServerTransport bug as Cowrie) | `kippo/core/ssh.py` (Twisted) |
| **K_M4** Kex mismatch | KEXINIT advertises `curve25519-sha256`, `ecdh-sha2-nistp256` (added 2013+) on a 2008-vintage banner | `ssh.py:128-131` |
| **K_C4** Vetterl probe | Malformed packet → raw ASCII `"Protocol mismatch.\n"` (not binary `SSH_MSG_DISCONNECT`) | `ssh.py:203-219` |

K_C4 is a definitive Kippo discriminator — zero false positives. K_M4 (ancient banner + modern KEX) confirms the Twisted fingerprint without triggering auth.

### Honeyd fingerprinting (`--fingerprint`, HTTP ports)

Signals derived from static analysis of [DataSoft/Honeyd](https://github.com/DataSoft/Honeyd) source code.

| Signal | Method | Source |
|--------|--------|--------|
| **H21** Open-no-service | TCP connects fully, HTTP request sent, zero bytes returned (vs LaBrea: blocks before send) | `honeyd.c:1440-1443` |
| **C3/H9** SimpleHTTPServer | `Server: BaseHTTP/0.3 Python/2.x` in response header | `webserver/server.py` |
| **C3/H9** Directory listing | `<title>Directory listing for` in response body | `webserver/server.py:69-76` |
| **C8** Fork latency | TCP connect <3ms but time-to-first-byte 5-35ms (fork+exec overhead) — supplementary signal | `honeyd.c:1502` |
| **HTTP IIS emulation** | `Server: Microsoft-IIS/4.0` or `/5.0` (2000-2003 vintage) | Honeyd personality layer |
| **HTTP Apache emulation** | `Server: Apache/1.3.x` or `Apache/2.0.x` (Specter/Honeyd presets) | Honeyd personality layer |

Note: TCP window = 16000 (C6) and TSecr = 0 (C7) require raw socket access and are not implemented in the current probe suite — they require CAP_NET_RAW or equivalent.

### Telnet fingerprinting (`--fingerprint`, port 23)

| Signal | Method |
|--------|--------|
| **S5** NEW-ENVIRON | Send `IAC DO NEW-ENVIRON` (0xFF 0xFD 0x27) — Cowrie responds `IAC WILL NEW-ENVIRON`; real telnetd sends WONT or ignores |
| IAC negotiation absent | Cowrie sends login prompt without any IAC negotiation; real telnetd negotiates terminal options first |

### SMTP fingerprinting (`--fingerprint`, ports 25/465/587/2525)

Minimal honeypots disconnect with `503` immediately. Real SMTP servers send `220` followed by EHLO capabilities. galleria sends EHLO and checks for multi-line capability response.

### FTP fingerprinting (`--fingerprint`, port 21)

Sends `SYST` after banner. Real FTP reports OS type (`UNIX Type: L8`). Honeyd and Specter emulators often return implausible or contradictory OS strings that don't match the banner.

### Dionaea fingerprinting (`--fingerprint`, ports 21/1883/8883/5060/5061/11211)

Signals derived from static analysis of [DinoTools/DionaeaFR](https://github.com/DinoTools/DionaeaFR) and the Dionaea source tree. Each probe is a single protocol exchange — no auth required.

#### SIP (ports 5060/5061)

| Signal | Method | Source |
|--------|--------|--------|
| **H21** Hardcoded nonce | REGISTER → `WWW-Authenticate: Digest nonce="foobar123"` — never rotates, globally unique | `sip/__init__.py:813,829` |
| **C9** No-auth INVITE | INVITE accepted without 401 challenge; auth handler has a `# TODO` comment | `sip/__init__.py:297-299` |

SIP H21 is a definitive 99%-confidence discriminator — no real SIP server uses a hardcoded nonce.

#### MQTT (port 1883/8883)

| Signal | Method | Source |
|--------|--------|--------|
| **M20** CONNACK 0x00 | Send CONNECT with deliberately wrong credentials; Dionaea returns CONNACK return code 0x00 (accepted). Real brokers return 0x04 (bad user/pass) or 0x05 (not authorized) | `mqtt/mqtt.py:140-141` |

#### Memcache (port 11211)

| Signal | Method | Source |
|--------|--------|--------|
| **Emulation gap** | Pipeline SET then GET in one connection: SET returns `STORED`, GET returns `END` (no VALUE) — values are not retained in Dionaea's Memcache emulation | `memcached.py` (emulated protocol) |

#### FTP (port 21)

| Signal | Method | Source |
|--------|--------|--------|
| **L13** Static banner | `"Welcome to the ftp service"` — hardcoded, never customized | `ftp.py` banner string |
| **L13** Any-creds-accepted | USER + any PASS → 231+230 (logged in) regardless of credentials | `ftp.py:284-299` |

### LaBrea tarpit detection (`--fingerprint`, ports 21/22/23/25/110)

TCP connect accepted but zero bytes received within 2 seconds on a first-speaker port = LaBrea tarpit. Logged as `portspoof` type at 75% confidence.

### HTTP behavioral probes (`--fingerprint`)

| Signal | Method |
|--------|--------|
| Ancient version strings | `Apache/1.3`, `IIS/4.0`, `IIS/5.0` in `Server:` header |
| Header typos | `Conent-Length`, `X-Powored-By`, `Cotent-Type` |
| Content-Length mismatch | Declared `Content-Length` differs from actual body by >50 bytes |
| OS contradiction | `Windows` in banner + `Apache` in header, or `Linux` + `IIS` |

### Named honeypot identification

galleria matches behavioral signals against source-code-derived signatures to name the specific honeypot software. The output `honeypot_type` field and `evidence` string report both the name and which signals fired.

| Type | Identified by | Confidence |
|------|--------------|-----------|
| `cowrie` | H1 banner (6.0p1), H2 KEXINIT null padding, H3 cipher list (blowfish-cbc), S6 silent drop on malformed packet | 85–95% (multi-signal) |
| `kippo` | K_H1 banner (5.1p1), K_H2 null padding, K_M4 modern kex on 2008 banner, K_C4 ASCII "Protocol mismatch." on malformed packet | 80–95% (K_C4 alone = 95%) |
| `honeyd` | H21 silent-accept, SimpleHTTPServer/BaseHTTP header, directory listing, fork latency, IIS 4.0/5.0 HTTP emulation, Apache 1.3/2.0 emulation, SSH-1.99 banner, static Telnet vendor banners, OS contradiction | 62–78% (multi-signal) |
| `dionaea` | SIP nonce="foobar123" (hardcoded; 99%), FTP static banner / any-creds-accepted, MQTT CONNACK 0x00 with wrong creds, Memcache SET→STORED / GET→END (values not retained) | 88–99% per signal |
| `opencanary` | `opencanary` string in HTTP response, nginx serving Apache "It works!" body | 65–80% |
| `glastopf` | `glastopf` string in HTTP response | 95% |
| `portspoof` | Floor detection (junk-port / canary / decoy-path / cross-port / timing / malformed-verb), SMTP 503, FTP rare SYST OS | 75–85% |
| `generic-python` | Python traceback / SyntaxError / NameError from C/Java syntax probes, misspelled HTTP headers | 85–90% |

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
      --all-tiers          Probe all tiers even when floor is confirmed (exhaustive)

Subcommands:
  mcp                      Start MCP server (stdio) for LLM/Claude Code tool use
```
