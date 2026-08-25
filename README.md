# galleria

Go binary that separates real AI/ML services from honeypot port noise. When a honeypot runs portspoof across hundreds of ports, scanners see everything as open. galleria characterizes the noise floor first, then uses protocol-native probes and an embedded corpus of 339 AI/ML platform fingerprints to find what's actually running — and name the honeypot software if it's deceptive infrastructure.

## Install

```bash
go install github.com/sshpie/galleria@latest
```

Or grab a release binary from [releases](https://github.com/sshpie/galleria/releases).

## Usage

```bash
galleria <ip> --ports <port-list> [flags]

# Common patterns
galleria 85.9.205.64 --ports 80,443,8080,11434,6333,9200
galleria 85.9.205.64 --ports "$(cat ports.txt | tr '\n' ',')"
galleria 47.123.220.240 --ports 22,23,80,443,5060,1883 --fingerprint
galleria 192.0.2.1 --ports 80,443 --floor-only
galleria 192.0.2.1 --ports "$(cat ports.txt | tr '\n' ',')" -c 80 --out findings.jsonl

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

**Per-port record:**
```json
{"ts":"2026-08-25T22:00:00Z","ip":"192.0.2.1","port":11434,"state":"REAL","platform":"ollama","auth_off":true,"evidence":"...","floor":{"active":true,"body_size":259,"http_code":200,"how_detected":"junk-port"}}
```

**Honeypot record:**
```json
{"ts":"...","ip":"47.123.220.240","port":22,"state":"HONEYPOT","honeypot_type":"kippo","confidence":95,"evidence":"SSH K_C4: ASCII Protocol mismatch response to malformed packet"}
```

**Summary record** (always last line — parse this in LLM pipelines):
```json
{"type":"summary","ts":"...","ip":"47.123.220.240","floor_active":true,"floor_how":"junk-port","real":0,"unknown":0,"honeypot":3,"floor":412,"honeypot_ids":[{"port":22,"honeypot_type":"kippo","confidence":95,"evidence":"..."}]}
```

**States:**

| State | Meaning |
|-------|---------|
| `REAL` | Protocol-native probe confirmed a live service |
| `UNKNOWN` | Response deviates from floor; no corpus marker matched |
| `FLOOR` | Response matches catch-all signature (portspoof) |
| `HONEYPOT` | Behavioral fingerprinting identified deceptive infrastructure |

## MCP / LLM integration

galleria ships a built-in MCP server. Any LLM with Claude Code can say "scan 47.123.220.240 with galleria" and it runs natively.

**Setup:**
```bash
claude mcp add galleria -- galleria mcp
```

Or add to `~/.claude/mcp.json`:
```json
{"mcpServers": {"galleria": {"command": "galleria", "args": ["mcp"]}}}
```

**Tool:** `scan` — accepts `ip` (required), `ports`, `fingerprint` (bool), `concurrency`. Returns per-port JSONL + summary record.

**From the shell:**
```bash
# Let an LLM analyze the output
galleria 47.123.220.240 --ports "$(cat ports.txt | tr '\n' ',')" --fingerprint | \
  claude "Is this a real AI deployment or a honeypot?"

# Parse summary only
galleria 47.123.220.240 --ports 22,80,443 --fingerprint | grep '"type":"summary"' | jq .
```

## Honeypot fingerprinting (`--fingerprint`)

### Floor detection (always active)

Six stages run in parallel before per-port probing. First positive wins.

| Stage | Signal |
|-------|--------|
| Junk ports | SYN-ACK on ports 7, 13, 19, 37, 79 — should never be open |
| Canary ports | Probes 64998–64996 — no real service uses these |
| Decoy path | `GET /galleria-decoy-9f3a2c` → 200 means catch-all listener |
| Cross-port | ≥3 of 7 sampled ports return identical body size + HTTP code |
| Timing | Response latency stddev < 15ms across ≥5 ports |
| Malformed verb | `XYZZY-GALLERIA / HTTP/1.1` → 200 (real HTTP returns 400/405/501) |

### Named honeypot identification

All signals are derived from static source analysis of each honeypot project. The `honeypot_type` and `evidence` fields in output report the name and which signals fired.

#### Cowrie (ports 22/2222/2200) — [cowrie/cowrie](https://github.com/cowrie/cowrie)

| Signal | Probe | Source |
|--------|-------|--------|
| H1 Banner | `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` default version string | `factory.py:44` |
| H2 Null padding | KEXINIT padding bytes all zero; real OpenSSH randomizes | `transport.py:229` |
| H3 Cipher list | Includes `blowfish-cbc`/`cast128-cbc` removed in OpenSSH 6.7 | `factory.py:144-154` |
| S6 Vetterl probe | Malformed `0xDEADBEEF` packet → silent drop (Cowrie) vs ASCII response (Kippo) vs binary `SSH_MSG_DISCONNECT` (real) | Vetterl 2018 |

Confidence: 85–95% multi-signal; S6 silent drop alone = 90%.

#### Kippo (ports 22/2222/2200) — [desaster/kippo](https://github.com/desaster/kippo)

| Signal | Probe | Source |
|--------|-------|--------|
| K_H1 Banner | `SSH-2.0-OpenSSH_5.1p1 Debian-5` (2008 vintage) | `kippo.cfg.dist:139`, `ssh.py:116` |
| K_H2 Null padding | KEXINIT null padding — Twisted SSHServerTransport bug | `kippo/core/ssh.py` |
| K_M4 Kex mismatch | KEXINIT advertises `curve25519-sha256` (2013+) on 2008-vintage banner | `ssh.py:128-131` |
| K_C4 Vetterl probe | Malformed packet → raw ASCII `"Protocol mismatch.\n"` instead of binary disconnect | `ssh.py:203-219` |

K_C4 is definitive — zero false positives. Confidence: 80–95% (K_C4 alone = 95%).

#### Honeyd (HTTP ports) — [DataSoft/Honeyd](https://github.com/DataSoft/Honeyd)

| Signal | Probe | Source |
|--------|-------|--------|
| H21 Open-no-service | TCP handshake completes, HTTP sent, zero bytes returned | `honeyd.c:1440-1443` |
| C3/H9 SimpleHTTPServer | `Server: BaseHTTP/0.3 Python/2.x` header | `webserver/server.py` |
| C3/H9 Directory listing | `<title>Directory listing for` in body | `webserver/server.py:69-76` |
| C8 Fork latency | TCP connect <3ms, TTFB 5–35ms (fork+exec overhead) | `honeyd.c:1502` |
| IIS emulation | `Server: Microsoft-IIS/4.0` or `/5.0` (2000-2003 vintage) | Honeyd personality layer |
| Apache emulation | `Server: Apache/1.3.x` or `Apache/2.0.x` (excl. 2.0.48 — that's Glastopf) | Honeyd personality layer |

Confidence: 62–78% (H21 = 72%; multi-signal combinations higher).

#### Dionaea (ports 21/1883/5060/5061/8883/11211) — [DinoTools/DionaeaFR](https://github.com/DinoTools/DionaeaFR)

| Protocol | Signal | Probe | Source |
|----------|--------|-------|--------|
| SIP | Hardcoded nonce | REGISTER → `WWW-Authenticate: Digest nonce="foobar123"` — never rotates | `sip/__init__.py:813,829` |
| SIP | No-auth INVITE | INVITE accepted without 401 challenge | `sip/__init__.py:297-299` |
| MQTT | CONNACK 0x00 | CONNECT with wrong creds → accepted (real brokers: 0x04/0x05) | `mqtt/mqtt.py:140-141` |
| Memcache | Emulation gap | SET → `STORED`, GET → `END` (values not retained) | `memcached.py` |
| FTP | Static banner | `"Welcome to the ftp service"` — hardcoded, never customized | `ftp.py` |
| FTP | Any-creds-accepted | USER + any PASS → 231+230 regardless of credentials | `ftp.py:284-299` |

SIP nonce = 99% confidence (globally unique, hardcoded). Other signals: 88–95%.

#### Glastopf (HTTP ports) — [mushorg/glastopf](https://github.com/mushorg/glastopf)

Definitive single-packet test: `HEAD / HTTP/1.1` → response `HTTP/1.0 ... Server: Apache/2.0.48 ` (trailing space).

| Signal | Probe | Source |
|--------|-------|--------|
| G1 HTTP/1.0 downgrade | `HEAD /` with `HTTP/1.1` → response starts `HTTP/1.0` | `handler.py:47` hardcoded |
| G1 Trailing space | `Server: Apache/2.0.48 ` — space after version from `sys_version=' '` | `glastopf.py:265` |
| G2 SQLi prefix | `GET /?id=1'+OR+'1'='1` → body contains `"Invalid query: "` | `responses.xml:6` |
| G3 LFI hardcoded | `GET /?page=/etc/passwd` → body references `vars1.php` regardless of input | `lfi.py:59` |
| G4 Frozen CSRF | Two `/phpmyadmin/` requests → identical token (default arg frozen at import) | `phpmyadmin.py:31` |

G1 combined = 99%. G2 and G3 = 98% each, independent.

#### Summary table

| `honeypot_type` | Protocols | Confidence |
|-----------------|-----------|-----------|
| `cowrie` | SSH | 85–95% |
| `kippo` | SSH | 80–95% |
| `honeyd` | HTTP, TCP | 62–78% |
| `dionaea` | SIP, MQTT, Memcache, FTP | 88–99% |
| `glastopf` | HTTP | 85–99% |
| `opencanary` | HTTP | 65–80% |
| `portspoof` | HTTP, SMTP, FTP | 75–85% |
| `generic-python` | HTTP | 85–90% |

## Corpus

339 AI/ML platform fingerprints embedded at compile time via `go:embed`. Source: [sshpie/tome](https://github.com/sshpie/tome). Includes Ollama, Qdrant, ChromaDB, Milvus, Weaviate, MLflow, Hugging Face inference, Kokoro TTS, and ~330 others. No runtime dependencies.
