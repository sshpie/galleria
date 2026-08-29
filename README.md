# galleria

[![Release](https://img.shields.io/github/v/release/sshpie/galleria)](https://github.com/sshpie/galleria/releases)
[![Go](https://img.shields.io/badge/go-%3E%3D1.21-blue?logo=go)](https://go.dev)
[![MCP](https://img.shields.io/badge/Claude%20Code-MCP%20server-blueviolet?logo=anthropic)](https://modelcontextprotocol.io)

Separate honeypots and noise from real services before you act on scan results. Identifies 30 honeypot frameworks by behavioral signature, fingerprints 339 AI/ML platforms, and emits JSONL with confidence scores and evidence strings.

## Where the signatures come from

We audited the source code of every honeypot galleria detects. We found bugs and exploitable errors in all of them. Those bugs are the fingerprints. We identify honeypots by their own mistakes.

The bugs fall into two categories:

**Hardcoded values** — constants embedded in source that no real service produces. Single-packet, pre-auth identification, near-zero false-positive rate:

- MysqlPot (`MysqlDefs.cs`): auth scramble is always 12 bytes of `0x42` (`BBBBBBBBBBBB`). Real MySQL generates a random 20-byte nonce.
- Cowrie (`ssh/factory.py:44`): SSH banner hardcoded to `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`, a 2012 release.
- Cowrie (`ssh/transport.py:229`): KEXINIT packets null-padded. Real OpenSSH uses random padding on all packet types. Detectable passively before any auth attempt.
- pghoney (`serverutils.go:67`): MD5 auth salt is the same hardcoded value on every connection to every deployment.
- sticky_elephant (`postgres_simulator.rb`): backend PID always reported as `666` in ParameterStatus messages. Real PostgreSQL reports the actual OS PID.
- Dionaea (`sip.py`): SIP digest nonce hardcoded to `foobar123` across all deployments.
- Conpot (databus template): SNMP `sysLocation` hardcoded to `"Venus"`; Guardian AST station name hardcoded to `"STATOIL STATION"`.
- OpenCanary (`mssql.py`): NTLM challenge blob contains `thinkst.com` verbatim.
- elastichoney / elasticpot (`main.go`): node UUID, MAC address, and build hash identical across every deployment worldwide.
- Lophiid (`backend.go:626`): `SendStatus` documented as unauthenticated in source. `// SendStatus is not authenticated.` Any host can drain the command queue and register phantom nodes.

**Behavioral bugs** — implementation errors that cause the honeypot to respond differently than the real protocol requires. Detected by sending a sequence of messages and observing the deviation:

- Dionaea Memcache: `SET foo bar` then `GET foo`. Real Memcache returns `VALUE foo`. Dionaea returns `END`. Values not retained because a fresh FakeRedis instance is created per data event.
- Dionaea MQTT: `CONNECT` with garbage credentials. Real brokers return `CONNACK 0x05` (refused). Dionaea returns `CONNACK 0x00` (accepted) unconditionally.
- Dionaea SIP: `INVITE` without `Authorization`. Real SIP servers respond `407 Proxy Authentication Required`. Dionaea accepts it.
- nosqlpot (`redisdeploy.py:75`): `AUTH` missing from the command dispatch table. Every password attempt returns `unknown command 'auth'`. Real Redis returns `-NOAUTH Authentication required`.
- MongoDB-HoneyProxy: no OP_MSG handler. Message dropped silently. Real MongoDB responds.
- OpenCanary MSSQL (`mssql.py:129`): `bytes.find(str)` raises `TypeError` in Python 3 on the first valid TDS PRELOGIN packet. Handler crashes before logging anything.
- sticky_elephant (`handler/handshake.rb`): `authenticate()` calls `send_authentication_ok` without checking the password. Every credential, including random garbage, is accepted.
- Honeyd FTP: `SYST` returns `Windows_NT` on Linux hosts.

Full findings, file paths, line numbers, and exploit chains: [`docs/honeypot-research/`](docs/honeypot-research/).

## How it works

galleria runs two stages on every host:

**1. Noise floor characterization** — five concurrent probes determine whether the host is running Portspoof or a similar catch-all:
- Junk-port probe (ports 7, 13, 19, 37, 79 — no real service uses these)
- Canary-port probe (64996-64998 — portspoof listens everywhere, real hosts RST)
- Decoy path probe (`/galleria-decoy-9f3a2c` — catch-all returns 200, real services 404)
- Cross-port sampling + timing uniformity (stddev < 15ms across ports = one process handling all)
- Malformed HTTP verb (`XYZZY-GALLERIA`) — portspoof returns 200, real HTTP returns 400/405

Once the floor is confirmed, all HTTP-tier ports are marked `FLOOR` without probing. Binary protocols (Redis, MQTT, Modbus, SIP, MongoDB) bypass the floor. Portspoof speaks HTTP and cannot fake binary wire protocol.

**2. Per-port classification** — each port runs against a priority-tiered probe set:
- Binary protocols: native wire-protocol dialogs (PING/PONG, CONNACK, INVITE, OP_MSG)
- AI/ML corpus: 339-platform embedded JSON, marker-matched response probes
- Honeypot fingerprinters: static identifiers and behavioral invariants from source analysis
- `--fingerprint` mode: multi-step behavioral probes (SET→GET memory retention, garbage-credential auth, protocol depth tests)

## Detects

| Honeypot | Key fingerprint | Research |
|----------|----------------|----------|
| Cowrie | `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` banner; KEXINIT null padding | [analysis](docs/honeypot-research/cowrie-security-analysis.md) |
| Kippo | Same SSH lineage as Cowrie; management console bound to all interfaces, no auth | [analysis](docs/honeypot-research/kippo-security-analysis.md) |
| Honeyd | FTP `SYST` returns `Windows_NT` on non-Windows hosts | [analysis](docs/honeypot-research/honeyd-security-analysis.md) |
| Dionaea | Memcache SET→GET state loss; MQTT CONNACK unconditional; SIP nonce `foobar123` | [analysis](docs/honeypot-research/dionaea-security-analysis.md) |
| Glastopf | 200 on any path with uniform body; caught by floor decoy-path probe | [analysis](docs/honeypot-research/glastopf-security-analysis.md) |
| OpenCanary | MySQL capability bytes `0xff 0xf7 0x08 0x02`; MSSQL `thinkst.com` in NTLM blob | [analysis](docs/honeypot-research/opencanary-security-analysis.md) |
| Canarytokens | Kubeconfig cluster name always `k8s-prod-cluster`; MCP JWE default key | [analysis](docs/honeypot-research/canarytokens-security-analysis.md) |
| Amun | Lotus Domino IMAP banner; POP3 220 instead of +OK; VNC missing trailing `\n` | [analysis](docs/honeypot-research/amun-security-analysis.md) |
| Conpot | SNMP `sysLocation="Venus"`; Guardian AST `"STATOIL STATION"`; Modbus FC17 stub | [analysis](docs/honeypot-research/conpot-security-analysis.md) |
| Krawl | Login page structure markers | [analysis](docs/honeypot-research/krawl-security-analysis.md) |
| express-honeypot | PHP error page fingerprint on LFI probe | [analysis](docs/honeypot-research/express-honeypot-security-analysis.md) |
| EoHoneypotBundle | Hidden honeypot field naming conventions | [analysis](docs/honeypot-research/EoHoneypotBundle-security-analysis.md) |
| msurguy/Honeypot | Hidden Laravel form field pattern | [analysis](docs/honeypot-research/honeypot-msurguy-security-analysis.md) |
| Pasithea | HTTP 200 + `<h1>404 Not Found</h1>` body on port 8082 | [analysis](docs/honeypot-research/pasithea-security-analysis.md) |
| Nodepot | WordPress response markers + Node.js server header | [analysis](docs/honeypot-research/nodepot-security-analysis.md) |
| Lophiid | goja JS engine response structure; `SendStatus` unauthenticated (documented in source) | [analysis](docs/honeypot-research/lophiid-security-analysis.md) |
| RedisHoneyPot | Static `run_id`; absent AUTH command; RESP type mismatch | [analysis](docs/honeypot-research/RedisHoneyPot-security-analysis.md) |
| pghoney | MD5 auth salt identical on every connection | [analysis](docs/honeypot-research/pghoney-security-analysis.md) |
| nosqlpot | AUTH returns `unknown command 'auth'`; INFO always reports 1 command | [analysis](docs/honeypot-research/nosqlpot-security-analysis.md) |
| sticky_elephant | `pid=666` in ParameterStatus; every password accepted unconditionally | [analysis](docs/honeypot-research/sticky_elephant-security-analysis.md) |
| SAP Cloud Active Defense | Keycloak fingerprint + clone-app HTTP markers | [analysis](docs/honeypot-research/cloud-active-defense-security-analysis.md) |
| FCaptcha | CAPTCHA challenge response structure on port 3000 | [analysis](docs/honeypot-research/FCaptcha-security-analysis.md) |
| GHH | Static PHP shell UI markers on dork paths | [analysis](docs/honeypot-research/ghh-security-analysis.md) |
| HellPot | Absent Content-Length; unbounded transfer size | [analysis](docs/honeypot-research/hellpot-security-analysis.md) |
| MongoDB-HoneyProxy | No OP_MSG handler; drops message silently | [analysis](docs/honeypot-research/MongoDB-HoneyProxy-security-analysis.md) |
| elastichoney | Hardcoded node UUID + MAC + build hash across all deployments | [analysis](docs/honeypot-research/elastichoney-security-analysis.md) |
| elasticpot | Same hardcoded node UUID as elastichoney (Green Goblin config) | [analysis](docs/honeypot-research/elasticpot-security-analysis.md) |
| MysqlPot | Auth scramble always `BBBBBBBBBBBB` (0x42 * 12), single-packet pre-auth ID | [analysis](docs/honeypot-research/MysqlPot-security-analysis.md) |
| mysql-honeypotd | `thread_id` starts at 0, increments sequentially | [analysis](docs/honeypot-research/mysql-honeypotd-security-analysis.md) |
| Portspoof | Makes every port look open | floor characterization stage |

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

Release binaries: [releases](https://github.com/sshpie/galleria/releases).

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

JSONL to stdout (or `--out`). Progress to stderr. Last line is always a `summary` record.

```json
{"ts":"...","ip":"47.123.220.240","port":22,"state":"HONEYPOT","honeypot_type":"cowrie","confidence":95,"evidence":"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2 (2012 release)"}
{"ts":"...","ip":"47.123.220.240","port":6379,"state":"REAL","platform":"redis","auth_off":true,"evidence":"Redis PING->+PONG"}
{"ts":"...","ip":"47.123.220.240","port":80,"state":"FLOOR","evidence":"portspoof floor via=canary code=200 size=1842"}
{"type":"summary","ts":"...","ip":"47.123.220.240","floor_active":true,"real":1,"unknown":0,"honeypot":1,"floor":412,"honeypot_ids":[{"port":22,"honeypot_type":"cowrie","confidence":95}]}
```

States: `REAL` / `UNKNOWN` / `FLOOR` / `HONEYPOT`

## MCP

```bash
claude mcp add galleria -- galleria mcp
```

Exposes a `scan` tool over stdio JSON-RPC 2.0. Accepts `ip`, `ports`, `fingerprint`, `concurrency`.

## Research

Full findings in [`docs/honeypot-research/`](docs/honeypot-research/). Architecture and competitive comparison: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
