# galleria — Architecture, Build Methodology, and Competitive Position

## What It Does

galleria answers one question before you act on scan results: **which of these ports is real?** It identifies 30 honeypot frameworks by behavioral signature, fingerprints 339 AI/ML platforms via embedded JSON corpus, and emits JSONL with confidence scores and evidence strings. Portspoof floors are characterized once and amortized across all ports — binary protocols (Redis, MQTT, Modbus, SIP) bypass the floor entirely.

---

## How It Was Built

The fingerprint database is sourced from direct static analysis of each honeypot's source code. The 29 analysis files in [`docs/honeypot-research/`](honeypot-research/) are the research input — each one is a structured vulnerability audit across 5 parallel lanes that extracted the behavioral invariants that became galleria's detection signatures. That work was the expensive part. The Go code is the delivery mechanism.

### Research → Signature Pipeline

For each honeypot, the analysis extracted two categories of signal:

**Static identifiers** — values hardcoded in source that a real service would never have:

| Honeypot | Hardcoded value | Source location |
|----------|----------------|-----------------|
| Cowrie | `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` (2012) | `src/cowrie/ssh/factory.py:44` |
| Cowrie | KEXINIT null-padded (real OpenSSH uses random padding) | `transport.py:229-233` |
| OpenCanary/MySQL | Capability bytes `0xff 0xf7 0x08 0x02` in greeting | OpenCanary `mysql.py` |
| MysqlPot | Auth scramble = `BBBBBBBBBBBB` (all 0x42) | `MysqlDefs.cs` |
| mysql-honeypotd | `thread_id` starts at 0, increments sequentially | `mysql-honeypotd` source |
| elastichoney/elasticpot | Identical hardcoded node UUID across all deployments | `main.go:383` |
| pghoney | MD5 auth salt identical on every connection | `serverutils.go:67` |
| sticky_elephant | `pid=666`, fixture row content, static config_file path | `postgres_simulator.rb` |
| Dionaea/SIP | `nonce="foobar123"` hardcoded | `sip.py` |
| Conpot/SNMP | `sysLocation = "Venus"` | databus template |
| Conpot/Guardian AST | `"STATOIL STATION"` hardcoded station name | `guardian_ast_server.py` |
| OpenCanary/MSSQL | `"thinkst.com"` in NTLM challenge blob | `mssql.py` |
| Amun/IMAP | `"Lotus Domino 6.5.4 7.0.2 IMAP4"` banner | `amun/modules/imap` |
| nosqlpot | AUTH command absent — returns `unknown command 'auth'` | `redisdeploy.py:75` |
| Lophiid | `SendStatus` documented unauthenticated; drains command queue | `backend.go:626` |
| SAP Cloud Active Defense | Keycloak fingerprint + clone-app markers | Kubernetes manifests |

**Behavioral invariants** — things a real service does that a honeypot doesn't, or vice versa:

| Honeypot | Behavioral gap | Probe |
|----------|---------------|-------|
| Portspoof | Responds identically on every port including junk ports (7,13,19,37,79) | Canary + decoy path + timing stddev |
| Cowrie | SSH: sends login prompt without IAC negotiation on Telnet port | Telnet IAC negotiation probe |
| Cowrie | KEXINIT carries null padding — passive packet inspection pre-auth | SSH handshake analysis |
| Dionaea/Memcache | SET returns `STORED`, GET returns `END` (values not retained) | SET then GET round-trip |
| Dionaea/MQTT | CONNACK `0x00` (accepted) for any credentials, including random garbage | Garbage-credential CONNECT |
| Dionaea/SIP | Accepts INVITE without challenge — real SIP requires auth | INVITE without Authorization |
| MongoDB-HoneyProxy | No OP_MSG handler — drops the message; real MongoDB responds | OP_MSG probe |
| nosqlpot/Redis | `total_commands_processed` in INFO always reports 1 (FakeRedis per call) | INFO → PING → INFO |
| OpenCanary | MSSQL crashes on first valid TDS PRELOGIN packet (Python 3 type bug) | TDS PRELOGIN |
| MysqlPot | Single-threaded listener — one held connection blocks all subsequent | DoS pattern (passive: sequential thread_id) |
| sticky_elephant | Every password accepted (`send_authentication_ok` unconditionally) | Bad-password attempt |
| Conpot/Modbus | FC17 stub behavior — real PLCs respond to FC17 with system description | Modbus FC17 probe |
| HellPot | Infinite response body; `Content-Length` absent or absurd | Transfer size measurement |
| Glastopf | 200 on any path with consistent body (catch-all PHP error page) | Decoy path + malformed verb |

---

## Code Architecture

```
galleria <ip> --ports <list>
         |
         +- floor.Characterize()          [5 concurrent stages, 12s timeout]
         |    +- stage 1: junk-port probe  (7,13,19,37,79)
         |    +- stage 2: canary-port probe (64996-64998)
         |    +- stage 3: decoy path /galleria-decoy-9f3a2c on web ports
         |    +- stage 4: cross-port sampling + timing stddev (<15ms = portspoof)
         |    +- stage 5: malformed HTTP verb XYZZY-GALLERIA -> expects 400/405, not 200
         |
         +- bloom.Seen()                  [in-memory, 1M-bit, 4-hash FNV]
         |    +- caches floor signatures across multi-host runs
         |
         +- corpus.GroupPortsByTier()     [embedded 339-platform JSON, 5 tiers]
         |    +- binary     -> always probed (Redis, Kafka, MQTT, Modbus, SIP)
         |    +- ai-inference -> always probed (Ollama 11434, Qdrant 6333, Milvus 19530...)
         |    +- ml-platform  -> skipped if floor confirmed (unless --all-tiers)
         |    +- data-infra   -> skipped if floor confirmed
         |    +- ics-scada    -> skipped if floor confirmed
         |
         +- verdict.Classify() [per port, concurrent, semaphore-gated]
              +- binary protocol handlers (Redis/Memcache/MQTT/SIP/MongoDB/Elasticsearch)
              +- per-port honeypot fingerprinters (SSH, Telnet, MySQL, PgSQL, SMTP, FTP...)
              +- floor.Signature.IsFloor() check on HTTP responses
              +- corpus.ProbeTargets() marker matching (response_markers conjunctive)
              +- fingerprint.HTTP() behavioral layer (--fingerprint flag)
```

### Key design decisions

**No external dependencies.** `go.mod` pulls only `cobra` + `pflag`. The 339-platform corpus is compiled into the binary via `//go:embed`. No Python runtime, no YAML parser, no config file at runtime.

**Floor amortization.** Once `floor.Characterize()` confirms a portspoof signature, all remaining HTTP-tier ports are marked `FLOOR` without individual probes. Only binary protocols (which can't be faked by an HTTP catch-all) continue to run. On a Portspoof host with 400 open ports, this cuts probe count from 400 to ~5.

**Bloom filter for batch runs.** The `bloom` package caches `(issuer, bodySize, httpCode)` triples across hosts in a single session. A second host with the same portspoof signature skips `Characterize()` entirely.

**Tier ordering.** `ai-inference` always runs because that's the primary target for this toolchain. `binary` always runs because floor can't fake raw protocol. Everything else gates on floor state.

**Evidence strings.** Every `Verdict` carries an `Evidence` field — the specific response excerpt or probe detail that triggered the classification. Confidence scores are set per-fingerprinter based on signal strength (static value = 90-95; behavioral single-exchange = 70-85; timing only = 50-60).

---

## Comparison to Other Honeypot Fingerprinters

### honeyscore (Shodan)

Shodan's `/labs/honeyscore` returns a 0.0-1.0 probability score. It is:
- Black box — no evidence strings, no per-port breakdown
- HTTP-only — doesn't handle binary protocols (Redis, Modbus, SIP, MQTT)
- No AI/ML corpus — doesn't know what port 11434 or 6333 is
- Single score per host — can't distinguish "port 22 is Cowrie, ports 80-8443 are Portspoof floor, port 6379 is real Redis"
- Rate-limited and API-key gated — unusable for bulk recon

galleria: per-port verdict, evidence string, honeypot type identified, AI/ML platform named, zero external API calls.

### nmap NSE

Nmap's honeypot detection is implicit and fragmented:
- `ssh-hostkey` shows Cowrie's fingerprint only if you know what to look for
- `banner` grabs the SSH version string — you have to manually recognize `OpenSSH_6.0p1 Debian-4+deb7u2`
- No awareness of KEXINIT null-padding, MySQL scramble identity, or PostgreSQL pid=666
- No portspoof floor characterization
- No timing-uniformity detection across ports

galleria encodes the domain knowledge nmap leaves implicit.

### p0f / passive fingerprinters

p0f and similar tools work from captured traffic. They can't do the behavioral tests (SET→GET memory retention, MQTT garbage-credential CONNACK, SIP INVITE without challenge) that distinguish honeypot from real service. p0f OS fingerprinting evaporates against honeypots running on real kernels.

### nuclei honeypot templates

Community nuclei templates check specific honeypot banners. They:
- Run templates one at a time, no floor optimization
- Have no binary protocol support
- Don't perform multi-step behavioral probes (no SET→GET, no KEXINIT analysis)
- Produce findings, not verdicts — no REAL/FLOOR/UNKNOWN/HONEYPOT classification

### What galleria does differently

1. **Floor characterization first.** No other tool amortizes portspoof detection across all ports before probing. Per-port probes against a 400-port portspoof host is exactly what portspoof was designed to waste your time with.

2. **Binary protocol correctness.** Portspoof speaks HTTP. It cannot fake a Redis `+PONG`, a Modbus FC17 response, a SIP 407 challenge, or a MongoDB OP_MSG reply. galleria runs binary-native protocol dialogs — not banner grabs.

3. **Multi-step behavioral probes.** The Dionaea Memcache check is `SET foo bar` → `GET foo` → expect `$3\r\nbar`. A banner grab returns `STORED` and concludes nothing.

4. **Evidence output.** Every verdict includes the specific telltale. `"SSH K_C4: ASCII Protocol mismatch response to malformed packet"` is actionable; a `0.8 honeypot score` is not.

5. **AI/ML corpus co-location.** On the same port set that triggers honeypot checks, galleria also identifies the real AI/ML service if present. You don't run two tools.

6. **MCP integration.** `galleria mcp` exposes the `scan` tool via stdio JSON-RPC 2.0. Claude Code can call it directly: "scan 47.123.220.240 with galleria" → JSONL results in-session.

---

## Evidence Base — Findings Driving the Signatures

The full analysis is in [`docs/honeypot-research/`](honeypot-research/). Summary of the signatures each file produced:

### Cowrie — [`cowrie-security-analysis.md`](honeypot-research/cowrie-security-analysis.md)
8 HIGH, 10 MED, 12 LOW.

- **H1** — `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` at `factory.py:44`. No production server runs a 14-year-old SSH daemon. galleria checks this before any authentication attempt.
- **H2** — KEXINIT null padding at `transport.py:229-233`. Real OpenSSH pads all packets randomly; Cowrie uses null bytes specifically for KEXINIT.
- **H3** — HASSH cipher list mismatch vs. any real OpenSSH version.

Secondary: SSRF via wget (partial RFC-1918 blocklist with gaps), pickle RCE in twisted session files, FD leak on SFTP.

### Kippo — [`kippo-security-analysis.md`](honeypot-research/kippo-security-analysis.md)
4 CRITICAL, 15 HIGH, 18 MED.

- **C1** — `wget.py:132`: real outbound TCP to attacker-supplied URL, zero network filtering. AWS IMDS, internal Redis, local web apps all reachable.
- **C2** — `kippo.tac:59-61`: telnet management console bound to all interfaces, zero auth, immediate full session management on connect.

galleria detection: same SSH version-string and HASSH check as Cowrie (shared lineage); interact console as secondary fingerprint.

### Honeyd — [`honeyd-security-analysis.md`](honeypot-research/honeyd-security-analysis.md)
8 CRITICAL, 22 HIGH, 14 MED. Written in C.

- **C1** — `ui.c:163-173` + `pyextend.c:815-903`: unauthenticated UNIX socket exposes `!` command that eval's arbitrary Python at honeyd's UID.
- **C2** — unknown socket commands fall through to live config parser; `add <template> subsystem "<cmd>"` forks arbitrary binaries immediately.

galleria detection: FTP subsystem returns `"Windows_NT"` from `SYST` on any non-Windows host.

### Dionaea — [`dionaea-security-analysis.md`](honeypot-research/dionaea-security-analysis.md)
10 CRITICAL, 25 HIGH, 24 MED — most findings overall.

- **C1** — `connection_tcp.c:197-216`: VLA on thread stack sized from `SIOCINQ`; attacker fills socket buffer → controlled stack allocation up to 6MB.
- **C3** — `smb.py:166-727`: SMB `NT_CREATE_ANDX`, `WRITE_ANDX`, `TRANSACTION` processed without Session Setup completion. Full IPC$ pre-auth.

galleria detection — four probes:
- Memcache: `SET foo bar` → `GET foo` → `END` (values not retained; fresh FakeRedis per call)
- MQTT: garbage-credential `CONNECT` → `CONNACK 0x00`
- SIP: `INVITE` without `Authorization` → accepted
- SIP nonce: `nonce="foobar123"` hardcoded in `sip.py`

### OpenCanary — [`opencanary-security-analysis.md`](honeypot-research/opencanary-security-analysis.md)
4 CRITICAL, 11 HIGH, 22 MED.

- **C1** — `httpproxy.py:76-80`: `exit(1)` in NTLM handler kills entire process. Single TCP connection, no auth.
- **C2** — `mssql.py:129`: `bytes.find(str)` TypeError on first TDS PRELOGIN packet.

galleria detection — three probes:
- MySQL: capability bytes `0xff 0xf7 0x08 0x02` in server greeting
- MSSQL: `"thinkst.com"` in NTLM challenge blob
- Redis: non-standard auth error string

### Glastopf — [`glastopf-security-analysis.md`](honeypot-research/glastopf-security-analysis.md)
6 CRITICAL, 11 HIGH, 14 MED.

- **C1** — PHP backtick operator bypasses entire sandbox (language construct, not interceptable via `override_function`).
- **C2** — `rfi.py:62-88`: unbounded SSRF proxy with zero network filtering — AWS IMDS, k8s API, internal Redis all reachable.

galleria detection: returns 200 on any path with consistent body; caught by floor characterization decoy path probe before per-port logic runs.

### Lophiid — [`lophiid-security-analysis.md`](honeypot-research/lophiid-security-analysis.md)
10 CRITICAL, 19 HIGH. Most sophisticated honeypot in the set (Go, gRPC, LLM, YARA, PostgreSQL).

- **C1** — `backend.go:626`: `SendStatus` documented unauthenticated in source. Any host can drain command queues and register phantom nodes.
- **C2** — `backend.go:1451`: deferred channel send blocks all handler goroutines when channel full under load.

galleria detection: HTTP response structure from goja JavaScript engine and LLM-generated responses matched by `--fingerprint` behavioral layer.

### elastichoney / elasticpot — [`elastichoney-security-analysis.md`](honeypot-research/elastichoney-security-analysis.md) / [`elasticpot-security-analysis.md`](honeypot-research/elasticpot-security-analysis.md)

- **C3** (elastichoney) — SensorIP fetched over plain HTTP; MITM injects arbitrary source IP, corrupting all hpfeeds attribution.
- **C1** — No HTTP timeouts + no body limit; single large POST OOMs the process.

galleria detection: both hardcode the same node UUID, build hash, and MAC address across all deployments. `GET /` → static `_node.id` match.

### MysqlPot — [`MysqlPot-security-analysis.md`](honeypot-research/MysqlPot-security-analysis.md)
3 CRITICAL, 6 HIGH.

- **C1** — Single-threaded listener with no timeout; one held connection permanently blocks all subsequent.
- **C2** — Process-wide SSL bypass via `ServicePointManager.ServerCertificateValidationCallback`.

galleria detection: auth scramble in MySQL handshake is always `BBBBBBBBBBBB` (12 bytes of `0x42`). Real MySQL generates a cryptographically random 20-byte nonce. Single-packet, pre-auth identification — the most unambiguous static fingerprint in the set.

### pghoney — [`pghoney-security-analysis.md`](honeypot-research/pghoney-security-analysis.md)
4 CRITICAL, 9 HIGH.

- **C1** — `serverutils.go:26`: `buf[-4:0]` panic; remote pre-auth crash via single null-prefixed startup packet.
- **C2** — `pgpacket.go:36-40`: `(*b)[:-1]` panic on any field without null terminator.
- **C4** — `deploy_pghoney-mhn.sh`: fetches `registration.sh` over HTTP, no checksum, sources as root — supply chain RCE.

galleria detection: hardcoded MD5 auth salt, identical across all connections. galleria reads the startup auth challenge and checks the salt against the known default.

### sticky_elephant — [`sticky_elephant-security-analysis.md`](honeypot-research/sticky_elephant-security-analysis.md)
3 CRITICAL, 7 HIGH.

- **C1** — `configuration.rb:16`: `YAML.load_file` without `safe_load`; Psych gadget chain RCE via operator-supplied config path.
- **C2** — `authenticate()` calls `send_authentication_ok` unconditionally; wrong password gets `AuthenticationOk`.
- **C3** — Infinite retry on `EOFError`; 100% CPU per half-closed connection, unbounded thread creation.

galleria detection: `pid=666` in `ParameterStatus` packets after auth. Real PostgreSQL has OS-assigned PIDs.

### nosqlpot — [`nosqlpot-security-analysis.md`](honeypot-research/nosqlpot-security-analysis.md)
1 CRITICAL, 4 HIGH.

- **C1** — `redisdeploy.py:75`: AUTH command absent from dispatch table; all attacker passwords silently discarded.
- Secondary: `-ERR unknown command 'auth'` differs from real Redis error strings.

galleria detection: `PING` → `+PONG` → `AUTH randomgarbage` → check error string. `unknown command 'auth'` = nosqlpot.

### Conpot — [`conpot-security-analysis.md`](honeypot-research/conpot-security-analysis.md)
6 CRITICAL, 18 HIGH. ICS/SCADA (S7comm, Modbus, IEC104, BACnet, SNMP, Guardian AST).

- **C1** — `databus.py:90,98`: `eval()` on XML template data → RCE at init.
- **C2** — XPath injection via HTTP request path; full config extraction.
- **C4** — IPMI pre-session auth bypass via `presession_v2` path; all management commands pre-auth.
- **C5** — Guardian AST: zero auth, full tank telemetry + write commands on TCP connect.

galleria detection — four probes:
- Modbus FC17: known Conpot stub behavior vs. real PLC response
- SNMP `sysLocation`: `"Venus"` hardcoded in databus template
- Guardian AST: `"STATOIL STATION"` in tank inventory response
- S7comm COTP: Conpot's 0x62 stripping behavior differs from real Siemens PLC

### Canarytokens — [`canarytokens-security-analysis.md`](honeypot-research/canarytokens-security-analysis.md)
2 CRITICAL, 9 HIGH.

- **C1** — `frontend/app.py:469`: shared management secret logged on every auth failure.
- **H1** — `MCP_SERVER_SECRET` defaults to `"abcD0123defG4567"` — AES-128-GCM key for MCP JWE; any deployment missing the env var uses the public default.
- **H2** — kubeconfig cluster name always `"k8s-prod-cluster"` — 480-combination username space enables probabilistic canary identification.

---

## Output Format

```json
{"ts":"2026-08-29T09:14:22Z","ip":"47.123.220.240","port":22,"state":"HONEYPOT",
 "honeypot_type":"cowrie","confidence":95,
 "evidence":"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2 (2012 release)"}

{"ts":"2026-08-29T09:14:22Z","ip":"47.123.220.240","port":6379,"state":"REAL",
 "platform":"redis","auth_off":true,"evidence":"Redis PING->+PONG"}

{"ts":"2026-08-29T09:14:22Z","ip":"47.123.220.240","port":80,"state":"FLOOR",
 "evidence":"portspoof floor via=canary code=200 size=1842"}

{"type":"summary","ts":"...","ip":"47.123.220.240",
 "floor_active":true,"real":1,"unknown":0,"honeypot":1,"floor":412,
 "honeypot_ids":[{"port":22,"honeypot_type":"cowrie","confidence":95}]}
```

States: `REAL` / `HONEYPOT` / `FLOOR` / `UNKNOWN`

---

## Install and MCP Registration

```bash
go install github.com/sshpie/galleria@latest

# MCP registration
claude mcp add galleria -- galleria mcp
# -> Claude Code: "scan 47.123.220.240 ports 22,6379,9200,11434 with galleria"
```
