# RedisHoneyPot — Security Analysis

**Repo:** https://github.com/cypwnpwnsocute/RedisHoneyPot  
**Type:** Go Redis honeypot — RESP protocol server using gev event loop; serves GET/SET/DEL/EXISTS/KEYS/DBSIZE/CONFIG/INFO  
**Lanes:** 2 (server.go core · config.go + redis.conf + deployment)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 7 |
| MEDIUM | 5 |
| LOW | 5 |
| INFO | 4 |

RedisHoneyPot has two independent pre-auth crash paths via out-of-bounds slice access on the CONFIG command, and a complete absence of AUTH command implementation — the honeypot both accepts all unauthenticated clients and returns an error to AUTH that immediately identifies it as non-Redis. The redis.conf ships five static INFO fields (run_id, master_replid, process_id, uptime, connections) that never change across sessions — any single one is a definitive honeypot fingerprint, and all five are invariant on every `INFO` response.

---

## CRITICAL

### C1 — server.go:158-160 — Panic on bare CONFIG command; remote pre-auth crash

```go
case "config":
    if cmd.Args[1] == "get" && len(cmd.Args) > 2 {
```

`cmd.Args[1]` is accessed unconditionally before the `len(cmd.Args) > 2` guard. When a client sends `CONFIG\r\n` (zero arguments beyond the command name), `cmd.Args` has length 1 and `cmd.Args[1]` panics with index out of range. The same pattern at line 176-177 panics on `CONFIG SET key` (three tokens): `cmd.Args[3]` is accessed with no `>= 4` length check.

**Trigger:** `CONFIG\r\n` or `*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\nfoo\r\n` (no value) — unauthenticated, single packet.  
**Impact:** Remote process crash. Honeypot goes offline silently.

---

### C2 — server.go (entire dispatch) — AUTH command absent; all clients get full unauthenticated access

No `case "auth"` exists in the command switch. `requirepass` in redis.conf is never read or enforced — the `LoadConfig` call at line 29 loads the file but the password field is never consulted in the command handler. Any client can issue SET/GET/KEYS/CONFIG/INFO immediately.

When a standard Redis client (redis-cli, any driver with `auth` configured) sends `AUTH password`, the response is `-ERR unknown command \`AUTH\`, with args beginning with:` — this both breaks any tooling expecting `+OK` or `-WRONGPASS` and exposes the honeypot: real Redis 6.x/7.x never returns "unknown command" for AUTH.

**Trigger:** `AUTH password\r\n` — returns error leaking honeypot identity.  
**Impact:** Authentication model completely absent; interactive probe identifies honeypot in one command.

---

### C3 — redis.conf:18 — Static `run_id` across all sessions; definitive single-field fingerprint

```
run_id = 41be2f14e917b27b95ab0fe58f90d9521661dcd1
```

Real Redis generates a cryptographically random 40-hex `run_id` at each startup. This value is the same on every honeypot deployment, on every connection, across restarts. Any attacker that queries `INFO` and checks `run_id` against this known constant identifies the deployment with 100% certainty. This value is suitable for a Shodan dork (`INFO server` responses indexed by crawlers), a BARE module fingerprint, and an aimap signature.

---

### C4 — redis.conf:124 — Static `master_replid`; second invariant field for dual-oracle detection

```
master_replid = e8ab6fdf17602f25e3aee87612ddaa3919502761
```

Real Redis regenerates `master_replid` on restart and after simulated failover. Static replication ID + static `run_id` forms a two-field fingerprint detectable from a single `INFO replication` response. SLAVEOF/REPLICAOF probes additionally expose it: the replid never shifts after a simulated promotion.

---

### C5 — redis.conf:14 — Static `process_id = 89810`; never increments between restarts or connections

```
process_id = 89810
```

A real Redis process ID changes on every restart. An attacker who queries `INFO server` across two sessions (or across a service restart) sees the same PID. Definitive multi-session honeypot confirmation.

---

## HIGH

### H1 — server.go:94,101,177 — Data race on `hashmap` and `s.Config` under `NumLoops > 1`

```go
s.hashmap.Put(cmd.Args[1], cmd.Args[2])   // SET
v, bool := s.hashmap.Get(cmd.Args[1])     // GET
s.Config.Section("info").NewKey(...)      // CONFIG SET
```

`github.com/emirpasic/gods/maps/hashmap` is documented not thread-safe. `ini.File` mutations (CONFIG SET) and reads (INFO, CONFIG GET) share no lock. With `-num 2+`, gev distributes connections across N event loops in separate goroutines sharing the single `RedisServer` struct. Concurrent SET + GET or CONFIG GET + CONFIG SET triggers unsynchronized map/struct writes — data corruption, potential nil dereference, Go race detector violation.

**Trigger:** `-num 2` (or any multi-loop invocation) with concurrent clients.

---

### H2 — server.go:66 — RESP frame boundary check `== 2` misses partial frames; large multi-bulk OOM

```go
if command.Len() == 2 {
    return
}
```

Skips exactly 2-byte inputs (`\r\n`) only. A 1-byte fragment or any partial RESP multi-bulk header passes to `resp.ReadCommand`. Sending `*999999999\r\n` (large array count with no body) causes the library to attempt allocation proportional to the declared element count before parsing fails. No upper bound on declared array size. Amplified by no connection limit — each parallel connection can send one packet to drive this allocation.

---

### H3 — redis.conf:9 — `multiplexing_api = kqueue`; Darwin-only API on Linux hosts

```
multiplexing_api = kqueue
```

kqueue is macOS/BSD only. Linux Redis always reports `epoll`. Any honeypot deployed on Linux (the standard target and the platform instructed by README) returns `kqueue` on `INFO server` — an immediate platform mismatch fingerprint.

---

### H4 — redis.conf:7 — `os = Darwin 20.3.0 x86_64`; cross-platform contradiction

```
os = Darwin 20.3.0 x86_64
```

Combined with `kqueue`, any TCP stack fingerprint (nmap OS detection, p0f) of the actual Linux host contradicts the Darwin claim. Two-oracle mismatch is a reliable discriminator: the wire protocol says macOS, the IP stack says Linux.

---

### H5 — redis.conf:15-16 — Uptime never increments; single-probe detection

```
uptime_in_seconds = 28
uptime_in_days = 0
```

Real Redis uptime advances with wall-clock time. A 30-second interval between two `INFO server` queries yields identical values. Single-probe session detection without even storing the run_id.

---

### H6 — redis.conf:88-89 — Connection/command counters frozen at initial values

```
total_connections_received = 1
total_commands_processed = 2
```

Real Redis monotonically increments both. An attacker issues `INFO stats` twice; values unchanged = honeypot. Also: `total_connections_received = 1` means the honeypot has "never been connected to before" on every scan hit — implausible for an internet-exposed Redis instance that would have scan traffic.

---

### H7 — config.go:8 — No path validation on config file argument; arbitrary INI file loaded

```go
func LoadConfig(filename string) ...
```

Caller-controlled path, no canonicalization, no allowlist, no chroot check. If the config file path is sourced from a CLI argument or environment variable in a deployment wrapper, a local operator with partial environment control can load an arbitrary INI-parseable file — including system files that happen to be parseable (`/etc/passwd` parses silently with `SkipUnrecognizableLines: true`).

---

## MEDIUM

### M1 — server.go:38-41 — No read/write deadline; no connection limit

No `connection.SetDeadline` in `OnConnect`. An idle TCP session holds an event-loop slot indefinitely. No accept-rate limit or maximum connection count. `hping3 --flood -S <host> -p 6379` or slow-loris connects exhaust the fd quota — honeypot stops accepting connections while silently discarding all capture.

---

### M2 — server.go:43-44 — Dead code: `panic(err)` after `return nil, err`

```go
return nil, err
panic(err)   // unreachable
```

`panic` never executes. Signals the codebase was not reviewed. Any static analysis or coverage tool flags it.

---

### M3 — redis.conf:6 — Version 6.0.10 declared; command coverage matches Redis ~2.x

`redis_version = 6.0.10` but `LPOS`, `GETDEL`, `OBJECT FREQ`, `XADD`, and all Redis 6.0+ commands return "unknown command." A scanner comparing declared version against command availability detects the version-behavior delta — a standard honeypot discriminator.

---

### M4 — redis.conf:72 — RDB save timestamp frozen at 2021; LASTSAVE never advances

```
rdb_last_save_time = 1618106377  # April 2021
```

`BGSAVE` then `LASTSAVE` shows no update. Static epoch combined with `rdb_changes_since_last_save = 0` (never increments) is detectable with two commands.

---

### M5 — go.mod:3 — `go 1.15`; multiple patched CVEs in stdlib

Go 1.15 predates patches for CVE-2021-27918 (encoding/xml XXE, fixed 1.15.9), CVE-2021-3114 (crypto/elliptic invalid-curve, fixed 1.15.8), CVE-2021-33196 (archive/zip DoS, fixed 1.16.5), CVE-2022-24675 (encoding/pem stack overflow, fixed 1.17.9). Any honeypot compiled with 1.15.x carries a vulnerable Go runtime.

---

## LOW

- **server.go:112-113** — `DEL` always returns `+(integer) 1\r\n` regardless of key existence; uses `+` (simple string) instead of `:` (integer type); RESP type mismatch breaks any client that calls `ReadInt()` on the response.
- **redis.conf:14** — `gcc_version = 4.2.1` (Apple LLVM shim, 2011 vintage); no legitimate 2021 Redis build uses gcc 4.2.1; hardens macOS origin fingerprint but also flags as anachronistic.
- **go.mod:9** — `github.com/walu/resp v0.0.0-20141104153306` last committed 2014; no maintenance for 12 years; RESP edge cases (inline commands, pipelining, large bulk strings) may cause undefined parse behavior.
- **README.md:22** — instructs `nohup ./RedisHoneyPot -addr 0.0.0.0:6379` with no firewall guidance; honeypot exposed on all interfaces with no layer-3 gate.
- **go.mod:6** — `github.com/Allenxuxu/gev v0.2.2`; event loop library abandoned ~2021; TLS half-close or RST handling edge cases may cause goroutine leaks under adversarial packet sequences.

---

## INFO

- **redis.conf:50** — `maxmemory = 0`; an attacker issuing mass SET commands consumes all host memory; no eviction policy; honeypot process killed by OOM killer, terminating capture. Missing: `maxmemory 256mb` + `maxmemory-policy allkeys-lru`.
- **server.go:188-190** — default error response uses `"-ERR unknown command \`" + cmd.Name() + "\`, with args beginning with:\r\n"` — omits the argument list appended by real Redis; secondary fingerprint signal on any unimplemented command.
- **redis.conf:13** — `executable = /etc/redis/bin/redis-server`; non-standard path (`/usr/bin/redis-server` is standard); minor tell for operators cross-referencing INFO against host filesystem.
- **redis.conf:87** — intentionally captures FLUSHALL, SLAVEOF, CONFIG; captured logs from prior attacker sessions include their source IPs and full command sequences, potentially exposing other researcher identities in shared log infrastructure.

---

## Fingerprint Table

| Signal | Field | Value | Confidence |
|--------|-------|-------|------------|
| `INFO server` | `run_id` | `41be2f14e917b27b95ab0fe58f90d9521661dcd1` | Definitive |
| `INFO server` | `process_id` | `89810` | Definitive |
| `INFO server` | `multiplexing_api` | `kqueue` | Very High (on any Linux host) |
| `INFO server` | `os` | `Darwin 20.3.0 x86_64` | Very High |
| `INFO server` | `uptime_in_seconds` | `28` (never changes) | Very High |
| `INFO replication` | `master_replid` | `e8ab6fdf17602f25e3aee87612ddaa3919502761` | Definitive |
| `AUTH x` | Error response | `-ERR unknown command \`AUTH\`` | Definitive |
| `GET nonexistent` | Null response | `+(nil)\r\n` instead of `$-1\r\n` | Very High |
| `DBSIZE` | Integer type | `+(integer) N\r\n` instead of `:N\r\n` | High |
| `CONFIG\r\n` | Process behavior | Crash (panic) | Definitive — kills process |

**Minimum detection sequence (2 commands, no auth):**
1. `AUTH x` → `-ERR unknown command` → confirmed non-Redis
2. `INFO server` → `run_id = 41be2f14...` → confirmed RedisHoneyPot

**Crash sequence (1 command):**
1. `CONFIG\r\n` → process panic → honeypot offline
