# pghoney — Security Analysis

**Repo:** https://github.com/betheroot/pghoney  
**Type:** Go PostgreSQL honeypot — captures login credentials and queries via a partial Postgres wire protocol implementation; reports to hpfeeds  
**Lanes:** 2 (server/pgconn/serverutils · hpfeeds/pgpacket/main/deploy)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 9 |
| MEDIUM | 8 |
| LOW | 4 |
| INFO | 4 |

pghoney has two independent remote pre-auth crash paths: a panic on null-prefixed startup packets (slice index `-4`) and a panic on any startup message whose fields have no null terminator (slice index `-1`). The `next()` slice helper crashes on any packet with an attacker-controlled oversized length field. The deployment script fetches `registration.sh` over HTTP with no checksum and sources it as root — full host RCE at install time. The hpfeeds secret is transmitted in cleartext TCP and logged in plaintext on every connection.

---

## CRITICAL

### C1 — serverutils.go:26 — Panic on null-prefixed startup packet; remote pre-auth crash

```go
for i := 0; i < len(buf); i += 4 {
    word := buf[i : i+4]
    if isNullWord(word) {
        return i - numberOfTrailingNulls(buf[i-4:i])  // i=0 → buf[-4:0]
```

First iteration: `i = 0`, `isNullWord(buf[0:4])` returns true for `\x00\x00\x00\x00`, then `buf[0-4:0]` = `buf[-4:0]` — runtime panic: slice bounds out of range. `handleStartup` calls `indexOfLastFilledByte` before any length guard. A single startup packet with four leading null bytes crashes the connection goroutine. If the outer accept loop has no recover, the server process itself terminates.

**Trigger:** `\x00\x00\x00\x00` as the first 4 bytes of any startup packet — single unauthenticated packet.

---

### C2 — pgpacket.go:36-40 — Panic when string field has no null terminator

```go
i := bytes.IndexByte(*b, 0)
if i < 0 {
    log.Error("invalid message format; expected string terminator")
}
s := (*b)[:i]   // i == -1 → panic: slice bounds [:-1]
```

`IndexByte` returns -1 if no null byte is found. Error is logged but execution falls through; `(*b)[:-1]` panics. An attacker sends a startup packet where any string field (username, database, application_name) has no null terminator before the packet boundary. Single-packet pre-auth crash.

---

### C3 — pgpacket.go:44-47 — Panic on oversized length field; any parsed length-prefixed field

```go
func (b *postgresRequest) next(n int) (v []byte) {
    v = (*b)[:n]
    *b = (*b)[n:]
```

`n` is derived from `int32()` (4-byte big-endian read from wire). No bounds check before `(*b)[:n]`. An attacker-controlled length field larger than the remaining buffer causes `(*b)[:n]` to panic. Applies to every length-prefixed field parsed from any incoming packet. `int32()` itself also panics on buffers < 4 bytes (line 15-18).

---

### C4 — deploy-scripts/deploy_pghoney-mhn.sh:14,17 — Supply chain RCE; `registration.sh` fetched over HTTP and sourced as root

```bash
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
. ./registration.sh $server_url $deploy_key "pghoney"
```

`$server_url` comes from `argv[1]` (unquoted, shell metacharacter injection). wget fetches over plaintext HTTP with no checksum or signature verification. `. ./registration.sh` executes the downloaded script as root immediately. A MITM or compromised `$server_url` host delivers arbitrary shell code executing as root on the honeypot host.

---

## HIGH

### H1 — serverutils.go:67 — Hardcoded MD5 auth salt; identical across all connections

```go
buf.bytes([]byte{51, 111, 191, 210})  // 0x336FBFD2
```

Every MD5 challenge uses the identical 4-byte salt. Real PostgreSQL generates a cryptographically random salt per connection. An attacker comparing two consecutive auth challenges identifies the static salt and recognizes the honeypot. Also enables offline rainbow tables: precompute `md5(password + "336fbfd2")` for all common passwords, compare against the captured md5 response without brute force.

---

### H2 — server.go:63-76 — No connection cap; goroutine exhaustion DoS

```go
for {
    conn, err := p.listener.Accept()
    p.waitGroup.Add(1)
    go p.handleRequest(pgConn)
}
```

Every accepted TCP connection spawns an unbounded goroutine. No semaphore, no max_connections parameter, no per-IP rate limit. At default Linux FD limits (~1024), an attacker opens 1,000 simultaneous half-open connections and saturates the process.

---

### H3 — pgconn.go:25 — Wall-clock deadline, not idle timeout; slow-read attack

```go
conn.SetDeadline(time.Now().Add(tcpTimeout))
```

Single absolute deadline set at connection creation. A client sending 1 byte per `(tcpTimeout - 1)` seconds keeps the goroutine alive for the full duration. Proper mitigation is `conn.SetReadDeadline` reset after each successful `Read`. Combined with H2: `goroutines = SYN_rate × tcpTimeout`.

---

### H4 — pgconn.go:47 — Read byte count discarded; partial reads produce zero-padded 512-byte buffers

```go
_, err := pgConn.connection.Read(pgConn.buffer)
```

`n` discarded; positions `k..511` remain zero from prior `resetBuffer` allocation. The startup parser (`indexOfLastFilledByte`) treats zero bytes as trailing padding and computes incorrect `actualLength`, causing spurious `claimedLength != actualLength` errors for legitimate clients delivering data in small TCP segments. Proper: `io.ReadFull`.

---

### H5 — server.go:56-59 — `Close()` cannot signal `Listen()` loop; accept goroutine leaks permanently

```go
func (p *PostgresServer) Close() {
    p.waitGroup.Wait()
    p.listener.Close()
}
```

`Listen()` loops `for {}` with no done-channel. After `listener.Close()`, `Accept()` returns an error each iteration, the loop hits `continue`, and the goroutine never exits. Graceful shutdown is broken.

---

### H6 — server.go:204-213 — Log injection via attacker-controlled password and username

```go
pgConn.logger.WithFields(log.Fields{
    "cleartext_password": fmt.Sprintf("%s", buf.string()),
}).Info("Got cleartext password")
```

Attacker-supplied password bytes written verbatim into logrus structured log field. Embedded newlines, ANSI escape codes, or logrus field separators (e.g., `\n level=error msg=fake`) in the password corrupt log integrity. Same for username at line 175-178. No sanitization at any log call site.

---

### H7 — hpfeeds.go:29-30 — hpfeeds auth secret logged and transmitted in cleartext

```go
hp := hpfeeds.NewHpfeeds(hpfeedsConfig.Host, hpfeedsConfig.Port, hpfeedsConfig.Ident, hpfeedsConfig.Secret)
hp.Log = true
```

`hp.Log = true` enables debug logging of the full hpfeeds exchange including the auth frame carrying `Ident` and `Secret`. `go-hpfeeds` uses plaintext TCP with no TLS option. Both the debug log and the network path transmit credentials in cleartext.

---

### H8 — server.go:83-84 — IPv6 `SplitHostPort` bug; source IP/port wrong for all IPv6 peers

```go
SourceIP:   strings.Split(sourceAddr, ":")[0],
SourcePort: strings.Split(sourceAddr, ":")[1],
```

For IPv6, `RemoteAddr().String()` format is `[::1]:5432`. `strings.Split("[::1]:5432", ":")` returns `["[", "", "1]", "5432"]`. `[0]` = `"["`, `[1]` = `""`. All IPv6 hpfeeds events carry empty/wrong source IP and port — attribution data silently corrupted for dual-stack deployments.

---

### H9 — deploy-scripts/deploy_pghoney-mhn.sh:23-25 — Go 1.8 EOL toolchain fetched without checksum

```bash
curl -O https://storage.googleapis.com/golang/go1.8.linux-amd64.tar.gz
tar -xvf go1.8.linux-amd64.tar.gz
mv go /usr/local
```

Go 1.8 (2017) is EOL with multiple stdlib CVEs. No checksum verification. A MITM delivers a backdoored toolchain.

---

## MEDIUM

- **main.go:80** — `signal.Notify(shutdownSignal)` on unbuffered channel; SIGTERM dropped if goroutine not blocked on receive; `postgresServer.Close()` never called; FD/connection leak on shutdown.
- **main.go:64** — `hpfeedsChannel := make(chan []byte, 1024)`; when hpfeeds broker is down, buffer fills, every handler goroutine blocks on send indefinitely (no `select` with `default`) → service-wide DoS.
- **main.go:58** — `tcpTimeout = time.Duration(config.TcpTimeout)` — zero value (missing config key) means no timeout enforced; slow-loris survives indefinitely.
- **pghoney.conf.sample:12-13** — `"ident":"abc123"`, `"secret":"def567"` — sample credentials shipped in repo; operators using template start in production with defaults accessible to anyone reading the repo.
- **deploy-scripts/deploy_pghoney-mhn.sh:31** — `git clone git@github.com:ajvb/pghoney.git` with no `--branch` + pinned commit; HEAD compromise deploys malicious code automatically.
- **serverutils.go:99-113** — Static error strings `Fpostmaster.c`, `L2005`, `RProcessStartupPacket` — verbatim nmap probe capture; 1-packet probe with invalid startup identifies pghoney with regex match.
- **serverutils.go:83-84** — Attacker-controlled username reflected into wire error response; null-byte truncation in `authErrorResponse`; Postgres error-field prefix bytes in username may corrupt response framing.
- **server.go:95-101** — `log.Infof("Discarded buffer: %s", pgConn.buffer)` — 512 bytes of raw attacker content formatted as `%s` into the Info log on every channel-full event; log injection under sustained load.

---

## LOW

- **pgpacket.go:83-87** — `wrap()` uses `b.pos` which may exceed `len(b.buf)` after `next()` call; `b.buf[b.pos:]` panics on the response-building path.
- **pgpacket.go:59-63** — `int32(n)` on negative `n` wraps to large uint32; wire-level length field corruption on any negative response size.
- **pgconn.go:14** — Fixed 512-byte buffer; PostgreSQL startup messages up to 10,000 bytes per spec; clients sending many parameters are silently truncated.
- **server.go:141-148** — All non-password post-auth messages hit `TODO` branch with no response; client blocks until tcpTimeout fires, doubling goroutine hold time.

---

## INFO

- **serverutils.go:54-68** — Auth type (cleartext vs MD5) is server-wide flag, not per-user; real PostgreSQL selects per `pg_hba.conf`; behavioral divergence fingerprint.
- **server.go:183 (TODO comment)** — Cleartext mode is itself flagged as a fingerprint in the source code; developer acknowledged but did not remediate.
- **pgconn.go:55-57** — `resetBuffer` allocates new `[]byte` on every read loop iteration; GC pressure at high connection rates.
- **deploy-scripts/deploy_pghoney-mhn.sh:35** — `go get || true` silences all dependency fetch errors; partially-built binary deployed silently.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| Startup packet `\x00\x00\x00\x00` → process crash | Active probe | CRITICAL — also DoS |
| MD5 auth salt always `0x336FBFD2` | Compare two challenges | Definitive |
| Error response contains literal `Fpostmaster.c`, `L2005`, `RProcessStartupPacket` | Send invalid startup | Definitive |
| `SELECT 1` → no response (TODO path) | Post-auth query | Very High |
| All cleartext password challenges (no per-user auth mode selection) | Observe auth flow | High |
| Port 5432 with PostgreSQL behavior but static salt | Connect + auth observe | Very High |

**Minimum pre-auth detection sequence:**
1. Connect, send startup with `user=a\x00database=b` (no null terminator on database) → crash OR static salt `0x336FBFD2` on MD5 challenge → confirmed pghoney in one packet
