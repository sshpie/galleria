# mysql-honeypotd — Security Analysis

**Repo:** https://github.com/sjinks/mysql-honeypotd  
**Type:** C MySQL honeypot daemon — MySQL wire protocol server; libev event loop; syslog/file logging  
**Lanes:** 2 (L1: dfa.c/connection.c/protocol.c · L2: utils.c/globals.c/Dockerfile/eventloop.c/pidfile.c/log.c)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 4 |
| MEDIUM | 5 |
| LOW | 5 |
| INFO | 3 |

mysql-honeypotd is a mature C codebase with generally solid memory handling, but has a pre-auth integer overflow in the LEI (length-encoded integer) parser that allows attacker-placed bytes to drive auth-flow DFA state; `rand()` seeded with `time(NULL)` for the auth challenge means challenge bytes are predictable within a 1-second window; the Dockerfile's `MINIMALISTIC_BUILD` flag strips the privilege-drop code, shipping a root container; and a blocking `getnameinfo` call in the libev event loop allows single-connection rDNS-stall DoS.

---

## CRITICAL

### C1 — dfa.c:212 — LEI length integer overflow; attacker-placed bytes drive auth-flow DFA

```c
pwd_len = decodeLEI(pos, (size_t)(conn->buffer + conn->size - pos), &bytes);
// bytes=9, pwd_len=UINT64_MAX from 0xFE+8×0xFF in attacker packet
pos += bytes + pwd_len;   // 9 + UINT64_MAX → wraps to 8 on 64-bit
```

Triggered when `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` capability flag is set in the attacker's handshake. A length-encoded integer beginning with `0xFE` signals an 8-byte LE value follows. An attacker sends `0xFE FF FF FF FF FF FF FF FF` — `decodeLEI` returns `UINT64_MAX`, `bytes=9`. The `pos += 9 + UINT64_MAX` addition wraps on `size_t` (64-bit: `UINT64_MAX + 9 = 8`). `pos` advances only 8 bytes. The subsequent bounds check `if (pos > conn->buffer + conn->size)` passes because the wrapped `pos` is within the buffer. When `CLIENT_PLUGIN_AUTH` is also set, `auth_plugin = pos` reads from the attacker-controlled bytes at the wrapped position. `strcasecmp(auth_plugin, "mysql_native_password")` or `"mysql_clear_password"` is decided by attacker-placed data — bypassing the `AuthSwitchRequest` path and routing the DFA along the attacker's chosen state.

No out-of-bounds memory access occurs (downstream `memchr` calls are explicitly bounded), but the authentication decision path is driven by arbitrary attacker data rather than a validated field.

---

## HIGH

### H1 — utils.c:84-90 + globals.c:17 — `rand()` seeded with `time(NULL)`; challenge bytes predictable within 1-second window

```c
// globals.c:17
srand((unsigned int)time(NULL));

// utils.c:84-90
for (size_t i = 0; i < 20; i++) {
    challenge[i] = (uint8_t)(rand() % 255) + 1;
}
```

`rand()` is seeded once at daemon startup with the current Unix timestamp (1-second granularity). An attacker who knows or can estimate the daemon start time (e.g., from the first successful connection, or by observing PID assignment) can reconstruct the PRNG state and predict all 20 challenge bytes for any connection in the current second. Pre-computing all `rand()` sequences for a ±60-second window requires only ~120 PRNG state trials. This allows:

1. **Rainbow table bypass:** Precompute `md5(password + predicted_challenge)` for the predicted challenge; compare against the captured auth response without brute force.
2. **Challenge correlation:** Two connections in the same second produce challenge bytes deterministic from the same seed — a fingerprint confirming daemon start time.

---

### H2 — connection.c:135 — Blocking `getnameinfo` in libev event loop; rDNS-stall DoS

```c
getnameinfo((const struct sockaddr*)&sa, len,
            conn->host, sizeof(conn->host), NULL, 0, 0);
```

`getnameinfo` without `NI_NUMERICHOST` performs a synchronous reverse-DNS lookup on every new connection. libev is single-threaded; this call blocks the entire event loop for the duration of the DNS round-trip. Attacker connects repeatedly from IP ranges with slow or non-existent rDNS (e.g., RFC 1918 space without PTR records). Each connection stalls the loop for the OS resolver timeout (default 5-30 seconds depending on `/etc/resolv.conf`). At 10 connections per 5-second timeout: the event loop is saturated; no other connections are processed.

Fix: pass `NI_NUMERICHOST | NI_NUMERICSERV` to suppress lookup, or use c-ares for async resolution.

---

### H3 — Dockerfile:15-32 — `MINIMALISTIC_BUILD` strips privilege drop; container runs as root permanently

```dockerfile
ARG MINIMALISTIC_BUILD
RUN cmake -DMINIMALISTIC_BUILD=${MINIMALISTIC_BUILD:-OFF} ...
```

The `MINIMALISTIC_BUILD=ON` CMake flag disables `setuid`/`setgid`/`setgroups` calls in the daemon startup sequence (the privilege-drop path from root to a lower-privilege user). The `FROM scratch` base image means there is no system user to drop to at all — the container runs as UID 0 with no alternative. The `scratch` base also removes `/etc/group`, `/etc/passwd`, `/proc`, and `/dev` pseudo-filesystems — there is no security policy layer, no seccomp default, and no AppArmor profile. Any memory corruption that leads to code execution runs as root in a container with no security boundaries short of cgroups.

---

### H4 — eventloop.c:39-44 — No connection count cap; fd exhaustion DoS

```c
w->accept_ev.cb = on_connection;
ev_io_init(&w->accept_ev, on_connection, fd, EV_READ);
ev_io_start(loop, &w->accept_ev);
```

No semaphore, no connection counter, no per-IP rate limit. Each accepted TCP connection allocates a `connection` struct, calls `getnameinfo` (see H2), and registers `EV_READ` watchers. At the default Linux fd limit (~1024), an attacker opens 1,020 half-open connections — the daemon stops accepting. No cleanup timer; goroutines (libev watchers) stay alive until timeout fires. The timeout is configurable but defaults may allow long dwell time.

---

## MEDIUM

### M1 — dfa.c:321-326 — `malloc(0)` on zero-length packet; allocator-defined behavior

```c
conn->size = conn->length & 0x00FFFFFF;  // attacker sets 3-byte length = 0
conn->buffer = malloc(conn->size);        // malloc(0)
if (conn->buffer == NULL) { return 0; }
```

On glibc, `malloc(0)` returns a non-NULL unique pointer; the NULL check passes; `safe_read(fd, ptr, 0)` returns 0 immediately. The connection is terminated cleanly. On other libc implementations, `malloc(0)` returns NULL — also clean. No memory corruption. However, at connection scale, a zero-length flood drives repeated `malloc(0)` / `free()` cycles, inflating allocator metadata. Not a crash, but measurable overhead.

---

### M2 — dfa.c:137-142 — Unbounded username in syslog; no length clamp in `log_access_denied`

```c
my_log(LOG_AUTH | LOG_WARNING,
    "Access denied for user '%s' from %s:%u ...",
    user, conn->ip, ...);
```

`memchr` guarantees null termination within `conn->size`, so no OOB read. However, `user` may be up to ~4080 bytes (4096-byte max packet minus header and mandatory fields). The full username string is forwarded to `syslog()` without a length cap. Impact: syslog backend storage exhaustion; embedded control characters or ANSI sequences in the username corrupt log display. `create_auth_failed` at line 155 uses `%.48s` — the bound exists there but not in `log_access_denied`.

---

### M3 — pidfile.c:74-78 — Lock released before PID write; dual-instance race window

```c
flock(fd, LOCK_EX);    // acquire exclusive lock
// ...
flock(fd, LOCK_UN);    // release — before write_pid on older kernels without OFD locks
write_pid(fd, pid);
```

On Linux kernels that do not support open file description (OFD) locks (`F_OFD_SETLK`), `flock()` is advisory per-file-descriptor, not per-open-file-description. Releasing the lock before `write_pid` opens a race window where a second daemon instance can acquire the lock, read a stale PID, and both instances run concurrently — two honeypots on the same port causes bind failure for one, or worse, both succeed if port reuse is enabled.

---

### M4 — log.c:22-33 — Log injection on `--foreground --no-syslog` path via `\n` in username

```c
if (use_syslog) {
    vsyslog(priority, format, ap);
} else {
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
}
```

When running in foreground mode without syslog, stderr receives the raw log line. An attacker supplies a username of `\n[2026-01-01 00:00:00] SYSTEM: Login succeeded for root` — `vfprintf` writes the embedded `\n`, injecting a synthetic log line. syslog backends typically strip control characters; the foreground stderr path does not.

---

### M5 — protocol.c:43 — `uint16_t` truncation of 3-byte MySQL length field

```c
uint16_t pl_size = (uint16_t)(pkt_size - 4);
store2(result, pl_size);
```

MySQL packet length is a 3-byte LE field. The third byte is implicitly provided by a separate byte in the template. If `pkt_size - 4` exceeds 65535 (possible if `server_ver` is a long string), `pl_size` wraps silently; the stored length is incorrect and the client drops the connection. Operator-controlled `server_ver` content can trigger this silently.

---

## LOW

- **dfa.c:281-283** — Latent NULL-deref on `conn->auth_failed` in `do_auth_asr`; not reachable via current normal code paths, but the missing guard is a maintenance trap.
- **dfa.c:39** — `conn->size` computed by re-parsing own-crafted buffer in `out_of_order` rather than from a constant; any future `create_ooo_error` modification that doesn't update the length field silently produces wrong `conn->size`.
- **byteutils.h:30-43** — `load3` performs a four-byte BE swap on a three-byte-populated value; mathematically correct only because the fourth byte is zero-initialized; not self-evident without the zero-guard invariant in scope.
- **protocol.c:43** — `gcc_version` in the greeting is hardcoded to a static string; combined with `server_version`, version-behavior delta is detectable by any scanner probing both.
- **globals.c:17** — `srand` call at daemon start is not isolated from library initialization order; if any linked library calls `rand()` before the honeypot's `main()` seed, the PRNG state diverges from the expected sequence.

---

## INFO

- **globals.c** — Default `server_version = "8.0.19"` — EOL as of April 2023; thread_id starts at 0 and increments by 1 per connection; real MySQL thread_ids are not sequential from 0 and vary across restarts.
- **CMakeLists.txt** — `MINIMALISTIC_BUILD` is documented in `README` as reducing dependencies; the security implication (disabling privilege drop) is not documented in the `README` or `Dockerfile`.
- **log.c:37** — `vsyslog` format string: callers always pass a format string literal; no attacker-supplied format strings flow to this path in the current codebase. Noted because any future caller that passes user data as the format argument triggers a format string vulnerability.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| Thread ID starts at 0 and increments sequentially | Two consecutive connections | Very High |
| Challenge bytes predictable from observed start time | PRNG prediction (60-second window) | Very High |
| `CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA` + overflow → same challenge byte sequence | Auth probe with LEI overflow | High |
| rDNS-stall: connect from no-PTR IP → loop pauses | Timing probe | High |
| Server version `8.0.19` + sequential thread_id 0,1,2… | Multiple connections | High |

**Minimum detection sequence:**
1. Two connections in sequence: `thread_id = 0`, `thread_id = 1` → confirmed sequential from 0; real MySQL thread_ids are non-sequential across sessions
2. Predict challenge bytes from daemon startup time → pre-auth fingerprint confirmation
