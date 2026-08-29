# nosqlpot — Security Analysis

**Repo:** https://github.com/torque59/nosqlpot  
**Type:** Python 2 honeypot framework — fake RESP server (Twisted + fakeredis) for Redis; CherryPy HTTP server for CouchDB  
**Lane:** 1 comprehensive lane (nosqlpot.py + redispot/*.py + couchpot/*.py + configs)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 4 |
| MEDIUM | 4 |
| LOW | 4 |
| INFO | 1 |

nosqlpot's fundamental flaw is that its primary objective — credential capture — is broken: the AUTH command is completely absent from the Redis dispatcher. Every attacker password attempt falls through to a generic error branch and is discarded. The couchpot has a JSON syntax error in its index response (trailing semicolon), an invalid Content-Type, and is bound to localhost by default. Both are Python 2 EOL codebases with no upgrade path.

---

## CRITICAL

### C1 — redisdeploy.py:75 — AUTH command absent; all attacker passwords discarded

```python
else:
    self.transport.write("-ERR unknown command '%s'\r\n" % (data[0]))
```

`AUTH` is not in the command dispatch table. A client sending `AUTH <password>` falls through to the catch-all error branch. The password is never logged, stored, or captured. This is nosqlpot's sole stated purpose for the Redis honeypot component — the feature is entirely non-functional. Additionally, the `-ERR unknown command 'auth'` response differs from real Redis 4.x+ (which returns `-NOAUTH Authentication required` when requirepass is set, not "unknown command"), immediately identifying the honeypot.

---

## HIGH

### H1 — redisdeploy.py:37 — Log injection via raw attacker bytes

```python
print "original data:" + str(rcvdata),
```

Raw, unescaped attacker bytes (the full TCP payload) are written directly to stdout/`redis.log`. An attacker sends `\r\n[2026-01-01 INFO] AUTH admin success\r\n` to inject synthetic log lines. No sanitization at any layer. ANSI escape codes (`\x1b[31m`) render in any terminal. The print statement also discards any exception context if `rcvdata` is non-UTF8.

---

### H2 — redisdeploy.py:46 — QUIT handler is dead code; connections cannot be closed by client

```python
if command.lower == "quit":   # .lower is a method object, not a call
    self.transport.loseConnection()
```

`command.lower` is a bound method object. Comparing a method object to the string `"quit"` is always `False`. QUIT never closes the connection. Combined with `timeout 0` in the INFO config (no server-side timeout), connections cannot be terminated by client request. Repeated QUIT-and-reconnect accumulates open connections; eventual FD exhaustion takes the Twisted reactor down.

---

### H3 — redisdeploy.py:34-35 — FakeRedis instantiated per data event; state never persists across calls

```python
def dataReceived(self, rcvdata):
    r = fakeredis.FakeStrictRedis()
```

A fresh `FakeStrictRedis` instance is created on every `dataReceived` invocation. TCP delivers data in arbitrary chunks — a single TCP connection may trigger `dataReceived` multiple times. State resets between calls: SET returns `+OK`, but a GET in the next chunk sees an empty store. Any scanner or attacker issuing two sequential commands observes the reset and identifies the honeypot. Also: `cmd_count = 0` inside `dataReceived` is a local shadowing the module global — `total_commands_processed` in INFO responses always reports 1.

---

### H4 — redisdeploy.py:55 — Pre-RESP-parse CONFIG trigger; bare `config` on the wire triggers response

```python
elif command.lower() == "config get *" or rcvdata.find('config') == 0:
    self.transport.write(rediscommands.parse_config())
```

The `rcvdata.find('config') == 0` branch fires on raw bytes before RESP parsing. Sending the 6-byte string `config\r\n` without RESP framing triggers the full config dump. Non-RESP tooling (curl, netcat) receives the response. Additionally, any RESP frame whose first bytes happen to be `config` (e.g., a bulk string value starting with "configure") incorrectly triggers the config branch — the check runs on raw TCP data, not the decoded command.

---

## MEDIUM

### M1 — redisconfig.py:91 — Disk write on every INFO command; path mismatch on re-read

```python
with open('redispot/config/info', 'wb') as configfile:
    parser.write(configfile)
```

Every INFO request triggers a write to `redispot/config/info`. No rate limiting — an attacker issuing INFO at 1,000/sec drives unbounded disk I/O. The subsequent read at line 93 calls `parser.read('info')` — a relative path that reads from CWD, not `redispot/config/info`. On standard deployments where CWD != `redispot/config/`, the re-read is a no-op; updated counters from the write are never reflected in the in-memory parser.

---

### M2 — redisconfig.py:46 — TypeError crash on KEYS when store is non-empty

```python
result.append(len(res))   # int appended to list
return "".join(result)    # TypeError: expected str, found int
```

`encode_keys()` appends `len(res)` as a Python int. `"".join()` raises `TypeError`. The bare `except:` in `dataReceived` (line 43) catches RESP decode errors only — the TypeError propagates to the Twisted callback level, which logs it and silently drops the connection. An attacker issuing `SET x y` then `KEYS *` reliably kills the connection with no error response.

---

### M3 — redispot/info:3,9,34,35 — Static INFO fingerprint; five invariant fields

```
redis_version = 2.4.16
process_id = 30064
last_save_time = 1427948762   # 2015-04-01
loading = 1                   # never transitions to 0
```

Redis 2.4.16 has been EOL since 2013. `process_id = 30064` never changes. `loading = 1` implies RDB is in progress — legitimate Redis exits loading state at startup. `total_commands_processed` always reports 1 (see H3). The INFO response format is also wrong: real Redis returns a single bulk string `$N\r\n...\r\n`; nosqlpot returns an array of individual RESP bulk strings — a protocol-level fingerprint detectable with a single INFO call.

---

### M4 — redisdeploy.py:43-45 — Bare `except:` catches `KeyboardInterrupt` and `SystemExit`

```python
except:
    data = rcvdata
    command = rcvdata
```

Catches `BaseException` including `KeyboardInterrupt` and `SystemExit`. TCP fragmentation sends partial RESP frames, which the decoder fails to parse; `command` is then set to the raw bytes. Subsequent `.lower()` comparisons return False for all commands. The attacker's first fragmented packet silently causes every command comparison to fail for the lifetime of the connection — the honeypot appears to accept the connection but responds to nothing.

---

## LOW

- **couchpot/couch.conf:2** — Response body `{"couchdb":"Welcome",...};` — trailing semicolon makes the response invalid JSON. `json.loads()` and `JSON.parse()` both throw. Real CouchDB 1.6.1 never returns a semicolon-terminated response. Single-request fingerprint.
- **couchpot/server.conf:2** — `server.socket_host = "127.0.0.1"` — CouchDB honeypot bound to localhost by default; unreachable externally without manual reconfiguration. Default port 8112 vs real CouchDB 5984 is also an immediate fingerprint.
- **couchpot/server.conf:9** — `response.headers.Content-Type = 'text/plain; charset=utf-7'` — real CouchDB returns `application/json; charset=utf-8`. UTF-7 charset is anomalous; no CORS headers (`Access-Control-Allow-Origin`) emulated.
- **couchdeploy.py:30-33** — `_cp_dispatch` returns empty list `[]` instead of a CherryPy handler; any database-name URL (e.g., `/mydb`) gets a 500/404 instead of a CouchDB response.

---

## INFO

- **Entire codebase** — Python 2 EOL (January 2020). `print` statement syntax, `ConfigParser`, `httplib`, `urllib`, `SafeConfigParser` (deprecated alias). `fakeredis` compatible with Python 2 is also EOL. Not installable on Python 3 without porting. No pip-installable security patches exist for the Python 2 interpreter or any library version in use.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| `AUTH password` → `-ERR unknown command 'auth'` | RESP command | Definitive |
| INFO `redis_version = 2.4.16` | INFO response | Very High |
| INFO `process_id = 30064` (never changes) | INFO response | Definitive |
| INFO `loading = 1` (never clears) | INFO response | Very High |
| INFO format: array of bulk strings vs single bulk string | RESP wire format | High |
| `QUIT` → no response, connection stays open | Wire behavior | High |
| `SET x y; GET x` → empty (state reset) | Two-command probe | Very High |
| CouchDB port 8112 (default 5984) | Port scan | Medium |
| CouchDB response: trailing semicolon in JSON | HTTP GET / | Definitive |
| CouchDB Content-Type: `text/plain; charset=utf-7` | HTTP header | Very High |

**Minimum detection sequence:**
1. `AUTH password\r\n` → `-ERR unknown command 'auth'` → confirmed non-Redis (C1)
2. INFO → `process_id = 30064`, `loading = 1`, wrong RESP format → confirmed nosqlpot
