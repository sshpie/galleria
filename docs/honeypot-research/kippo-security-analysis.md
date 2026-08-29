# Kippo SSH Honeypot — Security Analysis
**Target:** https://github.com/desaster/kippo  
**Date:** 2026-08-25  
**Status:** Complete  
**Method:** Static source analysis, 5 parallel lanes — injection/auth/crypto, DoS/state machine/evasion, command emulation/output/config, SSH protocol, coding errors (pending)

---

## Severity Summary

| Sev | Count |
|-----|-------|
| CRITICAL | 4 |
| HIGH | 15 |
| MEDIUM | 18 |
| LOW | 6 |

---

## CRITICAL Findings

---

### C1 — Real SSRF via wget (No Blocklist)
**File:** `kippo/commands/wget.py:132`

```python
self.connection = reactor.connectTCP(host, port, factory, bindAddress=out_addr)
```

`host` and `port` parsed directly from attacker URL via `urlparse.urlparse(url)`. Zero RFC-1918 filtering, zero localhost block, zero cloud metadata block. Kippo makes a real outbound TCP connection to wherever the attacker points.

**Exploits:**
- `wget http://169.254.169.254/latest/meta-data/` — AWS IMDS, full SSRF
- `wget http://10.0.0.1:6379/` — internal Redis
- `wget http://127.0.0.1:8080/` — local web app
- Any HTTP-reachable host from the honeypot's network

Unlike Cowrie (which had a blocklist with gaps), Kippo has no blocklist at all. SSL refused (`line 113`), so HTTPS targets are safe — everything else is not.

**Fix:** Resolve hostname, check against RFC-1918/loopback/link-local/metadata denylist before `connectTCP`. Or run in a network namespace with no route to internal services.

---

### C2 — Unauthenticated Management Console (Session Hijack)
**Files:** `kippo.tac:59-61`, `kippo/core/interact.py:10-154`

```python
# kippo.tac:59-61 — no interface binding, no auth
service = internet.TCPServer(iport, interact.makeInteractFactory(factory))
```

```python
# interact.py — connectionMade grants immediate full access
def connectionMade(self):
    self.transport.write('*** kippo session management console ***\r\n')
    self.cmd_help()
```

Interact telnet console listens on all interfaces (`''` = `0.0.0.0`). Zero authentication. Any TCP connection is immediately granted:
- `cmd_list` — enumerate all live attacker sessions with source IPs and SSH client versions
- `cmd_view` — read-only monitor of any live session
- `cmd_hijack` — inject keystrokes into any live session via `recvline.HistoricRecvLine.keystrokeReceived`
- `cmd_disconnect` — kill sessions, disrupting capture

If the interact port is reachable, a third party owns the honeypot. If an attacker in one session tunnels to the interact port, they can hijack other attacker sessions.

**Fix:** Bind to `127.0.0.1` only. Add shared-secret authentication.

---

### C3 — SSH Version String (2008) / KEXINIT Capability Mismatch
**File:** `kippo/core/ssh.py:116`, `kippo.cfg.dist:139`

```python
t.ourVersionString = "SSH-2.0-OpenSSH_5.1p1 Debian-5"
```

OpenSSH 5.1p1 is from 2008. Worse: Twisted advertises ECDH, curve25519, `hmac-sha2-*` in KEXINIT — none of which existed until years after 5.1. The version-vs-capability mismatch is machine-detectable in one KEXINIT parse. HASSH fingerprint of Twisted's KEX set is indexed in public threat intel databases.

---

### C4 — Single-Packet Pre-Auth Kippo Detection
**File:** `kippo/core/ssh.py:203-219`

```python
if not 'bad packet length' in desc:
    transport.SSHServerTransport.sendDisconnect(self, reason, desc)
else:
    self.transport.write('Protocol mismatch.\n')   # raw ASCII, not SSH_MSG_DISCONNECT
    self.transport.loseConnection()
```

Send a packet with a bad length field. Real OpenSSH responds with `SSH_MSG_DISCONNECT` (binary SSH packet type 1). Kippo writes `"Protocol mismatch.\n"` as raw ASCII then closes TCP. Zero false positives. One packet before any auth.

---

## HIGH Findings

---

### H1 — wget Writes Real Files to Host Filesystem
**File:** `kippo/commands/wget.py:96-99`

```python
self.safeoutfile = '%s/%s_%s' % (
    cfg.get('honeypot', 'download_path'),
    time.strftime('%Y%m%d%H%M%S'),
    re.sub('[^A-Za-z0-9]', '_', url))
```

Downloaded content lands on the real host filesystem at `download_path` (`dl/` default). Attacker stages ELF binary, cron payload, or script via `wget` → it lands on the real host. If any other process reads from `download_path` or it's world-executable, attacker has a real-FS write primitive without escaping the honeypot.

**Fix:** Stream to in-memory buffer or pipe. Never materialize to real FS without sandboxing.

---

### H2 — Cleartext Credential Storage (DB + userdb.txt)
**Files:** `kippo/core/auth.py:44-65`, `kippo/dblog/mysql.py:91-101`

All captured attacker passwords stored in cleartext in `userdb.txt` and MySQL `auth` table. No hashing. `save()` writes `'%s:%d:%s\n' % (login, uid, passwd)`. MySQL plugin inserts `args['password']` directly. Every brute-force attempt — thousands per day — stored plaintext.

**Fix:** Hash stored honeypot passwords. Schema comment should document that captured attacker credentials are deliberately plaintext for intelligence purposes.

---

### H3 — Non-ASCII Password Drops DB Record (Session Evasion)
**File:** `kippo/core/auth.py:131,134`

```python
print 'login attempt [%s/%s] succeeded' % (username, password)
```

Python 2 `print` with `\x80-\xff` bytes raises `UnicodeDecodeError` on UTF-8 stdout. Exception propagates through `checkUserPass` → `requestAvatarId`. Auth appears to fail to the attacker, but no login record (success or failure) is written to the DB. The exception appears in the Twisted error log without the credential pair.

**Exploit:** `ssh root@kippo` with password `\x80` against a `root:0:*` wildcard entry. Auth succeeds (wildcard matches), exception fires before logging, no DB record. Repeat with different usernames to enumerate valid accounts without appearing in the auth log.

---

### H4 — Username with `\n` Drops DB Record (Regex Bypass)
**File:** `kippo/core/dblog.py:22-26`

```python
'^login attempt \[(?P<username>.*)/(?P<password>.*)\] failed'
```

`.` doesn't match `\n`. Username containing newline causes the formatted log line to span multiple lines; regex fails to match; `handleLoginFailed` never called; zero DB record. Combine with `\n` in password for same effect.

---

### H5 — `yes` Orphaned callLater — Permanent Reactor Saturation
**File:** `kippo/commands/base.py:285-291`

```python
def y(self):
    self.writeln('y')
    self.scheduled = reactor.callLater(0.01, self.y)
```

Only `ctrl_c()` cancels. `connectionLost` does not cancel `self.scheduled`. Drop TCP via RST without CTRL-C: 100Hz `callLater` loop runs forever on a dead transport. If Twisted's `write()` on dead transport silently discards (typical), chain runs indefinitely. 50 sessions = 5,000 reactor callbacks/sec permanent after disconnect.

---

### H6 — `ping` Orphaned callLater
**File:** `kippo/commands/ping.py:42-48`

Same pattern as `yes` at 1Hz. `connectionLost` does not cancel. Long-running ping + TCP RST = indefinite 1Hz orphaned timer chain per session.

---

### H7 — No Idle Timeout
No `callLater` for inactivity detection anywhere in the codebase. No `ClientAliveInterval` equivalent. Sessions hold reactor resources indefinitely. No cross-connection brute-force enforcement — attacker exhausts 20 `maxAuthTries`, opens a new TCP connection, continues.

---

### H8 — UserDB Read from Disk Per Auth Attempt
**File:** `kippo/core/auth.py:130`

```python
def checkUserPass(self, username, password):
    if UserDB().checklogin(username, password):
```

`UserDB()` reads and parses `userdb.txt` from disk on every call. No caching. Under brute-force with unlimited new connections: full disk read + parse per attempt. Large userdb files multiply cost. Effective disk I/O amplifier.

---

### H9 — One ttylog File Per Connection, No Cap
**File:** `kippo/core/protocol.py:228-235`

No disk space check, no max file count, no rotation. Mass connections each creating a ttylog fill disk. Additionally: `ttylog_write` opens, writes, and closes the file per keystroke (`ttylog.py:11-16`) — no buffering. Under `yes` across many sessions: FD exhaustion, inode cache thrash, reactor thread blocking.

---

### H10 — Log Injection / DB Field Poison (Regex Smuggling)
**Files:** `kippo/core/auth.py:131`, `kippo/core/dblog.py:24-26`

Greedy `.*` regex on format-string log output. Username containing `/` (e.g., `user/admin`, password `pass`) → regex captures `username=user`, `password=admin/pass`. Attacker-chosen values inserted into the DB credential intelligence table. Poisoning threat intel feeds sharing from this instance.

---

### H11 — cmdstack Double-Pop via callLater After Disconnect
**File:** `kippo/core/honeypot.py:33-34`

```python
def exit(self):
    self.honeypot.cmdstack.pop()
    self.honeypot.cmdstack[-1].resume()
```

When `ping`/`yes` fires a `callLater` after `connectionLost` has cleared `cmdstack`, `cmdstack[-1]` on an empty list raises `IndexError`. Propagates as unhandled Twisted reactor error. Reactor noise on every such disconnect.

---

### H12 — Private SSH Key Written World-Readable
**File:** `kippo/core/ssh.py:316-319`

```python
with file(private_key, 'w+b') as f:
    f.write(privateKeyString)
```

No `os.chmod()` call. Private key inherits process umask. Default umask 0022 → `0o644` (world-readable). Any process or co-tenant on the host can read the honeypot's private key.

---

### H13 — DSA-1024 Host Key
**File:** `kippo/core/ssh.py:311-312`

```python
KEY_LENGTH = 1024
dsaKey = DSA.generate(KEY_LENGTH, randbytes.secureRandom)
```

DSA-1024 broken per FIPS 186-4, removed in OpenSSH 7.0+. Offered in `supportedPublicKeys`.

---

### H14 — KEXINIT Null Padding (Passive Fingerprint)
**Inherited from Twisted `SSHServerTransport`**

Real OpenSSH always sends 1-255 random padding bytes in KEXINIT. Twisted sends 0. Single passive packet capture IDs Kippo before auth with ~100% confidence.

---

### H15 — `session.factory` Leak on connectionLost Exception
**File:** `kippo/core/ssh.py:195-196`

```python
del self.factory.sessions[self.transport.sessionno]
```

If `connectionLost` raises before this `del` (e.g., `ttylog_close` on missing file), session entry leaks in `factory.sessions` permanently. Protocol object stays referenced, entire session object graph never GC'd.

---

## MEDIUM Findings

---

### M1 — tar Command Shadows Real Commands (In-Session Detection Channel)
**File:** `kippo/commands/tar.py:78-79`

```python
self.honeypot.commands[dest] = pick_handler(os.path.basename(dest), f.size)
```

Extracted tar entries registered as command handlers for that session. Attacker downloads a tar containing `/bin/cat` → that command is replaced for the session. Output changes, observable to the attacker. Reliable in-session honeypot detection channel.

---

### M2 — txtcmds Real FS Read (Symlink/Config Attack)
**File:** `kippo/core/protocol.py:98-101`

```python
txt = os.path.abspath('%s/%s' % (self.env.cfg.get('honeypot', 'txtcmds_path'), path))
if os.path.exists(txt) and os.path.isfile(txt):
    return self.txtcmd(txt)
```

`txtcmd()` opens and reads the real file. If a symlink inside `txtcmds/` points outside the directory, attacker gets arbitrary real-FS reads served as command output.

**Fix:** `os.path.realpath(txt)` must start with `os.path.realpath(txtcmds_path)` before opening.

---

### M3 — KEX List: SHA-1 Always Present, No Config Control
**File:** `kippo/core/ssh.py:120-131`

Only `diffie-hellman-group-exchange-sha1` is conditionally removed (when no moduli file). `diffie-hellman-group14-sha1` remains unconditionally. No config key for KEX algorithms.

---

### M4 — Banner-vs-Capability Version Mismatch (HASSH Fingerprint)
**File:** `kippo/core/ssh.py:128-131`

Twisted's KEXINIT includes `curve25519`, ECDH, `hmac-sha2-*` — none present in real OpenSSH 5.1. Known Kippo HASSH values indexed in Salesforce HASSH database and public threat intel feeds.

---

### M5 — `exec_enabled` Bypasses Interactive Logging
**File:** `kippo/core/ssh.py:254-268`

`exec_enabled = true` (default). Attacker sends commands via `ssh host cmd` (non-interactive). Takes a different logging path than interactive shell. Commands appear in Twisted console log but not through `HoneyPotShell.lineReceived` — DB logging coverage differs.

---

### M6 — Malformed shlex Input Drops Command from DB
**File:** `kippo/core/honeypot.py:87-95`

```python
try:
    cmdAndArgs = shlex.split(line)
except:
    self.honeypot.writeln('bash: syntax error: ...')
    self.cmdpending = []
    self.showPrompt()
    return
```

Unclosed quote triggers except path. `print 'CMD: %s' % line` fires (Twisted log only) but `logDispatch` is never reached. Command appears in console log, absent from DB.

---

### M7 — `uptime` Unhandled ValueError — Session Orphan
**File:** `kippo/commands/base.py:21-23`

```python
secs = int(self.args[0])   # no try/except
```

`uptime abc` → `ValueError`. Exception propagates, `exit()` never called, `cmdstack` not popped. Subsequent commands cannot execute. Shell appears to hang until disconnect.

---

### M8 — TAB Without Prior PTY Crashes on windowSize
**File:** `kippo/core/honeypot.py:231`

```python
perline = int(self.honeypot.user.windowSize[1] / (maxlen + 1))
```

Send `shell` request without prior `pty-req` → `windowSize` never set → TAB triggers `AttributeError`.

---

### M9 — Pre-Auth TCP Drop Leaks Session Entry
**File:** `kippo/core/dblog.py:65-84`

Connection drop during SSH handshake before full init: `_connectionLost` pattern never matches, session entry stays in `self.sessions` dict indefinitely. Slow memory leak per probe/scan.

---

### M10 — Username with `/` Corrupts DB Fields
**File:** `kippo/core/dblog.py:22-26`

Greedy `.*` regex: `username=user/admin` → DB records `username=user`, `password=admin/<rest>`. Attacker's actual username never correctly stored.

---

### M11 — `reboot`/`uptime` Modify Global Factory State
**File:** `kippo/core/protocol.py:131`

```python
transport.factory.starttime = reset
```

`reboot` or `uptime <N>` in any session modifies the global uptime visible to all sessions. Cross-session corruption.

---

### M12 — `channel-open-failure` Returns Wrong Reason Code
**File:** `kippo/core/ssh.py:233` (absence of `direct-tcpip`)

Kippo returns `ADMINISTRATIVELY_PROHIBITED` (reason 1) for unknown channel types. Real OpenSSH returns `UNKNOWN_CHANNEL_TYPE` (reason 3). Detectable.

---

### M13 — Static `ps` Output (Every Instance Identical)
**File:** `kippo/commands/base.py:91-148`

Hardcoded PIDs, hardcoded start times (`Nov06`, `Nov08`). Run `ps aux` twice from different sessions: identical. Start time vs current date mismatch. Reliable detection oracle.

---

### M14 — `uname -a` Returns 2009 Kernel
**File:** `kippo/commands/base.py:82-86`

```python
self.writeln('Linux %s 2.6.26-2-686 #1 SMP Wed Nov 4 20:45:37 UTC 2009 i686 GNU/Linux' % ...)
```

2009 kernel on i686 while modern Kippo runs x86_64.

---

### M15 — exit Behavior Oracle (Client-Version-Dependent)
**File:** `kippo/commands/base.py:55-66`

```python
if 'PuTTY' in self.honeypot.clientVersion or 'libssh' in ...:
    self.honeypot.terminal.loseConnection()
    return
self.honeypot.terminal.reset()
self.writeln('Connection to server closed.')
```

Two connections with different `SSH_libssh` vs standard client version strings — `exit` behavior differs. Detection oracle.

---

### M16 — Unbounded lineBuffer Pre-Enter
**File:** `kippo/core/protocol.py:194-197`

No cap on `lineBuffer`. `line[:500]` truncation only fires at Enter. Stream bytes without `\r\n` → uncapped heap growth for duration of session. In CPython 2, each 1-byte str in list ~50 bytes overhead. 10MB stream ≈ 500MB Python objects.

---

### M17 — shutdown/reboot callLater Not Cancelled on Disconnect
**File:** `kippo/commands/base.py:219,228,251`

```python
reactor.callLater(3, self.finish)
```

If connection drops in the 3-second window, `self.finish` fires on dead transport. No cancel in disconnect path.

---

### M18 — `getattr` Dispatch in Interact Console
**File:** `kippo/core/interact.py:46-50`

```python
func = getattr(self, 'cmd_' + cmd)
```

Any `cmd_*` attribute callable from unauthenticated telnet. Pattern risk if class is extended.

---

## LOW Findings

---

### L1 — Pickle Deserialization of fs.pickle
**File:** `kippo/core/honeypot.py:256`

```python
self.fs = pickle.load(file(self.cfg.get('honeypot', 'filesystem_file'), 'rb'))
```

Write access to kippo working dir + replace `fs.pickle` → RCE on next connection.

**Fix:** Verify with HMAC before loading. Replace with JSON.

---

### L2 — UserDB TOCTOU Race
**File:** `kippo/core/auth.py:48-58` *(self-documented: "subject to races between kippo instances, but hey...")*

`open('w')` truncates file immediately. Two concurrent `passwd` commands: last writer overwrites the other. Concurrent instance crash mid-write → empty `userdb.txt` → all subsequent auth fails.

**Fix:** Write to `.tmp`, then `os.rename()` (atomic on POSIX).

---

### L3 — Auth Wildcard `*` Policy Not Documented
**File:** `kippo/core/auth.py:65`

```python
if login == thelogin and passwd in (thepasswd, '*'):
```

Default `userdb.txt` has wildcard entries. Bots succeed on first attempt, raising operator suspicion that something is wrong. Not visible without reading source.

---

### L4 — `historyLines` Unbounded Growth
**File:** `kippo/core/protocol.py:204`

Every Enter appends to `historyLines`, never truncated. Long sessions grow indefinitely.

---

### L5 — DSA-1024 Cryptographically Broken
**File:** `kippo/core/ssh.py:311`

See H13. Separately noted: offering DSA on claimed OpenSSH 5.1 is era-consistent but is a broken primitive regardless.

---

### L6 — Dangerous Config Defaults
**File:** `kippo.cfg.dist`

- `exec_enabled = true` — non-interactive channel enabled; lower bar for SSRF/FS-write exploitation
- `hostname = svr03` — static, documented Kippo fingerprint
- `ssh_version_string = SSH-2.0-OpenSSH_5.1p1 Debian-5` — 2008
- MySQL creds `kippo/kippopw` — default, exposed credential DB to anyone with MySQL access
- `download_limit_size` commented out — no cap; attacker fills disk via `wget` of large file
- `interact_enabled = false` by default — but one line from exposing unauthenticated hijack console

---

## Verified NOT Vulnerable

- **Shell injection:** No `subprocess`, `os.system`, `os.popen`, `eval()`, `exec()` on attacker input in command dispatch path
- **SQL injection:** `kippo/dblog/mysql.py` uses adbapi parameterized queries (`%s` placeholders) throughout
- **Fake FS path traversal:** Virtual FS `resolve_path` collapses `..` before real path construction; txtcmds join is blocked by virtual path resolution (though symlink attack remains, M2)
- **Zip-slip in tar:** Virtual path resolver strips `..` in extracted tar entry destinations

---

## Attack Chains

**Chain 1 — Permanent Reactor Saturation (no auth required to sustain):**
Authenticate (wildcard `root:0:*` accepts anything) → run `yes` → drop TCP via RST without CTRL-C → repeat 50 times. Each session leaves 100Hz orphaned `callLater` chain. 50 sessions = 5,000 no-op reactor callbacks/sec permanent. New connections get progressively slower.

**Chain 2 — Auth with Zero DB Records:**
SSH with password `\x80` against any wildcard userdb entry. `print` in `checkUserPass` raises `UnicodeDecodeError`. No success or failure record written to DB. Enumerate valid usernames without appearing in auth log.

**Chain 3 — Single-Packet Kippo Identification:**
Send any TCP data with a bad SSH packet length field. Kippo → raw ASCII `"Protocol mismatch.\n"` + TCP close. Real OpenSSH → `SSH_MSG_DISCONNECT` binary packet + TCP close. Zero false positives. Works before banner exchange completes.

**Chain 4 — Passive HASSH Identification:**
Capture TCP stream, extract SSH KEXINIT packet, compute HASSH. Compare against published Kippo/Twisted database. No active probe required.

---

## Coding Errors & Python 2 Artifacts (Lane 5)

Kippo is Python 2 only. The following make it non-functional on Python 3 and contain logic bugs even on Python 2.

---

### Python 2 / Python 3 Incompatibilities (whole-file import failures)

**Print statements** — pervasive across every file (`core/honeypot.py`, `core/ssh.py`, `core/protocol.py`, `commands/wget.py`, `commands/tar.py`, `dblog/mysql.py`, etc.). `SyntaxError` at import time on Python 3.

**`except ExcType, var:` syntax** — `commands/fs.py:84,156`, `commands/wget.py:50`, `commands/ssh.py:15`, `dblog/mysql.py:23`. `SyntaxError` on Python 3.

**`raise Exception, "msg"` syntax** — `core/ssh.py:147,261`. `SyntaxError`.

**`file()` builtin removed** — Used in `core/fs.py:137`, `core/protocol.py:77`, `core/utils.py:8`, `core/dblog.py:99`, `core/ssh.py:37,291-298,314-320`, `commands/last.py:27`, `dblog/textlog.py:15`, `core/honeypot.py:256`. `NameError` at runtime on Python 3.

**Removed modules** — `import urlparse` (→ `urllib.parse`), `import anydbm` (→ `dbm`), `import ConfigParser` (→ `configparser`), `import exceptions` (removed entirely). `ImportError` at startup.

**`long()` removed** — `core/utils.py:13`: `seconds = long(round(seconds))`. `NameError`.

**`dict.has_key()`** — `commands/wget.py:175,178`. `AttributeError` on Python 3.

**`hashlib.md5(str)`** — `commands/ping.py:33`, `commands/ssh.py:40`: `hashlib.md5(self.host)` passes `str` not `bytes`. `TypeError: Strings must be encoded before hashing`. `ping nonexistent-hostname` crashes.

---

### Logic Bugs in Fake Commands (Detectable)

**`rm` processes flag arguments as file paths** — `commands/fs.py:55-72`: `rm -rf /tmp/foo` → kippo tries to delete a path named `-rf`, prints `rm: cannot remove '-rf': No such file or directory`. Immediately detectable.

**`rmdir` compares full path against basename entries** — `commands/fs.py:241`: `rmdir /tmp/mydir` always reports "No such file or directory" because `f` (`/tmp/mydir`) is compared against bare `mydir` in the dir listing.

**`ps` column alignment wrong** — `commands/base.py:129-130`: `'%s'.ljust(8) % user` pads the format string literal `%s` to 8 chars, not the user value. Column alignment always wrong. Detectable.

**wget rejects all non-port-80 HTTP as SSL** — `commands/wget.py:112-115`: `if scheme == 'https' or port != 80:` → `wget http://example.com:8080/file` prints "Sorry, SSL not supported". Detectable.

**bash/sh with no args silently exits** — `commands/base.py:295-299`: Real bash opens interactive subshell. Kippo silently exits.

**`sizeof_fmt()` returns `None` for files ≥ 1 PiB** — `commands/wget.py:35-39`: Loop exhausts prefix list, implicit `return None`. `TypeError` on large file wget.

---

### Uninitialized Variables

**`HTTPProgressDownloader.speed`** — `commands/wget.py:248`: `self.speed` used in `pageEnd()` but only assigned in `pagePart()`. If server returns 0-byte body, `AttributeError`.

---

### Unhandled Exceptions → Session Orphan

**`uptime` non-integer arg** — `commands/base.py:20-22`: `int('-V')` raises `ValueError`. No try/except. `cmdstack` not popped. Shell hangs.

**`auth.py:36` userdb malformed line** — `(login, uid_str, passwd) = line.split(':', 2)` with fewer than 2 colons → `ValueError`. FD leak (file never closed).

---

### File Descriptor Leaks

- `core/fs.py:137`: `file(realfile, 'rb').read()` — no close, relies on CPython refcount
- `core/ttylog.py:12-28`: open/write/close pattern; write error skips close
- `core/auth.py:36-46`: exception in userdb parse leaves FD open

---

### Broad `except:` Swallowing Security Exceptions

- `commands/fs.py:21` (`cat`) — bare `except:` shows "No such file or directory" for any error
- `commands/ls.py:48,80` — same
- `core/protocol.py:60-62` — `except: pass` on MOTD display; silently drops all errors

---

### Regex Bugs

**Greedy `.*` login regex misparses passwords with `/`** — `core/dblog.py:24-25`: Username `user/admin` password `pass` → DB records `username=user`, `password=admin/pass`. See also H10.

**IPv4 regex accepts octets >255** — `commands/ping.py:29-30`: `999.888.777.666` accepted as valid IP, fake ICMP output produced. Detectable.

---

### Dead Code

**`command_start_sh1`** — `commands/malware.py:57-61`: Class defined but never registered in `slist`. Completely unreachable.

**`DBLogger.start()` missing `self`** — `core/dblog.py:53`: `def start(): pass` — called as `self.start(cfg)`. `TypeError` for any subclass that doesn't override it.
