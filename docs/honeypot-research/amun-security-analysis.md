# Amun — Security Analysis

**Repo:** https://github.com/zeroq/amun  
**Reference:** https://amunhoney.sourceforge.net/ | amunhoneypot2.pdf  
**Lanes:** 5 parallel (Core/Server/Shellcode · Download/FTP/TFTP/SMB · All 30+ vuln_modules · Logging/Submit pipeline · Fingerprints/Evasion)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 6 |
| HIGH | 19 |
| MEDIUM | 20 |
| LOW | 8 |

Amun has three independent single-packet process-kill paths in the shellcode manager, five SQL injection vectors in the logging pipeline (including one using `re.escape` as a SQL escape function), and a systemic null-byte evasion that bypasses all 84 shellcode decoders simultaneously. Most vuln modules have non-functional or catch-all state machines. The codebase is Python 2 throughout.

---

## CRITICAL

### C1 — shellcode_mgr_core.py:1710 — NameError in `handle_berlin` kills process

```python
ftpURL = "ftp://%s:%s@%s:%s%s" % (user, passw, ipself.resultSet['port'], filename)
#                                          ^^^^^^ should be: ip, self.resultSet['port']
```

`ipself` is an undefined identifier. Any shellcode triggering the Berlin path raises `NameError`, which propagates to the bare `except: exit(0)` at line 796-802 and terminates the entire daemon.

**Trigger:** Send data matching the `ftpcmd` regex pattern (embedded `cmd /c echo open <IP> <PORT>`) to any listened port. This string appears in many real worm payloads.  
**Impact:** Full honeypot process termination.

---

### C2 — shellcode_mgr_core.py:796-802 — Bare `except: exit(0)` in `match_shellcodes`

```python
except:
    ...
    exit(0)
```

Any non-`KeyboardInterrupt` exception anywhere in the 800-line `match_shellcodes` dispatch chain — `IndexError`, `struct.error`, `ValueError`, `AttributeError` — kills the process. C1, C3, and every future decoder bug is amplified by this catch-all.

---

### C3 — shellcode_mgr_core.py:1910-1912 — FTP URL without credentials kills process

```python
(userpass, hostport) = url_obj[1].split('@')
```

When a shellcode-embedded URL has scheme `ftp` but no `user:pass@` component (e.g., `ftp://192.168.1.1:21/x.exe`), `split('@')` returns one element; the destructuring raises `ValueError` → C2 catch-all → `exit(0)`.

**Trigger:** Embed `ftp://1.2.3.4:21/malware.exe` in any exploit payload. The URL regex at `decoders.py:36` matches this form.

---

### C4 — bagle_modul.py:132 + arkeia_modul.py:126 + http_modul.py:211 — `sys.exit(1)` as exception handler

Three independent modules call `sys.exit(1)` inside `except StandardError:`. Any exception during `amun_logging` instantiation, `random_reply` construction, or response formatting in these modules kills the daemon.

**Trigger (HTTP port):** Send any HTTP request that triggers an exception in `http_modul.py`'s response path — e.g., malformed Accept header that breaks the phpMyAdmin branch logic.  
**Trigger (Bagle port):** Any packet causing `AttributeError` on the logger object.

---

### C5 — dcom_modul.py:88-100 — `else` branch accepts every non-matching packet as DCOM exploit

```python
else:
    result = True
    accept = True
    self.shellcode.append(message)
    self.stage = "SHELLCODE"
```

In `DCOM_STAGE1`, the `else` branch fires when the packet doesn't match any of the four known DCOM bind requests. Every unrecognized packet — including garbage, port scanners, and unknown protocols — is classified as a DCOM exploit attempt and transitions to shellcode collection. The honeypot generates exploit events for every source that reaches this port regardless of content.

---

### C6 — submit_mysql.py:101,108,112 — SQL injection, zero escaping on attacker-controlled `downURL`

```python
"SELECT eventid FROM amun_hits_%s WHERE ... AND downurl='%s'" % (tableName, attIP, victimIP, downURL)
"INSERT INTO amun_hits_%s ... VALUES ('%s','%s','%s','%s','%s')" % (..., downURL, ...)
```

`downURL` is the worm's download URL — fully attacker-controlled shellcode content — interpolated directly into SQL with zero escaping. Contrast: `log_mysql.py` wraps `downURL` in `MySQLdb.escape_string()`. `submit_mysql.py` applies nothing.

**Trigger:** Deliver a shellcode payload whose download URL is `'); DROP TABLE amun_storage; --`.  
**Impact:** Full SQL write/exec on the logging database, depending on db user privileges.

---

## HIGH

### H1 — utils.py:66-67 — OS command injection via `shell=True` with config-supplied device name

```python
command = "ip addr show %s" % (device)
child = subprocess.Popen([command], shell=True, ...)
```

`device` comes from the `ip:` config directive. A config entry of `ip: eth0; id > /tmp/pwned` executes the injected command as the Amun process user (typically root pre-privilege-drop).

---

### H2 — shellcode_mgr_core.py:97-98 — Null-byte injection bypasses all 84 shellcode decoders

```python
self.shellcode = str(vulnResult['shellcode']).replace('\0','').strip()   # used by 82 of 84 decoders
self.shellcode2 = str(vulnResult['shellcode']).strip()                   # used by bindshell3/5/6 only
```

All primary decoders operate on `self.shellcode` (null-stripped). An attacker who inserts `\x00` bytes at known signature offsets breaks every regex match simultaneously. Detection gap is systemic — all 82 decoders fail at once.

**Trigger:** Send any shellcode pattern with null bytes at positions matching regex anchors. Result: payload triggers hexdump-only write, no download event generated, no malware classification.

---

### H3 — amun_bindport_core.py:190,265 — `sys.exit(1)` in bindport `handle_error`

Both `handle_error` overrides in the bindport module call `sys.exit(1)` unconditionally. Any unexpected exception during accept or data exchange on an open bindport kills the entire daemon.

**Trigger:** Connect to a bindport and send RST or OOB data triggering any socket-level exception.

---

### H4 — amun_bindport_core.py:80 — `"local quit"` string evasion bypasses shellcode analysis

```python
if data != "" and data != 'local quit':
    ...  # process + append to shellcmds
elif data == 'local quit':
    self.handle_close()
```

`"local quit"` is the internal IPC signal to terminate idle bindports. An attacker who sends this 10-byte literal string via an open bindport triggers `handle_close()` immediately, bypassing `check_shellcommands` analysis entirely — zero shellcode extraction, zero download event.

---

### H5 — amun_server.py:105 — `accept()` returning `None` causes `TypeError` crashing listener

```python
(sock_obj, addr) = self.accept()
```

`asyncore.dispatcher.accept()` returns `None` on `EAGAIN`. Destructuring `None` raises `TypeError`, propagating to `handle_error` which re-raises — potentially closing the listening socket under high connection rate.

---

### H6 — download_core.py + ftp_download_core.py + tftp_download_core.py — No download size cap (OOM/disk)

All three protocol handlers buffer the full download in memory before processing with no size gate:
- `download_core.py:149,186,190`: `self.content.append(data)` in read loop
- `ftp_download_core.py:73`: same pattern
- `tftp_download_core.py:139`: `self.rcv_packet.append(buffer[4:])` unbounded

`Content-Length` from HTTP is extracted but only compared after connection close, never used to bound reads.

**Trigger:** Serve a multi-gigabyte payload via any protocol. **Impact:** OOM crash or disk fill.

---

### H7 — shellcode_mgr_core.py — Hostname URLs bypass RFC1918 SSRF check

`ipmatch = self.decodersDict['checkIP'].search(dl_host)` only fires for dotted-quad IPs. If the shellcode embeds `http://metadata.internal/x.exe` or `http://localhost/x.exe`, the RFC1918 check is skipped entirely and `download_http` is invoked against the unvalidated hostname.

**Impact:** Honeypot makes outbound connections to arbitrary internal services, IMDS endpoints, etc.

---

### H8 — mysql_modul.py:84-95 — Entire MySQL module is inert (STAGE1 always returns False/False)

```python
def handleMySQLSTAGE1(self, message, bytes, ip):
    self.print_message(message)
    return False, False
```

No stage transition. STAGE2/3/4 are unreachable. `welcome_message = ""` — no greeting emitted. Zero exploits ever classified, zero shellcode collected. The module processes connections and silently drops them.

---

### H9 — mssql_modul.py:90-98 — MSSQL STAGE2 never advances; STAGE3/4 are dead code

After the 41-byte prelogin probe is accepted in STAGE1, STAGE2 returns `False, False` without advancing `self.stage`. STAGE3 and STAGE4 exist but are permanently unreachable. The module accepts exactly one packet then drops every subsequent connection.

---

### H10 — sasserftpd_modul.py:83-89 — No matching; any two packets classified as Sasser exploit

Zero content matching in STAGE1 and STAGE2. Any TCP connection sending two packets of any content, any size, advances to shellcode collection and generates a Sasser exploit event. Port scanners and web crawlers produce false positive records.

---

### H11 — dameware_modul.py:88-97 — No matching in STAGE1; every packet accepted as Dameware

Same catch-all pattern as H10. Additionally, lines 92-94 assign string chars into byte-indexed slots of `self.reply` (mixed-type list), causing `TypeError` on `"".join(self.reply)` → process exception.

---

### H12 — msdtc_modul.py:79-85 — No matching; any two-packet exchange classified as MSDTC exploit

Both MSDTC stages accept all input unconditionally.

---

### H13 — iis_modul.py:62 — Trigger condition accepts any packet ≥ 140 bytes as IIS exploit

```python
if self.stage == "IIS_STAGE1" and (bytes == 133 or bytes >= 140 or bytes == 78):
```

`bytes >= 140` covers virtually every standard HTTP request with headers. No URL, method, or content check. Every HTTP client becomes an IIS exploit candidate.

---

### H14 — wins_modul.py:131-132 — 1024-byte packet bypasses WINS fingerprint handshake

```python
if self.stage == "WINS_STAGE1" and bytes == 1024:
    self.stage = "SHELLCODE"
# falls through to:
if self.stage == "WINS_STAGE1" and bytes == 45:  # <- not elif; now fails silently
```

Not an `elif` — control falls through. The 45-byte WREPL fingerprint handshake is entirely bypassed. Send exactly 1024 bytes → direct shellcode collection, zero protocol negotiation logged.

---

### H15 — log_pgsql.py:138,145,149,160 — Wrong-library SQL escaping (MySQLdb on PostgreSQL)

`MySQLdb.escape_string(downURL)` applied before interpolation into PostgreSQL queries via psycopg2. MySQL and PostgreSQL use different quoting conventions. Dollar-sign-quoted PostgreSQL injection payloads bypass MySQL's escape entirely. Correct fix: psycopg2 parameterized queries.

---

### H16 — log_mysql.py:94,104 — Connection fields unparameterized

`attackerIP`, `victimIP`, `victimPort`, `vulnName` interpolated into SQL with no escaping in `insertConnection()`. While IP fields are constrained by the kernel, `vulnName` is module-supplied and unvalidated.

---

### H17 — log_surfnet.py:99,103,109,143 — SQL injection in stored procedure calls

`downloadMethod`, `shellcodeName`, `vulnName`, `downloadURL` all attacker-influenced, all interpolated raw into stored proc `SELECT` calls.

---

### H18 — log_surfnet.py:143 — `re.escape` used as SQL escape function

```python
from re import escape
...
escape(downloadURL)  # used before SQL string interpolation
```

`re.escape` escapes regex metacharacters (`.`, `*`, `\`, etc.), not SQL metacharacters (`'`, `"`, `;`). `downloadURL = "foo' OR '1'='1"` passes through unchanged and executes as SQL.

---

### H19 — amun_request_handler.py:300-358 — Proxy recv loop blocks entire asyncore event loop

When `enableProxy=True`, `collect_incoming_data` enters a blocking `while True` recv loop with a 2-second timeout running synchronously in the asyncore dispatch thread. A slow proxied endpoint stalls all other connections. The break condition (`len(self.out_buffer) < 1024 and len(self.out_buffer) != 0`) fails on 1024-byte-aligned chunks, creating an infinite loop.

---

## MEDIUM

### Protocol / State Machine

**M1 — check_modul.py:45** — `hashlib.sha("".join(self.shellcode))` — `hashlib.sha` does not exist in any Python version. Should be `hashlib.sha1()`. Raises `AttributeError` → hits `sys.exit(1)` in the CHECK module's StandardError handler. Any data reaching the hexdump code path kills the process.

**M2 — tftp_download_core.py:134** — TFTP source validation uses `and` instead of `or`: `if raddress != self._address[0] and rport != self._address[1]`. A spoofed UDP packet matching only the source port bypasses the check. Attacker-injected data stored as a malware sample attributed to the real server.

**M3 — ftp_download_core.py:184-187** — FTP passive data port accepts connections from any remote IP. No source validation against the control-channel peer. Third-party races the PORT-announced data port to inject arbitrary content into the malware corpus.

**M4 — amun_smb_core.py:73-80** — Static NTLM challenge bytes `\xd3\x62\xfe\xb4\x4b\x2c\xbc\x9a` hardcoded for every session. Pre-computed LM/NTLMv1 rainbow tables apply to the entire captured credential corpus. Also a honeypot fingerprint (single known challenge value).

**M5 — download_core.py** — HTTP download socket has no `settimeout()`. Attacker trickle-sends at 1 byte/minute, holding socket and accumulating memory indefinitely. FTP sets `settimeout(60.0)`; HTTP does not.

**M6 — upnp_modul.py:98** — 173-byte threshold silently drops any UPnP exploit payload ≤ 173 bytes with `accept=False`. Short staged payloads evade the module entirely.

**M7 — ftpd_modul.py:87-98** — FTP always grants auth. Any `PASS` command returns `230 User logged in, proceed` regardless of credentials. No credential validation.

**M8 — All shellcode-collecting modules** — No upper bound on `self.shellcode` accumulation. Attacker in SHELLCODE stage streams data continuously until OOM. Affects dcom, iis, rdp, wins, smb, mysql, mssql, rsync, upnp, ca, veritas, bagle, and all others.

**M9 — amun_smb_core.py:1147-1150** — SMB WriteAndX fragmentation reassembly unbounded. Attacker sends large fragmented PE over SMB → unbounded memory growth before shellcode manager sees it.

### Logging / Submit

**M10 — log_hpfeeds.py:113** — No TLS on hpfeeds channel. Auth uses HMAC-SHA1 challenge-response but channel content (attacker IPs, exploit names, shellcode, malware hashes, download URLs) transits in cleartext. Any MitM reads the full telemetry stream.

**M11 — submit_anubis.py + submit_cwsandbox.py + submit_joebox.py + submit_mwportal.py** — All submit modules use `httplib.HTTPConnection` (not HTTPS). Malware binary samples POSTed over unencrypted HTTP. Modules actively reject non-`http://` URLs, blocking even a config upgrade to HTTPS.

**M12 — log_blastomat.py:44-46** — Hardcoded `secret = "testing"` and `blastHost = "127.0.0.1:12345"` in function body (not config). SHA1 HMAC key is public knowledge from open source. Any party can forge valid authentication tokens.

**M13 — log_hpfeeds.py:272** — Raw malware binary published to hpfeeds broker via `json.dumps()` with `latin1` encoding. Corrupts arbitrary binary; may raise encoding exceptions. Binary payload transits the unauthenticated (no TLS) channel.

**M14 — conf/*.conf** — Weak/blank default credentials shipped in repo: hpfeeds `secret: secret`, MySQL `MySQLPass: mysqlPass`, PostgreSQL `pgSQLPass: notset`, Sarcophagus `pgSQLPass:` (blank, user `jan`).

### Evasion / ReDoS

**M15 — shellcodes/decoders.py:52,36** — `ftpcmd2` regex contains multiple nested `.*?` groups with `re.S|re.I` applied to attacker-controlled binary data. Near-matching FTP-shaped input triggers catastrophic backtracking. `url` regex `((\/\/)|(\\\\))+` also invites backtracking. CPU exhaustion / event loop starvation.

**M16 — amun_request_handler.py:278-279** — `self.proxyShellcode.append(data)` and `self.proxyRequests.append(data)` in proxy mode with no size cap. Extended sessions cause unbounded memory growth.

**M17 — amun_server.py:769-770** — `del newMods; del curMods` raises `UnboundLocalError` when `up_portList` is empty on config reload. Neither variable is assigned if the loop body never executes. `UnboundLocalError` propagates to main loop, sets `running=False`, shuts down honeypot.

### Fingerprints

**M18 — realvnc_modul.py:28** — `welcome_message = "RFB 003.008"` — missing trailing `\n`. Every real VNC server sends `"RFB 003.008\n"`. Static discriminator in one byte.

**M19 — bagle_modul.py:94** — Hardcoded reply `"12345678"` (8 ASCII bytes) to Bagle auth packet. Unique to Amun. Probe: send Bagle auth bytes → observe reply → confirm honeypot.

**M20 — http_modul.py:100** — `Server: Apache/1.3.29 (Unix) PHP/4.3.4` hardcoded on all HTTP responses; body contains `tim.bohn@gmx.net` and `johan83@freenet.de` in the default reply page.

---

## LOW

**L1 — mssql_modul.py:119** — SHELLCODE stage always returns `"\x42\xb6\x8a\xba"` (4 static bytes). Never a valid TDS response. Static 4-byte fingerprint.

**L2 — ftpd_modul.py:63** — Raw FTP `USER`/`PASS` command content logged without sanitization. ANSI escape sequences or terminal control codes render in terminal-based log viewers.

**L3 — sub7_modul.py:85-103** — Protocol commands matched by prefix only (`message[:3]=="PWD"`, etc.). Arbitrary content after prefix accepted. Protocol state advances without full handshake validation.

**L4 — dcom_modul.py:101-107** — Second `DCOM_STAGE1` branch (1024/872-byte path) is dead code. The prior `if bytes > 0` catch-all at line 59 consumes both values. Real Sasser/LSASS 1024-byte prelude falls into the C5 catch-all instead of this handler.

**L5 — tftp_download_core.py:69** — `blksize = 516` sent as TFTP blksize negotiation value. Standard TFTP data payload is 512 bytes. Last-packet detection at line 142 checks `len(buffer) < 516`; if server honours 516-byte blocks, last-packet detection may fail.

**L6 — download_core.py:157-183** — 302 redirect handler is dead code. The `if not status in ['206','200']:` branch at line 157 returns before the `elif status in ['302']:` can execute. Attacker responding with HTTP 302 causes silent connection drop.

**L7 — log_syslog.py:36 + log_mail.py:54** — `downloadMethod` (shellcode-parsed, attacker-controlled) embedded unsanitized in syslog messages and email subjects. Newlines in `downloadMethod` split syslog lines and forge synthetic log entries.

**L8 — iprange.py:23-28,40-43** — Malformed CIDR raises unhandled `ValueError`/`IndexError`. Depending on caller exception handling, result is fail-open (all connections allowed when IP range check crashes).

---

## Fingerprint Summary — Definitive Identifiers

### Conjunctive probe set (any two = confirmed Amun, all three = hard fingerprint)

1. `GET / HTTP/1.1\r\nHost: x\r\n\r\n` on HTTP port → body MUST contain `tim.bohn@gmx.net` AND `johan83@freenet.de`
2. TCP connect to any declared port, send `\r\n` only → reply MUST be exactly `\r\n` (2 bytes)
3. SMBv2 Negotiate Request to port 445 → connection MUST close or return non-SMB2 bytes (no `\xfe\x53\x4d\x42` header)

Probe (1) is safe and non-triggering — matches GET / before any shellcode stage is entered.

### Per-service tells

| Service | Tell | Probe |
|---------|------|-------|
| HTTP | Body contains `tim.bohn@gmx.net`; `Server: Apache/1.3.29 (Unix) PHP/4.3.4` | `GET /` |
| IIS/443 | Raw TCP, no TLS handshake | Send TLS CLIENT_HELLO |
| SMB | Only SMBv1; static NTLM challenge `\xd3\x62\xfe\xb4\x4b\x2c\xbc\x9a` | SMBv2 negotiate or SMB1 negotiate → check bytes[9] of response |
| DCOM/135 | No EPM Map support; null-byte response; everything else is "exploit" | Send EPM Map request |
| FTP | `"220 Welcome to my FTP Server"` banner; no PASV/LIST/RETR | `PASV\r\n` after login → `500 Unknown Command` |
| SasserFTPd | No FTP banner at all; raw null bytes on connect | Connect + read |
| IMAP (Domino) | `a200 Lotus Domino 6.5.4 7.0.2 IMAP4\r\n`; always `a001 OK` regardless of command | Send `A001 CAPABILITY\r\n`, observe non-capability response |
| POP3 (SLMail) | Greeting `220 mailserver\r\n` (wrong code; should be `+OK`) | `CAPA\r\n` |
| RDP/3389 | Raw TCP, no X.224/TLS; null-byte response | X.224 connection request |
| RealVNC | `"RFB 003.008"` without `\n`; `\x01\x02` without 16-byte challenge | RFB version handshake |
| Bagle | Reply `"12345678"` to auth packet | Send Bagle auth bytes |
| MSSQL | 4-byte reply `\x42\xb6\x8a\xba` to any SHELLCODE-stage packet | Send prelogin + any followup |
| Shell emulator | `systeminfo` returns empty; `netstat` shows hardcoded ports not matching actual open ports; volume serial always ends `-FAB8` | Post-exploit: run `netstat -anp tcp` |

### Shellcode decoder gaps (evasion)

| Missing decoder | Impact |
|----------------|--------|
| **Shikata Ga Nai** (Metasploit default poly-XOR) | No matching pattern — evades all 84 decoders |
| **call4dword / countdown** poly stubs | Absent — any Metasploit module using these passes through |
| **Alpha3 / unicode_upper / unicode_mixed** | Only one specific prologue covered |
| **SEH-based decoders** | Not present |
| **Egg hunters** | No pattern — staged payloads with egg tag evade detection |
| **Base64 without `LoadTestPassword:` sentinel** | Wrapper required; any other base64 wrapping is invisible |
| **Polymorphic NOP sleds** | Only direct `\x90` match; alternatives (`\x41`-`\x47`, `\x97`, `\xfc`) not stripped |

**Systemic bypass:** `\x00`-byte insertion at signature offsets breaks all 84 decoders simultaneously (C2 above).

### Global architectural tells

| Tell | Detail |
|------|--------|
| `listen(1)` for every port | 3+ simultaneous SYN → 2-3 dropped; real Windows services use SOMAXCONN |
| Empty-data response `\r\n` | Connect + 0 bytes → exactly `\r\n` returned on all ports |
| Uniform 60s timeout | Identical across all ports — real services vary per protocol |
| Single asyncore event loop | Concurrent exploit attempts cause inter-packet timing skew across ports |
