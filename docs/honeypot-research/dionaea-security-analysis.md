# Dionaea — Security Analysis
**Target:** https://github.com/dinotools/dionaea  
**Date:** 2026-08-25  
**Status:** Complete (5 lanes)  
**Language:** C core + embedded Python3 + libemu shellcode emulator  
**Protocol surface:** SMB, MSSQL, MySQL, MongoDB, HTTP, FTP, TFTP, SIP, MQTT, PPTP, UPnP, Memcache, JetDirect/PJL  
**Method:** Static source analysis — C core memory safety, protocol parsing bugs, shellcode emulation/curl SSRF, secondary protocol emulators, detection fingerprints/logging/hpfeeds

---

## Severity Summary

| Sev | Count |
|-----|-------|
| CRITICAL | 10 |
| HIGH | 25 |
| MEDIUM | 24 |
| LOW | 14 |

---

## CRITICAL Findings

---

### C1 — Stack Overflow via Attacker-Controlled VLA
**File:** `src/connection_tcp.c:197-216`

```c
int buf_size = ...;  // from ioctl(SIOCINQ) — socket receive buffer size
ioctl(con->socket, SIOCINQ, &buf_size);
buf_size++;
unsigned char buf[buf_size];  // VLA on thread stack
```

`buf_size` comes from `SIOCINQ` (bytes pending in TCP receive buffer). Attacker fills the socket buffer before `EV_READ` fires — max `net.core.rmem_max` (default ~212 KB, operator-tunable to 6+ MB). Thread stack is typically 8 MB. Controlled VLA that large overflows the stack. The IOCTL fail fallback is `16*1024+1 = 16385` — still a large stack allocation. Triggerable on any TCP connection; no prior auth required.

**Fix:** Replace VLA with `g_malloc`/`g_free`, or cap `buf_size` to a fixed maximum (e.g., 65535).

---

### C2 — Privileged Child Executes Arbitrary Function Pointer from Parent Socket
**File:** `src/pchild.c:40-48`

```c
uintptr_t ptr;
read(fd, &ptr, sizeof(uintptr_t));
pchild_cmd cmd = (pchild_cmd)ptr;
cmd(...);  // called with root privileges
```

The privileged child (runs as root to bind ports < 1024) reads a raw function pointer from a socketpair and calls it with no validation. The parent sends `(uintptr_t)pchild_recv_bind`. Any parent-side memory corruption that allows influencing what is written to `g_dionaea->pchild->fd` results in arbitrary code execution as root. This is also an unconditional privilege escalation primitive: compromise the parent process (any memory corruption finding in the C core or any Python module) → write desired address to the socket → root exec.

---

### C3 — SMB: Auth State Machine Absent — All Commands Processed Unauthenticated
**File:** `modules/python/dionaea/smb/smb.py:166-727`

`process()` dispatches `SMB_COM_NT_CREATE_ANDX`, `SMB_COM_WRITE_ANDX`, and `SMB_COM_TRANSACTION` without checking whether Session Setup has completed. Full IPC$ pipe access without any prior auth.

**Exploit:** `SMB_NEGOTIATE` → `SMB_TREE_CONNECT_ANDX` → `SMB_NT_CREATE_ANDX` (skip Session Setup entirely).

---

### C4 — SMB: NTLM Authenticate Always Returns STATUS_SUCCESS
**File:** `modules/python/dionaea/smb/smb.py:200-306`

Session Setup ESEC path responds `negResult=0` (success) unconditionally for any NTLM Authenticate type-3 blob. Any hash — wrong, zeroed, or garbage — is accepted.

**Trigger:** NTLM Negotiate → any NTLM Authenticate blob → `STATUS_SUCCESS`.

---

### C5 — SMB: Legacy Session Setup Accepts Any Password (Guest Access)
**File:** `modules/python/dionaea/smb/smb.py:307-314`

`SMB_Sessionsetup_AndX_Request2` (WordCount=13) returns `Action=1` (guest) with no password checking.

---

### C6 — MSSQL: TDS7 Login Accepted Unconditionally
**File:** `modules/python/dionaea/mssql/mssql.py:142-175`

Handler logs username/password but always returns `TDS_Token_LoginACK` + Done (success). No auth gate. `PRETDS7_LOGIN` (line 177-182) has identical behavior.

**Trigger:** Any TDS7 Login packet → immediate `LoginACK`.

---

### C7 — MySQL: Auth Challenge Never Verified
**File:** `modules/python/dionaea/mysql/mysql.py:445-457`

State `greeting` → `online` transition on first Client Authentication packet. Challenge-response is generated and sent to the client but the response is never cryptographically verified. All-zeros auth packet accepted.

---

### C8 — Shellcode SSRF via Controlled Download URL (Cloud IMDSv1 Credential Theft)
**File:** `modules/curl/module.c:563-569`

```c
if( strncasecmp(url->str, "http", 4) != 0 )
    return;
session_download_new(i, url->str);
```

Only the scheme prefix is checked. Destination IP/hostname not validated. Shellcode embedding `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDSv1), `http://100.100.100.200/` (Alibaba Cloud), `http://192.168.x.x/`, or `http://127.0.0.1:<PORT>/` causes dionaea to fetch those URLs. curl follows up to 10 redirects (`CURLOPT_FOLLOWLOCATION, 10`). Cloud-deployed instances leak IAM credentials on first matching shellcode.

**Trigger:** Send any exploit payload containing `URLDownloadToFile` or HTTP `connect+RETR` pattern pointing to the metadata endpoint.

---

### C9 — SIP: INVITE Accepted Without Authentication (Toll Fraud Amplification)
**File:** `modules/python/dionaea/sip/__init__.py:297-299`

```python
# ToDo: Check authentication
```

Any caller who knows a valid username pattern can INVITE without credentials. The honeypot enters INVITE_TRYING → INVITE_RINGING → CALL state and initiates outbound UDP RTP to the attacker's IP on the port specified in the SDP `m=` line.

**Trigger:** `INVITE sip:0000000000@target SIP/2.0` with `m=audio <any_port> RTP/AVP 0`.

---

### C10 — MySQL: SQLite Injection via COM_FIELD_LIST Table Name
**File:** `modules/python/dionaea/mysql/mysql.py:101-103`

```python
query = "PRAGMA table_info(%s);" % p.Table.decode('ascii')[:-1]
```

Attacker controls `p.Table` with no sanitization. `COM_FIELD_LIST` with `Table = "x); DROP TABLE connections; --"` executes arbitrary SQLite against the capture database.

---

## HIGH Findings

---

### H1 — Heap OOB Read in XOR Key Decode (xmatch)
**File:** `modules/xmatch/xmatch.c:120-149`

`key->data` allocated as `malloc(pattern->len)`. Decode loop indexes `key->data[j + p - (offset % p)]`. When `offset % p == 0`, index = `j + p`; `j` ranges `[0, p-1]`, so max index is `2p-1`. Valid range is `[0, p-1]`. Reads `p` bytes past allocation from adjacent heap memory. Triggerable if xmatch processor enabled and attacker sends matching network data.

---

### H2 — NULL Dereference in bistream_get_stream Iterator
**File:** `src/bistream.c:267-272`

```c
it = g_list_next(it);
itsc = it->data;  // crash if it == NULL
```

If `start` falls past the last chunk's range (but bounds check passes due to range alignment issues), `g_list_next` returns NULL and `it->data` crashes. Reachable from protocol processors calling `bistream_get_stream`.

---

### H3 — Unix Socket Path Not Null-Terminated; Downstream strlen OOB
**File:** `src/util.c:210-217`

`strncpy(su->sun_path, p, 107)` with no null termination guarantee for inputs 108-125 chars. Followed by `strlen(su->sun_path)` which walks past the 108-byte field into adjacent struct bytes. Inflated length passed to `bind()`/`connect()` system calls.

---

### H4 — SMB: Unbounded `self.buf` Accumulation (Memory Exhaustion)
**File:** `modules/python/dionaea/smb/smb.py:459-461`

`SMB_COM_WRITE_ANDX` with unknown FID appends `h.Data` to `self.buf` with no size cap before the `FragLen == len(self.buf)` gate. Repeated WRITE_ANDX with a FragLen that never matches → unbounded heap growth until OOM.

---

### H5 — SMB: Infinite Loop on Unterminated BER Tag
**File:** `modules/python/dionaea/smb/include/ber.py:114-136`

`BER_identifier_dec` while-loop reads continuation bytes until high-bit clear; never terminates if all bytes have bit 7 set.

**Trigger:** SPNEGO SecurityBlob with BER tag where every continuation byte has bit 7 set → hangs the connection handler thread.

---

### H6 — SMB: No Upper Bound on BER-Decoded Length (4GB Field Accepted)
**File:** `modules/python/dionaea/smb/include/ber.py:154-171`

`BER_len_dec` decodes multi-byte length into `ll` without a max check. Length `\x84\xff\xff\xff\xff` returns 4GB; subsequent slice returns empty bytes, silently corrupting SPNEGO parse.

---

### H7 — MSSQL: Attacker-Controlled Offset Arithmetic (No Bounds)
**File:** `modules/python/dionaea/mssql/mssql.py:148-157`

```python
ib = 8 + packet.getfieldval("ib" + i)   # from TDS7 Login — attacker-controlled
cch = packet.getfieldval("cch" + i) * 2
data[ib:ib+cch]                          # unchecked slice
```

TDS7 Login with `ibUserName=0xffff, cchUserName=0xffff` reads the full remaining buffer.

---

### H8 — MSSQL: SQL Batch Without Login State Check
**File:** `modules/python/dionaea/mssql/mssql.py:186-188`

`TDS_TYPES_SQL_BATCH` has no check that a login sequence completed. TDS Pre-Login → SQL Batch (no Login packet) proceeds normally.

---

### H9 — MySQL: Attacker-Controlled SQLite Query (`ATTACH DATABASE` Bypass)
**File:** `modules/python/dionaea/mysql/mysql.py:228-230`

`p.Query` passed directly to `self.cursor.execute(query)` on fallthrough. `ATTACH DATABASE` regex (line 222) bypassed with double-space or mixed case:

```
Attach  Database '/etc/shadow' AS x; SELECT * FROM x.passwd;
```

---

### H10 — MongoDB: `messageLength=0` Causes Infinite Loop
**File:** `modules/python/dionaea/mongo/mongo.py:163-164`

```python
offset = offset + h.messageLength  # never advances when 0
```

Break condition `len(data) - offset < h.messageLength` → `len(data) < 0` is never true. Permanent hang.

**Trigger:** MongoDB wire header with `messageLength = 0x00000000`.

---

### H11 — NDR: `unpack_string` Unbounded Buffer Read
**File:** `modules/python/dionaea/ndrlib.py:98-108`

`ac` (actual count) from RPC stub, attacker-controlled, used as slice end with no bounds check. `ac=0x7fffffff` returns entire remaining buffer to the RPC handler.

---

### H12 — SMB: `LsarLookupSids2` Attacker-Controlled Entries Drive CPU DoS
**File:** `modules/python/dionaea/smb/rpcservices.py:853-904`

`TranslatedNames.Entries = SidEnumBuffer.Entries` — attacker-controlled, no range check. `Entries = 0x7fffffff` burns CPU until timeout.

---

### H13 — TLS Peer Verification Disabled on All Upload Sessions
**File:** `modules/curl/module.c:506-507`

```c
curl_easy_setopt(session->easy, CURLOPT_SSL_VERIFYPEER, 0);
curl_easy_setopt(session->easy, CURLOPT_SSL_VERIFYHOST, 0);
```

Applied to every upload session — VT submission, `submit_http`, `submit_http_post`. HTTP Basic credentials, VT API key, and raw malware samples transmitted to MITM-able endpoints.

---

### H14 — libemu: Negative `send()` Length Crashes dionaea
**File:** `modules/emu/hooks.c:1031-1034`

```c
int len = va_arg(vl, int);   // signed int from shellcode stack
help->data = g_malloc0(len); // g_error() on failure — terminates process
```

Shellcode calls `send(s, buf, -1, 0)` or `send(s, buf, 0x7fffffff, 0)`. `g_malloc0` with a huge/negative value calls `g_error`, terminating the entire dionaea process. Same pattern in `user_hook__lwrite` (hooks.c:1473) and `user_hook_WriteFile` (hooks.c:1206).

---

### H15 — libemu: FTP URL SSRF → Internal Port Scan
**File:** `modules/python/dionaea/ftp_download.py:314`

Shellcode-controlled FTP URL scheme checked (`ftp://`) but host/port not validated. `ftp://192.168.1.1:22/` causes dionaea to initiate TCP to internal host:port. Active-mode FTP also sends PORT command with dionaea's own listen address to the attacker's FTP server — internal IP topology leak.

---

### H16 — libemu: `recv()` write-what-where Within Emulated Address Space
**File:** `modules/emu/hooks.c:923`

```c
emu_memory_write_block(emu_memory_get(env->emu), buf, ...);
```

`buf` is the 32-bit emulated destination address from shellcode stack — fully attacker-controlled. Shellcode can overwrite its own code region, exception handler tables, or libemu environment structures to redirect emulation to attacker-supplied instruction sequences.

---

### H17 — hpfeeds: strpack8 Modulo-255 Bug — Protocol Desync
**File:** `modules/python/dionaea/hpfeeds.py:75`

```python
struct.pack('!B', len(x) % 0xff)
```

`% 0xff` is modulo-255 (not 256). When `len(x) == 255`, packed length = 0. Broker reads zero bytes as the ident → auth failure or wrong identity → all subsequent publishes misrouted or dropped.

---

### H18 — hpfeeds: Premature `authenticated=True` Before Broker ACK
**File:** `modules/python/dionaea/hpfeeds.py:168`

```python
self.send(msgauth(...))
self.authenticated = True   # set before broker validates
self.handle_io_out()        # drains queued events immediately
```

Rogue broker sends OP_INFO with arbitrary nonce → dionaea marks itself authenticated → begins publishing all honeypot capture data before credential validation. Combined with plaintext transport (F: below), trivial MITM on port 10000 exfiltrates full capture stream.

---

### H19 — hpfeeds: dynip_resolve Over HTTP Without IP Validation — Source IP Spoofing
**File:** `modules/python/dionaea/hpfeeds.py:290, 447-456`

Timer fires every 300s → downloads `http://hpfriends.honeycloud.net/ip` (plaintext HTTP, no TLS, no cert pin) → assigns response body as `self.ownip` with zero format validation. MITM the HTTP GET → return arbitrary string → every hpfeeds event published with attacker-controlled `local_host`. Persistent false attribution in downstream threat-intel feeds.

---

### H20 — hpfeeds: Full Capture Stream in Plaintext TCP
**File:** `modules/python/dionaea/hpfeeds.py:135-232`

`hpclient` is a plain TCP connection. No TLS. `sendfile()`/`sendfiledata()` streams raw malware binaries over the wire. Any network observer on the path between dionaea and the broker obtains a full copy of: raw malware samples, attacker credentials (FTP/MySQL/MSSQL/MQTT usernames+passwords), SIP call metadata, shellcode profiles.

---

### H21 — SIP: Static Nonce `"foobar123"` (Fingerprint + Offline Precompute)
**File:** `modules/python/dionaea/sip/__init__.py:813, 829`

Nonce hardcoded, never rotates. Every dionaea instance globally produces `WWW-Authenticate: Digest nonce="foobar123"` — instant fingerprint for any SIP scanner checking nonce entropy. Also enables offline precompute for credential replay.

---

### H22 — MQTT: Unrecognized Packet Type Crashes Handler
**File:** `modules/python/dionaea/mqtt/mqtt.py:38, 125`

```python
x = None
# none of the elif branches match CONNACK (0x20), PUBACK (0x40), etc.
x.show()  # AttributeError: 'NoneType' object has no attribute 'show'
```

Any first-byte value not matching the handled set (CONNECT, PUBLISH, SUBSCRIBE, PINGREQ, DISCONNECT) crashes the handler. A 2-byte CONNACK (`\x20\x02\x00\x00`) kills the connection with a single packet.

---

### H23 — MSSQL: UnboundLocalError on Unhandled TDS Packet Type
**File:** `modules/python/dionaea/mssql/mssql.py:73-85`

`x` is never assigned for unhandled TDS types (RPC=0x03, ATTENTION=0x06, etc.) but `x.show()` called unconditionally. Any unhandled type byte crashes the MSSQL handler.

---

### H24 — SMB: IPC$ Share Bypass via Case/Trailing-Byte Variation
**File:** `modules/python/dionaea/smb/smb.py:316-359`

Only literal `b'ADMIN$\0'` and `b'C$\0'` are denied. `b'ipc$\0'` (lowercase) or `b'IPC$\0x'` (extra byte) gets a valid TID. Full IPC$ RPC pipe access via case variation.

---

### H25 — Stack Buffer Overflow in opaque_data_dump via Unbounded Recursion
**File:** `src/incident.c:122-123`

```c
char x[1024];
memset(x, '\t', indent);  // no bounds check on indent
```

`opaque_data_dump` calls itself recursively with `indent+1` for list/dict types with no depth limit. Deeply nested incident data from a protocol module overflows the 1024-byte stack buffer.

---

## MEDIUM Findings

---

### M1 — Type Confusion in bistream sizeof Calculation
**File:** `src/bistream.c:224-226`

Casting `GList *` to `struct stream_chunk *` reads `GList->data` instead of the actual string length. Silent size corruption in any caller.

---

### M2 — `g_snprintf` Truncation Check Never Triggers
**File:** `src/modules.c:97-99`

Guard checks for `-1` return but `g_snprintf` (like POSIX `snprintf`) never returns -1 — it returns the number of bytes that would have been written. Module path truncation is silently undetected.

---

### M3 — connection_strerror Off-by-One: Valid Error Code Returns NULL
**File:** `src/connection.c:2219-2224`

Guard `>= ECONMANY` returns NULL for index 3 (the "too many connections" error), so callers receive NULL for a valid code. Any caller that dereferences the return value without NULL check crashes.

---

### M4 — SMB: Bare `except` Consumes All Parsing Exceptions (Permanent Parser Desync)
**File:** `modules/python/dionaea/smb/smb.py:88-92`

`handle_io_in` wraps `NBTSession(data)` in a bare except and returns `len(data)`. Any malformed packet consumed; framing permanently desynced.

---

### M5 — SMB: `self.buf2` Reset to `str` After TRANS2 (TypeError on Next Packet)
**File:** `modules/python/dionaea/smb/smb.py:632-633`

Line 633: `self.buf2 = ''` (str). Next TRANS2 appends bytes to str → `TypeError`. Trigger: send TRANS2 payload >10MB, then one more TRANS2 packet.

---

### M6 — SMB: OOB Index in MZ Scan (IndexError)
**File:** `modules/python/dionaea/smb/smb.py:652-653`

`xor_output[i+1]`/`xor_output[i+2]` without `i+2 < len(xor_output)` guard. Trigger: DoublePulsar payload with MZ signature at final two bytes.

---

### M7 — SMB: Cross-Session FID Close (No Ownership Validation)
**File:** `modules/python/dionaea/smb/smb.py:365-374`

`SMB_COM_CLOSE` checks `FID in self.fids` but not session ownership. FIDs are sequential (`0x4000 + n*0x200`) — predictable. Brute-force FID → close another session's handle.

---

### M8 — SMB: DCERPC Request Accepted Without Prior Bind
**File:** `modules/python/dionaea/smb/smb.py:793-795`

If `uuid` not in `self.state`, logs warning but falls through — may reach service handlers via alternate UUID injection path.

---

### M9 — MSSQL: `cmd[1]` Access Without Length Guard (IndexError)
**File:** `modules/python/dionaea/mssql/mssql.py:188`

No check that SQL Batch payload is ≥ 2 bytes before Unicode heuristic test. Trigger: SQL Batch with 0- or 1-byte payload.

---

### M10 — MySQL: Logic Inversion on DB Open (Error on Success, OK on Failure)
**File:** `modules/python/dionaea/mysql/mysql.py:453-455`

```python
if self._open_db(Database) == True:
    r = MySQL_Result_Error(...)  # inverted
```

Successful database open returns error; failed open returns OK.

---

### M11 — MySQL: Unknown Command Byte Raises Unhandled `KeyError`
**File:** `modules/python/dionaea/mysql/mysql.py:466`

`MySQL_Commands[p.Command]` — if `p.Command` not in dict, crashes with `KeyError`. Any unregistered MySQL command byte (real MySQL clients send these) kills the handler.

---

### M12 — MongoDB: OP_COMMAND Single-Document Crash
**File:** `modules/python/dionaea/mongo/mongo.py:197-199`

`docs[0]` and `docs[1]` accessed; `bson.decode_all` returning <2 documents raises `IndexError`. Trigger: OP_COMMAND (opCode 2010) with single BSON document.

---

### M13 — NDR: Alignment Padding Attacker-Influenceable (Field Desync)
**File:** `modules/python/dionaea/ndrlib.py:83-90`

`self.__pos += self.__pos % 4` — padding derived from running position controlled by prior RPC struct fields. Crafted layout causes wrong fields to be parsed.

---

### M14 — libemu: Write-Before-Check Disk Fill (2GB per Connection)
**File:** `modules/emu/hooks.c:1205-1216`

Filesize limit checked via `ftell` after the write. Shellcode calling `WriteFile(h, buf, 2147483647, ...)` writes up to 2GB to disk before check fires. Concurrent sessions multiply impact.

---

### M15 — VT API Key Transmitted in Incident Plaintext (Visible in Debug Logs)
**File:** `modules/python/dionaea/virustotal.py:129`

API key set as a named field on every `dionaea.upload.request` incident. At default `logging.DEBUG`, the curl debug callback logs request details including the API key.

---

### M16 — libemu: GetPC-Only Detection Heuristic — Known Bypass Classes
**File:** `modules/emu/detect.c:133`

`emu_shellcode_test` covers only GetPC variants. Bypassed by SEH-based GetPC, position-independent with known load address, egg-hunter patterns, and staged delivery with pure data-decoding first stage. When bypassed: no profile(), no emulate(), no download URL extraction — complete IOC blind spot.

---

### M17 — MD5 Deduplication Bypass via Chosen-Prefix Collision
**File:** `modules/python/dionaea/store.py:49`

```python
md5 = md5file(p)
n = os.path.join(self.download_dir, md5)
```

MD5 chosen-prefix collisions are feasible in seconds on modern hardware. Deliver legitimate-looking PE to populate the MD5 key, then deliver the malicious variant that collides — second payload escapes both VT submission and S3 upload via `dionaea.download.complete.again` branch.

---

### M18 — SIP: Personality Logic Inversion Bypasses Method ACLs
**File:** `modules/python/dionaea/sip/extras.py:295`

```python
if personality in self.personalities:   # should be "not in"
    personality = "default"
```

For every valid named personality, resets to "default". Configured per-personality method restrictions never applied.

---

### M19 — SIP: Via Header Accepted Verbatim — Third-Party Response Routing
**File:** `modules/python/dionaea/sip/rfc3261.py:488-489`

Via headers deep-copied into responses without validating topmost Via address against the connection's actual source IP. Attacker injects `Via: SIP/2.0/UDP <victim_ip>:5060` → honeypot sends SIP responses to victim.

---

### M20 — MQTT: CONNECT Always Succeeds (No Auth Validation)
**File:** `modules/python/dionaea/mqtt/mqtt.py:140-141`

Username and password logged to incident then discarded. Always returns `CONNACK` with return code 0 (accepted). Real brokers reject invalid credentials with 0x04/0x05.

---

### M21 — FTP: PORT Bounce Drop Without 5xx Response (RFC Violation + Fingerprint)
**File:** `modules/python/dionaea/ftp.py:319-322`

Anti-bounce check logs warning and returns `None` with no response. RFC 959/2577 require `501 Server cannot accept argument.` The silent drop is fingerprint-detectable.

---

### M22 — FTP: Unlimited Directory Creation (Inode Exhaustion)
**File:** `modules/python/dionaea/ftp.py:557`

No depth limit, count limit, or rate limit on `MKD`. After auth (any credentials accepted), tight `MKD` loop exhausts inodes in the download directory.

---

### M23 — TFTP: Root Confinement `startswith` Escape via Sibling Directory
**File:** `modules/python/dionaea/tftp.py:667`

```python
if self.filename.startswith(os.path.abspath(self.root)):
```

With `root="/srv/tftp"`, the path `/srv/tftpextra/evil` satisfies `startswith("/srv/tftp")` = True. If a sibling directory exists with matching prefix name, `../tftpextra/evil` escapes confinement.

**Fix:** `startswith(os.path.abspath(self.root) + os.sep)`

---

### M24 — PPTP: Length Field No Bounds Check Against Received Data
**File:** `modules/python/dionaea/pptp/pptp.py:66-68`

`p.Length` from wire only checked for 0. `Length = 0xFFFF` with 4 bytes of data — scapy reads fixed-length struct fields from too-short buffer, producing garbage fields used in the response.

---

### M25 — JetDirect/PJL: ECHO Reflects Attacker Input Verbatim
**File:** `modules/python/dionaea/printer.py:463-469`

```python
def pjl_ECHO(self, command):
    stripped_command = command.strip()
    self.reply(stripped_command)
```

ESC sequences, PJL control codes, and binary data reflected without sanitization.

---

### M26 — JetDirect/PJL: PCL Data Written Without Size Limit
**File:** `modules/python/dionaea/printer.py:554-572`

All data received in PCL mode appended to a single file per connection with no max file size or disk space check. Continuous stream on port 9100 fills the `download_dir` partition.

---

### M27 — Log Injection via Attacker-Controlled `remote.host`
**File:** `src/log.c:319`; triggered from `logsql.py:645`, `log_json.py:186`

`con.remote.host` (attacker's IP/rDNS) inserted into log format strings without escaping. IPv6 or crafted rDNS containing `\n` creates injected log lines with fresh timestamps. SIEM parsers triggered by forged entries.

---

## LOW Findings

---

### L1 — `connection_set_blocking` Sets All Flags Instead of Clearing O_NONBLOCK
**File:** `src/connection.c:759`

```c
flags |= ~O_NONBLOCK;  // should be flags &= ~O_NONBLOCK
```

Sets all bits except O_NONBLOCK. Connection remains nonblocking when it should switch to blocking mode.

---

### L2 — `connection_listen_timeout_set` Activates Wrong Timer
**File:** `src/connection.c:1467`

```c
ev_timer_again(CL, &con->events.sustain_timeout);  // should be listen_timeout
```

Listen connections never expire. Sustain timeouts fire spuriously, potentially closing established connections.

---

### L3 — `connection_reconnect` Skips Socket fd 0
**File:** `src/connection.c:1091`

```c
if( con->socket > 0 )  // should be != -1
```

If stdin is closed before socketpair creation and fd 0 is assigned, the socket is never closed on reconnect.

---

### L4 — NTLM Version Field Not Validated; Field-Offset Corruption
**File:** `modules/python/dionaea/smb/include/ntlmfields.py:196`

If `NTLMSSP_NEGOTIATE_VERSION` set and packet too short, Version parsing reads from next field's bytes, corrupting all subsequent field offsets.

---

### L5 — HTTP: Request Line Split Without Arity Check (IndexError)
**File:** `modules/python/dionaea/http.py:119-123`

`reqparts[0]`, `[1]`, `[2]` accessed after `split(b" ")` with no length check. `GET\r\n` crashes handler.

---

### L6 — HTTP: Response Splitting via CRLF in Stored Headers
**File:** `modules/python/dionaea/http.py:141-142`

Header values not stripped of `\r\n` before storage; re-emitted verbatim in responses.

---

### L7 — hpfeeds: Empty Default `ident`/`secret` in Shipped Config
**File:** `conf/ihandlers/hpfeeds.yaml:9-10`

Default config ships with empty strings. SHA1(rand + `""`) is trivially brute-forceable. Common in automated deployments where operators don't fill in credentials.

---

### L8 — p0f: Null-Byte `find()` Inverted — Binary Data Into SQLite
**File:** `modules/python/dionaea/p0f.py:67`

```python
if s.find(b'\x00'):  # returns 0 (falsy) when found at position 0 — truncation skipped
```

NUL at field offset 0 in a malicious p0f daemon response bypasses truncation and lands raw binary in `p0f_genre`/`p0f_detail` SQLite columns.

---

### L9 — services.py: Always-True Condition — `addr.del` Never Tears Down Services
**File:** `modules/python/dionaea/services.py:71`

```python
if icd.origin == "dionaea.module.nl.addr.new" or "dionaea.module.nl.addr.hup":
```

Non-empty string is always truthy. `addr.del` branch at line 90 is unreachable. Services accumulate without cleanup on interface address churn.

---

### L10 — SIP: SDP SQL Placeholder Bug — Operator SDP Templates Never Load
**File:** `modules/python/dionaea/sip/extras.py:250`

```python
ret = self._cur.execute("SELECT sdp FROM sdp WHERE name='?'")
```

`'?'` is a string literal. Named argument is ignored. Always returns no rows, falling to default SDP. Operator-configured per-personality SDP templates silently never applied.

---

### L11 — SIP: Nonce Not Bound to Connection (Challenge Confusion on UDP)
**File:** `modules/python/dionaea/sip/__init__.py:806-833`

`self._auth` stored per SipSession (shared across UDP connections on port 5060). Second REGISTER from a different user overwrites `self._auth`, enabling the second client to answer the first client's challenge.

---

### L12 — PPTP: MagicCookie Never Validated
**File:** `modules/python/dionaea/pptp/pptp.py:63-86`

RFC 2637 requires `MagicCookie == 0x1A2B3C4D`. Dionaea parses but never validates. Packets with zeroed magic are processed normally.

---

### L13 — FTP: All Credentials Accepted (Always `331`/`230`)
**File:** `modules/python/dionaea/ftp.py:284-299`

Always sends `331` at `USER` stage (real servers send `530` for unknown users) and `230` at `PASS`. Fingerprints dionaea from the first login attempt.

---

### L14 — PPTP: `PeerCallID=0` in Outgoing-Call-Reply — Real Clients Disconnect
**File:** `modules/python/dionaea/pptp/packets.py:105`

RFC 2637 §9.2 requires echoing the client's `CallID` into `PeerCallID`. Hardcoded 0 prevents GRE demultiplexing. Windows PPTP clients log event ID 20227 and disconnect. Fingerprints dionaea to any real PPTP client.

---

## Detection Fingerprint Summary

Dionaea is identifiable across all emulated protocols with minimal interaction:

| Signal | Method | Confidence |
|--------|--------|------------|
| SIP `WWW-Authenticate: Digest nonce="foobar123"` | Single REGISTER | ~100% |
| SIP INVITE accepted without 401 challenge | Single INVITE | ~100% |
| FTP: any credentials accepted (`331`→`230`) | USER+PASS | ~100% |
| FTP: static banner "Welcome to the ftp service" | TCP connect | ~95% |
| MySQL: any auth packet accepted | 1 packet | ~100% |
| MSSQL: any TDS7 Login accepted | 1 packet | ~100% |
| MQTT: `CONNACK 0x20 0x02 0x00 0x00` regardless of `clean_session` | 1 CONNECT | ~100% |
| MQTT: SET→GET returns END (data not retained) | 2 packets | ~100% |
| Memcache: SET returns STORED, GET returns END for same key | 2 commands | ~100% |
| TFTP: WRQ returns error 4 (Illegal) instead of error 2 (Access Violation) | 1 packet | ~99% |
| PPTP: `PeerCallID=0` in Outgoing-Call-Reply | 1 handshake | ~100% |
| Echo: reverses and truncates input instead of verbatim echo (RFC 862) | 1 packet | ~100% |
| hpfeeds channel names in plaintext TCP/10000 | Passive capture | ~100% |
| hpfeeds dynip_resolve HTTP GET to `hpfriends.honeycloud.net/ip` every 300s | Passive capture | ~100% |
| SQLite schema: `dcerpcbinds`, `emu_profiles`, `mssql_fingerprints`, `mqtt_fingerprints` | Local read | ~100% |
| JSON log: `dst_ip/dst_port/src_ip/src_port/connection.protocol/connection.transport` exact schema | Log access | ~100% |
| UPnP: only M-SEARCH handled; NOTIFY/SUBSCRIBE/GET return nothing | Passive UPnP | ~90% |

---

## Attack Chains

**Chain 1 — Shellcode SSRF → Cloud Credential Exfiltration:**
Send any exploit payload to dionaea's SMB/FTP/HTTP listener that contains `URLDownloadToFile` or HTTP connect/RETR with `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → libemu detects shellcode → curl module fetches URL → AWS IAM credentials returned and stored as a malware "sample." No auth required, no login state.

**Chain 2 — hpfeeds MITM → Full Capture Stream Exfiltration:**
Position on path between dionaea and `hpfriends.honeycloud.net:10000` (plaintext TCP). Send OP_INFO with arbitrary nonce → dionaea sends OP_AUTH with SHA1(nonce+secret), marks `authenticated=True`, begins publishing. Receive: raw malware binaries, attacker credentials from FTP/MySQL/MSSQL/MQTT, SIP call metadata, shellcode profiles.

**Chain 3 — MySQL `COM_FIELD_LIST` → Capture DB Destruction:**
Connect to MySQL port (any credentials accepted) → send `COM_FIELD_LIST` with `Table = "x); DROP TABLE connections; --"` → SQLite injection executes against capture database → all collected connection records deleted.

**Chain 4 — C Core VLA Overflow → Root via pchild:**
Trigger C1 (VLA stack overflow on any TCP connection) → corrupt parent process heap/stack → write desired function address to pchild socketpair → C2 executes it as root.

**Chain 5 — SIP INVITE → RTP Amplification:**
No credentials needed. Send `INVITE sip:0000000000@target SIP/2.0` with `m=audio <attacker_port> RTP/AVP 0` → dionaea enters CALL state, initiates UDP RTP stream to attacker-controlled port → potential bandwidth amplification from the sensor.

**Chain 6 — FTP → Inode Exhaustion → Logging Disruption:**
Any credentials accepted → tight `MKD` loop → ext4 inode exhaustion in `download_dir` → dionaea cannot write new capture files → malware samples silently discarded → attacker operates unlogged.
