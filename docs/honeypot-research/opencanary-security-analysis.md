# OpenCanary — Security Analysis

**Repo:** https://github.com/thinkst/opencanary  
**Lanes:** 5 parallel (SSH/Telnet/MySQL/MSSQL · HTTP/Git/MongoDB/Redis/Samba/HttpProxy · FTP/VNC/RDP/SIP/SNMP/NTP/TFTP/LLMNR/TCPBanner · Core/Logger/Config · Fingerprints/Evasion)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 11 |
| MEDIUM | 22 |
| LOW | 18 |

Python 3 migration is incomplete throughout the codebase — `bytes` vs `str` confusion silently disables entire subsystems (credential capture, error handling, alerting). Four modules crash on first valid protocol packet. The honeypot fingerprints itself across every emulated protocol via hardcoded strings, static values, and structural omissions detectable in a single round-trip.

---

## CRITICAL

### C1 — httpproxy.py:76-80 — `exit(1)` in NTLM handler kills entire OpenCanary process

Debug code shipped to production. Any HTTP proxy connection sending a valid-UTF-8 NTLM token triggers `exit(1)`, terminating the entire OpenCanary daemon — every module, every port.

```python
elif atype == "NTLM":
    print(b64decode(token).decode("utf-8").split(":"))
    exit(1)   # <-- kills the process
```

**Trigger:** `Proxy-Authorization: NTLM dGVzdA==` (decodes to `test`, valid UTF-8). Single TCP connection, no auth needed.  
**Impact:** Complete DoS of the honeypot. All emulated services go dark simultaneously.

---

### C2 — mssql.py:129 — `bytes.find(str)` TypeError crashes PRELOGIN handler

Python 3 type bug. `bytes.find()` requires a `bytes` argument; `str` raises `TypeError`. The PRELOGIN handler runs this on every first connection.

```python
if data.find("SQLSERVER") >= 0:  # TypeError in Python 3
```

**Trigger:** Any TDS PRELOGIN packet (standard SQL Server client connection).  
**Impact:** MSSQL module crashes on first packet from any client. No credentials logged.

---

### C3 — mssql.py:346 — No return after `abortConnection()` on null `loginData`

Control flow continues after connection abort. If `loginData` is `None`, `abortConnection()` fires, but execution falls through to `loginData["USERNAME"]` reference, raising `KeyError` inside a partially-aborted connection state.

**Trigger:** Any malformed LOGIN7 TDS packet where the login parser returns `None`.  
**Impact:** Protocol handler crash; unhandled exception propagates into Twisted reactor.

---

### C4 — mssql.py:397 — `self.logAuth()` does not exist on `MSSQLProtocol`

Latent `AttributeError`. The `TDS_TYPE_SSPI` (Windows auth) handler calls `self.logAuth()` which is not defined anywhere on the class.

```python
def handle_sspi(self, data):
    self.logAuth(...)  # AttributeError — method does not exist
```

**Trigger:** Send a TDS packet with type byte `0x11` (SSPI/Windows auth).  
**Impact:** Connection crashes with unhandled `AttributeError`. Confirmed via Lane 5 single-packet probe: send `0x11` → connection aborts.

---

## HIGH

### H1 — logger.py:37 — `globals().get(classname)` resolves config-controlled log handler class

Config-controlled class name is resolved via `globals()` at runtime. An attacker who can write to the OpenCanary config file (or inject config via the `/api/` endpoint if exposed) can point any log handler to an arbitrary class in scope, including `HTTPHandler`, `SocketHandler`, or any imported module.

```python
handler_class = globals().get(classname)
```

**Impact:** SSRF/exfiltration — log handler can be redirected to attacker-controlled endpoints. If combined with `os.path.expandvars()` in config parsing (see M1), full chain: env var sets handler URL → logs exfiltrated.

---

### H2 — logger.py:271,349,409 — SlackHandler/TeamsHandler/WebhookHandler accept arbitrary URLs

No validation on the webhook destination URL in any of the three alerting handlers. Config-supplied webhook URL is used directly.

**Impact:** SSRF via misconfiguration or config compromise. Alerts (including captured credentials) can be exfiltrated to attacker-controlled endpoints.

---

### H3 — redis.py:11-18 — `bytes.format()` disables all Redis error handling

Both `ProtocolError` and `ArgumentCountError` call `.format()` on a `bytes` literal, which doesn't exist in Python 3. Their `__init__` methods always raise `AttributeError` before the exception is constructed.

```python
self.message = b"-ERR Protocol error: {reason}\r\n".format(reason=reason)
# AttributeError: 'bytes' object has no attribute 'format'
```

**Impact:** `except ProtocolError` blocks in `dataReceived` never fire. Protocol errors (unbalanced quotes, wrong arg counts) are silently swallowed — no error sent to client, no log entry. Attacker can probe Redis protocol edge cases without generating alerts.

---

### H4 — redis.py:33-34 — RESP response injection via `UnknownCommandError`

`.replace()` result is discarded — newlines remain in the command name before it's embedded in the RESP error response.

```python
cmd.replace("\r", " ").replace("\n", " ")  # result not assigned back
self.message = ("-ERR unknown command '{cmd}'\r\n".format(cmd=cmd.lower())).encode()
```

**Trigger:** Send command name `FOO\r\n+PONG`. Response contains `\r\n+PONG` which the client's RESP parser reads as a separate `+PONG` message — arbitrary RESP token injection into the response stream.

---

### H5 — samba.py:14-35 — Field injection via pipe character in attacker-controlled SMB fields

The audit line is split on `|`; fields are accessed by fixed index. Client hostname, username, or share path containing `|` shifts all subsequent field lookups.

**Trigger:** Connect to Samba with a NetBIOS name containing `|fake_user|fake_ip|...`. What OpenCanary logs as `USER` becomes `srcHost`.  
**Impact:** Attacker controls every logged field — enables false-flag attribution in incident response.

---

### H6 — samba.py:22-35 — `IndexError` crashes log watcher on malformed pipe-delimited lines

`data[0]` through `data[12]` accessed unconditionally with no length check. Reachable via the pipe injection above.

**Impact:** Uncaught `IndexError` kills the log watcher thread or drops all subsequent samba events, depending on `FileSystemWatcher` exception handling.

---

### H7 — httpproxy.py:73 — Basic auth credential capture broken in Python 3

`b64decode(token)` returns `bytes`. `.split(":")` with a `str` separator raises `TypeError`. Caught by bare `except:` — silently discarded.

**Impact:** All Basic auth credentials submitted to the proxy honeypot are lost. The primary collection function fails completely in Python 3.

---

### H8 — llmnr.py:33-51 — False alert injection via crafted LLMNR response

`datagramReceived` processes any packet on UDP 5355, including attacker-crafted responses with spoofed source IPs.

**Trigger:** `scapy send(IP(src="victim.ip")/UDP(sport=5355,dport=5355)/DNS(qd=DNSQR(qname="DC03")))` — generates alert attributing the event to the spoofed victim IP.  
**Impact:** Attacker generates alerts pointing to arbitrary innocent hosts. False-flag incident response misdirection.

---

### H9 — tcpbanner.py:144 — Python 3 type confusion silently disables keep-alive alerting

`self.keep_alive_secret` is `bytes`. Guard is `if self.keep_alive_secret != ""` — in Python 3, `bytes != str` is always `True`. If secret is left unconfigured (`b""`), `b"" in data` is always `True`. First data packet from any attacker permanently sets `self.keep_alive_disable_alerting = True`.

**Impact:** Keep-alive-enabled TCPBanner instances silently stop alerting after the first connection if `keep_alive_secret` is not explicitly configured.

---

### H10 — portscan.py:57 — SYN spoofing generates false alerts

`src_host` comes from the IP header, which is trivially spoofable on SYN packets (no response needed). Attacker can attribute portscan alerts to arbitrary IPs.

**Trigger:** `hping3 --spoof victim_ip -S <canary_ip> -p 80`  
**Impact:** False-flag alert generation; can flood alert queue with events attributing innocent parties.

---

### H11 — mssql.py:182 — Password decoding never works in Python 3

`ord(int)` raises `TypeError` in Python 3. The XOR-decoding loop for captured passwords always crashes. No MSSQL credentials are ever captured.

```python
ch = bytearray[offset]  # returns int in Python 3
password += chr(ord(ch) ^ 0xa5)  # TypeError: ord() expected string of length 1
```

---

## MEDIUM

### M1 — config.py:24 — `os.path.expandvars()` on all config strings — env var injection

Every string in the config is passed through `os.path.expandvars()`. An attacker who can set environment variables on the OpenCanary process (e.g., via a parent process, Docker env injection) can control any config string including webhook URLs and log handler destinations.

---

### M2 — iphelper.py:10 — `socket.inet_aton()` IPv4-only; IPv6 bypasses ignorelist

`inet_aton()` raises `OSError` on IPv6 addresses. The exception is caught and IPv6 addresses are treated as "not in the ignore list." An attacker using an IPv6 source address bypasses all configured IP ignoring.

---

### M3 — opencanary/modules/mssql.py — `thinkst.com` in hardcoded NTLM challenge blob

Static NTLM challenge payload contains `win2k12-domainsrv.corp.thinkst.com`. Any packet capture or NTLM challenge inspection trivially identifies the honeypot.

---

### M4 — opencanary/modules/mysql.py:135 — Unbounded buffer accumulation (OOM DoS)

`self.buf += data` with no upper bound. 47,999,999 bytes of garbage triggers no guard until the `MONGO_MAX_MESSAGE_SIZE_BYTES` check fires. Per-connection ~48 MB allocation possible.

---

### M5 — opencanary/modules/ssh.py:432 — `TypeError` when `preauth_banner` is set

`bytes` vs `str` comparison when banner is configured. Crashes the SSH session setup before any connection is accepted.

---

### M6 — httpproxy.py:92-96 — Jinja2 renders `url` without autoescape — XSS in 407 response

`Template(f.read())` with `autoescape=False` (default). `url=self.uri.decode()` is attacker-controlled. If `auth.html` renders `{{ url }}`, XSS in the 407 response.

---

### M7 — httpproxy.py:73 — Passwords with `:` silently discarded

`split(":")` without `maxsplit=1`. `ValueError` on passwords containing colons caught by bare `except:`. Any password with `:` is never logged.

---

### M8 — mongodb.py:265-289 — Incomplete SCRAM handshake immediately fingerprints honeypot

Returns `{ok: 0, errmsg: "Authentication failed."}` to `saslStart`. Real MongoDB 4.x sends a SCRAM server-first-message. Any conforming MongoDB driver identifies this as an invalid server in one round-trip.

---

### M9 — redis.py:271 — `QUIT` handler writes `str` to Twisted transport — `TypeError` in Python 3

`self.transport.write("+OK\r\n")` — Twisted requires `bytes`. `TypeError` crashes the QUIT handler.

---

### M10 — redis.py:293-298 — Truncation counter is negative — leaks configuration

`str(self.factory.max_arg_length - len(args))` where `len(args) > max_arg_length` always produces a negative number. Log records `"(and -170 more bytes)"`. Reveals the configured truncation limit.

---

### M11 — http.py:76-79 — Partial XSS via attacker-controlled path in error page

`err_page()` strips `<` and `>` but not quotes. If a skin template places `[[URL]]` inside an HTML attribute, quote characters break attribute context.

---

### M12 — git.py:33-39 — Log injection and wire-response injection via repository path

Attacker-controlled path goes into both log (`REPO` field) and pkt-line error response. Path containing `\n0000` injects arbitrary git protocol framing.

---

### M13 — mongodb.py:278-287 — Log injection via BSON-extracted username

`str(auth_doc)` logged without sanitization. Username `foo\n"action":"mongodb.connection","username":"admin"` shapes synthetic log records.

---

### M14 — ftp.py:30-75 — FTP bounce pre-auth via inherited Twisted `PORT` handler

`LoggingFTP` only overrides `ftp_PASS`. Parent's `ftp_PORT` handler is active pre-auth. Depending on Twisted version, enables active-mode data connection to attacker-controlled IP:port.

---

### M15 — vnc.py:86 — Python 3 type comparison bug — security type byte never validated

`data != "\x02"` compares `bytes` to `str` → always `True`. The security-type byte value is never checked. Any single byte proceeds to auth phase.

---

### M16 — rdp.py:24 — Domain-format usernames (`CORP\user`) logged as `None`

Regex `[a-zA-Z0-9-_@]*` misses backslash. Domain-joined username formats produce empty username field in alert.

---

### M17 — sip.py:17 — Log injection via attacker-controlled SIP headers

Raw Twisted SIP headers dict logged without sanitization. Newlines in `User-Agent` or other headers inject into log stream.

---

### M18 — snmp.py:19-20 — Log injection via community string and OID values

Community string and OID values logged directly. Community `"public\nFAKE LOG ENTRY action=admin"` shapes synthetic log records.

---

### M19 — tftp.py:33 — Log injection via attacker-controlled filename

TFTP filename logged without sanitization. `\x00\r\nFAKE_ALERT\r\n` as filename injects into log stream.

---

### M20 — llmnr.py:15-18 — `query_interval=0` floods LAN with multicast LLMNR queries

No minimum interval enforced on `startQueryLoop`. Misconfigured interval floods `224.0.0.252:5355`.

---

### M21 — llmnr.py:44 — Log injection via Scapy `summary()` of attacker-controlled packet

`llmnr_response.summary()` includes decoded `qname` string. Attacker-controlled qname containing newlines injects into log.

---

### M22 — tcpbanner.py:139 — Empty `alertstring` triggers alert on every data packet

`b"" in data` always `True`. Any operator who enables `alertstring` without setting a value gets alert fatigue / log flooding on every connection.

---

## LOW (Selected)

- **ssh.py:23** — Static host key at `/var/tmp/id_rsa`. Same key across all deployments.
- **mysql.py** — Thread ID starts in 0-4095 range, static capability bytes `\xff\xf7\x08\x02`, sequence ID hardcoded `0x02` on error.
- **mssql.py** — `spid=54` hardcoded in all TDS responses; PRELOGIN VERSION always `\x0c\x00\x10\x04\x00\x00` regardless of configured version.
- **mongodb.py** — `requestID=9999` in all OP_MSG responses; `connectionId=1` always; `localTime` BSON type `0x02` (string) not `0x09` (datetime); wire version 8 with claimed version 4.4.6.
- **vnc.py:132** — "111111" duplicated in COMMON_PASSWORDS (indices 0 and 5), wasting one brute-force slot.
- **mtls.py:175** — Weak cert serial: `random.randint(0, 100000000)` — Mersenne Twister, not CSPRNG.
- **portscan.py** — Only detects SYN/Null/XMAS/FIN/T3; ACK scan, Window scan, UDP, ICMP all evade.
- **portscan.py:122-192** — iptables rules installed via `os.system()` with no verification they succeeded.
- **ntp.py:23** — `d[3] != "*"` check — edge case Unicode confusion for bytes 0xC0+ could misclassify packets.
- **ftp.py:37-43** — No truncation on logged password length; multi-megabyte PASS argument written to log in full.
- **snmp.py:28** — `except Exception: print(e); pass` — malformed SNMP silently dropped, allows Scapy version probing.
- **sip.py:18** — `transport.getPeer` monkeypatched per-datagram on shared UDP socket — race condition can log wrong source IP.
- **tftp.py:16-17** — 5-byte guard too short; 5-6 byte malformed packet raises uncaught `ValueError` into Twisted error log.

---

## Fingerprint Summary — Single-Packet Identifiers

| Protocol | Definitive Signal | Detection Method |
|----------|------------------|-----------------|
| SSH | `SSH-2.0-OpenSSH_5.1p1 Debian-5` banner | Banner grab |
| SSH | No `ssh-ed25519` / `ecdsa-*` in KEXINIT | KEXINIT parse |
| Telnet | IAC `\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f` on connect | Byte match |
| HTTPS | Cert Subject `O=Synology Inc. CA` | TLS handshake |
| MySQL | Capability bytes `\xff\xf7\x08\x02` at greeting offset 14 | Greeting parse |
| MSSQL | `thinkst.com` in NTLM challenge blob | Byte search |
| MSSQL | TDS_TYPE_SSPI (0x11) → connection abort | Send 0x11 |
| MongoDB | `requestID=9999` in OP_MSG response | Wire protocol |
| MongoDB | `localTime` BSON type 0x02 (string) not 0x09 (datetime) | BSON type check |
| Redis | `-ERR invalid password` missing `WRONGPASS` | Auth error string |
| VNC | RFB 3.7/3.8 client → immediate ProtocolError close | Send 3.7 version |
| RDP | X.224 CC `src-ref=0x1234` hardcoded | X.224 field parse |
| Git | `git-receive-pack` → immediate connection close | Send receive-pack |
| SIP/SNMP/NTP/TFTP | No response to any well-formed request | Send request, await silence |

**Cross-protocol tells:**
- Port co-occurrence: SSH+Telnet+FTP+MySQL+HTTP+HTTPS+MSSQL+Redis simultaneously = definitive honeypot
- All auth fails uniformly across all protocols
- Twisted reactor timing characteristics consistent across all TCP modules
- LLMNR module actively queries `DC03` to `224.0.0.252` every ~60s — queries from a host with all these other ports open is unambiguous
