# Conpot — Security Analysis

**Repo:** https://github.com/mushorg/conpot  
**Type:** ICS/SCADA multi-protocol honeypot (S7comm, Modbus, IEC104, BACnet, SNMP, HTTP, FTP, TFTP, Kamstrup, IPMI, Guardian AST, EtherNet/IP)  
**Lanes:** 5 parallel (ICS protocols/core · SNMP/HTTP/FTP/TFTP · IPMI/AST/Kamstrup/VFS · logging/config · fingerprints/evasion)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 6 |
| HIGH | 18 |
| MEDIUM | 10 |
| LOW | 7 |

Conpot embeds multiple process-killing `eval()` calls, three fully unauthenticated management protocols (IPMI, Guardian AST, Kamstrup), and a design flaw where unauthenticated Modbus writes mutate a shared databus read by all protocols simultaneously. The fingerprint surface is extreme: impossible hardware co-presence across all running protocols, hardcoded leet easter eggs in SZL responses, and static device strings make identification trivial.

---

## CRITICAL

### C1 — databus.py:90,98 — `eval()` on XML template data → RCE at init

`conpot/core/databus.py:90,98` calls `eval(value)` and `eval(params[0])` on arbitrary strings from `<key_value_mappings>` XML nodes during databus initialization. Function-type values intentionally invoke `__import__` via namespace resolution (lines 92-99), compounding blast radius — the template controls both the `eval` path and dynamic class instantiation simultaneously.

**Trigger:** Attacker-writable path to any template XML file → code execution as the Conpot process user at next restart.  
**Impact:** Full RCE. Not sandboxed.

---

### C2 — conpot/protocols/http/command_responder.py — XPath injection via request path

```python
configuration.xpath('//http/htdocs/node[@name="' + self.path.partition("?")[0] + '"]')
```

The HTTP request path is concatenated directly into an XPath expression. A request to `/"]/../../*["` or equivalent traverses and extracts the entire configuration document, including all databus key/value mappings, hpfeeds credentials, and any secrets stored in the XML config.

**Trigger:** `GET /"]/ancestor-or-self::*["a"="a HTTP/1.0` or Burp Intruder with XPath payloads.  
**Impact:** Full configuration extraction including credentials; potential for XPath boolean-blind enumeration of the entire XML tree.  
**Note:** The same file also calls `eval()` on a template key attribute during response construction.

---

### C3 — log_worker.py:62 — `eval()` on hpfeeds channel list from config

```python
eval(config.get("hpfeeds", "channels"))
```

The hpfeeds channel list is parsed via `eval()` at initialization. Any write access to `conpot.cfg` (world-readable by default in most deployments) allows injecting arbitrary Python code executed at Conpot startup.

**Trigger:** Write `channels = __import__('os').system('backdoor_cmd')` to the `[hpfeeds]` section.  
**Impact:** Pre-auth RCE via config file — any local user or attacker with file-write access.

---

### C4 — fakesession.py:87-103 + ipmi_server.py:199 — IPMI pre-session auth bypass

After `send_auth_cap` fires, `self.session.ipmicallback` is set to `handle_client_request` (line 199). From that point, any IPMI v2 packet with `payload_type=0`, no auth/encrypt bits set, and `session_id=0` triggers the `presession_v2` path at `fakesession.py:90-103`. That path calls `_ipmi15 → _parse_payload → ipmicallback`, bypassing RAKP entirely.

**Trigger:** Send Get Channel Auth Capabilities, then immediately send an IPMI v2 payload with `data[6:10]=\x00\x00\x00\x00`, auth/encrypt bits clear, any valid IPMI command body. No RAKP exchange needed.  
**Impact:** All IPMI management commands execute without authentication — power control, user enumeration, privilege escalation, Set User Password.

---

### C5 — guardian_ast_server.py — Zero authentication on all tank telemetry and write commands

No authentication gate of any kind. TCP connect → send `\x01I20100\n` → full IN-TANK INVENTORY (volumes, temperature, water level, ullage, height for 4 tanks, product names, station name, fill timestamps). Delivery history, leak detection status, shift reports, and alarm status similarly exposed.

Write: `\x01S60201<name>\n` renames tank product label — accepted immediately, reflected in subsequent reads.

**Impact:** Direct CWE-306 reproduction. Real Guardian AST deployments were Shodan-searchable targets circa 2015 for exactly this reason.

---

### C6 — kamstrup_management_server.py:37-92 — Zero authentication on full meter config rewrite

No authentication. TCP connect → `!GC` → device name, DHCP state, IP, subnet, gateway, DNS 1-3, MAC address, service server IP/host, both meter channel numbers, KAP ACK state, KAP port, local port.

Write surface: `!SC` rewrites all network config and triggers reboot signal; `!SA`/`!SB` redirect KAP heartbeat streams; `!SI` changes IP; `!SD` sets device name; `!SN` sets all nameservers; `!SP` changes all ports; `!SS` reconfigures serial channels A/B; `!RR` triggers reboot. No rate limiting.

---

## HIGH

### H1 — modbus_block_databus_mediator.py:32-36 + slave.py:27-38 — Unauthenticated Modbus writes poison shared databus (all protocols)

Any Modbus client sends FC05 (write single coil), FC06 (write single register), FC15, or FC16. Write handlers call `__setitem__` on `ModbusBlockDatabusMediator`, which calls `conpot_core.get_databus().get_value(self.databus_key).__setitem__()`. The databus is a singleton shared across all running protocol handlers.

**Impact:** Modbus client mutates databus keys simultaneously served by S7 SSL/SZL responses, SNMP OIDs, and IEC104 registers. Cross-protocol databus poisoning with no access control. Attacker writes Modbus register → SNMP GET on same key returns attacker-controlled value. Enables systematic deception of downstream consumers of honeypot log data.

---

### H2 — modbus_server.py:136-142 — Attacker-controlled MBAP length drives unbounded byte-by-byte recv loop

MBAP header bytes 4-5 (`uint16 length`) set to `0xFFFF`. Reassembly loop: `while len(request) < (length + 6): new_byte = sock.recv(1)`. No cap, no secondary timeout between iterations.

**Impact:** Up to 65,541 sequential `recv(1)` calls per connection. Under gevent, each call yields the greenlet but holds session state. Sending crafted MBAP then disconnecting mid-reassembly leaves the loop draining `recv()` exceptions for the socket timeout window. Repeated connections saturate the connection pool.

---

### H3 — IEC104.py:221 — `spawn_later(1, self.disconnect())` evaluates immediately

`gevent.Greenlet.spawn_later(1, self.disconnect())` — the `()` evaluates `disconnect()` immediately (closing the socket, resetting SSN/RSN/ack to 0), and passes its return value `None` to `spawn_later`. One second later, gevent spawns a greenlet that calls `None()`, raising `TypeError` silently inside gevent.

**Trigger:** Send a single i-frame with wrong `SendSeq` after `STARTDT_act`.  
**Impact:** Immediate socket closure (not graceful IEC104 disconnect with S-frame). Cascade of socket errors on the return path.

---

### H4 — conpot/protocols/snmp/command_responder.py:77-84 — SNMP SET with public write community, no access control

SNMP SET operations are accepted with community string `"public"` (same as read). `# TODO: Access control` comment at `databus_mediator.py:81-89` confirms the guard was intentionally deferred and never implemented.

**Impact:** Any unauthenticated client can SET arbitrary SNMP OIDs, mutating the shared databus (see H1 chain).

---

### H5 — conpot/protocols/ftp/ftp_server.py:120-122 — `bool("false") == True` → anonymous FTP always enabled

```python
if bool(config.get("ftp", "anonymous_login")):
    self.FTPHandler.authorizer.add_anonymous(self.vfs.get_root_path())
```

`config.get()` returns the string `"false"`. `bool("false")` is `True` (non-empty string). Anonymous FTP is enabled in every Conpot deployment regardless of configuration.

---

### H6 — conpot/protocols/ftp/ftp_server.py:265 — Hardcoded user `nobody`/`nobody` in every deployment

```python
user_db[13] = {"uname": "nobody", "password": "nobody"}
```

Index 13 is never overwritten by config loading. Credential `nobody:nobody` exists unconditionally in every FTP instance.

---

### H7 — conpot/protocols/ftp/ftp_handler.py:528-549 — FTP PORT command SSRF

FTP active-mode PORT command accepts any host:port combination with no source IP restriction. Conpot initiates an outbound TCP connection to the attacker-specified address for data transfer.

**Impact:** Server-side request forgery via FTP active mode — probe internal services, establish connections to attacker-controlled hosts.

---

### H8 — conpot/protocols/tftp/tftp_handler.py:121-168 — TFTP WRQ unauthenticated write

TFTP Write Request (WRQ) is processed without authentication. Existing files in the VFS are overwritten. Combined with VFS 0o777 defaults (M7), any TFTP client can overwrite any VFS file.

---

### H9 — s7_server.py:200,252 — Post-handshake `recv(1024)` truncates large S7 PDUs

After PDU negotiation, the inner loop uses `data = sock.recv(1024)` without TPKT-length-aware framing. S7 PDU sizes of 240+ bytes are common; any PDU > 1024 bytes is silently truncated. Remaining bytes stay in the TCP receive buffer and are read as the start of the next packet, misaligning the parser.

---

### H10 — s7_server.py:38-40 — `cleanse_byte_string()` strips all 0x62 bytes from TPKT payload

`packet.decode("latin-1").replace("b", "").encode("latin-1")` removes ALL occurrences of byte 0x62 (ASCII 'b') from the binary payload before TPKT parsing. Any S7 parameter or data field containing 0x62 is silently corrupted. Applied to handshake traffic only (line 101) — not applied to post-handshake traffic (line 200) — creating inconsistent parsing behavior between handshake and command phases.

**Fingerprint:** Insert 0x62 into COTP CR payload → Conpot response differs from real PLC.

---

### H11 — s7.py:169-172 — `plc_stop_signal` encodes literal ASCII strings "0x00"/"0x29" instead of binary

`str_to_bytes("0x00")` → `b'0x00'` (4 ASCII bytes: 0x30 0x78 0x30 0x30). Confirmed by `networking.py:35-36`: `str_to_bytes = lambda x: str(x).encode("ascii")`. Any S7 tool that parses the PLC STOP response (OpenS7, S7comm scanner) rejects or errors on the malformed 4-byte ASCII hex blob, immediately distinguishing Conpot from a real PLC.

---

### H12 — ipmi_server.py:469,488,503,532 — OOB array index on `userid` in four user commands

`list(self.authdata.keys())[userid - 1]` without bounds checking in Get User Access (0x44), Get User Name (0x46), Set User Name (0x45), Set User Password (0x47). `userid=0` maps to index -1 (Python wraps — silent wrong-user data leak). `userid > len(authdata)` raises unhandled `IndexError`, killing the session handler.

---

### H13 — ipmi_server.py:484-565 — Missing privilege check on Get/Set User Name and Set User Password

Get User Access (0x44) checks `self.clientpriv > self.maxpriv` at line 463. Get User Name (0x46), Set User Name (0x45), and Set User Password (0x47) perform no privilege check. Any authenticated session at privilege level 1 (User) can enumerate all configured usernames and overwrite any user's password.

---

### H14 — ipmi_server.py:502,509,538,554,559 — Python 3 TypeError/AttributeError crashes Set User Name and Set User Password

`"".join(...).strip(b"\x00")` at line 502 raises `TypeError` (Python 3 `str.strip` rejects bytes argument). `self.authdata.iteritems()` at line 509 raises `AttributeError` (Python 3 dicts have no `iteritems`). Both Set User Name and Set User Password crash the handler greenlet on any authenticated invocation.

---

### H15 — kamstrup_management_server.py — Inverted length guard → IndexError → handler crash

`messages.py:77-79`: guard is `len(self.message_bytes[1:]) * 2 < register_count` (inverted — should be `len([1:]) < register_count * 2`). A packet with `register_count=3` and 2 bytes of register data produces `2*2=4 < 3` → False → no exception → loop accesses out-of-bounds index → `IndexError`. Unhandled in `kamstrup_server.py`. Kills handler greenlet.

---

### H16 — sysinfo.py — Real host psutil metrics served via emulated ICS protocols

`sysinfo.py` calls `psutil.cpu_percent()`, `psutil.virtual_memory()`, `psutil.disk_usage()`, and `psutil.net_if_addrs()` and serves the results as S7 SNMP/databus values. Real internal IP addresses and hardware metrics of the honeypot host are exposed to any attacker querying the ICS protocols.

---

### H17 — taxii_log.py:35,55 — `use_https` flag stored but never applied; STIX always sent in plaintext

The `use_https` configuration flag is parsed and stored but never used when establishing the TAXII connection. All STIX attribution reports are sent over plain HTTP regardless of configuration. MITM on the TAXII feed corrupts all operator attribution.

---

### H18 — testing.cfg:34-35 — Hardcoded hpfeeds default credentials committed to repo

```
ident = 3Ykf9Znv
secret = 4nFRhpm44QkG9cvD
```

Any Conpot deployment that uses `testing.cfg` (or forgets to override hpfeeds credentials) publishes all captured attacker data to the shared hpfeeds channel with public credentials.

---

## MEDIUM

### M1 — IEC104.py:307-322 — `sentmsgs` list grows unbounded; IEC104 `k` parameter not enforced

After `STARTDT_act`, `sentmsgs` is appended to on every sent I-frame and only pruned when ack arrives. No check that `len(sentmsgs) >= k` (spec default k=12) blocks further sends. Each unacked frame holds a live `gevent.Timeout`.

**Impact:** Memory exhaustion — client never sends S-frames to ack, `sentmsgs` accumulates indefinitely.

---

### M2 — attack_session.py:68-72 — Timestamp key collision spin loop is O(N²) under event flood

```python
while elapse_ms in self.data:
    elapse_ms += 1
```

Under request flood (>1000 req/s), the while loop iterates N times per new event for N events in the same millisecond window. CPU cost is O(N²). In gevent cooperative runtime, the loop does not yield, stalling all other greenlets.

---

### M3 — session_manager.py:29-34 — Session lookup ignores source port

Session lookup keyed on `(protocol, source_ip)` only. Two connections from the same source IP to the same protocol share a session. UDP protocols (BACnet, IEC104): source IP spoofing silently injects log events into a victim session. Forensic integrity of the attack log is compromised.

---

### M4 — cotp.py:107-112 — COTP variable header parameter length ≠ 1 or 2 raises ParseException

RFC 1006 allows variable-length COTP parameters. Conpot rejects any parameter with `chunk_param_length` other than 1 or 2, raising `ParseException` and dropping the connection. One malformed COTP CR kills the session before the S7 layer is reached. Also a hard fingerprint tell.

---

### M5 — ext_ip.py — HTTP-only external IP resolution; MITM corrupts all STIX attribution

External IP lookup uses plain HTTP. MITM on the DNS or HTTP path returns an arbitrary IP as the honeypot's "external address", which propagates into all STIX attribution reports filed to the TAXII feed.

---

### M6 — guardian_ast_server.py:322-328 — Unbounded recv accumulation → OOM

`while not (b"\n" in request or b"00" in request): request += sock.recv(4096)` — no max size, no timeout on inner recv. Continuous stream of non-matching bytes causes `request` to grow without bound.

---

### M7 — filesystem.py:92,124,172 — 0o777 default permissions on all virtual files

`create_mode=0o777` applied recursively to all VFS content at initialization. Every FTP/TFTP consumer inherits world-write permissions unless explicitly called per file via `chmod`.

---

### M8 — ipmi_server.py:107-128,211-219 — Single shared IPMI session instance

`self.session` is a single attribute on `IpmiServer`, not per-connection. A second incoming connection overwrites `self.session`, causing the first client's session to be closed when the second triggers cleanup. Packet responses keyed to `self.session.sockaddr` may reach the wrong client.

---

### M9 — kamstrup_management_server.py — `parse_ip()` ValueError on non-numeric octets crashes handler

`parse_ip()` calls `int(octet)` on each dotted octet with no `try/except`. Any command accepting an IP parameter (`!AC`, `!AS`, `!SA`, `!SB`, `!SC`, `!SI`, `!SN`, `!SP`, `!SS`) crashes the handler greenlet on malformed input.

---

### M10 — kamstrup command_responder.py:65 — `assert False` on unknown command → AssertionError DoS

Any Kamstrup command byte other than 0x10 returns `KamstrupRequestUnknown`, then `respond()` hits `assert False`. `AssertionError` propagates unhandled out of the while loop in `kamstrup_server.py`, killing the handler greenlet.

---

## LOW / FINGERPRINT

### L1 — Cross-protocol impossible hardware co-presence (hard fingerprint)

Siemens S7-300 (S7comm + ISO-on-TCP:102) + Alerton BACnet controller (BACnet/IP:47808) + Guardian AST fuel monitoring (TCP:10001) + Kamstrup smart meter + IPMI BMC on the same IP is physically impossible. Any defender or red-teamer who queries three protocols simultaneously identifies Conpot in one scan.

### L2 — S7 SZL hardware version 0x0539 (= 1337 leet) — hardcoded easter egg

`s7.py:262,287`: hardware version field is `0x0539` (decimal 1337), firmware `0x053A` (1338). SSL/SZL `ssl_resp_params` (lines 302-312) always returns `\x00\x01\x12\x08\x12\x84\x01\x01` regardless of request; sequence field hardcoded to `0x01` instead of echoing the client's counter.

### L3 — Guardian AST static strings: "STATOIL STATION", Tank 2 always HIGH WATER ALARM

`guardian_ast_server.py`: station name is `"STATOIL STATION"`. Tank 2 `HIGH WATER ALARM` is hardcoded True in `I20500()`. Any attacker who has previously seen a real Guardian AST system recognizes these static values.

### L4 — SNMP static strings: `sysLocation = "Venus"`, hardcoded IP `163.172.189.137` in MIB tables

Published in the repository as MIB table entries. Shodan dork `SNMP sysLocation:"Venus"` uniquely returns Conpot instances.

### L5 — IPMI Manufacturer ID = 0x0F (unregistered), Product ID = 0x0E

Both values are outside the IANA-registered range for any real IPMI manufacturer. Any IPMI scanner that validates against the IANA list flags Conpot immediately.

### L6 — Modbus FC17 REPORT SLAVE ID always returns hardcoded `\x11\x01\x01\xFF`

Real Modbus RTU slaves return variable-length device-specific identification strings. The fixed 4-byte response is an immediate fingerprint on any Modbus scanner.

### L7 — IEC104_server.py:141 — `print()` in socket error handler bypasses logging subsystem

`print(("socket error ", err))` routes socket errors to stdout, breaking log aggregation pipelines in containerized deployments where stdout and log files are captured separately.

---

## Detection / Evasion Summary

| Protocol | Fingerprint | Confidence |
|----------|-------------|------------|
| S7comm | Hardware version 0x539 (1337), firmware 0x53A, static ssl_resp_params | Hard |
| SNMP | `sysLocation = "Venus"`, hardcoded `163.172.189.137` MIB IP | Hard |
| Guardian AST | `"STATOIL STATION"`, Tank 2 always HIGH WATER ALARM | Hard |
| Modbus | FC17 always returns `\x11\x01\x01\xFF` | Hard |
| IPMI | Manufacturer ID 0x0F, Product ID 0x0E (unregistered) | Hard |
| Cross-protocol | S7 + BACnet + AST + Kamstrup + IPMI on same IP | Impossible combination |
| FTP | anonymous always enabled + `nobody`/`nobody` credential | Medium |
| All | `cleanse_byte_string()` strips 0x62 from COTP CR payload | Protocol-level |
