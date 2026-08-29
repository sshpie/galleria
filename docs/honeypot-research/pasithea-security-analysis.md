# PasitheaHoneypot — Security Analysis

**Repo:** https://github.com/Marist-Innovation-Lab/PasitheaHoneypot  
**Type:** Java REST API honeypot using NanoHTTPD 2.2.0 — logs all HTTP traffic; simulates a generic REST endpoint  
**Lane:** Single comprehensive lane (1 Java source file + docs)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 5 |
| LOW | 2 |

Pasithea is a skeleton honeypot: a single Java file atop NanoHTTPD that logs every request and returns `HTTP 200 OK` with body `<h1>404 Not Found</h1>` to everything. The most operationally significant finding is F4 — the HTTP 200 / "404 Not Found" response pair is a near-zero-false-positive conjunctive fingerprint that detects this deployment in two fields. F2 and F3 are high-severity log injection and latent SQLi. F5 is a pre-auth OOM crash via Content-Length.

---

## CRITICAL

### C1 — APIrest.java:72-143 — No authentication on any endpoint; complete zero-auth exposure

```java
public Response serve(IHTTPSession session) {
    // logs request
    String responseTxt = "<h1>404 Not Found</h1>";
    Response response = newFixedLengthResponse(responseTxt);
    return response;
}
```

Every HTTP method (GET, POST, PUT, DELETE, HEAD, OPTIONS, TRACE) on every URI path is accepted with zero authentication or authorization. Port 8082 is the only gate. For a honeypot this is intended, but any future code additions to the `serve()` method (e.g., the commented-out database write path at `APIrest.java:161-169`) inherit this zero-auth posture automatically.

---

## HIGH

### H1 — APIrest.java:131,137-138 — Log injection via attacker-controlled URI and User-Agent

```java
String requestText = String.valueOf(session.getUri());
String msg = HPID + "~" + method.toString() + "~" + requestText + "~" + fromIP + "~" + userAgent;
writeLog(msg);
```

The log delimiter is `~`. Both `requestText` (full URI) and `userAgent` (raw User-Agent header) are attacker-controlled with no sanitization. An attacker injects `~` characters to shift log columns, or injects `\r\n` to synthesize entirely new log lines with arbitrary field values:

```
User-Agent: Mozilla~127.0.0.1~DELETE~/admin~forged-entry
```

Produces a log line where the forged entry is indistinguishable from a real record. Downstream SIEM parsing, attribution, or forensic analysis operates on poisoned data.

---

### H2 — APIrest.java:161-169 — Latent SQL injection in commented-out DB write path

```java
/* String insertCommand = "INSERT INTO errorlogs(error_string, time, source, severity) " +
                         "VALUES ('" + logMsg + "', current_timestamp, 'back-end', 0)";
   dbCommand(insertCommand); */
```

`logMsg` contains the full attacker-controlled URI and User-Agent directly concatenated into a SQL string without parameterization. The block is commented out, but the design pattern is broken at the architectural level. If uncommented — or if any future implementer follows this pattern — the payload `'); DROP TABLE errorlogs; --` in the URI executes as written.

**Trigger (if uncommented):** Any HTTP request. URI payload in query string or path.

---

### H3 — APIrest.java:141-143 — HTTP 200 returned with "404 Not Found" body; protocol violation and primary fingerprint

```java
String responseTxt = "<h1>404 Not Found</h1>";
Response response = newFixedLengthResponse(responseTxt);  // single-arg overload = Status.OK
return response;
```

`NanoHTTPD.newFixedLengthResponse(String)` is the single-argument overload. In NanoHTTPD 2.2.0, this defaults to `Response.Status.OK` (HTTP 200). The response status is never explicitly set. Every request receives `HTTP/1.1 200 OK` with body `<h1>404 Not Found</h1>`. This is the most reliable fingerprint for this honeypot.

**Conjunctive detection rule (two-field, near-zero false positive rate):**
`status == 200 AND body == "<h1>404 Not Found</h1>"`

No production REST API or real HTTP server returns exactly this combination. Any scanner checking both conditions identifies this deployment with certainty.

---

## MEDIUM

### M1 — APIrest.java:103-111 — OOM / NegativeArraySizeException via arbitrary Content-Length

```java
Integer contentLength = Integer.parseInt(headers.get("content-length"));
byte[] buf = new byte[contentLength];
```

No null check before `parseInt` (NPE if header absent). No bounds check before allocation. `Content-Length: 2147483647` (Integer.MAX_VALUE) attempts to allocate 2GB in one shot → `OutOfMemoryError`. A negative value → `NegativeArraySizeException`. Both are caught by the broad `catch (Exception e)` at line 127 which does nothing — but OOM in a JVM is not reliably recoverable and can leave the process in a degraded state or crash the JVM entirely.

**Trigger:** `POST / HTTP/1.1\r\nContent-Length: 2147483647\r\n\r\n`

---

### M2 — Framework default — NanoHTTPD 2.2.0 `Server` header disclosure

NanoHTTPD 2.2.0 emits `Server: NanoHTTPD-Webserver` (webserver artifact) or `Server: NanoHTTPD` (core artifact) on every response. No code in `APIrest.java` overrides or removes this header. The version string is searchable against the public NanoHTTPD changelog to correlate deployment date and identify version-specific behavior.

Combined with H3, a three-field conjunctive rule: `status==200 AND body=="<h1>404 Not Found</h1>" AND Server: NanoHTTPD` is a positive identification with essentially zero false positive rate.

---

### M3 — APIrest.java:43-44,59 — Self-identifying string in startup stdout and every log line

```java
public static final String apiName = "SecureCloud REST API Honeypot version " + apiVersion;
...
System.out.println("Welcome to the " + apiName + ".");
```

"SecureCloud REST API Honeypot" is embedded in every log line and emitted to stdout at startup. Any log aggregation system, process monitor (`ps`, `/proc/<pid>/cmdline`), or stdout capture immediately sees this string. The log file `API.log` contains the word "Honeypot" in every entry — any attacker with log access confirms identity.

---

### M4 — install.sh:83 — Code injection via unquoted port variable in `sed` during installation

```bash
sed -i "s/apiPort    = 8082/apiPort    = "$1"/" edu/marist/jointstudy/APIrest.java
```

The outer `"` terminates before `$1`; the argument is unquoted in the shell expansion. If `$1` contains `/`, it breaks the sed delimiter. If it contains a pattern like `8082/g; s/apiPort/injectedToken/`, the sed expression becomes multi-command. No input validation (`[[ $PORT_NUM =~ ^[0-9]+$ ]]`) exists.

**Trigger:** When prompted for port during install, enter `8082/g; s/import/malicious_import/g; s/8082`.  
**Impact:** Arbitrary modification of the Java source before compilation.

---

### M5 — No rate limiting; DoS confirmed in production deployment

`docs/analysis.txt` documents 500–6,000 requests/second sustained traffic: "Perhaps some kind of API DoS attack?" NanoHTTPD 2.2.0 uses a fixed-size thread pool (default 20 threads in `ServerRunner`). No connection-rate limiting, no source-IP throttling, no backpressure logic in the code.

**Trigger:** Any sustained HTTP flood to port 8082.  
**Impact:** Thread pool exhausted within seconds; honeypot stops collecting data.

---

## LOW

- **install.sh:73-74** — `HPID=$(dbus-uuidgen)` written to `/etc/environment` system-wide. Any process on the host reads `$HPID`. If the machine is later used for other purposes or any service leaks environment variables, the honeypot's unique identifier is disclosed.
- **APIrest.java:106** — `session.getInputStream().read(buf, 0, contentLength)` — single `read()` call, not a loop. For slow or large POSTs, fewer bytes than `contentLength` are read. Truncated body is passed to GSON parsing; exception is caught silently. No retry, no logging of the partial read.

---

## Fingerprint Table

| Signal | Detection Method | Confidence |
|--------|-----------------|------------|
| `HTTP/1.1 200 OK` + body `<h1>404 Not Found</h1>` | Response status + body | Very High |
| `Server: NanoHTTPD-Webserver` or `Server: NanoHTTPD` | Response header | High |
| Identical response body on ALL paths (GET/POST/PUT/DELETE) | Multi-method probe | Very High |
| HTTP 200 for non-existent paths | Protocol anomaly | High |
| Port 8082 (non-standard) | Port scan | Medium |
| `Content-Type: text/html` for all responses regardless of Accept | Header pattern | Medium |
| Process name contains `edu.marist.jointstudy.APIrest` | Host-level process list | Definitive |
| Log entries contain literal "SecureCloud REST API Honeypot" | Log access | Definitive |

**Minimal 2-request detection sequence:**
1. `GET /anything HTTP/1.1` → check: `200 OK` + body `<h1>404 Not Found</h1>` → confirmed Pasithea.
2. No second request needed.
