# elasticpot — Security Analysis

**Repo:** https://gitlab.com/bontchev/elasticpot  
**Type:** Python Elasticsearch honeypot — Twisted HTTP server mimicking Elasticsearch REST API; 20 output plugins (MySQL, Postgres, SQLite, Redis, Kafka, Slack, Telegram, Discord, syslog, etc.)  
**Lanes:** 2 (L1: core/protocol.py + core/tools.py + core/config.py + core/logfile.py · L2: all 20 output plugins)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 8 |
| MEDIUM | 8 |
| LOW | 5 |
| INFO | 5 |

elasticpot's core has two critical paths: an unbounded POST body read enabling OOM DoS, and an SSRF via the `HONEYPOT_PUBLIC_IP_URL` environment variable that allows redirecting the IP-fetch request to an internal network endpoint. The output plugin layer has extensive injection vulnerabilities: Telegram HTML injection delivers attacker-controlled live hyperlinks to the operator, CEF syslog injection corrupts SIEM correlation data, Slack mrkdwn and Discord markdown injection enables `@everyone` pings from attacker-crafted requests, and the `nlcvapi` plugin crashes with a `KeyError` on every invocation, potentially blocking the entire output pipeline.

---

## CRITICAL

### C1 — core/protocol.py:233-237 — Unbounded POST body read; OOM DoS

```python
def dataReceived(self, data):
    body = b''
    while True:
        chunk = self.transport.readSomeData()
        if not chunk:
            break
        body += chunk
```

No `http.MaxBytesReader` equivalent, no `Content-Length` cap, no body size limit. An attacker sends a POST with `Transfer-Encoding: chunked` and streams data indefinitely. `body += chunk` creates a new string object each iteration (Python string immutability); with 100 MB/s input, this triggers quadratic string allocation — each concatenation copies all previously accumulated bytes. OOM kills the Twisted process. Exploitable with a single keep-alive POST from any unauthenticated client.

**Trigger:** `curl -X POST http://elasticpot:9200/_search -T /dev/zero` — unauthenticated.

---

### C2 — core/tools.py:46-48 + core/config.py:18-22 — SSRF via `HONEYPOT_PUBLIC_IP_URL` environment variable

```python
# core/config.py:18-22
IP_URL = os.environ.get('HONEYPOT_PUBLIC_IP_URL', 'http://api.ipify.org/')

# core/tools.py:46-48
def get_public_ip():
    response = requests.get(IP_URL, timeout=10)
    return response.text.strip()
```

`HONEYPOT_PUBLIC_IP_URL` controls the HTTP GET target for external IP discovery. An operator (or any process that can set the environment before elasticpot starts) sets this to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS IMDS) or `http://kubernetes.default.svc/api/v1/secrets`. The response text is stored as `sensorIP` and used only for logging — the SSRF response is not rendered to an attacker. Impact: exfiltration of cloud metadata credentials via the honeypot operator's logging/alerting pipeline, or use of the honeypot process to probe internal services unreachable from the attacker's network.

---

## HIGH

### H1 — core/logfile.py:43-44 — Log injection via URL path; `\r` not stripped

```python
logfile.write('[{}] {} {} {}\n'.format(
    timestamp, src_ip, method, path))
```

`path` is the raw HTTP request path from the wire. An attacker GETs `/_search%0d%0a[2026-01-01%2012:00:00]%20ADMIN%20injected_line%0d%0a` — after URL decoding, `\r\n` is embedded in `path`. The write inserts a synthetic log line. `\r` in the middle of a log entry causes terminal display corruption; `\n` injects a complete fake event. No sanitization at the logfile writer.

---

### H2 — core/protocol.py:385-394 — Attacker URL echoed into JSON error; mutates class-level cache dict

```python
ERROR_CACHE = {}  # class-level dict

def render_error(path):
    if path not in ERROR_CACHE:
        ERROR_CACHE[path] = json.dumps({'error': path, 'status': 404})
    return ERROR_CACHE[path]
```

`path` (attacker-controlled URL path) is stored verbatim in a class-level `ERROR_CACHE` dict. This cache persists for the lifetime of the process. An attacker who sends 1,000 unique URLs causes 1,000 entries in `ERROR_CACHE`. At an average 200 bytes per URL, 50,000 unique URLs = 10 MB of heap consumed by the error cache. Additionally, `path` is embedded in the JSON response (`'error': path`) and returned to the attacker — an XSS surface if any operator dashboard renders error responses without encoding.

---

### H3 — core/httpclient.py:66-70 — TLS verification disabled for some plugins

```python
response = requests.get(url, verify=False)
```

Several output plugin HTTP calls use `verify=False`. TLS certificate validation is disabled for these outbound connections — operator alert traffic (event data, attacker credentials, captured payloads) is transmitted without certificate verification to MITM-capable positions on the operator's network path.

---

### H4 — core/tools.py:113 — Dynamic plugin import from operator-controlled config section name

```python
plugin_module = importlib.import_module('output.' + section_name)
```

`section_name` comes from the config file's section headers. An operator who misconfigures a section name (typo, path traversal) causes `importlib.import_module` to attempt importing from an unintended Python path. With `section_name = "../../system_module"`, the import path becomes `output.../../system_module` which Python normalizes differently across versions. Not remotely exploitable, but operator misconfiguration may import unintended modules or crash the loader.

---

### H5 (plugin) — telegram.py:119 — HTML injection into Telegram `parse_mode=HTML`; attacker-controlled hyperlinks delivered to operator

```python
params = 'chat_id={}&parse_mode=HTML&text={}'.format(
    self.chat_id, quote_plus(message))
```

`message` is built from `event['url']`, `event['message']`, and `event['request']` at lines 58-62 without sanitization. An attacker sends a GET request to `/<a href="http://evil.com">click here</a>` — the URL path contains an HTML anchor tag. `message` includes the raw path; `quote_plus` URL-encodes the outer wrapper but the tag content passes through Telegram's HTML parser (`parse_mode=HTML`). Telegram's HTML mode renders `<a href>`, `<b>`, `<code>`, `<pre>`, and `<tg-spoiler>`. The operator's Telegram channel receives a clickable attacker-controlled hyperlink on every matching event — phishing surface targeting the honeypot operator.

---

### H6 (plugin) — nlcvapi.py:68 — `KeyError: ''` on every invocation; potential pipeline blockage

```python
sub_event['message'] = event['']   # empty-string key — always KeyError
```

`event['']` raises `KeyError` unconditionally — empty string is never a key in the event dict. `write()` has no try/except. If the output plugin runner does not isolate per-plugin exceptions, all plugins ordered after `nlcvapi` in the chain are skipped for every honeypot event. Additionally, line 78 posts `event` (the full raw event including payload) rather than `sub_event` to the NLCV API — unintended raw payload exfiltration to a third-party service on any call that reaches line 78 (which it never does due to the crash on line 68).

---

### H7 (plugin) — localsyslog.py:36-40 — CEF extension field injection via attacker-controlled values

```python
cefList.append('{}={}'.format(key, value))
cefExtension = ' '.join(cefList)
```

`value` comes from `logentry['message']`, `logentry['url']`, `logentry['request']` — all attacker-controlled. A URL of `http://x/ msg=injected dst=10.0.0.1` places ` msg=injected dst=10.0.0.1` into the CEF extension string. CEF extensions are space-separated key=value pairs; injected key=value sequences are parsed by SIEM correlation engines as legitimate fields. An attacker can fabricate source IPs, severity levels, or event classifications in the SIEM's parsed event data.

---

### H8 (plugin) — kafka.py:26-30 — Kafka producer PLAINTEXT with no authentication (SASL block commented out)

```python
self.producer = Producer({
    'bootstrap.servers': '{}:{}'.format(...),
    # 'sasl.mechanism': 'SCRAM-SHA-256',  # commented out
})
```

All honeypot event data transmitted to Kafka in cleartext with no authentication. Any host on the network path between the honeypot and Kafka broker can read or inject messages into the topic.

---

## MEDIUM

- **slack.py:54-57** — Slack mrkdwn injection: attacker URL `<http://evil.com|Click here>` renders as hyperlink; `<!channel>` and `<!here>` in attacker-controlled fields ping all channel members.
- **discord.py:52-55** — Discord markdown injection: `@everyone` or `@here` in attacker-controlled URL or message body notifies all channel members; backtick sequences render code blocks.
- **textlog.py:32** — Newline injection into text log file via `event['payload']`; fake log entries indistinguishable from real ones.
- **socketlog.py:23-25** — Raw plaintext TCP to log socket; no TLS, no authentication; honeypot event stream readable by any on-path observer.
- **elastic.py:33** — `verify_certs = CONFIG.getboolean('output_elastic', 'verify_certs', fallback=False)` — TLS cert verification disabled by default for Elasticsearch output; warn-and-continue pattern (line 48) gives false confidence without enforcement.
- **redisdb.py:31** — `b'Authorization': 'Bearer {}'.format(...)` — bytes key with string value; in Python 3 with `requests`, header may be silently dropped or malformed, leaving the Upstash Redis REST call unauthenticated.
- **core/protocol.py** — Static Elasticsearch fingerprint fields: `instance_name = "Green Goblin"`, node ID `x1JG6g9PRHy6ClCOO2-C4g`, build hash `b88f43fc40b0bcd7f173a1f9ee2e97816de80b21`, MAC `08:01:c7:3F:15:DD` — all hardcoded, same as elastichoney's node UUID (shared static identity between two separate honeypot projects).
- **elasticpot/cli.py:499** — `description="MongoDB Honeypot"` in the Elasticsearch honeypot's argument parser — copy-paste error from a different project; indicates codebase lineage and reduces operator trust in documentation accuracy.

---

## LOW

- **mysql.py:218-219**, **postgres.py:86-88**, **sqlite.py:82-83** — Table/column identifier interpolation in INSERT statements (`"INSERT IGNORE INTO \`{}\`"`) — exploitable if any future caller passes attacker-influenced table names; current call sites use hardcoded strings.
- **mysql.py:191**, **postgres.py:64**, **sqlite.py:58** — `self.dbh.runInteraction(self.connect_event, event)` with no try/except in `write()`; DB connection failure during `start()` leaves `self.dbh` unset; subsequent `write()` raises `AttributeError` that propagates to plugin runner.
- **hpfeed.py:29** — hpfeeds traffic in plaintext TCP when `tlscert` absent from config (default); HMAC auth exchange readable on hostile networks.
- **core/config.py** — No config schema validation; missing required keys surface as `AttributeError` or `KeyError` at runtime when a specific code path is triggered, not at startup.
- **Dockerfile (if present)** — Python base image version not pinned to a specific digest; `pip install` at build time resolves to latest compatible versions without reproducibility.

---

## INFO

- **elastic.py:48** — TLS warning logged but connection proceeds — warn-and-continue anti-pattern. No enforcement.
- **nlcvapi.py:78** — Wrong variable (`event` vs `sub_event`) would exfiltrate full raw payload to third-party API on any call that reached line 78. Bug on line 68 prevents it, but the exfiltration logic is present.
- **hpfeed.py:29** — Complementary to H8: hpfeeds TLS path requires `tlscert` config key; operators deploying without a cert send all data in cleartext.
- **Static node ID shared with elastichoney** — `x1JG6g9PRHy6ClCOO2-C4g` appears in both elasticpot and elastichoney; any Shodan dork or BARE module targeting this UUID matches both honeypot types — cannot distinguish them by node ID alone.
- **core/protocol.py** — All unsupported Elasticsearch API paths return 200 with a generic JSON body; real Elasticsearch returns 405 (Method Not Allowed) or 404 with structured error. Behavioral divergence for any scanner that checks response codes on non-search endpoints.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| `GET /_nodes` → `id = x1JG6g9PRHy6ClCOO2-C4g` | Single REST call | Very High (shared with elastichoney) |
| `GET /_nodes` → `mac_address = 08:01:c7:3F:15:DD` | Single REST call | Very High |
| `GET /_nodes` → build hash `b88f43fc40b0bcd7f173a1f9ee2e97816de80b21` | Single REST call | Definitive |
| Instance name `Green Goblin` in cluster info | `GET /_cluster/settings` | Definitive |
| POST `/_search` with 10 MB body → process OOM | Active probe | CRITICAL — also DoS |
| Any path → 200 response (not 404 for unimplemented routes) | Probe non-existent endpoint | High |

**Minimum detection sequence (1 HTTP request):**
1. `GET http://target:9200/_nodes` → `id = x1JG6g9PRHy6ClCOO2-C4g` + build hash `b88f43fc...` → confirmed elasticpot/elastichoney
2. Check instance name: `GET /_cluster/settings` → `"Green Goblin"` → confirmed elasticpot specifically

**DoS sequence (1 request):**
1. `POST http://target:9200/_search` with streaming body → unbounded accumulation → OOM → process exit
