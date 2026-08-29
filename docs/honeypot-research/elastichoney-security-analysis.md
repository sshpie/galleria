# elastichoney — Security Analysis

**Repo:** https://github.com/jordan-wright/elastichoney  
**Type:** Go Elasticsearch honeypot — HTTP server mimicking Elasticsearch REST API; collects attacker queries and reports to hpfeeds  
**Lanes:** 2 (main.go core · config.json + hpfeeds integration)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 5 |
| MEDIUM | 4 |
| LOW | 3 |
| INFO | 4 |

elastichoney serves a hard-coded Elasticsearch cluster identity (static node UUID, MAC address, build hash, PID, hostname) from a 2014 codebase with no HTTP timeouts and an unbuffered hpfeeds channel that blocks HTTP handlers when the broker is unreachable. The sensor IP is fetched over plaintext HTTP at startup — a MITM on that request injects any IP as the reported source, corrupting all attribution data in the hpfeeds event stream. The default hpfeeds credentials (`elastichoney`/`elastichoney`) are published in the repo config.

---

## CRITICAL

### C1 — main.go:383 — No HTTP server timeouts and no request body size limit; OOM via POST

```go
http.ListenAndServe(listenStr, nil)
```

No `http.Server` struct with `ReadTimeout`, `WriteTimeout`, or `IdleTimeout`. An attacker opens a keep-alive connection and sends headers incrementally — the handler goroutine blocks until the OS TCP timeout (hours). Multiplied by Go's goroutine-per-connection model: N slow connections = N goroutines blocked.

Additionally, `ioutil.ReadAll(r.Body)` is called at every POST handler (lines 300-310) with no `http.MaxBytesReader` wrapper. A POST with `Content-Length: 2147483647` or chunked transfer encoding causes `ioutil.ReadAll` to allocate until the system's available memory is exhausted. The OOM killer terminates the elastichoney process.

**Trigger:** `curl -X POST http://elastichoney:9200/_search -d $(python -c "print 'A'*500000000")` — single unauthenticated request.

---

### C2 — main.go:54,294 — Unbuffered hpfeeds channel; HTTP handler goroutines block indefinitely when broker is down

```go
var hpChan = make(chan attackDetails)  // unbuffered, line 54

// In HTTP handler goroutines (line 294):
hpChan <- details  // blocks forever if hpfeeds goroutine is not consuming
```

`make(chan attackDetails)` creates an unbuffered channel. The consuming goroutine at line 57-70 reads from `hpChan` in a loop and calls `hp.Publish()`. When the hpfeeds broker is unreachable, `Publish()` blocks on the TCP write. The consuming goroutine stalls. Every HTTP handler goroutine that subsequently reaches `hpChan <- details` blocks indefinitely — the channel has no buffer and no `select` with `default`. With a sufficient number of attacker requests, all goroutines in the HTTP server's internal pool block on the channel, and new requests queue and eventually time out.

**Trigger:** Kill the hpfeeds broker, then send requests to the honeypot.

---

### C3 — main.go:354 — SensorIP fetched over HTTP (not HTTPS); MITM injects arbitrary source IP

```go
resp, err := http.Get(config.SensorIP)
// config.SensorIP = "http://api.ipify.org" (default in config.json)
```

At startup, elastichoney fetches its own external IP over plaintext HTTP. An on-path attacker intercepts this request and returns an arbitrary IP in the response body. `sensorIP` is then used as the `source_ip` field in every hpfeeds event for the lifetime of the process. All attribution data (which Elasticsearch installation was probed) is corrupted for all events. The attacker can erase the deployment's identity or frame another IP as the honeypot.

---

## HIGH

### H1 — main.go:139-192 — Static `/_nodes` response; definitive 5-field fingerprint

```go
"id": "x1JG6g9PRHy6ClCOO2-C4g",
"mac_address": "08:01:c7:3F:15:DD",
"name": "elk",
"pid": 2039,
// ...
"build_hash": "89d3241d670db65f994242c8e838b169779e2d4"
```

All five static values are hardcoded string literals and never randomized. Real Elasticsearch generates a random UUID node ID at cluster formation, uses the actual network interface MAC, reports the real process PID, and the build hash is specific to the compiled binary version. An attacker querying `GET /_nodes` and comparing against this known tuple identifies elastichoney with certainty. This fingerprint can be added to a BARE module, aimap signature, or Shodan dork.

---

### H2 — main.go:121-133 — Static `build_hash` in `/_cluster/health` and `/_cluster/stats` responses

```go
"build_hash": "89d3241d670db65f994242c8e838b169779e2d4"
```

The same build hash appears in multiple response endpoints. Any Shodan query for `http.html:"89d3241d670db65f994242c8e838b169779e2d4"` returns all internet-exposed elastichoney instances. The build hash corresponds to no known Elasticsearch binary — it is a fabricated constant. A legitimate scanner verifying the build hash against the Elasticsearch artifact registry fails immediately.

---

### H3 — main.go:308-318 — XSS sanitization undone before forwarding to remote attacker-controlled endpoint

```go
var buf bytes.Buffer
enc := json.NewEncoder(&buf)
enc.SetEscapeHTML(false)
enc.Encode(...)
```

Go's `json.NewEncoder` escapes `<`, `>`, and `&` by default. `enc.SetEscapeHTML(false)` disables this. The encoded JSON is then POSTed to the remote hpfeeds broker. The original attack payload (a search query, a script injection attempt) is forwarded with HTML characters unescaped to whatever downstream system consumes the hpfeeds events. If the event consumer renders the payload in a web UI without re-encoding, XSS is delivered from elastichoney's event stream.

---

### H4 — config.json:16-18 — Default hpfeeds credentials identical to repo name

```json
"ident": "elastichoney",
"secret": "elastichoney"
```

Shipped default credentials. Operators who deploy from the repo without changing the config authenticate to public hpfeeds brokers (e.g., `hpfeeds.honeynet.org`) with publicly known credentials. Any observer with the ident/secret can subscribe to the same channel and receive the identical event stream.

---

### H5 — Dockerfile:1 — `golang:1.3-onbuild` from 2014; EOL base image

```dockerfile
FROM golang:1.3-onbuild
```

Go 1.3 is from June 2014. Known vulnerabilities include CVE-2014-7189 (TLS MITM, net/http), CVE-2015-8618 (math/big exponent overflow), CVE-2016-5386 (httpoxy), and multiple stdlib issues fixed through Go 1.4-1.22. `onbuild` images are deprecated since 2016 and no longer receive security updates. The container runs as root by default.

---

## MEDIUM

- **main.go:383** — No graceful shutdown; `http.ListenAndServe` returns only on listener error; `os.Signal` handler at line 368-380 only logs on receipt — `server.Shutdown()` is never called; open connections are not drained before exit.
- **main.go:299-303** — `w.WriteHeader(http.StatusOK)` called before `w.Header().Set("Content-Type", ...)` — headers set after `WriteHeader` are silently discarded in Go's net/http. All elastichoney responses have no `Content-Type` header, which diverges from Elasticsearch (which always sends `application/json; charset=UTF-8`). Secondary fingerprint.
- **main.go:354-365** — `sensorIP` is set once at startup and never refreshed; if the host's external IP changes (DHCP renewal, IP rotation), all subsequent events carry a stale source IP until process restart.
- **main.go:50-52** — `config.json` path hardcoded to `"config.json"` (relative to CWD); no CLI override; no environment variable; operators must run elastichoney from its directory or symlink the config file — deployment friction leading to operators copying the default config verbatim.

---

## LOW

- **main.go:245-260** — `/_search` handler returns a static 1-hit search result regardless of query; real Elasticsearch returns results correlated to the query; a scanner issuing `{"query": {"term": {"_id": "canary-uuid-that-does-not-exist"}}}` expects 0 hits; elastichoney returns 1 hit unconditionally — behavioral fingerprint.
- **main.go:73-90** — All non-`/_nodes`, non-`/_cluster`, non-`/_search` routes return 404 with Elasticsearch-formatted error body; however, real Elasticsearch has a `/_cat/indices`, `/_mapping`, `/_aliases` API surface that elastichoney does not implement — any automated Elasticsearch scanner that probes these endpoints identifies the honeypot by the uniform 404 response to all non-implemented routes.
- **main.go:383** — `log.Fatal(http.ListenAndServe(...))` — `log.Fatal` calls `os.Exit(1)` after logging; deferred functions in `main()` do not execute; any cleanup (temp file removal, DB writes) in deferred calls is skipped on listener error.

---

## INFO

- **main.go:139** — Cluster name `"elasticsearch"` (the default) — real clusters are typically renamed; a production Elasticsearch cluster named "elasticsearch" is an operator configuration error, not a real fingerprint on its own, but combined with the other static fields it strengthens detection.
- **main.go:179** — hostname `"elk"` — a common development hostname for ELK stack VMs; suspicious on an internet-exposed "production" node.
- **config.json** — hpfeeds `"port": 10000` — the default MHN hpfeeds port; confirms deployment in a Modern Honey Network context.
- **go.mod absent** — pre-modules codebase (Go 1.3 era); `go get` at build time resolves all dependencies to their latest HEAD at that moment; reproducible builds are impossible; library API changes may silently break the build.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| `GET /_nodes` → `id = x1JG6g9PRHy6ClCOO2-C4g` | Single REST call | Definitive |
| `GET /_nodes` → `mac_address = 08:01:c7:3F:15:DD` | Single REST call | Definitive |
| `GET /_nodes` → `build_hash = 89d3241d670db65f994242c8e838b169779e2d4` | Single REST call | Definitive |
| `GET /_nodes` → `pid = 2039` (static) | Compare across two sessions | Definitive |
| `GET /_nodes` → hostname `elk` | Single REST call | High |
| `GET /_search` with non-matching query → 1 hit returned | POST with impossible query | Very High |
| Response: no `Content-Type` header | HTTP header inspection | Medium |

**Minimum detection sequence (1 HTTP request, unauthenticated):**
1. `GET http://target:9200/_nodes` → JSON with `id = x1JG6g9PRHy6ClCOO2-C4g` → confirmed elastichoney
