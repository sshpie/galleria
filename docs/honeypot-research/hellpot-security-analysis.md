# HellPot — Security Analysis

**Repo:** https://github.com/yunginnanet/HellPot  
**Type:** Go HTTP tarpit — serves infinite Markov-chain-generated HTML to crawlers/bots that hit disallowed robots.txt paths  
**Lane:** Single comprehensive lane (Go server, heffalump content engine, Docker/config)

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH | 1 |
| MEDIUM | 3 |
| LOW-MEDIUM | 1 |
| LOW | 1 |
| INFO | 2 |

HellPot's operational weakness is a public-documentation attack: the UA blacklist entries are in the README, the Markov source text (Nietzsche's "The Birth of Tragedy") is embedded and named in the repo, and the robots.txt CRLF + path pattern is deterministic. An adversary who has read the HellPot documentation can bypass the trap (UA spoof → 404 + Trace-only log) and confirm deployment (robots.txt probe) without triggering a visible log entry. F1 is a code-level bug with real resource impact under adversarial conditions; F2 enables turning HellPot's resource-exhaustion design against itself.

---

## HIGH

### F1 — heffalump/heffalump.go:58 — WriteHell discards io.CopyBuffer error; extra write cycles after client disconnect

```go
if n, err = io.CopyBuffer(bw, h.mm, buf); err != nil {
    h.pool.Put(buf)
    return n, nil   // error discarded
}
```

When a client disconnects, `io.CopyBuffer` fails with a write error. `WriteHell` discards it and returns `(n, nil)`. The caller loop in `router.go:62-69` sees `nil` and calls `WriteHell` again. The loop eventually terminates because `bufio.Writer` maintains a sticky error state — the next `bw.WriteString("<html>\n<body>\n")` call propagates the buffered error and breaks the loop.

Real-world impact scales with TCP send buffer size (Linux default ~212KB–2MB): dozens of `WriteHell` iterations execute after client disconnect before EPIPE/ECONNRESET propagates, each consuming a 100KB pool buffer allocation and CPU. Under a distributed slow-disconnect flood, this compounds into measurable goroutine and allocator pressure against an already resource-contested server.

**Fix:** `return n, err` at heffalump.go:58.

---

## MEDIUM

### F2 — internal/http/router.go:87-117 — No write deadline; slow-drip reverse-tarpit attack

`fasthttp.Server` configures `ReadTimeout: 5 * time.Second` but no `WriteTimeout`. A client that sets its TCP receive window to zero blocks HellPot's goroutine on `bw.Flush()` indefinitely. With `MaxConnsPerIP: 10` and a distributed fleet, `10 × N_IPs` goroutines are held in permanent blocked-write state — inverting the tarpit: HellPot stalls waiting on the attacker's deliberate slow reads.

At default `MaxWorkers = fasthttp.DefaultConcurrency` (262,144) and 10 conns/IP, an attacker needs ~26,200 distinct IPs to saturate. A /16 botnet achieves this trivially.

**Fix:** Add `WriteTimeout: 60 * time.Second` in `getSrv()`.

---

### F3 — internal/http/router.go:21-27 — X-Real-IP accepted without validation; log IP spoofing in direct-exposure deployments

```go
func getRealRemote(ctx *fasthttp.RequestCtx) string {
    xrealip := string(ctx.Request.Header.Peek(config.HeaderName))
    if len(xrealip) > 0 {
        return xrealip
    }
    return ctx.RemoteIP().String()
}
```

`config.HeaderName` defaults to `X-Real-IP`. No format validation. In direct-exposure deployments (the Docker config binds `0.0.0.0:8080` publicly), any client can send `X-Real-IP: 8.8.8.8` and HellPot logs Google's DNS resolver as the attacker's address. Downstream SIEM/threat-intel pipelines fed HellPot's JSON logs ingest attacker-chosen IPs.

Nginx proxy config (`proxy_set_header X-Real-IP $remote_addr`) mitigates this for correctly proxied deployments; direct exposure is the gap.

**Fix:** Validate header value with `net.ParseIP` before trusting it; fall through to TCP remote address on failure.

---

### F4 — internal/http/router.go:42-48 — UA blacklist entries are public; trivial 404 bypass with no Info-level log

```go
for _, denied := range config.UseragentBlacklistMatchers {
    if strings.Contains(string(ctx.UserAgent()), denied) {
        slog.Trace().Msg("Ignoring useragent")
        ctx.Error("Not found", http.StatusNotFound)
        return
    }
}
```

Default blacklist entries (`Cloudflare-Traffic-Manager`, `curl`) are in the public README and `docker_config.toml`. The check fires BEFORE the `slog.Info().Msg("NEW")` entry. A bot that sets `User-Agent: Cloudflare-Traffic-Manager` receives:
- Clean 404 response
- Trace-level log only (suppressed unless `trace = true`)
- No tarpit exposure
- No Info-level visibility

The bypass requires zero technical sophistication — read the README, set the header.

**Fix:** Log blacklisted-UA requests at Info level; move the UA check after the "NEW" log entry; keep default entries private.

---

## LOW-MEDIUM

### F5 — Dockerfile — Container runs as root (no USER directive)

No `USER` directive in the Dockerfile. The distroless base (`gcr.io/distroless/static-debian11`) defaults to root (UID 0). Container escape yields root.

The distroless image ships a `nonroot` user. **Fix:** Add `USER nonroot` before `ENTRYPOINT`.

---

## LOW

### F6 — heffalump/heffalump.go:40-63 — Dead code on io.CopyBuffer success path

`MarkovMap.Read()` never returns `io.EOF` — it fills `p` and returns `(n, nil)` unconditionally (infinite reader by design). Therefore `io.CopyBuffer` never exits via the success path. The `pool.Put(buf)` at line 63 on the non-error path is unreachable dead code. Structural API contract violation: the `io.Reader` implementation never signals completion without documentation, and the caller loop depends on `bufio.Writer`'s sticky-error behavior as an implicit termination mechanism.

---

## INFO

### F7 — robots.txt is a deterministic HellPot fingerprint

Generated robots.txt:
```
User-agent: *\r\n
Disallow: /wp-login.php\r\n
Disallow: /wp-login\r\n
\r\n
```

CRLF line endings (real WordPress robots.txt uses LF), non-standard `/wp-login` alongside `/wp-login.php`, no `Sitemap:`, no `Allow:`. Any bot that reads robots.txt before crawling can identify HellPot before triggering it — the opposite of the intended lure effect.

---

### F8 — Markov source text is public; body content is classifiable after <10KB

The Markov chain is built from Nietzsche's "The Birth of Tragedy" (Project Gutenberg #51356), named in the README and embedded in `heffalump/src.go`. A classifier trained on the expected n-gram distribution detects HellPot response bodies with high confidence after reading <10KB. Combined with: no `Content-Length`, `<html>\n<body>\n` response preamble (no DOCTYPE), non-terminating chunked stream — fingerprinting HellPot without touching robots.txt is straightforward.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| Response never terminates (no EOF) | Read >200KB, no close | Very High |
| No `Content-Length` header | Header absence | High |
| `<html>\n<body>\n` preamble, no DOCTYPE | First 16 bytes | High |
| Nietzsche "Birth of Tragedy" n-gram distribution | Body content classifier | Very High |
| robots.txt: CRLF + `/wp-login` (no .php variant) | String match on `/robots.txt` | Very High |
| robots.txt Disallow paths match exactly the tarpit trigger routes | Path enumeration | High |
| No cookies, no nonces, no X-Powered-By on wp-login response | Header absence | High |
| <5ms first-byte (no DB query latency) | Timing | Medium |

## Tarpit Bypass Summary

| Method | Log Visibility | Sophistication |
|--------|---------------|----------------|
| UA = `Cloudflare-Traffic-Manager` | Trace only (invisible by default) | Trivial |
| Probe `/robots.txt` only | Debug level (`SERVE_ROBOTS`) | Trivial |
| Identify from robots.txt before crawling | Zero log entries | Trivial |
| Set TCP recv window = 0 (F2) | Info level — but consumes HellPot resources | Low |
| Slow-disconnect flood (F1) | Info level — exhausts goroutine/allocator | Low |
