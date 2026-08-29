# FCaptcha — Security Analysis

**Repo:** https://github.com/WebDecoy/FCaptcha  
**Type:** Behavioral bot-detection CAPTCHA with Go/Node.js/Python servers, browser JS widget, PoW primitive, JA4/JA3 TLS fingerprinting, webbotauth  
**Lanes:** 5 parallel (Go server · Node.js server · Python server · client-side JS · deployment/PoW/conformance)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 10 |
| MEDIUM | 9 |
| LOW | 5 |

FCaptcha's behavioral detection is fully client-supplied with no cryptographic anchor when `signalsJson` is omitted — the PoW is the only hard server-side requirement. Two client-supplied boolean fields (`touchEvents:1`, `pointerHasNonMouseType:true`) suppress ~60% of the VisionAI and Behavioral category weight. The benchmark corpus ships the exact human signal values an attacker needs to replay, and `normalize.js` in the same repo documents every Playwright anti-detection patch required to pass environmental checks. The npm library's `verifyToken` skips the single-use replay guard entirely.

---

## CRITICAL

### C1 — main.go:522-537 + scoring.go — Signal commitment is opt-in; omitting `signalsJson` bypasses cryptographic binding entirely

Signal commitment — the mechanism binding behavioral signals to the PoW solution — is conditional:

```go
if req.SignalsJson != "" && clientSignalsHash != "" {
    computedHash := sha256.Sum256([]byte(req.SignalsJson))
    // validate hash
}
signals := req.Signals  // used directly when check is skipped
```

When the client sends `signals` directly without `signalsJson` and without a `powSolution.signalsHash`, the entire commitment check is skipped. The server scores the attacker-supplied `signals` map with no cryptographic anchor.

**Trigger:** POST `/api/verify` with valid PoW solution solved against `sha256("{}")` or any fixed signal hash, plus a fabricated `signals` body and no `signalsJson` field.  
**Impact:** Complete decoupling of PoW computation from submitted behavioral signals. Any behavioral profile scores the same regardless of what was actually observed. This is a structural bypass that renders the entire detection stack advisory.

---

### C2 — index.js:400-427 — npm library `verifyToken` has no token replay guard

The server's `/api/token/verify` correctly calls `SHARED_STATE.claimToken` or `tokenStore.markUsed` before returning valid. The npm library's `verifyToken` method (used by integrators calling `createMiddleware`/`tokenVerifyHandler`) decodes, checks expiry, and verifies the HMAC — but never calls any replay store method.

**Trigger:** POST the same base64url token to any endpoint backed by the library's `verifyToken` repeatedly within the 5-minute expiry window.  
**Impact:** Complete token replay. One legitimately-earned token satisfies arbitrarily many backend verifications. Any consumer using the library integration path has zero single-use protection.

---

### C3 — fcaptcha.js:3044-3070 — Client-side-only mode issues unsigned base64 tokens; no server required

When `FCaptcha.serverUrl` is null, the entire evaluation runs inside `_clientSideVerify`: pure arithmetic operating on attacker-supplied JSON. On "success", the token is `btoa(JSON.stringify({timestamp, score, id}))` — no HMAC, no server signature, plaintext base64.

Any backend that inspects this token locally rather than calling `/api/siteverify` is bypassed entirely.

**Trigger:** Deploy widget without `serverUrl` configured, or operate in unhosted self-contained mode.  
**Impact:** CAPTCHA reduced to client-side arithmetic on attacker-controlled numbers with no server involvement.

---

### C4 — bench/capture/normalize.js:50-203 — Project ships the exact Playwright bypass playbook

`normalizeEnvironment()` in the benchmark toolkit documents and implements every environmental bypass needed to pass FCaptcha's detection layer:

- `navigator.webdriver` → `Object.defineProperty` to `false`
- `navigator.plugins` → patched to return 5-plugin PDF viewer set
- `window.chrome` → `{csi, loadTimes}`
- `window.outerHeight` → `innerHeight + 118`
- `navigator.connection.rtt` → `50`
- `Notification.permission` → `'default'` (eliminates contradiction signal)
- `WebGLRenderingContext.prototype.getParameter` → returns `'Apple M-series GPU'`
- `RTCPeerConnection.createOffer` → injects fake RFC 1918 ICE candidate

This is the project's own benchmark normalization code. An attacker using Playwright with this init script attached passes every environmental check the widget runs. The bypass playbook is public, maintained, and in the same repo as the target.

---

### C5 — config.js:3 + main.go:138 + test/test-detection.js:20-21 — Hardcoded public default signing key

Both server implementations fallback to `dev-secret-change-in-production` as the signing secret. This string is in the public source repository and is the HMAC key for all CAPTCHA tokens.

The test suite (`test/test-detection.js:20-21`) additionally hardcodes this value as `VERIFY_SECRET`:

```javascript
const VERIFY_SECRET = process.env.FCAPTCHA_VERIFY_SECRET ||
  process.env.FCAPTCHA_SECRET ||
  'dev-secret-change-in-production';
```

**Trigger:** Any deployment with `FCAPTCHA_INSECURE_DEV_MODE=1` or where the secret was not set. Running `node test/test-detection.js http://target:3000` against any such server fully authenticates to `/api/token/verify`.  
**Impact:** Forge valid tokens without solving PoW; consume any pending user token before the user's backend does (DoS). Helm chart enforces explicit secret at render time; raw Docker/Compose/binary deployments do not.

---

## HIGH

### H1 — scoring.go:1055-1062 + engine.js:92-95 — Two attacker-supplied booleans suppress all mouse detection (60% of weight)

`isTouchModality` returns true when `touchEvents >= 1 && pointerHasNonMouseType == true` (both client-supplied). When true, the following are suppressed:

| Detector | Category | Score weight |
|---------|---------|-------------|
| No mouse movement before click | VisionAI | 0.9 |
| No approach trajectory | VisionAI | 0.7/0.8 |
| Mouse micro-tremor absent | VisionAI | 0.7/0.6 |
| Approach directness too straight | VisionAI | 0.5/0.5 |
| Zero mouse/touch/keyboard events | Behavioral | 0.8/0.9 |
| Insufficient mouse movement | Behavioral | 0.6/0.7 |
| Mouse velocity too consistent | Behavioral | 0.6/0.6 |
| Mouse event rate abnormal | Behavioral | 0.4/0.4 |

**Trigger:** `POST /api/verify` with `signals.behavioral.touchEvents = 1` and `signals.behavioral.pointerHasNonMouseType = true`.  
**Impact:** VisionAI and Behavioral categories contribute nearly nothing. Combined with a clean environment payload, score lands well under 0.5 ("allow").

---

### H2 — bench/corpus/ + fcaptcha.js — Corpus provides exact human signal values; deterministic bypass payload constructible

The benchmark corpus ships exact passing human sample values (`human-mouse-desktop.json`). A minimal bypass:

```json
{
  "behavioral": {
    "microTremorScore": 1.0,
    "velocityVariance": 0.133,
    "straightLineRatio": 0.297,
    "overshootCorrections": 1,
    "approachDirectness": 0.154,
    "interactionDuration": 3168,
    "touchEvents": 3
  },
  "environmental": {
    "webdriver": false,
    "cdp": { "detected": false },
    "plugins": 5,
    "languages": true
  }
}
```

Combine with valid PoW, wait 1.5s, POST. Score < 0.3.

---

### H3 — fcaptcha.js:3066-3069 — Fail-open: server error silently passes forms with unsigned token

`InvisibleSession._attachToForms` calls `form.submit()` on any exception from the FCaptcha flow. Server downtime, DNS failure, CORS rejection, or rate-limit timeout causes the widget to silently issue an unsigned client-side token and let the form proceed without protection.

**Trigger:** Block `FCaptcha.serverUrl` at the network layer, or cause a 5xx on `/api/verify`.  
**Impact:** CAPTCHA protection disappears completely; form submission proceeds.

---

### H4 — clientip.go:47-56 — Default TRUSTED_PROXIES covers all RFC1918 — any co-located service forges any client IP

Default trust set when `TRUSTED_PROXIES` is unset:
```
127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7
```

Any service on the same private network — same K8s cluster, same Docker network, same VPC — can set `X-Forwarded-For: <arbitrary>` and the server accepts it as the client IP.

All IP-keyed defenses fall: rate limiting, IP reputation/datacenter detection, PoW difficulty escalation, suspicion ledger, token IP binding.

---

### H5 — main.go:215 + INSTALLATION.md — `FCAPTCHA_LEGACY_UNAUTH_VERIFY` disables token verification auth

Setting `FCAPTCHA_LEGACY_UNAUTH_VERIFY=true` makes all siteverify endpoints (`/turnstile/v0/siteverify`, `/recaptcha/api/siteverify`, `/siteverify`, `/api/token/verify`) accept any caller without a `secret` field. Any party that can reach the port can consume tokens.

**Impact:** Single-use guard becomes network-reachability-only. An attacker who intercepts a token (network sniff, log, XSS) consumes it before the legitimate backend, blocking the real user.

---

### H6 — siteverify.go:247-252 — Hostname allowlist bypassed when Origin and Referer absent

```go
if !a.Enabled() || hostname == "" {
    return true
}
```

`RequestHostname` returns `""` when both `Origin` and `Referer` are absent. Any server-side caller (curl, HTTP client) that omits these headers unconditionally passes the hostname allowlist even when `FCAPTCHA_ALLOWED_HOSTNAMES` is configured.

**Impact:** Hostname binding provides no protection against server-side callers. Combined with C1 (crafted signals), an attacker mints valid tokens for a target site from their own infrastructure using that site's public site key.

---

### H7 — main.go:541-552 + scoring.go:1103-1128 — PoW timing check reads client-supplied `PowTiming` struct

`PowTiming.duration`, `.iterations`, `.difficulty` are deserialized from the request body and fed directly into the "PoW completed impossibly fast" timing detector. The server has no independent record of solve duration.

**Trigger:** Include `"powTiming": {"duration": 3000, "iterations": 175000, "difficulty": 4}` in any verify request.  
**Impact:** PoW timing as a bot-detection signal is fully attacker-controlled.

---

### H8 — docker/docker-compose.yml + render.yaml + charts/ — No TLS enforced in 3 of 4 deployment paths

Only `fly.toml` enforces TLS (`force_https = true`). Docker Compose, Render, and Helm ingress all default to plaintext HTTP.

**Impact:** Tokens, `FCAPTCHA_VERIFY_SECRET`, behavioral signals (canvas, typing), and JA4/JA3 values transit cleartext and are interceptable. Passive observer can replay intercepted tokens within the 5-minute window.

---

### H9 — server-node/server.js:276-283 — PoW replay across processes without Redis

In-memory path's SET-then-GET anti-replay is atomic within one Node.js process. In a multi-process deployment without `REDIS_URL`, two simultaneous verify requests carrying the same PoW solution routed to different processes both pass and both receive tokens.

---

### H10 — limits.js:120-148 — BoundedSet LRU eviction reopens token replay window

`tokenStore.usedTokens` is a `BoundedSet(100000)`. On overflow, the oldest entry is evicted. A spent token within the 5-minute expiry window whose entry was evicted can be replayed. Redis path (`SET NX PX`) is not affected.

---

## MEDIUM

### M1 — server.js:543-551 vs index.js:400-427 — Library vs server path inconsistency; replay guard only on server path

The server's `/api/token/verify` calls `claimToken`/`markUsed` before returning. The library's `verifyToken` (used by `createMiddleware`) does not. Consumers who choose the npm library over the self-hosted server get fundamentally weaker replay protection. Not documented.

---

### M2 — scoring.go:397-399 — Rate limit category weight 0.01 is operationally irrelevant

Max rate-limit contribution to final score: `0.72 × 0.01 = 0.007`. Against 0.5 pass threshold, a bot making 50+ requests per minute picks up 0.007 additional score. Rate limiting raises the score imperceptibly while the adaptive PoW minimum-age escalation (`minAgeMs` up to 15s for flagged sources) is the real control.

---

### M3 — clientip.go:16-25 — PoW IP binding uses /24 granularity; CGNAT laundering

PoW challenges are bound to IPv4 /24 or IPv6 /56. Any IP in the same /24 can submit a PoW solution obtained by another IP in that /24. In shared-egress environments (corporate NAT, cloud CGNAT), this enables challenge marketplace: fetch on a clean IP, solve, submit from a flagged IP.

---

### M4 — detection.go:606 — JA4 fingerprint set empty by design; TLS detection contributes zero signal

`knownBotJA4Hashes = map[string]string{}`. JA4 never fires. JA3 only catches self-identifying bots that retain default TLS stacks (curl, Python requests). Browser-emulating automation is uncaught.

---

### M5 — fcaptcha.js:3537 — `data-endpoint` attribute sets global serverUrl; XSS pivot

Auto-init reads `container.dataset.endpoint` and assigns globally to `FCaptcha.serverUrl`. DOM injection on any element with `data-fcaptcha` redirects all widget verification to an attacker-controlled server, collecting submitted signal payloads for replay.

---

### M6 — fcaptcha.js:2259-2293 — WebRTC local IP exfiltration in signal payload

`_getWebRTCInfo()` collects RFC 1918 local addresses via ICE candidate parsing (no permission required) and transmits them in `signals.environmental.webrtcInfo.localIPs` to the FCaptcha server on every verification. Internal network topology of real users is exfiltrated. Chrome mDNS obfuscation reduces this on modern browsers.

---

### M7 — detection.py:82 — Blocking reverse DNS lookup in async FastAPI event loop

`socket.gethostbyaddr(ip)` is called inside a FastAPI route handler on every `/api/verify` and `/api/score` request. `socket.gethostbyaddr` is a blocking syscall — it parks the asyncio event loop thread for the full DNS resolver timeout on every IP with no PTR record or a slow nameserver.

**Trigger:** Send verify requests from IPs across many reverse-DNS zones with missing PTR records (Mullvad exit IPs, cloud egress IPs, RFC1918 without rDNS). Each request stalls the event loop for 5–30s depending on resolver config.  
**Impact:** Single-connection DoS against all traffic handled by that uvicorn worker. No PoW required for `/api/score`, lowering barrier further.  
**Fix:** `asyncio.get_event_loop().run_in_executor(None, socket.gethostbyaddr, ip)` or `aiodns`.

---

### M8 — detection.py:558-719 + inputforensics.py:104-122 — Type confusion crash in statistical analysis; no PoW required to trigger

Client-supplied list fields (`intervals`, `dwellTimes`, `burst_gaps`) are iterated in math operations with no type guard:

```python
log_intervals = [math.log(v) for v in intervals if v > 0]  # TypeError on str
avg_dwell = sum(dwells) / len(dwells)                        # TypeError on None
```

FastAPI returns 500 on unhandled `TypeError`. The detection path runs before the PoW gate check for `/api/score`, making this a pre-auth crash path. Sending `{"signals":{"formAnalysis":{"textareaKeyboard":{"f":{"intervals":["x","y"]}}}}}` with a valid siteKey but no PoW crashes the handler.

---

### M9 — charts/fcaptcha/templates/secret.yaml — Helm secret in `stringData` not encrypted at rest

Kubernetes Secrets are base64-encoded, not encrypted, by default. Any principal with `get/list` on Secrets in the namespace extracts `FCAPTCHA_SECRET` in plaintext. The chart recommends Sealed Secrets/External Secrets but does not enforce them.

---

## LOW

- **main.go:206-208** — `FCAPTCHA_VERIFY_SECRET` defaults to signing key; backends transmitting the verify secret are transmitting the minting key, which logs, scraping, or cleartext HTTP interception turns into unlimited token forgery.
- **main.go:350-362** — pprof server can be externally exposed via `FCAPTCHA_PPROF_ADDR`. If reachable, `/debug/pprof/heap` exposes the HMAC signing key and all in-memory tokens.
- **server.js:1012-1019** — Legacy `/api/challenge` endpoint issues `challengeId` not stored in `powChallengeStore`; any solution submitted hits `challenge_not_found`. Also uses `Date.now()` (sequential, low-entropy) for ID generation.
- **main.go:220-226** — `FCAPTCHA_LOG_VERDICTS_INCLUDE_RAW=1` writes visitor-derived PII (reverse-DNS hostnames, User-Agent fragments, form field IDs) to stdout logs. GDPR exposure in regulated deployments.
- **scoring.go:255-263** — `MarkSolutionUsed` is orphaned (not called in the PoW verification flow). If called independently, it writes to LRU without deleting the challenge, leaving the challenge redeemable after the solution is "marked used."

---

## PoW Algorithm (Precise Specification)

```
pow_input    = "${challengeId}:${timestampMs}:${difficulty}:${signalsHash}:${nonce}"
solution     = sha256(pow_input)  // must start with '0' * difficulty (hex)
difficulty-4 = 16^4 = 65,536 expected iterations
```

- Nonce: integer starting at 0, linear increment. **Fully parallelizable** — no inter-iteration dependency.
- GPU-solvable in microseconds at difficulty 4. Solve time → hold solution 1,501ms → submit.
- Server-side gate: challenge must be ≥ `minAgeMs` (1,500ms default, up to 15s for flagged sources) old at submission time — measured by server clock, unforgeable.
- Effective throughput cap: ~40 attempts/minute per IP/siteKey at clean status.
- Network binding: bound to source /24 (IPv4) or /56 (IPv6) at challenge issuance.

---

## Bot Detection Signals — Spoofability Matrix

| Signal | Spoofable | Difficulty | Notes |
|--------|-----------|------------|-------|
| `behavioral.*` (mouse, scroll, timing) | Yes | Trivial | Copy from corpus JSON |
| `environmental.webdriver/cdp/playwright` | Yes | Trivial | normalize.js patches these |
| `environmental.plugins/chrome/outerHeight` | Yes | Trivial | normalize.js patches these |
| `powTiming.duration/iterations` | Yes | Trivial | Client-supplied, server has no clock on solve |
| `formAnalysis.*` | Yes | Trivial | No server anchor |
| `clickData.holdDuration` < 1ms | Hard | Hard | Physically impossible for humans |
| `cadenceGapCV` = 0.35 vs human 3.56 | Hard | Hard | Must synthesize realistic typing variance |
| `scrollMorphology.distancePerEvent` 700px vs human 58px | Hard | Medium | Must synthesize realistic scroll events |
| `inputForensics.inputsWithoutInputType` | Hard | Medium | Requires knowing monitored fields |
| `environmental.sensor.*` (motion/gyro) | N/A | N/A | Absence treated as neutral server-side |
| PoW hash validity | No | N/A | SHA-256 verified server-side |
| PoW `ServerElapsed` timing | No | N/A | Server clock, not client |
| Token HMAC signature | No | N/A | Server secret required |
| TLS fingerprint (JA3/JA4) | Partial | Low | Empty JA4 set; JA3 only catches stock bots |
| `coalescedEmptyRatio` | Poor discriminator | N/A | = 1.0 for BOTH humans AND bots on macOS Chrome |

---

## FCaptcha Fingerprint Table (Bot Operator Reference)

| Signal | Value |
|--------|-------|
| Challenge endpoint | `GET /api/pow/challenge?siteKey=<key>` |
| Verify endpoint | `POST /api/verify` (JSON) |
| Score endpoint | `POST /api/score` (JSON) |
| Token verify | `POST /api/token/verify` |
| Turnstile compat | `POST /turnstile/v0/siteverify` |
| reCAPTCHA compat | `POST /recaptcha/api/siteverify` |
| Widget JS | `GET /fcaptcha.js` |
| Health | `GET /health` → `{"status":"ok"}` |
| Challenge response shape | `{"challengeId":str,"prefix":str,"difficulty":int,"minAgeMs":int,"expiresAt":int,"nonce":str,"sig":str}` |
| Success shape | `{"success":true,"score":float,"token":str,"recommendation":"allow","categoryScores":{...},"detections":[...]}` |
| 413 shape | `{"error":"request_too_large"}` at 64KB body |
| Token format | Unpadded base64url, compact sorted-key JSON payload, HMAC-SHA256 |
| Token expiry | 5 minutes, single-use (on server path; zero replay protection on library path) |
| Detection categories | `bot`, `headless`, `datacenter`, `vision_ai`, `behavioral`, `declared_ai`, `webbotauth` |
| CORS | `Access-Control-Allow-Origin: *` (all origins) |
| Default port | 3000 |
| PoW bypass field | omit `signalsJson` → no commitment check |
| Touch exemption trigger | `behavioral.touchEvents >= 3` suppresses all mouse checks |
| Keyboard exemption trigger | `behavioral.keyEvents >= 2` with no mouse → suppresses vision_ai |
| Container image | `ghcr.io/webdecoy/fcaptcha:latest` |
| npm package | `@webdecoy/fcaptcha-client` |
