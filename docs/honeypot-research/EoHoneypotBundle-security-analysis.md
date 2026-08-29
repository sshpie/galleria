# EoHoneypotBundle — Security Analysis

**Repo:** https://github.com/eymengunay/EoHoneypotBundle  
**Type:** Symfony PHP bundle — adds hidden honeypot fields to forms for bot detection  
**Lane:** Single comprehensive lane (small codebase, ~18 files)

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 3 |
| INFO | 1 |

The bundle's core detection mechanism is entirely CSS/attribute-based hiding with no cryptographic or session-bound component. The honeypot field is identifiable via three static DOM attributes in a single query selector, making it trivially bypassable by any bot with an HTML parser. The blacklisting feature is undermined in all reverse-proxy deployments (the standard production topology) via X-Forwarded-For spoofing, and the file-logging integration documented in the README creates a fail2ban weaponization path via log injection.

---

## HIGH

### H1 — Form/Type/HoneypotType.php:100-113 + Resources/views/Form/div_layout.html.twig:2 — Honeypot field fingerprinted by deterministic HTML attributes

Three hard-coded defaults injected into every rendered honeypot field with no randomization or per-request variation:
- `tabindex="-1"`
- `aria-hidden="true"`
- `style="position: fixed; left: -100%; top: -100%;"`

**Bypass:**
```javascript
document.querySelectorAll('[tabindex="-1"][aria-hidden="true"]')
// Returns the honeypot field. Bot omits it from submission.
// !$data evaluates true at HoneypotType.php:75 → no trigger, no record, no redirect.
```

The comment at line 105 acknowledges the autocomplete fingerprint problem and applies a random string to counter it. No equivalent treatment is applied to the structural attributes that are far more identifying.

**Impact:** Complete bypass against any bot with a DOM parser. Detection never triggers; no record created; no error raised.

---

### H2 — Form/Type/HoneypotType.php:80 + Manager/HoneypotManager.php:51,84 — IP spoofing defeats blacklisting and poisons fail2ban integration

`$request->getClientIp()` is the sole IP source for logging and blacklisting. In any deployment behind a reverse proxy (nginx, AWS ALB, Cloudflare — the standard production topology), Symfony trusts `X-Forwarded-For` and `getClientIp()` returns the leftmost unverified value.

The README explicitly documents fail2ban integration via the file log at `HoneypotManager.php:84`.

**Bypass:**
```http
POST /contact HTTP/1.1
X-Forwarded-For: 8.8.8.8
[honeypot field: populated → triggers, logs 8.8.8.8, not attacker's real IP]
```

`isBlacklisted()` at line 51 does `findBy(['ip' => $ip])` — comparing against the spoofed value. The attacker's real IP is never recorded. Rotating `X-Forwarded-For` values defeats the blacklist permanently.

**Weaponization:** Deliberately trigger the honeypot with `X-Forwarded-For: 8.8.8.8` → fail2ban bans Google's DNS resolver → DoS for all users whose DNS resolves through 8.8.8.8.

---

## MEDIUM

### M1 — Manager/HoneypotManager.php:84 — Log injection via unsanitized IP in file output

```php
$data = sprintf("[%s] - %s\n", $prey->getCreatedAt()->format('c'), $prey->getIp());
file_put_contents($this->options['storage']['file']['output'], $data, FILE_APPEND);
```

IP value interpolated into log line with no newline stripping, no encoding, no validation. Combined with H2 (X-Forwarded-For spoofing):

```
X-Forwarded-For: 1.2.3.4\n[2026-01-01T00:00:00+00:00] - 192.168.1.1
```

Writes two log lines, the second with an injected IP. Against a fail2ban config watching this file, this blocks `192.168.1.1` (internal host, gateway, DNS server).

**Requires:** file storage enabled (not the default).

---

### M2 — EventListener/RedirectListener.php:45 — Open redirect via Host header injection in redirect fallback

```php
} else {
    $target = $event->getRequest()->getUri();
}
$event->setResponse(new RedirectResponse($target));
```

When `redirect.enabled: true` but neither `url` nor `route` is configured, the redirect target is `Request::getUri()`. Symfony builds the URI from the incoming `Host` header. Without trusted-hosts configuration (a common misconfiguration), an attacker submitting a request with `Host: evil.com` receives a redirect to `http://evil.com/<path>`.

**Requires:** redirect enabled; `url` and `route` both null (defaults); no trusted-hosts config.

---

### M3 — EventListener/RedirectListener.php:24-25 — Duplicate listener registration under multiple honeypot fields

```php
public function onBirdInCage()
{
    $this->eventDispatcher->addListener('kernel.response', array($this, 'onKernelResponse'));
}
```

Registered dynamically on each `bird.in.cage` event. If a form has two `HoneypotType` fields and both receive data, `onBirdInCage` fires twice, registering `onKernelResponse` twice. Both invocations call `$event->setResponse(new RedirectResponse($target))` on the same response event; both prey records persisted via `flush()`. Potential redirect loop if `$target` resolves to the same URI.

---

## LOW

- **Resources/config/doctrine/HoneypotPrey.orm.xml:8** — `<field name="ip" type="string" column="default_format"/>` — column name is `default_format`, a template artifact. IP data stored in a column with no semantic meaning; any DBA, raw SQL query, or log correlation tool operating on the physical schema is misled.
- **Manager/HoneypotManager.php:85** — `file_put_contents()` return value discarded. Default path `/var/log/honeypot.log` is typically owned by root. All honeypot captures silently lost on permission error; no exception, no fallback, no warning.
- **Manager/HoneypotManager.php:76-87** — No rate limiting on honeypot trigger. Each non-empty submission creates and persists a `HoneypotPrey` record and calls `flush()`. No deduplication or IP-based throttle. Automated submission with rotating IPs causes unbounded DB growth.

---

## INFO

- No minimum-fill-time check. No timestamp token issued at form render; no elapsed time checked at submission. A bot that fills and submits in 50ms is indistinguishable from a human. Combined with H1's attribute bypass, the bundle provides meaningful protection only against bots that fill all fields without parsing HTML attributes.

---

## Bypass Techniques — Ranked by Complexity

| Rank | Technique | Sophistication | Bypasses |
|------|-----------|----------------|---------|
| 1 | Omit honeypot field from POST body entirely | Trivial | H1 |
| 2 | Submit honeypot field with empty string `""` | Trivial | Inherent to design |
| 3 | DOM parse for `tabindex="-1"` + `aria-hidden="true"` + fixed-position style; skip those fields | Low | H1 |
| 4 | Rotate `X-Forwarded-For` after detection to evade blacklist | Low | H2 |
| 5 | Inject newlines into `X-Forwarded-For` to forge fail2ban log entries and block legitimate IPs | Medium | M1 |
| 6 | Set `Host: evil.com` when triggering honeypot to receive open-redirect response | Medium | M2 |

Techniques 1-3 achieve zero-detection bypass. Techniques 4-6 are post-detection evasion or active abuse of the platform against its operator.
