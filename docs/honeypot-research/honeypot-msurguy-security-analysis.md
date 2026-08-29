# msurguy/Honeypot — Security Analysis

**Repo:** https://github.com/msurguy/Honeypot  
**Type:** Laravel PHP form honeypot bundle — hidden field + time-based spam detection  
**Lanes:** 2 (core PHP logic · validator RE + test coverage)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 1 |
| HIGH | 5 |
| MEDIUM | 4 |
| LOW | 5 |
| INFO | 1 |

The entire defense is a stateless client-side mechanism with no server-side token registry, no session binding, and no per-submission invalidation. The crypto layer (`Crypt::encrypt` → AES-CBC + HMAC-SHA256 over APP_KEY) is sound — tokens cannot be forged. The attack surface is entirely in the logic above it: one harvested ciphertext provides unlimited replays forever. An attacker who makes one GET request to any form using this bundle has a permanent bypass token for that deployment.

---

## CRITICAL

### C1 — Honeypot.php:66-76 — Token replay: no expiry, no one-time-use, no session binding

```php
return ( is_numeric($value) && time() > ($value + $parameters[0]) );
```

Three independent flaws compound into one critical bypass:

1. **No maximum age.** `time() > issued_at + min_seconds` enforces a floor but no ceiling. A token harvested from a cached page, a crawled archive, or any prior GET is valid indefinitely — 30 days later, 6 months later, permanently.

2. **No single-use enforcement.** There is no seen-token registry, no session binding, no per-submission invalidation. The same ciphertext submitted N times passes N times.

3. **No context binding.** The ciphertext carries no session ID, CSRF token, form name, or IP. A token generated on the contact form is valid against the registration form. A token from session A is valid in session B.

**Trigger:** GET any form page once. Extract the `my_time` input value. POST with `my_name=` (empty) and the extracted ciphertext on any subsequent request from any IP, any session, any form — forever.  
**Impact:** The time-based signal is neutralizable with a single prior request. Any bot operating a fetch-once/replay-many pattern bypasses the honeypot permanently and at scale.

---

## HIGH

### H1 — Honeypot.php:55 — PHP 7 type-juggling bypass: integer 0 passes field check

```php
return $value == '';
```

PHP 7 loose comparison: `0 == ''` evaluates `true`. A bot submitting a JSON-encoded body with `"my_name": 0` (integer) passes the honeypot field check unconditionally. Laravel's `Request::input()` returns the raw PHP type from JSON decode. `composer.json` declares `php: >=5.3.0`, covering all PHP 7 installations.

**Trigger:** `Content-Type: application/json`, body `{"my_name": 0, "my_time": "<valid_token>"}`.  
**Fix:** `=== ''` (strict comparison).  
**Scope:** PHP 5.3–7.x. Fixed in PHP 8 (strict comparison semantics changed for `0 == string`).

---

### H2 — Honeypot.php:36 — CSS-only concealment: single DOM query reveals and bypasses both honeypot fields

```php
$html = '<div class="' . $honey_name . '_wrap" style="display:none;"><input name="' . $honey_name . '" type="text" value="" id="' . $honey_name . '"/><input name="' . $honey_time . '" type="text" value="' . $honey_time_encrypted . '"/></div>';
```

The hiding mechanism is a single inline `style="display:none"` wrapper. Any headless browser (Puppeteer, Playwright, Selenium) or HTML parser identifies both fields with one query:

```javascript
document.querySelectorAll('[style*="display:none"] input[type="text"]').map(f => f.name)
// Returns: ["my_name", "my_time"]
```

The bot submits the form without these fields. The `validateHoneypot` check (`$value == ''`) passes because `Request::input('my_name')` returns `null`, and `null == ''` is true. No CSS-class indirection, no off-screen positioning, no randomized wrapper attributes.

---

### H3 — README.md:38 + tests/HoneypotTest.php:22 — Field names documented globally; `_wrap` suffix pattern fingerprints wrapper

Canonical usage pattern `generate('my_name', 'my_time')` is the default every integrator copies from the README. There is no randomization at generation time, no per-deployment salt, and no per-request name variation. The `_wrap` suffix pattern (`<div class="X_wrap">`) is unique to this package — any passive scanner can identify installations by matching the class against the inner input name, then predict the exact field names to omit.

**Bypass:** POST with `my_name=` empty and a valid/replayed `my_time`. All validation passes.

---

### H4 — Honeypot.php:36 — Deterministic HTML fingerprint; Laravel Crypt envelope pattern is Shodan-dorkable

The output structure:
```html
<div class="my_name_wrap" style="display:none;">
  <input name="my_name" type="text" value="" id="my_name"/>
  <input name="my_time" type="text" value="eyJpdiI6..."/>
</div>
```

The second input carries a Base64-encoded Laravel Crypt envelope (`{"iv":...,"value":...,"mac":...}`). This structure — `_wrap` class, `display:none`, paired inputs, JSON-in-base64 value — is unique to this package. A passive scanner can fingerprint installations before ever interacting with the forms. The Crypt envelope format also distinguishes Laravel 4 (mcrypt) from Laravel 5+ (OpenSSL AES-256-CBC) deployments.

---

### H5 — Honeypot.php:76 — Missing `$parameters[0]` guard; undefined offset collapses minimum wait to zero

```php
return ( is_numeric($value) && time() > ($value + $parameters[0]) );
```

If a developer registers the validator without a time argument (`'honey_time' => 'honeytime'`), `$parameters[0]` is undefined. PHP 7: `null` coerces to 0 in arithmetic; `time() > ($value + 0)` passes any past timestamp. PHP 8 strict mode: `TypeError` — fatal crash. No defensive check or default fallback exists.

**Trigger:** Misconfigure the validation rule; submit any past timestamp. Minimum wait collapses to zero seconds.

---

## MEDIUM

### M1 — Honeypot.php:83-86 — Token not bound to session, form, or user; lateral portability across application

```php
return Crypt::encrypt(time());
```

`Crypt::encrypt(time())` carries no session ID, no form name, no CSRF context, no IP. A token from the contact form is valid against the registration form. A bot that harvests one token from any form in the application can use it against every other form.

---

### M2 — Honeypot.php:36 — XSS if field names are config- or request-derived

`$honey_name` and `$honey_time` are concatenated raw into HTML without `htmlspecialchars()`. The API has no guard against dynamic-name patterns. Any deployment that derives field names from database values, config keys, or request parameters is an XSS sink.

**Trigger:** `Honeypot::generate('"><script>alert(1)</script>', 't')` injects inline.

---

### M3 — lang/*/validation.php — Error message discloses bot detection actively; should silent-discard

```php
'honeypot' => 'Spam has been detected',
```

When triggered, the user receives explicit confirmation that bot detection is active and their submission was flagged. Best practice is a fake-success response (silent discard) so bots cannot distinguish "detected" from "passed." The detection confirmation allows adaptive probing.

---

### M4 — Honeypot.php:98-104 — `catch (\Exception $exception)` swallows all decryption failures silently

```go
catch (\Exception $exception)
{
    return null;
}
```

Catches the base `\Exception`, not `DecryptException` specifically. OOM, framework misconfiguration, and APP_KEY rotation errors all return `null` silently. `is_numeric(null)` is false → validation fails → user sees an error indistinguishable from bot detection. No logging, no re-throw, no differentiation between tampered ciphertext and infrastructure failure.

---

## LOW

- **Honeypot.php:55** — `null == ''` passes when field is absent from POST body entirely — no presence assertion, bots that strip the field bypass the check (though this is the intended pattern for non-bot traffic).
- **Honeypot.php:83-86** — APP_KEY rotation immediately invalidates all outstanding tokens in open browser tabs; users receive "Please wait" error with no recourse. No token versioning or grace window.
- **README.md:52 vs Honeypot.php:36** — README documents `id="my_name_wrap"` but code emits `class="my_name_wrap"`. CSS selectors added by developers targeting `#my_name_wrap` silently fail.
- **tests/HoneypotTest.php** — Test suite covers only the happy path and two trivial negative cases; none of the bypass paths (type juggling, no-upper-bound, replay, JSON int input, parameter-absent crash) are exercised.
- **tests/bootstrap.php** — `time()` is stubbed to constant 1000, so all timing tests are against a frozen clock. No real-world timing edge case can be caught.

---

## INFO

- **Honeypot.php:55** — `is_numeric("1e5")` returns `true` in PHP (scientific notation). If the Crypt layer ever returned a scientific-notation-formatted timestamp (it doesn't currently), `1e5` would pass the numeric check. Not currently exploitable but a latent correctness risk.

---

## Bypass Matrix

| Attack | Sophistication | Bypasses |
|--------|---------------|---------|
| GET once → harvest token → replay forever | Trivial | C1 |
| POST `my_name=0` as JSON integer | Low (PHP 7 targets) | H1 |
| DOM parse `[style*="display:none"] input` → skip fields | Low | H2 |
| Read README → know field names → submit empty | Trivial | H3 |
| Token from form A → submit to form B | Trivial | M1 |
| Force error with invalid time → probe detection | Low | M3 |

The core defense model — stateless client-side concealment — is only effective against bots that submit every visible field without DOM inspection and make no prior GET request. Modern commodity spam bots and any human-operated form submitter with browser devtools fall outside that threat model.
