# Canarytokens — Security Analysis

**Repo:** https://github.com/thinkst/canarytokens  
**Lanes:** 5 parallel (Core/Storage/DNS/HTTP · Webhook/Email · Cloud Keys/AWS/Azure · Input Channels SMTP/MySQL/mTLS/WireGuard/MCP · Detection Evasion)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 9 |
| MEDIUM | 22 |
| LOW | 10 |

The most severe issues are in the AWS infrastructure subsystem: a shared management secret leaked to logs on every auth failure, and a non-atomic state machine that allows duplicate Lambda invocations. Multiple alert suppression and fingerprinting vectors exist across token types. Python 3 type bugs appear throughout the codebase but are less severe than in OpenCanary.

---

## CRITICAL

### C1 — frontend/app.py:469 — Shared secret logged in plaintext on every auth failure

`frontend/app.py:469`:
```python
log.warning(f"{bearer_str} != {authorization}")
```

`bearer_str = f"Bearer {aws_infra.get_shared_secret()}"`. Every failed `POST /awsinfra/management-response` logs the actual bearer token in plaintext. Any log sink (CloudWatch, Sentry, log forwarders) exposes it.

**Impact chain:** Extract the secret → POST to `/awsinfra/management-response` with any `handle` + `result` dict → inject arbitrary management Lambda responses → control state machine transitions, influence decoy name generation via Gemini, advance INGESTING state on arbitrary token handles.  
**Trigger:** Send any request with wrong `Authorization` header to `/awsinfra/management-response`, then read logs.

---

### C2 — frontend/app.py:1318-1324 + aws_infra/operations.py:359-364 — Fake Lambda response injection post-secret extraction

Once C1 yields the shared secret:

```python
# operations.py:359-364
def add_handle_response(handle: str, response: dict) -> None:
    json.dumps(response)  # no schema validation
    r.set(handle, ...)    # writes directly to Redis
```

Attacker-controlled `response` dict reaches `generate_proposed_plan` (Gemini prompt), `save_current_assets`, and controls `session_credentials_retrieved` state flag. State machine transitions (`INGESTING`, `COMPLETE`) can be forced on any token whose handle is known.

**Impact:** Arbitrary state advancement in any AWS canary token; potential influence over decoy asset naming.

---

## HIGH

### H1 — settings.py:143 — `MCP_SERVER_SECRET` defaults to hardcoded public value

```python
MCP_SERVER_SECRET: Optional[str] = "abcD0123defG4567"
```

AES-128-GCM key for MCP JWE generation. Any deployment omitting `CANARY_MCP_SERVER_SECRET` uses this key.

**Impact:** Decrypt any captured MCP canary `Authorization: Bearer <JWE>` header with the public default key → recover `token_id`, `alert_on`, `aws_token`. MCP configs live in `~/.config/claude/claude_desktop_config.json` — prime dotfile exposure surface.  
**Trigger:** Grab leaked MCP config, AES-128-GCM decrypt with `"abcD0123defG4567"`.

---

### H2 — kubeconfig.py:109 — Cluster name hardcoded to `"k8s-prod-cluster"` across all tokens

```python
cluster_name = "k8s-prod-cluster"
```

Every generated kubeconfig uses this string. Grep for `k8s-prod-cluster` → immediate Canarytokens identification. Alert never fires; attacker discards without use.

Additionally: username space is 5×8×4×3 = 480 combinations. Enumerate all 480 to probabilistically identify kubeconfigs as canaries without triggering use.

---

### H3 — aws_infra/utils.py:43-51 — `generate_tf_module_prefix()` uses Mersenne Twister PRNG

```python
def _random_alpha_numeric_string(length: int, ...) -> str:
    return "".join(random.choices(characters, k=length))
```

The 27-char Terraform module prefix is the S3 bucket path for each customer's `tf.zip`. `generate_external_id()` and `generate_handle_id()` correctly use `secrets`; this function does not. With ~624 observed prefixes, Mersenne Twister state is recoverable → future prefixes predictable → download other customers' Terraform plans from S3.

---

### H4 — settings.py:133 — `AZUREAPP_SECRET` is plain `str`, not `SecretStr`

```python
AZUREAPP_SECRET: Optional[str]  # TODO: Figure out SecretStr with Azure secrets
```

Inline TODO confirms known-unfixed state. Pydantic `.dict()`, `__repr__`, `__str__`, and Sentry error context serialize this in plaintext. Sentry is enabled by default (`SENTRY_ENABLE: bool = True`). Any unhandled exception with `settings` in scope emits the Azure app secret to Sentry. Same for `GEMINI_API_KEY`, `AWSID_AUTH`, `AZURE_ID_TOKEN_AUTH`.

---

### H5 — canarydrop.py:460-461 — JS injection via unescaped `clonedsite` field

`get_cloned_site_javascript()` interpolates `self.clonedsite` (user-supplied domain, no character validation) directly into a JS string literal via f-string. `clonedsite_js` is returned for embedding AND surfaced in the management UI (`app.py:769`, `1720`).

**Trigger:** `clonedsite = 'evil.com"; alert(document.domain); //'` — syntactically valid injected JS, stored XSS in the token-owner's dashboard.

---

### H6 — msreg.py:39-43 — Registry file injection via `cmd_process`

`cmd_process` validated only for `.endswith(".exe")` then interpolated into `REG_TEMPLATE` at `{PROCESS}` positions in a downloaded `.reg` file.

**Trigger:** `cmd_process = "klist.exe]\r\n[HKEY_CURRENT_USER\\Software\\Classes\\ms-settings\\shell\\open\\command]\r\n@=cmd.exe\r\n;klist.exe"` — satisfies `.exe` check, injects arbitrary registry keys into victim's imported `.reg` file. UAC bypass and persistence keys directly achievable.

---

### H7 — channel_input_smtp.py:127-130 — SMTP metadata fully attacker-controlled

`validateFrom` accepts any MAIL FROM. `client_name` (HELO), `sender`, `headers`, `links`, `attachments` stored verbatim from attacker's connection.

**Impact:** Alert notification displays completely attacker-crafted "who connected" data. False-flag / incident response misdirection. Attacker controls the forensic trail visible to the token owner.

---

### H8 — aws_infra/state_management.py:97-121 — `update_state` is not Redis-atomic (TOCTOU)

```python
def update_state(canarydrop, new_state, **kwargs):
    if not allow_next_state(canarydrop, new_state):  # read
        raise ...
    canarydrop.aws_infra_state = ...
    queries.save_canarydrop(canarydrop)              # write (no WATCH/MULTI/EXEC)
```

Two concurrent SETUP_INGESTION calls both pass the state check on the same stale read → both write new state → two SQS messages queued → management Lambda runs twice → duplicate EventBridge rules deployed, double infrastructure cost, potential duplicate alerts.

Compare: `update_data_generation_requests` in `db_queries.py:57-71` correctly uses `r.transaction()`.

---

### H9 — tokens.py:327, channel_input_mysql.py — Timestamp injection / unbounded buffer

- `tokens.py:327`: `ts_key` timestamp field derived from attacker-controlled data — log record timestamp can be forged to appear in the past or future.
- `channel_input_mysql.py:33-34`: `self.buf += data` with no upper bound; `MIN_LENGTH` enforces minimum, not maximum. Attacker streams data indefinitely, consuming process memory. `loseConnection()` fires only after `len >= 60`, but buffer can reach process-memory limits first.

---

## MEDIUM

### Input channel issues

**M1 — channel_output_email.py:252** — STARTTLS silently skipped when no SMTP credentials are configured. Alert emails sent unencrypted without warning.

**M2 — models/cc.py:38** — `CreditCard.render_html()` interpolates `self.name`, `self.expiration`, `self.cvc` into HTML via f-string with no escaping. Stored XSS if any field contains `<script>` and the card provisioning backend accepts user-influenced data.

**M3 — channel_input_smtp.py:178-180** — `receivedHeader` stores attacker-controlled HELO `client_name` directly into the hit record without sanitization.

**M4 — channel_input_mtls.py:59-67** — `send_response()` triggered on empty line: `self.lines[0].split(b" ")[1]` raises `IndexError` if first byte is `\r\n`. Bare `except Exception` catches it but transport may already be in error state. Repeated connections → repeated exceptions.

**M5 — channel_input_mtls.py:69-72** — `line.split(b":")[1]` instead of `split(b":", 1)[1]`. Headers with multiple colons (e.g., `Authorization: Bearer xyz`) silently truncated. Headers with no colon crash `send_response()`.

**M6 — channel_input_mysql.py:82-86** — `host_buf.decode()` after `host_buf.index(b"\x00")`: if no null terminator, `ValueError`. If null byte far into buffer (unbounded per M9 above), very large string logged. Attacker-controlled hostname written to alert notifications without length cap.

### AWS infrastructure

**M7 — aws_infra/data_generation.py:264-270** — Prompt injection via user-controlled AWS resource names into Gemini. `inventory` (real AWS asset names) and `parent_name` are interpolated into LLM prompt without sanitization. Adversarially named bucket can attempt injection; `responseSchema` constraint limits impact but crafted names could exhaust the 5-attempt retry loop.

**M8 — lambda_source/exposed_key_checker/lambda_handler.py:115-131** — Exposed key checker POSTs to `data.tokens_server` from IAM username regex parse, no validation against existing canarydrops. Crafted IAM username on a publicly leaked real AWS key triggers a false `token_exposed=True` POST for a victim token, poisoning their investigation timeline.

### Token evasion / fingerprinting

**M9 — queries.py:596** — Non-atomic rate-limit TOCTOU. Rate limit check and increment are separate Redis operations. Parallel requests can both pass the check before either increments, allowing double-triggering within a rate-limit window.

**M10 — frontend/app.py:853** — `fetchlinks` email oracle. Behavior difference between existing and non-existing token email addresses allows enumeration of registered canary alert addresses.

**M11 — frontend/app.py:933** — Unauthenticated `/commitsha` endpoint exposes deployment version. Combined with known CVEs/bugs per version, enables targeted exploitation.

**M12 — switchboard.env.dist:17** — WireGuard key seed committed to the repository. Default deployments using this file unmodified share derivable key material.

**M13 — switchboard.env.dist:35** — Live Sentry DSN committed to repository. Any reader of the repo can submit events to the Canarytokens Sentry project, polluting production error tracking.

**M14 — channel_output_webhook.py:30** — `port_whitelist=set(range(0, 65535))`: all ports whitelisted in advocate. Internal services on non-standard ports (e.g., internal admin panel on port 8080) potentially reachable if SSRF bypass path exists. Noted as partially mitigated by advocate's IP validation.

**M15 — tokens.py:800** — MCP `client_ip` field is fully attacker-controlled (HTTP X-Forwarded-For or similar header). False source attribution in MCP token alerts.

**M16 — canarydrop.py line 636** — `can_notify_again()` dead code path. Alert suppression logic branch that is never reached under normal flow — potential gap in notification rate limiting if path becomes reachable.

**M17 — AWS kubeconfig evasion** — `api-server-addr` in generated kubeconfig uses a subdomain of the attacker's chosen domain. Sophisticated red-teamers strip kubeconfigs from repos before use, check the API server endpoint against known canary infrastructure.

**M18** — DNS canary tokens fire on any lookup including passive recursive resolvers, CDN prefetch, and browser link prefetch. False positive rate is non-zero; defenders may tune alert fatigue by suppressing these — attackers know this and use DNS-only access to test if monitoring is active.

**M19** — Image/Web Bug tokens fire on crawlers, link preview bots, and email client prefetch. Alert notification distinguishes User-Agent types but operators often ignore these. Attacker using a curl-spoofed Googlebot UA can test for monitoring with reduced operator attention.

**M20** — All canary token URLs share `canarytokens.org` or configured domain. A single domain blocklist entry silences all token types simultaneously. Self-hosted deployments mitigate this.

**M21** — Token memo field is searchable by token owners but not validated for length or content. Excessively long memos cause rendering issues in management UI.

**M22** — `channel_input_mtls.py:175`: `random.randint(0, 100000000)` for cert serial number — Mersenne Twister, not CSPRNG. Birthday collision probability non-trivial at 100M possible values with multiple issued certs.

---

## LOW

- **sign_file.py:30-35** — Unnecessary `shell=True` for `echo` subprocess. `tmpdir` is server-controlled so no direct exploitability, but inconsistent with adjacent uses of `shlex.split()`.
- **channel_input_mysql.py:82** — Hostname extraction raises `ValueError` if no null terminator, falls to `except Exception` at line 63, silently drops the hostname from alert.
- **switchboard.env.dist** — Example file ships with `DEBUG=True`, `LOG_LEVEL=DEBUG`, and placeholder secrets that are not obviously invalid — operators may deploy with these.
- **canarytokens/channel_output_webhook.py** — No retry backoff or timeout cap on webhook delivery. A slow attacker-controlled webhook endpoint holds the Twisted worker for the duration of the timeout.
- **DNS canary** — TTL on canary DNS responses is 0 (no caching). Detectable by passive DNS observers monitoring for zero-TTL entries on specific domains.
- **AWS keys (awskeys.py:63-76)** — Canary nature visible only in IAM username field (`server@@token`), not in access key ID or secret. TruffleHog `--only-verified` passes — real credential. Alert suppression window: time between key theft and detection pipeline.
- **Azure keys (azurekeys.py:43-52)** — Real Azure AD service principal with real certificate. Working Azure identity until alert fires.
- **kubeconfig username space** — 480 combinations enumerable in seconds; low confidence as a standalone fingerprint but useful in conjunction with `k8s-prod-cluster` (H2).
- **HTTP canary** — Redirect-on-visit behavior (302 to target URL) is identical for triggered and non-triggered tokens. No timing-based distinction possible; side-channel token probing not applicable.
- **Token ID format** — 25-char base58 string, `secrets.token_hex(16)` derived. Secure; no enumeration path.

---

## Detection Evasion Summary

| Vector | Mechanism | Mitigation Gap |
|--------|-----------|---------------|
| DNS token | Passive resolver / CDN prefetch triggers false positive | Operators tune these out |
| Web Bug / Image | Crawler / link preview fires before attacker | User-agent filtering helps but spoofable |
| Kubeconfig | `k8s-prod-cluster` + 480 username patterns | Trivial static grep |
| MCP JWE | Default key `"abcD0123defG4567"` public in source | Decrypt without triggering |
| AWS key | Canary indicator only in IAM username | Real credential — scanner-bypasses by design |
| Canarytokens domain | Single domain blocklist kills all token types | Self-hosted deployments only mitigation |
| SMTP source | All HELO/MAIL FROM/headers attacker-controlled | False-flag attribution trivial |
| Rate limit | Non-atomic TOCTOU in `queries.py:596` | Alert suppression via rapid parallel requests |
