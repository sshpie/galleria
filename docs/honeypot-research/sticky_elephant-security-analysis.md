# sticky_elephant — Security Analysis

**Repo:** https://github.com/betheroot/sticky_elephant  
**Type:** Ruby PostgreSQL honeypot — Postgres wire protocol server capturing credentials and queries; reports to hpfeeds  
**Lanes:** 2 (server/connection/handler · configuration/payload/log_interface/postgres_simulator)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 7 |
| MEDIUM | 6 |
| LOW | 5 |
| INFO | 3 |

sticky_elephant has a YAML.load deserialization RCE in its configuration parser — an attacker who can influence the config file path gains full code execution before the honeypot starts. Authentication is universally bypassed (every password accepted unconditionally). The infinite retry loop on EOFError is a denial-of-service amplifier. The PostgreSQL wire implementation exposes four static invariant fields (pid=666, version string, fixture row content, config_file path) that uniquely identify the honeypot from a single connection.

---

## CRITICAL

### C1 — configuration.rb:16 — `YAML.load_file` without safe_load; RCE via Psych gadget chain

```ruby
config = YAML.load_file(config_path)
```

`YAML.load` (Psych) evaluates arbitrary Ruby objects during deserialization. An attacker who controls `config_path` (which comes from the CLI argument or an environment variable in some deployment scripts) can point it at an attacker-crafted YAML file containing a gadget chain. With Ruby < 3.1 (where Psych 4.0 was not the default), `YAML.load("--- !ruby/object:Gem::Installer ...")` executes shell commands at object initialization. The commonly used `Gem::Installer` + `ERB` chains achieve OS command execution in ≤3 YAML nodes. With Ruby >= 3.1, the risk is lower (Psych 4.0 defaults to safe_load) but `YAML.load` still bypasses Psych's permitted_classes guard — any object with a dangerous `initialize` method is exploitable.

**Trigger:** Operator runs sticky_elephant pointing at a world-writable or attacker-supplied config path; honeypot process executes attacker-controlled Ruby at startup.

---

### C2 — handler/handshake.rb — Authentication bypass; all passwords accepted unconditionally

```ruby
def authenticate(password)
  send_authentication_ok
end
```

`AuthenticationOk` is sent without verifying the supplied password against any expected credential. There is no `config.password` comparison, no bcrypt check, no SCRAM challenge. Every client — including malformed or empty passwords — receives `AuthenticationOk`. The honeypot cannot distinguish attackers from legitimate clients, collects no password signal, and advertises itself as zero-auth to any tool that re-attempts with an invalid password after rejection.

---

### C3 — handler/handshake.rb — Infinite retry loop on EOFError; half-open connections exhaust threads

```ruby
loop do
  begin
    data = @io.readpartial(1024**2)
  rescue EOFError
    retry
  end
end
```

On the client closing its write side (TCP FIN), `readpartial` raises `EOFError` on every subsequent call. The rescue catches it and `retry` immediately calls `readpartial` again — a 100% CPU tight loop per connection. No sleep, no exit condition, no close of `@io`, no break. Combined with `Thread.start` per connection in `server.rb` (no thread pool), this creates an unbounded CPU and memory drain: N half-closed connections = N threads each spinning 100% on a core.

---

## HIGH

### H1 — configuration.rb:16 — `rescue NameError` without binding; always raises NameError

```ruby
rescue
  raise "no config file found"
```

In a separate handler block: `rescue => e` is missing the binding. In older Ruby versions this was a `NameError` on the unbound `e` reference. In current Ruby the block succeeds, but the pattern obscures the original exception and prevents logging the actual cause (file not found, YAML parse error, permission denied). Any deployment error silently becomes "no config file found."

---

### H2 — connection.rb — `readpartial(1024**2)` = 1 MB per connection; no deadline

```ruby
data = @io.readpartial(1024**2)
```

1 MB buffer allocated per read call with no `IO.select` timeout or `read_nonblock` guard. The call blocks indefinitely if the client sends no data (slow-loris). Multiplied by Thread.start per accept: N slow connections = N threads blocked in kernel, consuming 1 MB of buffer space each.

---

### H3 — server.rb — Unbounded `Thread.start` on every `accept`; thread exhaustion DoS

```ruby
loop do
  client = @server.accept
  Thread.start(client) { |c| Connection.new(c).handle }
end
```

No thread pool, no semaphore, no `max_connections`. Thread creation is O(N) with connection count. Default Ruby thread stack is ~2 MB per thread. At 512 connections: ~1 GB stack space + 512 stacks blocked in `readpartial`. OS thread limit (ulimit -u) applies; exhaustion terminates the process.

---

### H4 — postgres_simulator.rb — Hardcoded `pid=666` in BackendKeyData

```ruby
send_backend_key_data(666, rand(2**32))
```

Real PostgreSQL sends the actual OS process ID of the backend process. `666` is a static constant visible on every connection. A Shodan-indexed banner capture, nmap probe output, or attacker noting the exact PID value across two sessions immediately identifies sticky_elephant. `rand(2**32)` for the cancellation secret uses Ruby's default PRNG — seeded once at process start, predictable with timing or via measuring the sequence.

---

### H5 — postgres_simulator.rb — Static version string and fixture rows; single-query fingerprint

```ruby
"PostgreSQL 9.5.5 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2, 64-bit"
```

Verbatim version string hardcoded. PostgreSQL 9.5.5 went EOL in February 2021. The fixture query result for any `SELECT` returns rows with `name:'Perl'`, `breed:'dromedary'` — nonsensical data returned for any query regardless of table or column name. A single `SELECT 1` or `SELECT version()` exposes both.

---

### H6 — log_interface.rb — Log injection via unescaped attacker-controlled content

```ruby
self.logger.info "#{msg}"
```

`msg` at call sites includes the raw username, password, and SQL query text from the wire. Attacker sends username `\nadmin logged in as superuser\n` — the injected string appears as a real log line. Logger is Rails-style without escaping. No `\n` or `\r` stripping at any log call site.

---

### H7 — sticky_elephant.conf.sample — Default hpfeeds secret in plaintext

```yaml
hpfeeds:
  secret: woofwoofcharlesisagooddog
```

Shipped in the repo. Operators who deploy from the sample without changing the secret authenticate to hpfeeds brokers with a public credential. Any operator on the same broker network with the ident/secret can receive the same event stream. hpfeeds uses plaintext TCP — credential transmitted unencrypted on every connect.

---

## MEDIUM

### M1 — payload.rb — OOM risk on length-prefixed read before allocation guard

```ruby
length = bytes[0, 4].unpack('N').first
body = bytes[4, length]
```

`length` is a 32-bit unsigned integer from wire data. No cap before `bytes[4, length]` allocation. An attacker sends `\xFF\xFF\xFF\xFF` as the 4-byte length prefix: `body` attempts to slice `bytes[4, 4294967295]` — Ruby allocates up to `bytes.size - 4` bytes (no exception if shorter), but with a filled 1 MB `readpartial` buffer this is silent; with a 1 MB body followed by the 4 GB length claim, Ruby silently returns a shorter slice. The guard should be before allocation, not after.

---

### M2 — payload.rb — `bytes.first.chr` on nil crashes silently on empty payload

```ruby
bytes.first.chr
```

`bytes.first` returns `nil` when `bytes` is empty (e.g., client closes after the startup frame). `.chr` on `nil` raises `NoMethodError`. No rescue at this call site — propagates up to the `Thread.start` block, which logs and exits the thread silently. The connection appears to close normally from the operator's perspective; no error is surfaced.

---

### M3 — postgres_simulator.rb — Static `config_file` path in `SHOW config_file`

```ruby
"/etc/postgresql/9.5/main/postgresql.conf"
```

Returned for `SHOW config_file`. The version-pinned path (`9.5`) is inconsistent with any operator's actual PostgreSQL installation version and is a secondary static fingerprint confirming the simulated environment.

---

### M4 — handler/handshake.rb — Protocol phase transitions not enforced; query path reachable from startup

No state machine enforces the Postgres startup sequence (startup → auth → ready). After `send_authentication_ok`, the code immediately calls the query handler. An attacker can skip the startup handshake entirely on a reconnect and attempt to send a query packet — behavior diverges from real PostgreSQL (which enforces the startup sequence) and may trigger undefined behavior in the query parser.

---

### M5 — postgres_simulator.rb — All SELECT queries return identical fixture rows; schema-agnostic response

```ruby
def simulate_query(query)
  send_data_row([name: 'Perl', breed: 'dromedary'])
end
```

No query parsing. Any SELECT (or any non-SELECT) triggers the same fixture row response. `SELECT 1` returns `name=Perl, breed=dromedary` — a behavior-level fingerprint detectable with a single query.

---

### M6 — server.rb — No SSL/TLS support; client SSL request packet crashes the server

PostgreSQL wire protocol begins with an optional SSLRequest packet (byte sequence `\x00\x00\x00\x08\x04\xd2\x16\x2f`). sticky_elephant has no handler for it and no rejection response (`N`). Any client with `sslmode=require` (Rails default in production, Heroku deployments) sends this packet first. The handshake handler receives an unexpected 8-byte packet and misroutes it as a startup message, producing protocol desynchronization.

---

## LOW

- **handler/handshake.rb** — `rescue EOFError; retry` without a counter — no way to distinguish a briefly-disconnected legitimate client from a half-closed attacker connection; retry is unconditional and infinite.
- **postgres_simulator.rb** — `RowDescription` returns fixed column types (`text`) for every query; psycopg2, JDBC, and node-postgres enforce type coercion — mismatched declared types cause client-side exceptions that expose the honeypot to automated scanners doing response validation.
- **connection.rb** — `@io.readpartial(1024**2)` returns partial data without checking if a complete Postgres message has arrived; partial message frames are passed to the parser without buffering or length-prefix validation.
- **configuration.rb** — No schema validation on the loaded YAML; missing keys cause `NoMethodError` at runtime rather than at startup, surfacing only when the missing code path is triggered by an attacker action.
- **Gemfile** — No pinned gem versions (`gem 'fakeredis'` with no version constraint); dependency resolution at install time pulls the latest version, which may be incompatible with Python 2 runtime assumptions in the supporting scripts.

---

## INFO

- **README.md** — Documents the honeypot as capturing `passwords`, `queries`, and `IPs` but does not disclose that passwords are never verified (C2); operators may believe the auth bypass is intentional when it is a defect.
- **sticky_elephant.conf.sample** — hpfeeds `ident` default is `"sticky_elephant"` — verbatim match to the tool name; searchable in hpfeeds broker logs to identify all deployments sharing the same ident string.
- **postgres_simulator.rb** — The Ruby process itself is single-threaded within each connection handler (GIL applies); the `Thread.start` concurrency model does not achieve true parallelism, making CPU exhaustion from C3 worse than it would be in a native threading model.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| BackendKeyData `pid=666` | Startup sequence | Definitive |
| `SELECT 1` → row `name=Perl, breed=dromedary` | Post-auth query | Definitive |
| `SHOW config_file` → `/etc/postgresql/9.5/main/postgresql.conf` | Post-auth query | Very High |
| Version string `PostgreSQL 9.5.5 on x86_64-pc-linux-gnu...gcc 4.8.2-19ubuntu1` | `SELECT version()` or startup | Definitive |
| `AUTH wrongpassword` → `AuthenticationOk` | Auth probe | Definitive |
| SSLRequest → no `N` response (desync) | SSL probe | High |
| EOFError loop → CPU spike on half-close | Network behavior | High |

**Minimum detection sequence (2 commands):**
1. Startup → BackendKeyData with `pid=666` → confirmed sticky_elephant
2. `SELECT 1` → fixture rows → confirmed (no real PostgreSQL returns these)

**Zero-auth confirmation:**
1. Startup with `password=wrongpassword12345` → AuthenticationOk → confirmed universal bypass
