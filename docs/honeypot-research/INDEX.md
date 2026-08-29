# Honeypot Research — Source Analysis Index

Static source analysis across 29 honeypot frameworks. Each file covers 5 parallel audit lanes. Findings from these analyses are the direct source of galleria's fingerprint signatures — see [`../ARCHITECTURE.md`](../ARCHITECTURE.md) for the mapping from finding to detection probe.

| File | Honeypot | Type | CRIT | HIGH | MED | LOW | Key galleria signal |
|------|----------|------|------|------|-----|-----|---------------------|
| [amun-security-analysis.md](amun-security-analysis.md) | Amun | Windows exploit emulator | - | - | - | - | Lotus Domino IMAP banner; POP3 wrong greeting code; VNC trailing `\n` absent |
| [canarytokens-security-analysis.md](canarytokens-security-analysis.md) | Canarytokens | Tripwire tokens | 2 | 9 | 22 | 10 | MCP JWE default key; kubeconfig cluster name always `k8s-prod-cluster` |
| [cloud-active-defense-security-analysis.md](cloud-active-defense-security-analysis.md) | SAP Cloud Active Defense | Kubernetes deception | - | - | - | - | Keycloak fingerprint + clone-app HTTP markers |
| [conpot-security-analysis.md](conpot-security-analysis.md) | Conpot | ICS/SCADA | 6 | 18 | 10 | 7 | `sysLocation="Venus"`; Guardian AST `"STATOIL STATION"`; Modbus FC17 stub; COTP 0x62 strip |
| [cowrie-security-analysis.md](cowrie-security-analysis.md) | Cowrie | SSH/Telnet | 0 | 8 | 10 | 12 | `OpenSSH_6.0p1 Debian-4+deb7u2`; KEXINIT null padding; HASSH mismatch |
| [dionaea-security-analysis.md](dionaea-security-analysis.md) | Dionaea | Multi-protocol malware trap | 10 | 25 | 24 | 14 | Memcache SET→GET state loss; MQTT CONNACK 0x00 unconditional; SIP nonce `foobar123` |
| [elastichoney-security-analysis.md](elastichoney-security-analysis.md) | elastichoney | Fake Elasticsearch | 3 | 5 | 4 | 3 | Hardcoded node UUID + MAC + build hash |
| [elasticpot-security-analysis.md](elasticpot-security-analysis.md) | elasticpot | Fake Elasticsearch | - | - | - | - | Same hardcoded node UUID as elastichoney (`Green Goblin` config) |
| [EoHoneypotBundle-security-analysis.md](EoHoneypotBundle-security-analysis.md) | EoHoneypotBundle | Hidden form fields (Laravel) | - | - | - | - | HTTP body markers; honeypot field naming conventions |
| [express-honeypot-security-analysis.md](express-honeypot-security-analysis.md) | express-honeypot | Fake PHP LFI/RFI | - | - | - | - | PHP error page fingerprint on LFI probe |
| [FCaptcha-security-analysis.md](FCaptcha-security-analysis.md) | FCaptcha | Bot-detection CAPTCHA | - | - | - | - | CAPTCHA challenge response structure on port 3000 |
| [ghh-security-analysis.md](ghh-security-analysis.md) | GHH | Fake PHP shell | - | - | - | - | Static PHP shell UI markers on dork paths |
| [glastopf-security-analysis.md](glastopf-security-analysis.md) | Glastopf | Fake PHP web app | 6 | 11 | 14 | 12 | 200 on any path; decoy path + malformed verb floor detection |
| [hellpot-security-analysis.md](hellpot-security-analysis.md) | HellPot | Infinite page tarpit | - | - | - | - | Absent/absurd Content-Length; unbounded transfer |
| [honeyd-security-analysis.md](honeyd-security-analysis.md) | Honeyd | Network emulator (C) | 8 | 22 | 14 | 9 | FTP `SYST` returns `Windows_NT` on non-Windows; UNIX socket Python eval |
| [honeypot-msurguy-security-analysis.md](honeypot-msurguy-security-analysis.md) | msurguy/Honeypot | Hidden Laravel form fields | - | - | - | - | Honeypot form field naming pattern |
| [kippo-security-analysis.md](kippo-security-analysis.md) | Kippo | SSH trap | 4 | 15 | 18 | 6 | Same SSH version/HASSH as Cowrie lineage; interact console all-interface no-auth |
| [krawl-security-analysis.md](krawl-security-analysis.md) | Krawl | Fake login pages | - | - | - | - | Login page structure markers; credential capture endpoint |
| [lophiid-security-analysis.md](lophiid-security-analysis.md) | Lophiid | LLM-powered distributed | 10 | 19 | 11 | 7 | goja JS engine response structure; `SendStatus` unauthenticated (documented) |
| [MongoDB-HoneyProxy-security-analysis.md](MongoDB-HoneyProxy-security-analysis.md) | MongoDB-HoneyProxy | Fake MongoDB | - | - | - | - | No OP_MSG handler; drops message; real MongoDB responds |
| [mysql-honeypotd-security-analysis.md](mysql-honeypotd-security-analysis.md) | mysql-honeypotd | Fake MySQL | - | - | - | - | `thread_id` starts at 0, increments sequentially |
| [MysqlPot-security-analysis.md](MysqlPot-security-analysis.md) | MysqlPot | Fake MySQL (C#) | 3 | 6 | 6 | 4 | Auth scramble always `BBBBBBBBBBBB` (0x42 * 12) |
| [nodepot-security-analysis.md](nodepot-security-analysis.md) | Nodepot | Fake WordPress (Node) | - | - | - | - | WordPress response markers + Node.js server header |
| [nosqlpot-security-analysis.md](nosqlpot-security-analysis.md) | nosqlpot | Fake Redis + CouchDB | 1 | 4 | 4 | 4 | `AUTH` absent — returns `unknown command 'auth'`; INFO always reports 1 command |
| [opencanary-security-analysis.md](opencanary-security-analysis.md) | OpenCanary | Multi-protocol trap | 4 | 11 | 22 | 18 | MySQL capability bytes `0xff 0xf7 0x08 0x02`; MSSQL `thinkst.com` in NTLM blob |
| [pasithea-security-analysis.md](pasithea-security-analysis.md) | Pasithea | Fake REST API (Java) | - | - | - | - | HTTP 200 + `<h1>404 Not Found</h1>` body on port 8082 |
| [pghoney-security-analysis.md](pghoney-security-analysis.md) | pghoney | Fake PostgreSQL (Go) | 4 | 9 | 8 | 4 | MD5 auth salt identical on every connection |
| [RedisHoneyPot-security-analysis.md](RedisHoneyPot-security-analysis.md) | RedisHoneyPot | Fake Redis | - | - | - | - | Static `run_id`; absent AUTH; RESP type mismatch |
| [sticky_elephant-security-analysis.md](sticky_elephant-security-analysis.md) | sticky_elephant | Fake PostgreSQL (Ruby) | 3 | 7 | 6 | 5 | `pid=666` in ParameterStatus; every password accepted |
