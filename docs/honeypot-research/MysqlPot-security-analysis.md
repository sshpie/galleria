# MysqlPot — Security Analysis

**Repo:** https://github.com/schmalle/MysqlPot  
**Type:** C# MySQL honeypot — MySQL wire protocol server capturing credentials; optional EWS (Exchange Web Services) alerting  
**Lanes:** 2 (Server.cs/Mysql.cs/MysqlDefs.cs/Main.cs · EWSSender.cs/Database.cs/Logger.cs)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 6 |
| MEDIUM | 6 |
| LOW | 4 |
| INFO | 4 |

MysqlPot's listener is single-threaded with no timeout — one slow connection permanently blocks all subsequent connections. The EWS alert module has process-wide SSL certificate verification disabled (global bypass via `ServicePointManager.ServerCertificateValidationCallback`), XML injection via raw string concatenation of attacker-supplied fields, and the EWS authentication token is printed to stdout at startup and again on every alert. The scramble (`BBBBBBBBBBBB` = all 0x42 bytes) is a definitive static fingerprint identifying MysqlPot on any MySQL challenge-response capture.

---

## CRITICAL

### C1 — Server.cs:159-177 — Single-threaded listener with no timeout; one connection = total DoS

```csharp
TcpListener server = new TcpListener(IPAddress.Any, port);
server.Start();
while (true)
{
    TcpClient client = server.AcceptTcpClient();
    byte[] dataIn = new byte[2048];
    int bytesRead = client.GetStream().Read(dataIn, 0, 2048);
    // ... synchronous processing
    client.Close();
}
```

`AcceptTcpClient()` and `GetStream().Read()` are fully synchronous. The loop accepts one connection, reads from it, processes it, and only then calls `AcceptTcpClient()` again. `GetStream().Read()` with no `ReadTimeout` blocks indefinitely. An attacker opens a TCP connection and sends no data — the main loop never returns from `Read()`, and all subsequent connection attempts queue in the OS backlog (default 100 on Windows). After the backlog fills, new connection attempts are refused at the TCP layer. The honeypot captures zero credentials while the blocking connection is held.

---

### C2 — EWSSender.cs:79 — Process-wide SSL certificate verification bypass

```csharp
ServicePointManager.ServerCertificateValidationCallback =
    delegate { return true; };
```

`ServicePointManager.ServerCertificateValidationCallback` is a process-global setting in .NET Framework. After `EWSSender.Initialize()` runs, every subsequent TLS connection made by the process — including any future library that uses HttpWebRequest — skips certificate validation. An attacker positioned to MITM the EWS connection receives the full alert payload (including attacker IP, credentials, attack classification, and the EWS authentication token) without presenting a valid certificate.

---

### C3 — EWSSender.cs:48,53,62 — XML injection via raw string concatenation; EWS SOAP body corruption

```csharp
string xml = "..." +
    "<t:Subject>" + ident + attackType + " from " + req + "</t:Subject>" +
    "<t:Body>" + ip + "</t:Body>" + ...
```

`ip`, `req`, `attackType`, and `ident` are all attacker-supplied strings inserted into a SOAP XML template via direct concatenation with no encoding. An attacker's source IP cannot be controlled (it's the actual TCP source), but `req` (captured request string) and `attackType` (derived from classifier logic that may be influenced by the packet content) can contain `<`, `>`, `&`, and `"` characters. Injecting `</t:Subject><t:HasAttachments>true</t:HasAttachments><t:Subject>` within the request field corrupts the SOAP XML structure, bypassing operator EWS filtering rules, causing schema validation failures on the Exchange side, or injecting false metadata into alert emails.

---

## HIGH

### H1 — Mysql.cs:240 — `handleLoginPacket` writes 0x0 into shared `dataIn[]` at fixed offset; buffer mutation

```csharp
dataIn[32] = 0x0;
```

`handleLoginPacket` takes the shared `dataIn` byte array (2048 bytes, allocated per connection in `Server.cs`) and writes a null byte at position 32. This is intended to null-terminate the username field for subsequent `ReadAnsiString` parsing. However, `dataIn` is the original receive buffer. If any other field crosses position 32 (e.g., a username shorter than 32 bytes followed immediately by the auth response), this mutation corrupts adjacent protocol fields before they are parsed. The write is unconditional regardless of packet content.

---

### H2 — Mysql.cs:223-253 — All credentials accepted unconditionally

```csharp
private static byte[] generateOKPacket(uint seq)
{
    return new byte[] { 0x07, 0x00, 0x00, seq, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
}
// called unconditionally at end of handleLoginPacket
```

No password verification against any expected credential. Every login attempt receives `OK`. The honeypot captures attacker credentials but advertises zero-auth behavior — any tool that retries with an invalid credential and receives `OK` identifies the endpoint as a honeypot or misconfigured server, not a real MySQL instance.

---

### H3 — Main.cs:78 + EWSSender.cs:31-32 — EWS authentication token printed to stdout and on every alert

```csharp
Console.WriteLine("Init: " + Config.ServerPostAlertsUsername + ":" +
    Config.ServerPostAlertsPassword);
// ...
Console.WriteLine("Sending alert: [" + username + ":" + password + "] ...");
```

The EWS domain/username/password token is printed to stdout at startup. On every subsequent alert, the full token is re-printed via the `Sending alert` line (though the password is not in that specific line, the startup print exposes it). Any log aggregation system receiving stdout from the MysqlPot process captures these credentials in plaintext.

---

### H4 — Server.cs:133 + doSetup() — Socket handle leak; `EADDRINUSE` on restart without port release

```csharp
TcpListener server = new TcpListener(IPAddress.Any, port);
server.Start();
```

No `server.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true)` call. On .NET Framework, `TcpListener` does not set `SO_REUSEADDR` by default. After abnormal termination (exception, kill), the OS holds the port in `TIME_WAIT` for up to 240 seconds. Restarting MysqlPot within that window fails with `EADDRINUSE` — the honeypot goes offline after every crash until the OS releases the port.

---

### H5 — Mysql.cs:127-141 — `copyBytes()` has no destination bounds check; potential buffer overrun

```csharp
static void copyBytes(byte[] src, int srcOffset, byte[] dest, int destOffset, int num)
{
    for (int i = 0; i < num; i++)
        dest[destOffset + i] = src[srcOffset + i];
```

No check that `destOffset + num <= dest.Length`. Call sites in `generateHandshakePacket` use hardcoded offsets and lengths that are correct for the fixed-size scramble and version strings. However, `generateGreeting()` passes `serverVersion` (a configurable string) with no length guard — if `serverVersion` exceeds the space remaining in the greeting packet byte array, the loop writes past `dest` into adjacent memory. .NET's bounds checker will throw `IndexOutOfRangeException` rather than silently overwrite, but the exception terminates the connection handler.

---

### H6 — EWSSender.cs:83 — Hardcoded EWS endpoint URL ignores `Config.ServerPostAlertsURL`

```csharp
string url = "https://hardcoded-exchange-server/EWS/Exchange.asmx";
```

The config file has a `ServerPostAlertsURL` setting that is parsed and stored in `Config` but never consulted in `EWSSender.Send()`. The hardcoded URL is a developer's own Exchange endpoint. Operators deploying the tool see no EWS alerts because the hardcoded URL is unreachable from their environment; they may assume EWS alerting works when it silently fails.

---

## MEDIUM

- **Main.cs:52** — Log file path taken directly from `argv[1]` with no sanitization; a path containing `..` or pointing to a system file causes the logger to write to arbitrary locations (though `Logger.cs` is an empty stub, so no current-code impact — future fill-in inherits this risk).
- **MysqlDefs.cs** — `SCRAMBLE_LENGTH = 8` (single-byte header + 8 challenge bytes); MySQL native auth uses 20 bytes (8 + 12 split across two message parts); the short scramble is detectable at the wire level.
- **Mysql.cs:89-91** — `ReadAnsiString` uses `IndexOf(0, offset)` without an upper bound; a malformed packet with no null terminator causes `IndexOf` to return -1, then `Substring(-1)` throws `ArgumentOutOfRangeException`.
- **Server.cs** — No per-connection rate limiting or IP-based throttling; the single-threaded listener serializes all connections but an attacker can still flood the OS backlog, denying service to other scanners.
- **Database.cs** — Empty stub class; no credential storage; all captured credentials are lost on process restart. Operators believe the honeypot is logging to a database when it captures nothing persistently.
- **Logger.cs** — Empty stub class; `Console.WriteLine` is the only logging mechanism; no file logging despite Main.cs accepting a log path argument.

---

## LOW

- **Main.cs:147** — Default log path `"/Users/flake/mysqlpot.log"` (developer's macOS home directory) exposed in the binary; path leaks the developer's username and platform.
- **Mysql.cs:36-40** — MySQL handshake sends `server_version` as null-terminated; version string is hardcoded to `"5.5.20-log"` — EOL version (2012); `5.5.20-log` is the binary log suffix variant, an unusual combination for a public-facing server.
- **Main.cs:108-111** — `Console.WriteLine("New connection from " + client.Client.RemoteEndPoint)` — IPv6 `RemoteEndPoint.ToString()` format includes brackets (e.g., `[::1]:12345`); no address parsing; log analysis tools parsing this output may split on `:` and misidentify port.
- **Mysql.cs:200-210** — Sequence number (`seq`) is passed as `uint` but the MySQL packet sequence field is 1 byte (0-255); `(byte)seq` is used in the OK packet but `seq + 1` arithmetic in caller code is `uint` — carries correctly for sequences 0-254 but wraps correctly on overflow because the cast to byte occurs at the assignment site.

---

## INFO

- **MysqlDefs.cs** — `SCRAMBLE = "BBBBBBBBBBBB"` (12 bytes of 0x42); in the handshake, this appears in the auth-plugin-data field. Any MySQL traffic capture or honeypot scanner that checks the challenge bytes for the string `0x42 × 12` identifies MysqlPot definitively. This value is indexed by any IDS with a MySQL fingerprint ruleset.
- **EWSSender.cs:33** — `Console.WriteLine("Alert sent!")` printed on success, `Console.WriteLine("EXCEPTION: " + e.Message)` on failure; combined with stdout credential logging, any log scraper sees the full alert life cycle including failures.
- **Server.cs** — No graceful shutdown; `TcpListener.Stop()` is never called; the listening socket is not released on `Ctrl-C`; the OS binds the port for TIME_WAIT duration after each kill.
- **Mysql.cs:97-100** — `ReadUInt16`/`ReadUInt32` methods read from the shared `dataIn` buffer using arithmetic shifts without checking remaining bytes; `handleLoginPacket` may call these past the end of a truncated packet, producing incorrect values silently (no bounds check, no exception — reads zero-padded bytes beyond `bytesRead`).

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| Auth challenge bytes all `0x42` (`BBBBBBBBBBBB`) | MySQL handshake capture | Definitive |
| Server version `5.5.20-log` | Handshake ServerVersion field | Very High |
| `AUTH wrongpassword` → OK response | Auth probe | Definitive |
| Server capabilities exactly match MysqlDefs.cs constants | Handshake capabilities bitmask | Very High |
| Scramble length 8 (not 20) in handshake | Wire-level inspection | Very High |
| Single active connection blocks all others | Timing probe (two simultaneous connections) | High |

**Minimum detection sequence (1 packet):**
1. Connect → HandshakeV10 with challenge bytes `42 42 42 42 42 42 42 42` (`BBBBBBBB`) → confirmed MysqlPot
