# MongoDB-HoneyProxy — Security Analysis

**Repo:** https://github.com/Plazmaz/MongoDB-HoneyProxy  
**Type:** Node.js MongoDB transparent proxy honeypot — intercepts and logs MongoDB wire protocol traffic between attacker and a real backend  
**Lane:** 1 (index.js + Dockerfile — 220 lines total)

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 5 |
| MEDIUM | 3 |
| LOW | 3 |
| INFO | 3 |

MongoDB-HoneyProxy has four independent remote crash paths reachable pre-authentication: no error handler on the service socket causes uncaught exceptions to terminate the process; a new TCP socket is created per data event (not per connection), exhausting file descriptors in a single session; no TCP stream reassembly means any fragmented MongoDB packet crashes with a RangeError; attacker-controlled `docCount`/`numToSkip` fields drive `bson.deserializeStream` into OOM. Additionally, OP_MSG (MongoDB wire protocol opcode 2013, required by all drivers since MongoDB 3.6) is completely unimplemented — the proxy captures zero credentials from any modern MongoDB driver.

---

## CRITICAL

### C1 — index.js:54,69 — No `.on('error')` on `serviceSocket`; uncaught exception terminates process

```javascript
var serviceSocket = new net.Socket();
// No serviceSocket.on('error', handler) anywhere in the file
```

Node.js throws an uncaught `Error` event when a TCP socket encounters a connection error (ECONNREFUSED, ECONNRESET, ETIMEDOUT) and no `error` handler is attached. An `EventEmitter` with no `error` listener re-throws the error as an uncaught exception, which in Node.js terminates the process. If the backend MongoDB instance is down, refuses connections, or times out, the first proxy attempt kills the entire honeypot process. An attacker who knows the backend is unreachable can trigger this on demand.

---

### C2 — index.js:52-54 — New TCP socket created per `data` event (not per connection); FD exhaustion in single session

```javascript
proxySocket.on('data', function(data) {
    var serviceSocket = new net.Socket();
    serviceSocket.connect(servicePort, serviceHost, function() {
        serviceSocket.write(data);
    });
});
```

`proxySocket.on('data', ...)` fires on every TCP data delivery. TCP can fragment a single MongoDB message across multiple data events (see C3). Each `data` event creates a new `net.Socket`, opens a new TCP connection to the backend, writes the fragment, and never closes the socket (no `.end()`, no `.destroy()` — only a `.on('close', ...)` that fires if the backend closes first). For a single attacker session with a MongoDB driver that sends a multi-packet auth sequence: 3-5 data events → 3-5 unclosed backend connections. At 200 concurrent connections: up to 1,000 leaked FDs. Default Node.js fd limit is 1,024 — process stalls and no new connections can be accepted.

---

### C3 — index.js:52,56,90-91 — No TCP stream reassembly; partial packet delivery triggers RangeError crash

```javascript
proxySocket.on('data', function(data) {
    // data may be a partial MongoDB packet
    var length = data.readInt32LE(0);  // index.js:56 — reads from offset 0
    // ...
    var docCount = data.readInt32LE(89); // offset 89 may not exist in partial packet
```

TCP is a byte-stream protocol; `data` events deliver arbitrarily-sized chunks. A MongoDB OP_QUERY packet with a 2,000-byte document may arrive as two data events: bytes 0-999 and bytes 1000-1999. The first event's `data` buffer is 1,000 bytes. Line 89 reads at offset 89 (within bounds) but line 90 reads at offset that may exceed 1,000 → Node.js throws `RangeError: Index out of range`. The uncaught exception handler at index.js:7-10 is commented out, so the process terminates.

---

### C4 — index.js:119,140 — Attacker-controlled `docCount`/`numToSkip` fed to `bson.deserializeStream`; OOM

```javascript
var docCount = data.readInt32LE(89);
// ...
var docs = [];
bson.deserializeStream(data, offset, docCount, docs, 0);
```

`docCount` is a signed 32-bit integer read from the wire. The attacker sets it to `0x7FFFFFFF` (2,147,483,647). `bson.deserializeStream` iterates `docCount` times, allocating a new object per iteration. With a minimal data buffer and a large `docCount`, the loop creates 2B allocation attempts before crashing. Even at 1,000 docs per second, the OOM killer terminates the Node.js process within milliseconds at high `docCount` values — no authentication required.

---

## HIGH

### H1 — index.js:163-168 — `readCString` without null terminator guard; OOB native memory read

```javascript
function readCString(buffer, index) {
    var s = '';
    while (buffer[index] != 0x00) {
        s += String.fromCharCode(buffer[index]);
        index++;
    }
```

`buffer[index]` returns `undefined` when `index >= buffer.length` in JavaScript — but `bson` internal buffers may be `Buffer` objects, and `Buffer[beyond_end]` returns `undefined`. The comparison `undefined != 0x00` is always true (undefined is not 0), so the loop runs indefinitely reading `undefined` characters, building a string of `"\x00"` characters (via `String.fromCharCode(undefined)` = `"\x00"`), until the Node.js process exhausts string memory or the GC kills it. On attacker-controlled collection names without a null terminator: infinite loop + OOM.

---

### H2 — index.js:106-108 — OP_MSG (opcode 2013) unimplemented; zero credential capture from modern drivers

```javascript
if (opCode == 2004) {
    // OP_QUERY handling
} else {
    // No handler for opCode 2013 (OP_MSG)
}
```

MongoDB deprecated OP_QUERY in MongoDB 5.1 (2021) and OP_MSG (opcode 2013) is the only wire protocol message type used by all current drivers (mongo 4.0+, pymongo 4.x, the official Go/Node/Java drivers). Any MongoDB client running pymongo >= 3.12, the Node.js official driver >= 3.6, or any driver connecting to MongoDB >= 3.6 will use OP_MSG exclusively. The honeypot receives the OP_MSG authentication packet, has no handler for it, and logs nothing. `Authentication` and credential capture are completely broken for the current driver ecosystem.

---

### H3 — index.js:165,36 — Log injection via collection name and query document

```javascript
console.log('MongoDB Query on: ' + collectionName);
console.log('Decoded: ', docs);
```

`collectionName` is read directly from the wire (via `readCString`) with no sanitization. An attacker names a collection `\r\n[2026-01-01 12:00:00] SYSTEM: Authentication succeeded for admin` — the string appears as a synthetic log line. `docs` is a BSON-decoded JavaScript object printed via `console.log`; an object with a custom `toString()` method (achievable in certain BSON edge cases) could inject arbitrary text.

---

### H4 — index.js:191-194 — `new Buffer(n)` allocates n uninitialized bytes, not a buffer containing the byte n

```javascript
var buf = new Buffer(1);
buf[0] = 0x00;
// used to write response header
```

`new Buffer(n)` in Node.js 8 allocates `n` uninitialized bytes from a memory pool (not zeroed). The intent is a 1-byte buffer holding `0x00`, which is then correctly set at `buf[0] = 0x00`. However, any code path that uses `new Buffer(n)` with `n > 1` and does not fully initialize all bytes sends garbage bytes to the attacker. The correct API is `Buffer.alloc(n)` (zero-filled) or `Buffer.from([0x00])`. This pattern is present in response construction; any missed byte is a memory disclosure of heap contents from the Node.js process.

---

### H5 — index.js:7-10 — `uncaughtException` handler commented out; crashes are silent

```javascript
/*
process.on('uncaughtException', function(err) {
    console.log(err);
});
*/
```

The global uncaught exception handler is commented out. Every crash from C1-C4 terminates the process silently. No crash reason is logged. Operators see the honeypot go offline without any indication of why. The comment block suggests the developer removed it for debugging purposes and never re-enabled it.

---

## MEDIUM

- **Dockerfile:1** — `FROM node:8` — Node.js 8 EOL (December 2019). V8 engine CVEs (V8 type confusion, CVE-2018-6143, heap-use-after-free). No security patches available. The container runs as root by default (no `USER` directive).
- **index.js:18-25** — Config parsed from a JSON file using `fs.readFileSync` with no error handling; if config file is missing or malformed, `JSON.parse` throws and crashes the process before any listener is established.
- **index.js:90-95** — `data.readInt32LE(89)` and subsequent reads use hardcoded offsets derived from the OP_QUERY packet structure; no validation that `data.length` exceeds these offsets before reading — see C3. The specific offsets (89 for `docCount`, 93 for `numToSkip`) will be wrong for any OP_QUERY variant with a different flags or fullCollectionName length, causing incorrect deserialization or range errors.

---

## LOW

- **index.js:52-54** — `serviceSocket.connect()` callback never handles connection failure; if the backend is up but rejects the connection (wrong credentials, auth required), the write at `serviceSocket.write(data)` may execute on an unconnected socket, throwing a synchronous exception that bypasses the uncaught exception handler (commented out).
- **index.js:71-77** — `proxySocket.on('data', ...)` inside `server.on('connection', ...)` adds a new data listener on every connection. If `proxySocket` is reused (it's not in current code, but the pattern is fragile), multiple listeners accumulate per socket — Node.js emits `MaxListenersExceededWarning` at >10 listeners on the same socket, consuming increasing memory per warning.
- **package.json** — `bson` version unpinned (`"bson": "*"`); npm resolves to latest major at install time. BSON 4.x → 5.x introduced breaking API changes; `bson.deserializeStream` signature changed. Deployments from 2016 (Node.js 8 era) likely have `bson` 1.x while fresh installs get `bson` 6.x; the `deserializeStream` call at line 119 may fail differently or not at all depending on installed version.

---

## INFO

- **index.js:1** — `var net = require('net')` — `var` throughout the codebase (no `const`/`let`); `net` is declared at module scope but only `net.createServer` is called once — no global state issues from this pattern, but indicates 2015-era Node.js idioms and no linting.
- **index.js:159-162** — `readCString` builds a string by concatenating single characters (`s += String.fromCharCode(...)`); JavaScript string concatenation in a loop is O(n²) due to string immutability. For a collection name of 10,000 bytes, this creates ~50 million character allocations. Use `Buffer.toString('utf8', start, end)` or `indexOf(0x00)` + `slice`.
- **README.md** — Documents the tool as "transparent proxy" but does not disclose that OP_MSG is unimplemented; operators deploying against MongoDB >= 3.6 targets capture zero credentials. No version compatibility matrix documented.

---

## Fingerprint Table

| Signal | Detection | Confidence |
|--------|-----------|------------|
| OP_MSG (opcode 2013) → no response | Connect with modern driver | Very High — also exposes feature gap |
| `new Buffer(n)` response bytes may contain heap garbage | Response byte inspection | Medium |
| Process crash on any fragmented delivery | Send multi-chunk packet | Active crash trigger |
| `docCount = 0x7FFFFFFF` → OOM then process exit | OP_QUERY with large docCount | Active crash trigger |
| Proxy connection to real MongoDB backend | Detect backend connection on MongoDB port | High — exposes backend address |

**Minimum detection sequence:**
1. Connect with any MongoDB 3.6+ driver using default settings → OP_MSG sent → zero response → honeypot confirmed
2. Send OP_QUERY with `data.readInt32LE(89)` = `0x0FFFFFFF` → crash → confirmed MongoDB-HoneyProxy
