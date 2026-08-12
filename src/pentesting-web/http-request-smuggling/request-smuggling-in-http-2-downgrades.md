# Request Smuggling in HTTP/2 Downgrades

{{#include ../../banners/hacktricks-training.md}}

HTTP/2 is generally considered immune to classic request-smuggling because the length of each DATA frame is explicit. **That protection disappears as soon as a front-end proxy “downgrades” the request to HTTP/1.x before forwarding it to a back-end**. The moment two different parsers (the HTTP/2 front-end and the HTTP/1 back-end) try to agree on where one request ends and the next begins, all the old desync tricks come back – plus a few HTTP/2-only injection gadgets.<sup>[[1]](#references)</sup>

Recent desync research reached the same conclusion from the defensive side: **HTTP/2 at the edge does not save you if the proxy still speaks HTTP/1.1 upstream**. The downgrade boundary is the attack surface.<sup>[[2]](#references)</sup>

---
## Why downgrades happen

1. Browsers already speak HTTP/2, but much legacy origin infrastructure still only understands HTTP/1.1.
2. Reverse-proxies (CDNs, WAFs, load-balancers) therefore terminate TLS + HTTP/2 at the edge and **rewrite every request as HTTP/1.1** for the origin.
3. That translation layer has to emit a single, valid HTTP/1.1 body delimiter for the origin.
4. RFC 9113 is stricter than many downgrade implementations:
   * connection-specific headers such as `transfer-encoding`, `upgrade`, `keep-alive`, or `proxy-connection` make the HTTP/2 message malformed;
   * `te` is only valid as `te: trailers`;
   * if `content-length` is present, it must match the sum of the DATA frame payload lengths.

Whenever the front-end trusts the HTTP/2 frame length **but** the back-end trusts CL or TE, an attacker can force them to disagree.

---
## Two dominant primitive classes

| Variant | Front-end length | Back-end length | Typical payload |
|---------|-----------------|-----------------|-----------------|
| **H2.TE** | HTTP/2 frame | `Transfer-Encoding: chunked` | Embed an extra chunked message body whose final `0\r\n\r\n` is *not* sent, so the back-end waits for the attacker-supplied “next” request. |
| **H2.CL** | HTTP/2 frame | `Content-Length` | Send a *smaller* CL than the real body, or inject `content-length: 0` during downgrade, so the back-end reads past the boundary into the following request. |

> These are identical in spirit to classic TE.CL / CL.TE, just with HTTP/2 replacing one of the parsers.

---
## Identifying a downgrade chain

1. Use **ALPN** in a TLS handshake (`openssl s_client -alpn h2 -connect host:443`) or **curl**:
   ```bash
   curl -v --http2 https://target
   ```
   If `* Using HTTP2` appears, the edge speaks H2.
2. If the site *looks* HTTP/1.1-only, probe for **hidden HTTP/2** anyway:
   ```bash
   curl --http2-prior-knowledge https://target
   ```
   Some stacks support H2 but forget to advertise it via ALPN, which means you would otherwise miss downgrade-only bugs.
3. Send a deliberately malformed CL/TE request *over* HTTP/2 (Burp Repeater can force HTTP/2). If the response is an HTTP/1.1-style error such as `400 Bad chunk` or a back-end-specific parse failure, you have strong evidence that the edge converted the traffic for an HTTP/1 parser downstream.

---
## Exploitation workflow (H2.TE example)

```http
:method: POST
:path: /login
:scheme: https
:authority: example.com
content-length: 13      # ignored by the edge
transfer-encoding: chunked

5;ext=1\r\nHELLO\r\n
0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\nX: X
```
1. The **front-end** reads exactly 13 bytes (`HELLO\r\n0\r\n\r\nGE`), thinks the request is finished and forwards that much to the origin.
2. The **back-end** trusts the TE header, keeps reading until it sees the *second* `0\r\n\r\n`, thereby consuming the prefix of the attacker’s second request (`GET /admin …`).
3. The remainder (`GET /admin …`) is treated as a *new* request queued behind the victim’s.

Replace the smuggled request with:
* `POST /api/logout` to force session fixation
* `GET /users/1234` to steal a victim-specific resource

If you can only poison requests on your **own** client-mapped upstream connection, the bug can still be useful for cache poisoning, internal-header leaks, or front-end control bypass. For those reuse-locked cases, pivot to [HTTP Connection Request Smuggling](../http-connection-request-smuggling.md).

---
## Modern downgrade-only injection gadgets

Many modern front-ends already strip a literal `transfer-encoding: chunked` header. Recent findings often work by **manufacturing dangerous HTTP/1.1 bytes during the downgrade itself** rather than sending them as a normal header.<sup>[[1]](#references)</sup>

### CRLF / LF injection in header values

HTTP/2 field values are binary. If the downgrade code fails to sanitize `\r\n` — or even a bare `\n` — you can often synthesize a backend-only header:

```http
:method: POST
:path: /
:authority: example.com
foo: bar\r\ntransfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: example.com
```

The edge sees a legal-ish HTTP/2 header block; the back-end receives a fresh `Transfer-Encoding` header and starts parsing the body as chunked. The same trick can be used to inject `content-length: 0`, terminate the header section early, or split one downgraded request into two.

### Header-name injection

Some vendors fixed newline injection in **values** but forgot to validate **names**. If the downgrade code accepts spaces, colons, or other non-HTTP/1.1-safe bytes in a header name, the generated HTTP/1.1 request can contain multiple backend-visible header lines. This is a common way to re-introduce `transfer-encoding` after a partial hotfix.

### Pseudo-header / request-line injection

A buggy mapper that copies `:method`, `:path`, `:authority`, or `:scheme` into the HTTP/1.1 request line without strict validation can let you:

* inject a full secondary request line,
* supply an ambiguous host or path,
* prepend a URL prefix that changes routing, cache keys, or SSRF targets.

If a literal `TE` header is blocked but pseudo-headers are not normalized before downgrade, this is the next place to look.

---
## Related but distinct: h2c smuggling (clear-text upgrades)

This is not a CL/TE downgrade bug, but during the same assessment you should also test whether the edge forwards the HTTP/1.1 `Upgrade: h2c` header to a back-end that supports clear-text HTTP/2. If it does, you may be able to tunnel *raw* HTTP/2 frames through an edge that only validated the initial HTTP/1.1 request.

Key requirements:
* Edge forwards **both** `Connection: Upgrade` and `Upgrade: h2c` unchanged.
* Origin upgrades to HTTP/2 and keeps the connection-reuse semantics that enable request queueing or direct internal access.

For proxy-specific quirks and tunnel-focused payloads, see [Upgrade Header Smuggling](../h2c-smuggling.md).

---
## Notable real-world examples

* **2025 desync research** – large shared edge providers were still exploitable because the dangerous trust boundary remained **upstream HTTP/1.1**, not the client-facing HTTP/2 session.<sup>[[2]](#references)</sup>
* **CVE-2023-25690** – Apache HTTP Server `mod_proxy` rewrite rules could be chained into request splitting and smuggling when rewritten bytes were forwarded downstream. (fixed in 2.4.56)
* **CVE-2023-25950** – HAProxy 2.7.0 and 2.6.1-2.6.7 had an HTTP request/response smuggling issue in HTX handling that could alter a legitimate user’s request.
* **CVE-2022-41721** – Go `MaxBytesHandler` left unread body bytes that could later be interpreted as **HTTP/2** frames, showing how “leftover bytes become a new protocol message” is not limited to classic H1 desync.

---
## Tooling

* **Burp Request Smuggler** – since **v3.0 (2025)** it includes parser-discrepancy detection plus HTTP/2 tunnelling / header-injection probes. Enable **HTTP/2 probing** and ALPN override when hunting hidden H2 support.
* [**http2smugl**](https://github.com/neex/http2smugl) – purpose-built H2→H1 detector and raw requester. The `request` subcommand accepts escaped bytes such as `\r`, `\n`, and `\x3a`, which is handy when normal clients refuse malformed headers:
  ```bash
  go install github.com/neex/http2smugl@latest
  http2smugl detect https://target
  ```
* [**SmuggleFuzz**](https://github.com/Moopinger/smugglefuzz) – fast downgrade scanner with customizable gadget lists and an explicit confirm mode:
  ```bash
  go install github.com/moopinger/smugglefuzz@latest
  smugglefuzz scan -u https://target --confirm
  ```
* **h2cSmuggler** – Python PoC by Bishop Fox to automate the clear-text upgrade attack:
  ```bash
  python3 h2csmuggler.py -u https://target -x 'GET /admin HTTP/1.1\r\nHost: target\r\n\r\n'
  ```
* **curl** / **hyper** – useful for quick ALPN checks and for replaying handcrafted HTTP/2 payloads: `curl --http2-prior-knowledge -X POST --data-binary @payload.raw https://target`

---
## Defensive measures

1. **Use upstream HTTP/2 end-to-end whenever possible** – removing the H2→H1 translation step is the cleanest fix.
2. **Enforce RFC 9113 on ingress** – reject HTTP/2 requests carrying connection-specific headers; only allow `te: trailers`; reject mismatched `content-length` values.
3. **Strip and regenerate body-length metadata on downgrade** – never forward attacker-supplied `Content-Length` / `Transfer-Encoding` into the downgraded request.
4. **Normalize before mapping to HTTP/1.1** – reject or canonicalize CR, LF, colon, obs-fold, and non-ASCII bytes in header names, header values, and pseudo-headers *before* routing / rewrite logic.
5. **Reduce or isolate upstream connection reuse** – if you are stuck on upstream HTTP/1.1, limiting shared back-end connections sharply reduces queue-poisoning impact.
6. **Strip `Upgrade` unless it is explicitly required for WebSocket** – prevents `h2c` tunnelling.

---
## References

- [1] [PortSwigger Research - HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- [2] [PortSwigger Research - HTTP/1.1 must die: the desync endgame](https://portswigger.net/research/http1-must-die)

{{#include ../../banners/hacktricks-training.md}}

