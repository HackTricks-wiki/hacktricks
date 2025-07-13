# Request Smuggling in HTTP/2 Downgrades

{{#include ../../banners/hacktricks-training.md}}

HTTP/2 is generally considered immune to classic request-smuggling because the length of each DATA frame is explicit. **That protection disappears as soon as a front-end proxy “downgrades” the request to HTTP/1.x before forwarding it to a back-end**. The moment two different parsers (the HTTP/2 front-end and the HTTP/1 back-end) try to agree on where one request ends and the next begins, all the old desync tricks come back – plus a few new ones.

---
## Why downgrades happen

1. Browsers already speak HTTP/2, but much legacy origin infrastructure still only understands HTTP/1.1.
2. Reverse-proxies (CDNs, WAFs, load-balancers) therefore terminate TLS + HTTP/2 at the edge and **rewrite every request as HTTP/1.1** for the origin.
3. The translation step has to create *both* `Content-Length` **and/or** `Transfer-Encoding: chunked` headers so that the origin can determine body length.

Whenever the front-end trusts the HTTP/2 frame length **but** the back-end trusts CL or TE, an attacker can force them to disagree.

---
## Two dominant primitive classes

| Variant | Front-end length | Back-end length | Typical payload |
|---------|-----------------|-----------------|-----------------|
| **H2.TE** | HTTP/2 frame | `Transfer-Encoding: chunked` | Embed an extra chunked message body whose final `0\r\n\r\n` is *not* sent, so the back-end waits for the attacker-supplied “next” request. |
| **H2.CL** | HTTP/2 frame | `Content-Length` | Send a *smaller* CL than the real body, so the back-end reads past the boundary into the following request. |

> These are identical in spirit to classic TE.CL / CL.TE, just with HTTP/2 replacing one of the parsers.  

---
## Identifying a downgrade chain

1. Use **ALPN** in a TLS handshake (`openssl s_client -alpn h2 -connect host:443`) or **curl**:
   ```bash
   curl -v --http2 https://target
   ```
   If `* Using HTTP2` appears, the edge speaks H2.
2. Send a deliberately malformed CL/TE request *over* HTTP/2 (Burp Repeater now has a dropdown to force HTTP/2). If the response is an HTTP/1.1 error such as `400 Bad chunk`, you have proof the edge converted the traffic for a HTTP/1 parser downstream.

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

---
## h2c smuggling (clear-text upgrades)

A 2023 study showed that if a front-end passes the HTTP/1.1 `Upgrade: h2c` header to a back-end that supports clear-text HTTP/2, an attacker can tunnel *raw* HTTP/2 frames through an edge that only validated HTTP/1.1. This bypasses header normalisation, WAF rules and even TLS termination.  

Key requirements:
* Edge forwards **both** `Connection: Upgrade` and `Upgrade: h2c` unchanged.
* Origin increments to HTTP/2 and keeps the connection-reuse semantics that enable request queueing.

Mitigation is simple – strip or hard-code the `Upgrade` header at the edge except for WebSockets.

---
## Notable real-world CVEs (2022-2025)

* **CVE-2023-25690** – Apache HTTP Server mod_proxy rewrite rules could be chained for request splitting and smuggling. (fixed in 2.4.56)  
* **CVE-2023-25950** – HAProxy 2.7/2.6 request/response smuggling when HTX parser mishandled pipelined requests.  
* **CVE-2022-41721** – Go `MaxBytesHandler` caused left-over body bytes to be parsed as **HTTP/2** frames, enabling cross-protocol smuggling.  

---
## Tooling

* **Burp Request Smuggler** – since v1.26 it automatically tests H2.TE/H2.CL and hidden ALPN support. Enable “HTTP/2 probing” in the extension options.
* **h2cSmuggler** – Python PoC by Bishop Fox to automate the clear-text upgrade attack:
  ```bash
  python3 h2csmuggler.py -u https://target -x 'GET /admin HTTP/1.1\r\nHost: target\r\n\r\n'
  ```
* **curl**/`hyper` – crafting manual payloads: `curl --http2-prior-knowledge -X POST --data-binary @payload.raw https://target`.

---
## Defensive measures

1. **End-to-end HTTP/2** – eliminate the downgrade translation completely.
2. **Single source of length truth** – when downgrading, *always* generate a valid `Content-Length` **and** **strip** any user-supplied `Content-Length`/`Transfer-Encoding` headers.
3. **Normalize before route** – apply header-sanitisation *before* routing/rewrite logic.
4. **Connection isolation** – do not reuse back-end TCP connections across users; “one request per connection” defeats queue-based exploits.
5. **Strip `Upgrade` unless WebSocket** – prevents h2c tunnelling.

---
## References

* PortSwigger Research – “HTTP/2: The Sequel is Always Worse” <https://portswigger.net/research/http2>
* Bishop Fox – “h2c Smuggling: request smuggling via HTTP/2 clear-text” <https://bishopfox.com/blog/h2c-smuggling-request>

{{#include ../../banners/hacktricks-training.md}}
