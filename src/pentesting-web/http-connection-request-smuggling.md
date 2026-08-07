# HTTP Connection Request Smuggling

{{#include ../banners/hacktricks-training.md}}

**HTTP connection request smuggling** is a **connection-state / routing** problem rather than a classic CL.TE/TE.CL parser discrepancy. The bug appears when a front-end decides **where a connection is allowed to go only once**, then silently reuses that same TCP/TLS connection for later requests with a different `Host` or `:authority`.<sup>[[1]](#references)[[2]](#references)</sup>

If you need the classic length-confusion variants, see [HTTP Request Smuggling / HTTP Desync Attack](http-request-smuggling/README.md) and [Request Smuggling in HTTP/2 Downgrades](http-request-smuggling/request-smuggling-in-http-2-downgrades.md).

## Connection-State Attacks <a href="#state" id="state"></a>

### First-request Validation

When routing requests, reverse proxies often depend on the **Host** header (or **`:authority`** in HTTP/2) to decide the destination back-end server and whether that destination is allowed. A recurring bug class is that this whitelist is **only enforced on the first request on a connection**. After that, the front-end trusts the connection itself instead of re-validating each request:

```http
GET / HTTP/1.1
Host: allowed-external-host.example

GET /admin HTTP/1.1
Host: internal-only.example
```

This turns connection reuse into an SSRF-like primitive against **internal virtual hosts**, admin panels, debug routes, and alternate tenants sharing the same edge.<sup>[[1]](#references)</sup>

### First-request Routing

Some reverse proxies map the **entire back-end connection** to a destination pool based only on the **first request** they forward. Every later request on that client connection is then sent to the same upstream, even if the `Host` header changes. This is especially useful when combined with [Host header attacks](https://portswigger.net/web-security/host-header) such as password-reset poisoning, cache poisoning, or virtual-host brute forcing:

```http
GET / HTTP/1.1
Host: public.example

POST /pwreset HTTP/1.1
Host: private.internal
```

> [!TIP]
> PortSwigger's **HTTP Request Smuggler** extension includes a **connection-state probe** specifically for these cases. They are easy to dismiss as “just connection reuse” or “just pipelining”, so always confirm with a fresh-connection control request.

### Why this is different from classic desyncs

- **No CL/TE ambiguity is required.** The dangerous behavior is the **routing/authorization decision being cached per connection**.
- **Reuse is mandatory.** If the front-end or browser opens a new connection for the second request, the attack dies.
- **False positives are common.** Ordinary HTTP pipelining/reuse can look suspicious, so re-test the same request on a brand-new connection and compare the response origin, headers, and status code.

---

## Browser-Powered Connection-State Abuse (2022-2025)

The most practical modern variant is **browser-powered** exploitation. A victim first opens a legitimate connection to an attacker-controlled or attacker-triggered origin, and the browser later **reuses or coalesces** that connection for a different authority.<sup>[[1]](#references)</sup>

### Coalescing preconditions worth checking

For HTTP/2 and HTTP/3, prioritize targets where several hostnames share the same edge infrastructure:

- The certificate presented on the existing connection is valid for **both** the attacker-controlled hostname and the target hostname.
- For classic HTTP/2 coalescing, browsers commonly require the hostnames to resolve to the **same edge / overlapping IP set**.
- **ORIGIN frames** can further expand which authorities are considered reusable on an existing HTTP/2 connection, so “same IP” is **not** the whole story anymore.
- Shared **CDNs, API gateways, WAFs, service meshes, Alt-Svc / HTTP/3 endpoints**, and wildcard certificates increase the odds of cross-origin reuse.
- The front-end performs **routing or host validation only once** instead of per request / per stream.

### Exploitation scenario

1. The attacker controls `evil.com`, which terminates on the same shared edge as `internal.company`.
2. The victim opens `https://evil.com/` and the browser establishes an HTTP/2 or HTTP/3 connection.
3. The attacker causes the victim to request `https://internal.company/...` (for example via an `<img>`, `fetch()`, or redirect chain).
4. The browser reuses the **existing** connection because the endpoint looks authoritative for both origins.
5. If the edge only validated the **first** request, the later request to `internal.company` is routed or authorized using stale connection state.

> [!NOTE]
> A hardened deployment may respond with **`421 Misdirected Request`** when a reused connection is not valid for the new authority. Seeing `421` is usually a good sign: the server noticed the connection was coalesced but refused to trust it.

### Practical testing workflow

#### HTTP/1.1 manual probe

```bash
printf 'GET / HTTP/1.1\r\nHost: public.example\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal.example\r\nConnection: close\r\n\r\n' \
| openssl s_client -quiet -connect target:443
```

If the second response clearly belongs to `internal.example`, or if back-end behavior changes only when both requests share one socket, investigate further.

#### HTTP/2 workflow

1. In **Burp Repeater**, enable **Allow HTTP/2 ALPN override** so you can test **hidden HTTP/2** support even when the server does not advertise it.
2. Send an initial request to an allowed host / authority.
3. Reuse the **same Repeater tab / same connection** and change only `:authority` (or the target path) for the next request or stream.
4. Repeat the exact same second request from a **fresh connection** as a control.
5. A genuine issue normally shows a routing / authorization difference that exists **only** on the reused connection.

### High-value chains

Connection-state flaws combine particularly well with:

- **Internal virtual-host enumeration** and access to admin panels or preview environments.
- **Host header attacks** such as password-reset poisoning or cache poisoning on an internal / alternate vhost.
- **Client-side desync** and browser-assisted queue poisoning techniques from [Browser HTTP Request Smuggling](http-request-smuggling/browser-http-request-smuggling.md).
- **HTTP/2 downgrade gadgets** from [Request Smuggling in HTTP/2 Downgrades](http-request-smuggling/request-smuggling-in-http-2-downgrades.md) when you need a second primitive to poison a shared back-end connection.

---

## Related State-Transition Abuse: `h2c` Upgrade Tunnelling

A closely related bug appears when a front-end forwards **`Upgrade: h2c`** and, after the `101 Switching Protocols`, stops inspecting the traffic and simply tunnels bytes to the back end. In practice, the proxy may enforce routing / ACLs only on the **initial HTTP/1.1 request**, after which the attacker speaks raw clear-text HTTP/2 directly to the internal service.

```http
GET / HTTP/1.1
Host: public.example
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAAQCAAAAAAIAAAAA
```

This is worth testing on reverse proxies that support upgrade-style tunnelling or permissive `proxy_pass` rules.

---

## Tooling

- **HTTP Request Smuggler** (Burp) – useful for **connection-state probes**, hidden-HTTP/2 testing, browser-powered desync work, and modern parser-discrepancy detection.
- **`http2smugl`** – purpose-built for finding **HTTP/2 → HTTP/1.1 downgrade** smuggling paths and related request poisoning opportunities.
- **`smugglefuzz`** – a **Go-based** downgrade smuggling scanner with customizable gadget lists and fast bulk probing.
- **`h2cSmuggler`** – focuses on `Upgrade: h2c` tunnelling mistakes that bypass front-end ACLs.

---

## Mitigations

- Re-validate **`Host` / `:authority` on every request and every HTTP/2 stream**, not just once per socket.
- Keep **internal and external hostnames** on separate certificates / origin sets / Alt-Svc advertisements when possible.
- Return **`421 Misdirected Request`** when a reused connection is not authoritative for the new origin.
- Strip or hard-code **`Upgrade: h2c`** at the edge unless it is explicitly required.
- Where feasible, avoid reusing a single privileged upstream connection across unrelated tenants or trust zones.

---

## References

- [1] [PortSwigger Research - Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- [2] [PortSwigger Research - HTTP/1.1 must die: the desync endgame](https://portswigger.net/research/http1-must-die)

{{#include ../banners/hacktricks-training.md}}
