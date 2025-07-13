# HTTP Connection Request Smuggling

{{#include ../banners/hacktricks-training.md}}

**This page summarizes, extends and updates** the seminal PortSwigger research on [Browser-Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks) and subsequent work on HTTP/2 connection-state abuse. It focuses on vulnerabilities where **an origin is determined only once per TCP/TLS connection**, enabling an attacker to “smuggle” requests to a different internal host once the channel is established.

## Connection-State Attacks <a href="#state" id="state"></a>

### First-request Validation

When routing requests, reverse proxies might depend on the **Host** (or **:authority** in HTTP/2) header to determine the destination back-end server, often relying on a whitelist of hosts that are permitted access. However, a vulnerability exists in a number of proxies where the whitelist is **only enforced on the very first request in a connection**. Consequently, attackers can access internal virtual hosts by first sending an allowed request and then re-using the same underlying connection:

```http
GET / HTTP/1.1
Host: allowed-external-host.example

GET /admin HTTP/1.1
Host: internal-only.example
```

### First-request Routing

Many HTTP/1.1 reverse proxies map an outbound connection to a back-end pool **based exclusively on the first request they forward**. All subsequent requests sent through the same front-end socket are silently re-used, regardless of their Host header. This can be combined with classic [Host header attacks](https://portswigger.net/web-security/host-header) such as password-reset poisoning or [web cache poisoning](https://portswigger.net/web-security/web-cache-poisoning) to obtain SSRF-like access to other virtual hosts:

```http
GET / HTTP/1.1
Host: public.example

POST /pwreset HTTP/1.1
Host: private.internal
```

> [!TIP]
> In Burp Suite Professional ≥2022.10 you can enable **HTTP Request Smuggler → Connection-state probe** to automatically detect these weaknesses.

---

## NEW in 2023-2025 – HTTP/2/3 Connection Coalescing Abuse

Modern browsers routinely **coalesce** HTTP/2 and HTTP/3 requests onto a single TLS connection when the certificate, ALPN protocol and IP address match. If a front-end only authorizes the first request, every subsequent coalesced request inherits that authorisation – **even if the Host/:authority changes**.

### Exploitation scenario
1. The attacker controls `evil.com` which resolves to the same CDN edge node as the target `internal.company`.
2. The victim’s browser already has an open HTTP/2 connection to `evil.com`.
3. The attacker embeds a hidden `<img src="https://internal.company/…">` in their page.
4. Because the connection parameters match, the browser re-uses the **existing** TLS connection and multiplexes the request for `internal.company`.
5. If the CDN/router only validated the first request, the internal host is exposed.

PoCs for Chrome/Edge/Firefox are available in James Kettle’s talk *“HTTP/2: The Sequel is Always Worse”* (Black Hat USA 2023).

### Tooling
* **Burp Suite 2023.12** introduced an experimental **HTTP/2 Smuggler** insertion point that automatically attempts coalescing and TE/CL techniques.
* **smuggleFuzz** (https://github.com/microsoft/smugglefuzz) – A Python framework released in 2024 to brute-force front-end/back-end desync vectors over HTTP/2 and HTTP/3, including connection-state permutations.

### Mitigations
* Always **re-validate Host/:authority on every request**, not only on connection creation.
* Disable or strictly scope **origin coalescing** on CDN/load-balancer layers (e.g. `http2_origin_cn` off in NGINX).
* Deploy separate certificates or IP addresses for internal and external hostnames so the browser cannot legally coalesce them.
* Prefer **connection: close** or `proxy_next_upstream` after each request where practical.

---

## Real-World Cases (2022-2025)

| Year | Component | CVE | Notes |
|------|-----------|-----|-------|
| 2022 | AWS Application Load Balancer | – | Host header only validated on first request; fixed by patching rules engine (disclosed by SecurityLabs). |
| 2023 | Apache Traffic Server < 9.2.2 | CVE-2023-39852 | Allowed request smuggling via HTTP/2 connection reuse when `CONFIG proxy.config.http.parent_proxy_routing_enable` was set. |
| 2024 | Envoy Proxy < 1.29.0 | CVE-2024-2470 | Improper validation of :authority after first stream enabled cross-tenant request smuggling in shared meshes. |

---

## Detection Cheat-Sheet

1. Send two requests in the **same** TCP/TLS connection with different Host or :authority headers.
2. Observe whether the second response originates from the first host (safe) or the second host (vulnerable).
3. In Burp: `Repeat → keep-alive → Send → Follow`.
4. When testing HTTP/2, open a **dedicated** stream (ID 1) for a benign host, then multiplex a second stream (ID 3) to an internal host and look for a reply.

---

## References

* PortSwigger Research – *HTTP/2: The Sequel is Always Worse* (Black Hat USA 2023)
* Envoy Security Advisory CVE-2024-2470 – Improper authority validation

{{#include ../banners/hacktricks-training.md}}