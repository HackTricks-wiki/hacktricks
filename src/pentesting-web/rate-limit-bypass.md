# Rate Limit Bypass

{{#include ../banners/hacktricks-training.md}}

## Rate limit bypass techniques

### Exploring Similar Endpoints

During an authorized test, compare variations of the protected endpoint, such as `/api/v3/sign-up`, `/Sign-up`, `/SignUp`, `/signup`, `/api/v1/sign-up`, and `/api/sign-up`. A bypass here normally indicates that canonicalization or routing happens after the rate-limit decision.

### Incorporating Blank Characters in Code or Parameters

Test whether the limiter and application normalize delimiters differently. Candidates include a NUL (`%00`), CRLF (`%0d%0a`), CR (`%0d`), LF (`%0a`), horizontal tab (`%09`), form feed (`%0c`), and space (`%20`). For example, `code=1234%0a` may produce a different limiter key even if the application later trims the newline. `%0d%0a` is a two-character line break, not a blank byte; malformed control characters can also be rejected by proxies before reaching the application.

### Manipulating IP Origin via Headers

Test which signal the application uses as the client IP. Spoofable headers matter only when a trusted proxy or the application accepts them from an untrusted client; a secure edge should overwrite them and trust forwarded values only from known proxy hops. Candidate headers include `X-Originating-IP`, `X-Forwarded-For`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, and `X-Forwarded-Host`, including duplicate `X-Forwarded-For` fields. Loopback values are shown for parser testing but can activate separate trust paths, so use controlled addresses first.

```bash
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwarded-Host: 127.0.0.1

# Double X-Forwarded-For header example
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```

### Changing Other Headers

Compare other possible limiter keys such as `User-Agent`, device identifiers, and cookies. If rotating one changes the quota while the account and operation remain identical, document that the limiter is keyed to a client-controlled value.

### Leveraging API Gateway Behavior

Some API gateways key rate limits on a combination of path and parameters. Varying an ignored parameter, such as `/resetpwd?someparam=1`, can reveal that each syntactically distinct request receives a separate quota.

### Logging into Your Account Before Each Attempt

Logging into a controlled account before each attempt, or each small set of attempts, can reveal whether issuing a new session resets the counter. In Burp Intruder, a Pitchfork attack can rotate test credentials or session tokens while following the same redirect flow. Also test whether lockout applies to the account, the source, or both; account lockout must resist distribution across sessions and IP addresses.<sup>[[5]](#references)</sup>

### Utilizing Proxy Networks

With explicit authorization, controlled egress nodes can establish whether a limiter is only source-IP based. Do not use unknown public/open proxies: they can record credentials and may route test traffic through systems whose owners did not consent.

### Splitting the Attack Across Different Accounts or Sessions

If the target system applies rate limits on a per-account or per-session basis, distributing the attack or test across multiple accounts or sessions can help in avoiding detection. This approach requires managing multiple identities or session tokens, but can effectively distribute the load to stay within allowable limits.

### Keep Trying

Note that even if a rate limit is in place you should try to see if the response is different when the valid OTP is sent. In [**this post**](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732), the bug hunter discovered that even if a rate limit is triggered after 20 unsuccessful attempts by responding with 401, if the valid one was sent a 200 response was received.<sup>[[1]](#references)</sup>

---

### Abusing HTTP/2 multiplexing & request pipelining (2023-2025)

A misconfigured limiter may count **TCP connections** rather than the HTTP/2 request streams multiplexed inside each connection. Test whether many streams on one authorized connection consume one quota unit or one unit per request; a correct application-level limiter counts the protected operation independently of transport reuse.<sup>[[6]](#references)</sup>

```bash
# Reuse one HTTP/2 connection for 100 requests containing the same test body
printf '%s\n' '{"code":"000000"}' > post.json
h2load -n 100 -c 1 -m 100 -d post.json \
  -H 'content-type: application/json' https://target/api/v2/verify
```

The common `seq | xargs curl` pattern starts many curl processes and therefore does **not** demonstrate a single multiplexed connection. For different OTP values on separate streams, use a client such as Turbo Intruder that supports request variation while retaining connections.

If the limiter protects only `/verify` but not `/api/v2/verify`, you can also combine **path confusion** with HTTP/2 multiplexing for *extremely* high-speed OTP or credential brute-forcing.

> 🐾  **Tip:** PortSwigger’s [Turbo Intruder](https://portswigger.net/research/turbo-intruder) supports HTTP/2 and lets you fine-tune `maxConcurrentConnections` and `requestsPerConnection` to automate this attack.

### GraphQL aliases & batched operations

GraphQL aliases allow one operation to invoke a field several times under different response names. If throttling counts only HTTP requests rather than sensitive resolver invocations, aliases can bypass login or password-reset limits; properly instrumented resolvers still enforce a limit per attempt.<sup>[[2]](#references)</sup>

```graphql
mutation bruteForceOTP {
  a: verify(code:"111111") { token }
  b: verify(code:"222222") { token }
  c: verify(code:"333333") { token }
  # … add up to dozens of aliases …
}
```

Inspect each alias's field or error entry in the single GraphQL response. There is only one HTTP status for the entire response, so an individual alias does not independently “return 200”; the successful field may instead contain a token while other fields contain errors or null values.

PortSwigger's GraphQL testing guidance demonstrates the alias-based rate-limit bypass.<sup>[[2]](#references)</sup>

### Abuse of *batch* or *bulk* REST endpoints

Some APIs expose helper endpoints such as `/v2/batch` or accept an **array of objects** in the request body. If the limiter is placed in front of the *legacy* endpoints only, wrapping multiple operations inside a single bulk request may completely sidestep the protection.

```json
[
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"123"}},
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"456"}}
]
```

### Timing the sliding-window

A **fixed-window** limiter resets on a boundary (for example, every minute). If that boundary is known from a response such as `X-RateLimit-Reset: 27`, send the maximum authorized test burst just before it and another immediately afterward. Sliding-window, token-bucket, and leaky-bucket algorithms do not all have the same hard reset behavior.

```
|<-- 60 s window ‑->|<-- 60 s window ‑->|
       ######                 ######
```

This boundary burst can approach twice the nominal fixed-window allowance over a short interval.

### Upgrading to WebSockets / gRPC streaming after the handshake

Some edge products inspect the initial WebSocket upgrade request but not the messages inside the established connection. Cloudflare documents this limitation for its WAF; an application-level WebSocket limiter may still inspect and throttle every message. gRPC behavior depends on the proxy and application and must be tested separately.<sup>[[3]](#references)</sup>

Practical workflow:

```bash
# Flood 1,000 OTP guesses through a single WebSocket connection
seq -w 000000 000999 | websocat -n ws://target.tld/api/verify-ws

# gRPC streaming: send multiple Verify requests in one stream
grpcurl -d @ -plaintext target.tld:50051 service.VerifyOTP/Stream <<'EOF'
{ "code": "111111" }
{ "code": "222222" }
{ "code": "333333" }
EOF
```

If the same authorized login or OTP operation is exposed through HTTP and WebSocket/gRPC variants, compare whether every message consumes the same logical quota.

### Exploiting CDN PoP‑sharded counters

Some CDNs shard rate-limit counters **per data center/PoP instead of globally**. Cloudflare documents that its counters are not shared across data centers, which can allow one quota per PoP for the same key.<sup>[[4]](#references)</sup> Validate this only with controlled egress nodes included in the test authorization.

Example layout using a tester-owned proxy list:

```bash
for p in $(cat proxies.txt); do
  HTTPS_PROXY=$p curl -s -X POST https://target/api/login -d @payload.json &
done
wait
```

Make sure the limiter key is not per-account; otherwise also rotate user IDs / session tokens.

---

## Tools

- [**https://github.com/Hashtag-AMIN/hashtag-fuzz**](https://github.com/Hashtag-AMIN/hashtag-fuzz): Fuzzing tool that supports header randomisation, chunked word-lists and round-robin proxy rotation.
- [**https://github.com/ustayready/fireprox**](https://github.com/ustayready/fireprox): Creates AWS API Gateway endpoints that can be used to evaluate source-IP-based throttling in an authorized environment; usage incurs AWS resources and costs.
- **Burp Suite – IPRotate + extension**: Uses a pool of SOCKS/HTTP proxies (or AWS API Gateway) to rotate the source IP transparently during *Intruder* and *Turbo Intruder* attacks.
- **Turbo Intruder (BApp)**: High-performance attack engine supporting HTTP/2 multiplexing; tune `requestsPerConnection` to 100-1000 to collapse hundreds of requests into a single connection.

## References

- [1] [The $2,200 ATO most bug hunters overlooked by closing Intruder too soon](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732)
- [2] [PortSwigger Web Security Academy – GraphQL API vulnerabilities: Bypassing rate limiting using aliases](https://portswigger.net/web-security/graphql)
- [3] [Cloudflare Docs – WebSockets & WAF applicability](https://developers.cloudflare.com/network/websockets/)
- [4] [Cloudflare Docs – Request rate calculation and PoP-local counters](https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/)
- [5] [OWASP WSTG — Testing for Weak Lock Out Mechanism](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism)
- [6] [PortSwigger Research — HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)

{{#include ../banners/hacktricks-training.md}}
