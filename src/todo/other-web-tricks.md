# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header (and friends)

Many applications still *trust* the value of the `Host` header (or its variants that are added by proxies) to build absolute URLs, find the tenant that should be served, or decide which business-logic branch to execute.  A classic—and still extremely common—impact is **Password-reset link poisoning**:

1. Intercept the request that triggers the *Forgot-password* workflow.
2. Add **every host-related header you can think of** pointing to a domain you control:

```http
Host: attacker.tld
X-Forwarded-Host: attacker.tld
X-Forwarded-Server: attacker.tld
X-HTTP-Host-Override: attacker.tld
Forwarded: for=127.0.0.1;host=attacker.tld;proto=https
```
3. When the back-end builds the reset URL it will often pick the first header in the chain and send the victim an email that contains your domain.
4. The victim (or an AV/spam-filter robot) requests the URL and leaks the secret token to you.

⚠️ **Blind tokens:** you frequently get the reset token *without* any user interaction because security scanners, link preview bots, etc. will preload the URL.  Make sure to tail the logs of your exploit server.

Other juicy attack surfaces that rely on `Host` / `X-Forwarded-*` are:
* multi-tenant routing (steal other tenants' data)
* OAuth/OpenID `redirect_uri` validation
* SSRF protection lists comparing the host against an allow-list

**Testing tip**  –  Burp → *Extender → BApp Store → Host Header Attack* gives you a passive and active scanner that automatically fuzzes all the above headers.

> **Defense.** Never trust a client-supplied `Host` header.  Resolve the canonical external URL from configuration or from trusted proxy headers that have been sanity-checked by your reverse-proxy/WAF.

*(excellent practical labs: PortSwigger Academy – Password-reset poisoning)*

### Session booleans & second-order IDOR

Some frameworks simply drop a Boolean flag in your session after you finish a sensitive workflow (KYC completed, MFA passed, promo-code redeemed, …).  The flag is later consulted **everywhere**:

```python
# Django-ish pseudocode
if request.session.get("mfa_passed"):
    return sensitive_page(request)
```

Attack chain:
1. Pass the legitimate check once (or manipulate the endpoint that sets the flag).
2. Replay completely different requests that only verify the Boolean.  You now access data/actions that were never meant to be available to you.

Because the vulnerable logic is executed *after* some state is stored, this pattern is also called a **second-order IDOR**.  Look for attributes such as `is_premium`, `is_verified`, `passed_mfa` that are persisted in cookies, session storage, or JWT claims.

Automate the hunt with Burp *AuthMatrix* or *Autorize* by recording a privileged and an unprivileged identity and diffing the responses.

### Register functionality tricks

• Try to sign-up with an *already existing* e-mail but use case/Unicode tricks:  `juán@example.com` vs `juan01@example.com`, `john doe@example.com` (U+2006 six-per-em space), trailing spaces (`"john@example.com␠"`).  
• Many SaaS platforms accept unlimited dots or plus-aliases in Gmail addresses—use it to collide with the target account.

### E-mail takeover races

1. Register with `victim@example.com`.
2. **Do not** click the verification link.
3. Change account e-mail to **your** inbox.
4. Validate the new address *with the first token*—now you control both addresses in the account profile.

If the application sends *all* future verification/2FA codes to *both* addresses you can fully own arbitrary accounts.

### Atlassian Jira Service Management portals

Internal help-desks running in the Atlassian Cloud are often exposed at predictable URLs such as:

```
https://<company>.atlassian.net/servicedesk/customer/user/login
```

If *public signup* is allowed you can create a customer account and then test for vulnerabilities such as:
* **CVE-2023-22501** – token-reuse that lets you impersonate other users if you can read the signup e-mail they receive.  Patch level ≥5.6.0 is required.
* Legacy path-traversal `…/servicedesk/customer/../../secure/` (CVE-2019-14994) that exposes internal Jira projects.

Always attempt common escalations: access knowledge-base articles, attachment downloads, or filter `assignee=currentUser()` JQL queries to exfiltrate user names.

### TRACE / XST

Send a raw request:

```bash
$ printf 'TRACE / HTTP/1.1\r\nHost: target.com\r\nTest: hacktricks\r\n\r\n' | nc target.com 80
```

If the response reflects the `Test:` header the server supports `TRACE`.  Combined with legacy client-side tricks (Flash, old ActiveX) this enables **Cross-Site-Tracing (XST)** to steal cookies even when `HttpOnly` is set.  Modern browsers block JavaScript TRACE calls, but disabling the method is still the safest mitigation.

### HTTP method override / tunnelling

Some REST stacks accept special headers or query parameters to *rewrite* the HTTP verb, e.g.:

```http
POST /api/resource HTTP/1.1
X-HTTP-Method-Override: DELETE
```

If a WAF only filters dangerous verbs at the edge while the origin honours the override, you gain a **method-confusion auth bypass**.  A real-world example is **CVE-2023-30845 / GHSA-6qmp-9p95-fc5f** in Google ESP-v2, where adding the header let attackers skip JWT authentication entirely.

Headers to try:
* `X-HTTP-Method-Override`
* `X-Method-Override`
* `X-HTTP-Method`

Automate with: `ffuf -w verbs.txt -H "X-HTTP-Method-Override: FUZZ" -X POST <url>`.

---



## References

* PortSwigger Web Security Academy – Password-reset poisoning via Host header 
* GHSA-6qmp-9p95-fc5f – JWT authentication bypass via X-HTTP-Method-Override 
{{#include ../banners/hacktricks-training.md}}
