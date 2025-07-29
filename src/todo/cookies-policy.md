# Cookies Policy

Last updated: 07/29/2025

### Introduction

This Cookies Policy applies to the following websites owned and operated by HackTricks team ("HackTricks", "we", "us" or "our"):

* hacktricks.wiki
* [www.hacktricks.wiki](https://www.hacktricks.wiki/)
* book.hacktricks.wiki
* cloud.hacktricks.wiki

By using any of these websites, you agree to the use of cookies in accordance with this Cookies Policy. If you do not agree, please disable cookies in your browser settings or refrain from using our websites.

### What are cookies?

Cookies are small text files that are stored on your computer or mobile device when you visit a website. They are widely used to make websites work, improve their functionality, and provide a more personalized user experience.

### How we use cookies

We use cookies on our websites for the following purposes:

1. Essential cookies: These cookies are necessary for the basic functionality of our websites, such as enabling user authentication, maintaining security, and remembering your preferences.
2. Performance cookies: These cookies help us understand how visitors interact with our websites, by collecting and reporting information anonymously. This allows us to improve our website performance and user experience.
3. Functionality cookies: These cookies enable our websites to remember choices you make, such as your language or region, to provide a more personalized experience.
4. Targeting/advertising cookies: These cookies are used to deliver relevant ads and marketing communications based on your interests, browsing history, and interactions with our websites.

Moreover, the pages book.hacktricks.wiki and cloud.hacktricks.wiki are hosted in Gitbook. You can find more information about Gitbooks cookies in <https://gitbook-1652864889.teamtailor.com/cookie-policy>.

### Third-party cookies

In addition to our own cookies, we may also use third-party cookies to report website usage statistics, deliver advertisements, and enable social-media sharing buttons. The use of third-party cookies is subject to their respective privacy policies.

### Managing cookies

Most web browsers allow you to manage cookies through their settings. You can choose to block, delete, or limit the use of cookies on your device. However, please note that disabling cookies may affect the functionality and performance of our websites.

---

## Security considerations for cookies (technical guidance)

Although this document is primarily a legal notice, HackTricks is a security-focused project and we want to provide actionable advice for defenders and penetration testers who work with cookies every day.

### Common attack vectors

* **Session hijacking & side-jacking** – stealing a victim’s session ID via XSS, MitM or leaked Referer headers.
* **Session fixation** – forcing a user to authenticate using a cookie value chosen by the attacker.
* **CSRF & SameSite bypasses** – abusing relaxed SameSite policies or browser implementation flaws (e.g. Samsung Internet CVE-2023-30674) to perform state-changing requests cross-site. citeturn1search0
* **Cookie tossing / prefix confusion** – planting a cookie on a parent domain so that it shadows a more secure cookie.
* **Cookie poisoning** – manipulating cookie values (e.g. in JWTs stored in cookies) to escalate privileges.

### Recommended defensive attributes

| Attribute | Purpose | Example |
|-----------|---------|---------|
| `Secure` | Prevents transmission over plain HTTP. | `Set-Cookie: id=abc; Secure` |
| `HttpOnly` | Blocks JavaScript access (mitigates XSS session theft). | `Set-Cookie: id=abc; HttpOnly` |
| `SameSite=Strict \| Lax` | Mitigates CSRF by withholding cookies on cross-site requests. | `Set-Cookie: id=abc; SameSite=Lax` |
| `SameSite=None; Secure` | Allows cross-site use **only** when truly required (payment, SSO). Must be combined with `Secure`. | `Set-Cookie: token=xyz; SameSite=None; Secure` |
| `Partitioned` | New (Chrome 114+) attribute from *Cookies Having Independent Partitioned State* (CHIPS). Enables a third-party cookie to be double-keyed per top-level site, surviving the upcoming third-party cookie phase-out while blocking cross-site tracking. | `Set-Cookie: __Host-example=34d8g; Path=/; Secure; SameSite=None; Partitioned` citeturn0search1 |
| `__Host-` / `__Secure-` prefixes | Enforce `Secure`, `Path=/` and (for `__Host-`) the absence of `Domain`, limiting the scope and preventing cookie-shadowing. | `Set-Cookie: __Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax` |

> 💡 Tip: Combine *multiple* attributes. A modern, highly secure session cookie looks like:
>
> `Set-Cookie: __Host-session=s%3A123…; Path=/; Secure; HttpOnly; SameSite=Lax;`  
> or, for an embedded third-party service that must persist after Chrome’s 2025 3PCD rollout:  
> `Set-Cookie: __Host-chat=34d8g; Path=/; Secure; SameSite=None; Partitioned;` 

### Browser changes you should be aware of (2024–2025)

* **Chrome 118+ Privacy Sandbox (“3PCD”) experiments** – Google has started rolling out the removal of unrestricted third-party cookies. Sites that rely on `SameSite=None` cookies should migrate to CHIPS (`Partitioned`), the Storage Access API, or other Privacy-Sandbox alternatives.
* **`Partitioned` attribute shipped (Chrome 114, June 2024)** – gives developers a forward-compatible way to keep legitimate cross-site state without enabling tracking. Other Chromium-based browsers (Edge, Brave) have followed quickly.
* **RFC 6265bis drafts (2024-2025)** – the IETF HTTPBIS working group is standardising new attributes (`Partitioned`, updated `SameSite` semantics, cookie prefixes) and clarifying historical ambiguities.

### Testing & debugging tools

* **Chrome DevTools “Cookies” panel & Issues tab** – surfaces deprecation warnings for `SameSite=None` and shows partitioning status.
* **Privacy Sandbox Analysis Tool (PSAT)** – a DevTools extension that simulates the 3PCD environment and helps audit third-party cookie usage. citeturn3search1

---

### Changes to this Cookies Policy

We may update this Cookies Policy from time to time to reflect changes in our practices, relevant laws, or browser behaviour. We encourage you to periodically review this page for the latest information.

### Contact us

If you have any questions or concerns about this Cookies Policy, please contact us at [support@hacktricks.xyz](mailto:support@hacktricks.xyz)

## References

* Google Privacy Sandbox – Cookies Having Independent Partitioned State (CHIPS) *(accessed July 2025)*
* PortSwigger Web Security Academy – Bypassing SameSite cookie restrictions *(accessed July 2025)*
