# Cookies Policy

Last updated: 25/07/2025

### Introduction

This Cookies Policy applies to the following websites owned and operated by the HackTricks team ("HackTricks", "we", "us" or "our"):

* hacktricks.wiki
* [www.hacktricks.wiki](https://www.hacktricks.wiki)
* book.hacktricks.wiki
* cloud.hacktricks.wiki

By using any of these websites, you agree to the use of cookies in accordance with this Cookies Policy. If you do not agree, please disable cookies in your browser settings or refrain from using our websites.

---

## What are cookies?

Cookies are small text files that are stored on your computer or mobile device when you visit a website. They are widely used to make websites work, improve their functionality, and provide a more personalized user experience.

## How we use cookies

We use cookies on our websites for the following purposes:

1. **Essential cookies** – Necessary for basic functionality such as authentication, security, and remembering your preferences.
2. **Performance cookies** – Help us understand how visitors interact with our websites by collecting anonymised statistics so we can improve performance and user experience.
3. **Functionality cookies** – Enable our websites to remember choices you make (e.g. language or region) to provide a more personalised experience.
4. **Targeting / advertising cookies** – Used to deliver relevant ads and marketing communications based on your interests, browsing history, and interaction with our websites.

Parts of our documentation (book.hacktricks.wiki and cloud.hacktricks.wiki) are hosted on GitBook. GitBook’s own cookies are therefore also set – see their policy at <https://gitbook-1652864889.teamtailor.com/cookie-policy>.

## Third-party cookies

In addition to our own cookies, we may use third-party cookies to compile website usage statistics, deliver advertisements, and enable social-media sharing buttons. The use of third-party cookies is governed by the respective third-party privacy policies.

## Managing cookies

Most web browsers allow you to manage cookies through their settings. You can choose to block, delete or limit cookies on your device. Disabling cookies may affect the functionality and performance of our websites.

## Changes to this Cookies Policy

We may update this Cookies Policy from time to time to reflect changes in our practices or relevant laws. We encourage you to periodically review this page for the latest information on our cookie practices.

## Contact us

If you have any questions or concerns about this Cookies Policy, please contact us at [support@hacktricks.xyz](mailto:support@hacktricks.xyz).

---

# Security notes for pentesters & developers (2023 – 2025)

> The following section summarises recent browser changes, attack trends and defensive measures that anyone building or assessing web applications should know about. It does **not** affect the legal policy above, but complements it with offensive/defensive insights.

## 1. Recent browser changes impacting cookies

| Year | Browser | Change | Practical impact |
|------|---------|--------|------------------|
| 2025 | Chrome | **Phase-out of third-party cookies** (Privacy Sandbox) starts rolling out to 100 % of users. The `Partitioned` attribute ("CHIPS") is now available by default. | Tracking cookies will disappear; legitimate cross-site use-cases must migrate to `Partitioned` or the Storage Access API. Pentesters should expect many legacy apps to break and mis-configure `SameSite=None`.
| 2024 | Safari 16.4 | **ITP 2.3+** limits *all* server-set first-party cookies behind CNAMEs or on mismatching /24 prefixes to **7 days**. | Behaviour-based analytics and tag-manager deployments that rely on long-lived cookies will silently fail for Safari users.
| 2023–2024 | Firefox | **Total Cookie Protection** (state partitioning) shipped to all channels. | Each top-level site gets its own cookie jar, effectively eliminating classic cross-site leaks such as Cookie Tossing.

ℹ️  Use Chrome `DevTools > Application > Storage > Cookies` or the Privacy Sandbox Analysis Tool (PSAT) extension to quickly identify non-compliant cookies and attributes.

## 2. New cookie attributes of interest

* `Partitioned` (CHIPS) – opt-in to a *double-keyed* cookie jar (`host key` + `top-level site`). Must be sent with `Secure` and normally combined with `SameSite=None`.
* `SameSite` default is **Lax** (Chrome 80+, Edge 109+, Firefox 103+, Safari 13+). Explicitly set `SameSite=None; Secure` for cross-site usage.
* `Priority={High|Medium|Low}` – allows the browser to evict low-priority cookies first when reaching per-domain limits (Chrome 118+).

Example secure session cookie header:

```http
Set-Cookie: session=BASE64; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1200; Priority=High
```

## 3. Modern cookie attack surface (2024 – 2025)

1. **Adversary-in-the-Middle (AiTM) phishing** – Reverse-proxy toolkits such as Evilginx 3, Modlishka v3, and Muraena transparently steal session cookies (ESTSAUTH/ESTSAUTHPERSISTENT, SAPISID, etc.) to bypass MFA. FBI and multiple IR firms have reported a surge in such campaigns targeting cloud portals in 2024 citeturn1search0.
2. **Malicious browser extensions** – Custom Chrome/Edge extensions shipped via GPO or sideloaded in Developer Mode can hook `chrome.cookies.*` APIs to exfiltrate real-time auth cookies; several PoCs published in 2025 showed full Azure Entra ID takeover by streaming session cookies citeturn1search3.
3. **Process-memory scraping by infostealers** – Malware families (RedLine, Lumma, RisePro) dump decrypted cookies directly from browser memory, avoiding on-disk encryption.
4. **Legacy issues** – Cookie Tossing, Cookie Monster, oversized Cookie Bombs still apply; see dedicated HackTricks page below.

{{#ref}}
pentesting-web/hacking-with-cookies/README.md
{{#endref}}

## 4. Recommended hardening checklist (server-side)

* Use `HttpOnly; Secure` for every auth/session cookie.
* Prefer `SameSite=Strict` for sensitive areas, fall back to `Lax` where cross-site POSTs are required. Use explicit `None; Secure` only when absolutely necessary.
* Migrate third-party use-cases to **partitioned cookies** (`; Partitioned`) or the Storage Access API.
* Short TTL + *rotating* session identifiers; revoke on logout with
  `Clear-Site-Data: "cookies"`.
* Bind session cookies to additional signals (user-agent hash, IP / ASN heuristics, signed tokens) on the server side.
* Monitor for credential-less login events (cookie replay) in SIEM.

## 5. Testing tips & tools

* **Burp Suite** ➜ *Proxy → HTTP history → right-click «Show response cookies»*; use the *Session Cookie Tracker* extension to detect inconsistent attributes.
* **Chrome/Edge DevTools** ➜ *Application tab* > *Storage* > *Cookies*, Issues tab warns about upcoming 3PC phase-out.
* **PSAT (Privacy Sandbox Analysis Tool)** – DevTools extension by Google to surface all cookies flagged as `SameSite=None` ahead of the 2025 cut-off citeturn0search1.
* **sqlite3 / jq one-liner** to inspect local cookie DBs (Chrome/Edge):

  ```bash
  sqlite3 "$HOME/.config/google-chrome/Default/Cookies" \
      "SELECT host_key, name, encrypted_value FROM cookies WHERE is_secure=0 LIMIT 5;"
  ```

---

## References

* FBI – “Cybercriminals Are Stealing Cookies to Bypass Multifactor Authentication” (Oct 30 2024) citeturn1search0
* Google Privacy Sandbox – “Cookies Having Independent Partitioned State (CHIPS)” docs (2025) citeturn2search0