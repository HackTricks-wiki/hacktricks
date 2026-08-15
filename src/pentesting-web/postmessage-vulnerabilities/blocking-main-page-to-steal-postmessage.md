# Blocking the Main Page to Steal a `postMessage`

{{#include ../../banners/hacktricks-training.md}}

## Winning RCs with Iframes

According to this [**Terjanq writeup**](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710), blob documents created from `null` origins can end up **process-isolated** from the parent page. This makes an interesting race possible: if you can force the **parent** window to spend enough time inside a synchronous code path, a malicious **child** document may still keep running, finish bootstrapping its JS, register `onmessage`, and steal the next sensitive `postMessage`.<sup>[[1]](#references)</sup>

A simplified vulnerable flow is:

```javascript
iframe.addEventListener(
  "load",
  () => {
    iframe.contentWindow?.postMessage(secret, "*")
  },
  { once: true }
)

window.addEventListener("message", (e) => {
  if (e.data == "blob loaded") {
    $("#previewModal").modal()
  }
})
```

Therefore, the goal of the attacker is to **let the parent create the iframe**, but **before** the **parent** page **sends** the sensitive data, **keep it busy** and send a **payload to the child iframe**. While the **parent** is busy, the **iframe** executes attacker-controlled JS, installs `onmessage`, and waits for the next sensitive `postMessage`. Once the parent becomes responsive again, it sends the secret and the malicious child leaks it.

A practical flow is usually:

1. Trigger the victim to create/load the target iframe.
2. Detect when the child exists (`win.length === 1`, `frames.length > 0`, or similar heuristics).
3. Send a message that reaches an **expensive synchronous gadget** in the parent.
4. While the parent event loop is stalled, send your payload to the child iframe.
5. Let the payload leak the next secret the parent sends to the child.

### Blocking gadgets

The original 2022 challenge used a **loose comparison** gadget:<sup>[[1]](#references)</sup>

```javascript
window.addEventListener("message", (e) => {
  if (e.data == "blob loaded") {
    $("#previewModal").modal()
  }
})
```

Because `==` coerces non-strings, a large `Uint8Array`/`ArrayBuffer` can make the parent spend noticeable time converting attacker-controlled data to a string:

```javascript
const buffer = new Uint8Array(1e7)
victim.postMessage(buffer, "*", [buffer.buffer])
```

Passing the `ArrayBuffer` in the **transfer list** transfers ownership and detaches it from the sender instead of copying its contents. Whether this produces a useful delay in the receiver remains browser-, size-, and gadget-dependent.<sup>[[3]](#references)</sup>

Recent Postviewer variants showed that **any attacker-controlled synchronous work reachable from the parent's `message` handler** can be enough. Examples worth hunting for are loops over attacker-controlled lengths or debug leftovers such as:

```javascript
window.onmessage = (e) => {
  if (e.data.type === "share") {
    for (let i = 0; i < e.data.files.length; i++) {
      // expensive per-file work
    }
  }

  if (e.data.slow) {
    for (let i = 0; i < e.data.slow; i++) {}
  }
}
```

So, when auditing, don't only look for a `==` coercion gadget: also look for loops over attacker-controlled `length` fields, debug leftovers, or any other synchronous path reachable **before** the sensitive `postMessage` is sent. Conceptually this abuses the same single-thread primitive used in [busy event loop XS-Leaks](../xs-search/README.md#busy-event-loop), but here the goal is to arm the malicious child before the parent resumes.

### Timing the race

The race window is usually only a few milliseconds, so use cheap synchronization signals before firing the slow gadget:

- Poll for `win.length === 1` / `frames.length > 0` to know when the child exists.
- Reuse a single popup/window across attempts to reduce navigation jitter.
- Tune small `setTimeout` delays empirically for the browser/hardware being attacked.
- If the victim uses wildcard `postMessage(..., "*")`, keep sending until the child payload is definitely installed.

### Popup / non-frameable variant

A useful 2025 evolution of the same idea appeared in **Postviewer v5²**. When the target page was **not frameable**, the race was still winnable from a **popup**. Instead of directly changing `iframe.location`, the attacker used a child/popup payload that **continuously reloads itself**, creating another `onload` just before the victim cleans up its listener:<sup>[[2]](#references)</sup>

```html
<script>
setTimeout(() => {
  location = URL.createObjectURL(
    new Blob([document.documentElement.innerHTML], { type: "text/html" })
  )
}, 150)
</script>
```

This turns the primitive into:

1. Open the target in a popup.
2. Get the victim to render a self-reloading attacker-controlled document.
3. Render a second payload whose only job is to install `onmessage` and leak the next secret.
4. Stall the opener/main page with one of the blocking gadgets above.
5. When the opener resumes, it may deliver the sensitive `postMessage` to the attacker payload **before** it processes the child's cleanup/ack message.

This is handy when you only control a `window.open()` flow, or when frame restrictions stop you from directly hijacking nested iframe locations.

## Defensive checks

The race only matters when a sensitive message is sent to a window whose document can become attacker-controlled. Use an exact `targetOrigin` instead of `"*"`, validate both `event.origin` and `event.source` on receipt, keep untrusted input away from synchronous pre-send handlers, and re-check the destination window's expected lifecycle before releasing a secret. These controls address the trust failure even if timing changes across browser versions.<sup>[[3]](#references)</sup>

## References

- [1] [Terjanq writeup - Winning RCs with Iframes](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710)
- [2] [Terjanq writeup - Postviewer v5² (Google CTF 2025)](https://gist.github.com/terjanq/e66c2843b5b73aa48405b72f4751d5f8)
- [3] [MDN - `Window.postMessage()` security and transferable-object guidance](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

{{#include ../../banners/hacktricks-training.md}}
