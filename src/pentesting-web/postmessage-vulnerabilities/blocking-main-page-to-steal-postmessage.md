# Blocking main page to steal postmessage

{{#include ../../banners/hacktricks-training.md}}

## Winning RCs with Iframes

According to this [**Terjanq writeup**](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710) blob documents created from null origins are isolated for security benefits, which means that if you maintain busy the main page, the iframe page is going to be executed.

Basically in that challenge an **isolated iframe is executed** and right **after** it's **loaded** the **parent** page is going to **send a post** message with the **flag**.\
However, that postmessage communication is **vulnerable to XSS** (the **iframe** can execute JS code).

Therefore, the goal of the attacker is to **let the parent create the iframe**, but **before** let the **parent** page **send** the sensitive data (**flag**) **keep it busy** and send the **payload to the iframe**. While the **parent is busy** the **iframe executes the payload** which will be some JS that will listen for the **parent postmessage message and leak the flag**.\
Finally, the iframe has executed the payload and the parent page stops being busy, so it sends the flag and the payload leaks it.

But how could you make the parent be **busy right after it generated the iframe and just while it's waiting for the iframe to be ready to send the sensitive data?** Basically, you need to find **async** **action** you could make the parent **execute**. For example, in that challenge the parent was **listening** to **postmessages** like this:

```javascript
window.addEventListener("message", (e) => {
  if (e.data == "blob loaded") {
    $("#previewModal").modal()
  }
})
```

so it was possible to send a **big integer in a postmessage** that will be **converted to string** in that comparison, which will take some time:

```bash
const buffer = new Uint8Array(1e7);
win?.postMessage(buffer, '*', [buffer.buffer]);
```

And in order to be precise and **send** that **postmessage** just **after** the **iframe** is created but **before** it's **ready** to receive the data from the parent, you will need to **play with the miliseconds of a `setTimeout`**.

{{#include ../../banners/hacktricks-training.md}}



