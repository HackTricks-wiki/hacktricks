# DOM XSS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **DOM vulnerabilities**

> **Sources**
>
> A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.

> **Sinks**
>
> A sink is a potentially dangerous JavaScript function or DOM object that can cause undesirable effects if attacker-controlled data is passed to it. For example, the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when a website **passes data from a source to a sink**, which then handles the data in an unsafe way in the context of the client's session.

{% hint style="info" %}
**You can find a more updated list of sources and sinks in** [**https://github.com/wisec/domxsswiki/wiki**](https://github.com/wisec/domxsswiki/wiki)
{% endhint %}

**Common sources:**

```javascript
document.URL
document.documentURI
document.URLUnencoded
document.baseURI
location
document.cookie
document.referrer
window.name
history.pushState
history.replaceState
localStorage
sessionStorage
IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)
Database
```

**Common Sinks:**

| [**Open Redirect**](dom-xss.md#open-redirect)                                    | [**Javascript Injection**](dom-xss.md#javascript-injection)                         | [**DOM-data manipulation**](dom-xss.md#dom-data-manipulation) | **jQuery**                                                             |
| -------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `location`                                                                       | `eval()`                                                                            | `scriptElement.src`                                           | `add()`                                                                |
| `location.host`                                                                  | `Function() constructor`                                                            | `scriptElement.text`                                          | `after()`                                                              |
| `location.hostname`                                                              | `setTimeout()`                                                                      | `scriptElement.textContent`                                   | `append()`                                                             |
| `location.href`                                                                  | `setInterval()`                                                                     | `scriptElement.innerText`                                     | `animate()`                                                            |
| `location.pathname`                                                              | `setImmediate()`                                                                    | `someDOMElement.setAttribute()`                               | `insertAfter()`                                                        |
| `location.search`                                                                | `execCommand()`                                                                     | `someDOMElement.search`                                       | `insertBefore()`                                                       |
| `location.protocol`                                                              | `execScript()`                                                                      | `someDOMElement.text`                                         | `before()`                                                             |
| `location.assign()`                                                              | `msSetImmediate()`                                                                  | `someDOMElement.textContent`                                  | `html()`                                                               |
| `location.replace()`                                                             | `range.createContextualFragment()`                                                  | `someDOMElement.innerText`                                    | `prepend()`                                                            |
| `open()`                                                                         | `crypto.generateCRMFRequest()`                                                      | `someDOMElement.outerText`                                    | `replaceAll()`                                                         |
| `domElem.srcdoc`                                                                 | **\`\`**[**Local file-path manipulation**](dom-xss.md#local-file-path-manipulation) | `someDOMElement.value`                                        | `replaceWith()`                                                        |
| `XMLHttpRequest.open()`                                                          | `FileReader.readAsArrayBuffer()`                                                    | `someDOMElement.name`                                         | `wrap()`                                                               |
| `XMLHttpRequest.send()`                                                          | `FileReader.readAsBinaryString()`                                                   | `someDOMElement.target`                                       | `wrapInner()`                                                          |
| `jQuery.ajax()`                                                                  | `FileReader.readAsDataURL()`                                                        | `someDOMElement.method`                                       | `wrapAll()`                                                            |
| `$.ajax()`                                                                       | `FileReader.readAsText()`                                                           | `someDOMElement.type`                                         | `has()`                                                                |
| **\`\`**[**Ajax request manipulation**](dom-xss.md#ajax-request-manipulation)    | `FileReader.readAsFile()`                                                           | `someDOMElement.backgroundImage`                              | `constructor()`                                                        |
| `XMLHttpRequest.setRequestHeader()`                                              | `FileReader.root.getFile()`                                                         | `someDOMElement.cssText`                                      | `init()`                                                               |
| `XMLHttpRequest.open()`                                                          | `FileReader.root.getFile()`                                                         | `someDOMElement.codebase`                                     | `index()`                                                              |
| `XMLHttpRequest.send()`                                                          | [**Link manipulation**](dom-xss.md#link-manipulation)                               | `someDOMElement.innerHTML`                                    | `jQuery.parseHTML()`                                                   |
| `jQuery.globalEval()`                                                            | `someDOMElement.href`                                                               | `someDOMElement.outerHTML`                                    | `$.parseHTML()`                                                        |
| `$.globalEval()`                                                                 | `someDOMElement.src`                                                                | `someDOMElement.insertAdjacentHTML`                           | [**Client-side JSON injection**](dom-xss.md#client-side-sql-injection) |
| **\`\`**[**HTML5-storage manipulation**](dom-xss.md#html-5-storage-manipulation) | `someDOMElement.action`                                                             | `someDOMElement.onevent`                                      | `JSON.parse()`                                                         |
| `sessionStorage.setItem()`                                                       | [**XPath injection**](dom-xss.md#xpath-injection)                                   | `document.write()`                                            | `jQuery.parseJSON()`                                                   |
| `localStorage.setItem()`                                                         | `document.evaluate()`                                                               | `document.writeln()`                                          | `$.parseJSON()`                                                        |
| **``**[**`Denial of Service`**](dom-xss.md#denial-of-service)**``**              | `someDOMElement.evaluate()`                                                         | `document.title`                                              | **\`\`**[**Cookie manipulation**](dom-xss.md#cookie-manipulation)      |
| `requestFileSystem()`                                                            | **\`\`**[**Document-domain manipulation**](dom-xss.md#document-domain-manipulation) | `document.implementation.createHTMLDocument()`                | `document.cookie`                                                      |
| `RegExp()`                                                                       | `document.domain`                                                                   | `history.pushState()`                                         | [**WebSocket-URL poisoning**](dom-xss.md#websocket-url-poisoning)      |
| [**Client-Side SQl injection**](dom-xss.md#client-side-sql-injection)            | [**Web-message manipulation**](dom-xss.md#web-message-manipulation)                 | `history.replaceState()`                                      | `WebSocket`                                                            |
| `executeSql()`                                                                   | `postMessage()`                                                                     | \`\`                                                          | \`\`                                                                   |

The **`innerHTML`** sink doesn't accept `script` elements on any modern browser, nor will `svg onload` events fire. This means you will need to use alternative elements like `img` or `iframe`.

This kind of XSS is probably the **hardest to find**, as you need to look inside the JS code, see if it's **using** any object whose **value you control**, and in that case, see if there is **any way to abuse** it to execute arbitrary JS.

## Tools to find them

* [https://github.com/mozilla/eslint-plugin-no-unsanitized](https://github.com/mozilla/eslint-plugin-no-unsanitized)

## Examples

### Open Redirect

From: [https://portswigger.net/web-security/dom-based/open-redirection](https://portswigger.net/web-security/dom-based/open-redirection)

#### How

DOM-based open-redirection vulnerabilities arise when a script writes **attacker-controllable data** into a **sink** that can trigger **cross-domain navigation**.

Remember that **if you can start the URL** were the victim is going to be **redirected**, you could execute **arbitrary code** like: **`javascript:alert(1)`**

#### Sinks

```
location
location.host
location.hostname
location.href
location.pathname
location.search
location.protocol
location.assign()
location.replace()
open()
domElem.srcdoc
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.ajax()
$.ajax()
```

### Cookie manipulation

From: [https://portswigger.net/web-security/dom-based/cookie-manipulation](https://portswigger.net/web-security/dom-based/cookie-manipulation)

#### How

DOM-based cookie-manipulation vulnerabilities arise when a script writes **attacker-controllable data into the value of a cookie**.\
This could be abuse to make the page behaves on unexpected manner (if the cookie is used in the web) or to perform a [session fixation](../hacking-with-cookies/#session-fixation) attack (if the cookie is used to track the user's session).

#### Sinks

```
document.cookie
```

### JavaScript Injection

From: [https://portswigger.net/web-security/dom-based/javascript-injection](https://portswigger.net/web-security/dom-based/javascript-injection)

#### How

DOM-based JavaScript-injection vulnerabilities arise when a script executes **attacker-controllable data as JavaScript**.

#### Sinks

```
eval()
Function() constructor
setTimeout()
setInterval()
setImmediate()
execCommand()
execScript()
msSetImmediate()
range.createContextualFragment()
crypto.generateCRMFRequest()
```

### Document-domain manipulation

From: [https://portswigger.net/web-security/dom-based/document-domain-manipulation](https://portswigger.net/web-security/dom-based/document-domain-manipulation)

#### How

Document-domain manipulation vulnerabilities arise when a script uses **attacker-controllable data to set** the **`document.domain`** property.

The `document.domain` property is used by browsers in their **enforcement** of the **same origin policy**. If **two pages** from **different** origins explicitly set the **same `document.domain`** value, then those two pages can **interact in unrestricted ways**.\
Browsers **generally enforce some restrictions** on the values that can be assigned to `document.domain`, and may prevent the use of completely different values than the actual origin of the page. **But this doesn't occur always** and they usually **allow to use child** or **parent** domains.

#### Sinks

```
document.domain
```

### WebSocket-URL poisoning

From: [https://portswigger.net/web-security/dom-based/websocket-url-poisoning](https://portswigger.net/web-security/dom-based/websocket-url-poisoning)

#### How

WebSocket-URL poisoning occurs when a script uses **controllable data as the target URL** of a WebSocket connection.

#### Sinks

The `WebSocket` constructor can lead to WebSocket-URL poisoning vulnerabilities.

### Link manipulation

From: [https://portswigger.net/web-security/dom-based/link-manipulation](https://portswigger.net/web-security/dom-based/link-manipulation)

#### How

DOM-based link-manipulation vulnerabilities arise when a script writes **attacker-controllable data to a navigation target** within the current page, such as a clickable link or the submission URL of a form.

#### Sinks

```
someDOMElement.href
someDOMElement.src
someDOMElement.action
```

### Ajax request manipulation

From: [https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation](https://portswigger.net/web-security/dom-based/ajax-request-header-manipulation)

#### How

Ajax request manipulation vulnerabilities arise when a script writes **attacker-controllable data into the an Ajax request** that is issued using an `XmlHttpRequest` object.

#### Sinks

```
XMLHttpRequest.setRequestHeader()
XMLHttpRequest.open()
XMLHttpRequest.send()
jQuery.globalEval()
$.globalEval()
```

### Local file-path manipulation

From: [https://portswigger.net/web-security/dom-based/local-file-path-manipulation](https://portswigger.net/web-security/dom-based/local-file-path-manipulation)

#### How

Local file-path manipulation vulnerabilities arise when a script passes **attacker-controllable data to a file-handling API** as the `filename` parameter. An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause the **user's browser to open/write an arbitrary local file**.

#### Sinks

```
FileReader.readAsArrayBuffer()
FileReader.readAsBinaryString()
FileReader.readAsDataURL()
FileReader.readAsText()
FileReader.readAsFile()
FileReader.root.getFile()
FileReader.root.getFile()
```

### Client-Side SQl injection

From: [https://portswigger.net/web-security/dom-based/client-side-sql-injection](https://portswigger.net/web-security/dom-based/client-side-sql-injection)

#### How

Client-side SQL-injection vulnerabilities arise when a script incorporates **attacker-controllable data into a client-side SQL query in an unsafe way**.

#### Sinks

```
executeSql()
```

### HTML5-storage manipulation

From: [https://portswigger.net/web-security/dom-based/html5-storage-manipulation](https://portswigger.net/web-security/dom-based/html5-storage-manipulation)

#### How

HTML5-storage manipulation vulnerabilities arise when a script **stores attacker-controllable data in the HTML5 storage** of the web browser (either `localStorage` or `sessionStorage`).\
This **behavior does not in itself constitute a security vulnerability**. However, if the application later **reads data back from storage and processes it in an unsafe way**, an attacker may be able to leverage the storage mechanism to deliver other DOM-based attacks, such as cross-site scripting and JavaScript injection.

#### Sinks

```
sessionStorage.setItem()
localStorage.setItem()
```

### XPath injection

From: [https://portswigger.net/web-security/dom-based/client-side-xpath-injection](https://portswigger.net/web-security/dom-based/client-side-xpath-injection)

#### How

DOM-based XPath-injection vulnerabilities arise when a script incorporates **attacker-controllable data into an XPath query**.

#### Sinks

```
document.evaluate()
someDOMElement.evaluate()
```

### Client-side JSON injection

From: [https://portswigger.net/web-security/dom-based/client-side-json-injection](https://portswigger.net/web-security/dom-based/client-side-json-injection)

#### How

DOM-based JSON-injection vulnerabilities arise when a script incorporates **attacker-controllable data into a string that is parsed as a JSON data structure and then processed by the application**.

#### Sinks

```
JSON.parse()
jQuery.parseJSON()
$.parseJSON()
```

### Web-message manipulation

From: [https://portswigger.net/web-security/dom-based/web-message-manipulation](https://portswigger.net/web-security/dom-based/web-message-manipulation)

#### How

Web-message vulnerabilities arise when a script sends **attacker-controllable data as a web message to another document** within the browser.\
**Example** of vulnerable Web-message manipulation in [https://portswigger.net/web-security/dom-based/controlling-the-web-message-source](https://portswigger.net/web-security/dom-based/controlling-the-web-message-source)

#### Sinks

The `postMessage()` method for sending web messages can lead to vulnerabilities if the event listener for receiving messages handles the incoming data in an unsafe way.

### DOM-data manipulation

From: [https://portswigger.net/web-security/dom-based/dom-data-manipulation](https://portswigger.net/web-security/dom-based/dom-data-manipulation)

#### How

DOM-data manipulation vulnerabilities arise when a script writes **attacker-controllable data to a field within the DOM** that is used within the visible UI or client-side logic. An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will modify the appearance or behaviour of the client-side UI.

#### Sinks

```
scriptElement.src
scriptElement.text
scriptElement.textContent
scriptElement.innerText
someDOMElement.setAttribute()
someDOMElement.search
someDOMElement.text
someDOMElement.textContent
someDOMElement.innerText
someDOMElement.outerText
someDOMElement.value
someDOMElement.name
someDOMElement.target
someDOMElement.method
someDOMElement.type
someDOMElement.backgroundImage
someDOMElement.cssText
someDOMElement.codebase
document.title
document.implementation.createHTMLDocument()
history.pushState()
history.replaceState()
```

### Denial of Service

From: [https://portswigger.net/web-security/dom-based/denial-of-service](https://portswigger.net/web-security/dom-based/denial-of-service)

#### How

DOM-based denial-of-service vulnerabilities arise when a script passes **attacker-controllable data in an unsafe way to a problematic platform API**, such as an API whose invocation can cause the user's computer to consume **excessive amounts of CPU or disk space**. This may result in side effects if the browser restricts the functionality of the website, for example, by rejecting attempts to store data in `localStorage` or killing busy scripts.

#### Sinks

```
requestFileSystem()
RegExp()
```

## Dom Clobbering

{% content-ref url="dom-clobbering.md" %}
[dom-clobbering.md](dom-clobbering.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
