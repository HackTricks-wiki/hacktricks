# Shadow DOM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Basic Information

Shadow DOM is part of the [Web Components](https://developer.mozilla.org/en-US/docs/Web/Web\_Components) feature suite, which aims to allow JS developers to create reusable custom elements with their functionality encapsulated away from the rest of the website code.

Essentially, you can use the Shadow DOM to **isolate your component's HTML and CSS from the rest of the webpage**. For example, if you create element IDs in a shadow DOM, they **will not conflict with element IDs in the parent DOM**. Any CSS selectors you utilize in your shadow DOM will only apply within the shadow DOM and not to the parent DOM, and any selectors you utilize in the parent will not penetrate within the shadow DOM.

```js
// creating a shadow DOM
let $element = document.createElement("div");
$shadowDomRef = $element.attachShadow({ mode: "open" }); // open or closed
```

Normally, when you attach an **"open" shadow DOM to an element**, you can obtain a reference to the shadow DOM with **`$element.shadowRoot`**. However, if the shadow DOM is attached under **"closed"** mode, you **can't obtain a reference** to it this way. Even after reading all developer documentation I could find, I'm still slightly unclear about the purpose of closed mode. [According to Google](https://developers.google.com/web/fundamentals/web-components/shadowdom):

> There's another flavour of shadow DOM called "closed" mode. When you create a **closed** shadow tree, **outside JavaScript won't be able to access the internal DOM of your component**. This is similar to how native elements like `<video>` work. JavaScript cannot access the shadow DOM of `<video>` because the browser implements it using a closed-mode shadow root.

However, they also state:

> Closed shadow roots are not very useful. Some developers will see closed mode as an **artificial security feature**. But let's be clear, it's **not** a security feature.

## Accessing the Shadow DOM

### window.find() and text selections <a href="#introducing-windowfind-and-text-selections" id="introducing-windowfind-and-text-selections"></a>

The function **`window.find("search_text")` penetrates within a shadow DOM**. This function effectively has the same functionality as ctrl-F on a webpage.

It's possible to call **`document.execCommand("SelectAll")`** to expand the selection as **much as possible** and then call **`window.getSelection()`** to **return the contents** of selected text inside the shadow DOM.

In **firefox** you can use `getSelection()` which returns a [Selection](https://developer.mozilla.org/en-US/docs/Web/API/Selection) object, where `anchorElement` is a **reference to an element in the shadow DOM**. So, we can exfiltrate contents of the shadow DOM as follows:

```js
getSelection().anchorNode.parentNode.parentNode.parentNode.innerHTML
```

But this doesn't work in Chromium.

### contenteditable or CSS injection <a href="#contenteditable-or-css-injection" id="contenteditable-or-css-injection"></a>

One way we might be able to interact with the shadow DOM is if we have an **HTML or JS injection inside of it**. There are some interesting situations where you can obtain injection within a shadow DOM where you wouldn't be able to on a normal crossorigin page.

One example, is if you have any **elements with the `contenteditable` attribute**. This is a deprecated and little used HTML attribute that declares the **content of that element to be user-editable**. We can use selections along with the **`document.execCommand`** API to interact with a contenteditable element and obtain an HTML injection!

```js
find('selection within contenteditable');

document.execCommand('insertHTML',false,'<svg/onload=console.log(this.parentElement.outerHTML)>')
```

Perhaps even more interestingly, **`contenteditable`** can be declared on any element in chromium by applying a deprecated **CSS property: `-webkit-user-modify:read-write`**

This allows us to **elevate a CSS/style injection into an HTML injection**, by adding the CSS property to an element, and then utilizing the `insertHTML` command.

## CTF

Check this writeup where this technique was used as a CTF challenge: [https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md](https://github.com/Super-Guesser/ctf/blob/master/2022/dicectf/shadow.md)

## References

* [https://blog.ankursundara.com/shadow-dom/](https://blog.ankursundara.com/shadow-dom/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
