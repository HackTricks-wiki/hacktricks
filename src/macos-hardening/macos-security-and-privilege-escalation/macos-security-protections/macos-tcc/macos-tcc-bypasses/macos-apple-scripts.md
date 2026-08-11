# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript 是一种自动化语言，可以向支持脚本的应用程序发送 Apple Events。在获得相关授权后，恶意软件可以将 JavaScript 注入支持脚本的浏览器标签页，或使用 System Events/Accessibility 点击权限对话框。Apple Events 和 Accessibility 是不同的 TCC 服务，通常需要用户分别批准。<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository 包含自动化示例。<sup>[[7]](#references)</sup>\
在[**这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)了解更多关于使用 applescripts 的 malware 信息。<sup>[[3]](#references)</sup>

### 自动化 / TCC 特性

Apple Events 的授权是**有方向性的**：提示针对的是**源进程 -> 目标进程**这一对进程。用户点击 **Allow** 后，来自同一源进程到同一目标进程的后续请求都会被允许，直到该条目被重置。在测试期间，只需授予一次 `Terminal -> Finder` 或 `Terminal -> System Events` 权限，之后即可重复使用该权限，而不会再次弹出提示。<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
当 **target** 是 **Finder** 时，这一点尤其相关，因为即使 Finder 没有显示在 FDA UI 中，它也始终拥有 **Full Disk Access**。因此，任何已经对 Finder 拥有 Automation 权限的 host，都可以作为 AppleScript/JXA proxy 来访问受 TCC 保护的文件。<sup>[[1]](#references)</sup> 通用的 Finder 和 System Events payload 已记录在[主 TCC 页面](../README.md)和 [Apple Events 页面](../macos-apple-events.md)中。

### Modern offensive tradecraft

`/usr/bin/osascript` 只是最显眼的入口点。AppleScript 和 JXA 也可以通过 **`NSAppleScript`** / **`OSAScript`** 从 **Mach-O binaries** 中执行，这既有利于规避检测，也可以在已经拥有有价值 TCC grants 的 host 中运行。<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
如果你构建一个直接发送 Apple Events 的自定义 helper，为其提供一个**真实的 app identity**可以让测试和操作更加可靠。实际上，这意味着嵌入包含 `CFBundleIdentifier` 和 `NSAppleEventsUsageDescription` 的 `Info.plist`、对 binary 进行签名，并授予 `com.apple.security.automation.apple-events` entitlement。否则，Apple Events prompt 通常会归因于**父级 host**（例如 `Terminal`），或者 `NSAppleScript` 执行会直接失败，并出现令人困惑的 `-1750` / `errOSASystemError` errors。<sup>[[2]](#references)</sup>

AppleScripts 可以保存为 compiled form，通常可以使用 `osadecompile` 进行 decompile。

不过，这些 scripts 也可以通过“Export...”选项导出为 **“Read only”**：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
在这种情况下，`osadecompile` 会拒绝还原普通源代码，但仍然可以分析 bytecode 和 Apple Event 术语。

SentinelOne 关于 run-only 的研究介绍了如何在此限制下恢复结构。`applescript-disassembler` 和 `aevt_decompile` 可帮助检查已编译的脚本和 Apple Event 数据。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [意外及有意绕过 macOS TCC User Privacy Protections](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [让 AppleScript 在 macOS CLI Tools 中运行：未公开的部分](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [攻击者如何使用 AppleScript 攻击 macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | 逆向恶意 Run-Only AppleScripts 的经历](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts 示例](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
