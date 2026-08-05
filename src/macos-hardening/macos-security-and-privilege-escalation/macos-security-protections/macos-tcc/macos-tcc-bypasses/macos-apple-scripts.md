# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

这是一种用于任务自动化的脚本语言，可**与远程进程交互**。它可以非常容易地**请求其他进程执行某些操作**。**Malware** 可能会滥用这些功能，以滥用其他进程导出的函数。\
例如，Malware 可以**向浏览器打开的页面注入任意 JS 代码**，或**自动点击**向用户请求的某些允许权限；<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
这里有一些示例：[https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
在[**这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)查看更多关于使用 applescripts 的 malware 信息。

### Automation / TCC quirks

Apple Events approvals 是**有方向性的**：提示针对的是一个 **source process -> target process** 对。用户点击 **Allow** 后，来自同一 source、发往同一 target 的后续请求都会被允许，直到该条目被重置。在测试期间，只需授予一次 `Terminal -> Finder` 或 `Terminal -> System Events` 权限，之后即可重复使用该权限，而不会再次弹出提示。<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
当 **target** 是 **Finder** 时，这一点尤其重要，因为即使 Finder 没有出现在 FDA UI 中，它也始终拥有 **Full Disk Access**。因此，任何已经对 Finder 具有 Automation 权限的 host，都可以用作 AppleScript/JXA proxy，以访问受 TCC 保护的文件。<sup>[1]</sup> 通用的 Finder 和 System Events payload 已记录在[主要 TCC 页面](../README.md)和 [Apple Events 页面](../macos-apple-events.md)中。

### 现代攻击技艺

`/usr/bin/osascript` 只是最明显的入口点。AppleScript 和 JXA 还可以通过 **Mach-O binaries** 中的 **`NSAppleScript`** / **`OSAScript`** 执行，这对于规避检测，以及驻留在已经拥有有价值 TCC grants 的 host 中都很有用。<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
如果你构建一个直接发送 Apple Events 的自定义 helper，为其提供一个**真实的 app identity**，可以让测试和操作更加可靠。实际操作中，这意味着嵌入包含 `CFBundleIdentifier` 和 `NSAppleEventsUsageDescription` 的 `Info.plist`，对二进制文件进行签名，并授予 `com.apple.security.automation.apple-events` entitlement。否则，Apple Events prompt 通常会被归因于**父级 host**（例如 `Terminal`），或者 `NSAppleScript` 执行会因令人困惑的 `-1750` / `errOSASystemError` errors 而失败。<sup>[2]</sup>

Apple scripts 可以轻松地进行 "**compiled**"。这些版本可以使用 `osadecompile` 轻松地进行 "**decompiled**"

不过，这些 scripts 也可以通过 "Export..." 选项导出为 **"Read only"**：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
而且在这种情况下，即使使用 `osadecompile` 也无法对内容进行反编译。

不过，仍然有一些工具可以帮助理解这类可执行文件，[**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> 工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 配合 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) 将非常有助于理解脚本的工作方式。

## 参考资料

- [1] [意外和蓄意绕过 macOS TCC 用户隐私保护](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [在 macOS CLI 工具中使用 AppleScript：未记录的部分](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [攻击者如何使用 AppleScript 攻击 macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | 逆向分析恶意 Run-Only AppleScript 的经历](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
