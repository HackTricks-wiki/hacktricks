# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

这是一种用于任务自动化的脚本语言，**与远程进程交互**。它让你很容易地**请求其他进程执行某些操作**。**恶意软件**可能滥用这些特性来滥用其他进程导出的功能。\
例如，恶意软件可以在浏览器打开的页面中**注入任意 JS 代码**。或者**自动点击**用户被请求授予的某些允许权限；
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Here you have some examples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
在 [**这里**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) 查找更多关于使用 applescripts 的 malware 信息。

### Automation / TCC quirks

Apple Events approvals are **directional**: 提示针对的是一个 **source process -> target process** 对。 一旦用户点击 **Allow**，来自相同 source 到相同 target 的后续请求就会被允许，直到该条目被重置。在测试中，授予 `Terminal -> Finder` 或 `Terminal -> System Events` 一次，之后就足以复用该权限，而不会再次弹出提示。
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
这点尤其相关，当 **target** 是 **Finder** 时，因为 Finder 始终拥有 **Full Disk Access**，即使它没有出现在 FDA UI 中。因此，任何已经对 Finder 拥有 Automation 的主机，都可以被用作 AppleScript/JXA 代理来访问受 TCC 保护的文件。通用的 Finder 和 System Events payloads 已经在 [the main TCC page](../README.md) 和 [the Apple Events page](../macos-apple-events.md) 中有文档说明。

### Modern offensive tradecraft

`/usr/bin/osascript` 只是最显眼的入口点。AppleScript 和 JXA 也可以通过 **`NSAppleScript`** / **`OSAScript`** 从 **Mach-O binaries** 中执行，这既有助于 evasion，也有助于驻留在一个已经拥有有价值 TCC grants 的 host 中。
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
如果你构建一个直接发送 Apple Events 的自定义 helper，给它一个**真实的 app 身份**会让测试和运维可靠得多。实际上，这意味着要嵌入包含 `CFBundleIdentifier` 和 `NSAppleEventsUsageDescription` 的 `Info.plist`，对二进制文件进行签名，并授予 `com.apple.security.automation.apple-events` entitlement。否则，Apple Events 弹窗经常会被归因于**父宿主**（例如 `Terminal`），或者 `NSAppleScript` 执行会直接失败，并报出令人困惑的 `-1750` / `errOSASystemError` 错误。

Apple scripts 可能很容易被“**编译**”。这些版本可以很容易用 `osadecompile` “**反编译**”

不过，这些脚本也可以被导出为“**只读**”（通过“Export...” 选项）：

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
并且在这种情况下，即使使用 `osadecompile` 也无法反编译

不过，仍然有一些工具可以用来理解这类可执行文件，[**read this research for more info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)。工具 [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) 配合 [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) 对理解脚本如何工作会非常有帮助。

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
