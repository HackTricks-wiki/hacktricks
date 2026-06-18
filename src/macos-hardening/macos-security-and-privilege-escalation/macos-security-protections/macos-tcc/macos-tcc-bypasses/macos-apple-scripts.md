# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es un lenguaje de scripting usado para la automatización de tareas **interactuando con procesos remotos**. Hace muy fácil **pedir a otros procesos que realicen algunas acciones**. **Malware** puede abusar de estas funciones para abusar de funciones exportadas por otros procesos.\
Por ejemplo, un malware podría **inyectar código JS arbitrario en páginas abiertas del navegador**. O **auto click** en algunos permisos de allow solicitados al usuario;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aquí tienes algunos ejemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encuentra más información sobre malware usando applescripts [**aquí**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automation / TCC quirks

Las aprobaciones de Apple Events son **directional**: el prompt es para un par **source process -> target process**. Una vez que el usuario hace clic en **Allow**, las solicitudes futuras desde el mismo source al mismo target están permitidas hasta que la entrada se restablece. Durante las pruebas, conceder `Terminal -> Finder` o `Terminal -> System Events` una vez es suficiente para reutilizar el permiso más tarde sin otro popup.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Esto es especialmente relevante cuando el **target** es **Finder**, porque Finder siempre tiene **Full Disk Access** incluso si no aparece en la UI de FDA. Por lo tanto, cualquier host que ya tenga Automation sobre Finder puede usarse como un proxy de AppleScript/JXA para acceder a archivos protegidos por TCC. Los payloads genéricos de Finder y System Events ya están documentados en [la página principal de TCC](../README.md) y en [la página de Apple Events](../macos-apple-events.md).

### Modern offensive tradecraft

`/usr/bin/osascript` es solo el punto de entrada más visible. AppleScript y JXA también pueden ejecutarse desde **Mach-O binaries** mediante **`NSAppleScript`** / **`OSAScript`**, lo cual es útil tanto para evasion como para vivir dentro de un host que ya tiene grants TCC interesantes.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si construyes un helper personalizado que envía Apple Events directamente, darle una **identidad real de app** hace que las pruebas y las operaciones sean mucho más fiables. En la práctica, esto significa incrustar un `Info.plist` con `CFBundleIdentifier` y `NSAppleEventsUsageDescription`, firmar el binario y conceder el entitlement `com.apple.security.automation.apple-events`. De lo contrario, el prompt de Apple Events a menudo se atribuye al **parent host** (por ejemplo `Terminal`) o la ejecución de `NSAppleScript` simplemente falla con errores confusos `-1750` / `errOSASystemError`.

Los Apple scripts pueden "**compilarse**" fácilmente. Estas versiones pueden "**descompilarse**" fácilmente con `osadecompile`

Sin embargo, estos scripts también pueden exportarse como "**Read only**" (a través de la opción "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
y en este caso el contenido no puede ser descompilado incluso con `osadecompile`

Sin embargo, todavía hay algunas herramientas que se pueden usar para entender este tipo de ejecutables, [**lee esta investigación para más info**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). La herramienta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) será muy útil para entender cómo funciona el script.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}
