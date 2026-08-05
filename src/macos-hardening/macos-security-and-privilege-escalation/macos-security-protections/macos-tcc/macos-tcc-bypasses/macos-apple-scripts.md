# Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es un lenguaje de scripting utilizado para la automatización de tareas **interactuando con procesos remotos**. Facilita bastante **pedir a otros procesos que realicen determinadas acciones**. El **malware** puede abusar de estas funcionalidades para abusar de las funciones exportadas por otros procesos.\
Por ejemplo, un malware podría **inyectar código JS arbitrario en páginas abiertas del navegador**. O **hacer clic automáticamente** en algunos permisos de autorización solicitados al usuario;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aquí tienes algunos ejemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encuentra más información sobre malware que utiliza applescripts [**aquí**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

### Automatización / particularidades de TCC

Las aprobaciones de Apple Events son **direccionales**: el aviso corresponde a un par **proceso de origen -> proceso de destino**. Una vez que el usuario hace clic en **Allow**, las solicitudes futuras del mismo origen al mismo destino se permiten hasta que se restablezca la entrada. Durante las pruebas, conceder permiso una vez a `Terminal -> Finder` o `Terminal -> System Events` es suficiente para reutilizarlo más adelante sin que aparezca otro aviso.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Esto es especialmente relevante cuando el **objetivo** es **Finder**, porque Finder siempre tiene **Full Disk Access**, incluso si no aparece en la interfaz de usuario de FDA. Por lo tanto, cualquier host que ya tenga Automation sobre Finder puede utilizarse como proxy de AppleScript/JXA para acceder a archivos protegidos por TCC.<sup>[1]</sup> Los payloads genéricos de Finder y System Events ya están documentados en [the main TCC page](../README.md) y en [the Apple Events page](../macos-apple-events.md).

### Técnicas ofensivas modernas

`/usr/bin/osascript` es solo el punto de entrada más visible. AppleScript y JXA también pueden ejecutarse desde **Mach-O binaries** mediante **`NSAppleScript`** / **`OSAScript`**, lo que resulta útil tanto para la evasión como para operar dentro de un host que ya tenga permisos TCC interesantes.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si construyes un helper personalizado que envíe Apple Events directamente, darle una **identidad de aplicación real** hace que las pruebas y las operaciones sean mucho más fiables. En la práctica, esto significa incluir un `Info.plist` con `CFBundleIdentifier` y `NSAppleEventsUsageDescription`, firmar el binario y conceder el entitlement `com.apple.security.automation.apple-events`. De lo contrario, el aviso de Apple Events suele atribuirse al **host principal** (por ejemplo, `Terminal`) o la ejecución de `NSAppleScript` simplemente falla con errores confusos `-1750` / `errOSASystemError`.<sup>[2]</sup>

Los scripts de Apple pueden "**compiled**" fácilmente. Estas versiones pueden "**decompiled**" fácilmente con `osadecompile`

Sin embargo, estos scripts también pueden **exportarse como "Solo lectura"** (mediante la opción "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
y en este caso el contenido no puede descompilarse ni siquiera con `osadecompile`

Sin embargo, todavía existen algunas herramientas que pueden utilizarse para comprender este tipo de ejecutables; [**lee esta investigación para obtener más información**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> La herramienta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler), junto con [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), será muy útil para comprender cómo funciona el script.

## Referencias

- [1] [Elusión accidental y deliberada de las protecciones de privacidad de usuarios de macOS mediante TCC](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Cómo hacer que AppleScript funcione en herramientas CLI de macOS: los aspectos no documentados](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Cómo los actores ofensivos utilizan AppleScript para atacar macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventuras en la ingeniería inversa de AppleScripts maliciosos Run-Only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}
