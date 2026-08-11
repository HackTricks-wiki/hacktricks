# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript es un lenguaje de automatización que puede enviar Apple Events a aplicaciones compatibles con scripting. Con los grants relevantes, el malware puede inyectar JavaScript en una pestaña de un navegador compatible con scripting o usar System Events/Accessibility para hacer clic en un diálogo de permisos. Apple Events y Accessibility son servicios TCC distintos y, por lo general, requieren las aprobaciones de usuario correspondientes.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
El repositorio `abbeycode/AppleScripts` contiene ejemplos de automatización.<sup>[[7]](#references)</sup>\
Encuentra más información sobre malware que utiliza applescripts [**aquí**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automatización / peculiaridades de TCC

Las aprobaciones de Apple Events son **direccionales**: el aviso corresponde a un par de **proceso de origen -> proceso de destino**. Una vez que el usuario hace clic en **Allow**, las solicitudes futuras del mismo origen al mismo destino se permiten hasta que se restablezca la entrada. Durante las pruebas, conceder una vez `Terminal -> Finder` o `Terminal -> System Events` es suficiente para reutilizar el permiso más adelante sin otra ventana emergente.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Esto es especialmente relevante cuando el **objetivo** es **Finder**, porque Finder siempre tiene **Full Disk Access**, aunque no aparezca en la interfaz de usuario de FDA. Por lo tanto, cualquier host que ya tenga Automation sobre Finder puede utilizarse como proxy de AppleScript/JXA para acceder a archivos protegidos por TCC.<sup>[[1]](#references)</sup> Los payloads genéricos de Finder y System Events ya están documentados en [la página principal de TCC](../README.md) y en [la página de Apple Events](../macos-apple-events.md).

### Técnicas ofensivas modernas

`/usr/bin/osascript` es solo el punto de entrada más visible. AppleScript y JXA también pueden ejecutarse desde **binarios Mach-O** mediante **`NSAppleScript`** / **`OSAScript`**, lo que resulta útil tanto para la evasión como para operar dentro de un host que ya tenga permisos TCC interesantes.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Si construyes un helper personalizado que envíe Apple Events directamente, darle una **identidad real de aplicación** hace que las pruebas y las operaciones sean mucho más fiables. En la práctica, esto implica incluir un `Info.plist` con `CFBundleIdentifier` y `NSAppleEventsUsageDescription`, firmar el binario y conceder el entitlement `com.apple.security.automation.apple-events`. De lo contrario, el aviso de Apple Events suele atribuirse al **host principal** (por ejemplo, `Terminal`) o la ejecución de `NSAppleScript` simplemente falla con errores confusos `-1750` / `errOSASystemError`.<sup>[[2]](#references)</sup>

Los AppleScripts se pueden guardar en formato compilado y normalmente descompilarse con `osadecompile`.

Sin embargo, estos scripts también se pueden **exportar como "Read only"** (mediante la opción "Export..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
En ese caso, `osadecompile` se niega a recuperar el código fuente normal, pero el bytecode y la terminología de Apple Event aún pueden analizarse.

La investigación de SentinelOne sobre run-only describe cómo recuperar la estructura a pesar de esa restricción. `applescript-disassembler` y `aevt_decompile` ayudan a inspeccionar el script compilado y los datos de Apple Event.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Omitiendo las protecciones de privacidad de usuario de macOS TCC por accidente y diseño](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Hacer que AppleScript funcione en herramientas CLI de macOS: las partes no documentadas](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Cómo los actores ofensivos usan AppleScript para atacar macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Aventuras en la ingeniería inversa de AppleScripts maliciosos run-only](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [Ejemplos de AppleScripts de abbeycode](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}
