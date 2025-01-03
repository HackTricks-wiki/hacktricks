# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Es un lenguaje de scripting utilizado para la automatización de tareas **interactuando con procesos remotos**. Facilita bastante **pedir a otros procesos que realicen algunas acciones**. **El malware** puede abusar de estas características para aprovechar funciones exportadas por otros procesos.\
Por ejemplo, un malware podría **inyectar código JS arbitrario en las páginas abiertas del navegador**. O **hacer clic automáticamente** en algunos permisos permitidos solicitados al usuario;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Aquí tienes algunos ejemplos: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Encuentra más información sobre malware usando applescripts [**aquí**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Los scripts de Apple pueden ser fácilmente "**compilados**". Estas versiones pueden ser fácilmente "**decompiladas**" con `osadecompile`

Sin embargo, estos scripts también pueden ser **exportados como "Solo lectura"** (a través de la opción "Exportar..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
y en este caso el contenido no se puede descompilar incluso con `osadecompile`

Sin embargo, todavía hay algunas herramientas que se pueden usar para entender este tipo de ejecutables, [**lee esta investigación para más información**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). La herramienta [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) con [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) será muy útil para entender cómo funciona el script.

{{#include ../../../../../banners/hacktricks-training.md}}
