# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatización de WinDbg en modo usuario

{{#ref}}
windbg-automation.md
{{#endref}}

## Análisis de macros en documentos de Office

Para documentos de Office sospechosos, inspecciona [el junk code de las macros VBA y los controles UserForm ocultos](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

## Flujo de control de Windows basado en excepciones

{{#ref}}
../windows-exception-driven-control-flow.md
{{#endref}}

## Depuración del kernel de Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Descompilador de Wasm / compilador de Wat

En línea:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binario) a wat (texto legible)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- También puedes probar [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para la descompilación.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode en caché de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads virtualizados y VM personalizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina varios formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, un ensamblado se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja es que, si se necesita recuperar código fuente perdido a partir de un ensamblado heredado, esto puede ahorrar tiempo. Además, dotPeek facilita la navegación por el código descompilado, lo que lo convierte en una de las herramientas ideales para el **análisis de algoritmos de Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de complementos y una API que amplía la herramienta para adaptarla a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la amplia variedad de funciones de reverse engineering que ofrece esta herramienta:

- Permite ver cómo fluyen los datos a través de una biblioteca o componente
- Permite conocer la implementación y el uso de los lenguajes y frameworks de .NET
- Encuentra funcionalidades no documentadas ni expuestas para aprovechar mejor las API y tecnologías utilizadas.
- Encuentra dependencias y diferentes ensamblados
- Localiza el punto exacto de los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código de .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes usarlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, sin necesidad de descargar el repositorio de git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y **volver a compilar**, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o una bifurcación que se mantiene activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Inspección de código administrado con REA sin ejecución

**REA** puede inspeccionar metadatos PE/CLI y CIL sin cargar el ensamblado. Empieza por identificar el artefacto y luego inspecciona sus miembros y límites nativos declarados; esto resulta útil al revisar llamadas sospechosas antes de usar un descompilador o ejecutar el programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Para comparar versiones, `compare_managed_members` usa la identidad sin procesar de CIL/firmas y fingerprints de instrucciones decodificadas, en lugar de tratar los tokens de metadatos como estables entre compilaciones. Una declaración P/Invoke no demuestra que se haya ejecutado código nativo; `verify_managed_native_boundaries` necesita una exportación nativa coincidente o Evidence de una función para comprobar ese límite. Conserva el digest del artefacto, el MVID y las asignaciones sin resolver junto con el resultado.<sup>[[17]](#references)</sup>

### Registro de DNSpy

Para hacer que **DNSpy registre cierta información en un archivo**, puedes usar este fragmento:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuración de DNSpy

Para depurar código con DNSpy, debes:

Primero, cambiar los **atributos del ensamblado** relacionados con la **depuración**:

![Registro de DNSpy - Depuración de DNSpy: Primero, cambia los atributos del ensamblado relacionados con la depuración](<../../images/image (973).png>)

De:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

A:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

Y haz clic en **compilar**:

![DNSpy Logging - Depuración de DNSpy: haz clic en compilar](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo mediante _**Archivo >> Guardar módulo...**_:

![DNSpy Logging - Depuración de DNSpy: luego guarda el nuevo archivo mediante Archivo Guardar módulo](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código, y es posible que, al depurar, **nunca se alcance un punto de interrupción** o que **algunas variables no existan**.

Luego, si tu aplicación .NET se **ejecuta** en **IIS**, puedes **reiniciarla** con:

```
iisreset /noforce
```

Entonces, para empezar a depurar, cierra todos los archivos abiertos y, dentro de la **Debug Tab**, selecciona **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Entonces, para empezar a depurar, cierra todos los archivos abiertos y, dentro de la Debug Tab, selecciona Attach to Process](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para conectarte al **IIS server** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Luego selecciona w3wp.exe para conectarte al IIS server y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic derecho en cualquier módulo de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Con IDA

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el depurador **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, cuando empieces a depurar, **la ejecución se detendrá cada vez que se cargue una DLL**; por lo tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene cuando se cargan módulos, pero llegar al punto de entrada de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que se describe a continuación.

### Con x64dbg/x32dbg

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la línea de comandos** ( _File --> Change Command Line_ ) e indica la ruta de la DLL y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**; el depurador se detendrá en cada dll main y, en algún momento, **se detendrá en el Entry de tu DLL**. Desde ahí, solo tienes que buscar los puntos donde quieras poner un breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma que la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes en la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de front-end e ingeniería inversa para GNU Project Debugger (GDB), centrada en videojuegos. Sin embargo, se puede usar para cualquier tarea relacionada con la ingeniería inversa.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios descompiladores. Este servicio web permite comparar los resultados de distintos descompiladores en ejecutables pequeños.

### Descifrado de PCK de Godot y recuperación de proyectos

En un juego de Godot distribuido, localiza su PCK en un archivo `.pck` independiente, un paquete adjunto o incrustado en un ejecutable, o en el directorio `assets` de un APK. [gore](https://github.com/figurophobia/gore) puede inspeccionar y extraer el paquete, mientras que la reconstrucción completa de scripts y recursos requiere GDRE Tools (`gore setup` lo instala, o puedes usar `--gdre`). Para este flujo de trabajo, la herramienta admite los formatos PCK v2–v4 de Godot 4.x; puede detectar encabezados v1, pero requiere que se proporcione una clave para v1.<sup>[[25]](#references)</sup>

La recuperación automática de claves requiere una tabla de archivos cifrada; si solo están cifrados los contenidos de los archivos, proporciona una clave conocida. Si la recuperación falla, eso no demuestra que el paquete no esté cifrado.<sup>[[28]](#references)</sup>

La búsqueda de claves **no** es un ataque de fuerza bruta al espacio de claves de AES-256. Una tabla de archivos cifrada expone el MD5 de su texto sin formato, la longitud del texto sin formato, el IV y el texto cifrado AES-256-CFB.<sup>[[27]](#references)</sup> `gore` prueba ventanas de 32 bytes del ejecutable del juego o de archivos cercanos como claves candidatas. Filtra las candidatas según la longitud y el prefijo plausibles de las rutas descifradas, y luego confirma los resultados de los escaneos binarios descifrando la tabla completa y comprobando su MD5.<sup>[[26]](#references)[[28]](#references)</sup> Primero busca en las secciones de datos inicializadas de PE/ELF y, si no encuentra resultados, realiza un escaneo de todo el archivo; `--scan` añade otros archivos candidatos.<sup>[[28]](#references)</sup>

Si no se encuentra ninguna clave incrustada, se prueba una pequeña lista de contraseñas integrada; `--wordlist` permite proporcionar otras candidatas. Cada contraseña se prueba como la representación de clave derivada de contraseña del motor, como un literal rellenado con ceros o como una clave de 64 caracteres hexadecimales. A diferencia de los resultados de los escaneos binarios, los resultados de las listas de palabras solo superan el filtro de estructura de rutas en esta implementación. Confírmalos abriendo el paquete y validando los recursos extraídos.<sup>[[26]](#references)[[28]](#references)</sup>

Con el artefacto del juego disponible localmente, elige la etapa necesaria para el análisis. `recover` invoca GDRE para reconstruir un proyecto que se pueda abrir, mientras que `extract` solo desempaqueta los archivos sin procesar. `key` imprime una clave candidata para usarla con otra herramienta.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Investigación nativa respaldada por evidencias con REA

**REA** expone el análisis de Hopper, Ghidra e IDA a través de CLI y MCP. Requiere Node.js 22.x (al menos 22.19), 24.x (al menos 24.11) o 26+, además de npm. Configura primero un proveedor nativo existente; comprueba `rea providers --json` y selecciona explícitamente un proveedor cuando más de uno sea compatible con el objetivo. Sustituye `0x1000` por un nombre o una dirección de función observados en el inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Empieza con una cadena de funcionalidad o un símbolo, sigue las referencias y los llamadores y, después, inspecciona la ficha de la función seleccionada y el pseudocódigo con `rea decompile`. REA vincula una sesión al provider seleccionado, en lugar de sustituirlo silenciosamente tras un fallo. Para repetir consultas, `--snapshot PATH` reutiliza únicamente los bytes de artefactos, el provider, la configuración, la operación y los parámetros que coincidan; una snapshot es una caché local, no una base de datos del provider guardada. Conserva el Evidence devuelto y los aspectos explícitamente desconocidos, en vez de tratar las rutas inferidas o el texto del decompilador como código fuente original.<sup>[[16]](#references)[[18]](#references)</sup>

Para los puntos de entrada de JavaScript/Electron que conducen a add-ons nativos, consulta [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Análisis con scripts de IDA y Ghidra mediante un bridge TCP local

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) se ejecuta dentro de una base de datos de IDA o un programa de Ghidra CodeBrowser **ya abierto** y permite que un script independiente consulte y modifique esa base de datos de análisis. Ejecuta `ID_Server.py` desde la CLI de Python de IDA (`import ID_Server`) o `Ghidra_Server.py` desde el Script Manager de Ghidra. IDA se vincula a `127.0.0.1` a partir del puerto `5073` y prueba puertos superiores. El script actual de Ghidra empieza en el puerto `5093` y prueba diez puertos hasta `5102`; su socket de Java se vincula a la dirección comodín, no solo a loopback. Comprueba el puerto que muestra la instancia antes de conectarte. A diferencia de un analizador sin interfaz, este bridge opera sobre el programa abierto en ese momento en esa instancia de la GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Envía **un comando terminado en salto de línea por conexión** y lee la respuesta terminada en salto de línea. El resultado suele ser JSON. Por ejemplo, después de encontrar una API importada relacionada con una ruta de entrada, `IMPORTXREF` encuentra sus sitios de llamada; después, `DECOMP_XREF` decompila en lote los llamadores de una dirección seleccionada. `FUNC` inspecciona una función, mientras que `PCODE` devuelve la representación intermedia del decompilador. Usa la dirección de la base de datos activa, no una dirección copiada de un binario con una base de reubicación distinta. El ejemplo siguiente usa el puerto predeterminado de IDA; para Ghidra, usa el puerto que muestra su script.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

El mismo canal puede **cambiar la base de datos de análisis**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` y `PATCH` modifican nombres, tipos, definiciones de estructuras, límites de funciones o bytes almacenados. `PATCH` es una edición de la base de datos, **no** evidencia de un parche en un proceso en ejecución. Ninguno de los dos listeners documenta autenticación. IDA solo escucha en loopback, pero Ghidra puede ser accesible a través de interfaces de red; restringe el acceso al listener de Ghidra cuando lo uses. `QUIT` detiene cualquiera de los dos listeners, e IDA también expone `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depuración de un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) asigna el **shellcode**, imprime su **dirección de memoria** y pausa la ejecución.\
Conecta un debugger como IDA o x64dbg, establece un breakpoint en la dirección impresa y reanuda la ejecución para depurar el shellcode.

La página de releases de GitHub contiene archivos ZIP con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, solo tienes que **crear un proyecto de C/C++ en Visual Studio Code, copiar y pegar el código y compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depuración de un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Asigna el shellcode y entra en un bucle infinito. Conecta el debugger, reanuda la ejecución durante **2–5 segundos**, pausa la ejecución dentro de ese bucle y avanza hasta la siguiente llamada, que transfiere la ejecución al shellcode asignado.

![Debugger pausado en el bucle infinito de jmp2it, justo antes de la llamada al shellcode asignado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depuración de shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite «Open File» y «Open Shellcode». En mi caso, al abrir el shellcode como archivo lo descompiló correctamente, pero al abrirlo como shellcode no:

![Cutter muestra distintos resultados de análisis al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece allí un bp y, al parecer, Cutter iniciará automáticamente la emulación desde ese punto:

![Establecer un breakpoint en la entrada deseada del shellcode antes de iniciar la emulación de Cutter](<../../images/image (589).png>)

![Emulador de Cutter pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![Ver la pila del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Desofuscar shellcode y obtener las funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** usa el shellcode y si el shellcode se está **descodificando** en memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg también cuenta con un iniciador gráfico donde puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Iniciador gráfico de scDbg para seleccionar opciones de emulación y rastreo de shellcode](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se modifica dinámicamente en memoria (útil para descargar el shellcode decodificado). **start offset** puede ser útil para iniciar el shellcode en un desplazamiento específico. La opción **Debug Shell** sirve para depurar el shellcode usando la terminal de scDbg (aunque considero que cualquiera de las opciones explicadas antes es mejor para esto, ya que podrás usar Ida o x64dbg).

### Desensamblar usando CyberChef

Sube tu archivo de shellcode como entrada y usa la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que combinan operadores aritméticos (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, desplazamientos). Lo importante es que estas identidades normalmente solo son correctas con **aritmética modular de ancho fijo**, así que los acarreos y desbordamientos importan:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoró la semántica del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR/salida del decompilador (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
   - **Lineal**: sumas ponderadas de átomos bitwise
   - **Semilineal**: lineal más máscaras constantes como `x & 0xFF`
   - **Polinómica**: aparecen productos
   - **Mixta**: se intercalan productos y lógica bitwise, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** con pruebas aleatorias o una demostración SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de adivinar.

### Evitar el control-flow flattening con un segmento de ejecución acotado

A menudo no es necesario recuperar el grafo de flujo de control completo. Con control-flow flattening, predicados opacos, dispatchers grandes o código con mucho MBA, sigue las referencias desde los blobs cifrados y los buffers de salida hasta la rutina más pequeña que los transforma. Luego reproduce solo ese segmento de flujo de datos o ejecútalo de forma independiente; el dispatcher no forma parte de la solución necesaria si el estado relevante se puede inicializar directamente.<sup>[[7]](#references)</sup>

Un flujo de trabajo práctico es:<sup>[[7]](#references)</sup>

1. Haz un inventario de las secciones ejecutables y de datos, las reubicaciones y las referencias cruzadas. Vuelca las tablas candidatas de `.rodata` conservando el orden de los bytes y el ancho de los elementos.
2. Identifica la última rutina que escribe el texto plano o el buffer de salida. Registra sus entradas, las tablas referenciadas, las llamadas importadas y el estado global necesario.
3. Pasa solo esas operaciones a un modelo Python de ancho fijo. Si el segmento aún depende de demasiado estado, invoca la rutina con Unicorn, QEMU o un depurador y engancha las importaciones irrelevantes en lugar de emular todo el programa.
4. Valida que el extractor realmente derive su salida del binario proporcionado: elimina las alternativas silenciosas, busca respuestas incrustadas y pruébalo con builds no vistos que tengan cadenas, claves, identificadores, layouts y semillas de ofuscación diferentes.

Los comandos útiles para una primera pasada son:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detecta expresiones MBA que ocultan constantes

Una expresión de bytes que aparentemente depende de la entrada puede cancelar por completo dicha entrada. Tras extraer sus tablas, evalúa la expresión en todo el dominio de 8 bits; un conjunto de salida unitario demuestra que ese byte es constante, sin necesidad de recuperar la máquina de estados circundante.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Mantén la máscara final porque la suma original tiene desbordamiento circular al ancho de byte. Para un dominio más amplio, pregunta a un solver SMT si `f(x1) != f(x2)` es satisfacible para dos entradas simbólicas del mismo ancho: `unsat` demuestra la invariancia, mientras que `sat` proporciona un contraejemplo e indica que la entrada no se puede descartar.<sup>[[7]](#references)</sup>

#### Reconocer decodificación ligada al entorno

Las comprobaciones anti-análisis no tienen por qué provocar un salto ni un fallo. Un decoder puede mezclar el resultado de un sensor en un bit de una clave, una constante de un opaque predicate o el estado de un dispatcher aplanado, continuar normalmente y producir texto plano verosímil pero falso en un emulador. Por tanto, parchear solo las ramas de fallo visibles no es suficiente; sigue las dependencias de datos desde las sondas del entorno hasta el estado del decoder, compara el mismo segmento en el dispositivo auténtico y en el emulador, y prueba cómo cambia el búfer final al forzar cada resultado del sensor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador MBA práctico para el análisis de malware y la ingeniería inversa de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados, en lugar de aplicar una única pasada de reescritura genérica a todo.<sup>[[2]](#references)</sup>

Uso rápido:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Casos útiles:

- **Linear MBA**: CoBRA evalúa la expresión con entradas booleanas, obtiene una firma y ejecuta en paralelo varios métodos de recuperación, como el pattern matching, la conversión a ANF y la interpolación de coeficientes.
- **Semilinear MBA**: los átomos con máscaras constantes se reconstruyen mediante una reconstrucción particionada por bits para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en componentes, y las subexpresiones repetidas pueden trasladarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Esto puede simplificarse a:

```c
x * y
```

### Notas de reversing

- Es preferible ejecutar CoBRA sobre **expresiones IR elevadas** o sobre la salida del decompilador después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética enmascarada o de registros estrechos.
- Si necesitas una prueba más sólida, consulta las notas locales de Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **plugin de LLVM pass** (`libCobraPass.so`), útil para normalizar LLVM IR con mucho MBA antes de ejecutar otros pases de análisis.
- Los residuos mixtos de dominios no compatibles que dependen del carry deben considerarse una señal para conservar la expresión original y razonar manualmente sobre la ruta del carry.

## Recuperar el aplanamiento del flujo de control con estado XOR

Un flattener de estilo OLLVM puede mantener el estado del bloque básico actual en dos registros de 64 bits y reconstruirlo con XOR en un dispatcher. Cada bloque original escribe el par correspondiente al siguiente estado y vuelve al dispatcher. Un bloque condicional puede usar `CMOVcc` para sustituir una mitad del par según los flags de la CPU, por lo que seguir únicamente las instrucciones de salto visibles hace que se pasen por alto los dos sucesores. A diferencia de un dispatcher de salto indirecto, esta estructura puede usar back-edges directos en todo el código.<sup>[[19]](#references)[[20]](#references)</sup>

Para recuperar el grafo, identifica el árbol de comparaciones del dispatcher y los dos registros de estado, asigna cada estado XOR comparado a su bloque de destino y luego rastrea las escrituras que alcanzan el par de registros en cada bloque original. Para las escrituras condicionales, incluye la instrucción que establece los flags y ambos resultados de `CMOVcc`. Reescribe la salida del dispatcher de cada bloque como su sucesor directo resuelto o como un salto condicional; así, el dispatcher queda inalcanzable sin modificar el binario. Este es un enfoque de CFG completo; si solo importa un decoder, el [flujo de trabajo de ejecución con un slice reducido](#bypass-flattened-control-flow-with-a-narrow-execution-slice) anterior puede ser más rápido.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatiza esta estructura en Binary Ninja. Copia `plugins/DispatchThis` al directorio de plugins de usuario de Binary Ninja y reinicia. En la función afectada, abre **Function Settings** y selecciona `OLLVM_XOR_64`; si el análisis no empieza, usa **Analysis → Reanalyze All Functions**. Este modo reescribe los edges del flujo de control de MLIL, no los bytes del archivo, y no necesita Z3 ni el resolver de saltos indirectos. Se ha probado en Binary Ninja 5.3.9757+; no elimina las escrituras de estado muertas de cada bloque, así que no las confundas con transiciones activas que aún queden.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador sustituye las operaciones del programa por secuencias de instrucciones basadas en `mov` y usa el manejo de señales/excepciones para alterar el flujo de control. Más información:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para los binarios compatibles, [demovfuscator](https://github.com/kirschju/demovfuscator) puede desofuscar el resultado. Tiene varias dependencias.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, esta solución alternativa para encontrar la flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada**, busca las funciones con `::main`, como en:

![Encontrar un punto de entrada de Rust en Ghidra buscando nombres de funciones con dos puntos dobles y main](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, así que es bastante obvio que esta es la función main de interés.\
Con el **nombre** de las **funciones** a las que se llama, búscalas en **Internet** para averiguar cuáles son sus **entradas** y **salidas**.

### Recuperar cadenas de Rust de firmware ELF

En los binarios **Rust ELF**, muchas cadenas estáticas no se referencian mediante punteros terminados en NUL al estilo de C. Un formato común de `rustc` es una **tupla de puntero/longitud** dentro de **`.data.rel.ro`** que apunta al bloque de cadenas real almacenado en **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Esto significa que `strings` o el análisis predeterminado de Ghidra pueden combinar cadenas adyacentes o pasar por alto por completo las referencias cruzadas.<sup>[[3]](#references)</sup>

Flujo de trabajo rápido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** palabra por palabra.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un puntero a cadena candidato.
4. Trata la palabra siguiente como la longitud candidata.
5. Aplica filtros de cordura (por ejemplo, conserva longitudes de entre **4** y **100** bytes).
6. Lee exactamente `length` bytes de `.rodata` en lugar de buscar hasta `0x00`.

Lógica mínima del extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Esto es especialmente útil en la ingeniería inversa de firmware, porque las cadenas de Rust recuperadas suelen revelar **rutas HTTP, nombres de RPC, mensajes de registro, aserciones, nombres de archivo, claves de configuración, manejadores de comandos y lógica relacionada con la autenticación**.

Si Ghidra no detecta esas cadenas, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de cadena en los offsets de `.rodata` referenciados. Las herramientas `rust-strings` y `RustStrings.py`, publicadas por Pen Test Partners, son buenas referencias para adaptar la idea a otros **tamaños de palabra, órdenes de bytes y disposiciones de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados con Delphi, puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer ingeniería inversa de un binario Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Presiona **Alt+F7** en IDA para cargar un plugin de Python y luego selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al iniciar la depuración. Tras iniciarla, vuelve a presionar el botón Start (el verde o f9) y se activará un breakpoint al comienzo del código real.

Si presionas un botón en la aplicación gráfica, el depurador puede detenerse en la función invocada por ese botón.

## Golang

Para binarios Go convencionales, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) puede recuperar estructuras del runtime y mejorar los nombres de las funciones en IDA. Carga su plugin de Python con **Alt+F7**.

Si tienes que hacer ingeniería inversa de un binario Golang, te sugiero usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Presiona **Alt+F7** en IDA para cargar un plugin de Python y luego selecciona el archivo del plugin.

Esto resolverá los nombres de las funciones.

### Recuperar metadatos sin la tabla de símbolos

Un ejecutable Go sin símbolos sigue necesitando metadatos del runtime para asignar los contadores de programa a las funciones. [GoReSym](https://github.com/mandiant/GoReSym) localiza y analiza estructuras como `pclntab` y `moduledata` usando código derivado del runtime de Go. Esto puede recuperar límites de funciones, nombres, rutas de origen, tipos y detalles de compilación sin depender de la tabla de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator puede dejar esas estructuras utilizables mientras reemplaza los nombres recuperados. Garble, por ejemplo, aplica hash a los identificadores y las rutas de paquetes, y elimina la información de build, módulo y depuración.<sup>[[12]](#references)</sup> El token ofuscado del paquete debe mantenerse coherente entre las funciones de ese paquete. Agrupa las funciones por el token repetido, infiere un paquete a partir de sus funciones llamadas, cadenas y APIs, y luego propaga esa etiqueta de paquete a todo el grupo.<sup>[[13]](#references)</sup>

### Recuperar nombres de Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina la extracción de símbolos del runtime con la generación de referencias limpias y la comparación de grafos de flujo de control (CFG). Usa esta secuencia:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versión del compilador.** Prueba primero `BuildInfo` y las cadenas de versión incrustadas. Si el obfuscator las eliminó, compara partes del runtime de Go incluido con runtimes de referencia versionados. En las pruebas de Volexity, alrededor del `2%` del runtime bastó para distinguir las versiones principales de Go. Tómalo como una optimización empírica, no como un umbral universal.<sup>[[13]](#references)</sup>
2. **Crea referencias coincidentes.** Genera binarios limpios para la versión de Go identificada, la arquitectura de destino y las bibliotecas probables. La coincidencia de la cadena de herramientas reduce las diferencias de CFG generadas por el compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compara las funciones.** GoGrapher compara los CFG de las funciones y genera puntuaciones normalizadas de `0.0` a `1.0`. La comparación de bloques básicos se basa en una comparación ponderada de instrucciones similares. Las coincidencias de alta confianza vinculan las funciones aleatorizadas con la implementación limpia. Las coincidencias más débiles aún pueden identificar un paquete o módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valida e importa.** Confirma los nombres propuestos mediante las relaciones entre llamadas, las constantes, las cadenas y los efectos secundarios; luego importa el informe JSON con el plugin de GoResolver para IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instala la cadena de herramientas y ejecuta el extractor y el comparador de grafos combinados:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

El umbral predeterminado de coincidencia significativa es `0.9`. Las opciones `--extract` y `--graph` permiten aislar cualquiera de las dos etapas, mientras que, de forma predeterminada, se ejecutan ambas porque los metadatos recuperados del runtime y la evidencia del CFG se complementan.<sup>[[10]](#references)</sup> Las puntuaciones del CFG son heurísticas: el inlining, las opciones de compilación, la arquitectura y las diferencias entre versiones de bibliotecas pueden cambiar la forma del grafo, así que conserva las funciones sin resolver en lugar de asignarles nombres con baja confianza.<sup>[[13]](#references)</sup>

### Recuperar la tabla de cadenas de Go

Los binarios de Go colocan los bytes de las cadenas de todos los paquetes enlazados en una tabla contigua. Las entradas no terminan en NUL y las estructuras del runtime no exponen la base ni el tamaño de la tabla. Sin embargo, el compilador ordena las entradas primero por longitud y luego alfabéticamente, en todos los sistemas operativos y arquitecturas. Por lo tanto, después de encontrar una entrada, un analista puede recorrer las entradas adyacentes y usar referencias cruzadas de datos para asociar las cadenas con el código.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatiza este flujo de trabajo en IDA Pro y Ghidra. Espera a que termine el análisis automático, ya que el plugin depende de las referencias cruzadas del segmento de datos. Su ancla predeterminada es la cadena del runtime `entersyscall`; después, puede recorrer la tabla en cualquier dirección, definir las cadenas recuperadas en la base de datos y exportar un mapeo JSON de las cadenas a las funciones que las referencian.<sup>[[14]](#references)</sup>

Filtra el informe por el paquete de la función que hace referencia a la cadena para separar el código de la aplicación o del malware del ruido de las bibliotecas enlazadas. Esta técnica no puede recuperar los literales destruidos por ofuscación, como la transformación `-literals` de Garble. Aun así, puede organizar las cadenas del runtime que permanezcan sin ofuscar.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperar los tipos del runtime de Go

Go incorpora información de tipos del runtime que se utiliza en funciones como la recolección de basura. Cuando se eliminan los datos de compilación o el desensamblador no analiza estos metadatos, las instrucciones pueden parecer cargar direcciones de datos arbitrarias y la región de destino permanece sin tipar. Recuperar los metadatos convierte esas direcciones en referencias de tipos legibles y facilita la comprensión de las capacidades de los paquetes.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) puede extraer símbolos y analizar los tipos del runtime para generar un informe JSON. La CLI actual usa el subcomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

La opción `-y`/`--types` habilita el análisis de tipos. Importa el informe con el plugin de IDA Pro o Ghidra de GoResolver para definir los tipos recuperados y aplicar sus referencias en la base de datos de análisis. En el formato de informe introducido con esta función, si se omite `-y`, los miembros de la dirección RTTI y de los tipos recuperados quedan en null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver admite muestras PE, ELF y Mach-O para x86, AMD64, ARM y ARM64, por lo que se aplica el mismo flujo de trabajo a los binarios de Go de Windows, Linux y macOS.<sup>[[10]](#references)</sup>

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario ELF/EXE compilado de Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si obtienes el **binario** de un juego de GBA, puedes usar distintas herramientas para **emularlo** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Incluye un debugger con interfaz
- [**mgba** ](https://mgba.io)- Incluye un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![Configuración de controles de no$gba que muestra las asignaciones de botones de Game Boy Advance](<../../images/image (581).png>)

Al pulsarlas, cada **tecla tiene un valor** que la identifica:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Así que, en este tipo de programa, lo interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función habitual: **KEYINPUT**.

![Vista de Ghidra de un binario de GBA que hace referencia a KEYINPUT en la dirección 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función se llama desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de inicialización (sin importancia):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

Se encuentra este código:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

El último if comprueba que **`uVar4`** está entre las últimas teclas y no es la tecla actual; también se conoce como soltar un botón (la tecla actual se almacena en **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

En el código anterior puedes ver que estamos comparando **uVar1** (donde está el **valor del botón pulsado**) con algunos valores:

- Primero, se compara con el **valor 4** (botón **SELECT**): en el desafío, este botón borra la pantalla.
- Luego, se compara el valor con **8** (el botón **START**); en este desafío, esa ruta comprueba si el código introducido es válido.
  - En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si el valor coincide, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
  Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Así que, en este desafío, conociendo los valores de los botones, tenías que **pulsar una combinación de menos de 8 botones cuya suma resultante fuera 0xf3**.

**Referencia para este tutorial:** [guía archivada del desafío Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación de binarios)

## References

- [1] [Simplificación de la ofuscación MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositorio CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificación de cadenas de Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - cadenas de Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (archivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Vencer la ingeniería inversa asistida por IA, o al menos intentarlo](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un método para comparar grafos de flujo de control basado en la correspondencia de bloques básicos](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Repositorio GoResolver de Volexity](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Mecanismo de ofuscación de Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: uso de la similitud entre grafos de flujo de control para desofuscar automáticamente binarios de Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Repositorio GoStringExtractor de Volexity](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: actualizaciones de las herramientas de Golang de Volexity](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: ingeniería inversa de cualquier cosa](https://github.com/morluto/rea)
- [17] [Análisis de código administrado de REA](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [Guía de CLI y evidencias de REA](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: flujo de trabajo de Binary Ninja para deshacer el aplanamiento del flujo de control](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: intrusión de día cero en PaperCut MF, cargador Java, web shell y AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [README de IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [Implementación del servidor bridge de IDA](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Implementación del servidor bridge de Ghidra](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle: InetSocketAddress(int) se enlaza a la dirección comodín](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: kit de herramientas de ingeniería inversa para Godot](https://github.com/figurophobia/gore)
- [26] [Implementación de recuperación de claves de gore](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [Formato de blobs cifrados de gore](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [Implementación de comandos y recuperación de gore](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
