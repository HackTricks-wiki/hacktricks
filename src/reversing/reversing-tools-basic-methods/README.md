# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Automatización de WinDbg en modo usuario

{{#ref}}
windbg-automation.md
{{#endref}}

## Flujo de control basado en excepciones de Windows

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
- También puedes probar [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para descompilar.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode en caché de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads virtualizados y máquinas virtuales personalizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina varios formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, un ensamblado se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja es que, si se necesita recuperar código fuente perdido a partir de un ensamblado antiguo, esta herramienta puede ahorrar tiempo. Además, dotPeek facilita la navegación por el código descompilado, por lo que es una de las herramientas ideales para el **análisis de algoritmos de Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de complementos y una API que permite adaptar la herramienta a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran variedad de funciones de ingeniería inversa que ofrece esta herramienta:

- Permite ver cómo fluyen los datos a través de una biblioteca o un componente
- Permite conocer la implementación y el uso de lenguajes y frameworks de .NET
- Encuentra funcionalidades no documentadas ni expuestas para aprovechar mejor las API y tecnologías utilizadas.
- Encuentra dependencias y distintos ensamblados
- Localiza exactamente los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes usarlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, sin necesidad de descargar git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y **volver a compilar**, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o una bifurcación de este que se mantiene activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Inspección de código administrado sin ejecución con REA

**REA** puede inspeccionar los metadatos PE/CLI y el CIL sin cargar el ensamblado. Empieza por identificar el artefacto y, después, inspecciona sus miembros y los límites nativos declarados; esto resulta útil al revisar llamadas sospechosas antes de usar un descompilador o ejecutar el programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Para comparar diferencias entre versiones, `compare_managed_members` usa la identidad de CIL/firmas sin procesar y fingerprints de instrucciones decodificadas, en lugar de tratar los tokens de metadatos como estables entre compilaciones. Una declaración P/Invoke no demuestra que se haya ejecutado código nativo; `verify_managed_native_boundaries` necesita una exportación nativa coincidente o evidencia de función para comprobar ese límite. Conserva el digest del artefacto, el MVID y las asignaciones sin resolver junto con el resultado.<sup>[[17]](#references)</sup>

### Registro de DNSpy

Para hacer que **DNSpy registre cierta información en un archivo**, puedes usar este fragmento:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuración con DNSpy

Para depurar código con DNSpy, debes:

Primero, cambiar los **atributos del ensamblado** relacionados con la **depuración**:

![Registro de DNSpy - Depuración con DNSpy: Primero, cambiar los atributos del ensamblado relacionados con la depuración](<../../images/image (973).png>)

De:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

Para:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

Y haz clic en **compilar**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo mediante _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimizaciones** al código y es posible que, al depurarlo, **nunca se alcance un punto de interrupción** o que **algunas variables no existan**.

Luego, si tu aplicación .NET se está **ejecutando** en **IIS**, puedes **reiniciarla** con:

```
iisreset /noforce
```

Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y, en la pestaña **Debug Tab**, seleccionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y, en la pestaña Debug Tab, seleccionar Attach to Process](<../../images/image (318).png>)

Luego, selecciona **w3wp.exe** para adjuntarte al **servidor IIS** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Luego, selecciona w3wp.exe para adjuntarte al servidor IIS y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic con el botón derecho en cualquier módulo de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic con el botón derecho en cualquier módulo de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Usando IDA

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el depurador **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, al iniciar la depuración, **la ejecución se detendrá cada vez que se cargue una DLL**. Por lo tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene en los eventos de carga de módulos, pero llegar al punto de entrada de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que se describe a continuación.

### Usando x64dbg/x32dbg

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la línea de comandos** ( _File --> Change Command Line_ ) e indica la ruta de la dll y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**. El depurador se detendrá en cada dll main y, en algún momento, **se detendrá en el punto de entrada de la dll que quieres depurar**. Desde ahí, busca los puntos donde quieras establecer un breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma que la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones GUI / videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes en la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de interfaz/reverse engineering para GNU Project Debugger (GDB), enfocada en juegos. Sin embargo, puede usarse para cualquier tarea relacionada con reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) es una interfaz web para varios descompiladores. Este servicio web permite comparar los resultados de distintos descompiladores en ejecutables pequeños.

### Descifrado de PCK de Godot y recuperación de proyectos

En un juego de Godot distribuido, localiza su PCK en un `.pck` independiente, en un paquete añadido o integrado en un ejecutable, o en el directorio `assets` de un APK. [gore](https://github.com/figurophobia/gore) puede inspeccionar y extraer el paquete, mientras que la reconstrucción completa de scripts y recursos requiere GDRE Tools (`gore setup` lo instala, o puedes usar `--gdre`). Para este flujo de trabajo, la herramienta admite los formatos PCK v2–v4 de Godot 4.x; puede detectar encabezados v1, pero requiere una clave proporcionada para v1.<sup>[[25]](#references)</sup>

La recuperación automática de claves necesita una tabla de archivos cifrada; si solo está cifrado el contenido de los archivos, proporciona una clave conocida. Si la recuperación falla, eso no demuestra que el paquete no esté cifrado.<sup>[[28]](#references)</sup>

La búsqueda de claves **no** es un ataque al espacio de claves de AES-256. Una tabla de archivos cifrada expone el MD5 de su texto plano, la longitud del texto plano, el IV y el texto cifrado AES-256-CFB.<sup>[[27]](#references)</sup> `gore` prueba ventanas de 32 bytes del ejecutable del juego o de archivos cercanos como claves candidatas. Filtra las candidatas según la longitud y el prefijo plausibles de la ruta descifrada y, luego, confirma los resultados del escaneo binario descifrando la tabla completa y comprobando su MD5.<sup>[[26]](#references)[[28]](#references)</sup> Primero busca en las secciones de datos inicializados de PE/ELF y, si no encuentra resultados, realiza un escaneo del archivo completo; `--scan` añade otros archivos candidatos.<sup>[[28]](#references)</sup>

Si no se encuentra una clave integrada, se prueba una pequeña lista de contraseñas incorporada; `--wordlist` permite proporcionar otras candidatas. Cada contraseña se prueba como la representación de clave derivada de contraseña del motor, como literal rellenado con ceros o como clave de 64 caracteres hexadecimales. A diferencia de los resultados del escaneo binario, los resultados de la wordlist solo pasan el filtro de estructura de rutas en esta implementación. Confírmalos abriendo el paquete y validando los recursos extraídos.<sup>[[26]](#references)[[28]](#references)</sup>

Con el artefacto del juego disponible localmente, elige la etapa necesaria para el análisis. `recover` invoca GDRE para reconstruir un proyecto que se pueda abrir, mientras que `extract` solo desempaqueta los archivos sin procesar. `key` muestra una clave candidata que puedes usar con otra herramienta.<sup>[[25]](#references)[[28]](#references)</sup>

```bash
gore info game.exe
gore key game.pck --scan game.exe
gore extract game.pck -o ./raw
gore setup
gore recover game.exe -o ./game_project
```

## Investigación nativa respaldada por evidencia con REA

**REA** expone los análisis de Hopper, Ghidra e IDA mediante CLI y MCP. Requiere Node.js 22.x (como mínimo 22.19), 24.x (como mínimo 24.11) o 26+, además de npm. Configura primero un proveedor nativo existente; comprueba `rea providers --json` y selecciona explícitamente un proveedor si más de uno es compatible con el objetivo. Sustituye `0x1000` por un nombre de función o una dirección observados en el inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Empieza con una cadena de características o un símbolo, sigue las referencias y los llamadores; después, inspecciona el dossier de la función seleccionada y el pseudocódigo con `rea decompile`. REA vincula una sesión al proveedor seleccionado, en lugar de sustituirlo silenciosamente tras un fallo. Para consultas repetibles, `--snapshot PATH` reutiliza únicamente los bytes de artefactos, el proveedor, la configuración, la operación y los parámetros que coincidan; una snapshot es una caché local, no una base de datos del proveedor guardada. Conserva el objeto Evidence devuelto y las incógnitas explícitas en vez de tratar las rutas inferidas o el texto del decompilador como código fuente original.<sup>[[16]](#references)[[18]](#references)</sup>

Para los puntos de entrada de JavaScript/Electron que conducen a add-ons nativos, consulta [Electron Desktop Apps](../../desktop-application-security/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## Análisis con scripts de IDA y Ghidra mediante un puente TCP local

[IDA-Ghidra-bridge](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge) se ejecuta dentro de una base de datos de IDA o un programa CodeBrowser de Ghidra **ya abiertos** y permite que un script independiente consulte y modifique esa base de datos de análisis. Ejecuta `ID_Server.py` desde la CLI de Python de IDA (`import ID_Server`) o `Ghidra_Server.py` desde el Script Manager de Ghidra. IDA se vincula a `127.0.0.1` desde el puerto `5073` y busca en puertos superiores. El script actual de Ghidra empieza en el puerto `5093` e intenta diez puertos hasta `5102`; su socket Java se vincula a la dirección comodín, no solo a loopback. Comprueba el puerto que muestra la instancia antes de conectarte. A diferencia de un analizador headless, este puente opera sobre el programa que está abierto en esa instancia de la GUI.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

Envía **un comando terminado en salto de línea por conexión** y lee la respuesta terminada en salto de línea. El resultado normalmente es JSON. Por ejemplo, tras encontrar una API importada relevante para una ruta de entrada, `IMPORTXREF` encuentra sus sitios de llamada; `DECOMP_XREF` descompila por lotes los llamadores de una dirección seleccionada. `FUNC` inspecciona una función, mientras que `PCODE` devuelve la representación intermedia del decompilador. Usa la dirección de la base de datos activa, no una dirección copiada de un binario con una base de reubicación diferente. El ejemplo siguiente usa el puerto predeterminado de IDA; para Ghidra, usa el puerto que muestra su script.<sup>[[21]](#references)[[22]](#references)[[23]](#references)</sup>

```python
import socket

with socket.create_connection(("127.0.0.1", 5073)) as sock:
    sock.sendall(b"IMPORTXREF memcpy\n")
    print(sock.makefile("r", encoding="utf-8").readline())
```

El mismo canal puede **cambiar la base de datos de análisis**: `RENAME_FUNC`, `RETYPE`, `SETCONV`, `DEFSTRUCT`/`SETFIELD`, `MAKEFUNC` y `PATCH` modifican nombres, tipos, definiciones de estructuras, límites de funciones o bytes almacenados. `PATCH` es una edición de la base de datos, **no** una prueba de que se haya aplicado un patch a un proceso en ejecución. Ninguno de los listeners documenta autenticación. IDA solo escucha en loopback, pero Ghidra podría ser accesible desde interfaces de red; restringe el acceso al listener de Ghidra cuando lo uses. `QUIT` detiene cualquiera de los dos listeners, e IDA también ofrece `ida_bridge_stop()`.<sup>[[21]](#references)[[22]](#references)[[23]](#references)[[24]](#references)</sup>

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurar un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) asigna el **shellcode**, imprime su **dirección de memoria** y pausa la ejecución.\
Conecta un debugger como IDA o x64dbg, establece un breakpoint en la dirección impresa y reanuda la ejecución para depurar el shellcode.

La página de GitHub de releases contiene zips con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, solo tienes que **crear un proyecto de C/C++ en Visual Studio Code, copiar y pegar el código y compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurar un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Asigna el shellcode y entra en un bucle infinito. Conecta el debugger, reanuda la ejecución durante **2–5 segundos**, pausa dentro del bucle y avanza hasta la siguiente llamada, que transfiere la ejecución al shellcode asignado.

![Debugger pausado en el bucle infinito de jmp2it, justo antes de la llamada al shellcode asignado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurar un shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite «Open File» y «Open Shellcode». En mi caso, al abrir el shellcode como archivo lo descompiló correctamente, pero al abrirlo como shellcode no lo hizo:

![Cutter muestra distintos resultados de análisis al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece allí un bp; aparentemente, Cutter iniciará automáticamente la emulación desde ese punto:

![Establecer un breakpoint en la entrada deseada del shellcode antes de iniciar la emulación de Cutter](<../../images/image (589).png>)

![El emulador de Cutter está pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Por ejemplo, puedes ver la pila en un volcado hexadecimal:

![Ver la pila del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Desofuscar shellcode y obtener las funciones ejecutadas

Prueba [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** está usando el shellcode y si se está **decodificando** en memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Lanzador gráfico de scDbg para seleccionar opciones de emulación y tracing de shellcode](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se modifica dinámicamente en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** sirve para depurar el shellcode usando la terminal de scDbg (sin embargo, para esto prefiero cualquiera de las opciones explicadas anteriormente, ya que podrás usar Ida o x64dbg).

### Desensamblar usando CyberChef

Sube el archivo de shellcode como entrada y usa la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA obfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que mezclan operaciones aritméticas (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, shifts). Lo importante es que estas identidades normalmente solo son correctas con **aritmética modular de ancho fijo**, por lo que los acarreos y desbordamientos importan:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si simplificas este tipo de expresión con herramientas de álgebra genérica, puedes obtener fácilmente un resultado incorrecto porque se ignoró la semántica del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR levantado o de la salida del decompiler (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
   - **Lineal**: sumas ponderadas de átomos bitwise
   - **Semilineal**: expresión lineal más máscaras constantes, como `x & 0xFF`
   - **Polinómica**: aparecen productos
   - **Mixta**: se intercalan productos y lógica bitwise, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** con pruebas aleatorias o una demostración SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en vez de adivinar.

### Evadir el control flow aplanado con un narrow execution slice

A menudo no es necesario recuperar el grafo de control completo. Con control-flow flattening, opaque predicates, dispatchers grandes o código con mucho MBA, sigue las referencias desde los blobs cifrados y los buffers de salida hasta la rutina más pequeña que los transforma. Luego reproduce solo ese data-flow slice o ejecútalo de forma independiente; el dispatcher no es parte de la solución necesaria si se puede inicializar directamente el estado relevante.<sup>[[7]](#references)</sup>

Un flujo de trabajo práctico es:<sup>[[7]](#references)</sup>

1. Haz un inventario de las secciones ejecutables y de datos, las relocations y las referencias cruzadas. Vuelca las tablas candidatas de `.rodata`, conservando el orden de bytes y el ancho de los elementos.
2. Identifica la última rutina que escribe el texto plano o el buffer de salida. Registra sus entradas, las tablas referenciadas, las llamadas importadas y el estado global requerido.
3. Traslada solo esas operaciones a un modelo de Python de ancho fijo. Si el slice aún depende de demasiado estado, invoca la rutina con Unicorn, QEMU o un debugger y usa hooks para las importaciones irrelevantes, en vez de emular todo el programa.
4. Valida que el extractor realmente derive su salida del binario proporcionado: elimina los fallbacks silenciosos, busca respuestas incrustadas y ejecútalo con builds no vistos que tengan strings, claves, identificadores, layouts y seeds de ofuscación diferentes.

Algunos comandos útiles para una primera pasada son:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expresiones MBA que ocultan constantes

Una expresión de byte que aparentemente depende de la entrada puede cancelar por completo su entrada. Tras extraer sus tablas, evalúa la expresión en todo el dominio de 8 bits; un conjunto de salida con un solo elemento demuestra que ese byte es constante, sin necesidad de recuperar la máquina de estados circundante.<sup>[[7]](#references)</sup>

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

Conserva la máscara final porque la suma original tiene wraparound al ancho de byte. Para un dominio más amplio, pregunta a un solver SMT si `f(x1) != f(x2)` es satisfacible para dos entradas simbólicas del mismo ancho: `unsat` demuestra invariancia, mientras que `sat` proporciona un contraejemplo y significa que la entrada no se puede descartar.<sup>[[7]](#references)</sup>

#### Reconocer decodificación ligada al entorno

Las comprobaciones anti-análisis no tienen por qué provocar una bifurcación ni un fallo. Un decoder puede mezclar el resultado de un sensor en un bit de clave, una constante de opaque predicate o el estado de un dispatcher aplanado, continuar con normalidad y producir texto plano plausible pero falso en un emulador. Por tanto, no basta con parchear solo las ramas de fallo visibles; rastrea las dependencias de datos desde las sondas del entorno hasta el estado del decoder, compara el mismo fragmento en el dispositivo auténtico y en el emulador, y comprueba cómo cambia el búfer final al forzar el resultado de cada sensor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador práctico de MBA para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados, en lugar de aplicar un único paso de reescritura genérico a todo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalúa la expresión con entradas booleanas, obtiene una firma y pone a competir varios métodos de recuperación, como la coincidencia de patrones, la conversión a ANF y la interpolación de coeficientes.
- **Semilinear MBA**: los átomos con máscaras constantes se reconstruyen mediante una reconstrucción particionada por bits para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en componentes, y las subexpresiones repetidas pueden elevarse a variables temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Esto puede reducirse a:

```c
x * y
```

### Notas de reversing

- Es preferible ejecutar CoBRA sobre **expresiones IR levantadas** o sobre la salida del decompilador, después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética enmascarada o de registros estrechos.
- Si necesitas una prueba más sólida, consulta las notas locales sobre Z3:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también incluye un **plugin de paso LLVM** (`libCobraPass.so`), útil para normalizar LLVM IR con muchas operaciones MBA antes de ejecutar otros pases de análisis.
- Los residuos mixtos entre dominios que no admitan acarreos deben considerarse una señal para conservar la expresión original y analizar manualmente la ruta del acarreo.

## Recuperar el aplanamiento del flujo de control con estado XOR

Un aplanador de estilo OLLVM puede guardar el estado del bloque básico actual en dos registros de 64 bits y reconstruirlo mediante XOR en un dispatcher. Cada bloque original escribe el par correspondiente a su siguiente estado y vuelve al dispatcher. Un bloque condicional puede usar `CMOVcc` para sustituir una mitad del par según los flags de la CPU; por eso, seguir solo las instrucciones de salto visibles hace que se pasen por alto los dos sucesores. A diferencia de un dispatcher con salto indirecto, esta estructura puede usar saltos de retorno directos en todo el código.<sup>[[19]](#references)[[20]](#references)</sup>

Para recuperar el grafo, identifica el árbol de comparaciones del dispatcher y los dos registros de estado; asigna cada estado XOR comparado a su bloque de destino y luego rastrea las escrituras del par de registros que alcanzan cada bloque original. Para las escrituras condicionales, incluye la instrucción que establece los flags y ambos resultados de `CMOVcc`. Reescribe la salida de cada bloque al dispatcher como su sucesor directo resuelto o como un salto condicional; así, el dispatcher queda inaccesible sin modificar el binario. Este enfoque reconstruye el CFG completo; si solo importa un decoder, el [flujo de trabajo con un segmento de ejecución acotado](#bypass-flattened-control-flow-with-a-narrow-execution-slice) anterior puede ser más rápido.<sup>[[19]](#references)[[20]](#references)</sup>

[DispatchThis](https://github.com/YungBinary/DispatchThis) automatiza esta estructura en Binary Ninja. Copia `plugins/DispatchThis` en el directorio de plugins de usuario de Binary Ninja y reinicia el programa. En la función afectada, abre **Function Settings** y selecciona `OLLVM_XOR_64`; si el análisis no se inicia, usa **Analysis → Reanalyze All Functions**. Este modo reescribe los bordes del flujo de control de MLIL, no los bytes del archivo, y no necesita Z3 ni el resolver de saltos indirectos. Se ha probado con Binary Ninja 5.3.9757+; no elimina las escrituras de estado muertas de cada bloque, así que no las confundas con transiciones activas que aún queden.<sup>[[19]](#references)</sup>

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador reemplaza las operaciones del programa por secuencias de instrucciones basadas en `mov` y utiliza el manejo de señales/excepciones para alterar el flujo de control. Para más detalles:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para los binarios compatibles, [demovfuscator](https://github.com/kirschju/demovfuscator) puede desofuscar el resultado. Tiene varias dependencias.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, esta solución alternativa para encontrar la flag** puede ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada**, busca las funciones por `::main`, como en:

![Cómo encontrar el punto de entrada de Rust en Ghidra buscando nombres de funciones con dos puntos dobles seguidos de main](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, así que es bastante obvio que esta es la función main de interés.\
Con el **nombre** de las **funciones** a las que se llama, búscalas en **Internet** para averiguar sus **entradas** y **salidas**.

### Recuperar strings de Rust de firmware ELF

En los binarios **ELF de Rust**, muchas strings estáticas no se referencian mediante punteros terminados en NUL al estilo de C. Un diseño común de `rustc` usa una **tupla de puntero/longitud** dentro de **`.data.rel.ro`** que apunta al bloque de strings real almacenado en **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Esto significa que `strings` o el análisis predeterminado de Ghidra pueden fusionar cadenas adyacentes o no detectar referencias cruzadas por completo.<sup>[[3]](#references)</sup>

Flujo de trabajo rápido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** palabra por palabra.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un puntero a cadena candidato.
4. Trata la palabra siguiente como la longitud candidata.
5. Aplica filtros de plausibilidad (por ejemplo, conserva longitudes entre **4** y **100** bytes).
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

Esto es especialmente útil en firmware reversing porque las cadenas de Rust recuperadas suelen revelar **rutas HTTP, nombres de RPC, mensajes de log, aserciones, nombres de archivo, claves de configuración, handlers de comandos y lógica relacionada con la autenticación**.

Si Ghidra no detecta esas cadenas, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de cadena en los offsets de `.rodata` referenciados. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, endianness y diseños de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados con Delphi, puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, luego, selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al inicio de la depuración. Después de iniciar la depuración, vuelve a pulsar el botón Start (el verde o f9) y se activará un breakpoint al comienzo del código real.

Si pulsas un botón en la aplicación gráfica, el debugger puede detenerse en la función invocada por ese botón.

## Golang

Para los binarios Go habituales, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) puede recuperar estructuras runtime y mejorar los nombres de las funciones en IDA. Carga su plugin de Python con **Alt+F7**.

Si tienes que hacer reversing de un binario Golang, te sugiero usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, luego, selecciona el archivo del plugin.

Esto resolverá los nombres de las funciones.

### Recuperar metadatos sin la tabla de símbolos

Un ejecutable Go sin símbolos sigue necesitando metadatos runtime para asociar los contadores de programa con las funciones. [GoReSym](https://github.com/mandiant/GoReSym) localiza y analiza estructuras como `pclntab` y `moduledata` usando código derivado del runtime de Go. Así, puede recuperar los límites de las funciones, sus nombres, rutas de origen, tipos y detalles de compilación sin depender de la tabla de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscator puede dejar esas estructuras utilizables y reemplazar los nombres recuperados. Garble, por ejemplo, aplica hash a los identificadores y las rutas de los paquetes, y elimina información de build, módulos y depuración.<sup>[[12]](#references)</sup> El token ofuscado del paquete debe ser coherente entre las funciones de ese paquete. Agrupa las funciones según el token repetido, infiere un paquete a partir de sus funciones llamadas, cadenas y APIs, y luego propaga esa etiqueta de paquete a todo el grupo.<sup>[[13]](#references)</sup>

### Recuperar nombres de Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina la extracción de símbolos de runtime con la generación de referencias limpias y la comparación de grafos de flujo de control (CFG). Sigue esta secuencia:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versión del compilador.** Prueba primero con `BuildInfo` y las cadenas de versión incrustadas. Si el obfuscator las eliminó, compara partes del runtime de Go incluido con runtimes de referencia de distintas versiones. En las pruebas de Volexity, alrededor del `2%` del runtime bastó para distinguir las versiones principales de Go. Tómalo como una optimización empírica, no como un umbral universal.<sup>[[13]](#references)</sup>
2. **Genera referencias coincidentes.** Genera binarios limpios para la versión identificada de Go, la arquitectura de destino y las bibliotecas probables. Igualar la cadena de herramientas reduce las diferencias en los CFG generados por el compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compara funciones.** GoGrapher compara los CFG de las funciones y genera puntuaciones normalizadas de `0.0` a `1.0`. La comparación de bloques básicos se basa en una comparación ponderada de instrucciones similares. Las coincidencias de alta confianza asocian funciones aleatorizadas con la implementación limpia. Las coincidencias menos sólidas aún pueden identificar un paquete o módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valida e importa.** Confirma los nombres propuestos mediante las relaciones entre llamadas, las constantes, las cadenas y los efectos secundarios; luego importa el informe JSON con el plugin de GoResolver para IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instala la cadena de herramientas y ejecuta el extractor y comparador de grafos combinados:<sup>[[10]](#references)</sup>

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

El umbral predeterminado de coincidencia significativa es `0.9`. Las opciones `--extract` y `--graph` permiten aislar cualquiera de las etapas, mientras que, de forma predeterminada, se ejecutan ambas porque los metadatos recuperados del runtime y las pruebas del CFG se complementan.<sup>[[10]](#references)</sup> Las puntuaciones del CFG son heurísticas: el inlining, las opciones de build, la arquitectura y las diferencias entre versiones de bibliotecas pueden cambiar la forma del grafo, así que conserva las funciones sin resolver en lugar de asignarles nombres con poca confianza.<sup>[[13]](#references)</sup>

### Recuperar la tabla de cadenas de Go

Los binarios de Go almacenan los bytes de las cadenas de todos los paquetes enlazados en una tabla contigua. Las entradas no terminan en NUL y las estructuras del runtime no exponen la base ni el tamaño de la tabla. Sin embargo, el compilador ordena las entradas primero por longitud y luego alfabéticamente, en todos los sistemas operativos y arquitecturas. Por lo tanto, después de encontrar una entrada, un analista puede recorrer las entradas adyacentes y usar referencias cruzadas de datos para asociar las cadenas con el código.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatiza este flujo de trabajo en IDA Pro y Ghidra. Primero, deja que termine el análisis automático, ya que el plugin depende de las referencias cruzadas del segmento de datos. Su ancla predeterminada es la cadena del runtime `entersyscall`; a partir de ahí, puede analizar en ambas direcciones, definir las cadenas recuperadas en la base de datos y exportar una asignación JSON de cadenas a funciones que hacen referencia a ellas.<sup>[[14]](#references)</sup>

Filtra el informe por el paquete de la función que hace referencia a la cadena para separar el código de la aplicación o del malware del ruido de las bibliotecas enlazadas. Esta técnica no puede recuperar literales destruidos por ofuscación, como la transformación `-literals` de Garble. Aun así, puede organizar las cadenas del runtime que sigan sin ofuscar.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperar los tipos del runtime de Go

Go incluye información de tipos del runtime que utilizan funciones como la recolección de basura. Cuando se elimina la información de build o el desensamblador no analiza estos metadatos, puede parecer que las instrucciones cargan direcciones de datos arbitrarias y la región de destino queda sin tipar. Recuperar los metadatos convierte esas direcciones en referencias de tipos legibles y facilita comprender las capacidades de los paquetes.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) puede extraer símbolos y analizar los tipos del runtime para generar un informe JSON. La CLI actual usa el subcomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

La opción `-y`/`--types` habilita el análisis de tipos. Importa el informe con el complemento de IDA Pro o Ghidra de GoResolver para definir los tipos recuperados y aplicar sus referencias en la base de datos de análisis. En el formato de informe introducido con esta función, omitir `-y` deja como nulos los campos de dirección RTTI y tipos recuperados.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver admite muestras PE, ELF y Mach-O para x86, AMD64, ARM y ARM64, por lo que el mismo flujo de trabajo se aplica a los binarios de Go de Windows, Linux y macOS.<sup>[[10]](#references)</sup>

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario ELF/EXE compilado de Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si obtienes el **binario** de un juego de GBA, puedes usar distintas herramientas para **emularlo** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Incluye un depurador con interfaz
- [**mgba** ](https://mgba.io)- Incluye un depurador CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Complemento de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Complemento de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![Configuración de controles de no$gba que muestra las asignaciones de botones de Game Boy Advance](<../../images/image (581).png>)

Al pulsarlas, cada **tecla tiene un valor** para identificarla:

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

Así que, en este tipo de programa, lo interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función que se encuentra habitualmente: **KEYINPUT**.

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

Se encontró este código:

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

La última condición **if** comprueba que **`uVar4`** esté entre las últimas teclas y que no sea la tecla actual; esto equivale a soltar un botón (la tecla actual se almacena en **`uVar1`**).

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

- Primero, se compara con el **valor 4** (botón **SELECT**): en el challenge, este botón borra la pantalla.
- Luego, se compara el valor con **8** (botón **START**); en este challenge, esa ruta comprueba si el código introducido es válido.
  - En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si los valores coinciden, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
  Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Así que, en este challenge, conociendo los valores de los botones, había que **pulsar una combinación de menos de 8 botones cuya suma resultante fuera 0xf3.**

**Referencia para este tutorial:** [writeup archivado del challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación de binarios)

## References

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (archived)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Defeating AI-Assisted Reverse Engineering, or at Least Trying To](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [An Approach to Comparing Control Flow Graphs Based on Basic Block Matching](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [Mandiant GoReSym](https://github.com/mandiant/GoReSym)
- [10] [Volexity GoResolver repository](https://github.com/volexity/GoResolver)
- [11] [Volexity GoGrapher](https://github.com/volexity/GoGrapher)
- [12] [Garble obfuscation mechanism](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: Using Control-Flow Graph Similarity to Automatically Deobfuscate Golang Binaries](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
- [14] [Volexity GoStringExtractor repository](https://github.com/volexity/GoStringExtractor)
- [15] [Go Get 'Em: Updates to Volexity Golang Tooling](https://www.volexity.com/blog/2025/08/11/go-get-em-updates-to-volexity-golang-tooling/)
- [16] [REA: Reverse Engineer Anything](https://github.com/morluto/rea)
- [17] [REA managed-code analysis](https://github.com/morluto/rea/blob/main/docs/managed-code-analysis.md)
- [18] [REA CLI and Evidence guide](https://github.com/morluto/rea/blob/main/docs/cli.md)
- [19] [DispatchThis: Binary Ninja control-flow unflattening workflow](https://github.com/YungBinary/DispatchThis)
- [20] [eSentire: PaperCut MF Zero-Day Intrusion, Java Loader, Web Shell, and AdaptixC2](https://esentire.com/blog/papercut-mf-zero-day-intrusion-java-loader-web-shell-and-adaptixc2-via-cve-2026-82078-and-cve-2026-81578)
- [21] [IDA-Ghidra-bridge README](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge)
- [22] [IDA bridge server implementation](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/ID_Server.py)
- [23] [Ghidra bridge server implementation](https://github.com/oscarsantanaarias/IDA-Ghidra-bridge/blob/main/Ghidra_Server.py)
- [24] [Oracle - InetSocketAddress(int) binds to the wildcard address](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/InetSocketAddress.html)
- [25] [gore: Godot reverse engineering toolkit](https://github.com/figurophobia/gore)
- [26] [gore key-recovery implementation](https://github.com/figurophobia/gore/blob/master/src/keyfind.rs)
- [27] [gore encrypted-blob format](https://github.com/figurophobia/gore/blob/master/src/crypto.rs)
- [28] [gore command and recovery implementation](https://github.com/figurophobia/gore/blob/master/src/main.rs)
{{#include ../../banners/hacktricks-training.md}}
