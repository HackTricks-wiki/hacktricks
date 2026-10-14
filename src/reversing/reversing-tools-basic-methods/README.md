# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

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

## Payloads virtualizados y VMs personalizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina varios formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, un ensamblado se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja es que, si es necesario recuperar el código fuente perdido de un ensamblado heredado, esto puede ahorrar tiempo. Además, dotPeek ofrece una navegación práctica por el código descompilado, lo que lo convierte en una de las herramientas ideales para el **análisis de algoritmos de Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo completo de complementos y una API que amplía la herramienta para adaptarla a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran variedad de servicios de ingeniería inversa que ofrece esta herramienta:

- Permite ver cómo fluyen los datos a través de una biblioteca o componente.
- Permite conocer la implementación y el uso de lenguajes y frameworks de .NET.
- Encuentra funciones no documentadas ni expuestas para aprovechar mejor las API y tecnologías utilizadas.
- Encuentra dependencias y distintos ensamblados.
- Localiza exactamente los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes usarlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode; no hace falta descargar git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y **volver a compilar**, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o una bifurcación mantenida activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Haz clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Inspección administrada sin ejecución con REA

**REA** puede inspeccionar los metadatos de PE/CLI y CIL sin cargar el ensamblado. Empieza por identificar el artefacto y luego inspecciona sus miembros y los límites nativos declarados; esto resulta útil al revisar llamadas sospechosas antes de usar un descompilador o ejecutar el programa.<sup>[[16]](#references)[[17]](#references)</sup>

```bash
rea inspect-managed-artifact /absolute/path/Assembly.dll --json
rea inspect-managed-members /absolute/path/Assembly.dll --json
rea inspect-managed-native-boundaries /absolute/path/Assembly.dll --json
```

Para comparar versiones, `compare_managed_members` usa la identidad CIL/firma en bruto y fingerprints de instrucciones decodificadas, en lugar de tratar los tokens de metadatos como estables entre compilaciones. Una declaración P/Invoke no demuestra que se haya ejecutado código nativo; `verify_managed_native_boundaries` necesita Evidence coincidente de una exportación o función nativa para comprobar ese límite. Conserva el digest del artefacto, el MVID y las correspondencias sin resolver junto con el resultado.<sup>[[17]](#references)</sup>

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

![Registro de DNSpy - Depuración con DNSpy: Primero, cambia los atributos del ensamblado relacionados con la depuración](<../../images/image (973).png>)

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

![Registro de DNSpy - Depuración de DNSpy: haz clic en compilar](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo mediante _**Archivo >> Guardar módulo...**_:

![Registro de DNSpy - Depuración de DNSpy: luego guarda el nuevo archivo mediante Archivo Guardar módulo](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código, y es posible que, al depurar, **nunca se alcance un punto de interrupción** o que **algunas variables no existan**.

Luego, si **IIS** está **ejecutando** tu aplicación .NET, puedes **reiniciarla** con:

```
iisreset /noforce
```

Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y seleccionar **Attach to Process...** en la **pestaña Debug**:

![DNSpy Logging - Depuración con DNSpy: Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y seleccionar Attach to Process en la pestaña Debug](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarte al **servidor IIS** y haz clic en **attach**:

![DNSpy Logging - Depuración con DNSpy: Luego selecciona w3wp.exe para adjuntarte al servidor IIS y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - Depuración con DNSpy: Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - Depuración con DNSpy: Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - Depuración con DNSpy: Haz clic en cualquier módulo de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic con el botón derecho en cualquier módulo de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - Depuración con DNSpy: Haz clic con el botón derecho en cualquier módulo de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Uso de IDA

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el depurador **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Depuración de DLLs - Uso de IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Depuración de DLLs - Uso de IDA: Configura los parámetros de ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, al empezar a depurar, **la ejecución se detendrá cada vez que se cargue una DLL**. Por lo tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene ante eventos de carga de módulos, pero llegar al punto de entrada de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que se describe a continuación.

### Uso de x64dbg/x32dbg

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la línea de comandos** ( _File --> Change Command Line_ ) e indica la ruta de la dll y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**; el depurador se detendrá en cada dll main y, en algún momento, **se detendrá en la Entry de tu dll**. Desde ahí, busca los puntos donde quieras poner un breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![Uso de IDA - Uso de x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma cuándo la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones con GUI / videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes en la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de interfaz gráfica y reverse engineering para GNU Project Debugger (GDB), centrada en juegos. Sin embargo, se puede usar para cualquier tarea relacionada con reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) es una interfaz web para varios decompilers. Este servicio web permite comparar los resultados de distintos decompilers en ejecutables pequeños.

## Investigación nativa con REA respaldada por evidencia

**REA** ofrece análisis de Hopper, Ghidra e IDA mediante CLI y MCP. Requiere Node.js 22.x (como mínimo 22.19), 24.x (como mínimo 24.11) o 26+, además de npm. Primero configura un proveedor nativo existente; comprueba `rea providers --json` y selecciona explícitamente un proveedor si más de uno admite el objetivo. En lugar de `0x1000`, usa un nombre de función o una dirección observados en el inventario.<sup>[[16]](#references)[[18]](#references)</sup>

```bash
npm install --global rea-agents
rea providers --json
rea inspect /absolute/path/to/program --provider ghidra --json
rea search /absolute/path/to/program "search" --provider ghidra --json
rea trace /absolute/path/to/program "search" --provider ghidra --json
rea xrefs /absolute/path/to/program 0x1000 --provider ghidra --json
rea function /absolute/path/to/program 0x1000 --provider ghidra --json
```

Empieza con una cadena de características o un símbolo, sigue las referencias y los callers, y luego inspecciona el dossier de la función seleccionada y el pseudocódigo con `rea decompile`. REA vincula una sesión al provider seleccionado, en lugar de reemplazarlo silenciosamente tras un fallo. Para consultas repetibles, `--snapshot PATH` reutiliza solo los bytes del artefacto, el provider, la configuración, la operación y los parámetros que coincidan; un snapshot es una caché local, no una base de datos del provider guardada. Conserva la Evidence devuelta y las incógnitas explícitas, en lugar de tratar las rutas inferidas o el texto del decompilador como código fuente original.<sup>[[16]](#references)[[18]](#references)</sup>

Para los puntos de entrada de JavaScript/Electron que llevan a add-ons nativos, consulta [Aplicaciones de escritorio de Electron](../../network-services-pentesting/pentesting-web/electron-desktop-apps/#static-asar-to-native-boundary-tracing-with-rea).

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurar un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) asigna el **shellcode**, imprime su **dirección de memoria** y pausa la ejecución.\
Conecta un debugger como IDA o x64dbg, establece un breakpoint en la dirección impresa y reanuda la ejecución para depurar el shellcode.

La página de releases de GitHub contiene archivos zip con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión de Blobrunner ligeramente modificada en el siguiente enlace. Para compilarla, simplemente **crea un proyecto de C/C++ en Visual Studio Code, copia y pega el código y compílalo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurar un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Asigna el shellcode y entra en un bucle infinito. Conecta el debugger, reanuda durante **2–5 segundos**, pausa dentro de ese bucle y avanza hasta la siguiente llamada que transfiere la ejecución al shellcode asignado.

![Debugger pausado en el bucle infinito de jmp2it, justo antes de la llamada al shellcode asignado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurar shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite «Open File» y «Open Shellcode». En mi caso, al abrir el shellcode como archivo lo descompiló correctamente, pero al abrirlo como shellcode no:

![Cutter muestra resultados de análisis diferentes al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieres, establece un bp allí y, al parecer, Cutter iniciará automáticamente la emulación desde ese punto:

![Establecer un breakpoint en la entrada deseada del shellcode antes de iniciar la emulación de Cutter](<../../images/image (589).png>)

![Emulador de Cutter pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![Ver la pila del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Desofuscar shellcode y obtener las funciones ejecutadas

Prueba [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te dirá cosas como **qué funciones** está usando el shellcode y si se está **decodificando** en memoria.

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

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio dinámico en el shellcode en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode desde un offset específico. La opción **Debug Shell** sirve para depurar el shellcode usando la terminal de scDbg (sin embargo, para esto prefiero cualquiera de las opciones explicadas antes, ya que podrás usar Ida o x64dbg).

### Desensamblado con CyberChef

Sube tu archivo de shellcode como entrada y usa la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA obfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que combinan operaciones aritméticas (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, desplazamientos). Lo importante es que estas identidades suelen ser correctas únicamente con **aritmética modular de ancho fijo**, por lo que los acarreos y desbordamientos importan:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoró la semántica del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR/decompiler output elevado (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
   - **Lineal**: sumas ponderadas de átomos bitwise
   - **Semilineal**: lineal más máscaras constantes como `x & 0xFF`
   - **Polinómica**: aparecen productos
   - **Mixta**: se intercalan productos y lógica bitwise, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** mediante pruebas aleatorias o una prueba SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de hacer suposiciones.

### Evadir el flujo de control aplanado con un fragmento de ejecución acotado

A menudo no es necesario recuperar el grafo de flujo de control completo. Con control-flow flattening, predicates opacos, grandes despachadores o código con mucho MBA, sigue las referencias desde los blobs cifrados y los buffers de salida hasta la rutina más pequeña que los transforma. Después, reproduce solo ese fragmento de flujo de datos o ejecútalo de forma independiente; el despachador no forma parte de la solución necesaria si se puede inicializar directamente el estado relevante.<sup>[[7]](#references)</sup>

Un flujo de trabajo práctico es:<sup>[[7]](#references)</sup>

1. Haz un inventario de las secciones ejecutables y de datos, las relocations y las referencias cruzadas. Vuelca las tablas candidatas de `.rodata` conservando el orden de bytes y el ancho de los elementos.
2. Identifica la última rutina que escribe el texto plano o el buffer de salida. Registra sus entradas, las tablas referenciadas, las llamadas importadas y el estado global requerido.
3. Eleva solo esas operaciones a un modelo Python de ancho fijo. Si el fragmento aún depende de demasiado estado, invoca la rutina con Unicorn, QEMU o un debugger y hookea las importaciones irrelevantes en lugar de emular todo el programa.
4. Valida que el extractor realmente derive su salida del binario proporcionado: elimina los fallbacks silenciosos, búscalo en busca de respuestas incrustadas y ejecútalo con builds no vistos que tengan cadenas, claves, identificadores, layouts y semillas de ofuscación diferentes.

Los siguientes comandos son útiles para una primera pasada:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expresiones MBA que ocultan constantes

Una expresión de bytes que aparentemente depende de la entrada puede cancelar por completo dicha entrada. Tras extraer sus tablas, evalúa la expresión en todo el dominio de 8 bits; si el conjunto de salidas tiene un único elemento, queda demostrado que ese byte es constante sin necesidad de recuperar la máquina de estados circundante.<sup>[[7]](#references)</sup>

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

Keep the final mask because the original addition has byte-width wraparound. For a wider domain, ask an SMT solver whether `f(x1) != f(x2)` is satisfiable for two symbolic inputs of the same width: `unsat` proves invariance, while `sat` provides a counterexample and means the input cannot be discarded.<sup>[[7]](#references)</sup>

#### Reconocer la decodificación ligada al entorno

Las comprobaciones anti-análisis no tienen por qué provocar una bifurcación ni un fallo. Un decoder puede mezclar el resultado de un sensor en un bit de clave, una constante de opaque predicate o el estado de un dispatcher aplanado, continuar normalmente y producir texto plano plausible pero falso en un emulador. Por tanto, parchear solo las ramas de fallo visibles no es suficiente; rastrea las dependencias de datos desde las sondas del entorno hasta el estado del decoder, compara el mismo fragmento en el dispositivo auténtico y en el emulador, y prueba cómo cambia el búfer final al forzar el resultado de cada sensor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador práctico de MBA para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados, en lugar de aplicar un único pase de reescritura genérico a todo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalúa la expresión con entradas booleanas, deriva una firma y ejecuta en paralelo varios métodos de recuperación, como el emparejamiento de patrones, la conversión a ANF y la interpolación de coeficientes.
- **Semilinear MBA**: los átomos enmascarados con constantes se reconstruyen mediante una reconstrucción particionada por bits para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en componentes, y las subexpresiones repetidas se pueden elevar a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Esto se puede reducir a:

```c
x * y
```

### Notas de reversing

- Es preferible ejecutar CoBRA sobre **expresiones IR elevadas** o la salida del decompilador, una vez aislado el cálculo exacto.
- Usa `--bitwidth` explícitamente si la expresión proviene de aritmética enmascarada o registros estrechos.
- Si necesitas una prueba más sólida, consulta las notas locales sobre Z3:

{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también incluye un **plugin de pase LLVM** (`libCobraPass.so`), útil para normalizar IR de LLVM con mucho MBA antes de ejecutar otros pases de análisis.
- Los residuos mixtos de dominios sensibles al acarreo que no sean compatibles deben considerarse una señal para conservar la expresión original y analizar manualmente la ruta del acarreo.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator reemplaza las operaciones del programa por secuencias de instrucciones basadas en `mov` y usa el manejo de señales y excepciones para alterar el flujo de control. Más detalles:

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

Para encontrar el **punto de entrada**, busca las funciones por `::main`, como en:

![Encontrar un punto de entrada de Rust en Ghidra buscando nombres de funciones con dos puntos dobles seguidos de main](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, así que es bastante obvio que esta es la función main interesante.\
Una vez que tengas el **nombre** de las **funciones** llamadas, búscalas en **Internet** para averiguar sus **entradas** y **salidas**.

### Recuperar cadenas de Rust de firmware ELF

En los binarios **ELF de Rust**, muchas cadenas estáticas no se referencian mediante punteros terminados en NUL al estilo de C. Un diseño habitual de `rustc` es una **tupla de puntero y longitud** dentro de **`.data.rel.ro`** que apunta al bloque real de cadenas almacenado en **`.rodata`**:

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
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un posible puntero a una cadena.
4. Trata la palabra siguiente como la longitud candidata.
5. Aplica filtros de plausibilidad (por ejemplo, conserva longitudes de entre **4** y **100** bytes).
6. Lee exactamente `length` bytes de `.rodata` en lugar de buscar hasta encontrar `0x00`.

Lógica mínima del extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Esto es especialmente útil al hacer reversing de firmware, porque las cadenas de Rust recuperadas suelen revelar **rutas HTTP, nombres de RPC, mensajes de registro, aserciones, nombres de archivo, claves de configuración, manejadores de comandos y lógica relacionada con la autenticación**.

Si Ghidra no detecta esas cadenas, ejecuta un script o plugin personalizado que aplique la misma heurística y cree datos de cadena en los offsets de `.rodata` a los que se hace referencia. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, órdenes de bytes y disposiciones de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados con Delphi, puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugeriría usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y luego selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al inicio de la depuración. Después de iniciar la depuración, vuelve a pulsar el botón Start (el verde o f9) y se activará un breakpoint al inicio del código real.

Si pulsas un botón en la aplicación gráfica, el depurador puede detenerse en la función invocada por ese botón.

## Golang

Para los binarios Go habituales, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) puede recuperar estructuras del runtime y mejorar los nombres de las funciones en IDA. Carga su plugin de Python con **Alt+F7**.

Si tienes que hacer reversing de un binario Golang, te sugeriría usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y luego selecciona el archivo del plugin.

Esto resolverá los nombres de las funciones.

### Recuperar metadatos sin la tabla de símbolos

Un ejecutable Go sin símbolos sigue necesitando metadatos del runtime para asociar los contadores de programa con las funciones. [GoReSym](https://github.com/mandiant/GoReSym) localiza y analiza estructuras como `pclntab` y `moduledata` mediante código derivado del runtime de Go. Esto permite recuperar límites de funciones, nombres, rutas de origen, tipos e información de compilación sin depender de la tabla de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un ofuscador puede dejar esas estructuras utilizables mientras reemplaza los nombres recuperados. Garble, por ejemplo, aplica hashes a los identificadores y las rutas de paquetes, y elimina la información de compilación, módulos y depuración.<sup>[[12]](#references)</sup> El token ofuscado del paquete debe ser coherente en todas las funciones de ese paquete. Agrupa las funciones según el token repetido, deduce un paquete a partir de sus funciones llamadas, cadenas y API, y luego propaga la etiqueta de ese paquete a todo el grupo.<sup>[[13]](#references)</sup>

### Recuperar nombres de Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina la extracción de símbolos del runtime con la generación de referencias limpias y la comparación de grafos de flujo de control (CFG). Sigue esta secuencia:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versión del compilador.** Prueba primero con `BuildInfo` y las cadenas de versión incrustadas. Si el ofuscador las eliminó, compara partes del runtime de Go incluido con runtimes de referencia versionados. En las pruebas de Volexity, alrededor del `2%` del runtime bastó para distinguir las versiones principales de Go. Tómalo como una optimización empírica, no como un umbral universal.<sup>[[13]](#references)</sup>
2. **Genera referencias coincidentes.** Genera binarios limpios para la versión de Go identificada, la arquitectura objetivo y las bibliotecas probables. Hacer coincidir el toolchain reduce las diferencias en los CFG generados por el compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compara las funciones.** GoGrapher compara los CFG de las funciones y genera puntuaciones normalizadas de `0.0` a `1.0`. La comparación de bloques básicos se basa en una comparación ponderada de instrucciones similares. Las coincidencias de alta confianza asignan las funciones con nombres aleatorios a la implementación limpia. Las coincidencias menos sólidas aún pueden identificar un paquete o módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valida e importa.** Confirma los nombres propuestos mediante las relaciones entre llamadas, las constantes, las cadenas y los efectos secundarios; luego importa el informe JSON con el plugin de GoResolver para IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instala el toolchain y ejecuta el extractor y el comparador de grafos combinados:<sup>[[10]](#references)</sup>

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

El umbral predeterminado de coincidencia significativa es `0.9`. Las opciones `--extract` y `--graph` pueden aislar cualquiera de las etapas, mientras que, de forma predeterminada, se ejecutan ambas porque los metadatos de runtime recuperados y las evidencias del CFG se complementan entre sí.<sup>[[10]](#references)</sup> Las puntuaciones del CFG son heurísticas: el inlining, las opciones de compilación, la arquitectura y las diferencias entre versiones de bibliotecas pueden cambiar la forma del grafo, así que conserva las funciones sin resolver en lugar de asignarles nombres con poca confianza.<sup>[[13]](#references)</sup>

### Recuperación de la tabla de strings de Go

Los binarios de Go colocan los bytes de strings de todos los paquetes enlazados en una tabla contigua. Las entradas no terminan en NUL y las estructuras de runtime no exponen la dirección base ni el tamaño de la tabla. Sin embargo, el compilador ordena las entradas primero por longitud y luego alfabéticamente, en todos los sistemas operativos y arquitecturas. Por lo tanto, tras encontrar una entrada, un analista puede recorrer las entradas adyacentes y usar las referencias cruzadas de datos para asociar strings con código.<sup>[[15]](#references)</sup>

[GoStringExtractor](https://github.com/volexity/GoStringExtractor) automatiza este flujo de trabajo en IDA Pro y Ghidra. Espera primero a que termine el análisis automático, ya que el plugin depende de las referencias cruzadas del segmento de datos. El punto de anclaje predeterminado es el string de runtime `entersyscall`; a partir de ahí, puede explorar en ambas direcciones, definir los strings recuperados en la base de datos y exportar un mapeo JSON de strings a las funciones que hacen referencia a ellos.<sup>[[14]](#references)</sup>

Filtra el informe por el paquete de la función que hace referencia al string para separar el código de la aplicación o del malware del ruido de las bibliotecas enlazadas. Esta técnica no puede recuperar literales destruidos por la ofuscación, como la transformación `-literals` de Garble. Aun así, puede organizar los strings de runtime que permanezcan sin ofuscar.<sup>[[14]](#references)[[15]](#references)</sup>

### Recuperación de tipos de runtime de Go

Go incorpora información de tipos de runtime que utilizan funciones como la recolección de basura. Si se eliminan los datos de compilación o el desensamblador no analiza estos metadatos, puede parecer que las instrucciones cargan direcciones de datos arbitrarias y la región de destino queda sin tipar. Recuperar los metadatos convierte esas direcciones en referencias de tipos legibles y facilita entender las capacidades de los paquetes.<sup>[[15]](#references)</sup>

[GoResolver](https://github.com/volexity/GoResolver) puede extraer símbolos y analizar los tipos de runtime para generar un informe JSON. La CLI actual usa el subcomando `resolve`:<sup>[[10]](#references)</sup>

```bash
pip install goresolver
goresolver resolve -x -y -o report.json sample_bin.exe
```

La opción `-y`/`--types` habilita el análisis de tipos. Importa el informe con el plugin de IDA Pro o Ghidra de GoResolver para definir los tipos recuperados y aplicar sus referencias en la base de datos de análisis. En el formato de informe introducido con esta función, si se omite `-y`, los miembros de dirección RTTI y tipos recuperados quedan en null.<sup>[[10]](#references)[[15]](#references)</sup>

GoResolver admite muestras PE, ELF y Mach-O para x86, AMD64, ARM y ARM64, por lo que el mismo flujo de trabajo se aplica a los binarios Go de Windows, Linux y macOS.<sup>[[10]](#references)</sup>

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

![Configuración de controles de no$gba que muestra las asignaciones de los botones de Game Boy Advance](<../../images/image (581).png>)

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

En la imagen anterior puedes ver que se llama a la función desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

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

El último if comprueba que **`uVar4`** esté en las últimas Keys y que no sea la tecla actual; esto también se conoce como soltar un botón (la tecla actual se almacena en **`uVar1`**).

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
- Luego se compara con **8** (botón **START**); en este desafío, esa ruta comprueba si el código introducido es válido.
  - En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si el valor coincide, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
  Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Así que, en este desafío, conociendo los valores de los botones, había que **pulsar una combinación de menos de 8 botones cuya suma resultante fuera 0xf3.**

**Referencia para este tutorial:** [guía archivada del desafío Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (desofuscación de binarios)

## References

- [1] [Simplificación de la ofuscación MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositorio CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificación de cadenas de Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - cadenas de Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (archivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Cómo derrotar el reverse engineering asistido por IA, o al menos intentarlo](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
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
{{#include ../../banners/hacktricks-training.md}}
