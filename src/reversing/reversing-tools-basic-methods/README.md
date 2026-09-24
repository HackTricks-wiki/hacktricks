# Herramientas y métodos básicos de reversing

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompiler de Wasm / compiler de Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binario) a wat (texto claro)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- También puedes probar [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para la decompilación.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode en caché de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Decompiler de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un decompiler que **decompila y examina múltiples formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez decompilado, un assembly se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja es que, si es necesario restaurar el código fuente perdido a partir de un assembly antiguo, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica por todo el código decompilado, lo que lo convierte en una de las herramientas perfectas para el **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de add-ins y una API que amplía la herramienta para adaptarla a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran cantidad de servicios de reversing que proporciona esta herramienta:

- Proporciona información sobre cómo fluyen los datos a través de una biblioteca o componente
- Proporciona información sobre la implementación y el uso de lenguajes y frameworks de .NET
- Encuentra funcionalidades no documentadas y no expuestas para aprovechar mejor las APIs y tecnologías utilizadas.
- Encuentra dependencias y diferentes assemblies
- Localiza la ubicación exacta de los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier OS (puedes instalarlo directamente desde VSCode, sin necesidad de descargar git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **decompilar**, **modificar** y **compilar** de nuevo, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenido activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Logging de DNSpy

Para que **DNSpy registre cierta información en un archivo**, puedes usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración con DNSpy

Para depurar código usando DNSpy necesitas:

Primero, cambiar los atributos de **Assembly** relacionados con la **depuración**:

![Registro de DNSpy - Depuración con DNSpy: Primero, cambia los atributos de Assembly relacionados con la depuración](<../../images/image (973).png>)

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
Y haz clic en **compile**:

![DNSpy Logging - DNSpy Debugging: Y haz clic en compile](<../../images/image (314) (1).png>)

Después, guarda el nuevo archivo mediante _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Después, guarda el nuevo archivo mediante File Save module](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimizaciones** al código y podría ocurrir que, durante la depuración, un **break-point nunca se alcance** o que algunas **variables no existan**.

Después, si tu aplicación .NET está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```
iisreset /noforce
```
Luego, para comenzar la depuración, debes cerrar todos los archivos abiertos y, dentro de la **Debug Tab**, seleccionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Luego, para comenzar la depuración, debes cerrar todos los archivos abiertos y, dentro de la Debug Tab, seleccionar Attach to Process](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarte al **IIS server** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Luego selecciona w3wp.exe para adjuntarte al IIS server y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo dentro de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo dentro de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo dentro de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic derecho en cualquier módulo dentro de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depurando DLLs

### Usando IDA

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el debugger **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de la ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de la ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, cuando comiences la depuración, **la ejecución se detendrá cada vez que se cargue una DLL**; por tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene en los eventos de carga de módulos, pero alcanzar el entry point de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que aparece a continuación.

### Usando x64dbg/x32dbg

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la Command Line** ( _File --> Change Command Line_ ) y establece la ruta de la dll y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**; el debugger se detendrá en cada dll main y, en algún momento, **te detendrás en el dll Entry de tu dll**. Desde ahí, solo tienes que buscar los puntos donde quieras colocar un breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma cuándo la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta front-end/de reverse engineering para el GNU Project Debugger (GDB), centrada en videojuegos. Sin embargo, puede utilizarse para cualquier tarea relacionada con reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios decompilers. Este servicio web permite comparar el resultado de distintos decompilers en ejecutables pequeños.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserva el **shellcode**, imprime su **dirección de memoria** y pausa la ejecución.\
Adjunta un debugger como IDA o x64dbg, establece un breakpoint en la dirección impresa y reanuda la ejecución para depurar el shellcode.

La página de github de releases contiene archivos zip con las releases compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, simplemente **crea un proyecto de C/C++ en Visual Studio Code, copia y pega el código y compílalo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Reserva el shellcode y entra en un bucle infinito. Adjunta el debugger, reanuda durante **2–5 segundos**, pausa dentro de ese bucle y avanza hasta la siguiente llamada que transfiere la ejecución al shellcode reservado.

![Debugger pausado en el bucle infinito de jmp2it inmediatamente antes de la llamada al shellcode reservado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Usando Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite "Open File" y "Open Shellcode". En mi caso, cuando abrí el shellcode como archivo, lo decompiló correctamente, pero cuando lo abrí como shellcode, no lo hizo:

![Cutter mostrando distintos resultados de análisis al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece un bp allí y, aparentemente, Cutter iniciará automáticamente la emulación desde ese punto:

![Estableciendo un breakpoint en el entry point deseado del shellcode antes de iniciar la emulación de Cutter](<../../images/image (589).png>)

![Emulador de Cutter pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Puedes ver el stack, por ejemplo, dentro de un volcado hexadecimal:

![Visualizando el stack del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** utiliza el shellcode y si el shellcode se está **decodificando** en la memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Lanzador gráfico de scDbg para seleccionar opciones de emulación y tracing del shellcode](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio dinámicamente en el shellcode en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode usando el terminal de scDbg (sin embargo, considero que cualquiera de las opciones explicadas anteriormente es mejor para esto, ya que podrás usar Ida o x64dbg).

### Desensamblado usando CyberChef

Sube tu archivo de shellcode como entrada y utiliza la siguiente receta para descompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` mediante fórmulas que combinan operaciones aritméticas (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, desplazamientos). La parte importante es que estas identidades normalmente solo son correctas bajo **aritmética modular de ancho fijo**, por lo que los acarreos y desbordamientos importan:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoraron las semánticas del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR/salida del decompilador (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
- **Lineal**: sumas ponderadas de átomos bit a bit
- **Semilineal**: expresión lineal más máscaras constantes como `x & 0xFF`
- **Polinómica**: aparecen productos
- **Mixta**: los productos y la lógica bit a bit están intercalados, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** mediante pruebas aleatorias o una prueba SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de adivinar.

### Evita el control-flow flattening con un narrow execution slice

Recuperar el grafo de control completo suele ser innecesario. Con control-flow flattening, opaque predicates, dispatchers grandes o código con mucho MBA, sigue las referencias desde los blobs cifrados y los buffers de salida hasta la rutina más pequeña que los transforma. Después reproduce únicamente ese data-flow slice o ejecútalo de forma independiente; el dispatcher no forma parte de la solución necesaria si el estado relevante se puede inicializar directamente.<sup>[[7]](#references)</sup>

Un flujo de trabajo práctico es:<sup>[[7]](#references)</sup>

1. Haz un inventario de las secciones ejecutables y de datos, las relocations y las referencias cruzadas. Extrae las tablas candidatas de `.rodata` conservando su orden de bytes y el ancho de sus elementos.
2. Identifica la última rutina que escribe el plaintext o el buffer de salida. Registra sus entradas, las tablas referenciadas, las llamadas importadas y el estado global necesario.
3. Eleva únicamente esas operaciones a un modelo de Python de ancho fijo. Si el slice todavía depende de demasiado estado, invoca la rutina con Unicorn, QEMU o un debugger y realiza hook de las imports irrelevantes en lugar de emular todo el programa.
4. Valida que el extractor realmente derive su salida del binario proporcionado: elimina los fallbacks silenciosos, busca respuestas incrustadas y ejecútalo contra builds no vistos con strings, claves, identificadores, layouts y semillas de ofuscación modificados.

Los comandos útiles para una primera pasada son:<sup>[[7]](#references)</sup>
```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```
#### Detectar expresiones MBA que son constantes disfrazadas

Una expresión de bytes aparentemente dependiente de la entrada puede cancelar por completo su entrada. Después de extraer sus tablas, evalúa la expresión sobre todo el dominio de 8 bits; un conjunto de resultados unitario demuestra que ese byte es constante sin tener que recuperar la máquina de estados circundante.<sup>[[7]](#references)</sup>
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
Conserva la máscara final porque la suma original tiene un desbordamiento con ajuste al ancho de byte. Para un dominio más amplio, pregunta a un solver SMT si `f(x1) != f(x2)` es satisfacible para dos entradas simbólicas del mismo ancho: `unsat` demuestra la invariancia, mientras que `sat` proporciona un contraejemplo y significa que la entrada no puede descartarse.<sup>[[7]](#references)</sup>

#### Reconocer el decoding vinculado al entorno

Las comprobaciones anti-analysis no tienen por qué realizar un branch ni provocar un crash. Un decoder puede mezclar el resultado de un sensor en un bit de una key, en una constante de un opaque predicate o en el estado de un flattened dispatcher, continuar normalmente y producir un plaintext plausible pero falso en un emulator. Por lo tanto, parchear únicamente los failure branches visibles es insuficiente; rastrea las dependencias de datos desde las sondas del entorno hasta el estado del decoder, compara el mismo slice en el dispositivo auténtico y en el emulator, y prueba cómo cambia el buffer final al forzar cada resultado del sensor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador práctico de MBA para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados en lugar de aplicar un único paso de reescritura genérico a todo.<sup>[[2]](#references)</sup>

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

- **MBA lineal**: CoBRA evalúa la expresión con entradas booleanas, obtiene una firma y pone a competir varios métodos de recuperación, como la coincidencia de patrones, la conversión a ANF y la interpolación de coeficientes.
- **MBA semilineal**: los átomos enmascarados con constantes se reconstruyen mediante una reconstrucción particionada por bits, de modo que las regiones enmascaradas sigan siendo correctas.
- **MBA polinómico/mixto**: los productos se descomponen en núcleos y las subexpresiones repetidas pueden elevarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que normalmente merece la pena intentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Esto puede reducirse a:
```c
x * y
```
### Notas de reversing

- Se recomienda ejecutar CoBRA sobre **expresiones IR lifted** o sobre la salida del decompiler después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética con máscaras o de registros estrechos.
- Si necesitas un paso de prueba más sólido, consulta las notas locales sobre Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **plugin de pass de LLVM** (`libCobraPass.so`), lo que resulta útil cuando quieres normalizar LLVM IR con mucho MBA antes de ejecutar posteriores passes de análisis.
- Los residuos mixtos entre dominios sensibles al carry que no sean compatibles deben tratarse como una señal para conservar la expresión original y razonar manualmente sobre la ruta del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator reemplaza las operaciones del programa por secuencias de instrucciones basadas en `mov` y utiliza el manejo de señales/excepciones para alterar el flujo de control. Para obtener más detalles:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para los binarios compatibles, [demovfuscator](https://github.com/kirschju/demovfuscator) puede desofuscar el resultado. Tiene varias dependencias.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
E [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, este workaround para encontrar el flag** puede ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **entry point**, busca las funciones por `::main`, como en:

![Encontrar un entry point de Rust en Ghidra buscando nombres de funciones por main con doble dos puntos](<../../images/image (1080).png>)

En este caso, el binary se llamaba authenticator, por lo que resulta bastante obvio que esta es la función main interesante.\
Conociendo el **name** de las **functions** que se están llamando, búscalas en **Internet** para aprender sobre sus **inputs** y **outputs**.

### Recuperando strings de Rust desde firmware ELF

En los binaries **Rust ELF**, muchas strings estáticas no se referencian como pointers terminados en NUL al estilo C. Un layout común de `rustc` es una **tupla de pointer/length** dentro de **`.data.rel.ro`** que apunta al blob de strings real almacenado en **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Esto significa que `strings` o el análisis predeterminado de Ghidra pueden combinar strings adyacentes u omitir por completo las referencias cruzadas.<sup>[[3]](#references)</sup>

Flujo de trabajo rápido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** palabra por palabra.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un posible puntero a una cadena.
4. Trata la palabra siguiente como la longitud candidata.
5. Aplica filtros de validación (por ejemplo, conserva longitudes entre **4** y **100** bytes).
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
Esto es especialmente útil en firmware reversing porque las cadenas de Rust recuperadas suelen revelar **rutas HTTP, nombres de RPC, mensajes de log, aserciones, nombres de archivos, claves de configuración, handlers de comandos y lógica relacionada con la autenticación**.

Si Ghidra no encuentra esas cadenas, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de cadena en los offsets de `.rodata` referenciados. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, endianness y diseños de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados de Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, a continuación, selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al inicio de la depuración. Después de iniciar la depuración, pulsa de nuevo el botón Start (el verde o f9) y se alcanzará un breakpoint al principio del código real.

Si pulsas un botón en la aplicación gráfica, el debugger puede detenerse en la función invocada por ese botón.

## Golang

Si tienes que hacer reversing de un binario Golang, te sugiero usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, a continuación, selecciona el archivo del plugin.

Esto resolverá los nombres de las funciones.

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario ELF/EXE compilado de Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emularlo** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de debugging_) - Contiene un debugger con interfaz
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

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
Por lo tanto, en este tipo de programa, la parte interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![Vista de Ghidra de un binario de GBA que referencia KEYINPUT en la dirección 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función es llamada desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de inicialización (sin ninguna importancia):
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
El último `if` comprueba si **`uVar4`** está en las **últimas Keys** y no es la tecla actual, lo que también se denomina soltar un botón (la tecla actual se almacena en **`uVar1`**).
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
En el código anterior puedes ver que estamos comparando **uVar1** (el lugar donde se encuentra el **valor del botón pulsado**) con algunos valores:

- Primero, se compara con el **valor 4** (botón **SELECT**): en el challenge, este botón limpia la pantalla.
- Después, se compara el valor con **8** (el botón **START**); en este challenge, esa ruta comprueba si el código introducido es válido.
- En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si el valor es el mismo, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Por lo tanto, en este challenge, al conocer los valores de los botones, era necesario **pulsar una combinación de longitud menor que 8 cuya suma resultante fuera 0xf3.**

**Referencia para este tutorial:** [archived Nostalgia challenge writeup](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación binaria)

## References

- [1] [Simplificando la ofuscación MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositorio CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificando strings de Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (archivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Derrotando el Reverse Engineering asistido por IA, o al menos intentándolo](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
{{#include ../../banners/hacktricks-training.md}}
