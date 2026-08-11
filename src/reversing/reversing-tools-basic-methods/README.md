# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilador de Wasm / compilador de Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binario) a wat (texto claro)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- También puedes probar [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para la decompilación.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un decompilador que **decompila y examina múltiples formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez decompilado, un assembly se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja aquí es que, si es necesario restaurar el código fuente perdido a partir de un assembly heredado, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica por todo el código decompilado, lo que lo convierte en una de las herramientas perfectas para el **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de add-ins y una API que amplía la herramienta para adaptarla a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran cantidad de servicios de reverse engineering que proporciona esta herramienta:

- Proporciona información sobre cómo fluyen los datos a través de una biblioteca o componente
- Proporciona información sobre la implementación y el uso de lenguajes y frameworks de .NET
- Encuentra funcionalidades no documentadas y no expuestas para aprovechar mejor las API y tecnologías utilizadas.
- Encuentra dependencias y distintos assemblies
- Localiza la ubicación exacta de los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier OS (puedes instalarlo directamente desde VSCode, sin necesidad de descargar el git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **decompilar**, **modificar** y **compilar** de nuevo, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenido activamente de este, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Logging de DNSpy

Para hacer que **DNSpy registre cierta información en un archivo**, puedes usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración de DNSpy

Para depurar código usando DNSpy, debes:

Primero, cambiar los **atributos de Assembly** relacionados con la **depuración**:

![Registro de DNSpy - Depuración de DNSpy: Primero, cambia los atributos de Assembly relacionados con la depuración](<../../images/image (973).png>)

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

A continuación, guarda el archivo nuevo mediante _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: A continuación, guarda el archivo nuevo mediante File Save module](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimizaciones** al código y podría ocurrir que, durante la depuración, nunca se alcance un **breakpoint** o que algunas **variables no existan**.

Después, si tu aplicación .NET está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```
iisreset /noforce
```
Entonces, para empezar a depurar, debes cerrar todos los archivos abiertos y, dentro de la **Debug Tab**, seleccionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Entonces, para empezar a depurar, debes cerrar todos los archivos abiertos y, dentro de la Debug Tab, seleccionar Attach to Process](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para conectarte al **servidor IIS** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Luego selecciona w3wp.exe para conectarte al servidor IIS y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic derecho en cualquier módulo de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Decompiler de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Usando IDA

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el debugger **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de la ejecución introduciendo la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de la ejecución introduciendo la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Entonces, cuando empieces a depurar, **la ejecución se detendrá cuando se cargue cada DLL**; después, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene en los eventos de carga de módulos, pero alcanzar el entry point de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que aparece a continuación.

### Usando x64dbg/x32dbg

- **Carga rundll32** (64bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la Command Line** ( _File --> Change Command Line_ ) y establece la ruta de la dll y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**; el debugger se detendrá en cada dll main y, en algún momento, **te detendrás en el Entry de la dll**. Desde ahí, solo tienes que buscar los puntos donde quieres colocar un breakpoint.

Ten en cuenta que cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma cuándo la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta front-end/de reverse engineering para el GNU Project Debugger (GDB), centrada en juegos. Sin embargo, puede utilizarse para cualquier tarea relacionada con reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios decompilers. Este servicio web permite comparar el resultado de distintos decompilers en ejecutables pequeños.

## ARM y MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurando un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) reserva el **shellcode**, muestra su **dirección de memoria** y pausa la ejecución.\
Conecta un debugger como IDA o x64dbg, establece un breakpoint en la dirección mostrada y reanuda la ejecución para depurar el shellcode.

La página de github de releases contiene archivos zip con las releases compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, solo tienes que **crear un proyecto de C/C++ en Visual Studio Code, copiar y pegar el código y compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurando un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Reserva el shellcode y entra en un bucle infinito. Conecta el debugger, reanuda durante **2–5 segundos**, pausa dentro de ese bucle y avanza hasta la siguiente llamada que transfiere la ejecución al shellcode reservado.

![Debugger pausado en el bucle infinito de jmp2it inmediatamente antes de la llamada al shellcode reservado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Usando Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite "Open File" y "Open Shellcode". En mi caso, cuando abrí el shellcode como un archivo, lo decompiló correctamente, pero cuando lo abrí como shellcode no lo hizo:

![Cutter mostrando distintos resultados de análisis al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece un bp allí y, aparentemente, Cutter iniciará automáticamente la emulación desde ese punto:

![Estableciendo un breakpoint en la entrada deseada del shellcode antes de iniciar la emulación de Cutter](<../../images/image (589).png>)

![Emulador de Cutter pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![Visualizando la pila del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Deobfuscando shellcode y obteniendo las funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** está utilizando el shellcode y si el shellcode se está **decodificando** a sí mismo en memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un launcher gráfico en el que puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Launcher gráfico de scDbg para seleccionar las opciones de emulación y tracing del shellcode](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio en el shellcode dinámicamente en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode usando el terminal de scDbg (sin embargo, considero que cualquiera de las opciones explicadas anteriormente es mejor para esto, ya que podrás usar Ida o x64dbg).

### Desensamblado usando CyberChef

Carga tu archivo de shellcode como entrada y usa la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA obfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` tras fórmulas que combinan operadores aritméticos (`+`, `-`, `*`) y bitwise (`&`, `|`, `^`, `~`, shifts). La parte importante es que estas identidades normalmente solo son correctas bajo **aritmética modular de ancho fijo**, por lo que los carries y overflows importan:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoraron las semánticas del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR/decompiler levantado (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
- **Lineal**: sumas ponderadas de átomos bitwise
- **Semilineal**: lineal más máscaras constantes como `x & 0xFF`
- **Polinómica**: aparecen productos
- **Mixta**: los productos y la lógica bitwise están intercalados, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** mediante testing aleatorio o una prueba SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de adivinar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador MBA práctico para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados en lugar de aplicar un único paso genérico de reescritura a todo.<sup>[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalúa la expresión con entradas booleanas, deriva una firma y ejecuta en paralelo varios métodos de recuperación, como pattern matching, conversión a ANF e interpolación de coeficientes.
- **Semilinear MBA**: los átomos enmascarados con constantes se reconstruyen mediante una reconstrucción particionada por bits para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en núcleos, y las subexpresiones repetidas pueden convertirse en variables temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Esto puede simplificarse a:
```c
x * y
```
### Notas de reversing

- Es preferible ejecutar CoBRA sobre **expresiones de IR elevadas** o sobre la salida del decompiler después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética con máscaras o de registros estrechos.
- Si necesitas un paso de demostración más sólido, consulta las notas locales sobre Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **plugin de paso de LLVM** (`libCobraPass.so`), lo que resulta útil cuando quieres normalizar IR de LLVM con mucho MBA antes de ejecutar posteriores fases de análisis.
- Los residuos mixtos de dominios sensibles al carry que no sean compatibles deben tratarse como una señal para conservar la expresión original y razonar manualmente sobre la ruta del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator reemplaza las operaciones del programa por secuencias de instrucciones basadas en `mov` y utiliza el manejo de señales/excepciones para modificar el flujo de control. Para más detalles:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para los binarios compatibles, [demovfuscator](https://github.com/kirschju/demovfuscator) puede desofuscar el resultado. Tiene varias dependencias.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, esta técnica alternativa para encontrar el flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada**, busca las funciones por `::main`, como en:

![Encontrar un punto de entrada de Rust en Ghidra buscando nombres de funciones por main con doble dos puntos](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, por lo que es bastante obvio que esta es la función main interesante.\
Una vez que tengas el **nombre** de las **funciones** que se están llamando, búscalas en **Internet** para aprender sobre sus **entradas** y **salidas**.

### Recuperación de cadenas de Rust desde firmware ELF

En los binarios **ELF de Rust**, muchas cadenas estáticas no se referencian como punteros terminados en NUL al estilo de C. Un diseño común de `rustc` es una tupla de **puntero/longitud** dentro de **`.data.rel.ro`** que apunta al bloque de cadenas real almacenado en **`.rodata`**:
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
5. Aplica filtros de coherencia (por ejemplo, conserva longitudes entre **4** y **100** bytes).
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
Esto es especialmente útil en firmware reversing porque las strings de Rust recuperadas a menudo revelan **rutas HTTP, nombres RPC, mensajes de log, assertions, nombres de archivos, claves de configuración, command handlers y lógica relacionada con la autenticación**.

Si Ghidra no detecta esas strings, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de strings en los offsets de `.rodata` referenciados. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, endianness y disposiciones de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados con Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, después, selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al inicio del debugging. Después de iniciar el debugging, pulsa de nuevo el botón Start (el verde o f9) y se alcanzará un breakpoint al principio del código real.

Si pulsas un botón en la aplicación gráfica, el debugger puede detenerse en la función invocada por ese botón.

## Golang

Si tienes que hacer reversing de un binario Golang, te sugiero usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, después, selecciona el archivo del plugin.

Esto resolverá los nombres de las funciones.

## Compiled Python

En esta página puedes encontrar cómo obtener el código Python de un binario ELF/EXE compilado con Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emularlo** y hacerle **debugging**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de debugging_) - Contiene un debugger con interfaz
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![configuración de controles de no$gba mostrando las asignaciones de botones de Game Boy Advance](<../../images/image (581).png>)

Al pulsarla, cada **tecla tiene un valor** para identificarla:
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
Por lo tanto, en este tipo de programa, la parte interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función que aparece habitualmente: **KEYINPUT**.

![Vista de Ghidra de un binario de GBA que hace referencia a KEYINPUT en la dirección 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función es llamada desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de init (sin ninguna importancia):
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
El último if comprueba que **`uVar4`** esté en las **últimas Keys** y no sea la tecla actual; también se conoce como soltar un botón (la tecla actual se almacena en **`uVar1`**).
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

- Primero, se compara con el **valor 4** (botón **SELECT**): en el challenge este botón limpia la pantalla
- Después se compara el valor con **8** (botón **START**); en este challenge, esa ruta comprueba si el código introducido es válido.
- En este caso, la var **`DAT_030000d8`** se compara con 0xf3 y, si el valor es el mismo, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Por lo tanto, en este challenge, sabiendo los valores de los botones, era necesario **pulsar una combinación con una longitud menor que 8 cuya suma resultante fuera 0xf3.**

**Referencia para este tutorial:** [writeup archivado del challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (deobfuscación binaria)

## References

- [1] [Simplificación de la ofuscación MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositorio de Trail of Bits CoBRA](https://github.com/trailofbits/CoBRA)
- [3] [Decodificación de strings de Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (archivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
{{#include ../../banners/hacktricks-training.md}}
