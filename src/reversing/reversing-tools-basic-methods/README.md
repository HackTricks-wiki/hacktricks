# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilador de Wasm / compilador de Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binario) a wat (texto claro)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- también puedes intentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para decompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un decompilador que **decompila y examina múltiples formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez decompilado, un assembly se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja aquí es que, si es necesario restaurar el código fuente perdido a partir de un assembly antiguo, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica por todo el código decompilado, lo que lo convierte en una de las herramientas perfectas para el **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de add-ins y una API que amplía la herramienta para adaptarla a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran cantidad de servicios de ingeniería inversa que proporciona esta herramienta:

- Proporciona información sobre cómo fluyen los datos a través de una biblioteca o componente
- Proporciona información sobre la implementación y el uso de lenguajes y frameworks de .NET
- Encuentra funcionalidades no documentadas y no expuestas para aprovechar mejor las APIs y tecnologías utilizadas.
- Encuentra dependencias y diferentes assemblies
- Localiza la ubicación exacta de los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes usarlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, sin necesidad de descargar el repositorio git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **decompilar**, **modificar** y **recompilar** de nuevo, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenido activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Registro de DNSpy

Para hacer que **DNSpy registre cierta información en un archivo**, puedes usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración de DNSpy

Para depurar código usando DNSpy debes:

Primero, cambiar los **atributos del Assembly** relacionados con la **depuración**:

![Registro de DNSpy - Depuración de DNSpy: Primero, cambiar los atributos del Assembly relacionados con la depuración](<../../images/image (973).png>)

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

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimizaciones** al código y podría ocurrir que, durante la depuración, nunca se alcance un **break-point** o que algunas **variables no existan**.

Después, si tu aplicación .NET está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```
iisreset /noforce
```
Entonces, para comenzar la depuración, debes cerrar todos los archivos abiertos y, dentro de la **Debug Tab**, seleccionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Entonces, para comenzar la depuración, debes cerrar todos los archivos abiertos y, dentro de la pestaña Debug, seleccionar Attach to Process](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarlo al **IIS server** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Luego selecciona w3wp.exe para adjuntarlo al servidor IIS y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo dentro de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo dentro de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo dentro de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic derecho en cualquier módulo dentro de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure los **parámetros** de la ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de la ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, cuando comiences la depuración, **la ejecución se detendrá cada vez que se cargue una DLL**; por lo tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Pero ¿cómo puedes llegar al código de la DLL que se ha cargado? No sé cómo hacerlo utilizando este método.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código te encuentras** en la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código te encuentras en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Así, puedes comprobar cuándo la ejecución se detuvo en la DLL que quieres depurar.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta front-end/de reverse engineering para el GNU Project Debugger (GDB), centrada en juegos. Sin embargo, puede utilizarse para cualquier tarea relacionada con reverse engineering.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios decompilers. Este servicio web permite comparar el resultado de distintos decompilers en ejecutables pequeños.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **asignará** el **shellcode** dentro de un espacio de memoria, te **indicará** la **dirección de memoria** donde se asignó el shellcode y **detendrá** la ejecución.\
Después, debes **adjuntar un debugger** (Ida o x64dbg) al proceso, establecer un **breakpoint en la dirección de memoria indicada** y **reanudar** la ejecución. De esta forma depurarás el shellcode.

La página de releases de GitHub contiene zips con las releases compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, solo tienes que **crear un proyecto de C/C++ en Visual Studio Code, copiar y pegar el código y compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)es muy similar a blobrunner. **Asignará** el **shellcode** dentro de un espacio de memoria y ejecutará un **bucle infinito**. Después debes **adjuntar el debugger** al proceso, **pulsar start, esperar entre 2 y 5 segundos y pulsar stop**, y te encontrarás dentro del **bucle infinito**. Salta a la siguiente instrucción del bucle infinito, ya que será una llamada al shellcode, y finalmente te encontrarás ejecutando el shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it es muy similar a blobrunner. Asignará el shellcode dentro de un espacio de memoria y ejecutará un...](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite "Open File" y "Open Shellcode". En mi caso, cuando abrí el shellcode como archivo, lo decompiló correctamente, pero cuando lo abrí como shellcode no lo hizo:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Ten en cuenta que Cutter permite "Open File" y "Open Shellcode". En mi caso, cuando abrí el shellcode como archivo...](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece un bp allí y, aparentemente, Cutter iniciará automáticamente la emulación desde ese punto:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Para iniciar la emulación en el lugar que quieras, establece un bp allí y, aparentemente, Cutter iniciará automáticamente...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Para iniciar la emulación en el lugar que quieras, establece un bp allí y, aparentemente, Cutter iniciará automáticamente...](<../../images/image (387).png>)

Puedes ver la stack, por ejemplo, dentro de un volcado hexadecimal:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Puedes ver la stack, por ejemplo, dentro de un volcado hexadecimal](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** utiliza el shellcode y si el shellcode se está **decodificando** en memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un launcher gráfico en el que puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg también cuenta con un launcher gráfico en el que puedes seleccionar las opciones que quieras y...](<../../images/image (258).png>)

La opción **Create Dump** hará un dump del shellcode final si se realiza algún cambio en el shellcode dinámicamente en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode utilizando el terminal de scDbg (sin embargo, considero que cualquiera de las opciones explicadas anteriormente es mejor para esto, ya que podrás utilizar Ida o x64dbg).

### Desensamblado usando CyberChef

Sube tu archivo de shellcode como entrada y utiliza la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA obfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que combinan operaciones aritméticas (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, shifts). La parte importante es que estas identidades normalmente solo son correctas bajo **aritmética modular de ancho fijo**, por lo que los acarreos y los desbordamientos importan:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoró la semántica del ancho de bits.

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código/IR/salida del decompiler (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
- **Lineal**: sumas ponderadas de átomos bitwise
- **Semilineal**: expresiones lineales más máscaras constantes como `x & 0xFF`
- **Polinómica**: aparecen productos
- **Mixta**: los productos y la lógica bitwise están intercalados, normalmente con subexpresiones repetidas
3. **Verifica cada reescritura candidata** mediante pruebas aleatorias o una demostración SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de adivinar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador MBA práctico para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados en lugar de aplicar un único paso de reescritura genérico a todo.<sup>[[1]](#references)[[2]](#references)</sup>

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

- **Linear MBA**: CoBRA evalúa la expresión con entradas booleanas, deriva una firma y pone en competencia varios métodos de recuperación, como la coincidencia de patrones, la conversión a ANF y la interpolación de coeficientes.
- **Semilinear MBA**: los átomos enmascarados con constantes se reconstruyen mediante una reconstrucción particionada por bits, de modo que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en núcleos, y las subexpresiones repetidas pueden elevarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Esto puede reducirse a:
```c
x * y
```
### Notas de reversing

- Prefiere ejecutar CoBRA sobre **expresiones IR lifted** o sobre la salida del decompiler después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética con máscaras o de registros estrechos.
- Si necesitas un paso de demostración más sólido, consulta las notas locales de Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **plugin de LLVM pass** (`libCobraPass.so`), útil cuando quieres normalizar LLVM IR con mucho MBA antes de ejecutar otros análisis.
- Los residuos mixtos de dominios sensibles al carry que no sean compatibles deben tratarse como una señal para conservar la expresión original y razonar manualmente sobre la ruta del carry.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator **modifica todas las instrucciones para `mov`** (sí, realmente genial). También utiliza interrupciones para cambiar los flujos de ejecución. Para obtener más información sobre cómo funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará el binario. Tiene varias dependencias
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás participando en un **CTF, este workaround para encontrar el flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **entry point**, busca las funciones por `::main`, como en:

![Movfuscator - Rust: Para encontrar el entry point, busca las funciones por ::main, como en](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, por lo que es bastante obvio que esta es la función main interesante.\
Con el **nombre** de las **funciones** que se están llamando, búscalas en **Internet** para conocer sus **entradas** y **salidas**.

### Recuperación de strings de Rust desde firmware ELF

En los binarios **ELF de Rust**, muchos strings estáticos no se referencian como punteros terminados en NUL al estilo de C. Un diseño común de `rustc` es una tupla de puntero/longitud dentro de **`.data.rel.ro`** que apunta al blob de strings real almacenado en **`.rodata`**:<sup>[[3]](#references)</sup>
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Esto significa que `strings` o el análisis predeterminado de Ghidra pueden combinar cadenas adyacentes u omitir por completo las referencias cruzadas.

Flujo de trabajo rápido:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** palabra por palabra.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un puntero candidato a una cadena.
4. Trata la siguiente palabra como la longitud candidata.
5. Aplica filtros de validación (por ejemplo, conserva longitudes de entre **4** y **100** bytes).
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
Esto es especialmente útil en firmware reversing porque las strings de Rust recuperadas suelen revelar **rutas HTTP, nombres de RPC, mensajes de log, aserciones, nombres de archivos, claves de configuración, handlers de comandos y lógica relacionada con la autenticación**.

Si Ghidra no encuentra esas strings, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de strings en los offsets `.rodata` referenciados. Las herramientas `rust-strings` y `RustStrings.py` publicadas por Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, endianness y diseños de secciones**.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

## **Delphi**

Para binarios compilados de Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario de Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Simplemente pulsa **ATL+f7** (importar un plugin de Python en IDA) y selecciona el plugin de Python.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al inicio del debugging. Después de iniciar el debugging, pulsa de nuevo el botón Start (el verde o f9) y se alcanzará un breakpoint al principio del código real.

También es muy interesante porque, si pulsas un botón en la aplicación gráfica, el debugger se detendrá en la función ejecutada por ese botón.

## Golang

Si tienes que hacer reversing de un binario de Golang, te sugiero usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Simplemente pulsa **ATL+f7** (importar un plugin de Python en IDA) y selecciona el plugin de Python.

Esto resolverá los nombres de las funciones.

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario ELF/EXE compilado a partir de Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emularlo** y hacerle **debugging**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de debugging_) - Contiene un debugger con interfaz
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![configuración de los controles de no$gba mostrando las asignaciones de botones de Game Boy Advance](<../../images/image (581).png>)

Al pulsarla, cada **tecla tiene un valor** que permite identificarla:
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
Por lo tanto, en este tipo de programa, la parte interesante será **cómo el programa trata la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![Vista de Ghidra de un binario de GBA que referencia KEYINPUT en la dirección 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes observar que la función es llamada desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

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
El último **`if`** comprueba que **`uVar4`** está en las últimas **Keys** y no es la key actual; esto también se denomina soltar un botón (la key actual se almacena en **`uVar1`**).
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

- Primero, se compara con el **valor 4** (botón **SELECT**): En el challenge, este botón limpia la pantalla.
- Después, se compara con el **valor 8** (botón **START**): En el challenge, esto comprueba si el código es válido para obtener la flag.
- En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si el valor es el mismo, se ejecuta cierto código.
- En cualquier otro caso, se comprueba un contador (`DAT_030000d4`). Es un contador porque se incrementa en 1 justo después de introducir el código.\
**S**i es menor que 8, se realiza algo que implica **sumar** valores a **`DAT_030000d8`** (básicamente, se suman los valores de las teclas pulsadas en esta variable mientras el contador sea menor que 8).

Por tanto, en este challenge, conociendo los valores de los botones, era necesario **pulsar una combinación con una longitud menor que 8 cuya suma resultante fuera 0xf3.**<sup>[[6]](#references)</sup>

**Referencia para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## Referencias

- [1] [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [3] [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - GBA reversing tutorial (exp.codes)](https://exp.codes/Nostalgia/)

{{#include ../../banners/hacktricks-training.md}}
