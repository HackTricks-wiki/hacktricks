# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## ImGui Based Reversing tools

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm decompiler / Wat compiler

Online:

- Use [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) to **decompile** from wasm (binary) to wat (clear text)
- Use [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) to **compile** from wat to wasm
- you can also try to use [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) to decompile

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET decompiler

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un decompiler que **decompila e inspecciona múltiples formatos**, incluyendo **libraries** (.dll), **Windows metadata file**s (.winmd) y **executables** (.exe). Una vez decompilado, un assembly puede guardarse como un proyecto de Visual Studio (.csproj).

La ventaja aquí es que, si un código fuente perdido necesita ser restaurado desde un assembly antiguo, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica por todo el código decompilado, lo que lo convierte en una de las herramientas perfectas para el **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo completo de add-in y una API que amplía la herramienta para adaptarse a tus necesidades exactas, .NET reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran cantidad de servicios de reverse engineering que ofrece esta herramienta:

- Proporciona una visión de cómo fluyen los datos a través de una library o componente
- Proporciona visión sobre la implementación y el uso de lenguajes y frameworks de .NET
- Encuentra funcionalidad no documentada y no expuesta para sacar más provecho de las APIs y tecnologías utilizadas.
- Encuentra dependencias y diferentes assemblies
- Localiza la ubicación exacta de errores en tu código, componentes de terceros y libraries.
- Hace debugging en el origen de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier OS (puedes instalarlo directamente desde VSCode, no hace falta descargar el git. Haz clic en **Extensions** y **search ILSpy**).\
Si necesitas **decompile**, **modify** y **recompile** de nuevo puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenido activamente de este, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** para cambiar algo dentro de una función).

### DNSpy Logging

Para hacer que **DNSpy registre alguna información en un archivo**, puedes usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración con DNSpy

Para depurar código usando DNSpy necesitas:

Primero, cambiar los **Assembly attributes** relacionados con la **depuración**:

![DNSpy Logging - DNSpy Debugging: First, change the Assembly attributes related to debugging](<../../images/image (973).png>)

From:
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
Y haz clic en **compile**:

![DNSpy Logging - DNSpy Debugging: And click on compile](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo mediante _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Then save the new file via File Save module](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimisations** al código y podría ocurrir que, al depurar, un **break-point is never hit** o que algunas **variables don't exist**.

Entonces, si tu aplicación .NET se está **run**nando mediante **IIS**, puedes **restart**arla con:
```
iisreset /noforce
```
Entonces, para empezar a depurar, deberías cerrar todos los archivos abiertos y dentro de la **Debug Tab** seleccionar **Attach to Process...**:

![DNSpy Logging - DNSpy Debugging: Then, in order to start debugging you should close all the opened files and inside the Debug Tab select Attach to Process](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarlo al **IIS server** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: Then select w3wp.exe to attach to the IIS server and click attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es momento de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego haz clic en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Now that we are debugging the process, it's time to stop it and load all the modules. First click on Debug Break All and then click on Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo en **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Click any module on Modules and select Open All Modules](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo en **Assembly Explorer** y haz clic en **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Right click any module in Assembly Explorer and click Sort Assemblies](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Select " Suspend on library load/unload "](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![Debugging DLLs - Using IDA: Configure the parameters of the execution putting the path to the DLL and the function that you want to call](<../../images/image (704).png>)

Luego, cuando inicies la depuración, **la ejecución se detendrá cada vez que se cargue una DLL**, así que cuando rundll32 cargue tu DLL la ejecución se detendrá.

Pero, ¿cómo puedes llegar al código de la DLL que fue cargada? Usando este método, no sé cómo.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![Using IDA - Using x64dbg/x32dbg: Notice that when the execution is stopped by any reason in win64dbg you can see in which code you are looking in the top of the win64dbg window](<../../images/image (842).png>)

Then, looking to this ca see when the execution was stopped in the dll you want to debug.

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) is a useful program to find where important values are saved inside the memory of a running game and change them. More info in:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) is a front-end/reverse engineering tool for the GNU Project Debugger (GDB), focused on games. However, it can be used for any reverse-engineering related stuff

[**Decompiler Explorer**](https://dogbolt.org/) is a web front-end to a number of decompilers. This web service lets you compare the output of different decompilers on small executables.

## ARM & MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) will **allocate** the **shellcode** inside a space of memory, will **indicate** you the **memory address** were the shellcode was allocated and will **stop** the execution.\
Then, you need to **attach a debugger** (Ida or x64dbg) to the process and put a **breakpoint the indicated memory address** and **resume** the execution. This way you will be debugging the shellcode.

The releases github page contains zips containing the compiled releases: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
You can find a slightly modified version of Blobrunner in the following link. In order to compile it just **create a C/C++ project in Visual Studio Code, copy and paste the code and build it**.


{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)is very similar to blobrunner. It will **allocate** the **shellcode** inside a space of memory, and start an **eternal loop**. You then need to **attach the debugger** to the process, **play start wait 2-5 secs and press stop** and you will find yourself inside the **eternal loop**. Jump to the next instruction of the eternal loop as it will be a call to the shellcode, and finally you will find yourself executing the shellcode.

![Debugging a shellcode with blobrunner - Debugging a shellcode with jmp2it: jmp2it is very similar to blobrunner. It will allocate the shellcode inside a space of memory, and start an...](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it...](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (589).png>)

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically...](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![Debugging a shellcode with jmp2it - Debugging shellcode using Cutter: You can see the stack for example inside a hex dump](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

You should try [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
It will tell you things like **which functions** is the shellcode using and if the shellcode is **decoding** itself in memory.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que quieres y ejecutar el shellcode

![Debugging shellcode using Cutter - Deobfuscating shellcode and getting executed functions: scDbg also counts with a graphical launcher where you can select the options you want and...](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza cualquier cambio en el shellcode dinámicamente en memoria (útil para descargar el shellcode decodificado). La opción **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode usando el terminal de scDbg (sin embargo, encuentro que cualquiera de las opciones explicadas antes es mejor para esto, ya que podrás usar Ida o x64dbg).

### Disassembling using CyberChef

Sube tu archivo de shellcode como entrada y usa la siguiente recipe para decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

La obfuscation **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que mezclan operadores aritméticos (`+`, `-`, `*`) y bitwise (`&`, `|`, `^`, `~`, shifts). La parte importante es que estas identidades suelen ser correctas solo bajo **fixed-width modular arithmetic**, así que los carries y los overflows importan:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si simplificas este tipo de expresión con tooling algebraico genérico, puedes obtener fácilmente un resultado incorrecto porque se ignoraron las semánticas del bit-width.

### Flujo de trabajo práctico

1. **Mantén el bit-width original** del código/IR/output del decompiler levantado (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
- **Linear**: sumas ponderadas de átomos bitwise
- **Semilinear**: linear más máscaras constantes como `x & 0xFF`
- **Polynomial**: aparecen productos
- **Mixed**: productos y lógica bitwise están intercalados, a menudo con subexpresiones repetidas
3. **Verifica cada rewrite candidato** con pruebas aleatorias o una prueba SMT. Si no se puede probar la equivalencia, conserva la expresión original en lugar de adivinar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador MBA práctico para malware analysis y protected-binary reversing. Clasifica la expresión y la enruta por pipelines especializados en lugar de aplicar un solo rewrite pass genérico a todo.

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

- **Linear MBA**: CoBRA evalúa la expresión en entradas booleanas, deriva una firma y ejecuta en paralelo varios métodos de recuperación, como pattern matching, ANF conversion y coefficient interpolation.
- **Semilinear MBA**: los átomos con máscara constante se reconstruyen con bit-partitioned reconstruction para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en cores y las subexpresiones repetidas pueden elevarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que normalmente vale la pena intentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Esto puede reducirse a:
```c
x * y
```
### Notas de Reversing

- Preferir ejecutar CoBRA sobre **lifted IR expressions** o la salida del decompiler después de aislar el cálculo exacto.
- Usar `--bitwidth` explícitamente cuando la expresión provenga de aritmética enmascarada o registros estrechos.
- Si necesitas un paso de prueba más fuerte, revisa las notas locales de Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **LLVM pass plugin** (`libCobraPass.so`), lo cual es útil cuando quieres normalizar LLVM IR con mucho MBA antes de otros analysis passes.
- Los unsupported carry-sensitive mixed-domain residuals deberían tratarse como una señal para conservar la expresión original y razonar manualmente sobre el carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este obfuscator **modifies all the instructions for `mov`**(sí, de verdad, muy cool). También usa interruptions para cambiar executions flows. Para más información sobre cómo funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) deofuscará el binary. Tiene varias dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, este workaround para encontrar la flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada** busca las funciones por `::main` como en:

![Movfuscator - Rust: To find the entry point search the functions by ::main like in](<../../images/image (1080).png>)

En este caso el binario se llamaba authenticator, así que es bastante obvio que esta es la función main interesante.\
Teniendo el **nombre** de las **funciones** que se llaman, búscalas en **Internet** para aprender sobre sus **entradas** y **salidas**.

### Recovering Rust strings from ELF firmware

En binarios **Rust ELF**, muchas cadenas estáticas no se referencian como punteros estilo C terminados en NUL. Un diseño común de `rustc` es una **tupla puntero/longitud** dentro de **`.data.rel.ro`** apuntando al blob real de la cadena almacenado en **`.rodata`**:
```text
[8-byte little-endian pointer][8-byte little-endian length]
```
Esto significa que `strings` o el análisis por defecto de Ghidra pueden fusionar cadenas adyacentes o perder por completo las cross-references.

Quick workflow:
```bash
readelf -S <bin>
objdump -h <bin>
```
1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** una palabra a la vez.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un posible puntero a una cadena.
4. Trata la siguiente palabra como la posible longitud.
5. Aplica filtros de coherencia (por ejemplo, mantén longitudes entre **4** y **100** bytes).
6. Lee exactamente `length` bytes desde `.rodata` en lugar de escanear hasta `0x00`.

Minimal extractor logic:
```python
for off in range(0, len(data_rel_ro), 8):
ptr = u64(data_rel_ro[off:off+8])
length = u64(data_rel_ro[off+8:off+16])
if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
start = ptr - rodata_start
print(rodata[start:start+length])
```
Esto es especialmente útil en reversing de firmware porque las cadenas Rust recuperadas a menudo revelan **HTTP routes, RPC names, log messages, assertions, filenames, config keys, command handlers y lógica relacionada con auth**.

Si Ghidra no encuentra esas cadenas, ejecuta un script/plugin personalizado que aplique la misma heuristic y cree datos de string en los offsets `.rodata` referenciados. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **word sizes, endianness y section layouts**.

## **Delphi**

Para binarios compilados con Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugeriría usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Solo pulsa **ATL+f7** (import python plugin en IDA) y selecciona el python plugin.

Este plugin ejecutará el binario y resolverá los nombres de las funciones dinámicamente al inicio del debugging. Después de iniciar el debugging, pulsa de nuevo el botón Start (el verde o f9) y un breakpoint saltará al principio del código real.

También es muy interesante porque si pulsas un botón en la aplicación gráfica, el debugger se detendrá en la función ejecutada por ese bottom.

## Golang

Si tienes que hacer reversing de un binario Golang, te sugeriría usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Solo pulsa **ATL+f7** (import python plugin en IDA) y selecciona el python plugin.

Esto resolverá los nombres de las funciones.

## Compiled Python

En esta página puedes encontrar cómo obtener el código python desde un binario compilado python ELF/EXE:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si obtienes el **binary** de un juego de GBA puedes usar diferentes herramientas para **emular** y **debug**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Download the debug version_) - Contiene un debugger con interfaz
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **buttons** de Game Boy Advance

![no$gba controls configuration showing Game Boy Advance button mappings](<../../images/image (581).png>)

Cuando se pulsa, cada **key tiene un valor** para identificarla:
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
Entonces, en este tipo de programa, la parte interesante será **cómo el programa trata la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![Ghidra view of a GBA binary referencing KEYINPUT at address 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función se llama desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

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
El último if está comprobando que **`uVar4`** está en las **Last Keys** y no es la tecla actual, también llamado soltar un botón (la tecla actual se almacena en **`uVar1`**).
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
En el código anterior puedes ver que estamos comparando **uVar1** (el lugar donde está el **valor del botón pulsado**) con algunos valores:

- Primero, se compara con el **valor 4** (**SELECT** button): En el challenge este botón limpia la pantalla
- Luego, se compara con el **valor 8** (**START** button): En el challenge esto comprueba si el código es válido para obtener la flag.
- En este caso la var **`DAT_030000d8`** se compara con 0xf3 y si el valor es el mismo se ejecuta cierto código.
- En cualquier otro caso, se comprueba un cont (**`DAT_030000d4`**). Es un cont porque suma 1 justo después de entrar en el código.\
**S**i es menor que 8, se hace algo que implica **añadir** valores a **`DAT_030000d8`** (básicamente, está añadiendo a esta variable los valores de las teclas pulsadas mientras el cont sea menor que 8).

Así que, en este challenge, sabiendo los valores de los botones, necesitabas **pulsar una combinación con longitud menor que 8 cuyo resultado al sumar sea 0xf3.**

**Reference for this tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Courses

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Binary deobfuscation)

## References

- [Simplifying MBA obfuscation with CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [Trail of Bits CoBRA repository](https://github.com/trailofbits/CoBRA)
- [Decoding Rust strings - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [pentestpartners/reverse-engineering - rust-strings](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)

{{#include ../../banners/hacktricks-training.md}}
