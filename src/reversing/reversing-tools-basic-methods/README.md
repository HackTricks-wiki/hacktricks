# Reversing Tools & Basic Methods

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de Reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Descompilador Wasm / Compilador Wat

Online:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binario) a wat (texto claro)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- también puedes probar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para decompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Descompilador .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **decompila e inspecciona múltiples formatos**, incluyendo **libraries** (.dll), **Windows metadata file**s (.winmd) y **executables** (.exe). Una vez decompilado, un assembly puede guardarse como un proyecto de Visual Studio (.csproj).

La ventaja aquí es que, si el código fuente perdido necesita restaurarse a partir de un assembly heredado, esta acción puede ahorrar tiempo. Además, dotPeek ofrece una navegación muy práctica por todo el código decompilado, lo que lo convierte en una de las herramientas perfectas para el **análisis de algoritmos Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo completo de add-in y una API que amplía la herramienta para adaptarse exactamente a tus necesidades, .NET reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran variedad de servicios de reverse engineering que ofrece esta herramienta:

- Proporciona una visión de cómo fluyen los datos a través de una library o componente
- Proporciona información sobre la implementación y el uso de lenguajes y frameworks .NET
- Encuentra funcionalidad no documentada y no expuesta para sacar más partido de las APIs y tecnologías utilizadas.
- Encuentra dependencias y diferentes assemblies
- Localiza la ubicación exacta de errores en tu código, componentes de terceros y libraries.
- Depura el origen de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[ILSpy plugin for Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier OS (puedes instalarlo directamente desde VSCode, no hace falta descargar el git. Haz clic en **Extensions** y **search ILSpy**).\
Si necesitas **decompilar**, **modificar** y **recompilar** de nuevo puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork de este mantenido activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Right Click -> Modify Method** para cambiar algo dentro de una función).

### DNSpy Logging

Para hacer que **DNSpy registre algo de información en un archivo**, puedes usar este snippet:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración con DNSpy

Para depurar código usando DNSpy necesitas:

Primero, cambia los **Assembly attributes** relacionados con **debugging**:

![](<../../images/image (973).png>)

Desde:
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

![](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo mediante _**File >> Save module...**_:

![](<../../images/image (602).png>)

Esto es necesario porque si no haces esto, en **runtime** se aplicarán varias **optimisations** al código y podría ocurrir que, أثناء debugging, un **break-point nunca se alcance** o que algunas **variables no existan**.

Entonces, si tu aplicación .NET está siendo **run** por **IIS** puedes **restart**arla con:
```
iisreset /noforce
```
Entonces, para empezar a depurar debes cerrar todos los archivos abiertos y dentro de la **Debug Tab** seleccionar **Attach to Process...**:

![](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarte al **IIS server** y haz clic en **attach**:

![](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego haz clic en _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Haz clic en cualquier módulo en **Modules** y selecciona **Open All Modules**:

![](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo en **Assembly Explorer** y pulsa **Sort Assemblies**:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- Select **Windbg** debugger
- Select "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configure the **parameters** of the execution putting the **path to the DLL** and the function that you want to call:

![](<../../images/image (704).png>)

Then, when you start debugging **the execution will be stopped when each DLL is loaded**, then, when rundll32 load your DLL the execution will be stopped.

But, how can you get to the code of the DLL that was lodaded? Using this method, I don't know how.

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Change the Command Line** ( _File --> Change Command Line_ ) and set the path of the dll and the function that you want to call, for example: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Change _Options --> Settings_ and select "**DLL Entry**".
- Then **start the execution**, the debugger will stop at each dll main, at some point you will **stop in the dll Entry of your dll**. From there, just search for the points where you want to put a breakpoint.

Notice that when the execution is stopped by any reason in win64dbg you can see **in which code you are** looking in the **top of the win64dbg window**:

![](<../../images/image (842).png>)

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

![](<../../images/image (509).png>)

You can download a compiled version of [jmp2it inside the releases page](https://github.com/adamkramer/jmp2it/releases/).

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) is the GUI of radare. Using cutter you can emulate the shellcode and inspect it dynamically.

Note that Cutter allows you to "Open File" and "Open Shellcode". In my case when I opened the shellcode as a file it decompiled it correctly, but when I opened it as a shellcode it didn't:

![](<../../images/image (562).png>)

In order to start the emulation in the place you want to, set a bp there and apparently cutter will automatically start the emulation from there:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

You can see the stack for example inside a hex dump:

![](<../../images/image (186).png>)

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
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que quieras y ejecutar el shellcode

![](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio en el shellcode de forma dinámica en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode usando el terminal de scDbg (sin embargo, considero que cualquiera de las opciones explicadas antes es mejor para este caso, ya que podrás usar Ida o x64dbg).

### Disassembling using CyberChef

Sube tu archivo shellcode como entrada y usa la siguiente receta para decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## MBA obfuscation deobfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` detrás de fórmulas que mezclan operadores aritméticos (`+`, `-`, `*`) y bitwise (`&`, `|`, `^`, `~`, shifts). La parte importante es que estas identidades normalmente solo son correctas bajo **fixed-width modular arithmetic**, por lo que los carries y overflows importan:
```c
(x ^ y) + 2 * (x & y) == x + y
```
Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoraron las semánticas de ancho de bits.

### Flujo de trabajo práctico

1. **Mantén el ancho de bits original** del código/IR/decompiler output elevado (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
- **Lineal**: sumas ponderadas de átomos bit a bit
- **Semilineal**: lineal más máscaras constantes como `x & 0xFF`
- **Polinómica**: aparecen productos
- **Mixta**: los productos y la lógica bit a bit están entrelazados, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** con pruebas aleatorias o una prueba SMT. Si la equivalencia no puede demostrarse, conserva la expresión original en lugar de adivinar.

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador MBA práctico para análisis de malware y reversing de binarios protegidos. Clasifica la expresión y la enruta a través de pipelines especializados en lugar de aplicar un único paso genérico de reescritura a todo.

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

- **Linear MBA**: CoBRA evalúa la expresión sobre entradas booleanas, deriva una firma y ejecuta en paralelo varios métodos de recuperación, como pattern matching, conversión a ANF e interpolación de coeficientes.
- **Semilinear MBA**: los átomos con máscara constante se reconstruyen con bit-partitioned reconstruction para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en cores y las subexpresiones repetidas pueden elevarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixed que suele valer la pena intentar recuperar:
```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```
Esto puede reducirse a:
```c
x * y
```
### Reversing notes

- Prefiere ejecutar CoBRA sobre **lifted IR expressions** o la salida del decompiler después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética enmascarada o registros estrechos.
- Si necesitas un paso de prueba más fuerte, revisa las notas locales de Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también se distribuye como un **LLVM pass plugin** (`libCobraPass.so`), lo cual es útil cuando quieres normalizar LLVM IR con mucho MBA antes de pasos de análisis posteriores.
- Los residuales mixtos de dominio sensibles al carry no soportados deben tratarse como una señal para mantener la expresión original y razonar manualmente sobre la carry path.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

This obfuscator **modifies all the instructions for `mov`**(yeah, really cool). It also uses interruptions to change executions flows. For more information about how does it works:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

If you are lucky [demovfuscator](https://github.com/kirschju/demovfuscator) will deofuscate the binary. It has several dependencies
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, este workaround para encontrar la flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **entry point** busca las funciones por `::main` como en:

![](<../../images/image (1080).png>)

En este caso el binario se llamaba authenticator, así que es bastante obvio que esta es la función main interesante.\
Teniendo el **nombre** de las **funciones** que se están llamando, búscalas en **Internet** para aprender sobre sus **inputs** y **outputs**.

## **Delphi**

Para binarios compilados con Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reverse a un binario Delphi te sugeriría usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Solo presiona **ATL+f7** (import python plugin en IDA) y selecciona el plugin de python.

Este plugin ejecutará el binario y resolverá los nombres de las funciones dinámicamente al inicio del debugging. Después de iniciar el debugging presiona otra vez el botón Start (el verde o f9) y saltará un breakpoint al comienzo del código real.

También es muy interesante porque si presionas un botón en la aplicación gráfica el debugger se detendrá en la función ejecutada por ese botón.

## Golang

Si tienes que hacer reverse a un binario Golang te sugeriría usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Solo presiona **ATL+f7** (import python plugin en IDA) y selecciona el plugin de python.

Esto resolverá los nombres de las funciones.

## Compiled Python

En esta página puedes encontrar cómo obtener el código python desde un binario ELF/EXE de python compilado:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si obtienes el **binary** de un juego de GBA puedes usar diferentes herramientas para **emular** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión debug_) - Contiene un debugger con interfaz
- [**mgba** ](https://mgba.io)- Contiene un debugger CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![](<../../images/image (581).png>)

Cuando se pulsa, cada **key tiene un value** para identificarla:
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

![](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función es llamada desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de init (sin importancia):
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
El último if está comprobando que **`uVar4`** esté en las **last Keys** y no sea la key actual, también llamado soltar un botón (la key actual se almacena en **`uVar1`**).
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
- En este caso la var **`DAT_030000d8`** se compara con 0xf3 y si el valor es el mismo se ejecuta algo de código.
- En cualquier otro caso, se comprueba un cont (`DAT_030000d4`). Es un cont porque suma 1 justo después de entrar en el código.\
**S**i es menor que 8, se hace algo que implica **sumar** valores a **`DAT_030000d8`** (básicamente está sumando los valores de las teclas pulsadas en esta variable siempre que el cont sea menor que 8).

Así que, en este challenge, sabiendo los valores de los botones, necesitabas **pulsar una combinación con una longitud menor que 8 cuya suma resultante sea 0xf3.**

**Referencia para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

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

{{#include ../../banners/hacktricks-training.md}}
