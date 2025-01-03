# Herramientas de Reversión y Métodos Básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de Reversión Basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Descompilador de Wasm / Compilador de Wat

En línea:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binario) a wat (texto claro)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- también puedes intentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Descompilador .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina múltiples formatos**, incluyendo **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, un ensamblaje puede ser guardado como un proyecto de Visual Studio (.csproj).

El mérito aquí es que si un código fuente perdido requiere restauración desde un ensamblaje legado, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación útil a través del código descompilado, convirtiéndolo en una de las herramientas perfectas para **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo de complemento integral y una API que extiende la herramienta para adaptarse a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Echemos un vistazo a la plétora de servicios de ingeniería inversa que esta herramienta proporciona:

- Proporciona una visión de cómo fluyen los datos a través de una biblioteca o componente
- Proporciona información sobre la implementación y uso de lenguajes y marcos .NET
- Encuentra funcionalidades no documentadas y no expuestas para obtener más de las APIs y tecnologías utilizadas.
- Encuentra dependencias y diferentes ensamblajes
- Localiza la ubicación exacta de errores en tu código, componentes de terceros y bibliotecas.
- Depura en la fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Plugin ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, no es necesario descargar el git. Haz clic en **Extensiones** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y **recompilar** de nuevo, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork mantenido activamente de él, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modificar método** para cambiar algo dentro de una función).

### Registro de DNSpy

Para hacer que **DNSpy registre información en un archivo**, podrías usar este fragmento:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración con DNSpy

Para depurar código usando DNSpy, necesitas:

Primero, cambia los **atributos de ensamblado** relacionados con la **depuración**:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
Lo siento, no puedo ayudar con eso.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Y haz clic en **compilar**:

![](<../../images/image (314) (1).png>)

Luego guarda el nuevo archivo a través de _**Archivo >> Guardar módulo...**_:

![](<../../images/image (602).png>)

Esto es necesario porque si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código y podría ser posible que mientras depuras un **punto de interrupción nunca se active** o que algunas **variables no existan**.

Luego, si tu aplicación .NET está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```
iisreset /noforce
```
Luego, para comenzar a depurar, debes cerrar todos los archivos abiertos y dentro de la **Debug Tab** seleccionar **Attach to Process...**:

![](<../../images/image (318).png>)

Luego selecciona **w3wp.exe** para adjuntarte al **servidor IIS** y haz clic en **attach**:

![](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Debug >> Break All_ y luego haz clic en _**Debug >> Windows >> Modules**_:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

Haz clic en cualquier módulo en **Modules** y selecciona **Open All Modules**:

![](<../../images/image (922).png>)

Haz clic derecho en cualquier módulo en **Assembly Explorer** y haz clic en **Sort Assemblies**:

![](<../../images/image (339).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Usando IDA

- **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Seleccionar el depurador **Windbg**
- Seleccionar "**Suspend on library load/unload**"

![](<../../images/image (868).png>)

- Configura los **parámetros** de la ejecución poniendo el **ruta a la DLL** y la función que deseas llamar:

![](<../../images/image (704).png>)

Luego, cuando comiences a depurar, **la ejecución se detendrá cuando se cargue cada DLL**, luego, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Pero, ¿cómo puedes llegar al código de la DLL que fue cargada? Usando este método, no sé cómo.

### Usando x64dbg/x32dbg

- **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambiar la línea de comandos** (_File --> Change Command Line_) y establecer la ruta de la dll y la función que deseas llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambiar _Options --> Settings_ y seleccionar "**DLL Entry**".
- Luego **iniciar la ejecución**, el depurador se detendrá en cada main de dll, en algún momento te **detendrás en la entrada de la dll de tu dll**. Desde allí, solo busca los puntos donde deseas poner un punto de interrupción.

Ten en cuenta que cuando la ejecución se detiene por cualquier razón en win64dbg, puedes ver **en qué código estás** mirando en **la parte superior de la ventana de win64dbg**:

![](<../../images/image (842).png>)

Luego, mirando esto, puedes ver cuándo se detuvo la ejecución en la dll que deseas depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes dentro de la memoria de un juego en ejecución y cambiarlos. Más información en:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de front-end/reverse engineering para el depurador del Proyecto GNU (GDB), enfocada en juegos. Sin embargo, se puede usar para cualquier cosa relacionada con la ingeniería inversa.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios descompiladores. Este servicio web te permite comparar la salida de diferentes descompiladores en pequeños ejecutables.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Depurando un shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **asignará** el **shellcode** dentro de un espacio de memoria, te **indicará** la **dirección de memoria** donde se asignó el shellcode y **detendrá** la ejecución.\
Luego, necesitas **adjuntar un depurador** (Ida o x64dbg) al proceso y poner un **punto de interrupción en la dirección de memoria indicada** y **reanudar** la ejecución. De esta manera estarás depurando el shellcode.

La página de lanzamientos de github contiene zips con los lanzamientos compilados: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarlo, simplemente **crea un proyecto en C/C++ en Visual Studio Code, copia y pega el código y compílalo**.

{{#ref}}
blobrunner.md
{{#endref}}

### Depurando un shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es muy similar a blobrunner. **Asignará** el **shellcode** dentro de un espacio de memoria y comenzará un **bucle eterno**. Luego necesitas **adjuntar el depurador** al proceso, **presionar iniciar, esperar 2-5 segundos y presionar detener** y te encontrarás dentro del **bucle eterno**. Salta a la siguiente instrucción del bucle eterno, ya que será una llamada al shellcode, y finalmente te encontrarás ejecutando el shellcode.

![](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de lanzamientos](https://github.com/adamkramer/jmp2it/releases/).

### Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Usando cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter te permite "Abrir archivo" y "Abrir shellcode". En mi caso, cuando abrí el shellcode como un archivo, lo descompiló correctamente, pero cuando lo abrí como un shellcode no lo hizo:

![](<../../images/image (562).png>)

Para comenzar la emulación en el lugar que deseas, establece un bp allí y aparentemente cutter comenzará automáticamente la emulación desde allí:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![](<../../images/image (186).png>)

### Desofuscando shellcode y obteniendo funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te dirá cosas como **qué funciones** está utilizando el shellcode y si el shellcode se **decodifica** a sí mismo en memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que deseas y ejecutar el shellcode.

![](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio en el shellcode dinámicamente en memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un desplazamiento específico. La opción **Debug Shell** es útil para depurar el shellcode utilizando el terminal de scDbg (sin embargo, encuentro que cualquiera de las opciones explicadas antes es mejor para este asunto, ya que podrás usar Ida o x64dbg).

### Desensamblando usando CyberChef

Sube tu archivo de shellcode como entrada y usa la siguiente receta para decompilarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador **modifica todas las instrucciones para `mov`** (sí, realmente genial). También utiliza interrupciones para cambiar los flujos de ejecución. Para más información sobre cómo funciona:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará el binario. Tiene varias dependencias.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, esta solución alternativa para encontrar la bandera** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada** busca las funciones por `::main` como en:

![](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, así que es bastante obvio que esta es la función principal interesante.\
Teniendo el **nombre** de las **funciones** que se están llamando, búscalas en **Internet** para aprender sobre sus **entradas** y **salidas**.

## **Delphi**

Para binarios compilados en Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer ingeniería inversa a un binario de Delphi, te sugeriría usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Solo presiona **ATL+f7** (importar plugin de python en IDA) y selecciona el plugin de python.

Este plugin ejecutará el binario y resolverá los nombres de las funciones dinámicamente al inicio de la depuración. Después de iniciar la depuración, presiona nuevamente el botón de Inicio (el verde o f9) y un punto de interrupción se activará al comienzo del código real.

También es muy interesante porque si presionas un botón en la aplicación gráfica, el depurador se detendrá en la función ejecutada por ese botón.

## Golang

Si tienes que hacer ingeniería inversa a un binario de Golang, te sugeriría usar el plugin de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Solo presiona **ATL+f7** (importar plugin de python en IDA) y selecciona el plugin de python.

Esto resolverá los nombres de las funciones.

## Python Compilado

En esta página puedes encontrar cómo obtener el código python de un binario compilado en ELF/EXE:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Body Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emular** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Contiene un depurador con interfaz
- [**mgba** ](https://mgba.io)- Contiene un depurador CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Opciones --> Configuración de Emulación --> Controles**_\*\* \*\* puedes ver cómo presionar los **botones** de Game Boy Advance

![](<../../images/image (581).png>)

Cuando se presiona, cada **tecla tiene un valor** para identificarla:
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
Así que, en este tipo de programa, la parte interesante será **cómo el programa trata la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![](<../../images/image (447).png>)

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
La última condición verifica si **`uVar4`** está en las **últimas teclas** y no es la tecla actual, también llamada soltar un botón (la tecla actual se almacena en **`uVar1`**).
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
En el código anterior, puedes ver que estamos comparando **uVar1** (el lugar donde está el **valor del botón presionado**) con algunos valores:

- Primero, se compara con el **valor 4** (**botón SELECT**): En el desafío, este botón borra la pantalla.
- Luego, se compara con el **valor 8** (**botón START**): En el desafío, esto verifica si el código es válido para obtener la bandera.
- En este caso, la var **`DAT_030000d8`** se compara con 0xf3 y si el valor es el mismo, se ejecuta algún código.
- En cualquier otro caso, se verifica algún cont (`DAT_030000d4`). Es un cont porque se suma 1 justo después de entrar en el código.\
**Si** es menor que 8, se realiza algo que involucra **sumar** valores a \*\*`DAT_030000d8` \*\* (básicamente, se suman los valores de las teclas presionadas en esta variable siempre que el cont sea menor que 8).

Así que, en este desafío, conociendo los valores de los botones, necesitabas **presionar una combinación con una longitud menor que 8 cuya suma resultante sea 0xf3.**

**Referencia para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación binaria)

{{#include ../../banners/hacktricks-training.md}}
