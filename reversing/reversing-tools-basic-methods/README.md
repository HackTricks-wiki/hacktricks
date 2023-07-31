# Herramientas de Reversión y Métodos Básicos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Herramientas de Reversión basadas en ImGui

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Descompilador Wasm / Compilador Wat

En línea:

* Utiliza [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binario) a wat (texto claro)
* Utiliza [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
* También puedes probar a utilizar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para descompilar

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Descompilador .Net

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina múltiples formatos**, incluyendo **bibliotecas** (.dll), archivos de **metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, se puede guardar un ensamblado como un proyecto de Visual Studio (.csproj).

El mérito aquí es que si se requiere la restauración de un código fuente perdido a partir de un ensamblado heredado, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica a lo largo del código descompilado, lo que lo convierte en una de las herramientas perfectas para el análisis de algoritmos de Xamarin.

### [.Net Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo de complemento integral y una API que amplía la herramienta para adaptarse a tus necesidades exactas, .NET reflector ahorra tiempo y simplifica el desarrollo. Echemos un vistazo a la multitud de servicios de ingeniería inversa que esta herramienta proporciona:

* Proporciona una visión de cómo fluye los datos a través de una biblioteca o componente
* Proporciona información sobre la implementación y el uso de lenguajes y marcos de trabajo .NET
* Encuentra funcionalidades no documentadas y no expuestas para obtener más de las API y tecnologías utilizadas.
* Encuentra dependencias y diferentes ensamblados
* Localiza la ubicación exacta de los errores en tu código, componentes de terceros y bibliotecas.
* Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, no es necesario descargar el git. Haz clic en **Extensiones** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y **volver a compilar**, puedes usar: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) (**Haz clic derecho -> Modificar Método** para cambiar algo dentro de una función).\
También puedes probar [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

### Registro de DNSpy

Para hacer que **DNSpy registre alguna información en un archivo**, puedes utilizar estas líneas de código .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración con DNSpy

Para depurar código utilizando DNSpy, debes seguir estos pasos:

Primero, cambia los **atributos de ensamblado** relacionados con la **depuración**:

![](<../../.gitbook/assets/image (278).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
A: Reversing Tools - Basic Methods

# Reversing Tools

## Introduction

Reversing tools are essential for any hacker or security professional involved in reverse engineering. These tools allow you to analyze and understand the inner workings of software, identify vulnerabilities, and develop exploits. In this guide, we will cover some of the basic methods and tools used in the field of reverse engineering.

## Static Analysis

Static analysis involves examining the binary code of a program without executing it. This can be done using tools such as disassemblers and decompilers. Disassemblers convert machine code into assembly code, making it easier to understand and analyze. Decompilers, on the other hand, convert machine code into a higher-level programming language, such as C or C++. This allows for a more comprehensive analysis of the code.

## Dynamic Analysis

Dynamic analysis involves running the program and observing its behavior in real-time. This can be done using tools such as debuggers and dynamic analysis frameworks. Debuggers allow you to step through the code, set breakpoints, and inspect variables and memory. Dynamic analysis frameworks provide a more automated approach, allowing you to monitor system calls, network traffic, and other runtime behavior.

## Binary Patching

Binary patching involves modifying the binary code of a program to alter its behavior. This can be useful for bypassing security measures, removing licensing restrictions, or fixing bugs. Tools such as hex editors and patchers can be used to modify the binary code directly. However, caution must be exercised when patching binaries, as it can introduce unintended consequences and instability.

## Obfuscation and Anti-Reversing Techniques

Obfuscation and anti-reversing techniques are used to make the reverse engineering process more difficult. These techniques can include code obfuscation, encryption, and anti-debugging measures. Reverse engineers must be familiar with these techniques in order to overcome them and analyze the software effectively.

## Conclusion

Reversing tools are essential for reverse engineering and understanding the inner workings of software. By using static and dynamic analysis techniques, binary patching, and understanding obfuscation and anti-reversing techniques, hackers and security professionals can identify vulnerabilities and develop effective exploits.
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Y haz clic en **compilar**:

![](<../../.gitbook/assets/image (314) (1) (1).png>)

Luego guarda el nuevo archivo en _**Archivo >> Guardar módulo...**_:

![](<../../.gitbook/assets/image (279).png>)

Esto es necesario porque si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código y podría ser posible que al depurar no se alcance un **punto de interrupción** o que algunas **variables no existan**.

Luego, si tu aplicación .Net está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```
iisreset /noforce
```
Luego, para comenzar a depurar, debes cerrar todos los archivos abiertos y dentro de la pestaña **Depurar**, seleccionar **Adjuntar a proceso...**:

![](<../../.gitbook/assets/image (280).png>)

Luego selecciona **w3wp.exe** para adjuntarlo al servidor **IIS** y haz clic en **adjuntar**:

![](<../../.gitbook/assets/image (281).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Depurar >> Detener todo_ y luego haz clic en _**Depurar >> Ventanas >> Módulos**_:

![](<../../.gitbook/assets/image (286).png>)

![](<../../.gitbook/assets/image (283).png>)

Haz clic en cualquier módulo en **Módulos** y selecciona **Abrir todos los módulos**:

![](<../../.gitbook/assets/image (284).png>)

Haz clic derecho en cualquier módulo en **Explorador de ensamblajes** y selecciona **Ordenar ensamblajes**:

![](<../../.gitbook/assets/image (285).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Usando IDA

* **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
* Seleccionar el depurador **Windbg**
* Seleccionar "**Suspender en carga/descarga de bibliotecas**"

![](<../../.gitbook/assets/image (135).png>)

* Configurar los **parámetros** de la ejecución colocando la **ruta de la DLL** y la función que deseas llamar:

![](<../../.gitbook/assets/image (136).png>)

Luego, cuando comiences a depurar, **la ejecución se detendrá cuando se cargue cada DLL**, entonces, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Pero, ¿cómo puedes acceder al código de la DLL que se cargó? Usando este método, no sé cómo.

### Usando x64dbg/x32dbg

* **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
* **Cambiar la línea de comandos** ( _Archivo --> Cambiar línea de comandos_ ) y establecer la ruta de la DLL y la función que deseas llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Cambiar _Opciones --> Configuración_ y seleccionar "**Entrada de DLL**".
* Luego **iniciar la ejecución**, el depurador se detendrá en cada dll principal, en algún momento te detendrás en la **Entrada de DLL de tu DLL**. A partir de ahí, simplemente busca los puntos donde deseas poner un punto de interrupción.

Ten en cuenta que cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código te encuentras** mirando en la **parte superior de la ventana de win64dbg**:

![](<../../.gitbook/assets/image (137).png>)

Luego, al mirar esto, puedes ver cuándo se detuvo la ejecución en la DLL que deseas depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan los valores importantes dentro de la memoria de un juego en ejecución y cambiarlos. Más información en:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

## ARM y MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Depuración de un shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) asignará el **shellcode** a un espacio de memoria, te indicará la **dirección de memoria** donde se asignó el shellcode y detendrá la ejecución.\
Luego, debes **adjuntar un depurador** (Ida o x64dbg) al proceso y establecer un **punto de interrupción en la dirección de memoria indicada** y **reanudar** la ejecución. De esta manera, estarás depurando el shellcode.

La página de lanzamientos de GitHub contiene archivos zip con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarlo, simplemente **crea un proyecto C/C++ en Visual Studio Code, copia y pega el código y compílalo**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Depuración de un shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)es muy similar a blobrunner. Asignará el **shellcode** a un espacio de memoria y comenzará un **bucle eterno**. Luego, debes **adjuntar el depurador** al proceso, **iniciar, esperar de 2 a 5 segundos y detener** y te encontrarás dentro del **bucle eterno**. Salta a la siguiente instrucción del bucle eterno, ya que será una llamada al shellcode, y finalmente te encontrarás ejecutando el shellcode.

![](<../../.gitbook/assets/image (397).png>)

Puedes descargar una versión compilada de [jmp2it en la página de lanzamientos](https://github.com/adamkramer/jmp2it/releases/).

### Depuración de shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la interfaz gráfica de radare. Con Cutter, puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter te permite "Abrir archivo" y "Abrir shellcode". En mi caso, cuando abrí el shellcode como archivo, lo descompiló correctamente, pero cuando lo abrí como shellcode, no lo hizo:

![](<../../.gitbook/assets/image (400).png>)

Para comenzar la emulación en el lugar que desees, establece un punto de interrupción allí y aparentemente Cutter comenzará automáticamente la emulación desde allí:

![](<../../.gitbook/assets/image (399).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![](<../../.gitbook/assets/image (402).png>)
### Desofuscando shellcode y obteniendo funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Te dirá cosas como **qué funciones** está utilizando el shellcode y si el shellcode se está **descodificando** en memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que deseas y ejecutar el shellcode.

![](<../../.gitbook/assets/image (398).png>)

La opción **Crear volcado** volcará el shellcode final si se realiza algún cambio en el shellcode de forma dinámica en la memoria (útil para descargar el shellcode decodificado). El **desplazamiento de inicio** puede ser útil para iniciar el shellcode en un desplazamiento específico. La opción **Depurar Shell** es útil para depurar el shellcode utilizando la terminal de scDbg (sin embargo, encuentro que cualquiera de las opciones explicadas anteriormente es mejor para este propósito, ya que podrás usar Ida o x64dbg).

### Desensamblar usando CyberChef

Carga tu archivo de shellcode como entrada y utiliza la siguiente receta para descompilarlo: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador **modifica todas las instrucciones por `mov`** (sí, realmente genial). También utiliza interrupciones para cambiar los flujos de ejecución. Para obtener más información sobre cómo funciona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará el binario. Tiene varias dependencias.
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando un **CTF, este truco para encontrar la bandera** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada**, busca las funciones por `::main` como en:

![](<../../.gitbook/assets/image (612).png>)

En este caso, el binario se llamaba authenticator, por lo que es bastante obvio que esta es la función principal interesante.\
Teniendo el **nombre** de las **funciones** que se llaman, búscalas en **Internet** para aprender sobre sus **entradas** y **salidas**.

## **Delphi**

Para binarios compilados en Delphi, puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que revertir un binario de Delphi, te sugiero que uses el complemento de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Simplemente presiona **ATL+f7** (importar complemento de Python en IDA) y selecciona el complemento de Python.

Este complemento ejecutará el binario y resolverá los nombres de las funciones dinámicamente al inicio de la depuración. Después de iniciar la depuración, presiona nuevamente el botón de inicio (el verde o f9) y se detendrá en un punto de interrupción al comienzo del código real.

También es muy interesante porque si presionas un botón en la aplicación gráfica, el depurador se detendrá en la función ejecutada por ese botón.

## Golang

Si tienes que revertir un binario de Golang, te sugiero que uses el complemento de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Simplemente presiona **ATL+f7** (importar complemento de Python en IDA) y selecciona el complemento de Python.

Esto resolverá los nombres de las funciones.

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario compilado ELF/EXE:

{% content-ref url="../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emularlo** y **depurarlo**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Contiene un depurador con interfaz
* [**mgba** ](https://mgba.io)- Contiene un depurador de línea de comandos
* [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Complemento de Ghidra
* [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Complemento de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Options --> Emulation Setup --> Controls**_\*\* \*\* puedes ver cómo presionar los **botones** de Game Boy Advance

![](<../../.gitbook/assets/image (578).png>)

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
Entonces, en este tipo de programas, una parte interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![](<../../.gitbook/assets/image (579).png>)

En la imagen anterior puedes ver que la función es llamada desde **FUN\_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de inicialización (sin importancia alguna):
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
Se ha encontrado este código:
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
El último `if` verifica si **`uVar4`** está en las **últimas teclas** y no es la tecla actual, también conocido como soltar un botón (la tecla actual se almacena en **`uVar1`**).
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
En el código anterior se puede ver que estamos comparando **uVar1** (el lugar donde se encuentra el **valor del botón presionado**) con algunos valores:

* Primero, se compara con el **valor 4** (botón **SELECT**): En el desafío, este botón borra la pantalla.
* Luego, se compara con el **valor 8** (botón **START**): En el desafío, esto verifica si el código es válido para obtener la bandera.
* En este caso, se compara la variable **`DAT_030000d8`** con 0xf3 y si el valor es el mismo, se ejecuta algún código.
* En cualquier otro caso, se verifica una variable llamada `cont` (`DAT_030000d4`). Es una variable de control porque se le suma 1 justo después de ingresar el código.
* Si es menor que 8, se realiza algo que implica **agregar** valores a la variable **`DAT_030000d8`** (básicamente se suman los valores de los botones presionados en esta variable siempre y cuando `cont` sea menor que 8).

Entonces, en este desafío, sabiendo los valores de los botones, necesitabas **presionar una combinación con una longitud menor a 8 para que la suma resultante sea 0xf3**.

**Referencia para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación binaria)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
