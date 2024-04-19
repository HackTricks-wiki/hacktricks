# Herramientas de Reversing y Métodos Básicos

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Try Hard Security Group**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## Herramientas de Reversing basadas en ImGui

Software:

* ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Decompilador Wasm / Compilador Wat

En línea:

* Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm (binario) a wat (texto claro)
* Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
* También puedes probar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para decompilar

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Decompilador .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un decompilador que **decompila y examina múltiples formatos**, incluyendo **bibliotecas** (.dll), archivos de metadatos de Windows (.winmd) y **ejecutables** (.exe). Una vez decompilado, un ensamblado se puede guardar como un proyecto de Visual Studio (.csproj).

El mérito aquí es que si se necesita restaurar el código fuente perdido de un ensamblado heredado, esta acción puede ahorrar tiempo. Además, dotPeek proporciona una navegación práctica a lo largo del código decompilado, convirtiéndolo en una de las herramientas perfectas para el **análisis de algoritmos de Xamarin.**

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un modelo de complemento integral y una API que extiende la herramienta para adaptarse a tus necesidades exactas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Echemos un vistazo a la multitud de servicios de ingeniería inversa que esta herramienta proporciona:

* Proporciona una visión de cómo fluye los datos a través de una biblioteca o componente
* Proporciona información sobre la implementación y el uso de lenguajes y marcos .NET
* Encuentra funcionalidades no documentadas y no expuestas para sacar más provecho de las API y tecnologías utilizadas.
* Encuentra dependencias y diferentes ensamblados
* Rastrea la ubicación exacta de errores en tu código, componentes de terceros y bibliotecas.
* Depura en el origen de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) & [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode, no es necesario descargar el git. Haz clic en **Extensiones** y **busca ILSpy**).\
Si necesitas **decompilar**, **modificar** y **recompilar** nuevamente, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o un fork de él mantenido activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modificar método** para cambiar algo dentro de una función).

### Registro de DNSpy

Para hacer que **DNSpy registre alguna información en un archivo**, puedes usar este fragmento:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### Depuración de DNSpy

Para depurar código usando DNSpy, necesitas:

Primero, cambiar los **atributos de ensamblado** relacionados con la **depuración**:

![](<../../.gitbook/assets/image (970).png>)
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

![](<../../.gitbook/assets/image (314) (1).png>)

Luego guarda el nuevo archivo a través de _**Archivo >> Guardar módulo...**_:

![](<../../.gitbook/assets/image (599).png>)

Esto es necesario porque si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código y podría ser posible que mientras depuras un **punto de interrupción nunca se alcance** o algunas **variables no existan**.

Entonces, si tu aplicación .NET está siendo **ejecutada** por **IIS** puedes **reiniciarla** con:
```
iisreset /noforce
```
Luego, para comenzar a depurar, debes cerrar todos los archivos abiertos y dentro de la pestaña **Depurar** seleccionar **Adjuntar a proceso...**:

![](<../../.gitbook/assets/image (315).png>)

Luego selecciona **w3wp.exe** para adjuntarlo al **servidor IIS** y haz clic en **adjuntar**:

![](<../../.gitbook/assets/image (110).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero haz clic en _Depurar >> Detener todo_ y luego haz clic en _**Depurar >> Ventanas >> Módulos**_:

![](<../../.gitbook/assets/image (129).png>)

![](<../../.gitbook/assets/image (831).png>)

Haz clic en cualquier módulo en **Módulos** y selecciona **Abrir todos los módulos**:

![](<../../.gitbook/assets/image (919).png>)

Haz clic derecho en cualquier módulo en **Explorador de ensamblados** y haz clic en **Ordenar ensamblados**:

![](<../../.gitbook/assets/image (336).png>)

## Descompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Usando IDA

* **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
* Seleccionar el depurador **Windbg**
* Seleccionar "**Suspender en carga/descarga de librerías**"

![](<../../.gitbook/assets/image (865).png>)

* Configurar los **parámetros** de la ejecución colocando la **ruta de la DLL** y la función que deseas llamar:

![](<../../.gitbook/assets/image (701).png>)

Entonces, al comenzar a depurar, la ejecución se detendrá cuando se cargue cada DLL, por lo que cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Pero, ¿cómo puedes acceder al código de la DLL que se cargó? Usando este método, no sé cómo.

### Usando x64dbg/x32dbg

* **Cargar rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
* **Cambiar la línea de comandos** ( _Archivo --> Cambiar línea de comandos_ ) y establecer la ruta de la DLL y la función que deseas llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii\_2.dll",DLLMain
* Cambiar _Opciones --> Configuración_ y seleccionar "**Entrada de DLL**".
* Luego **iniciar la ejecución**, el depurador se detendrá en cada dll principal, en algún momento te **detendrás en la Entrada de DLL de tu dll**. Desde allí, simplemente busca los puntos donde deseas colocar un punto de interrupción.

Ten en cuenta que cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![](<../../.gitbook/assets/image (839).png>)

Entonces, al mirar esto, puedes ver cuándo se detuvo la ejecución en la dll que deseas depurar.

## Aplicaciones GUI / Videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan los valores importantes dentro de la memoria de un juego en ejecución y cambiarlos. Más información en:

{% content-ref url="cheat-engine.md" %}
[cheat-engine.md](cheat-engine.md)
{% endcontent-ref %}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de ingeniería inversa/front-end para el Depurador del Proyecto GNU (GDB), enfocada en juegos. Sin embargo, se puede utilizar para cualquier cosa relacionada con la ingeniería inversa.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios descompiladores. Este servicio web te permite comparar la salida de diferentes descompiladores en ejecutables pequeños.

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Depuración de un shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **asignará** el **shellcode** dentro de un espacio de memoria, te **indicará** la **dirección de memoria** donde se asignó el shellcode y **detendrá** la ejecución.\
Luego, debes **adjuntar un depurador** (Ida o x64dbg) al proceso y colocar un **punto de interrupción en la dirección de memoria indicada** y **resumir** la ejecución. De esta manera estarás depurando el shellcode.

La página de lanzamientos en GitHub contiene archivos zip con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarlo, simplemente **crea un proyecto C/C++ en Visual Studio Code, copia y pega el código y compílalo**.

{% content-ref url="blobrunner.md" %}
[blobrunner.md](blobrunner.md)
{% endcontent-ref %}

### Depuración de un shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)es muy similar a blobrunner. **Asignará** el **shellcode** dentro de un espacio de memoria y comenzará un **bucle eterno**. Luego debes **adjuntar el depurador** al proceso, **iniciar, esperar 2-5 segundos y presionar detener** y te encontrarás dentro del **bucle eterno**. Salta a la siguiente instrucción del bucle eterno, ya que será una llamada al shellcode, y finalmente te encontrarás ejecutando el shellcode.

![](<../../.gitbook/assets/image (506).png>)

Puedes descargar una versión compilada de [jmp2it en la página de lanzamientos](https://github.com/adamkramer/jmp2it/releases/).

### Depuración de shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la interfaz gráfica de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter te permite "Abrir archivo" y "Abrir shellcode". En mi caso, cuando abrí el shellcode como archivo, lo descompiló correctamente, pero cuando lo abrí como shellcode no lo hizo:

![](<../../.gitbook/assets/image (559).png>)

Para iniciar la emulación en el lugar que desees, establece un punto de interrupción allí y aparentemente Cutter iniciará automáticamente la emulación desde allí:

![](<../../.gitbook/assets/image (586).png>)

![](<../../.gitbook/assets/image (384).png>)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![](<../../.gitbook/assets/image (183).png>)

### Desofuscación de shellcode y obtención de funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7\&pid=152).\
Te dirá cosas como **qué funciones** está utilizando el shellcode y si el shellcode se está **descodificando** en la memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que deseas y ejecutar el shellcode

![](<../../.gitbook/assets/image (255).png>)

La opción **Crear volcado** volcará el shellcode final si se realiza algún cambio en el shellcode dinámicamente en la memoria (útil para descargar el shellcode decodificado). El **desplazamiento de inicio** puede ser útil para iniciar el shellcode en un desplazamiento específico. La opción **Depurar Shell** es útil para depurar el shellcode utilizando la terminal scDbg (sin embargo, considero que cualquiera de las opciones explicadas anteriormente es mejor para este propósito, ya que podrás utilizar Ida o x64dbg).

### Desensamblaje usando CyberChef

Carga tu archivo de shellcode como entrada y utiliza la siguiente receta para descompilarlo: [https://gchq.github.io/CyberChef/#recipe=To\_Hex('Space',0)Disassemble\_x86('32','Full%20x86%20architecture',16,0,true,true)](https://gchq.github.io/CyberChef/#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\))

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador **modifica todas las instrucciones por `mov`** (sí, realmente genial). También utiliza interrupciones para cambiar los flujos de ejecución. Para obtener más información sobre cómo funciona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF\_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará el binario. Tiene varias dependencias
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás participando en un **CTF, este método para encontrar la bandera** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada** busca las funciones por `::main` como en:

![](<../../.gitbook/assets/image (1077).png>)

En este caso, el binario se llamaba authenticator, por lo que es bastante obvio que esta es la función principal interesante.\
Teniendo el **nombre** de las **funciones** que se llaman, búscalas en **Internet** para aprender sobre sus **entradas** y **salidas**.

## **Delphi**

Para binarios compilados en Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que revertir un binario de Delphi te sugiero que uses el complemento de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Simplemente presiona **ATL+f7** (importa el complemento de Python en IDA) y selecciona el complemento de Python.

Este complemento ejecutará el binario y resolverá los nombres de las funciones dinámicamente al inicio de la depuración. Después de iniciar la depuración, presiona nuevamente el botón de inicio (el verde o f9) y se detendrá en el comienzo del código real.

También es muy interesante porque si presionas un botón en la aplicación gráfica, el depurador se detendrá en la función ejecutada por ese botón.

## Golang

Si tienes que revertir un binario de Golang te sugiero que uses el complemento de IDA [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper)

Simplemente presiona **ATL+f7** (importa el complemento de Python en IDA) y selecciona el complemento de Python.

Esto resolverá los nombres de las funciones.

## Python compilado

En esta página puedes encontrar cómo obtener el código Python de un binario compilado ELF/EXE:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## GBA - Game Body Advance

Si obtienes el **binario** de un juego de GBA, puedes usar diferentes herramientas para **emularlo** y **depurarlo**:

* [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Contiene un depurador con interfaz
* [**mgba** ](https://mgba.io)- Contiene un depurador de CLI
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
Entonces, en este tipo de programa, la parte interesante será **cómo el programa trata la entrada del usuario**. En la dirección **0x4000130** encontrarás la función comúnmente encontrada: **KEYINPUT**.

![](<../../.gitbook/assets/image (444).png>)

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
El último if está verificando que **`uVar4`** esté en las **últimas Keys** y no sea la clave actual, también conocida como soltar un botón (la clave actual se almacena en **`uVar1`**).
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
En el código anterior se puede ver que estamos comparando **uVar1** (el lugar donde está el **valor del botón presionado**) con algunos valores:

* Primero, se compara con el **valor 4** (botón **SELECT**): En el desafío este botón borra la pantalla.
* Luego, se compara con el **valor 8** (botón **START**): En el desafío esto verifica si el código es válido para obtener la bandera.
* En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y si el valor es el mismo se ejecuta algún código.
* En cualquier otro caso, se verifica un contador (`DAT_030000d4`). Es un contador porque se suma 1 justo después de ingresar el código.\
Si es menor que 8, se hace algo que implica **agregar** valores a **`DAT_030000d8`** (básicamente se están sumando los valores de las teclas presionadas en esta variable siempre y cuando el contador sea menor que 8).

Por lo tanto, en este desafío, sabiendo los valores de los botones, necesitabas **presionar una combinación con una longitud menor que 8 para que la suma resultante sea 0xf3.**

**Referencia para este tutorial:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## Game Boy

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación binaria)

**Grupo de Seguridad Try Hard**

<figure><img src="../../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
