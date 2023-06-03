<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Decompilador Wasm / Compilador Wat

En línea:

* Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **decompilar** de wasm \(binario\) a wat \(texto claro\)
* Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
* También puedes intentar usar [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) para decompilar

Software:

* [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
* [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

# Decompilador .Net

[https://github.com/icsharpcode/ILSpy](https://github.com/icsharpcode/ILSpy)  
[Plugin ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes tenerlo en cualquier sistema operativo \(puedes instalarlo directamente desde VSCode, no es necesario descargar el git. Haz clic en **Extensiones** y **busca ILSpy**\).  
Si necesitas **decompilar**, **modificar** y **volver a compilar** de nuevo, puedes usar: [**https://github.com/0xd4d/dnSpy/releases**](https://github.com/0xd4d/dnSpy/releases) \(**Clic derecho -&gt; Modificar método** para cambiar algo dentro de una función\).  
También puedes probar [https://www.jetbrains.com/es-es/decompiler/](https://www.jetbrains.com/es-es/decompiler/)

## Registro de DNSpy

Para hacer que **DNSpy registre información en un archivo**, puedes usar estas líneas de .Net:
```bash
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
## Depuración con DNSpy

Para depurar código usando DNSpy, debes hacer lo siguiente:

Primero, cambia los **atributos de ensamblado** relacionados con la **depuración**:

![](../../.gitbook/assets/image%20%287%29.png)

Desde:
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
I'm sorry, you didn't specify the recipient of the message. Could you please provide more information?
```text
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
Y haz clic en **compilar**:

![](../../.gitbook/assets/image%20%28314%29%20%281%29.png)

Luego guarda el nuevo archivo en _**Archivo &gt;&gt; Guardar módulo...**_:

![](../../.gitbook/assets/image%20%28261%29.png)

Esto es necesario porque si no lo haces, en **tiempo de ejecución** se aplicarán varias **optimizaciones** al código y podría ser posible que mientras se depura un **punto de interrupción nunca se alcance** o algunas **variables no existan**.

Luego, si tu aplicación .Net está siendo **ejecutada** por **IIS**, puedes **reiniciarla** con:
```text
iisreset /noforce
```
Para empezar a depurar, debes cerrar todos los archivos abiertos y dentro de la pestaña **Debug**, seleccionar **Attach to Process...**:

![](../../.gitbook/assets/image%20%28166%29.png)

Luego, selecciona **w3wp.exe** para adjuntarlo al **servidor IIS** y haz clic en **attach**:

![](../../.gitbook/assets/image%20%28274%29.png)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en _Debug &gt;&gt; Break All_ y luego haz clic en _**Debug &gt;&gt; Windows &gt;&gt; Modules**_:

![](../../.gitbook/assets/image%20%28210%29.png)

![](../../.gitbook/assets/image%20%28341%29.png)

Haz clic en cualquier módulo en **Modules** y selecciona **Open All Modules**:

![](../../.gitbook/assets/image%20%28216%29.png)

Haz clic derecho en cualquier módulo en **Assembly Explorer** y haz clic en **Sort Assemblies**:

![](../../.gitbook/assets/image%20%28130%29.png)

# Decompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)  
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

# Depuración de DLLs

## Usando IDA

* **Carga rundll32** \(64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe\)
* Selecciona el depurador **Windbg**
* Selecciona "**Suspend on library load/unload**"

![](../../.gitbook/assets/image%20%2869%29.png)

* Configura los **parámetros** de la ejecución poniendo la **ruta a la DLL** y la función que deseas llamar:

![](../../.gitbook/assets/image%20%28325%29.png)

Luego, cuando comiences a depurar, **la ejecución se detendrá cuando se cargue cada DLL**, entonces, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Pero, ¿cómo puedes llegar al código de la DLL que se cargó? Usando este método, no sé cómo.

## Usando x64dbg/x32dbg

* **Carga rundll32** \(64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe\)
* **Cambia la línea de comandos** \( _File --&gt; Change Command Line_ \) y establece la ruta de la DLL y la función que deseas llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\14.ridii\_2.dll",DLLMain
* Cambia _Options --&gt; Settings_ y selecciona "**DLL Entry**".
* Luego, **inicia la ejecución**, el depurador se detendrá en cada dll principal, en algún momento te **detendrás en la entrada de la DLL de tu DLL**. A partir de ahí, solo busca los puntos donde deseas poner un punto de interrupción.

Ten en cuenta que cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![](../../.gitbook/assets/image%20%28181%29.png)

Luego, mirando esto, puedes ver cuándo se detuvo la ejecución en la DLL que deseas depurar.

# ARM & MIPS

{% embed url="https://github.com/nongiach/arm\_now" %}

# Shellcodes

## Depurando un shellcode con blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **asignará** el **shellcode** dentro de un espacio de memoria, te **indicará** la **dirección de memoria** donde se asignó el shellcode y **detendrá** la ejecución.  
Luego, debes **adjuntar un depurador** \(Ida o x64dbg\) al proceso y poner un **punto de interrupción en la dirección de memoria indicada** y **reanudar** la ejecución. De esta manera, estarás depurando el shellcode.

La página de lanzamientos de Github contiene archivos zip que contienen las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)  
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarlo, simplemente **crea un proyecto C/C++ en Visual Studio Code, copia y pega el código y compílalo**.

{% page-ref page="blobrunner.md" %}

## Depurando un shellcode con jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4)es muy similar a blobrunner. **Asignará** el **shellcode** dentro de un espacio de memoria y comenzará un **bucle eterno**. Luego, debes **adjuntar el depurador** al proceso, **iniciar la ejecución, esperar 2-5 segundos y presionar stop** y te encontrarás dentro del **bucle eterno**. Salta a la siguiente instrucción del bucle eterno, ya que será una llamada al shellcode, y finalmente te encontrarás ejecutando el shellcode.

![](../../.gitbook/assets/image%20%28403%29.png)

Puedes descargar una versión compilada de [jmp2it dentro de la página de lanzamientos](https://github.com/adamkramer/jmp2it/releases/).

## Depurando shellcode usando Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Usando Cutter, puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter te permite "Abrir archivo" y "Abrir shellcode". En mi caso, cuando abrí el shellcode como archivo, lo descompiló correctamente, pero cuando lo abrí como shellcode, no lo hizo:

![](../../.gitbook/assets/image%20%28254%29.png)

Para comenzar la emulación en el lugar que desees, establece un bp allí y aparentemente Cutter comenzará automáticamente la emulación desde allí:

![](../../.gitbook/assets/image%20%28402%29.png)

![](../../.gitbook/assets/image%20%28343%29.png)

Puedes ver la pila, por ejemplo, dentro de un volcado hexadecimal:

![](../../.gitbook/assets/image%20%28404%29.png)

## Desofuscando shellcode y obteniendo funciones ejecutadas

Deberías probar [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).  
Te dirá cosas como **qué funciones** está utilizando el shellcode y si el shellcode se está **descodificando** a sí mismo en la memoria.
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que deseas y ejecutar el shellcode.

![](../../.gitbook/assets/image%20%28401%29.png)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio en el shellcode dinámicamente en la memoria (útil para descargar el shellcode decodificado). El **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** es útil para depurar el shellcode usando la terminal scDbg (sin embargo, encuentro que cualquiera de las opciones explicadas anteriormente es mejor para este asunto, ya que podrás usar Ida o x64dbg).

## Desensamblado usando CyberChef

Carga tu archivo de shellcode como entrada y usa la siguiente receta para descompilarlo: [https://gchq.github.io/CyberChef/\#recipe=To\_Hex\('Space',0\)Disassemble\_x86\('32','Full%20x86%20architecture',16,0,true,true\)](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

# [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador cambia todas las instrucciones por `mov` (sí, realmente genial). También utiliza interrupciones para cambiar los flujos de ejecución. Para obtener más información sobre cómo funciona:

* [https://www.youtube.com/watch?v=2VF\_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
* [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas\_2015\_the\_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Si tienes suerte, [demovfuscator](https://github.com/kirschju/demovfuscator) desofuscará el binario. Tiene varias dependencias.
```text
apt-get install libcapstone-dev
apt-get install libz3-dev
```
Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) \(`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`\)

Si estás jugando un **CTF, este truco para encontrar la flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html) 

# Delphi

Para binarios compilados en Delphi puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Deobfuscación binaria\)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
