# macOS Apps - Inspección, debugging y Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Análisis estático

### otool & objdump & nm
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```

```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```

```bash
nm -m ./tccd # List of symbols
```
### Disarm (old jtool2)

Puedes [**descargar disarm desde aquí**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Ten en cuenta que **`disarm`** también puede trabajar con archivos IM4P comprimidos (como `kernelcache`) y extraer solo las partes necesarias o incluso analizar la parte requerida sin extraerla.
```bash
export JCOLOR=1
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled

disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache
JDEBUG=1 disarm -e filesets kernelcache.release.d23 # Extract filesets from kernelcache with debug info
disarm -r "code signature" /bin/ps # Check code signature of a binary
disarm -e "code signature" /bin/ps # Extract code signature of a binary
```
### Codesign / ldid

> [!TIP]
> **`Codesign`** se puede encontrar en **macOS**, mientras que **`ldid`** se puede encontrar en **iOS**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo

# Get signature info
ldid -h <binary>

# Get entitlements
ldid -e <binary>

# Change entilements
## /tmp/entl.xml is a XML file with the new entitlements to add
ldid -S/tmp/entl.xml <binary>
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) es una herramienta útil para inspeccionar archivos **.pkg** (instaladores) y ver qué contienen antes de instalarlos.\
Estos instaladores tienen scripts bash `preinstall` y `postinstall` que los autores de malware suelen abusar para **persistir** **el** **malware**.

### hdiutil

Esta herramienta permite **montar** archivos de imagen de disco de Apple (**.dmg**) para inspeccionarlos antes de ejecutar cualquier cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Se montará en `/Volumes`

### Binarios empaquetados

- Comprobar si tienen una entropía alta
- Comprobar las strings (si casi no hay strings comprensibles, está empaquetado)
- El packer UPX para MacOS genera una sección llamada "\_\_XHDR"

## Análisis estático de Objective-C

### Metadatos

> [!CAUTION]
> Ten en cuenta que los programas escritos en Objective-C **conservan** sus declaraciones de clase **cuando** se **compilan** en [binarios Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Dichas declaraciones de clase **incluyen** el nombre y el tipo de:

- Las interfaces definidas
- Los métodos de las interfaces
- Las variables de instancia de las interfaces
- Los protocolos definidos

Ten en cuenta que estos nombres podrían ofuscarse para dificultar el reversing del binario.

### Llamadas a funciones

Cuando se llama a una función en un binario que utiliza Objective-C, el código compilado, en lugar de llamar a esa función, llamará a **`objc_msgSend`**, que se encargará de llamar a la función final:

![Metadatos - Llamadas a funciones: Cuando se llama a una función en un binario que utiliza Objective-C, el código compilado, en lugar de llamar a esa función, llamará a objc msgSend. Que se encargará de...](<../../../images/image (305).png>)

Los parámetros que espera esta función son:

- El primer parámetro (**self**) es "un puntero que apunta a la **instancia de la clase que debe recibir el mensaje**". Dicho de forma más sencilla, es el objeto sobre el que se invoca el método. Si el método es un método de clase, será una instancia del objeto de clase (en su conjunto), mientras que, para un método de instancia, self apuntará a una instancia de la clase instanciada como objeto.
- El segundo parámetro, (**op**), es "el selector del método que gestiona el mensaje". De nuevo, dicho de forma más sencilla, es simplemente el **nombre del método**.
- Los parámetros restantes son cualquier **valor requerido por el método** (op).

Consulta cómo **obtener fácilmente esta información con `lldb` en ARM64** en esta página:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**       | **Registro**                                                    | **(para) objc_msgSend**                              |
| ------------------- | --------------------------------------------------------------- | ---------------------------------------------------- |
| **1er argumento**   | **rdi**                                                         | **self: objeto sobre el que se invoca el método**   |
| **2º argumento**    | **rsi**                                                         | **op: nombre del método**                            |
| **3er argumento**   | **rdx**                                                         | **1er argumento del método**                         |
| **4º argumento**    | **rcx**                                                         | **2º argumento del método**                         |
| **5º argumento**    | **r8**                                                          | **3er argumento del método**                         |
| **6º argumento**    | **r9**                                                          | **4º argumento del método**                         |
| **7º+ argumento**   | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p>   | **5º+ argumento del método**                        |

### Volcar metadatos de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) es una herramienta para class-dump de binarios de Objective-C. GitHub especifica dylibs, pero también funciona con ejecutables.
```bash
./dynadump dump /path/to/bin
```
En el momento de redactar esto, **esta es actualmente la que mejor funciona**.

#### Herramientas habituales
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) es la herramienta original para generar declaraciones de las clases, categorías y protocolos en código Objective-C con formato.

Es antigua y no recibe mantenimiento, por lo que probablemente no funcionará correctamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) es una herramienta moderna y multiplataforma para realizar un class dump de Objective-C. En comparación con las herramientas existentes, iCDump puede ejecutarse independientemente del ecosistema de Apple y ofrece bindings de Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Análisis estático de Swift

Con binarios de Swift, debido a la compatibilidad con Objective-C, a veces puedes extraer declaraciones usando [class-dump](https://github.com/nygard/class-dump/), pero no siempre.

Con las líneas de comandos **`jtool -l`** o **`otool -l`**, es posible encontrar varias secciones que comienzan con el prefijo **`__swift5`**:
```bash
jtool2 -l /Applications/Stocks.app/Contents/MacOS/Stocks
LC 00: LC_SEGMENT_64              Mem: 0x000000000-0x100000000    __PAGEZERO
LC 01: LC_SEGMENT_64              Mem: 0x100000000-0x100028000    __TEXT
[...]
Mem: 0x100026630-0x100026d54        __TEXT.__swift5_typeref
Mem: 0x100026d60-0x100027061        __TEXT.__swift5_reflstr
Mem: 0x100027064-0x1000274cc        __TEXT.__swift5_fieldmd
Mem: 0x1000274cc-0x100027608        __TEXT.__swift5_capture
[...]
```
Puedes encontrar más información sobre la [**información almacenada en estas secciones en esta publicación del blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Además, los **binarios de Swift podrían contener símbolos** (por ejemplo, las bibliotecas necesitan almacenar símbolos para que sus funciones puedan ser llamadas). Los **símbolos normalmente contienen información sobre el nombre de la función** y sus atributos de una forma poco legible, por lo que son muy útiles, y existen "**demanglers"** que pueden obtener el nombre original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Análisis dinámico

> [!WARNING]
> Ten en cuenta que, para depurar binarios, **SIP debe estar deshabilitado** (`csrutil disable` o `csrutil enable --without debug`), o debes copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <binary-path>`, o permitir la depuración del binario (puedes usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Ten en cuenta que, para **instrumentar binarios del sistema** (como `cloudconfigurationd`) en macOS, **SIP debe estar deshabilitado** (eliminar únicamente la firma no funcionará).

### APIs

macOS expone algunas APIs interesantes que proporcionan información sobre los procesos:

- `proc_info`: Es la principal y proporciona mucha información sobre cada proceso. Necesitas ser root para obtener información de otros procesos, pero no necesitas entitlements especiales ni puertos mach.
- `libsysmon.dylib`: Permite obtener información sobre procesos mediante funciones expuestas a través de XPC; sin embargo, es necesario tener el entitlement `com.apple.sysmond.client`.

### Stackshot y microstackshots

**Stackshotting** es una técnica utilizada para capturar el estado de los procesos, incluidas las call stacks de todos los threads en ejecución. Esto resulta especialmente útil para la depuración, el análisis del rendimiento y la comprensión del comportamiento del sistema en un momento específico. En iOS y macOS, el stackshotting se puede realizar utilizando varias herramientas y métodos, como las herramientas **`sample`** y **`spindump`**.

### Sysdiagnose

Esta herramienta (`/usr/bini/ysdiagnose`) básicamente recopila mucha información de tu ordenador ejecutando decenas de comandos diferentes, como `ps`, `zprint`...

Debe ejecutarse como **root**, y el daemon `/usr/libexec/sysdiagnosed` tiene entitlements muy interesantes, como `com.apple.system-task-ports` y `get-task-allow`.

Su plist se encuentra en `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Elimina archivos antiguos de /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Puerto especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfaz en user mode mediante la clase Obj-C `Libsysdiagnose`. Se pueden pasar tres argumentos en un dict (`compress`, `display`, `run`)

### Unified Logs

MacOS genera muchos logs que pueden ser muy útiles al ejecutar una aplicación para comprender **qué está haciendo**.

Además, hay algunos logs que contienen la etiqueta `<private>` para **ocultar** cierta información **identificable** del **usuario** o del **ordenador**. Sin embargo, es posible **instalar un certificado para revelar esta información**. Sigue las explicaciones de [**aquí**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Labels**) del binario, la lista de procedimientos y funciones (**Proc**) y las strings (**Str**). Estas no son todas las strings, sino las definidas en varias partes del archivo Mac-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central puedes ver el **código desensamblado**. También puedes verlo como un desensamblado **raw**, como **gráfico**, como **descompilado** y como **binario**, haciendo clic en el icono correspondiente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Al hacer clic derecho en un objeto de código, puedes ver las **referencias hacia/desde ese objeto** o incluso cambiar su nombre (esto no funciona en el pseudocódigo descompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Además, en la **parte inferior del panel central puedes escribir comandos de Python**.

#### Panel derecho

En el panel derecho puedes ver información interesante, como el **historial de navegación** (para saber cómo llegaste a la situación actual), el **grafo de llamadas**, donde puedes ver todas las **funciones que llaman a esta función** y todas las funciones a las que **llama esta función**, así como información sobre las **variables locales**.

### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel **muy bajo** y proporciona una forma de **trazar** **programas** e incluso cambiar su flujo de ejecución. Dtrace utiliza **probes** que están **colocados por todo el kernel**, en ubicaciones como el principio y el final de las llamadas al sistema.

DTrace utiliza la función **`dtrace_probe_create`** para crear un probe para cada llamada al sistema. Estos probes pueden activarse en el **punto de entrada y de salida de cada llamada al sistema**. La interacción con DTrace se realiza mediante /dev/dtrace, que solo está disponible para el usuario root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para habilitar Dtrace sin deshabilitar completamente la protección SIP, puedes ejecutarlo en recovery mode: `csrutil enable --without dtrace`
>
> También puedes usar **`dtrace`** o **`dtruss`** con binarios que **hayas compilado**.

Los probes disponibles de dtrace se pueden obtener con:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
El nombre del probe consta de cuatro partes: el provider, el module, la function y el name (`fbt:mach_kernel:ptrace:entry`). Si no especificas alguna parte del nombre, Dtrace aplicará esa parte como un wildcard.

Para configurar DTrace para activar probes y especificar qué acciones realizar cuando se activen, necesitaremos usar el lenguaje D.

Puedes encontrar una explicación más detallada y más ejemplos en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecuta `man -k dtrace` para listar los **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`

- En línea
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- script
```bash
syscall:::entry
/pid == $1/
{
}

#Log every syscall of a PID
sudo dtrace -s script.d 1234
```

```bash
syscall::open:entry
{
printf("%s(%s)", probefunc, copyinstr(arg0));
}
syscall::close:entry
{
printf("%s(%d)\n", probefunc, arg0);
}

#Log files opened and closed by a process
sudo dtrace -s b.d -c "cat /etc/hosts"
```

```bash
syscall:::entry
{
;
}
syscall:::return
{
printf("=%d\n", arg1);
}

#Log sys calls with values
sudo dtrace -s syscalls_info.d -c "cat /etc/hosts"
```
### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### kdebug

Es una facility de tracing del kernel. Los códigos documentados se encuentran en **`/usr/share/misc/trace.codes`**.

Herramientas como `latency`, `sc_usage`, `fs_usage` y `trace` lo utilizan internamente.

Para interactuar con `kdebug` se utiliza `sysctl` sobre el namespace `kern.kdebug`, y los MIBs que se deben utilizar se encuentran en `sys/sysctl.h`, con las funciones implementadas en `bsd/kern/kdebug.c`.

Para interactuar con kdebug mediante un cliente personalizado, estos suelen ser los pasos:

- Eliminar la configuración existente con KERN_KDSETREMOVE
- Configurar el trace con KERN_KDSETBUF y KERN_KDSETUP
- Usar KERN_KDGETBUF para obtener el número de entradas del buffer
- Excluir al propio cliente del trace con KERN_KDPINDEX
- Activar el tracing con KERN_KDENABLE
- Leer el buffer llamando a KERN_KDREADTR
- Para asociar cada thread con su proceso, llamar a KERN_KDTHRMAP.

Para obtener esta información, es posible utilizar la herramienta de Apple **`trace`** o la herramienta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Ten en cuenta que Kdebug solo está disponible para 1 cliente a la vez.** Por lo tanto, solo se puede ejecutar una herramienta basada en k-debug al mismo tiempo.

### ktrace

Las APIs `ktrace_*` provienen de `libktrace.dylib`, que actúa como wrapper de las de `Kdebug`. De este modo, un cliente puede simplemente llamar a `ktrace_session_create` y `ktrace_events_[single/class]` para configurar callbacks sobre códigos específicos y, a continuación, iniciarlo con `ktrace_start`.

Puedes utilizar este incluso con **SIP activado**

Puedes utilizar como clientes la utilidad `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
O `tailspin`.

### kperf

Se utiliza para realizar profiling a nivel del kernel y está construido usando callouts de `Kdebug`.

Básicamente, se comprueba la variable global `kernel_debug_active` y, si está establecida, llama a `kperf_kdebug_handler` con el código de `Kdebug` y la dirección del kernel frame que realiza la llamada. Si el código de `Kdebug` coincide con uno de los seleccionados, obtiene las "actions" configuradas como un bitmap (consulta `osfmk/kperf/action.h` para ver las opciones).

Kperf también tiene una tabla MIB de sysctl: (como root) `sysctl kperf`. Este código se encuentra en `osfmk/kperf/kperfbsd.c`.

Además, un subconjunto de la funcionalidad de Kperf reside en `kpc`, que proporciona información sobre los performance counters de la máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para comprobar las acciones relacionadas con procesos que realiza un proceso (por ejemplo, monitorizar qué procesos nuevos crea un proceso).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) es una herramienta que muestra las relaciones entre procesos.\
Debes monitorizar tu Mac con un comando como **`sudo eslogger fork exec rename create > cap.json`** (el terminal que lo ejecute requiere FDA). Después puedes cargar el json en esta herramienta para visualizar todas las relaciones:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorizar eventos de archivos (como su creación, modificación y eliminación), proporcionando información detallada sobre dichos eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con el aspecto y la apariencia que los usuarios de Windows pueden conocer de _Procmon_, de Microsoft Sysinternals. Esta herramienta permite iniciar y detener la grabación de varios tipos de eventos, filtrar estos eventos por categorías como archivo, proceso, red, etc., y ofrece la funcionalidad de guardar los eventos registrados en formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) forma parte de las Developer tools de Xcode y se utiliza para monitorizar el rendimiento de las aplicaciones, identificar memory leaks y realizar un seguimiento de la actividad del filesystem.

![Crescendo - Apple Instruments: Apple Instruments forma parte de las Developer tools de Xcode y se utiliza para monitorizar el rendimiento de las aplicaciones, identificar memory leaks y realizar un seguimiento de la actividad del filesystem](<../../../images/image (1138).png>)

### fs_usage

Permite seguir las acciones realizadas por los procesos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** utilizadas por un binario, los **archivos** que utiliza y las conexiones de **red**.\
También comprueba los procesos binarios con **virustotal** y muestra información sobre el binario.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

En [**esta entrada de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo de cómo hacer **debugging de un daemon en ejecución** que utilizaba **`PT_DENY_ATTACH`** para impedir el debugging incluso con SIP deshabilitado.<sup>[[6]](#references)</sup>

### lldb

**lldb** es la herramienta **de facto** para el **debugging** de binarios de **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puedes configurar el formato intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta personal con la siguiente línea:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Dentro de lldb, vuelca un proceso con `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Command</strong></td><td><strong>Descripción</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Inicia la ejecución, que continuará sin interrupciones hasta que se alcance un breakpoint o el proceso termine.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia la ejecución deteniéndose en el punto de entrada</td></tr><tr><td><strong>continue (c)</strong></td><td>Continúa la ejecución del proceso depurado.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Ejecuta la siguiente instrucción. Este comando omitirá las llamadas a funciones.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Ejecuta la siguiente instrucción. A diferencia del comando nexti, este comando entra en las llamadas a funciones.</td></tr><tr><td><strong>finish (f)</strong></td><td>Ejecuta el resto de las instrucciones de la función actual (“frame”), retorna y se detiene.</td></tr><tr><td><strong>control + c</strong></td><td>Pausa la ejecución. Si el proceso se ha iniciado (r) o continuado (c), esto hará que el proceso se detenga ...dondequiera que se esté ejecutando actualmente.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Any func called main</p><p><code>b <binname>`main</code> #Main func of the bin</p><p><code>b set -n main --shlib <lib_name></code> #Main func of the indicated bin</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Any NSFileManager method</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Break in all functions of that library</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Breakpoint list</p><p><code>br e/dis <num></code> #Enable/Disable breakpoint</p><p>breakpoint delete <num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Get help of breakpoint command</p><p>help memory write #Get help to write into the memory</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format <<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s <reg/memory address></strong></td><td>Muestra la memoria como una cadena terminada en null.</td></tr><tr><td><strong>x/i <reg/memory address></strong></td><td>Muestra la memoria como una instrucción de ensamblador.</td></tr><tr><td><strong>x/b <reg/memory address></strong></td><td>Muestra la memoria como un byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Esto imprimirá el objeto referenciado por el parámetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Ten en cuenta que la mayoría de las APIs o métodos Objective-C de Apple devuelven objetos y, por tanto, deben mostrarse mediante el comando “print object” (po). Si po no produce una salida significativa, utiliza <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Write AAAA in that address<br>memory write -f s $rip+0x11f+7 "AAAA" #Write AAAA in the addr</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Disas current function</p><p>dis -n <funcname> #Disas func</p><p>dis -n <funcname> -b <basename> #Disas func<br>dis -c 6 #Disas 6 lines<br>dis -c 0x100003764 -e 0x100003768 # From one add until the other<br>dis -p -c 4 # Start in current address disassembling</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Check array of 3 components in x1 reg</td></tr><tr><td><strong>image dump sections</strong></td><td>Imprime el mapa de la memoria del proceso actual</td></tr><tr><td><strong>image dump symtab <library></strong></td><td><code>image dump symtab CoreNLP</code> #Get the address of all the symbols from CoreNLP</td></tr></tbody></table>

> [!TIP]
> Al llamar a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en null (“C”). Para imprimir el nombre mediante lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Análisis Anti-Dynamic

#### Detección de VM

- El comando **`sysctl hw.model`** devuelve "Mac" cuando el **host es un MacOS**, pero algo diferente cuando se trata de una VM.<sup>[[3]](#references)</sup>
- Manipulando los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**, algunos malwares intentan detectar si se trata de una VM.<sup>[[4]](#references)</sup>
- Algunos malwares también pueden **detectar** si la máquina es **VMware** basándose en la dirección MAC (00:50:56).
- También es posible averiguar **si un proceso está siendo depurado** mediante un código sencillo como:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- También puede invocar la llamada al sistema **`ptrace`** con el flag **`PT_DENY_ATTACH`**. Esto **impide** que un deb**u**gger se adjunte y realice tracing.
- Puedes comprobar si la función **`sysctl`** o **`ptrace`** está siendo **importada** (aunque el malware podría importarla dinámicamente)
- Como se indica en este writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
“_El mensaje Process # exited with **status = 45 (0x0000002d)** suele ser un indicio claro de que el objetivo de depuración utiliza **PT_DENY_ATTACH**_”

## Volcados de núcleo

Los volcados de núcleo se crean si:

- El sysctl `kern.coredump` está establecido en 1 (por defecto)
- Si el proceso no era suid/sgid o `kern.sugid_coredump` es 1 (por defecto es 0)
- El límite `AS_CORE` permite la operación. Es posible suprimir la creación de volcados de código llamando a `ulimit -c 0` y volver a habilitarlos con `ulimit -c unlimited`.

En esos casos, el volcado de núcleo se genera según el sysctl `kern.corefile` y normalmente se almacena en `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza los procesos que se bloquean y guarda un informe del fallo en el disco**. Un informe del fallo contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un fallo.\
Para las aplicaciones y otros procesos **que se ejecutan en el contexto launchd del usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda los informes de fallos en `~/Library/Logs/DiagnosticReports/` del usuario\
Para daemons, otros procesos **que se ejecutan en el contexto launchd del sistema** y otros procesos privilegiados, ReportCrash se ejecuta como un LaunchDaemon y guarda los informes de fallos en `/Library/Logs/DiagnosticReports` del sistema

Si te preocupa que los informes de fallos **se envíen a Apple**, puedes desactivarlos. De lo contrario, los informes de fallos pueden ser útiles para **averiguar cómo se bloqueó un servidor**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Suspensión

Al realizar fuzzing en un Mac, es importante evitar que el Mac entre en suspensión:

- systemsetup -setsleep Never
- pmset, Preferencias del Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión de SSH

Si estás realizando fuzzing mediante una conexión SSH, es importante asegurarse de que la sesión no se vaya a desconectar. Por lo tanto, modifica el archivo sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manejadores internos

**Consulta la siguiente página** para averiguar cómo encontrar qué app es responsable de **gestionar el esquema o protocolo especificado:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumeración de procesos de red

Esto es interesante para encontrar procesos que gestionan datos de red:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
O usa `netstat` o `lsof`

### Libgmalloc

<figure><img src="../../../images/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para herramientas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

**"simplemente funciona"** con herramientas GUI de macOS. Ten en cuenta que algunas aplicaciones de macOS tienen requisitos específicos, como nombres de archivo únicos, la extensión correcta o la necesidad de leer los archivos desde el sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Algunos ejemplos:
```bash
# iBooks
litefuzz -l -c "/System/Applications/Books.app/Contents/MacOS/Books FUZZ" -i files/epub -o crashes/ibooks -t /Users/test/Library/Containers/com.apple.iBooksX/Data/tmp -x 10 -n 100000 -ez

# -l : Local
# -c : cmdline with FUZZ word (if not stdin is used)
# -i : input directory or file
# -o : Dir to output crashes
# -t : Dir to output runtime fuzzing artifacts
# -x : Tmeout for the run (default is 1)
# -n : Num of fuzzing iterations (default is 1)
# -e : enable second round fuzzing where any crashes found are reused as inputs
# -z : enable malloc debug helpers

# Font Book
litefuzz -l -c "/System/Applications/Font Book.app/Contents/MacOS/Font Book FUZZ" -i input/fonts -o crashes/font-book -x 2 -n 500000 -ez

# smbutil (using pcap capture)
litefuzz -lk -c "smbutil view smb://localhost:4455" -a tcp://localhost:4455 -i input/mac-smb-resp -p -n 100000 -z

# screensharingd (using pcap capture)
litefuzz -s -a tcp://localhost:5900 -i input/screenshared-session --reportcrash screensharingd -p -n 100000
```
### Más información sobre Fuzzing en macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referencias

- [1] [Respuesta a incidentes en OS X: Scripting y análisis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [El arte del malware de Mac, volumen I: análisis](https://taomm.org/vol1/analysis.html)
- [4] [El arte del malware de Mac: guía para analizar software malicioso](https://taomm.org/)
- [5] [knight.sc - información almacenada en esta sección de esta publicación del blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Debugging de binarios de Apple que usan Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Cómo derrotar las técnicas Anti-Debug: variantes de ptrace en macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)

{{#include ../../../banners/hacktricks-training.md}}
