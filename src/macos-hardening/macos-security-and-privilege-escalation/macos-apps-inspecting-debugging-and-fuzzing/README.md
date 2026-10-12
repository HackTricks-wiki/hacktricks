# macOS Apps - Inspección, depuración y Fuzzing

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

Puedes [**descargar disarm aquí**](https://newosxbook.com/tools/disarm.html).

> [!TIP]
> Ten en cuenta que **`disarm`** también puede funcionar con archivos IM4P comprimidos (como `kernelcache`) y extraer solo las partes necesarias, o incluso analizar la parte necesaria sin extraerla.

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
> **`Codesign`** se puede encontrar en **macOS**, mientras que **`ldid`** se puede encontrar en **iOS**.

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
Estos instaladores tienen scripts de bash `preinstall` y `postinstall` que los autores de malware suelen abusar para **persist** **the** **malware**.

### hdiutil

Esta herramienta **mounts** archivos de imagen de disco de Apple (`.dmg`) para que se puedan inspeccionar antes de ejecutar nada:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Se montará en `/Volumes`

### Binarios empaquetados

- Comprueba si tienen alta entropía.
- Comprueba las cadenas (si casi no hay cadenas comprensibles, está empaquetado).
- El empaquetador UPX para macOS genera una sección llamada `__XHDR`.

## Análisis estático de Objective-C

### Metadatos

> [!CAUTION]
> Ten en cuenta que los programas escritos en Objective-C **conservan** sus declaraciones de clase **cuando se** **compilan** en [binarios Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Estas declaraciones de clase **incluyen** el nombre y el tipo de:

- Las interfaces definidas
- Los métodos de las interfaces
- Las variables de instancia de las interfaces
- Los protocolos definidos

Ten en cuenta que estos nombres podrían ofuscarse para dificultar la ingeniería inversa del binario.

### Llamadas a funciones

Cuando se llama a una función en un binario que usa Objective-C, el código compilado, en lugar de llamar a esa función, llamará a **`objc_msgSend`**, que llamará a la función final:

![Metadatos - Llamadas a funciones: Cuando se llama a una función en un binario que usa Objective-C, el código compilado, en lugar de llamar a esa función, llamará a objc msgSend, que será quien...](<../../../images/image (305).png>)

Los parámetros que espera esta función son:

- El primer parámetro (**self**) es «un puntero que apunta a la **instancia de la clase que debe recibir el mensaje**». Dicho de forma más sencilla, es el objeto sobre el que se invoca el método. Si el método es un método de clase, será una instancia del objeto de clase (en su conjunto); en cambio, para un método de instancia, `self` apuntará a una instancia de la clase creada como objeto.
- El segundo parámetro (**op**) es «el selector del método que gestiona el mensaje». Dicho de forma más sencilla, es simplemente el **nombre del método**.
- Los parámetros restantes son los **valores que requiere el método** (`op`).

Consulta en esta página cómo **obtener fácilmente esta información con `lldb` en ARM64**:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**       | **Registro**                                                     | **(para) objc_msgSend**                                   |
| ------------------- | ---------------------------------------------------------------- | --------------------------------------------------------- |
| **1.er argumento**  | **rdi**                                                          | **self: objeto sobre el que se invoca el método**         |
| **2.º argumento**   | **rsi**                                                          | **op: nombre del método**                                 |
| **3.er argumento**  | **rdx**                                                          | **1.er argumento del método**                             |
| **4.º argumento**   | **rcx**                                                          | **2.º argumento del método**                              |
| **5.º argumento**   | **r8**                                                           | **3.er argumento del método**                             |
| **6.º argumento**   | **r9**                                                           | **4.º argumento del método**                              |
| **7.º argumento en adelante** | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p> | **5.º argumento en adelante del método** |

### Volcar metadatos de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) es una herramienta para volcar las clases de binarios Objective-C. El repositorio de GitHub menciona dylibs, pero también funciona con ejecutables.

```bash
./dynadump dump /path/to/bin
```

En el momento de escribir esto, esta es **actualmente la que mejor funciona**.

#### Herramientas habituales

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) es la herramienta original para generar declaraciones de las clases, categorías y protocolos en código Objective-C.

Es antigua y ya no se mantiene, así que probablemente no funcione correctamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) es una herramienta moderna y multiplataforma para volcar clases de Objective-C. En comparación con las herramientas existentes, iCDump puede ejecutarse independientemente del ecosistema de Apple y ofrece bindings de Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Análisis estático de Swift

Con los binarios de Swift, debido a la compatibilidad con Objective-C, a veces puedes extraer declaraciones con [class-dump](https://github.com/nygard/class-dump/), pero no siempre.

Con las líneas de comandos **`jtool -l`** o **`otool -l`** es posible encontrar varias secciones que empiezan con el prefijo **`__swift5`**:

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

Puedes encontrar más información sobre la [**información almacenada en estas secciones en esta entrada del blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Además, **los binarios de Swift pueden tener símbolos** (por ejemplo, las bibliotecas necesitan almacenar símbolos para que se puedan llamar a sus funciones). Los **símbolos suelen incluir información sobre el nombre y los atributos de la función** de una forma poco legible, por lo que son muy útiles y existen "**demanglers"** que pueden recuperar el nombre original:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Análisis dinámico

> [!WARNING]
> Ten en cuenta que, para hacer debug de binarios, **SIP debe estar desactivado** (`csrutil disable` o `csrutil enable --without debug`), o bien debes copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <binary-path>` o permitir el debug del binario (puedes usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Ten en cuenta que, para **instrumentar binarios del sistema** (como `cloudconfigurationd`) en macOS, **SIP debe estar desactivado** (eliminar la firma no bastará).

### APIs

macOS expone algunas APIs interesantes que proporcionan información sobre los procesos:

- `proc_info`: Es la principal y proporciona mucha información sobre cada proceso. Necesitas ser root para obtener información de otros procesos, pero no necesitas entitlements especiales ni puertos mach.
- `libsysmon.dylib`: Expone información de procesos mediante funciones XPC, pero quienes las invoquen necesitan el entitlement `com.apple.sysmond.client`.

### Stackshot y microstackshots

**Stackshotting** es una técnica que se usa para capturar el estado de los procesos, incluidas las pilas de llamadas de todos los threads en ejecución. Esto resulta especialmente útil para debugging, análisis del rendimiento y para comprender el comportamiento del sistema en un momento determinado. En iOS y macOS, se pueden obtener stackshots con varias herramientas y métodos, como **`sample`** y **`spindump`**.

### Sysdiagnose

Esta herramienta (`/usr/bini/ysdiagnose`) básicamente recopila mucha información del equipo ejecutando decenas de comandos distintos, como `ps`, `zprint`...

Debe ejecutarse como **root** y el daemon `/usr/libexec/sysdiagnosed` tiene entitlements muy interesantes, como `com.apple.system-task-ports` y `get-task-allow`.

Su plist se encuentra en `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` y declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Elimina archivos antiguos de /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Puerto especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfaz en modo usuario mediante la clase Obj-C `Libsysdiagnose`. Se pueden pasar tres argumentos en un dict (`compress`, `display`, `run`)

### Unified Logs

macOS genera registros extensos que resultan útiles para analizar el comportamiento de una aplicación.

Algunos campos de los registros contienen la etiqueta `<private>` para ocultar información que identifica al usuario o al dispositivo. En instrucciones antiguas a veces se describe cómo instalar un certificado para revelar estos campos; las indicaciones de debugging actuales usan, en cambio, un perfil de configuración con el alcance explícito `Enable-Private-Data` o `OSLogPreferences` por aplicación. El comportamiento puede variar según el subsistema y la versión de macOS. La información antigua sobre certificados y perfiles se conserva en las referencias. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper se pueden ver los símbolos (**Labels**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). No son todas las cadenas, sino las definidas en varias partes del archivo Mach-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central se puede ver el **código desensamblado**. También se puede ver en formato **raw**, como **gráfico**, **decompilado** o **binario**, haciendo clic en el icono correspondiente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Al hacer clic derecho en un objeto de código, puedes ver las **referencias hacia y desde ese objeto** o incluso cambiarle el nombre (esto no funciona con el pseudocódigo decompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Además, **en la parte inferior central puedes escribir comandos de Python**.

#### Panel derecho

En el panel derecho puedes ver información interesante, como el **historial de navegación** (para saber cómo llegaste a la situación actual), el **grafo de llamadas**, donde puedes ver todas las **funciones que llaman a esta función** y todas las funciones a las que **esta función llama**, y la información de las **variables locales**.

### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel **muy bajo** y ofrece una forma de **rastrear** **programas** e incluso cambiar su flujo de ejecución. Dtrace utiliza **probes** que están **distribuidos por el kernel**, en ubicaciones como el principio y el final de las llamadas al sistema.

DTrace usa la función **`dtrace_probe_create`** para crear un probe para cada llamada al sistema. Estos probes pueden activarse en los **puntos de entrada y salida de cada llamada al sistema**. La interacción con DTrace se realiza a través de /dev/dtrace, que solo está disponible para el usuario root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para habilitar Dtrace sin desactivar por completo la protección SIP, puedes ejecutar en modo de recuperación: `csrutil enable --without dtrace`
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

El nombre de la probe consta de cuatro partes: el proveedor, el módulo, la función y el nombre (`fbt:mach_kernel:ptrace:entry`). Si no especificas alguna parte del nombre, DTrace la tratará como un comodín.

Para configurar DTrace para que active probes y especificar qué acciones realizar cuando se disparen, necesitaremos usar el lenguaje D.

Puedes encontrar una explicación más detallada y más ejemplos en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecuta `man -k dtrace` para ver una lista de **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`

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

Es una herramienta de tracing del kernel. Los códigos documentados se encuentran en **`/usr/share/misc/trace.codes`**.

Herramientas como `latency`, `sc_usage`, `fs_usage` y `trace` la usan internamente.

Para interactuar con `kdebug`, se usa `sysctl` en el namespace `kern.kdebug`; los MIB que se deben usar se encuentran en `sys/sysctl.h`, y las funciones están implementadas en `bsd/kern/kdebug.c`.

Para interactuar con kdebug mediante un cliente personalizado, estos suelen ser los pasos:

- Eliminar la configuración existente con KERN_KDSETREMOVE
- Configurar el trace con KERN_KDSETBUF y KERN_KDSETUP
- Usar KERN_KDGETBUF para obtener el número de entradas del buffer
- Obtener el propio cliente del trace con KERN_KDPINDEX
- Habilitar el tracing con KERN_KDENABLE
- Leer el buffer llamando a KERN_KDREADTR
- Para asociar cada thread con su proceso, llamar a KERN_KDTHRMAP.

Para obtener esta información, se puede usar la herramienta de Apple **`trace`** o la herramienta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Ten en cuenta que Kdebug solo está disponible para un cliente a la vez.** Por lo tanto, solo se puede ejecutar una herramienta basada en k-debug a la vez.

### ktrace

Las APIs `ktrace_*` provienen de `libktrace.dylib`, que actúa como wrapper de las de `Kdebug`. Así, un cliente puede simplemente llamar a `ktrace_session_create` y `ktrace_events_[single/class]` para configurar callbacks en códigos específicos y luego iniciarlo con `ktrace_start`.

Puedes usarlo incluso con **SIP activado**.

Puedes usar la utilidad `ktrace` como cliente:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

O `tailspin`.

### kperf

Se utiliza para realizar profiling a nivel de kernel y está construido con callouts de `Kdebug`.

Básicamente, se comprueba la variable global `kernel_debug_active` y, si está activada, se llama a `kperf_kdebug_handler` con el código de `Kdebug` y la dirección del frame del kernel que realiza la llamada. Si el código de `Kdebug` coincide con uno de los seleccionados, se ejecutan las «acciones» configuradas como un bitmap (consulta `osfmk/kperf/action.h` para ver las opciones).

Kperf también tiene una tabla MIB de sysctl: (como root) `sysctl kperf`. Estas entradas de código se encuentran en `osfmk/kperf/kperfbsd.c`.

Además, un subconjunto de las funciones de Kperf reside en `kpc`, que proporciona información sobre los contadores de rendimiento de la máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para comprobar las acciones relacionadas con procesos que realiza un proceso (por ejemplo, supervisar qué procesos nuevos crea un proceso).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) es una herramienta que muestra las relaciones entre procesos.\
Debes supervisar tu Mac con un comando como **`sudo eslogger fork exec rename create > cap.json`** (el terminal que lo ejecuta necesita FDA). Luego puedes cargar el json en esta herramienta para ver todas las relaciones:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) supervisa eventos de archivos, como su creación, modificación y eliminación.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con una apariencia que los usuarios de Windows pueden reconocer de _Procmon_, de Microsoft Sysinternals. Esta herramienta permite iniciar y detener la grabación de varios tipos de eventos, filtrarlos por categorías como archivos, procesos, red, etc., y guardar los eventos grabados en formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) forma parte de las herramientas para desarrolladores de Xcode y se utiliza para supervisar el rendimiento de las aplicaciones, identificar memory leaks y hacer seguimiento de la actividad del sistema de archivos.

![Crescendo - Apple Instruments: Apple Instruments forma parte de las herramientas para desarrolladores de Xcode y se utiliza para supervisar el rendimiento de las aplicaciones, identificar memory leaks y hacer seguimiento de la actividad del sistema de archivos](<../../../images/image (1138).png>)

### fs_usage

Permite seguir las acciones realizadas por los procesos:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** que usa un binario, los **archivos** que utiliza y las conexiones de **red**.\
También comprueba los procesos binarios en **VirusTotal** y muestra información sobre el binario.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

En [**esta publicación del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo de cómo **depurar un daemon en ejecución** que usaba **`PT_DENY_ATTACH`** para impedir la depuración incluso si SIP estaba desactivado.<sup>[[6]](#references)</sup>

### lldb

**lldb** es la herramienta **de facto** para la **depuración** de binarios de **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Puedes configurar la sintaxis Intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta de inicio con la siguiente línea:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dentro de lldb, vuelca un proceso con `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>(lldb) Comando</strong></td><td><strong>Descripción</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Inicia la ejecución, que continuará hasta que se alcance un punto de interrupción o finalice el proceso.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia la ejecución y se detiene en el punto de entrada.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Continúa la ejecución del proceso depurado.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Ejecuta la siguiente instrucción. Este comando omite las llamadas a funciones.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Ejecuta la siguiente instrucción. A diferencia del comando <code>nexti</code>, este comando entra en las llamadas a funciones.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Ejecuta las instrucciones restantes de la función (frame) actual, retorna y se detiene.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pausa la ejecución. Si el proceso se ha iniciado (<code>r</code>) o se ha continuado (<code>c</code>), esto hace que se detenga dondequiera que se esté ejecutando.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Cualquier función llamada main</p>
<p><code>b &lt;binname&gt;`main</code> # Función principal del binario</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Función principal del binario indicado</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Cualquier método de NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Interrumpir en todas las funciones de esa biblioteca</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista de puntos de interrupción</p>
<p><code>br e/dis &lt;num&gt;</code> # Activar/desactivar punto de interrupción</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Obtener ayuda para el comando breakpoint</p>
<p><code>help memory write</code> # Obtener ayuda para escribir en memoria</p>
</td></tr>
<tr><td><strong>reg</strong></td><td>
<p><code>reg read</code></p>
<p><code>reg read $rax</code></p>
<p><code>reg read $rax --format &lt;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>&gt;</code></p>
<p><code>reg write $rip 0x100035cc0</code></p>
</td></tr>
<tr><td><strong>x/s &lt;register/memory address&gt;</strong></td><td>Muestra la memoria como una cadena terminada en nulo.</td></tr>
<tr><td><strong>x/i &lt;register/memory address&gt;</strong></td><td>Muestra la memoria como una instrucción de ensamblador.</td></tr>
<tr><td><strong>x/b &lt;register/memory address&gt;</strong></td><td>Muestra la memoria como un byte.</td></tr>
<tr><td><strong>print object (po)</strong></td><td>
<p>Imprime el objeto al que hace referencia el parámetro.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
La mayoría de las API o métodos de Objective-C de Apple devuelven objetos y, por tanto, deben mostrarse con el comando “print object” (<code>po</code>). Si <code>po</code> no genera una salida significativa, usa <code>x/b</code>.
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Escribe AAAA en esa dirección<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Escribe AAAA en la dirección
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Desensambla la función actual</p>
<p><code>dis -n &lt;funcname&gt;</code> # Desensambla una función</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Desensambla una función<br>
<code>dis -c 6</code> # Desensambla seis líneas<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Desensambla desde una dirección hasta la otra<br>
<code>dis -p -c 4</code> # Empieza a desensamblar en la dirección actual</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspecciona un array de tres elementos en el registro <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Imprime un mapa de la memoria del proceso actual.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Obtiene la dirección de cada símbolo de CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Al llamar a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo (“C”). Para imprimir el nombre con lldb:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Análisis anti-dinámico

#### Detección de VM

- El comando **`sysctl hw.model`** normalmente devuelve un identificador de modelo de Mac en hardware físico y puede devolver un valor distinto en una VM.<sup>[[3]](#references)</sup>
- Al jugar con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**, algunos malware intentan detectar si se trata de una VM.<sup>[[4]](#references)</sup>
- Algunos malware también pueden **detectar** si la máquina está basada en **VMware** por la dirección MAC (00:50:56).
- También es posible detectar **si un proceso está siendo depurado** con código sencillo como:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- También puede invocar la llamada al sistema **`ptrace`** con la flag **`PT_DENY_ATTACH`**. Esto **impide** que un depu**r**ador se conecte y rastree el proceso.
  - Puedes comprobar si se está **importando** la función **`sysctl`** o **`ptrace`** (aunque el malware podría importarla dinámicamente).
  - Como se señala en este writeup, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_El mensaje Process # exited with **status = 45 (0x0000002d)** suele ser una señal reveladora de que el destino de depuración está usando **PT_DENY_ATTACH**_”

#### Transferencia del proceso mediante `fork()`

Un proceso puede evadir un depurador que siga conectado al PID original llamando a `fork()` al inicio, finalizando el proceso padre (`fork()` devuelve un PID positivo del hijo) y continuando la lógica protegida solo en el hijo (`fork()` devuelve `0`). Resolver `fork` con `dlsym(RTLD_DEFAULT, "fork")` también elimina el punto de llamada directo a `_fork`, pero esto solo supone un obstáculo para el análisis: la cadena con el nombre del símbolo y el flujo de datos de resolución dinámica siguen siendo visibles en el binario Mach-O.<sup>[[10]](#references)[[11]](#references)</sup>

En arm64, detecta este patrón siguiendo el flujo de datos en lugar de direcciones fijas: los dos primeros argumentos de `dlsym` se pasan en `x0` y `x1`, `RTLD_DEFAULT` puede aparecer como `-2` (por ejemplo, `movn x0, #1`), y un par `adrp`/`add` suele construir la dirección de la cadena `"fork"`. Después de la instrucción `bl` a la función stub de `dlsym`, sigue el puntero devuelto desde `x0` a través de su comprobación de nulo y su almacenamiento hasta un `blr` indirecto posterior. A continuación, sigue el resultado de `fork()` en `w0`: el valor cero selecciona la continuación del hijo, mientras que los valores positivos y `-1` seleccionan la ruta del padre o de error.<sup>[[10]](#references)[[11]](#references)</sup>

Un bypass estático consiste en suprimir la llamada indirecta y forzar que la comprobación del resultado existente tome la ruta del hijo. Por ejemplo, si el compilador generó la secuencia que se muestra abajo, aplica el parche `nop` a `blr` y al almacenamiento del resultado, proporciona un resultado cero sintético y conserva la lógica de comparación y salto. La aplicación continúa entonces bajo el PID original sin crear un proceso hijo; los registros de instrucción y los destinos de salto deben adaptarse a la compilación analizada.<sup>[[10]](#references)[[11]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Volcados de memoria

Los volcados de memoria se crean si:

- El sysctl `kern.coredump` está establecido en 1 (valor predeterminado)
- Si el proceso no era suid/sgid o `kern.sugid_coredump` está establecido en 1 (el valor predeterminado es 0)
- El límite `AS_CORE` permite la operación. Es posible impedir la creación de volcados de código llamando a `ulimit -c 0` y volver a habilitarlos con `ulimit -c unlimited`.

En esos casos, los volcados de memoria se generan según el sysctl `kern.corefile` y suelen guardarse en `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza los procesos que fallan y guarda un informe del fallo en el disco**. Un informe del fallo contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa del fallo.\
Para las aplicaciones y otros procesos **que se ejecutan en el contexto launchd del usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda los informes de fallos en `~/Library/Logs/DiagnosticReports/` del usuario.\
Para los daemons, otros procesos **que se ejecutan en el contexto launchd del sistema** y otros procesos privilegiados, ReportCrash se ejecuta como un LaunchDaemon y guarda los informes de fallos en `/Library/Logs/DiagnosticReports` del sistema.

Si te preocupa que los informes de fallos **se envíen a Apple**, puedes desactivarlos. De lo contrario, los informes de fallos pueden ser útiles para **averiguar por qué se bloqueó un servidor**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Suspensión

Al hacer fuzzing en macOS, evita que el Mac entre en reposo:

- systemsetup -setsleep Never
- pmset, Preferencias del Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión SSH

Si haces fuzzing mediante una conexión SSH, es importante asegurarte de que la sesión no se cierre. Así que modifica el archivo sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Manejadores internos

**Consulta la siguiente página** para descubrir cómo puedes averiguar qué app es responsable de **gestionar el esquema o protocolo especificado:**


{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerar procesos de red

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

Funciona con herramientas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

«**simplemente funciona**» con muchas herramientas GUI de macOS. Algunas aplicaciones tienen requisitos adicionales, como nombres de archivo únicos, una extensión concreta o leer archivos desde su sandbox container (`~/Library/Containers/com.apple.Safari/Data`).

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

### Más información sobre fuzzing en macOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44) <sup>[[2]](#references)</sup>
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## References

- [1] [Respuesta a incidentes de OS X: scripting y análisis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Verano de fuzzing: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [El arte del malware de Mac, volumen I: análisis](https://taomm.org/)
- [4] [No Starch Press - El arte del malware de Mac: guía para analizar software malicioso](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - información almacenada en estas secciones de esta publicación del blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - Depuración de binarios de Apple que usan Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - Cómo evadir técnicas anti-debug: variantes de ptrace de macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - registros estructurados de Xcode y `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - Mostrar datos privados en el registro unificado de macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [tony-go/antidebug-examples - ejemplos de fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [11] [Reverse Society - Técnica anti-debugging que usa dlsym y fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
{{#include ../../../banners/hacktricks-training.md}}
