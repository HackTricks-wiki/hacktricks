# Apps de macOS - Inspección, depuración y fuzzing

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

### Disarm (jtool2 antiguo)

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
> **`Codesign`** se encuentra en **macOS**, mientras que **`ldid`** se encuentra en **iOS**

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
Estos instaladores tienen scripts de bash `preinstall` y `postinstall` que los autores de malware suelen aprovechar para **persistir** **el** **malware**.

### hdiutil

Esta herramienta **monta** archivos de imagen de disco de Apple (`.dmg`) para que puedan inspeccionarse antes de ejecutar nada:

```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```

Se montará en `/Volumes`

### Binarios empaquetados

- Comprueba si tienen una entropía alta
- Comprueba las cadenas (si casi no hay cadenas comprensibles, está empaquetado)
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

### Llamada a funciones

Cuando se llama a una función en un binario que usa Objective-C, el código compilado, en lugar de llamar a esa función, llamará a **`objc_msgSend`**, que llamará a la función final:

![Metadatos - Llamada a funciones: Cuando se llama a una función en un binario que usa Objective-C, el código compilado, en lugar de llamar a esa función, llamará a objc msgSend . Que será quien llame a...](<../../../images/image (305).png>)

Los parámetros que espera esta función son:

- El primer parámetro (**self**) es «un puntero que apunta a la **instancia de la clase que debe recibir el mensaje**». Dicho de forma más sencilla, es el objeto sobre el que se invoca el método. Si el método es un método de clase, será una instancia del objeto de clase (en su conjunto), mientras que, para un método de instancia, self apuntará a una instancia de la clase.
- El segundo parámetro, (**op**), es «el selector del método que gestiona el mensaje». Dicho de forma más sencilla, es simplemente el **nombre del método**.
- Los parámetros restantes son los **valores que requiere el método** (op).

Consulta cómo **obtener esta información fácilmente con `lldb` en ARM64** en esta página:


{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**      | **Registro**                                                    | **(para) objc_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1.er argumento**  | **rdi**                                                         | **self: objeto sobre el que se invoca el método** |
| **2.º argumento**  | **rsi**                                                         | **op: nombre del método**                             |
| **3.er argumento**  | **rdx**                                                         | **1.er argumento del método**                         |
| **4.º argumento**  | **rcx**                                                         | **2.º argumento del método**                         |
| **5.º argumento**  | **r8**                                                          | **3.er argumento del método**                         |
| **6.º argumento**  | **r9**                                                          | **4.º argumento del método**                         |
| **7.º argumento o posterior** | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p> | **5.º argumento o posterior del método**                        |

### Volcar metadatos de Objective-C

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) es una herramienta para volcar las clases de binarios Objective-C. GitHub indica que funciona con dylibs, pero también sirve para ejecutables.

```bash
./dynadump dump /path/to/bin
```

En el momento de escribir esto, esta es actualmente la que mejor funciona.

#### Herramientas habituales

```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```

#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) es la herramienta original para generar declaraciones de las clases, categorías y protocolos del código Objective-C formateado.

Es antigua y ya no se mantiene, así que probablemente no funcione correctamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) es una herramienta moderna y multiplataforma para volcar clases de Objective-C. En comparación con las herramientas existentes, iCDump puede ejecutarse independientemente del ecosistema de Apple y ofrece bindings de Python.

```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```

## Análisis estático de Swift

Con los binarios de Swift, como existe compatibilidad con Objective-C, a veces se pueden extraer declaraciones usando [class-dump](https://github.com/nygard/class-dump/), pero no siempre.

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

Puedes encontrar más información sobre la [**información almacenada en estas secciones en esta entrada del blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).<sup>[[5]](#references)</sup>

Además, **los binarios de Swift pueden tener símbolos** (por ejemplo, las bibliotecas necesitan almacenar símbolos para que se puedan llamar a sus funciones). Los **símbolos suelen contener información sobre el nombre de la función** y sus atributos de una forma poco legible, por lo que son muy útiles y existen «**demanglers**» que pueden recuperar el nombre original:

```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```

## Análisis dinámico

> [!WARNING]
> **No desactives SIP como paso predeterminado de depuración.** Las builds de desarrollo con `com.apple.security.get-task-allow` pueden depurarse con SIP habilitado. Comprueba el objetivo con `codesign -d --entitlements :- /path/to/binary` antes de intentar usar LLDB. Un entitlement de debugger por sí solo no concede acceso a objetivos protegidos por SIP.<sup>[[15]](#references)</sup>
>
> Una app distribuida con hardened runtime normalmente omite `get-task-allow` y bloquea la conexión del debugger. Si es posible, usa una debug build proporcionada por el desarrollador; volver a firmar una copia desechable puede cambiar el comportamiento que se está analizando. Si un objetivo protegido requiere desactivar SIP, usa una máquina de pruebas o VM dedicada, en lugar de una máquina de la que dependas.<sup>[[16]](#references)</sup>
>
> Las instrucciones anteriores para un objetivo protegido en un entorno de pruebas aislado enumeraban estas alternativas:
>
> Ten en cuenta que, para depurar binarios, hay que desactivar SIP (`csrutil disable` o `csrutil enable --without debug`), o copiar los binarios a una carpeta temporal y eliminar la firma con `codesign --remove-signature <binary-path>`, o permitir la depuración del binario (puedes usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
>
> Este no es un requisito general de SIP: es preferible usar una debug build, y ten en cuenta que copiar o cambiar una firma puede alterar el comportamiento que se está analizando.

> [!WARNING]
> Ten en cuenta que, para **instrumentar binarios del sistema** (como `cloudconfigurationd`) en macOS, **hay que desactivar SIP** (eliminar la firma no bastará).

### APIs

macOS expone algunas APIs interesantes que proporcionan información sobre los procesos:

- `proc_info`: Es la principal y proporciona mucha información sobre cada proceso. Necesitas ser root para obtener información sobre otros procesos, pero no necesitas entitlements especiales ni puertos mach.
- `libsysmon.dylib`: Expone información de procesos mediante funciones XPC, pero quienes las llaman necesitan el entitlement `com.apple.sysmond.client`.

### Stackshot y microstackshots

**Stackshotting** es una técnica que se usa para capturar el estado de los procesos, incluidas las pilas de llamadas de todos los threads en ejecución. Es especialmente útil para depurar, analizar el rendimiento y comprender el comportamiento del sistema en un momento concreto. En iOS y macOS, se pueden obtener stackshots con varias herramientas y métodos, como **`sample`** y **`spindump`**.

### Sysdiagnose

Esta herramienta (`/usr/bini/ysdiagnose`) recopila mucha información del equipo ejecutando decenas de comandos diferentes, como `ps`, `zprint`...

Debe ejecutarse como **root**, y el daemon `/usr/libexec/sysdiagnosed` tiene entitlements muy interesantes, como `com.apple.system-task-ports` y `get-task-allow`.

Su plist se encuentra en `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist`, que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Elimina archivos antiguos en /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Puerto especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfaz de user mode a través de la clase Obj-C `Libsysdiagnose`. Se pueden pasar tres argumentos en un dict (`compress`, `display`, `run`)

### Unified Logs

macOS genera logs extensos que son útiles para analizar el comportamiento de una aplicación.

Algunos campos de los logs contienen la etiqueta `<private>` para ocultar información que permite identificar al usuario o al dispositivo. Las instrucciones antiguas a veces describen la instalación de un certificado para mostrar estos campos; las indicaciones actuales para depuración usan un configuration profile explícitamente delimitado con `Enable-Private-Data` o `OSLogPreferences` por aplicación, y el comportamiento puede variar según el subsistema y la versión de macOS. En las referencias se conserva la explicación antigua sobre certificados y perfiles. <sup>[[8]](#references)</sup><sup>[[9]](#references)</sup>

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Labels**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). No son todas las cadenas, sino las definidas en varias partes del archivo Mach-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central puedes ver el **código desensamblado**. Puedes verlo como desensamblado **en bruto**, como **grafo**, como **decompilado** y como **binario**, haciendo clic en el icono correspondiente:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Al hacer clic derecho en un objeto de código, puedes ver las **referencias hacia/desde ese objeto** o incluso cambiarle el nombre (esto no funciona en el pseudocódigo decompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Además, **en la parte inferior del panel central puedes escribir comandos Python**.

#### Panel derecho

En el panel derecho puedes ver información interesante, como el **historial de navegación** (para saber cómo llegaste a la situación actual), el **grafo de llamadas**, donde puedes ver todas las **funciones que llaman a esta función** y todas las funciones a las que **esta función llama**, y la información de las **variables locales**.

### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel **muy bajo** y ofrece una forma de **trazar** **programas** e incluso cambiar su flujo de ejecución. Dtrace usa **probes**, que están **distribuidos por el kernel** en ubicaciones como el inicio y el final de las llamadas al sistema.

DTrace usa la función **`dtrace_probe_create`** para crear un probe por cada llamada al sistema. Estos probes pueden activarse en los **puntos de entrada y salida de cada llamada al sistema**. La interacción con DTrace se realiza a través de /dev/dtrace, que solo está disponible para el usuario root.<sup>[[1]](#references)</sup>

> [!TIP]
> Para habilitar Dtrace sin desactivar por completo la protección de SIP, puedes ejecutar en el modo de recuperación: `csrutil enable --without dtrace`
>
> También puedes usar **`dtrace`** o **`dtruss`** con los binarios que **hayas compilado**.

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

El nombre de la sonda consta de cuatro partes: el proveedor, el módulo, la función y el nombre (`fbt:mach_kernel:ptrace:entry`). Si no especificas alguna parte del nombre, DTrace la tratará como un comodín.

Para configurar DTrace y activar las sondas, así como especificar qué acciones realizar cuando se activen, necesitaremos usar el lenguaje D.

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

Es una función de tracing del kernel. Los códigos documentados se encuentran en **`/usr/share/misc/trace.codes`**.

Herramientas como `latency`, `sc_usage`, `fs_usage` y `trace` la usan internamente.

Para interactuar con `kdebug`, se usa `sysctl` en el namespace `kern.kdebug`; los MIB que se deben usar se encuentran en `sys/sysctl.h`, y sus funciones están implementadas en `bsd/kern/kdebug.c`.

Para interactuar con kdebug mediante un cliente personalizado, estos suelen ser los pasos:

- Eliminar la configuración existente con KERN_KDSETREMOVE
- Configurar el trace con KERN_KDSETBUF y KERN_KDSETUP
- Usar KERN_KDGETBUF para obtener el número de entradas del buffer
- Obtener el propio cliente del trace con KERN_KDPINDEX
- Habilitar el tracing con KERN_KDENABLE
- Leer el buffer llamando a KERN_KDREADTR
- Para asociar cada thread con su proceso, llamar a KERN_KDTHRMAP.

Para obtener esta información, se puede usar la herramienta de Apple **`trace`** o la herramienta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.

**Ten en cuenta que Kdebug solo está disponible para un cliente a la vez.** Por lo tanto, solo se puede ejecutar una herramienta basada en k-debug a la vez.

### ktrace

Las APIs `ktrace_*` provienen de `libktrace.dylib`, que envuelve las de `Kdebug`. Así, un cliente solo tiene que llamar a `ktrace_session_create` y `ktrace_events_[single/class]` para configurar callbacks en códigos específicos y, luego, iniciarlo con `ktrace_start`.

También puedes usar esta opción con **SIP activado**

Puedes usar la utilidad `ktrace` como cliente:

```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```

O `tailspin`.

### kperf

Se usa para realizar análisis de rendimiento a nivel del kernel y está construido mediante llamadas de `Kdebug`.

Básicamente, se comprueba la variable global `kernel_debug_active` y, si está activada, se llama a `kperf_kdebug_handler` con el código de `Kdebug` y la dirección del frame del kernel que realiza la llamada. Si el código de `Kdebug` coincide con uno de los seleccionados, se ejecutan las «acciones» configuradas como un mapa de bits (consulta `osfmk/kperf/action.h` para ver las opciones).

Kperf también tiene una tabla MIB de sysctl: (como root) `sysctl kperf`. Este código se encuentra en `osfmk/kperf/kperfbsd.c`.

Además, un subconjunto de las funciones de Kperf reside en `kpc`, que proporciona información sobre los contadores de rendimiento de la máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para comprobar las acciones relacionadas con procesos que realiza un proceso (por ejemplo, supervisar qué procesos nuevos crea).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) es una herramienta que muestra las relaciones entre procesos.\
Debes supervisar tu Mac con un comando como **`sudo eslogger fork exec rename create > cap.json`** (el terminal desde el que se ejecuta necesita FDA). Después puedes cargar el archivo JSON en esta herramienta para ver todas las relaciones:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) supervisa eventos de archivos, como la creación, modificación y eliminación.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con una apariencia y un funcionamiento que quizá les resulten familiares a los usuarios de Windows por _Procmon_, de Microsoft Sysinternals. Esta herramienta permite iniciar y detener la grabación de distintos tipos de eventos, filtrarlos por categorías como archivos, procesos, red, etc., y guardar los eventos registrados en formato JSON.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) forma parte de las herramientas para desarrolladores de Xcode y se usa para supervisar el rendimiento de las aplicaciones, identificar memory leaks y rastrear la actividad del sistema de archivos.

![Crescendo - Apple Instruments: Apple Instruments forma parte de las herramientas para desarrolladores de Xcode y se usa para supervisar el rendimiento de las aplicaciones, identificar memory leaks y rastrear la actividad del sistema de archivos](<../../../images/image (1138).png>)

### fs_usage

Permite seguir las acciones realizadas por los procesos:

```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```

### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** que usa un binario, los **archivos** que utiliza y las conexiones de **red**.\
También comprueba los procesos del binario con **virustotal** y muestra información sobre él.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

En [**esta publicación del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo de cómo **depurar un daemon en ejecución** que usaba **`PT_DENY_ATTACH`** para impedir la depuración incluso si SIP estaba deshabilitado.<sup>[[6]](#references)</sup>

`PT_DENY_ATTACH` es una solicitud de `ptrace(2)` específica de Darwin con el valor **31** (`0x1f`); los demás argumentos se ignoran. Un proceso puede invocarla directamente, sin hacer un fork, para impedir que su proceso padre lo trace posteriormente.<sup>[[10]](#references)[[12]](#references)</sup>

```c
#include <sys/ptrace.h>

if (ptrace(PT_DENY_ATTACH, 0, 0, 0) == -1) {
    /* A debugger may already be present. */
}
```

### Estado de XNU y orden de las llamadas

El resultado depende de qué solicitud `ptrace` llega primero a XNU:<sup>[[11]](#references)[[12]](#references)</sup>

- **LLDB se conecta primero:** `debugserver` usa `PT_ATTACHEXC`; XNU lo convierte en `PT_ATTACH`, realiza la autorización `KAUTH_PROCESS_CANTRACE` y establece `P_LTRACED` en el objetivo. Una solicitud posterior de `PT_DENY_ATTACH` detecta esa marca y termina el objetivo con `W_EXITCODE(ENOTSUP, 0)`, que LLDB suele mostrar como estado **45** (`0x2d`).
- **El objetivo deniega primero:** XNU establece `P_LNOATTACH`. Una conexión posterior se rechaza durante la autorización de seguimiento de procesos; la ruta de error de conexión detecta `P_LNOATTACH` y envía `SIGSEGV` al proceso que intenta conectarse, lo que puede aparecer en LLDB como una conexión perdida con `debugserver`.

Para distinguir estas rutas, activa el registro de `debugserver` antes de iniciar o conectarte al proceso e inspecciona sus solicitudes `ptrace`:<sup>[[12]](#references)</sup>

```bash
export LLDB_DEBUGSERVER_LOG_FILE=./debugserver.log
lldb ./target                 # or: lldb -p <pid>
grep ptrace ./debugserver.log
```

### Identificación estática y bypass en ARM64

En un Mach-O ARM64 no ofuscado, localiza el stub importado `_ptrace` e inspecciona los puntos de llamada. El primer argumento entero se pasa en `w0`, así que esta secuencia revela directamente la solicitud anti-debug. La ausencia de la importación no es concluyente, porque el código puede resolver `ptrace` dinámicamente. Un `_sysctl` importado también puede indicar comprobaciones anti-debug, aunque también puede resolverse dinámicamente.<sup>[[7]](#references)[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x1f            ; PT_DENY_ATTACH
bl      imp___stubs__ptrace
```

En el ejemplo mostrado, cambiar el valor inmediato de `0x1f` a `0x0` modifica la solicitud a `PT_TRACE_ME` y permite que el programa continúe bajo LLDB. Se trata de un **bypass específico de esta muestra**, no de un no-op general: inspecciona las comprobaciones del valor de retorno y el flujo de control del llamador antes de decidir si cambiar la solicitud, omitir la llamada o forzar un retorno exitoso.<sup>[[10]](#references)[[12]](#references)</sup>

```armasm
movz    w0, #0x0             ; PT_TRACE_ME
bl      imp___stubs__ptrace
```

### lldb

**lldb** es la **herramienta de facto** para la **depuración** de binarios de **macOS**.

```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```

Puedes configurar el formato Intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta personal con la siguiente línea:

```bash
settings set target.x86-disassembly-flavor intel
```

> [!WARNING]
> Dentro de lldb, vuelca un proceso con `process save-core`

<table data-header-hidden>
<thead><tr><th width="225"></th><th></th></tr></thead>
<tbody>
<tr><td><strong>Comando (lldb)</strong></td><td><strong>Descripción</strong></td></tr>
<tr><td><strong>run (r)</strong></td><td>Inicia la ejecución, que continuará hasta que se alcance un breakpoint o finalice el proceso.</td></tr>
<tr><td><strong>process launch --stop-at-entry</strong></td><td>Inicia la ejecución y se detiene en el punto de entrada.</td></tr>
<tr><td><strong>continue (c)</strong></td><td>Continúa la ejecución del proceso depurado.</td></tr>
<tr><td><strong>nexti (n / ni)</strong></td><td>Ejecuta la siguiente instrucción. Este comando pasa por alto las llamadas a funciones.</td></tr>
<tr><td><strong>stepi (s / si)</strong></td><td>Ejecuta la siguiente instrucción. A diferencia del comando <code>nexti</code>, este comando entra en las llamadas a funciones.</td></tr>
<tr><td><strong>finish (f)</strong></td><td>Ejecuta las instrucciones restantes de la función (frame) actual, retorna y se detiene.</td></tr>
<tr><td><strong>control + c</strong></td><td>Pausa la ejecución. Si se ha iniciado (<code>r</code>) o reanudado (<code>c</code>) el proceso, esto hace que se detenga dondequiera que se esté ejecutando.</td></tr>
<tr><td><strong>breakpoint (b)</strong></td><td>
<p><code>b main</code> # Cualquier función llamada main</p>
<p><code>b &lt;binname&gt;`main</code> # Función principal del binario</p>
<p><code>b set -n main --shlib &lt;lib_name&gt;</code> # Función principal del binario indicado</p>
<p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> # Cualquier método de NSFileManager</p>
<p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p>
<p><code>break set -r . -s libobjc.A.dylib</code> # Detenerse en todas las funciones de esa biblioteca</p>
<p><code>b -a 0x0000000100004bd9</code></p>
<p><code>br l</code> # Lista de breakpoints</p>
<p><code>br e/dis &lt;num&gt;</code> # Activar/desactivar breakpoint</p>
<p><code>breakpoint delete &lt;num&gt;</code></p>
</td></tr>
<tr><td><strong>help</strong></td><td>
<p><code>help breakpoint</code> # Obtener ayuda sobre el comando breakpoint</p>
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
<p>Esto imprime el objeto al que hace referencia el parámetro.</p>
<p><code>po $raw</code></p>
<p><code>{</code></p>
<p><code>dnsChanger = {</code></p>
<p><code>"affiliate" = "";</code></p>
<p><code>"blacklist_dns" = ();</code></p>
</p>La mayoría de las APIs o métodos Objective-C de Apple devuelven objetos y, por lo tanto, deben mostrarse con el comando “print object” (<code>po</code>). Si <code>po</code> no genera un resultado significativo, usa <code>x/b</code>.</p>
</td></tr>
<tr><td><strong>memory</strong></td><td>
<code>memory read 0x000....</code><br>
<code>memory read $x0+0xf2a</code><br>
<code>memory write 0x100600000 -s 4 0x41414141</code> # Escribir AAAA en esa dirección<br>
<code>memory write -f s $rip+0x11f+7 "AAAA"</code> # Escribir AAAA en la dirección
</td></tr>
<tr><td><strong>disassembly</strong></td><td>
<p><code>dis</code> # Desensamblar la función actual</p>
<p><code>dis -n &lt;funcname&gt;</code> # Desensamblar una función</p>
<p><code>dis -n &lt;funcname&gt; -b &lt;basename&gt;</code> # Desensamblar una función<br>
<code>dis -c 6</code> # Desensamblar seis líneas<br>
<code>dis -c 0x100003764 -e 0x100003768</code> # Desensamblar desde una dirección hasta otra<br>
<code>dis -p -c 4</code> # Empezar a desensamblar en la dirección actual</p>
</td></tr>
<tr><td><strong>parray</strong></td><td><code>parray 3 (char **)$x1</code> # Inspeccionar un array de tres elementos en el registro <code>x1</code></td></tr>
<tr><td><strong>image dump sections</strong></td><td>Imprime un mapa de la memoria del proceso actual.</td></tr>
<tr><td><strong>image dump symtab &lt;library&gt;</strong></td><td><code>image dump symtab CoreNLP</code> # Obtener la dirección de cada símbolo de CoreNLP</td></tr>
</tbody>
</table>

> [!TIP]
> Al llamar a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo (“C”). Para imprimir el nombre mediante lldb, haz lo siguiente:
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
- Algunos malware intentan detectar si se trata de una VM jugando con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**.<sup>[[4]](#references)</sup>
- Un loader también puede consultar `kern.hv_vmm_present` y `machdep.cpu.brand_string` mediante `sysctl` para comprobar si hay una VM antes de desempaquetar la siguiente etapa. Estas comprobaciones complementan, pero no sustituyen, la comprobación de conexión del debugger descrita a continuación.<sup>[[20]](#references)</sup>
- Algunos malware también pueden **detectar** si la máquina está basada en **VMware** a partir de la dirección MAC (00:50:56).
- También es posible averiguar **si un proceso está siendo depurado** con código sencillo como este:
  - `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //process being debugged }`
- También puede invocar la llamada al sistema `ptrace` con el flag `PT_DENY_ATTACH`. Esto impide que un debugger se conecte y realice tracing. Consulta la [sección PT_DENY_ATTACH](#page-title) para ver su comportamiento en XNU, que depende del orden, los logs de `debugserver` y el flujo de trabajo de parcheo para ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
- También puede invocar la llamada al sistema **`ptrace`** con el flag **`PT_DENY_ATTACH`**. Consulta la [sección PT_DENY_ATTACH](#page-title) para ver su comportamiento en XNU, que depende del orden, los logs de `debugserver` y el flujo de trabajo de parcheo para ARM64.<sup>[[7]](#references)[[12]](#references)</sup>
  - Puedes comprobar si se está **importando** la función **`sysctl`** o **`ptrace`** (aunque el malware podría importarla dinámicamente).
  - Como se señala en este writeup, “[Derrotar técnicas anti-debug: variantes de macOS ptrace](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :<sup>[[7]](#references)</sup>\
    “_El mensaje Process # exited with **status = 45 (0x0000002d)** suele ser una señal clara de que el objetivo del debug está usando **PT_DENY_ATTACH**_”
#### Transferencia del proceso `fork()`

Un proceso puede evadir un debugger que siga conectado al PID original llamando a `fork()` poco después del inicio, terminando el proceso padre (`fork()` devuelve un PID hijo positivo) y continuando la lógica protegida solo en el proceso hijo (`fork()` devuelve `0`). Resolver `fork` con `dlsym(RTLD_DEFAULT, "fork")` también elimina la llamada directa a `_fork`, pero esto solo supone un obstáculo para el análisis: la cadena con el nombre del símbolo y el flujo de datos de la resolución dinámica siguen siendo visibles en el binario Mach-O.<sup>[[13]](#references)[[14]](#references)</sup>

En arm64, detecta este patrón siguiendo el flujo de datos en lugar de direcciones fijas: los dos primeros argumentos de `dlsym` se pasan en `x0` y `x1`, `RTLD_DEFAULT` puede aparecer como `-2` (por ejemplo, `movn x0, #1`), y un par `adrp`/`add` suele construir la dirección de la cadena `"fork"`. Después del `bl` al stub de `dlsym`, sigue el puntero devuelto desde `x0` a través de su comprobación de nulo y almacenamiento hasta un `blr` indirecto posterior. Luego, sigue el resultado de `fork()` en `w0`: el valor cero selecciona la continuación del proceso hijo, mientras que los valores positivos y `-1` seleccionan la ruta del proceso padre o de error.<sup>[[13]](#references)[[14]](#references)</sup>

Una forma de eludirlo estáticamente es suprimir la llamada indirecta y hacer que la comprobación del resultado existente tome la ruta del proceso hijo. Por ejemplo, si el compilador generó la secuencia que se muestra a continuación, parchea el `blr` y el almacenamiento del resultado con `nop`, proporciona un resultado sintético de cero y conserva la lógica de comparación y salto. La aplicación continuará entonces bajo el PID original sin crear un proceso hijo; los registros de instrucciones y los destinos de los saltos deben adaptarse a la compilación analizada.<sup>[[13]](#references)[[14]](#references)</sup>

```armasm
ldr  x8, [sp, #0x10]
nop                              ; patched blr x8
nop                              ; patched str w0, [sp, #0xc]
mov  w8, #0                      ; patched ldr w8, [sp, #0xc]
subs w8, w8, #0
cset w8, eq
tbnz w8, #0, child_continuation
```

## Core Dumps

Los core dumps se crean si:

- El sysctl `kern.coredump` está establecido en 1 (valor predeterminado)
- Si el proceso no era suid/sgid o `kern.sugid_coredump` es 1 (el valor predeterminado es 0)
- El límite `AS_CORE` permite la operación. Es posible impedir la creación de core dumps ejecutando `ulimit -c 0` y volver a habilitarla con `ulimit -c unlimited`.

En esos casos, los core dumps se generan según el sysctl `kern.corefile` y normalmente se guardan en `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza los procesos que fallan y guarda un informe del fallo en el disco**. Un informe del fallo contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un fallo.\
Para las aplicaciones y otros procesos **que se ejecutan en el contexto launchd por usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda los informes del fallo en `~/Library/Logs/DiagnosticReports/` del usuario.\
Para los daemons, otros procesos **que se ejecutan en el contexto launchd del sistema** y otros procesos con privilegios, ReportCrash se ejecuta como un LaunchDaemon y guarda los informes del fallo en `/Library/Logs/DiagnosticReports` del sistema.

Si te preocupa que los informes del fallo **se envíen a Apple**, puedes desactivarlos. De lo contrario, los informes del fallo pueden ser útiles para **averiguar cómo se bloqueó un servidor**.

```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```

### Suspensión

Al hacer fuzzing en macOS, evita que el Mac entre en suspensión:

- systemsetup -setsleep Never
- pmset, Preferencias del Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión SSH

Si haces fuzzing a través de una conexión SSH, es importante asegurarse de que la sesión no se interrumpa. Para ello, modifica el archivo sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0

```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

### Manejadores internos

**Consulta la siguiente página** para descubrir cómo encontrar qué app es responsable de **gestionar el esquema o protocolo especificado:**


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

### Fuzzing con estado de Mach IPC

Los servicios Mach expuestos por daemons privilegiados son objetivos útiles para fuzzing cuando un cliente sin privilegios o en sandbox puede obtener un send right. Empieza por la entrada `MachServices` de launchd del daemon y usa el [flujo de análisis de MIG](../macos-proces-abuse/macos-ipc-inter-process-communication/macos-mig-mach-interface-generator.md) para asociar los IDs de mensaje con sus handlers. Antes de modificar bytes, pon un breakpoint en la rutina del servidor MIG mientras un cliente normal usa el servicio y guarda mensajes de solicitud válidos como entradas iniciales. Conserva los campos de cabecera requeridos, los tamaños de mensaje y la disposición de los descriptores para que las mutaciones lleguen al handler en lugar de fallar inmediatamente durante el dispatch.<sup>[[17]](#references)</sup>

Muchos handlers dependen de llamadas previas. Haz que el harness inicialice el estado del servicio y luego procese cada entrada de fuzzing como una secuencia de **operaciones más argumentos**: envía solicitudes de configuración (como abrir o crear), conserva los identificadores devueltos y úsalos en solicitudes posteriores. Así, la retroalimentación de cobertura puede explorar transiciones de estado en lugar de llegar repetidamente a una comprobación de objeto no inicializado.<sup>[[17]](#references)</sup>

Para un objetivo de código cerrado, un harness en el mismo proceso que invoque la rutina de dispatch de MIG puede instrumentarse con Jackalope/TinyInst. El [harness CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz) es una implementación concreta, no un harness listo para usar con otros servicios.<sup>[[17]](#references)[[18]](#references)[[19]](#references)</sup>

**Valida cada crash a través de la ruta IPC real.** Un harness de dispatch directo omite la validación de mensajes Mach del kernel y puede generar falsos positivos, especialmente si proporciona memoria out-of-line (OOL) o descriptores de puerto no válidos. Asigna memoria OOL de respaldo válida en el harness y luego reproduce el testcase reducido mediante `mach_msg`, desde un cliente con el acceso original al servicio, y verifica que el daemon siga fallando.<sup>[[17]](#references)</sup>

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona con herramientas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

«**Simplemente funciona**» con muchas herramientas GUI de macOS. Algunas aplicaciones tienen requisitos adicionales, como nombres de archivo únicos, una extensión específica o leer archivos desde su contenedor de sandbox (`~/Library/Containers/com.apple.Safari/Data`).

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

- [1] [Respuesta a incidentes en OS X: scripting y análisis](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [2] [Jeremy Brown - Summer of Fuzz: MacOS - DEF CON 29 AppSec Village](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [3] [El arte del malware para Mac, volumen I: análisis](https://taomm.org/)
- [4] [No Starch Press - El arte del malware para Mac: guía para analizar software malicioso](https://nostarch.com/art-mac-malware)
- [5] [knight.sc - información almacenada en estas secciones de esta entrada del blog](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html)
- [6] [knight.sc - depuración de binarios de Apple que usan Pt Deny Attach](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html)
- [7] [alexomara.com - cómo eludir técnicas anti-debug: variantes de ptrace en macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants)
- [8] [Apple Developer Forums - registros estructurados de Xcode y `Enable-Private-Data`](https://developer.apple.com/forums/thread/738648)
- [9] [Super User - mostrar datos privados en el registro unificado de macOS](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log)
- [10] [Definiciones de solicitudes de Apple XNU `ptrace.h`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/ptrace.h)
- [11] [Implementación de Apple XNU `ptrace` en `mach_process.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/mach_process.c)
- [12] [Reverse Society - internals de ptrace: cómo impide que se adjunte un debugger](https://blog.reversesociety.co/blog/2024/anti-debugging-using-ptrace)
- [13] [tony-go/antidebug-examples - ejemplos de fork](https://github.com/tony-go/antidebug-examples/tree/main/fork)
- [14] [Reverse Society - técnica anti-debug con dlsym y fork](https://blog.reversesociety.co/blog/2024/anti-debugging-detection-with-fork)
- [15] [Apple - entitlement de la herramienta de debugging](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
- [16] [Apple Developer Forums - depuración de una aplicación de terceros protegida](https://developer.apple.com/forums/thread/776503)
- [17] [Project Zero - Rompiendo la barrera del sonido, parte I: fuzzing de CoreAudio con mensajes Mach](https://projectzero.google/2025/05/breaking-sound-barrier-part-i-fuzzing.html)
- [18] [Project Zero - harness de CoreAudioFuzz](https://github.com/googleprojectzero/p0tools/tree/master/CoreAudioFuzz)
- [19] [Project Zero - fuzzer Jackalope](https://github.com/googleprojectzero/Jackalope)
- [20] [Kaspersky Securelist - Una nueva versión del infostealer MacSync para macOS apunta a entusiastas de las criptomonedas y desarrolladores](https://securelist.com/macsync-new-version/121383/)
{{#include ../../../banners/hacktricks-training.md}}
