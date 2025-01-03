# macOS Apps - Inspección, depuración y Fuzzing

{{#include ../../../banners/hacktricks-training.md}}

## Análisis Estático

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
### jtool2 & Disarm

Puedes [**descargar disarm desde aquí**](https://newosxbook.com/tools/disarm.html).
```bash
ARCH=arm64e disarm -c -i -I --signature /path/bin # Get bin info and signature
ARCH=arm64e disarm -c -l /path/bin # Get binary sections
ARCH=arm64e disarm -c -L /path/bin # Get binary commands (dependencies included)
ARCH=arm64e disarm -c -S /path/bin # Get symbols (func names, strings...)
ARCH=arm64e disarm -c -d /path/bin # Get disasembled
jtool2 -d __DATA.__const myipc_server | grep MIG # Get MIG info
```
Puedes [**descargar jtool2 aquí**](http://www.newosxbook.com/tools/jtool.html) o instalarlo con `brew`.
```bash
# Install
brew install --cask jtool2

jtool2 -l /bin/ls # Get commands (headers)
jtool2 -L /bin/ls # Get libraries
jtool2 -S /bin/ls # Get symbol info
jtool2 -d /bin/ls # Dump binary
jtool2 -D /bin/ls # Decompile binary

# Get signature information
ARCH=x86_64 jtool2 --sig /System/Applications/Automator.app/Contents/MacOS/Automator

# Get MIG information
jtool2 -d __DATA.__const myipc_server | grep MIG
```
> [!CAUTION] > **jtool está en desuso a favor de disarm**

### Codesign / ldid

> [!TIP] > **`Codesign`** se puede encontrar en **macOS** mientras que **`ldid`** se puede encontrar en **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) es una herramienta útil para inspeccionar archivos **.pkg** (instaladores) y ver qué hay dentro antes de instalarlos.\
Estos instaladores tienen scripts bash `preinstall` y `postinstall` que los autores de malware suelen abusar para **persistir** **el** **malware**.

### hdiutil

Esta herramienta permite **montar** imágenes de disco de Apple (**.dmg**) para inspeccionarlas antes de ejecutar cualquier cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Se montará en `/Volumes`

### Binarios empaquetados

- Verificar la alta entropía
- Verificar las cadenas (si casi no hay cadenas comprensibles, empaquetado)
- El empaquetador UPX para MacOS genera una sección llamada "\_\_XHDR"

## Análisis estático de Objective-C

### Metadatos

> [!CAUTION]
> Tenga en cuenta que los programas escritos en Objective-C **retienen** sus declaraciones de clase **cuando** se **compilan** en [Mach-O binaries](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Tales declaraciones de clase **incluyen** el nombre y tipo de:

- Las interfaces definidas
- Los métodos de la interfaz
- Las variables de instancia de la interfaz
- Los protocolos definidos

Tenga en cuenta que estos nombres podrían estar ofuscados para dificultar la inversión del binario.

### Llamada a funciones

Cuando se llama a una función en un binario que utiliza Objective-C, el código compilado en lugar de llamar a esa función, llamará a **`objc_msgSend`**. Que llamará a la función final:

![](<../../../images/image (305).png>)

Los parámetros que esta función espera son:

- El primer parámetro (**self**) es "un puntero que apunta a la **instancia de la clase que debe recibir el mensaje**". O más simplemente, es el objeto sobre el cual se invoca el método. Si el método es un método de clase, esto será una instancia del objeto de la clase (en su totalidad), mientras que para un método de instancia, self apuntará a una instancia instanciada de la clase como un objeto.
- El segundo parámetro, (**op**), es "el selector del método que maneja el mensaje". Nuevamente, más simplemente, esto es solo el **nombre del método.**
- Los parámetros restantes son cualquier **valor que sea requerido por el método** (op).

Vea cómo **obtener esta información fácilmente con `lldb` en ARM64** en esta página:

{{#ref}}
arm64-basic-assembly.md
{{#endref}}

x64:

| **Argumento**     | **Registro**                                                   | **(para) objc_msgSend**                                 |
| ----------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argumento**  | **rdi**                                                        | **self: objeto sobre el cual se invoca el método**     |
| **2do argumento**  | **rsi**                                                        | **op: nombre del método**                              |
| **3er argumento**  | **rdx**                                                        | **1er argumento al método**                            |
| **4to argumento**  | **rcx**                                                        | **2do argumento al método**                            |
| **5to argumento**  | **r8**                                                         | **3er argumento al método**                            |
| **6to argumento**  | **r9**                                                         | **4to argumento al método**                            |
| **7mo+ argumento** | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p> | **5to+ argumento al método**                           |

### Volcar metadatos de ObjectiveC

### Dynadump

[**Dynadump**](https://github.com/DerekSelander/dynadump) es una herramienta para volcar clases de binarios de Objective-C. El github especifica dylibs, pero esto también funciona con ejecutables.
```bash
./dynadump dump /path/to/bin
```
En el momento de escribir esto, este es **actualmente el que mejor funciona**.

#### Herramientas regulares
```bash
nm --dyldinfo-only /path/to/bin
otool -ov /path/to/bin
objdump --macho --objc-meta-data /path/to/bin
```
#### class-dump

[**class-dump**](https://github.com/nygard/class-dump/) es la herramienta original que genera declaraciones para las clases, categorías y protocolos en código formateado en ObjetiveC.

Es antigua y no se mantiene, por lo que probablemente no funcionará correctamente.

#### ICDump

[**iCDump**](https://github.com/romainthomas/iCDump) es un volcado de clases de Objective-C moderno y multiplataforma. En comparación con las herramientas existentes, iCDump puede ejecutarse de forma independiente del ecosistema de Apple y expone enlaces de Python.
```python
import icdump
metadata = icdump.objc.parse("/path/to/bin")

print(metadata.to_decl())
```
## Análisis estático de Swift

Con los binarios de Swift, dado que hay compatibilidad con Objective-C, a veces puedes extraer declaraciones usando [class-dump](https://github.com/nygard/class-dump/) pero no siempre.

Con los comandos **`jtool -l`** o **`otool -l`** es posible encontrar varias secciones que comienzan con el prefijo **`__swift5`**:
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
Puedes encontrar más información sobre la [**información almacenada en esta sección en esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Además, **los binarios de Swift pueden tener símbolos** (por ejemplo, las bibliotecas necesitan almacenar símbolos para que sus funciones puedan ser llamadas). **Los símbolos generalmente tienen la información sobre el nombre de la función** y atributos de una manera poco legible, por lo que son muy útiles y hay "**demanglers"** que pueden obtener el nombre original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
## Análisis Dinámico

> [!WARNING]
> Tenga en cuenta que para depurar binarios, **SIP debe estar deshabilitado** (`csrutil disable` o `csrutil enable --without debug`) o copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <binary-path>` o permitir la depuración del binario (puede usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))

> [!WARNING]
> Tenga en cuenta que para **instrumentar binarios del sistema**, (como `cloudconfigurationd`) en macOS, **SIP debe estar deshabilitado** (simplemente eliminar la firma no funcionará).

### APIs

macOS expone algunas APIs interesantes que brindan información sobre los procesos:

- `proc_info`: Este es el principal que proporciona mucha información sobre cada proceso. Necesita ser root para obtener información de otros procesos, pero no necesita derechos especiales o puertos mach.
- `libsysmon.dylib`: Permite obtener información sobre procesos a través de funciones expuestas por XPC, sin embargo, es necesario tener el derecho `com.apple.sysmond.client`.

### Stackshot y microstackshots

**Stackshotting** es una técnica utilizada para capturar el estado de los procesos, incluidos los stacks de llamadas de todos los hilos en ejecución. Esto es particularmente útil para la depuración, análisis de rendimiento y comprensión del comportamiento del sistema en un momento específico. En iOS y macOS, el stackshotting se puede realizar utilizando varias herramientas y métodos como las herramientas **`sample`** y **`spindump`**.

### Sysdiagnose

Esta herramienta (`/usr/bini/ysdiagnose`) básicamente recopila mucha información de su computadora ejecutando decenas de comandos diferentes como `ps`, `zprint`...

Debe ejecutarse como **root** y el daemon `/usr/libexec/sysdiagnosed` tiene derechos muy interesantes como `com.apple.system-task-ports` y `get-task-allow`.

Su plist se encuentra en `/System/Library/LaunchDaemons/com.apple.sysdiagnose.plist` que declara 3 MachServices:

- `com.apple.sysdiagnose.CacheDelete`: Elimina archivos antiguos en /var/rmp
- `com.apple.sysdiagnose.kernel.ipc`: Puerto especial 23 (kernel)
- `com.apple.sysdiagnose.service.xpc`: Interfaz de modo usuario a través de la clase Obj-C `Libsysdiagnose`. Se pueden pasar tres argumentos en un dict (`compress`, `display`, `run`)

### Registros Unificados

MacOS genera muchos registros que pueden ser muy útiles al ejecutar una aplicación tratando de entender **qué está haciendo**.

Además, hay algunos registros que contendrán la etiqueta `<private>` para **ocultar** información **identificable** del **usuario** o **computadora**. Sin embargo, es posible **instalar un certificado para divulgar esta información**. Siga las explicaciones de [**aquí**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Etiquetas**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). No son todas las cadenas, sino las definidas en varias partes del archivo Mac-O (como _cstring o_ `objc_methname`).

#### Panel medio

En el panel medio puede ver el **código desensamblado**. Y puede verlo en un desensamblado **crudo**, como **gráfico**, como **decompilado** y como **binario** haciendo clic en el ícono respectivo:

<figure><img src="../../../images/image (343).png" alt=""><figcaption></figcaption></figure>

Al hacer clic derecho en un objeto de código, puede ver **referencias a/desde ese objeto** o incluso cambiar su nombre (esto no funciona en pseudocódigo decompilado):

<figure><img src="../../../images/image (1117).png" alt=""><figcaption></figcaption></figure>

Además, en la **parte media inferior puede escribir comandos de python**.

#### Panel derecho

En el panel derecho puede ver información interesante como el **historial de navegación** (para que sepa cómo llegó a la situación actual), el **gráfico de llamadas** donde puede ver todas las **funciones que llaman a esta función** y todas las funciones que **esta función llama**, y la información de **variables locales**.

### dtrace

Permite a los usuarios acceder a aplicaciones a un nivel **muy bajo** y proporciona una forma para que los usuarios **rastreen** **programas** e incluso cambien su flujo de ejecución. Dtrace utiliza **probes** que están **colocadas a lo largo del kernel** y están en ubicaciones como el inicio y el final de las llamadas al sistema.

DTrace utiliza la función **`dtrace_probe_create`** para crear un probe para cada llamada al sistema. Estos probes pueden activarse en el **punto de entrada y salida de cada llamada al sistema**. La interacción con DTrace ocurre a través de /dev/dtrace que solo está disponible para el usuario root.

> [!TIP]
> Para habilitar Dtrace sin deshabilitar completamente la protección SIP, podría ejecutar en modo de recuperación: `csrutil enable --without dtrace`
>
> También puede **`dtrace`** o **`dtruss`** binarios que **ha compilado**.

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
El nombre de la sonda consta de cuatro partes: el proveedor, módulo, función y nombre (`fbt:mach_kernel:ptrace:entry`). Si no especificas alguna parte del nombre, Dtrace aplicará esa parte como un comodín.

Para configurar DTrace para activar sondas y especificar qué acciones realizar cuando se disparen, necesitaremos usar el lenguaje D.

Una explicación más detallada y más ejemplos se pueden encontrar en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecuta `man -k dtrace` para listar los **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
- guion
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

Es una herramienta de trazado del kernel. Los códigos documentados se pueden encontrar en **`/usr/share/misc/trace.codes`**.

Herramientas como `latency`, `sc_usage`, `fs_usage` y `trace` la utilizan internamente.

Para interactuar con `kdebug`, se usa `sysctl` sobre el espacio de nombres `kern.kdebug` y los MIBs que se pueden encontrar en `sys/sysctl.h`, teniendo las funciones implementadas en `bsd/kern/kdebug.c`.

Para interactuar con kdebug con un cliente personalizado, estos son generalmente los pasos:

- Eliminar configuraciones existentes con KERN_KDSETREMOVE
- Establecer traza con KERN_KDSETBUF y KERN_KDSETUP
- Usar KERN_KDGETBUF para obtener el número de entradas del búfer
- Obtener el propio cliente de la traza con KERN_KDPINDEX
- Habilitar el trazado con KERN_KDENABLE
- Leer el búfer llamando a KERN_KDREADTR
- Para emparejar cada hilo con su proceso, llamar a KERN_KDTHRMAP.

Para obtener esta información, es posible usar la herramienta de Apple **`trace`** o la herramienta personalizada [kDebugView (kdv)](https://newosxbook.com/tools/kdv.html)**.**

**Nota que Kdebug solo está disponible para 1 cliente a la vez.** Así que solo se puede ejecutar una herramienta impulsada por k-debug al mismo tiempo.

### ktrace

Las APIs `ktrace_*` provienen de `libktrace.dylib`, que envuelven las de `Kdebug`. Luego, un cliente puede simplemente llamar a `ktrace_session_create` y `ktrace_events_[single/class]` para establecer callbacks en códigos específicos y luego iniciarlo con `ktrace_start`.

Puedes usar este incluso con **SIP activado**.

Puedes usar como clientes la utilidad `ktrace`:
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
O `tailspin`.

### kperf

Esto se utiliza para hacer un perfilado a nivel de kernel y está construido utilizando llamadas de `Kdebug`.

Básicamente, se verifica la variable global `kernel_debug_active` y si está activada, se llama a `kperf_kdebug_handler` con el código de `Kdebug` y la dirección del marco del kernel que llama. Si el código de `Kdebug` coincide con uno seleccionado, se obtienen las "acciones" configuradas como un bitmap (consulta `osfmk/kperf/action.h` para las opciones).

Kperf también tiene una tabla MIB de sysctl: (como root) `sysctl kperf`. Este código se puede encontrar en `osfmk/kperf/kperfbsd.c`.

Además, un subconjunto de la funcionalidad de Kperf reside en `kpc`, que proporciona información sobre los contadores de rendimiento de la máquina.

### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para verificar las acciones relacionadas con el proceso que un proceso está realizando (por ejemplo, monitorear qué nuevos procesos está creando un proceso).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) es una herramienta que imprime las relaciones entre procesos.\
Necesitas monitorear tu Mac con un comando como **`sudo eslogger fork exec rename create > cap.json`** (el terminal que lanza esto requiere FDA). Y luego puedes cargar el json en esta herramienta para ver todas las relaciones:

<figure><img src="../../../images/image (1182).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorear eventos de archivos (como creación, modificaciones y eliminaciones) proporcionando información detallada sobre dichos eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con la apariencia que los usuarios de Windows pueden conocer de _Procmon_ de Microsoft Sysinternal. Esta herramienta permite que la grabación de varios tipos de eventos se inicie y detenga, permite filtrar estos eventos por categorías como archivo, proceso, red, etc., y proporciona la funcionalidad para guardar los eventos grabados en un formato json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) son parte de las herramientas de desarrollador de Xcode – utilizadas para monitorear el rendimiento de aplicaciones, identificar fugas de memoria y rastrear la actividad del sistema de archivos.

![](<../../../images/image (1138).png>)

### fs_usage

Permite seguir las acciones realizadas por los procesos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** utilizadas por un binario, los **archivos** que está usando y las **conexiones** de **red**.\
También verifica los procesos binarios contra **virustotal** y muestra información sobre el binario.

## PT_DENY_ATTACH <a href="#page-title" id="page-title"></a>

En [**esta publicación del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo sobre cómo **depurar un daemon en ejecución** que utilizó **`PT_DENY_ATTACH`** para prevenir la depuración incluso si SIP estaba deshabilitado.

### lldb

**lldb** es la herramienta de **facto** para la **depuración** de binarios en **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puedes establecer el sabor de intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta de inicio con la siguiente línea:
```bash
settings set target.x86-disassembly-flavor intel
```
> [!WARNING]
> Dentro de lldb, volcar un proceso con `process save-core`

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descripción</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Iniciar la ejecución, que continuará sin interrupciones hasta que se alcance un punto de interrupción o el proceso termine.</td></tr><tr><td><strong>process launch --stop-at-entry</strong></td><td>Iniciar la ejecución deteniéndose en el punto de entrada</td></tr><tr><td><strong>continue (c)</strong></td><td>Continuar la ejecución del proceso depurado.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Ejecutar la siguiente instrucción. Este comando omitirá las llamadas a funciones.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Ejecutar la siguiente instrucción. A diferencia del comando nexti, este comando entrará en las llamadas a funciones.</td></tr><tr><td><strong>finish (f)</strong></td><td>Ejecutar el resto de las instrucciones en la función actual (“frame”) y detenerse.</td></tr><tr><td><strong>control + c</strong></td><td>Pausar la ejecución. Si el proceso ha sido ejecutado (r) o continuado (c), esto hará que el proceso se detenga ...donde sea que esté ejecutándose actualmente.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p><code>b main</code> #Cualquier función llamada main</p><p><code>b &#x3C;binname>`main</code> #Función principal del bin</p><p><code>b set -n main --shlib &#x3C;lib_name></code> #Función principal del bin indicado</p><p><code>breakpoint set -r '\[NSFileManager .*\]$'</code> #Cualquier método de NSFileManager</p><p><code>breakpoint set -r '\[NSFileManager contentsOfDirectoryAtPath:.*\]$'</code></p><p><code>break set -r . -s libobjc.A.dylib</code> # Romper en todas las funciones de esa biblioteca</p><p><code>b -a 0x0000000100004bd9</code></p><p><code>br l</code> #Lista de puntos de interrupción</p><p><code>br e/dis &#x3C;num></code> #Habilitar/Deshabilitar punto de interrupción</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obtener ayuda del comando de punto de interrupción</p><p>help memory write #Obtener ayuda para escribir en la memoria</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">formato</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;reg/dirección de memoria></strong></td><td>Mostrar la memoria como una cadena terminada en nulo.</td></tr><tr><td><strong>x/i &#x3C;reg/dirección de memoria></strong></td><td>Mostrar la memoria como instrucción de ensamblador.</td></tr><tr><td><strong>x/b &#x3C;reg/dirección de memoria></strong></td><td>Mostrar la memoria como byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Esto imprimirá el objeto referenciado por el parámetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Nota que la mayoría de las APIs o métodos de Objective-C de Apple devuelven objetos, y por lo tanto deben ser mostrados a través del comando “print object” (po). Si po no produce una salida significativa, usa <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escribir AAAA en esa dirección<br>memory write -f s $rip+0x11f+7 "AAAA" #Escribir AAAA en la dirección</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Desensamblar función actual</p><p>dis -n &#x3C;funcname> #Desensamblar función</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Desensamblar función<br>dis -c 6 #Desensamblar 6 líneas<br>dis -c 0x100003764 -e 0x100003768 # Desde una dirección hasta la otra<br>dis -p -c 4 # Comenzar en la dirección actual desensamblando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Verificar array de 3 componentes en el registro x1</td></tr><tr><td><strong>image dump sections</strong></td><td>Imprimir mapa de la memoria del proceso actual</td></tr><tr><td><strong>image dump symtab &#x3C;library></strong></td><td><code>image dump symtab CoreNLP</code> #Obtener la dirección de todos los símbolos de CoreNLP</td></tr></tbody></table>

> [!NOTE]
> Al llamar a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo (“C”). Para imprimir el nombre a través de lldb haz:
>
> `(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) print (char*)$rsi:`\
> `(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
>
> `(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

### Análisis Dinámico Anti

#### Detección de VM

- El comando **`sysctl hw.model`** devuelve "Mac" cuando el **host es un MacOS** pero algo diferente cuando es una VM.
- Jugando con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**, algunos malwares intentan detectar si es una VM.
- Algunos malwares también pueden **detectar** si la máquina está basada en **VMware** según la dirección MAC (00:50:56).
- También es posible encontrar **si un proceso está siendo depurado** con un código simple como:
- `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proceso siendo depurado }`
- También puede invocar la llamada al sistema **`ptrace`** con la bandera **`PT_DENY_ATTACH`**. Esto **previene** que un depurador se adjunte y rastree.
- Puedes verificar si la función **`sysctl`** o **`ptrace`** está siendo **importada** (pero el malware podría importarla dinámicamente)
- Como se señala en este informe, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_El mensaje Process # exited with **status = 45 (0x0000002d)** es generalmente una señal reveladora de que el objetivo de depuración está usando **PT_DENY_ATTACH**_”

## Volcados de Núcleo

Los volcados de núcleo se crean si:

- `kern.coredump` sysctl está configurado en 1 (por defecto)
- Si el proceso no era suid/sgid o `kern.sugid_coredump` es 1 (por defecto es 0)
- El límite `AS_CORE` permite la operación. Es posible suprimir la creación de volcados de núcleo llamando a `ulimit -c 0` y reactivarlos con `ulimit -c unlimited`.

En esos casos, el volcado de núcleo se genera de acuerdo con `kern.corefile` sysctl y se almacena generalmente en `/cores/core/.%P`.

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza procesos que fallan y guarda un informe de fallos en el disco**. Un informe de fallos contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un fallo.\
Para aplicaciones y otros procesos **que se ejecutan en el contexto de launchd por usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda informes de fallos en `~/Library/Logs/DiagnosticReports/` del usuario.\
Para demonios, otros procesos **que se ejecutan en el contexto de launchd del sistema** y otros procesos privilegiados, ReportCrash se ejecuta como un LaunchDaemon y guarda informes de fallos en `/Library/Logs/DiagnosticReports` del sistema.

Si te preocupa que los informes de fallos **se envíen a Apple**, puedes desactivarlos. Si no, los informes de fallos pueden ser útiles para **averiguar cómo se cayó un servidor**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sueño

Mientras se realiza fuzzing en MacOS, es importante no permitir que el Mac entre en modo de suspensión:

- systemsetup -setsleep Never
- pmset, Preferencias del Sistema
- [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión de SSH

Si estás realizando fuzzing a través de una conexión SSH, es importante asegurarte de que la sesión no se desconecte. Así que cambia el archivo sshd_config con:

- TCPKeepAlive Yes
- ClientAliveInterval 0
- ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Controladores Internos

**Consulta la siguiente página** para descubrir cómo puedes encontrar qué aplicación es responsable de **manejar el esquema o protocolo especificado:**

{{#ref}}
../macos-file-extension-apps.md
{{#endref}}

### Enumerando Procesos de Red

Esto es interesante para encontrar procesos que están gestionando datos de red:
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

Funciona para herramientas de línea de comandos

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Simplemente "**funciona"** con herramientas GUI de macOS. Tenga en cuenta que algunas aplicaciones de macOS tienen requisitos específicos como nombres de archivos únicos, la extensión correcta, necesitan leer los archivos desde el sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
### Más información sobre Fuzzing en MacOS

- [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
- [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
- [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referencias

- [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
- [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**The Art of Mac Malware: The Guide to Analyzing Malicious Software**](https://taomm.org/)

{{#include ../../../banners/hacktricks-training.md}}
