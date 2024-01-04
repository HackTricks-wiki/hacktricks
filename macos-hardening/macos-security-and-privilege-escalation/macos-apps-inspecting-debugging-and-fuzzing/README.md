# Aplicaciones macOS - Inspección, depuración y Fuzzing

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Análisis Estático

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

{% code overflow="wrap" %}
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
objdump --disassemble-symbols=_hello --x86-asm-syntax=intel toolsdemo #Disassemble a function using intel flavour
```
### jtool2

La herramienta puede usarse como un **reemplazo** para **codesign**, **otool** y **objdump**, y ofrece algunas características adicionales. [**Descárgala aquí**](http://www.newosxbook.com/tools/jtool.html) o instálala con `brew`.
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
### Codesign / ldid

{% hint style="danger" %}
**`Codesign`** se puede encontrar en **macOS** mientras que **`ldid`** se puede encontrar en **iOS**
{% endhint %}
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
Estos instaladores tienen scripts de bash `preinstall` y `postinstall` que los autores de **malware** suelen abusar para **persistir** **el** **malware**.

### hdiutil

Esta herramienta permite **montar** imágenes de disco de Apple (**.dmg**) para inspeccionarlas antes de ejecutar cualquier cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Se montará en `/Volumes`

### Objective-C

#### Metadatos

{% hint style="danger" %}
Ten en cuenta que los programas escritos en Objective-C **conservan** sus declaraciones de clase **cuando** se **compilan** en [binarios Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Dichas declaraciones de clase **incluyen** el nombre y tipo de:
{% endhint %}

* La clase
* Los métodos de la clase
* Las variables de instancia de la clase

Puedes obtener esta información utilizando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Llamada de función

Cuando se llama a una función en un binario que utiliza Objective-C, el código compilado, en lugar de llamar a esa función, llamará a **`objc_msgSend`**. Que será quien llame a la función final:

![](<../../../.gitbook/assets/image (560).png>)

Los parámetros que esta función espera son:

* El primer parámetro (**self**) es "un puntero que apunta a la **instancia de la clase que va a recibir el mensaje**". O dicho de manera más simple, es el objeto sobre el cual se está invocando el método. Si el método es un método de clase, esto será una instancia del objeto de clase (en su conjunto), mientras que para un método de instancia, self apuntará a una instancia instanciada de la clase como objeto.
* El segundo parámetro, (**op**), es "el selector del método que maneja el mensaje". Nuevamente, dicho de manera más simple, esto es solo el **nombre del método**.
* Los parámetros restantes son cualquier **valor que requiera el método** (op).

| **Argumento**       | **Registro**                                                    | **(para) objc\_msgSend**                                |
| ------------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argumento**   | **rdi**                                                         | **self: objeto sobre el cual se invoca el método**      |
| **2do argumento**   | **rsi**                                                         | **op: nombre del método**                               |
| **3er argumento**   | **rdx**                                                         | **1er argumento para el método**                        |
| **4to argumento**   | **rcx**                                                         | **2do argumento para el método**                        |
| **5to argumento**   | **r8**                                                          | **3er argumento para el método**                        |
| **6to argumento**   | **r9**                                                          | **4to argumento para el método**                        |
| **7mo+ argumento**  | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p>   | **5to+ argumento para el método**                       |

### Swift

Con los binarios Swift, ya que hay compatibilidad con Objective-C, a veces puedes extraer declaraciones usando [class-dump](https://github.com/nygard/class-dump/) pero no siempre.

Con las líneas de comando **`jtool -l`** o **`otool -l`** es posible encontrar varias secciones que comienzan con el prefijo **`__swift5`**:
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
Puede encontrar más información sobre la [**información almacenada en estas secciones en esta entrada de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

Además, los **binarios Swift pueden tener símbolos** (por ejemplo, las bibliotecas necesitan almacenar símbolos para que se puedan llamar a sus funciones). Los **símbolos generalmente tienen información sobre el nombre de la función** y attr de una manera fea, por lo que son muy útiles y hay "**demanglers**" que pueden obtener el nombre original:
```bash
# Ghidra plugin
https://github.com/ghidraninja/ghidra_scripts/blob/master/swift_demangler.py

# Swift cli
swift demangle
```
### Binarios empaquetados

* Verificar la alta entropía
* Revisar las cadenas (si casi no hay cadenas comprensibles, empaquetado)
* El empaquetador UPX para MacOS genera una sección llamada "\_\_XHDR"

## Análisis Dinámico

{% hint style="warning" %}
Nota que para depurar binarios, **SIP necesita estar deshabilitado** (`csrutil disable` o `csrutil enable --without debug`) o copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <ruta-del-binario>` o permitir la depuración del binario (puedes usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Nota que para **instrumentar binarios del sistema**, (como `cloudconfigurationd`) en macOS, **SIP debe estar deshabilitado** (solo eliminar la firma no funcionará).
{% endhint %}

### Registros Unificados

MacOS genera muchos registros que pueden ser muy útiles al ejecutar una aplicación para entender **qué está haciendo**.

Además, hay algunos registros que contendrán la etiqueta `<private>` para **ocultar** información **identificable** del **usuario** o del **ordenador**. Sin embargo, es posible **instalar un certificado para revelar esta información**. Sigue las explicaciones de [**aquí**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Etiquetas**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). Estas no son todas las cadenas sino las definidas en varias partes del archivo Mac-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central puedes ver el **código desensamblado**. Y puedes verlo en desensamblaje **crudo**, como **gráfico**, como **decompilado** y como **binario** haciendo clic en el icono respectivo:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Haciendo clic derecho en un objeto de código puedes ver **referencias hacia/desde ese objeto** o incluso cambiar su nombre (esto no funciona en pseudocódigo decompilado):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Además, en la **parte inferior central puedes escribir comandos de python**.

#### Panel derecho

En el panel derecho puedes ver información interesante como el **historial de navegación** (para saber cómo llegaste a la situación actual), el **gráfico de llamadas** donde puedes ver todas las **funciones que llaman a esta función** y todas las funciones que **esta función llama**, e información sobre **variables locales**.

### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel **muy bajo** y proporciona una forma de **rastrear** **programas** e incluso cambiar su flujo de ejecución. Dtrace utiliza **sondas** que están **ubicadas a lo largo del kernel** y están en ubicaciones como el principio y el final de las llamadas al sistema.

DTrace utiliza la función **`dtrace_probe_create`** para crear una sonda para cada llamada al sistema. Estas sondas pueden activarse en el **punto de entrada y salida de cada llamada al sistema**. La interacción con DTrace ocurre a través de /dev/dtrace que solo está disponible para el usuario root.

{% hint style="success" %}
Para habilitar Dtrace sin deshabilitar completamente la protección SIP puedes ejecutar en modo de recuperación: `csrutil enable --without dtrace`

También puedes **`dtrace`** o **`dtruss`** binarios que **has compilado**.
{% endhint %}

Las sondas disponibles de dtrace se pueden obtener con:
```bash
dtrace -l | head
ID   PROVIDER            MODULE                          FUNCTION NAME
1     dtrace                                                     BEGIN
2     dtrace                                                     END
3     dtrace                                                     ERROR
43    profile                                                     profile-97
44    profile                                                     profile-199
```
El nombre de la sonda consta de cuatro partes: el proveedor, el módulo, la función y el nombre (`fbt:mach_kernel:ptrace:entry`). Si no se especifica alguna parte del nombre, Dtrace aplicará esa parte como comodín.

Para configurar DTrace para activar sondas y especificar qué acciones realizar cuando se activan, necesitaremos usar el lenguaje D.

Una explicación más detallada y más ejemplos se pueden encontrar en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecuta `man -k dtrace` para listar los **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`

* En línea
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
* guión
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
### ktrace

Puedes usar este incluso con **SIP activado**
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para verificar las acciones relacionadas con procesos que un proceso está realizando (por ejemplo, monitorear qué nuevos procesos está creando un proceso).

### SpriteTree

[**SpriteTree**](https://themittenmac.com/tools/) es una herramienta que imprime las relaciones entre procesos.\
Necesitas monitorear tu mac con un comando como **`sudo eslogger fork exec rename create > cap.json`** (la terminal que lanza esto requiere FDA). Y luego puedes cargar el json en esta herramienta para ver todas las relaciones:

<figure><img src="../../../.gitbook/assets/image (710).png" alt="" width="375"><figcaption></figcaption></figure>

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorear eventos de archivos (como creación, modificaciones y eliminaciones) proporcionando información detallada sobre dichos eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con una apariencia que los usuarios de Windows pueden reconocer de _Procmon_ de Microsoft Sysinternal. Te permite iniciar y detener la grabación de eventos de todo tipo, filtrarlos por categorías (archivo, proceso, red, etc.) y guardar los eventos grabados como archivo json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) son parte de las herramientas de desarrollo de Xcode, utilizadas para monitorear el rendimiento de las aplicaciones, identificar fugas de memoria y rastrear la actividad del sistema de archivos.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permite seguir las acciones realizadas por los procesos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**TaskExplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** utilizadas por un binario, los **archivos** que está utilizando y las conexiones de **red**.\
También verifica los procesos binarios contra **virustotal** y muestra información sobre el binario.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

En [**este artículo del blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo sobre cómo **depurar un daemon en ejecución** que utilizó **`PT_DENY_ATTACH`** para prevenir la depuración incluso si SIP estaba deshabilitado.

### lldb

**lldb** es la herramienta **de facto** para **depuración** de binarios en **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puedes establecer la versión de Intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta de inicio con la siguiente línea:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Dentro de lldb, vuelca un proceso con `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descripción</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Inicia la ejecución, que continuará sin interrupciones hasta que se alcance un punto de interrupción o el proceso termine.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continúa la ejecución del proceso depurado.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Ejecuta la siguiente instrucción. Este comando omitirá las llamadas a funciones.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Ejecuta la siguiente instrucción. A diferencia del comando nexti, este comando entrará en las llamadas a funciones.</td></tr><tr><td><strong>finish (f)</strong></td><td>Ejecuta el resto de las instrucciones en la función actual ("frame") y se detiene al retornar.</td></tr><tr><td><strong>control + c</strong></td><td>Pausa la ejecución. Si el proceso ha sido iniciado (r) o continuado (c), esto hará que el proceso se detenga... dondequiera que se esté ejecutando actualmente.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Cualquier func llamada main</p><p>b &#x3C;binname>`main #Func principal del bin</p><p>b set -n main --shlib &#x3C;lib_name> #Func principal del bin indicado</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista de puntos de interrupción</p><p>br e/dis &#x3C;num> #Habilitar/Deshabilitar punto de interrupción</p><p>breakpoint delete &#x3C;num></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obtener ayuda del comando breakpoint</p><p>help memory write #Obtener ayuda para escribir en la memoria</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">format</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;dirección reg/memoria></strong></td><td>Muestra la memoria como una cadena terminada en nulo.</td></tr><tr><td><strong>x/i &#x3C;dirección reg/memoria></strong></td><td>Muestra la memoria como instrucción de ensamblaje.</td></tr><tr><td><strong>x/b &#x3C;dirección reg/memoria></strong></td><td>Muestra la memoria como byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Esto imprimirá el objeto referenciado por el parámetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Nota que la mayoría de las APIs o métodos de Objective-C de Apple devuelven objetos, y por lo tanto deben ser mostrados a través del comando "print object" (po). Si po no produce una salida significativa usa <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escribe AAAA en esa dirección<br>memory write -f s $rip+0x11f+7 "AAAA" #Escribe AAAA en la dirección</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Desensambla función actual</p><p>dis -n &#x3C;funcname> #Desensambla func</p><p>dis -n &#x3C;funcname> -b &#x3C;basename> #Desensambla func<br>dis -c 6 #Desensambla 6 líneas<br>dis -c 0x100003764 -e 0x100003768 # De una dirección a otra<br>dis -p -c 4 #Comienza en la dirección actual desensamblando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 # Revisa array de 3 componentes en reg x1</td></tr></tbody></table>

{% hint style="info" %}
Al llamar a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo ("C"). Para imprimir el nombre a través de lldb haz:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análisis Dinámico

#### Detección de VM

* El comando **`sysctl hw.model`** devuelve "Mac" cuando el **anfitrión es un MacOS** pero algo diferente cuando es una VM.
* Jugando con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`** algunos malwares intentan detectar si es una VM.
* Algunos malwares también pueden **detectar** si la máquina es **VMware** basándose en la dirección MAC (00:50:56).
* También es posible encontrar **si un proceso está siendo depurado** con un código simple como:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proceso siendo depurado }`
* También puede invocar la llamada al sistema **`ptrace`** con la bandera **`PT_DENY_ATTACH`**. Esto **previene** que un dep**u**rador se adjunte y trace.
* Puedes verificar si la función **`sysctl`** o **`ptrace`** está siendo **importada** (pero el malware podría importarla dinámicamente)
* Como se nota en este artículo, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
“_El mensaje Process # exited with **status = 45 (0x0000002d)** es generalmente una señal clara de que el objetivo de depuración está utilizando **PT\_DENY\_ATTACH**_”

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza procesos que se han caído y guarda un informe de fallos en disco**. Un informe de fallos contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un fallo.\
Para aplicaciones y otros procesos **ejecutándose en el contexto de lanzamiento por usuario**, ReportCrash funciona como un LaunchAgent y guarda los informes de fallos en `~/Library/Logs/DiagnosticReports/` del usuario\
Para demonios, otros procesos **ejecutándose en el contexto de lanzamiento del sistema** y otros procesos privilegiados, ReportCrash funciona como un LaunchDaemon y guarda los informes de fallos en `/Library/Logs/DiagnosticReports` del sistema

Si te preocupa que los informes de fallos **sean enviados a Apple** puedes deshabilitarlos. Si no, los informes de fallos pueden ser útiles para **averiguar cómo se cayó un servidor**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Suspensión

Al realizar fuzzing en un MacOS, es importante evitar que el Mac entre en suspensión:

* systemsetup -setsleep Never
* pmset, Preferencias del Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión SSH

Si estás realizando fuzzing a través de una conexión SSH, es importante asegurarse de que la sesión no se corte. Por lo tanto, cambia el archivo sshd_config con:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manejadores Internos

**Consulta la siguiente página** para descubrir cómo puedes encontrar qué aplicación es responsable de **manejar el esquema o protocolo especificado:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumeración de Procesos de Red

Esto es interesante para encontrar procesos que están gestionando datos de red:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
O utiliza `netstat` o `lsof`

### Libgmalloc

<figure><img src="../../../.gitbook/assets/Pasted Graphic 14.png" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```bash
lldb -o "target create `which some-binary`" -o "settings set target.env-vars DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib" -o "run arg1 arg2" -o "bt" -o "reg read" -o "dis -s \$pc-32 -c 24 -m -F intel" -o "quit"
```
### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para herramientas CLI

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Funciona "**simplemente**" con herramientas GUI de macOS. Nota que algunas aplicaciones de macOS tienen requisitos específicos como nombres de archivos únicos, la extensión correcta, necesidad de leer los archivos desde el sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

Algunos ejemplos:

{% code overflow="wrap" %}
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
```markdown
{% endcode %}

### Más Información sobre Fuzzing en MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referencias

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
```
