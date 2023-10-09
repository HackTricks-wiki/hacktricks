# macOS Apps - Inspección, depuración y Fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Análisis estático

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
{% endcode %}

### jtool2

Esta herramienta se puede utilizar como un **reemplazo** para **codesign**, **otool** y **objdump**, y ofrece algunas características adicionales. [**Descárgala aquí**](http://www.newosxbook.com/tools/jtool.html) o instálala con `brew`.
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
**`Codesign`** se encuentra en **macOS** mientras que **`ldid`** se encuentra en **iOS**
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

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) es una herramienta útil para inspeccionar archivos **.pkg** (instaladores) y ver qué hay dentro antes de instalarlo.\
Estos instaladores tienen scripts bash `preinstall` y `postinstall` que los autores de malware suelen abusar para **persistir** el **malware**.

### hdiutil

Esta herramienta permite **montar** imágenes de disco de Apple (**.dmg**) para inspeccionarlas antes de ejecutar cualquier cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Se montará en `/Volumes`

### Objective-C

#### Metadatos

{% hint style="danger" %}
Ten en cuenta que los programas escritos en Objective-C **mantienen** sus declaraciones de clase **cuando** se compilan en [binarios Mach-O](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md). Estas declaraciones de clase **incluyen** el nombre y tipo de:
{% endhint %}

* La clase
* Los métodos de clase
* Las variables de instancia de clase

Puedes obtener esta información utilizando [**class-dump**](https://github.com/nygard/class-dump):
```bash
class-dump Kindle.app
```
#### Llamada a funciones

Cuando se llama a una función en un binario que utiliza Objective-C, en lugar de llamar directamente a esa función, el código compilado llamará a **`objc_msgSend`**. Esta función llamará a la función final:

![](<../../../.gitbook/assets/image (560).png>)

Los parámetros que esta función espera son:

* El primer parámetro (**self**) es "un puntero que apunta a la **instancia de la clase que recibirá el mensaje**". En otras palabras, es el objeto sobre el cual se invoca el método. Si el método es un método de clase, esto será una instancia del objeto de la clase (en su totalidad), mientras que para un método de instancia, self apuntará a una instancia instanciada de la clase como objeto.
* El segundo parámetro (**op**) es "el selector del método que maneja el mensaje". Nuevamente, de manera más simple, este es simplemente el **nombre del método**.
* Los parámetros restantes son cualquier **valor que sea requerido por el método** (op).

| **Argumento**      | **Registro**                                                    | **(para) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argumento** | **rdi**                                                         | **self: objeto sobre el cual se invoca el método**      |
| **2do argumento** | **rsi**                                                         | **op: nombre del método**                              |
| **3er argumento** | **rdx**                                                         | **1er argumento para el método**                        |
| **4to argumento** | **rcx**                                                         | **2do argumento para el método**                        |
| **5to argumento** | **r8**                                                          | **3er argumento para el método**                        |
| **6to argumento** | **r9**                                                          | **4to argumento para el método**                        |
| **7mo+ argumento** | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p> | **5to+ argumento para el método**                       |

### Swift

Con binarios de Swift, dado que hay compatibilidad con Objective-C, a veces se pueden extraer declaraciones utilizando [class-dump](https://github.com/nygard/class-dump/), pero no siempre.

Con los comandos de línea **`jtool -l`** o **`otool -l`** es posible encontrar varias secciones que comienzan con el prefijo **`__swift5`**:
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
Puedes encontrar más información sobre la [**información almacenada en estas secciones en esta publicación de blog**](https://knight.sc/reverse%20engineering/2019/07/17/swift-metadata.html).

### Binarios comprimidos

* Verificar la entropía alta
* Verificar las cadenas (si no hay cadenas comprensibles, está comprimido)
* El empaquetador UPX para MacOS genera una sección llamada "\_\_XHDR"

## Análisis dinámico

{% hint style="warning" %}
Ten en cuenta que para depurar binarios, **SIP debe estar desactivado** (`csrutil disable` o `csrutil enable --without debug`) o copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <ruta-del-binario>` o permitir la depuración del binario (puedes usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b)).
{% endhint %}

{% hint style="warning" %}
Ten en cuenta que para **instrumentar binarios del sistema** (como `cloudconfigurationd`) en macOS, **SIP debe estar desactivado** (simplemente eliminar la firma no funcionará).
{% endhint %}

### Registros unificados

MacOS genera muchos registros que pueden ser muy útiles al ejecutar una aplicación para tratar de entender **qué está haciendo**.

Además, hay algunos registros que contendrán la etiqueta `<private>` para **ocultar** información **identificable** del **usuario** o **equipo**. Sin embargo, es posible **instalar un certificado para revelar esta información**. Sigue las explicaciones de [**aquí**](https://superuser.com/questions/1532031/how-to-show-private-data-in-macos-unified-log).

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Etiquetas**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). Estas no son todas las cadenas, sino las definidas en varias partes del archivo Mac-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central puedes ver el **código desensamblado**. Y puedes verlo como un desensamblado **en bruto**, como **gráfico**, como **descompilado** y como **binario** haciendo clic en el icono correspondiente:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Al hacer clic derecho en un objeto de código, puedes ver **referencias hacia/desde ese objeto** o incluso cambiar su nombre (esto no funciona en el pseudocódigo descompilado):

<figure><img src="../../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Además, en la **parte inferior central puedes escribir comandos de Python**.

#### Panel derecho

En el panel derecho puedes ver información interesante como el **historial de navegación** (para saber cómo llegaste a la situación actual), el **gráfico de llamadas** donde puedes ver todas las **funciones que llaman a esta función** y todas las funciones que **esta función llama**, e información sobre las **variables locales**.

### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel extremadamente **bajo** y proporciona una forma para que los usuarios **rastreen** **programas** e incluso cambien su flujo de ejecución. DTrace utiliza **sondas** que se **colocan en todo el kernel** y se encuentran en ubicaciones como el inicio y el final de las llamadas al sistema.

DTrace utiliza la función **`dtrace_probe_create`** para crear una sonda para cada llamada al sistema. Estas sondas se pueden activar en el **punto de entrada y salida de cada llamada al sistema**. La interacción con DTrace se realiza a través de /dev/dtrace, que solo está disponible para el usuario root.

{% hint style="success" %}
Para habilitar Dtrace sin desactivar completamente la protección SIP, puedes ejecutar en modo de recuperación: `csrutil enable --without dtrace`

También puedes **ejecutar** los binarios **`dtrace`** o **`dtruss`** que **has compilado**.
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
El nombre de la sonda consta de cuatro partes: el proveedor, el módulo, la función y el nombre (`fbt:mach_kernel:ptrace:entry`). Si no se especifica alguna parte del nombre, Dtrace la considerará como un comodín.

Para configurar DTrace y activar sondas, así como especificar las acciones a realizar cuando se activan, necesitaremos utilizar el lenguaje D.

Se puede encontrar una explicación más detallada y más ejemplos en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecuta `man -k dtrace` para listar los **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`

* En la línea
```bash
#Count the number of syscalls of each running process
sudo dtrace -n 'syscall:::entry {@[execname] = count()}'
```
# Inspeccionando, depurando y fuzzing de aplicaciones en macOS

En este directorio, encontrarás herramientas y técnicas para inspeccionar, depurar y realizar fuzzing en aplicaciones en macOS. Estas técnicas te permitirán analizar el comportamiento de las aplicaciones, identificar vulnerabilidades y encontrar posibles formas de escalada de privilegios.

## Inspeccionando aplicaciones

La inspección de aplicaciones implica examinar el código y los recursos de una aplicación para comprender su funcionamiento interno. Esto puede ayudarte a identificar posibles vulnerabilidades y a comprender cómo interactúa la aplicación con el sistema operativo.

### Herramientas de inspección

- [Hopper Disassembler](https://www.hopperapp.com/) - Un desensamblador de macOS que te permite examinar el código de una aplicación y comprender su estructura interna.
- [class-dump](https://github.com/nygard/class-dump) - Una herramienta de línea de comandos que extrae la declaración de clases y métodos de un binario ejecutable.
- [otool](https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/MachOTopics/0-Introduction/introduction.html) - Una herramienta de línea de comandos que muestra información sobre los archivos binarios de macOS.

## Depurando aplicaciones

La depuración de aplicaciones implica ejecutar una aplicación en un entorno controlado y examinar su comportamiento en tiempo de ejecución. Esto te permite identificar y solucionar problemas, así como descubrir posibles vulnerabilidades.

### Herramientas de depuración

- [lldb](https://lldb.llvm.org/) - Un depurador de macOS que te permite examinar y manipular el estado de una aplicación en tiempo de ejecución.
- [Xcode](https://developer.apple.com/xcode/) - Un entorno de desarrollo integrado (IDE) que incluye herramientas de depuración para aplicaciones macOS.

## Fuzzing de aplicaciones

El fuzzing es una técnica que implica enviar entradas aleatorias o maliciosas a una aplicación para encontrar posibles vulnerabilidades. Esta técnica es especialmente útil para descubrir vulnerabilidades de seguridad desconocidas.

### Herramientas de fuzzing

- [AFL](http://lcamtuf.coredump.cx/afl/) - Un marco de fuzzing que utiliza la instrumentación de código para generar entradas aleatorias y encontrar posibles vulnerabilidades.
- [Peach Fuzzer](https://peachfuzzer.com/) - Una plataforma de fuzzing que te permite crear y ejecutar pruebas de fuzzing personalizadas.
- [Radamsa](https://gitlab.com/akihe/radamsa) - Una herramienta de generación de mutaciones que se utiliza en combinación con otras herramientas de fuzzing.

## Recursos adicionales

Aquí tienes algunos recursos adicionales que pueden ser útiles para inspeccionar, depurar y realizar fuzzing en aplicaciones en macOS:

- [Apple Developer Documentation](https://developer.apple.com/documentation/) - Documentación oficial de Apple sobre el desarrollo de aplicaciones en macOS.
- [Reverse Engineering Resources](https://github.com/onethawt/reverseengineering-resources) - Una lista curada de recursos de ingeniería inversa, que incluye herramientas y tutoriales.

¡Diviértete explorando y descubriendo las vulnerabilidades de las aplicaciones en macOS!
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

`dtruss` is a command-line tool available on macOS that allows you to trace and inspect system calls made by a process. It can be used for debugging and analyzing the behavior of applications.

To use `dtruss`, you need to specify the process ID (PID) of the target application. You can find the PID using the `ps` command or by using tools like Activity Monitor.

Once you have the PID, you can run `dtruss` with the following syntax:

```bash
sudo dtruss -p <PID>
```

The `sudo` command is required because `dtruss` needs root privileges to trace system calls.

When `dtruss` is running, it will display a list of system calls made by the target process, along with their arguments and return values. This can be useful for understanding how an application interacts with the operating system and identifying any potential security vulnerabilities or performance issues.

Note that `dtruss` can generate a large amount of output, so it's recommended to redirect the output to a file for further analysis. You can do this by appending `> output.txt` to the `dtruss` command.

Keep in mind that `dtruss` is a powerful tool that should be used responsibly and with proper authorization. It can be used for legitimate purposes like debugging and troubleshooting, but it can also be misused for unauthorized access or malicious activities. Always ensure that you have the necessary permissions and legal authorization before using `dtruss` or any other similar tool.
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Puedes usar este incluso con **SIP activado**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para verificar las acciones relacionadas con los procesos que un proceso está realizando (por ejemplo, monitorear qué nuevos procesos está creando un proceso).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorear eventos de archivos (como creación, modificaciones y eliminaciones) proporcionando información detallada sobre dichos eventos.

### Crescendo

[**Crescendo**](https://github.com/SuprHackerSteve/Crescendo) es una herramienta GUI con la apariencia y sensación que los usuarios de Windows pueden conocer de _Procmon_ de Microsoft Sysinternal. Permite iniciar y detener la grabación de eventos de todo tipo, filtrarlos por categorías (archivo, proceso, red, etc.) y guardar los eventos grabados como archivo json.

### Apple Instruments

[**Apple Instruments**](https://developer.apple.com/library/archive/documentation/Performance/Conceptual/CellularBestPractices/Appendix/Appendix.html) son parte de las herramientas de desarrollador de Xcode, utilizadas para monitorear el rendimiento de las aplicaciones, identificar fugas de memoria y rastrear la actividad del sistema de archivos.

![](<../../../.gitbook/assets/image (15).png>)

### fs\_usage

Permite seguir las acciones realizadas por los procesos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** utilizadas por un binario, los **archivos** que está utilizando y las conexiones de **red**.\
También verifica los procesos binarios en **virustotal** y muestra información sobre el binario.

## PT\_DENY\_ATTACH <a href="#page-title" id="page-title"></a>

En [**esta publicación de blog**](https://knight.sc/debugging/2019/06/03/debugging-apple-binaries-that-use-pt-deny-attach.html) puedes encontrar un ejemplo sobre cómo **depurar un daemon en ejecución** que utiliza **`PT_DENY_ATTACH`** para evitar la depuración incluso si SIP está desactivado.

### lldb

**lldb** es la herramienta de **hecho** para la **depuración** de binarios en **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
Puedes configurar la variante de Intel al usar lldb creando un archivo llamado **`.lldbinit`** en tu carpeta de inicio con la siguiente línea:
```bash
settings set target.x86-disassembly-flavor intel
```
{% hint style="warning" %}
Dentro de lldb, volcar un proceso con `process save-core`
{% endhint %}

<table data-header-hidden><thead><tr><th width="225"></th><th></th></tr></thead><tbody><tr><td><strong>(lldb) Comando</strong></td><td><strong>Descripción</strong></td></tr><tr><td><strong>run (r)</strong></td><td>Iniciar la ejecución, que continuará sin interrupciones hasta que se alcance un punto de interrupción o el proceso termine.</td></tr><tr><td><strong>continue (c)</strong></td><td>Continuar la ejecución del proceso depurado.</td></tr><tr><td><strong>nexti (n / ni)</strong></td><td>Ejecutar la siguiente instrucción. Este comando omitirá las llamadas a funciones.</td></tr><tr><td><strong>stepi (s / si)</strong></td><td>Ejecutar la siguiente instrucción. A diferencia del comando nexti, este comando entrará en las llamadas a funciones.</td></tr><tr><td><strong>finish (f)</strong></td><td>Ejecutar el resto de las instrucciones en la función actual ("frame") y detenerse.</td></tr><tr><td><strong>control + c</strong></td><td>Pausar la ejecución. Si el proceso se ha ejecutado (r) o continuado (c), esto hará que el proceso se detenga ...donde sea que se esté ejecutando actualmente.</td></tr><tr><td><strong>breakpoint (b)</strong></td><td><p>b main #Cualquier función llamada main</p><p>b &#x3C;nombre_bin>`main #Función principal del binario</p><p>b set -n main --shlib &#x3C;nombre_lib> #Función principal del binario indicado</p><p>b -[NSDictionary objectForKey:]</p><p>b -a 0x0000000100004bd9</p><p>br l #Lista de puntos de interrupción</p><p>br e/dis &#x3C;número> #Habilitar/Deshabilitar punto de interrupción</p><p>breakpoint delete &#x3C;número></p></td></tr><tr><td><strong>help</strong></td><td><p>help breakpoint #Obtener ayuda del comando breakpoint</p><p>help memory write #Obtener ayuda para escribir en la memoria</p></td></tr><tr><td><strong>reg</strong></td><td><p>reg read</p><p>reg read $rax</p><p>reg read $rax --format &#x3C;<a href="https://lldb.llvm.org/use/variable.html#type-format">formato</a>></p><p>reg write $rip 0x100035cc0</p></td></tr><tr><td><strong>x/s &#x3C;dirección_reg/memoria></strong></td><td>Mostrar la memoria como una cadena terminada en nulo.</td></tr><tr><td><strong>x/i &#x3C;dirección_reg/memoria></strong></td><td>Mostrar la memoria como instrucción de ensamblador.</td></tr><tr><td><strong>x/b &#x3C;dirección_reg/memoria></strong></td><td>Mostrar la memoria como byte.</td></tr><tr><td><strong>print object (po)</strong></td><td><p>Esto imprimirá el objeto al que hace referencia el parámetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Tenga en cuenta que la mayoría de las API o métodos de Objective-C de Apple devuelven objetos y, por lo tanto, deben mostrarse mediante el comando "print object" (po). Si po no produce una salida significativa, use <code>x/b</code></p></td></tr><tr><td><strong>memory</strong></td><td>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escribir AAAA en esa dirección<br>memory write -f s $rip+0x11f+7 "AAAA" #Escribir AAAA en la dirección</td></tr><tr><td><strong>disassembly</strong></td><td><p>dis #Desensamblar la función actual</p><p>dis -n &#x3C;nombre_func> #Desensamblar función</p><p>dis -n &#x3C;nombre_func> -b &#x3C;nombre_base> #Desensamblar función<br>dis -c 6 #Desensamblar 6 líneas<br>dis -c 0x100003764 -e 0x100003768 #Desde una dirección hasta la otra<br>dis -p -c 4 #Comenzar en la dirección actual desensamblando</p></td></tr><tr><td><strong>parray</strong></td><td>parray 3 (char **)$x1 #Comprobar el array de 3 componentes en el registro x1</td></tr></tbody></table>

{% hint style="info" %}
Cuando se llama a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo ("C"). Para imprimir el nombre a través de lldb, haga lo siguiente:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análisis Dinámico

#### Detección de VM

* El comando **`sysctl hw.model`** devuelve "Mac" cuando el **host es un MacOS**, pero algo diferente cuando es una VM.
* Al jugar con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**, algunos malware intentan detectar si es una VM.
* Algunos malware también pueden **detectar** si la máquina es **VMware** basándose en la dirección MAC (00:50:56).
* También es posible encontrar si un proceso está siendo depurado con un código simple como:
* `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proceso siendo depurado }`
* También puede invocar la llamada al sistema **`ptrace`** con la bandera **`PT_DENY_ATTACH`**. Esto **impide** que un depurador se adjunte y realice un seguimiento.
* Puede verificar si la función **`sysctl`** o **`ptrace`** está siendo **importada** (pero el malware podría importarla dinámicamente)
* Como se señala en este artículo, "[Derrotando Técnicas Anti-Depuración: variantes de ptrace en macOS](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)":\
"_El mensaje Process # exited with **status = 45 (0x0000002d)** generalmente es una señal reveladora de que el objetivo de depuración está utilizando **PT\_DENY\_ATTACH**_"
## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza los procesos que se bloquean y guarda un informe de bloqueo en el disco**. Un informe de bloqueo contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un bloqueo.\
Para aplicaciones y otros procesos **que se ejecutan en el contexto de lanzamiento por usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda los informes de bloqueo en `~/Library/Logs/DiagnosticReports/` del usuario.\
Para demonios, otros procesos **que se ejecutan en el contexto de lanzamiento del sistema** y otros procesos privilegiados, ReportCrash se ejecuta como un LaunchDaemon y guarda los informes de bloqueo en `/Library/Logs/DiagnosticReports` del sistema.

Si te preocupa que los informes de bloqueo **se envíen a Apple**, puedes desactivarlos. Si no, los informes de bloqueo pueden ser útiles para **determinar cómo se bloqueó un servidor**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Suspensión

Cuando se realiza fuzzing en MacOS, es importante evitar que la Mac entre en suspensión:

* systemsetup -setsleep Never
* pmset, Preferencias del sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión SSH

Si estás realizando fuzzing a través de una conexión SSH, es importante asegurarse de que la sesión no se cierre. Para ello, cambia el archivo sshd\_config con:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Controladores internos

**Consulta la siguiente página** para descubrir cómo puedes encontrar qué aplicación es responsable de **manejar el esquema o protocolo especificado:**

{% content-ref url="../macos-file-extension-apps.md" %}
[macos-file-extension-apps.md](../macos-file-extension-apps.md)
{% endcontent-ref %}

### Enumeración de procesos de red

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
{% endcode %}

### Fuzzers

#### [AFL++](https://github.com/AFLplusplus/AFLplusplus)

Funciona para herramientas de línea de comandos.

#### [Litefuzz](https://github.com/sec-tools/litefuzz)

Funciona con herramientas de GUI de macOS. Ten en cuenta que algunas aplicaciones de macOS tienen requisitos específicos como nombres de archivo únicos, la extensión correcta, necesitan leer los archivos desde el sandbox (`~/Library/Containers/com.apple.Safari/Data`)...

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
{% endcode %}

### Más información sobre Fuzzing en MacOS

* [https://www.youtube.com/watch?v=T5xfL9tEg44](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [https://github.com/bnagy/slides/blob/master/OSXScale.pdf](https://github.com/bnagy/slides/blob/master/OSXScale.pdf)
* [https://github.com/bnagy/francis/tree/master/exploitaben](https://github.com/bnagy/francis/tree/master/exploitaben)
* [https://github.com/ant4g0nist/crashwrangler](https://github.com/ant4g0nist/crashwrangler)

## Referencias

* [**OS X Incident Response: Scripting and Analysis**](https://www.amazon.com/OS-Incident-Response-Scripting-Analysis-ebook/dp/B01FHOHHVS)
* [**https://www.youtube.com/watch?v=T5xfL9tEg44**](https://www.youtube.com/watch?v=T5xfL9tEg44)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
