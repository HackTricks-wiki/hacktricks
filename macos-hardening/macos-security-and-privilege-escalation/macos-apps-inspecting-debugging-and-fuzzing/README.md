# macOS Apps - Inspección, depuración y Fuzzing

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Análisis estático

### otool
```bash
otool -L /bin/ls #List dynamically linked libraries
otool -tv /bin/ps #Decompile application
```
### objdump

objdump es una herramienta de línea de comandos que se utiliza para inspeccionar archivos binarios y objetos. Puede mostrar información detallada sobre los archivos ejecutables, bibliotecas compartidas, archivos objeto y otros formatos de archivo binario. También puede desensamblar el código de la máquina y mostrar la información de depuración. objdump es una herramienta útil para la ingeniería inversa y la depuración de aplicaciones.
```bash
objdump -m --dylibs-used /bin/ls #List dynamically linked libraries
objdump -m -h /bin/ls # Get headers information
objdump -m --syms /bin/ls # Check if the symbol table exists to get function names
objdump -m --full-contents /bin/ls # Dump every section
objdump -d /bin/ls # Dissasemble the binary
```
### jtool2

La herramienta puede ser utilizada como un **reemplazo** para **codesign**, **otool** y **objdump**, y proporciona algunas características adicionales.
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

```
### Codesign

Codesign es una herramienta de línea de comandos que se utiliza para firmar digitalmente archivos en macOS. La firma digital proporciona una forma de verificar la integridad y autenticidad de los archivos. Los desarrolladores pueden usar codesign para firmar sus aplicaciones antes de distribuirlas, lo que ayuda a prevenir la manipulación malintencionada de los archivos. Además, codesign también se utiliza para verificar la firma de los archivos existentes y para identificar cualquier problema de firma.
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
```
### SuspiciousPackage

[**SuspiciousPackage**](https://mothersruin.com/software/SuspiciousPackage/get.html) es una herramienta útil para inspeccionar archivos **.pkg** (instaladores) y ver qué hay dentro antes de instalarlo.\
Estos instaladores tienen scripts bash `preinstall` y `postinstall` que los autores de malware suelen abusar para **persistir** el **malware**.

### hdiutil

Esta herramienta permite **montar** imágenes de disco de Apple (**.dmg**) para inspeccionarlas antes de ejecutar cualquier cosa:
```bash
hdiutil attach ~/Downloads/Firefox\ 58.0.2.dmg
```
Será montado en `/Volumes`

### Objective-C

Cuando se llama a una función en un binario que utiliza Objective-C, en lugar de llamar a esa función, el código compilado llamará a **`objc_msgSend`**. Que llamará a la función final:

![](<../../../.gitbook/assets/image (560).png>)

Los parámetros que esta función espera son:

* El primer parámetro (**self**) es "un puntero que apunta a la **instancia de la clase que recibirá el mensaje**". O dicho de manera más simple, es el objeto sobre el que se invoca el método. Si el método es un método de clase, esto será una instancia del objeto de la clase (en su totalidad), mientras que para un método de instancia, self apuntará a una instancia instanciada de la clase como objeto.
* El segundo parámetro, (**op**), es "el selector del método que maneja el mensaje". De nuevo, de manera más simple, este es solo el **nombre del método**.
* Los parámetros restantes son cualquier **valor que requiera el método** (op).

| **Argumento**      | **Registro**                                                    | **(para) objc\_msgSend**                                |
| ----------------- | --------------------------------------------------------------- | ------------------------------------------------------ |
| **1er argumento**  | **rdi**                                                         | **self: objeto sobre el que se invoca el método**      |
| **2º argumento**  | **rsi**                                                         | **op: nombre del método**                              |
| **3er argumento**  | **rdx**                                                         | **1er argumento para el método**                        |
| **4º argumento**  | **rcx**                                                         | **2º argumento para el método**                         |
| **5º argumento**  | **r8**                                                          | **3er argumento para el método**                        |
| **6º argumento**  | **r9**                                                          | **4º argumento para el método**                         |
| **7º+ argumento** | <p><strong>rsp+</strong><br><strong>(en la pila)</strong></p> | **5º+ argumento para el método**                       |

### Binarios empaquetados

* Comprobar la entropía alta
* Comprobar las cadenas (si hay casi ninguna cadena comprensible, empaquetado)
* El empaquetador UPX para MacOS genera una sección llamada "\_\_XHDR"

## Análisis dinámico

{% hint style="warning" %}
Tenga en cuenta que para depurar binarios, **SIP debe estar deshabilitado** (`csrutil disable` o `csrutil enable --without debug`) o copiar los binarios a una carpeta temporal y **eliminar la firma** con `codesign --remove-signature <ruta-del-binario>` o permitir la depuración del binario (puede usar [este script](https://gist.github.com/carlospolop/a66b8d72bb8f43913c4b5ae45672578b))
{% endhint %}

{% hint style="warning" %}
Tenga en cuenta que para **instrumentar binarios del sistema**, (como `cloudconfigurationd`) en macOS, **SIP debe estar deshabilitado** (simplemente eliminar la firma no funcionará).
{% endhint %}

### Hopper

#### Panel izquierdo

En el panel izquierdo de Hopper es posible ver los símbolos (**Etiquetas**) del binario, la lista de procedimientos y funciones (**Proc**) y las cadenas (**Str**). Estas no son todas las cadenas, sino las definidas en varias partes del archivo Mac-O (como _cstring o_ `objc_methname`).

#### Panel central

En el panel central se puede ver el **código desensamblado**. Y se puede ver como **crudo**, como **gráfico**, como **descompilado** y como **binario** haciendo clic en el icono respectivo:

<figure><img src="../../../.gitbook/assets/image (2) (6).png" alt=""><figcaption></figcaption></figure>

Al hacer clic con el botón derecho en un objeto de código, se pueden ver las **referencias desde/hacia ese objeto** o incluso cambiar su nombre (esto no funciona en el pseudocódigo descompilado):

<figure><img src="../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Además, en la **parte inferior central se pueden escribir comandos de Python**.

#### Panel derecho

En el panel derecho se pueden ver información interesante como el **historial de navegación** (para saber cómo llegó a la situación actual), el **gráfico de llamadas** donde se pueden ver todas las **funciones que llaman a esta función** y todas las funciones que **esta función llama**, e información de **variables locales**.

### dtruss
```bash
dtruss -c ls #Get syscalls of ls
dtruss -c -p 1000 #get syscalls of PID 1000
```
### ktrace

Puedes usar este incluso con **SIP activado**.
```bash
ktrace trace -s -S -t c -c ls | grep "ls("
```
### dtrace

Permite a los usuarios acceder a las aplicaciones a un nivel extremadamente **bajo nivel** y proporciona una forma para que los usuarios **rastreen** **programas** e incluso cambien su flujo de ejecución. Dtrace utiliza **sondas** que se **colocan en todo el kernel** y se encuentran en lugares como el inicio y el final de las llamadas al sistema.

DTrace utiliza la función **`dtrace_probe_create`** para crear una sonda para cada llamada al sistema. Estas sondas se pueden activar en el **punto de entrada y salida de cada llamada al sistema**. La interacción con DTrace ocurre a través de /dev/dtrace, que solo está disponible para el usuario root.

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
El nombre de la sonda consta de cuatro partes: el proveedor, el módulo, la función y el nombre (`fbt:mach_kernel:ptrace:entry`). Si no se especifica alguna parte del nombre, Dtrace la aplicará como comodín.

Para configurar DTrace para activar sondas y especificar qué acciones realizar cuando se activan, necesitaremos usar el lenguaje D.

Se puede encontrar una explicación más detallada y más ejemplos en [https://illumos.org/books/dtrace/chp-intro.html](https://illumos.org/books/dtrace/chp-intro.html)

#### Ejemplos

Ejecute `man -k dtrace` para listar los **scripts de DTrace disponibles**. Ejemplo: `sudo dtruss -n binary`

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
### ProcessMonitor

[**ProcessMonitor**](https://objective-see.com/products/utilities.html#ProcessMonitor) es una herramienta muy útil para verificar las acciones relacionadas con procesos que un proceso está realizando (por ejemplo, monitorear qué nuevos procesos está creando un proceso).

### FileMonitor

[**FileMonitor**](https://objective-see.com/products/utilities.html#FileMonitor) permite monitorear eventos de archivos (como creación, modificaciones y eliminaciones) proporcionando información detallada sobre dichos eventos.

### fs\_usage

Permite seguir las acciones realizadas por los procesos:
```bash
fs_usage -w -f filesys ls #This tracks filesystem actions of proccess names containing ls
fs_usage -w -f network curl #This tracks network actions
```
### TaskExplorer

[**Taskexplorer**](https://objective-see.com/products/taskexplorer.html) es útil para ver las **bibliotecas** utilizadas por un binario, los **archivos** que está utilizando y las **conexiones de red**.\
También verifica los procesos binarios en **virustotal** y muestra información sobre el binario.

### lldb

**lldb** es la herramienta de **hecho** para la **depuración** de binarios de **macOS**.
```bash
lldb ./malware.bin
lldb -p 1122
lldb -n malware.bin
lldb -n malware.bin --waitfor
```
| **Comando (lldb)**            | **Descripción**                                                                                                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **run (r)**                   | Inicia la ejecución, que continuará sin interrupción hasta que se alcance un punto de interrupción o el proceso termine.                                                                                                                                                                                                                                                                                                                     |
| **continue (c)**              | Continúa la ejecución del proceso depurado.                                                                                                                                                                                                                                                                                                                                                                               |
| **nexti (n / ni)**            | Ejecuta la siguiente instrucción. Este comando omitirá las llamadas a funciones.                                                                                                                                                                                                                                                                                                                                                 |
| **stepi (s / si)**            | Ejecuta la siguiente instrucción. A diferencia del comando nexti, este comando entrará en las llamadas a funciones.                                                                                                                                                                                                                                                                                                                       |
| **finish (f)**                | Ejecuta el resto de las instrucciones en la función actual ("frame"), devuelve y detiene.                                                                                                                                                                                                                                                                                                                                   |
| **control + c**               | Pausa la ejecución. Si el proceso se ha ejecutado (r) o continuado (c), esto hará que el proceso se detenga ... dondequiera que se esté ejecutando actualmente.                                                                                                                                                                                                                                                                             |
| **breakpoint (b)**            | <p>b main</p><p>b -[NSDictionary objectForKey:]</p><p>b 0x0000000100004bd9</p><p>br l #Lista de puntos de interrupción</p><p>br e/dis &#x3C;num> #Habilitar/Deshabilitar punto de interrupción</p><p>breakpoint delete &#x3C;num><br>b set -n main --shlib &#x3C;lib_name></p>                                                                                                                                                                               |
| **help**                      | <p>help breakpoint #Obtener ayuda del comando breakpoint</p><p>help memory write #Obtener ayuda para escribir en la memoria</p>                                                                                                                                                                                                                                                                                                         |
| **reg**                       | <p>reg read</p><p>reg read $rax</p><p>reg write $rip 0x100035cc0</p>                                                                                                                                                                                                                                                                                                                                                      |
| **x/s \<reg/memory address>** | Muestra la memoria como una cadena terminada en nulo.                                                                                                                                                                                                                                                                                                                                                                           |
| **x/i \<reg/memory address>** | Muestra la memoria como instrucción de ensamblador.                                                                                                                                                                                                                                                                                                                                                                               |
| **x/b \<reg/memory address>** | Muestra la memoria como byte.                                                                                                                                                                                                                                                                                                                                                                                               |
| **print object (po)**         | <p>Esto imprimirá el objeto referenciado por el parámetro</p><p>po $raw</p><p><code>{</code></p><p><code>dnsChanger = {</code></p><p><code>"affiliate" = "";</code></p><p><code>"blacklist_dns" = ();</code></p><p>Tenga en cuenta que la mayoría de las API o métodos Objective-C de Apple devuelven objetos y, por lo tanto, deben mostrarse mediante el comando "print object" (po). Si po no produce una salida significativa, use <code>x/b</code></p> |
| **memory**                    | <p>memory read 0x000....<br>memory read $x0+0xf2a<br>memory write 0x100600000 -s 4 0x41414141 #Escribir AAAA en esa dirección<br>memory write -f s $rip+0x11f+7 "AAAA" #Escribir AAAA en la dirección</p>                                                                                                                                                                                                                            |
| **disassembly**               | <p>dis #Desensambla la función actual<br>dis -c 6 #Desensambla 6 líneas<br>dis -c 0x100003764 -e 0x100003768 #Desde una dirección hasta la otra<br>dis -p -c 4 #Comienza en la dirección actual desensamblando</p>                                                                                                                                                                                                                                 |
| **parray**                    | parray 3 (char \*\*)$x1 # Verificar matriz de 3 componentes en el registro x1                                                                                                                                                                                                                                                                                                                                                           |

{% hint style="info" %}
Cuando se llama a la función **`objc_sendMsg`**, el registro **rsi** contiene el **nombre del método** como una cadena terminada en nulo ("C"). Para imprimir el nombre a través de lldb, haga lo siguiente:

`(lldb) x/s $rsi: 0x1000f1576: "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) print (char*)$rsi:`\
`(char *) $1 = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`

`(lldb) reg read $rsi: rsi = 0x00000001000f1576 "startMiningWithPort:password:coreCount:slowMemory:currency:"`
{% endhint %}

### Anti-Análisis Dinámico

#### Detección de VM

* El comando **`sysctl hw.model`** devuelve "Mac" cuando el **anfitrión es un MacOS**, pero algo diferente cuando es una VM.
* Jugando con los valores de **`hw.logicalcpu`** y **`hw.physicalcpu`**, algunos malwares intentan detectar si es una VM.
* Algunos malwares también pueden **detectar** si la máquina es **VMware** en función de la dirección MAC (00:50:56).
* También es posible encontrar **si un proceso está siendo depurado** con un código simple como:

  * `if(P_TRACED == (info.kp_proc.p_flag & P_TRACED)){ //proceso siendo depurado }`

* También puede invocar la llamada al sistema **`ptrace`** con la bandera **`PT_DENY_ATTACH`**. Esto **impide** que un depurador se adjunte y rastree.
  * Puede verificar si la función **`sysctl`** o **`ptrace`** está siendo **importada** (pero el malware podría importarla dinámicamente)
  * Como se señala en este artículo, “[Defeating Anti-Debug Techniques: macOS ptrace variants](https://alexomara.com/blog/defeating-anti-debug-techniques-macos-ptrace-variants/)” :\
    "_El mensaje Process # exited with **status = 45 (0x0000002d)** es generalmente una señal reveladora de que el objetivo de depuración está usando **PT\_DENY\_ATTACH**_"

## Fuzzing

### [ReportCrash](https://ss64.com/osx/reportcrash.html)

ReportCrash **analiza los procesos que se bloquean y guarda un informe de bloqueo en el disco**. Un informe de bloqueo contiene información que puede **ayudar a un desarrollador a diagnosticar** la causa de un bloqueo.\
Para aplicaciones y otros procesos **que se ejecutan en el contexto de lanzamiento por usuario**, ReportCrash se ejecuta como un LaunchAgent y guarda los informes de bloqueo en `~/Library/Logs/DiagnosticReports/` del usuario.\
Para demonios, otros procesos **que se ejecutan en el contexto de lanzamiento del sistema** y otros procesos privilegiados, ReportCrash se ejecuta como un LaunchDaemon y guarda los informes de bloqueo en `/Library/Logs/DiagnosticReports` del sistema.

Si le preocupa que los informes de bloqueo **se envíen a Apple**, puede desactivarlos. Si no, los informes de bloqueo pueden ser útiles para **averiguar cómo se bloqueó un servidor**.
```bash
#To disable crash reporting:
launchctl unload -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist

#To re-enable crash reporting:
launchctl load -w /System/Library/LaunchAgents/com.apple.ReportCrash.plist
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.ReportCrash.Root.plist
```
### Sleep

Mientras se realiza fuzzing en MacOS, es importante evitar que el equipo entre en modo de suspensión:

* systemsetup -setsleep Never
* pmset, Preferencias del Sistema
* [KeepingYouAwake](https://github.com/newmarcel/KeepingYouAwake)

#### Desconexión SSH

Si se está realizando fuzzing a través de una conexión SSH, es importante asegurarse de que la sesión no se desconecte. Para ello, se debe cambiar el archivo sshd\_config con:

* TCPKeepAlive Yes
* ClientAliveInterval 0
* ClientAliveCountMax 0
```bash
sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```
### Manejadores internos

[**Revisa esta sección**](../#file-extensions-apps) para descubrir cómo puedes encontrar qué aplicación es responsable de **manejar el esquema o protocolo especificado**.

### Enumerando procesos de red

Es interesante encontrar procesos que estén gestionando datos de red:
```bash
dtrace -n 'syscall::recv*:entry { printf("-> %s (pid=%d)", execname, pid); }' >> recv.log
#wait some time
sort -u recv.log > procs.txt
cat procs.txt
```
### Más información sobre Fuzzing en MacOS

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
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
