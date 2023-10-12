# Kernel y Extensiones del Sistema en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

El **núcleo de macOS es XNU**, que significa "X is Not Unix" (X no es Unix). Este núcleo está compuesto fundamentalmente por el **microkernel Mach** (que se discutirá más adelante) y elementos de la **Distribución de Software Berkeley (BSD)**. XNU también proporciona una plataforma para **controladores de kernel a través de un sistema llamado I/O Kit**. El núcleo XNU forma parte del proyecto de código abierto Darwin, lo que significa que **su código fuente es de libre acceso**.

Desde la perspectiva de un investigador de seguridad o un desarrollador de Unix, **macOS** puede parecer bastante **similar** a un sistema **FreeBSD** con una interfaz gráfica elegante y una serie de aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se pueden compilar y ejecutar en macOS sin necesidad de modificaciones, ya que las herramientas de línea de comandos familiares para los usuarios de Unix están presentes en macOS. Sin embargo, debido a que el núcleo XNU incorpora Mach, existen algunas diferencias significativas entre un sistema similar a Unix tradicional y macOS, y estas diferencias pueden causar problemas potenciales o proporcionar ventajas únicas.

Versión de código abierto de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principales principios de diseño fue **minimizar** la cantidad de **código** que se ejecuta en el **espacio del kernel** y, en su lugar, permitir que muchas funciones típicas del kernel, como el sistema de archivos, la red y la E/S, se **ejecuten como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que normalmente maneja un kernel, como la programación de procesadores, la multitarea y la gestión de memoria virtual.

### BSD

El núcleo XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código se **ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD debido a que se requirieron modificaciones para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, incluyendo:

* Gestión de procesos
* Manejo de señales
* Mecanismos básicos de seguridad, incluida la gestión de usuarios y grupos
* Infraestructura de llamadas al sistema
* Pila TCP/IP y sockets
* Firewall y filtrado de paquetes

Comprender la interacción entre BSD y Mach puede ser complejo debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza procesos como su unidad fundamental de ejecución, mientras que Mach opera en función de hilos. Esta discrepancia se reconcilia en XNU mediante **la asociación de cada proceso BSD con una tarea Mach** que contiene exactamente un hilo Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código de BSD dentro del kernel utiliza funciones de Mach para crear una tarea y una estructura de hilo.

Además, **Mach y BSD mantienen modelos de seguridad diferentes**: el modelo de seguridad de Mach se basa en **derechos de puerto**, mientras que el modelo de seguridad de BSD opera en función de la **propiedad del proceso**. Las disparidades entre estos dos modelos ocasionalmente han dado lugar a vulnerabilidades de escalada de privilegios locales. Además de las llamadas al sistema típicas, también existen **trampas de Mach que permiten que los programas en el espacio de usuario interactúen con el kernel**. Estos diferentes elementos juntos forman la arquitectura híbrida y multifacética del núcleo de macOS.

### I/O Kit - Controladores

I/O Kit es el marco de **controladores de dispositivos orientado a objetos** de código abierto en el núcleo XNU y es responsable de la adición y gestión de **controladores de dispositivos cargados dinámicamente**. Estos controladores permiten agregar código modular al kernel de forma dinámica para su uso con diferentes hardware, por ejemplo.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicación entre Procesos

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

El **kernelcache** es una versión **precompilada y preenlazada del núcleo XNU**, junto con controladores de dispositivos esenciales y extensiones del kernel. Se almacena en un formato **comprimido** y se descomprime en la memoria durante el proceso de inicio. El kernelcache facilita un **inicio más rápido** al tener una versión lista para ejecutarse del kernel y controladores importantes disponibles, lo que reduce el tiempo y los recursos que de otro modo se gastarían en cargar y enlazar dinámicamente estos componentes durante el inicio.

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** y en macOS se puede encontrar con **`find / -name kernelcache 2>/dev/null`**.
#### IMG4

El formato de archivo IMG4 es un formato de contenedor utilizado por Apple en sus dispositivos iOS y macOS para almacenar y verificar de manera segura los componentes del firmware (como el kernelcache). El formato IMG4 incluye un encabezado y varias etiquetas que encapsulan diferentes piezas de datos, incluyendo la carga útil real (como un kernel o un cargador de arranque), una firma y un conjunto de propiedades de manifiesto. El formato admite la verificación criptográfica, lo que permite al dispositivo confirmar la autenticidad e integridad del componente del firmware antes de ejecutarlo.

Por lo general, está compuesto por los siguientes componentes:

* **Carga útil (IM4P)**:
* A menudo comprimido (LZFSE4, LZSS, ...)
* Opcionalmente encriptado
* **Manifiesto (IM4M)**:
* Contiene la firma
* Diccionario adicional de clave/valor
* **Información de restauración (IM4R)**:
* También conocido como APNonce
* Evita la reproducción de algunas actualizaciones
* OPCIONAL: Por lo general, esto no se encuentra

Descomprimir el Kernelcache:
```bash
# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# img4tool (https://github.com/tihmstar/img4tool
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
#### Símbolos del Kernelcache

A veces Apple lanza **kernelcache** con **símbolos**. Puedes descargar algunos firmwares con símbolos siguiendo los enlaces en [https://theapplewiki.com](https://theapplewiki.com/).

### IPSW

Estos son los **firmwares** de Apple que puedes descargar desde [**https://ipsw.me/**](https://ipsw.me/). Entre otros archivos, contendrá el **kernelcache**.\
Para **extraer** los archivos, simplemente descomprímelo.

Después de extraer el firmware, obtendrás un archivo como: **`kernelcache.release.iphone14`**. Está en formato **IMG4**, puedes extraer la información interesante con:

* [**pyimg4**](https://github.com/m1stadev/PyIMG4)

{% code overflow="wrap" %}
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
{% endcode %}

* [**img4tool**](https://github.com/tihmstar/img4tool)
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
Puedes verificar los símbolos del kernelcache extraído con: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Con esto ahora podemos **extraer todas las extensiones** o la **que te interese:**
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## Extensiones del kernel de macOS

macOS es **muy restrictivo para cargar extensiones del kernel** (.kext) debido a los altos privilegios con los que se ejecutará el código. De hecho, por defecto es prácticamente imposible (a menos que se encuentre un bypass).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensiones del sistema de macOS

En lugar de utilizar extensiones del kernel, macOS creó las extensiones del sistema, que ofrecen API de nivel de usuario para interactuar con el kernel. De esta manera, los desarrolladores pueden evitar el uso de extensiones del kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
