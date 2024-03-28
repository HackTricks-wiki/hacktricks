# Arquitectura de macOS Kernel y Extensiones del Sistema

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

El **núcleo de macOS es XNU**, que significa "X is Not Unix". Este kernel está compuesto fundamentalmente por el **microkernel Mach** (que se discutirá más adelante), **y** elementos de la Distribución de Software de Berkeley (**BSD**). XNU también proporciona una plataforma para **controladores de kernel a través de un sistema llamado I/O Kit**. El kernel XNU es parte del proyecto de código abierto Darwin, lo que significa que **su código fuente es libremente accesible**.

Desde la perspectiva de un investigador de seguridad o un desarrollador de Unix, **macOS** puede sentirse bastante **similar** a un sistema **FreeBSD** con una interfaz gráfica elegante y una serie de aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se compilarán y ejecutarán en macOS sin necesidad de modificaciones, ya que las herramientas de línea de comandos familiares para los usuarios de Unix están presentes en macOS. Sin embargo, debido a que el kernel XNU incorpora Mach, existen algunas diferencias significativas entre un sistema similar a Unix tradicional y macOS, y estas diferencias podrían causar problemas potenciales o proporcionar ventajas únicas.

Versión de código abierto de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principios de diseño clave fue **minimizar** la cantidad de **código** que se ejecuta en el **espacio del kernel** y, en su lugar, permitir que muchas funciones típicas del kernel, como el sistema de archivos, la red y la E/S, se **ejecuten como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que típicamente maneja un kernel, como la programación de procesadores, el multitarea y la gestión de memoria virtual.

### BSD

El **kernel** XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD porque se requirieron modificaciones para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, incluyendo:

* Gestión de procesos
* Manejo de señales
* Mecanismos básicos de seguridad, incluida la gestión de usuarios y grupos
* Infraestructura de llamadas al sistema
* Pila TCP/IP y sockets
* Firewall y filtrado de paquetes

Comprender la interacción entre BSD y Mach puede ser complejo, debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza procesos como su unidad de ejecución fundamental, mientras que Mach opera en función de hilos. Esta discrepancia se reconcilia en XNU **asociando cada proceso BSD con una tarea Mach** que contiene exactamente un hilo Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código de BSD dentro del kernel utiliza funciones de Mach para crear una estructura de tarea y un hilo.

Además, **Mach y BSD mantienen modelos de seguridad diferentes**: el modelo de seguridad de **Mach** se basa en **derechos de puerto**, mientras que el modelo de seguridad de BSD opera en función de la **propiedad del proceso**. Las disparidades entre estos dos modelos a veces han dado lugar a vulnerabilidades de escalada de privilegios locales. Además de las llamadas al sistema típicas, también existen **trampas de Mach que permiten que los programas de espacio de usuario interactúen con el kernel**. Estos elementos diferentes juntos forman la arquitectura híbrida y multifacética del kernel de macOS.

### I/O Kit - Controladores

El I/O Kit es un marco de **controladores de dispositivos orientado a objetos de código abierto** en el kernel XNU, que maneja **controladores de dispositivos cargados dinámicamente**. Permite agregar código modular al kernel sobre la marcha, admitiendo hardware diverso.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicación entre Procesos

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

El **kernelcache** es una versión **precompilada y preenlazada del kernel XNU**, junto con controladores de dispositivos esenciales y extensiones de kernel. Se almacena en un formato **comprimido** y se descomprime en la memoria durante el proceso de arranque. El kernelcache facilita un **tiempo de arranque más rápido** al tener una versión lista para ejecutarse del kernel y controladores cruciales disponibles, reduciendo el tiempo y los recursos que de otro modo se gastarían en cargar y vincular dinámicamente estos componentes en el momento del arranque.

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** en macOS puedes encontrarlo con **`find / -name kernelcache 2>/dev/null`** o **`mdfind kernelcache | grep kernelcache`**

Es posible ejecutar **`kextstat`** para verificar las extensiones de kernel cargadas.

#### IMG4

El formato de archivo IMG4 es un formato de contenedor utilizado por Apple en sus dispositivos iOS y macOS para **almacenar y verificar de forma segura** componentes de firmware (como **kernelcache**). El formato IMG4 incluye un encabezado y varias etiquetas que encapsulan diferentes piezas de datos, incluida la carga útil real (como un kernel o cargador de arranque), una firma y un conjunto de propiedades de manifiesto. El formato admite verificación criptográfica, lo que permite al dispositivo confirmar la autenticidad e integridad del componente de firmware antes de ejecutarlo.

Generalmente está compuesto por los siguientes componentes:

* **Carga útil (IM4P)**:
* A menudo comprimido (LZFSE4, LZSS, …)
* Opcionalmente encriptado
* **Manifiesto (IM4M)**:
* Contiene Firma
* Diccionario adicional de Clave/Valor
* **Información de Restauración (IM4R)**:
* También conocido como APNonce
* Evita la repetición de algunas actualizaciones
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

Estos son **firmwares** de Apple que puedes descargar desde [**https://ipsw.me/**](https://ipsw.me/). Entre otros archivos, contendrá el **kernelcache**.\
Para **extraer** los archivos, simplemente puedes **descomprimirlo**.

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
Puedes verificar los símbolos extraídos del kernelcache con: **`nm -a kernelcache.release.iphone14.e | wc -l`**

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
## Extensiones de Kernel de macOS

macOS es **súper restrictivo para cargar Extensiones de Kernel** (.kext) debido a los altos privilegios con los que se ejecutará el código. De hecho, por defecto es virtualmente imposible (a menos que se encuentre un bypass).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensiones de Sistema de macOS

En lugar de utilizar Extensiones de Kernel, macOS creó las Extensiones de Sistema, que ofrecen APIs a nivel de usuario para interactuar con el kernel. De esta manera, los desarrolladores pueden evitar el uso de extensiones de kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
