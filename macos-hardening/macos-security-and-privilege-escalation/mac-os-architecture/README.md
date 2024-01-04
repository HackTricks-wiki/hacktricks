# Kernel y Extensiones del Sistema de macOS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

El **núcleo de macOS es XNU**, que significa "X no es Unix". Este kernel está compuesto fundamentalmente por el **microkernel Mach** (que se discutirá más adelante), **y** elementos del Berkeley Software Distribution (**BSD**). XNU también proporciona una plataforma para **drivers del kernel a través de un sistema llamado I/O Kit**. El kernel XNU es parte del proyecto de código abierto Darwin, lo que significa que **su código fuente es libremente accesible**.

Desde la perspectiva de un investigador de seguridad o un desarrollador Unix, **macOS** puede parecer bastante **similar** a un sistema **FreeBSD** con una GUI elegante y un conjunto de aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se compilarán y ejecutarán en macOS sin necesidad de modificaciones, ya que las herramientas de línea de comandos familiares para los usuarios de Unix están presentes en macOS. Sin embargo, debido a que el kernel XNU incorpora Mach, hay algunas diferencias significativas entre un sistema tradicional similar a Unix y macOS, y estas diferencias podrían causar problemas potenciales o proporcionar ventajas únicas.

Versión de código abierto de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principios de diseño clave fue **minimizar** la cantidad de **código** que se ejecuta en el espacio del **kernel** y permitir que muchas funciones típicas del kernel, como el sistema de archivos, la red y el I/O, **se ejecuten como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones de bajo nivel críticas** que un kernel típicamente maneja, como la programación de procesadores, la multitarea y la gestión de la memoria virtual.

### BSD

El **kernel XNU** también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD porque se requirieron modificaciones para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, incluyendo:

* Gestión de procesos
* Manejo de señales
* Mecanismos de seguridad básicos, incluyendo la gestión de usuarios y grupos
* Infraestructura de llamadas al sistema
* Pila TCP/IP y sockets
* Firewall y filtrado de paquetes

Entender la interacción entre BSD y Mach puede ser complejo, debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza procesos como su unidad fundamental de ejecución, mientras que Mach opera en base a hilos. Esta discrepancia se reconcilia en XNU **asociando cada proceso BSD con una tarea Mach** que contiene exactamente un hilo Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código de BSD dentro del kernel utiliza funciones de Mach para crear una tarea y una estructura de hilo.

Además, **Mach y BSD mantienen diferentes modelos de seguridad**: el modelo de seguridad de **Mach** se basa en **derechos de puerto**, mientras que el modelo de seguridad de BSD opera en base a **propiedad de procesos**. Las disparidades entre estos dos modelos han ocasionalmente resultado en vulnerabilidades de escalada de privilegios locales. Aparte de las llamadas al sistema típicas, también hay **trampas Mach que permiten a los programas de espacio de usuario interactuar con el kernel**. Estos diferentes elementos juntos forman la arquitectura híbrida y multifacética del kernel de macOS.

### I/O Kit - Drivers

I/O Kit es el marco de **drivers de dispositivos**, orientado a objetos y de código abierto en el kernel XNU y es responsable de la adición y gestión de **drivers de dispositivos cargados dinámicamente**. Estos drivers permiten que el código modular se agregue dinámicamente al kernel para su uso con diferentes hardware, por ejemplo.

{% content-ref url="macos-iokit.md" %}
[macos-iokit.md](macos-iokit.md)
{% endcontent-ref %}

### IPC - Comunicación Entre Procesos

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kernelcache

El **kernelcache** es una **versión precompilada y preenlazada del kernel XNU**, junto con **drivers** esenciales y **extensiones del kernel**. Se almacena en un formato **comprimido** y se descomprime en la memoria durante el proceso de arranque. El kernelcache facilita un **tiempo de arranque más rápido** al tener una versión lista para ejecutar del kernel y drivers cruciales disponibles, reduciendo el tiempo y los recursos que de otro modo se gastarían en cargar y enlazar dinámicamente estos componentes en el momento del arranque.

En iOS se encuentra en **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** en macOS puedes encontrarlo con **`find / -name kernelcache 2>/dev/null`**

#### IMG4

El formato de archivo IMG4 es un formato contenedor utilizado por Apple en sus dispositivos iOS y macOS para **almacenar y verificar de forma segura los componentes del firmware** (como **kernelcache**). El formato IMG4 incluye un encabezado y varias etiquetas que encapsulan diferentes piezas de datos, incluyendo la carga útil real (como un kernel o bootloader), una firma y un conjunto de propiedades del manifiesto. El formato admite verificación criptográfica, permitiendo al dispositivo confirmar la autenticidad e integridad del componente del firmware antes de ejecutarlo.

Generalmente está compuesto por los siguientes componentes:

* **Carga útil (IM4P)**:
* A menudo comprimida (LZFSE4, LZSS, …)
* Opcionalmente encriptada
* **Manifiesto (IM4M)**:
* Contiene Firma
* Diccionario adicional de Clave/Valor
* **Información de Restauración (IM4R)**:
* También conocido como APNonce
* Previene la repetición de algunas actualizaciones
* OPCIONAL: Generalmente esto no se encuentra

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
Para **extraer** los archivos puedes simplemente **descomprimir**.

Después de extraer el firmware obtendrás un archivo como: **`kernelcache.release.iphone14`**. Está en formato **IMG4**, puedes extraer la información interesante con:

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
Puedes verificar el kernelcache extraído para símbolos con: **`nm -a kernelcache.release.iphone14.e | wc -l`**

Con esto ahora podemos **extraer todas las extensiones** o **la que te interese:**
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
## Extensiones del Kernel de macOS

macOS es **sumamente restrictivo para cargar Extensiones del Kernel** (.kext) debido a los altos privilegios con los que se ejecutará el código. De hecho, por defecto es prácticamente imposible (a menos que se encuentre un bypass).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

### Extensiones del Sistema macOS

En lugar de usar Extensiones del Kernel, macOS creó las Extensiones del Sistema, que ofrecen APIs a nivel de usuario para interactuar con el kernel. De esta manera, los desarrolladores pueden evitar usar extensiones del kernel.

{% content-ref url="macos-system-extensions.md" %}
[macos-system-extensions.md](macos-system-extensions.md)
{% endcontent-ref %}

## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
