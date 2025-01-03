# Kernel de macOS y Extensiones del Sistema

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

El **núcleo de macOS es XNU**, que significa "X no es Unix". Este núcleo está fundamentalmente compuesto por el **microkernel Mach** (que se discutirá más adelante) **y** elementos de Berkeley Software Distribution (**BSD**). XNU también proporciona una plataforma para **controladores de núcleo a través de un sistema llamado I/O Kit**. El núcleo XNU es parte del proyecto de código abierto Darwin, lo que significa que **su código fuente es accesible de forma gratuita**.

Desde la perspectiva de un investigador de seguridad o un desarrollador de Unix, **macOS** puede parecer bastante **similar** a un sistema **FreeBSD** con una GUI elegante y una serie de aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se compilarán y ejecutarán en macOS sin necesidad de modificaciones, ya que las herramientas de línea de comandos familiares para los usuarios de Unix están presentes en macOS. Sin embargo, debido a que el núcleo XNU incorpora Mach, hay algunas diferencias significativas entre un sistema tradicional similar a Unix y macOS, y estas diferencias pueden causar problemas potenciales o proporcionar ventajas únicas.

Versión de código abierto de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principios de diseño clave fue **minimizar** la cantidad de **código** que se ejecuta en el **espacio del núcleo** y, en su lugar, permitir que muchas funciones típicas del núcleo, como el sistema de archivos, la red y la E/S, **se ejecuten como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que un núcleo maneja típicamente, como la programación de procesadores, la multitarea y la gestión de memoria virtual.

### BSD

El **núcleo** XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del núcleo junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD porque se requirieron modificaciones para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del núcleo, incluyendo:

- Gestión de procesos
- Manejo de señales
- Mecanismos de seguridad básicos, incluyendo gestión de usuarios y grupos
- Infraestructura de llamadas al sistema
- Pila TCP/IP y sockets
- Cortafuegos y filtrado de paquetes

Entender la interacción entre BSD y Mach puede ser complejo, debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza procesos como su unidad fundamental de ejecución, mientras que Mach opera en función de hilos. Esta discrepancia se reconcilia en XNU **asociando cada proceso BSD con una tarea Mach** que contiene exactamente un hilo Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código BSD dentro del núcleo utiliza funciones Mach para crear una tarea y una estructura de hilo.

Además, **Mach y BSD mantienen diferentes modelos de seguridad**: el modelo de seguridad de **Mach** se basa en **derechos de puerto**, mientras que el modelo de seguridad de BSD opera en función de **la propiedad del proceso**. Las disparidades entre estos dos modelos han resultado ocasionalmente en vulnerabilidades de escalada de privilegios locales. Aparte de las llamadas al sistema típicas, también hay **trampas Mach que permiten a los programas en espacio de usuario interactuar con el núcleo**. Estos diferentes elementos juntos forman la arquitectura híbrida y multifacética del núcleo de macOS.

### I/O Kit - Controladores

El I/O Kit es un marco de **controladores de dispositivos** orientado a objetos y de código abierto en el núcleo XNU, que maneja **controladores de dispositivos cargados dinámicamente**. Permite que se agregue código modular al núcleo sobre la marcha, soportando hardware diverso.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Comunicación entre Procesos

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Extensiones del Núcleo de macOS

macOS es **super restrictivo para cargar Extensiones del Núcleo** (.kext) debido a los altos privilegios con los que se ejecutará el código. De hecho, por defecto es prácticamente imposible (a menos que se encuentre un bypass).

En la siguiente página también puedes ver cómo recuperar el `.kext` que macOS carga dentro de su **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### Extensiones del Sistema de macOS

En lugar de usar Extensiones del Núcleo, macOS creó las Extensiones del Sistema, que ofrecen APIs a nivel de usuario para interactuar con el núcleo. De esta manera, los desarrolladores pueden evitar usar extensiones del núcleo.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## Referencias

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
