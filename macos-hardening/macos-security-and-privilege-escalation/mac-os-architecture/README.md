# Kernel de macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kernel XNU

El **núcleo de macOS es XNU**, que significa "X no es Unix". Este kernel está compuesto fundamentalmente por el **microkernel Mach** (que se discutirá más adelante), **y** elementos de Berkeley Software Distribution (**BSD**). XNU también proporciona una plataforma para **controladores de kernel a través de un sistema llamado I/O Kit**. El kernel XNU es parte del proyecto de código abierto Darwin, lo que significa que **su código fuente es libremente accesible**.

Desde la perspectiva de un investigador de seguridad o un desarrollador de Unix, **macOS** puede sentirse bastante **similar** a un sistema **FreeBSD** con una elegante GUI y una serie de aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se compilarán y ejecutarán en macOS sin necesidad de modificaciones, ya que las herramientas de línea de comandos familiares para los usuarios de Unix están presentes en macOS. Sin embargo, debido a que el kernel XNU incorpora Mach, hay algunas diferencias significativas entre un sistema similar a Unix tradicional y macOS, y estas diferencias pueden causar problemas potenciales o proporcionar ventajas únicas.

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principales principios de diseño fue **minimizar** la cantidad de **código** que se ejecuta en el **espacio del kernel** y, en su lugar, permitir que muchas funciones típicas del kernel, como el sistema de archivos, la red y la E/S, se **ejecuten como tareas de nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que un kernel maneja típicamente, como la planificación del procesador, la multitarea y la gestión de la memoria virtual.

### BSD

El **kernel** XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD porque se requirieron modificaciones para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, incluyendo:

* Gestión de procesos
* Manejo de señales
* Mecanismos básicos de seguridad, incluida la gestión de usuarios y grupos
* Infraestructura de llamadas al sistema
* Pila TCP/IP y sockets
* Firewall y filtrado de paquetes

Comprender la interacción entre BSD y Mach puede ser complejo, debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza procesos como su unidad de ejecución fundamental, mientras que Mach opera en función de hilos. Esta discrepancia se reconcilia en XNU **asociando cada proceso BSD con una tarea Mach** que contiene exactamente un hilo Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código de BSD dentro del kernel utiliza funciones de Mach para crear una tarea y una estructura de hilo.

Además, **Mach y BSD mantienen modelos de seguridad diferentes**: el modelo de seguridad de **Mach** se basa en **derechos de puerto**, mientras que el modelo de seguridad de BSD opera en función de la **propiedad del proceso**. Las disparidades entre estos dos modelos han dado lugar ocasionalmente a vulnerabilidades de escalada de privilegios locales. Además de las llamadas al sistema típicas, también hay **trampas de Mach que permiten que los programas de espacio de usuario interactúen con el kernel**. Estos diferentes elementos juntos forman la arquitectura multifacética y híbrida del kernel de macOS.

### I/O Kit - Controladores

I/O Kit es el marco de **controladores de dispositivos orientado a objetos** de código abierto en el kernel XNU y es responsable de la adición y gestión de **controladores de dispositivos cargados dinámicamente**. Estos controladores permiten que se agregue código modular al kernel de forma dinámica para su uso con diferentes hardware, por ejemplo. Se encuentran en:

* `/System/Library/Extensions`
  * Archivos KEXT integrados en el sistema operativo OS X.
* `/Library/Extensions`
  * Archivos KEXT instalados por software de terceros.
```bash
#Use kextstat to print the loaded drivers
kextstat
Executing: /usr/bin/kmutil showloaded
No variant specified, falling back to release
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
    1  142 0                  0          0          com.apple.kpi.bsd (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    2   11 0                  0          0          com.apple.kpi.dsep (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    3  170 0                  0          0          com.apple.kpi.iokit (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    4    0 0                  0          0          com.apple.kpi.kasan (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    5  175 0                  0          0          com.apple.kpi.libkern (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    6  154 0                  0          0          com.apple.kpi.mach (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    7   88 0                  0          0          com.apple.kpi.private (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    8  106 0                  0          0          com.apple.kpi.unsupported (20.5.0) 52A1E876-863E-38E3-AC80-09BBAB13B752 <>
    9    2 0xffffff8003317000 0xe000     0xe000     com.apple.kec.Libm (1) 6C1342CC-1D74-3D0F-BC43-97D5AD38200A <5>
   10   12 0xffffff8003544000 0x92000    0x92000    com.apple.kec.corecrypto (11.1) F5F1255F-6552-3CF4-A9DB-D60EFDEB4A9A <8 7 6 5 3 1>
```
Hasta el número 9, los controladores listados se **cargan en la dirección 0**. Esto significa que no son controladores reales, sino que son **parte del kernel y no se pueden descargar**.

Para encontrar extensiones específicas, puedes usar:
```bash
kextfind -bundle-id com.apple.iokit.IOReportFamily #Search by full bundle-id
kextfind -bundle-id -substring IOR #Search by substring in bundle-id
```
Para cargar y descargar extensiones de kernel, haz lo siguiente:
```bash
kextload com.apple.iokit.IOReportFamily
kextunload com.apple.iokit.IOReportFamily
```
### IPC - Comunicación Interprocesos

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

## Extensiones de Kernel de macOS

macOS es **muy restrictivo para cargar Extensiones de Kernel** (.kext) debido a los altos privilegios con los que se ejecutará el código. De hecho, por defecto es virtualmente imposible (a menos que se encuentre un bypass).

{% content-ref url="macos-kernel-extensions.md" %}
[macos-kernel-extensions.md](macos-kernel-extensions.md)
{% endcontent-ref %}

## Referencias

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
