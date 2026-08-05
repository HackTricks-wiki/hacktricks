# macOS Kernel y extensiones del sistema

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

El **núcleo de macOS es XNU**, que significa "X is Not Unix". Este kernel está compuesto fundamentalmente por el **microkernel de Mach** (que se tratará más adelante) **y** elementos de Berkeley Software Distribution (**BSD**). XNU también proporciona una plataforma para **kernel drivers mediante un sistema llamado I/O Kit**. El kernel XNU forma parte del proyecto open source Darwin, lo que significa que **su código fuente es de libre acceso**.

Desde la perspectiva de un security researcher o un desarrollador Unix, **macOS** puede parecer bastante **similar** a un sistema **FreeBSD** con una GUI elegante y numerosas aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD compilarán y se ejecutarán en macOS sin necesidad de modificaciones, ya que todas las command-line tools conocidas por los usuarios de Unix están presentes en macOS. Sin embargo, como el kernel XNU incorpora Mach, existen algunas diferencias significativas entre un sistema tradicional tipo Unix y macOS, y estas diferencias pueden causar posibles problemas o proporcionar ventajas únicas.

Versión open source de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principios de diseño fundamentales era **minimizar** la cantidad de **código** ejecutándose en el espacio del **kernel** y permitir, en su lugar, que muchas funciones típicas del kernel, como el sistema de archivos, las redes y la E/S, se **ejecutaran como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que normalmente gestiona un kernel, como la planificación del procesador, la multitarea y la gestión de la memoria virtual.

### BSD

El **kernel** XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD, ya que fue necesario modificarlo para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, entre ellas:

- Gestión de procesos
- Gestión de señales
- Mecanismos básicos de seguridad, incluida la gestión de usuarios y grupos
- Infraestructura de system calls
- Stack TCP/IP y sockets
- Firewall y filtrado de paquetes

Comprender la interacción entre BSD y Mach puede ser complejo debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza los procesos como unidad fundamental de ejecución, mientras que Mach funciona basándose en threads. Esta discrepancia se resuelve en XNU **asociando cada proceso BSD con una tarea Mach** que contiene exactamente un thread Mach. Cuando se utiliza la system call fork() de BSD, el código BSD dentro del kernel utiliza funciones de Mach para crear una tarea y una estructura de thread.

Además, **Mach y BSD mantienen modelos de seguridad diferentes**: el modelo de seguridad de **Mach** se basa en **port rights**, mientras que el modelo de seguridad de BSD funciona basándose en la **propiedad de los procesos**. Las diferencias entre estos dos modelos han provocado ocasionalmente vulnerabilidades de local privilege escalation. Además de las system calls habituales, también existen **Mach traps que permiten a los programas en user space interactuar con el kernel**. Estos elementos diferentes forman conjuntamente la arquitectura multifacética e híbrida del kernel de macOS.

### I/O Kit - Drivers

I/O Kit es un **framework de device drivers** open source y orientado a objetos del kernel XNU que gestiona **device drivers cargados dinámicamente**. Permite añadir código modular al kernel sobre la marcha, dando soporte a hardware diverso.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocessors en la arquitectura de macOS

Las plataformas de Apple dependen de varios coprocessors para mantener el trabajo sensible a la latencia fuera de los cores principales y aislar las funciones críticas para la seguridad.

- **Secure Enclave Processor (SEP)**: Un core ARM dedicado con su propio microkernel y secure boot chain, que normalmente se ejecuta en **EL3/secure world**. La interacción se realiza mediante mailbox drivers en macOS en EL1.
- Superficie de ataque: actualizaciones del firmware del SEP y los daemons de user space (`seputil`, `securityd`) que actúan como proxy de las solicitudes.
- Impacto de un compromiso: filtrar long-term keys, evadir el bloqueo biométrico y romper las protecciones de FileVault o Apple Pay.
- **System Management Controller (SMC)**: Ejecuta firmware propietario en un microcontrolador fuera de los ARM exception levels. macOS (EL1) accede a él mediante user clients de I/O Kit.
- Superficie de ataque: mensajes de USB-C power delivery, interfaces de gestión de ventiladores/batería y rutas de actualización del firmware.
- Impacto de un compromiso: anular los límites térmicos, inyectar datos falsos de sensores, cortar la alimentación o implantar backdoors persistentes en NVRAM.
- **T1/T2 Security Chips**: Ejecutan bridgeOS (derivado de watchOS), principalmente en EL1/EL3, en sus propios cores ARM. macOS se comunica mediante canales similares a PCIe/USB gestionados por IOKit.
- Superficie de ataque: rutas de DFU/restore, endpoints IPC expuestos por servicios como `tccd` y media pipelines conectados al T2.
- Impacto de un compromiso: desactivar secure boot, descifrar el contenido del SSD, secuestrar el control de la cámara/micrófono o emular entradas HID para lograr persistencia sigilosa.
- **Display Coprocessor (DCP)**: Ejecuta firmware en EL1 dentro de un espacio de direcciones aislado protegido por DART (la IOMMU de Apple).
- Superficie de ataque: interfaces `DCPAVService`, shared descriptor buffers y análisis de imágenes de firmware.
- Impacto de un compromiso: inyectar frames arbitrarios, espiar framebuffers o inutilizar el display pipeline para provocar DoS.
- **Apple Neural Engine (ANE)**: Ejecuta microcode en un cluster ML dedicado (sin ARM EL levels). macOS planifica el trabajo mediante `ANECompilerService` e IOKit.
- Superficie de ataque: binarios de modelos compilados (`.ane`), APIs de Core ML que proporcionan custom kernels y firmware loaders.
- Impacto de un compromiso: manipular o exfiltrar modelos ML, filtrar datos procesados de audio/visión o sabotear la inferencia on-device.
- **AGX GPU**: El firmware se ejecuta en custom GPU cores con un scheduler; EL0 envía comandos Metal que EL1 valida.
- Superficie de ataque: compilador de shaders Metal, APIs de shared buffer mapping e interfaces ioctl `com.apple.AGXFirmware`.
- Impacto de un compromiso: acceso DMA a la memoria del sistema, escapes del sandbox mediante GPU drivers o implants persistentes en el firmware.
- **Apple Video Encoder (AVE)**: El firmware se ejecuta en el Media Engine dentro de un sandbox similar a EL1. macOS interactúa mediante VideoToolbox y `AppleAVE2`.
- Superficie de ataque: codec bitstreams, parameter sets, buffers proporcionados por el usuario y firmware update blobs.
- Impacto de un compromiso: filtrar frames sin comprimir, evadir DRM u obtener code execution con acceso a DMA engines.
- **Image Signal Processor (ISP)**: Ejecuta secure firmware en el cluster Media Engine; los drivers de cámara de macOS operan en EL1.
- Superficie de ataque: Camera HALs, descriptores de frames RAW, colas de configuración del ISP y actualizaciones del firmware.
- Impacto de un compromiso: capturar silenciosamente feeds RAW de la cámara, desactivar los indicadores de privacidad o inyectar imágenes falsificadas.
- **AMX Matrix cores**: Funcionan como unidades coprocessor expuestas en EL0/EL1 mediante nuevas instrucciones.
- Superficie de ataque: virtualización por parte del kernel del estado de AMX (`thread_set_state`, cambios de contexto) y generación de código en user space.
- Impacto de un compromiso: filtrar los registros de tiles de otros procesos, fingerprint workloads o escalar privilegios mediante corrupción de memoria del kernel.

El macOS moderno trata estos coprocessors como componentes de confianza dentro de la chain of trust. El firmware del SEP, SMC y T2 está firmado por Apple, y los protocolos de handshake (a menudo implementados mediante mailboxes o familias de I/O Kit) incluyen comprobaciones challenge-response para que solo el firmware autenticado pueda atender las solicitudes.

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS es **muy restrictivo al cargar Kernel Extensions** (.kext) debido a los altos privilegios con los que se ejecutará ese código. De hecho, por defecto es prácticamente imposible (a menos que se encuentre un bypass).

En la siguiente página también puedes ver cómo recuperar el `.kext` que macOS carga dentro de su **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

En lugar de utilizar Kernel Extensions, macOS creó las System Extensions, que ofrecen APIs a nivel de usuario para interactuar con el kernel. De esta forma, los desarrolladores pueden evitar utilizar kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes y RSR (Rapid Security Response)

- **Cryptex** significa **CRYPTographically-sealed EXtension**. Es una imagen de disco sellada (contenedor) que Apple utiliza para alojar partes del OS (frameworks, shared libraries, apps) que tienen más probabilidades de cambiar entre actualizaciones principales del OS.
- En macOS e iOS, los componentes ubicados dentro de cryptexes pueden ser **parcheados o reemplazados** mediante RSR sin volver a sellar todo el volumen del sistema.
- Los cryptexes residen en el volumen **Preboot**, junto al firmware de arranque, y se integran en el sistema de archivos del OS durante el runtime.
- La carga del contenido de un cryptex implica validación: el sistema comprueba los file seals, manifests y root hashes, y después monta o “integra” el contenido del cryptex para que, durante el runtime, las apps utilicen las versiones del cryptex cuando estén presentes.
- En los boot logs, la carga del cryptex ocurre después de la inicialización del kernel, pero antes de que los servicios completos del sistema estén activos.


#### Rapid Security Response (RSR)

- **RSR** es el mecanismo de Apple para distribuir **security patches entre actualizaciones normales del OS**. Su objetivo es el contenido de los cryptexes para actualizar componentes vulnerables (por ejemplo, libraries y frameworks) sin modificar el volumen central del sistema.
- Al aplicar una actualización RSR, el dispositivo solicita al signing server de Apple un manifest **Cryptex1 Image4**. Este manifest está vinculado criptográficamente al dispositivo y al nuevo contenido del cryptex.
- El AP boot ticket existente del sistema base **no se modifica** mediante RSR. El parche funciona de forma aditiva sobre el OS base sellado.
- En macOS, determinados componentes parcheados (por ejemplo, Safari) se activan en cuanto se relanza la app; no siempre es necesario reiniciar completamente el sistema.
- Los RSR son **removibles**: cada uno incluye un parche y un “antipatch” que puede volver a la versión del OS base. Al eliminarlo, el contenido del cryptex se revierte.
- Las actualizaciones RSR suelen ser mucho más pequeñas que las actualizaciones completas del OS y requieren un nivel de batería menor para instalarse.


## Referencias

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
