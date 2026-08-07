# Kernel y extensiones del sistema de macOS

{{#include ../../../banners/hacktricks-training.md}}

## Kernel XNU

El **núcleo de macOS es XNU**, siglas de "X is Not Unix". Este kernel está compuesto fundamentalmente por el **microkernel Mach** (que se tratará más adelante) **y** elementos de Berkeley Software Distribution (**BSD**). XNU también proporciona una plataforma para **controladores del kernel mediante un sistema llamado I/O Kit**. El kernel XNU forma parte del proyecto de código abierto Darwin, lo que significa que **su código fuente está disponible libremente**.

Desde la perspectiva de un investigador de seguridad o un desarrollador de Unix, **macOS** puede parecer bastante **similar** a un sistema **FreeBSD** con una GUI elegante y numerosas aplicaciones personalizadas. La mayoría de las aplicaciones desarrolladas para BSD se compilan y ejecutan en macOS sin necesidad de modificaciones, ya que todas las herramientas de línea de comandos conocidas por los usuarios de Unix están presentes en macOS. Sin embargo, dado que el kernel XNU incorpora Mach, existen algunas diferencias importantes entre un sistema tradicional tipo Unix y macOS, y estas diferencias pueden causar posibles problemas o proporcionar ventajas únicas.

Versión de código abierto de XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach es un **microkernel** diseñado para ser **compatible con UNIX**. Uno de sus principios de diseño fundamentales era **minimizar** la cantidad de **código** que se ejecuta en el espacio del **kernel** y, en su lugar, permitir que muchas funciones habituales del kernel, como el sistema de archivos, las redes y la E/S, se **ejecuten como tareas a nivel de usuario**.

En XNU, Mach es **responsable de muchas de las operaciones críticas de bajo nivel** que normalmente gestiona un kernel, como la planificación del procesador, la multitarea y la gestión de la memoria virtual.

### BSD

El **kernel** XNU también **incorpora** una cantidad significativa de código derivado del proyecto **FreeBSD**. Este código **se ejecuta como parte del kernel junto con Mach**, en el mismo espacio de direcciones. Sin embargo, el código de FreeBSD dentro de XNU puede diferir sustancialmente del código original de FreeBSD, ya que fue necesario modificarlo para garantizar su compatibilidad con Mach. FreeBSD contribuye a muchas operaciones del kernel, entre ellas:

- Gestión de procesos
- Gestión de señales
- Mecanismos básicos de seguridad, incluida la gestión de usuarios y grupos
- Infraestructura de llamadas al sistema
- Pila TCP/IP y sockets
- Firewall y filtrado de paquetes

Comprender la interacción entre BSD y Mach puede ser complejo debido a sus diferentes marcos conceptuales. Por ejemplo, BSD utiliza los procesos como su unidad fundamental de ejecución, mientras que Mach funciona basándose en threads. Esta discrepancia se reconcilia en XNU **asociando cada proceso de BSD con una tarea de Mach** que contiene exactamente un thread de Mach. Cuando se utiliza la llamada al sistema fork() de BSD, el código de BSD dentro del kernel emplea funciones de Mach para crear una tarea y una estructura de thread.

Además, **Mach y BSD mantienen modelos de seguridad diferentes**: el modelo de seguridad de **Mach** se basa en **port rights**, mientras que el modelo de seguridad de BSD funciona basándose en la **propiedad de los procesos**. Las disparidades entre estos dos modelos han provocado ocasionalmente vulnerabilidades de escalada de privilegios local. Además de las llamadas al sistema habituales, también existen **Mach traps que permiten a los programas en el espacio de usuario interactuar con el kernel**. Estos elementos forman conjuntamente la arquitectura híbrida y multifacética del kernel de macOS.<sup>[[1]](#references)</sup>

### I/O Kit - Drivers

I/O Kit es un **framework de controladores de dispositivos** de código abierto y orientado a objetos dentro del kernel XNU, que gestiona **controladores de dispositivos cargados dinámicamente**. Permite añadir código modular al kernel sobre la marcha y proporciona compatibilidad con diversos dispositivos.


{{#ref}}
macos-iokit.md
{{#endref}}

### Coprocesadores en la arquitectura de macOS

Las plataformas de Apple dependen de varios coprocesadores para mantener el trabajo sensible a la latencia fuera de los cores principales y aislar las funciones críticas para la seguridad.

- **Secure Enclave Processor (SEP)**: Un core ARM dedicado con su propio microkernel y cadena de secure boot, que normalmente se ejecuta en **EL3/secure world**. La interacción se realiza mediante drivers de mailbox en macOS en EL1.
- Superficie de ataque: actualizaciones del firmware del SEP y los daemons en el espacio de usuario (`seputil`, `securityd`) que actúan como proxy para las solicitudes.
- Impacto de un compromiso: hacer leak de claves a largo plazo, evadir el control biométrico y vulnerar las protecciones de FileVault o Apple Pay.
- **System Management Controller (SMC)**: Ejecuta firmware propietario en un microcontrolador fuera de los niveles de excepción ARM. macOS (EL1) accede a él mediante user clients de I/O Kit.
- Superficie de ataque: mensajes de suministro de energía USB-C, interfaces de gestión de ventiladores y batería, y rutas de actualización del firmware.
- Impacto de un compromiso: anular los límites térmicos, inyectar datos falsos de sensores, cortar la alimentación o implantar backdoors persistentes en NVRAM.
- **T1/T2 Security Chips**: Ejecutan bridgeOS (derivado de watchOS), principalmente en EL1/EL3, en sus propios cores ARM. macOS se comunica mediante canales similares a PCIe/USB mediados por IOKit.
- Superficie de ataque: rutas de DFU/restauración, endpoints de IPC expuestos por servicios como `tccd` y pipelines multimedia conectados al T2.
- Impacto de un compromiso: desactivar secure boot, descifrar el contenido del SSD, secuestrar el control de la cámara o el micrófono, o emular entradas HID para lograr persistencia sigilosa.
- **Display Coprocessor (DCP)**: Ejecuta firmware en EL1 dentro de un espacio de direcciones aislado protegido por DART (el IOMMU de Apple).
- Superficie de ataque: interfaces `DCPAVService`, buffers de descriptores compartidos y análisis de imágenes de firmware.
- Impacto de un compromiso: inyectar frames arbitrarios, espiar framebuffers o inutilizar el pipeline de pantalla para provocar un DoS.
- **Apple Neural Engine (ANE)**: Ejecuta microcode en un cluster ML dedicado (sin niveles EL de ARM). macOS planifica el trabajo mediante `ANECompilerService` e IOKit.
- Superficie de ataque: binarios de modelos compilados (`.ane`), APIs de Core ML que proporcionan kernels personalizados y cargadores de firmware.
- Impacto de un compromiso: manipular o exfiltrar modelos ML, hacer leak de datos de audio o visión procesados, o sabotear la inferencia en el dispositivo.
- **AGX GPU**: El firmware se ejecuta en cores GPU personalizados con un scheduler; EL0 envía comandos Metal que EL1 valida.
- Superficie de ataque: compilador de shaders Metal, APIs de mapeo de buffers compartidos e interfaces ioctl de `com.apple.AGXFirmware`.
- Impacto de un compromiso: obtener acceso DMA a la memoria del sistema, escapar del sandbox mediante los drivers de GPU o implantar firmware persistente.
- **Apple Video Encoder (AVE)**: El firmware se ejecuta en el Media Engine dentro de un sandbox similar a EL1. macOS interactúa mediante VideoToolbox y `AppleAVE2`.
- Superficie de ataque: bitstreams de códecs, conjuntos de parámetros, buffers proporcionados por el usuario y blobs de actualización del firmware.
- Impacto de un compromiso: hacer leak de frames sin comprimir, evadir DRM u obtener ejecución de código con acceso a motores DMA.
- **Image Signal Processor (ISP)**: Ejecuta firmware seguro en el cluster Media Engine; los drivers de cámara de macOS funcionan en EL1.
- Superficie de ataque: HALs de cámara, descriptores de frames RAW, colas de configuración del ISP y actualizaciones del firmware.
- Impacto de un compromiso: capturar en secreto las transmisiones RAW de la cámara, desactivar los indicadores de privacidad o inyectar imágenes falsificadas.
- **AMX Matrix cores**: Funcionan como unidades coprocesadoras expuestas en EL0/EL1 mediante nuevas instrucciones.
- Superficie de ataque: virtualización por parte del kernel del estado de AMX (`thread_set_state`, cambios de contexto) y generación de código en el espacio de usuario.
- Impacto de un compromiso: hacer leak de los registros de tiles de otros procesos, fingerprinting de workloads o escalar privilegios mediante corrupción de memoria del kernel.

El macOS moderno trata estos coprocesadores como componentes de confianza dentro de la cadena de confianza. El firmware del SEP, SMC y T2 está firmado por Apple, y los protocolos de handshake (implementados a menudo mediante mailboxes o familias de I/O Kit) incluyen comprobaciones challenge-response para que solo el firmware autenticado pueda atender solicitudes.

### IPC - Comunicación entre procesos

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## Kernel Extensions de macOS

macOS es **muy restrictivo a la hora de cargar Kernel Extensions** (.kext) debido a los elevados privilegios con los que se ejecuta ese código. De hecho, de forma predeterminada es prácticamente imposible (a menos que se encuentre un bypass).

En la siguiente página también puedes ver cómo recuperar el `.kext` que macOS carga dentro de su **kernelcache**:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### System Extensions de macOS

En lugar de utilizar Kernel Extensions, macOS creó las System Extensions, que ofrecen APIs a nivel de usuario para interactuar con el kernel. De esta forma, los desarrolladores pueden evitar utilizar kernel extensions.

{{#ref}}
macos-system-extensions.md
{{#endref}}


### Cryptexes y RSR (Rapid Security Response)

- **Cryptex** significa **CRYPTographically-sealed EXtension**. Es una imagen de disco sellada (contenedor) que Apple utiliza para alojar partes del sistema operativo (frameworks, shared libraries, apps) que tienen más probabilidades de cambiar entre actualizaciones principales del sistema operativo.
- En macOS e iOS, los componentes colocados dentro de cryptexes pueden ser **parcheados o reemplazados** mediante RSR sin volver a sellar todo el volumen del sistema.
- Los cryptexes residen en el volumen **Preboot**, junto al firmware de arranque, y se integran en el sistema de archivos del sistema operativo durante el runtime.
- La carga del contenido de un cryptex implica una validación: el sistema comprueba los sellos de los archivos, los manifests y los hashes raíz, y después monta o “integra” el contenido del cryptex para que, durante el runtime, las apps utilicen las versiones del cryptex cuando estén presentes.
- En los logs de arranque, la carga de cryptex ocurre después de la inicialización del kernel, pero antes de que todos los servicios del sistema estén activos.


#### Rapid Security Response (RSR)

- **RSR** es el mecanismo de Apple para distribuir **security patches entre actualizaciones normales del sistema operativo**. Se dirige al contenido de los cryptexes para actualizar partes vulnerables (por ejemplo, libraries y frameworks) sin modificar el volumen central del sistema.
- Al aplicar una actualización RSR, el dispositivo solicita al servidor de firma de Apple un **manifest Cryptex1 Image4**. Este manifest está vinculado criptográficamente al dispositivo y al nuevo contenido del cryptex.
- El AP boot ticket existente del sistema base **no se modifica** mediante RSR. El parche funciona de forma aditiva sobre el sistema operativo base sellado.
- En macOS, ciertos componentes parcheados (por ejemplo, Safari) se activan en cuanto se vuelve a abrir la app; no siempre es necesario reiniciar completamente el sistema.
- Las RSR son **removibles**: cada una incluye un parche y un “antiparche” que puede volver a la versión del sistema operativo base. Al eliminarla, el contenido del cryptex se revierte.
- Las actualizaciones RSR suelen ser mucho más pequeñas que las actualizaciones completas del sistema operativo y requieren un nivel de batería inferior para instalarse.


## Referencias

- [1] [The Mac Hacker's Handbook](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [2] [The Art of Mac Malware, Vol. 1 — Analysis](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
