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


El firmware es un software esencial que permite que los dispositivos funcionen correctamente gestionando y facilitando la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, asegurando que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que conduce al arranque del sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recopilación de información**

**Recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Especificaciones del bootloader
- Disposición del hardware y datasheets
- Métricas del codebase y ubicaciones del source
- Bibliotecas externas y tipos de licencia
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **open-source intelligence (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software open-source disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuitos que se pueden aprovechar para encontrar problemas potenciales.

## **Adquisición del firmware**

Obtener firmware se puede abordar por diversas vías, cada una con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Construyéndolo** a partir de instrucciones proporcionadas
- **Descargando** desde sitios de soporte oficiales
- Utilizando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** mediante técnicas man-in-the-middle
- **Extrayendo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de actualización dentro de la comunicación del dispositivo
- Identificar y usar endpoints de actualización **hardcoded**
- **Dumping** desde el bootloader o la red
- **Extraer y leer** el chip de almacenamiento, cuando todo lo demás falla, usando las herramientas hardware apropiadas

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
Si no encuentras mucho con esas herramientas, verifica la **entropía** de la imagen con `binwalk -E <bin>`; si la entropía es baja, probablemente no esté cifrada. Si es alta, probablemente esté cifrada (o comprimida de alguna forma).

Además, puedes usar estas herramientas para extraer **archivos embebidos dentro del firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtener el sistema de archivos

Con las herramientas comentadas anteriormente como `binwalk -ev <bin>` deberías haber podido **extraer el sistema de archivos**.\
Binwalk normalmente lo extrae dentro de una **carpeta nombrada según el tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá el magic byte del sistema de archivos en sus firmas**. En esos casos, usa binwalk para **encontrar el offset del sistema de archivos y carve el sistema de archivos comprimido** del binario y **extraer manualmente** el sistema de archivos según su tipo usando los pasos abajo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente **dd command** para extraer (carving) el sistema de archivos Squashfs.
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

Los archivos estarán en el directorio `squashfs-root` después.

- Para archivos CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizando Firmware

Una vez obtenido el firmware, es esencial diseccionarlo para entender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis iniciales

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer strings, analizar datos binarios y comprender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se verifica la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere ausencia de cifrado, mientras que una entropía alta indica posible cifrado o compresión.

Para extraer **embedded files**, se recomiendan herramientas y recursos como la documentación **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extracción del filesystem

Usando `binwalk -ev <bin>`, normalmente se puede extraer el filesystem, a menudo en un directorio nombrado según el tipo de filesystem (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de filesystem debido a la ausencia de magic bytes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el offset del filesystem, seguido del comando `dd` para extraer el filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, dependiendo del tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan diferentes comandos para extraer manualmente el contenido.

### Filesystem Analysis

Con el sistema de archivos extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a daemons de red inseguros, credenciales hardcoded, endpoints de API, funcionalidades del servidor de actualizaciones, código sin compilar, scripts de inicio y binarios compilados para análisis dinámico u offline.

**Ubicaciones clave** y **elementos** a inspeccionar incluyen:

- **etc/shadow** and **etc/passwd** para credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de vulnerabilidades potenciales
- Binarios embebidos para análisis adicional
- Servidores web y binarios comunes en dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para la búsqueda de información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análisis integral de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Security Checks on Compiled Binaries

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben ser escrutados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protecciones que podrían explotarse.

## Emulating Firmware for Dynamic Analysis

El proceso de emular firmware permite el **análisis dinámico** ya sea del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede encontrar desafíos debido a dependencias de hardware o arquitectura, pero transferir el root filesystem o binarios específicos a un dispositivo con arquitectura y endianness coincidentes, como una Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, es crucial identificar la endianness y la arquitectura CPU del programa.

#### Example with MIPS Architecture

Para emular un binario de arquitectura MIPS, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), se utiliza `qemu-mips`, y para binarios little-endian, la elección sería `qemu-mipsel`.

#### ARM Architecture Emulation

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Full System Emulation

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), y otras, facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Dynamic Analysis in Practice

En esta etapa se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso a shell del OS y al sistema de ficheros. La emulación puede no reproducir perfectamente las interacciones con el hardware, lo que requerirá reinicios ocasionales de la emulación. El análisis debe revisar el sistema de ficheros, explotar páginas web y servicios de red expuestos, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles puertas traseras.

## Runtime Analysis Techniques

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno de ejecución, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

## Binary Exploitation and Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere un profundo conocimiento de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones en tiempo de ejecución para binarios en sistemas embebidos son raras, pero cuando existen, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

## Prepared Operating Systems for Firmware Analysis

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro destinada a ayudarte a realizar security assessment and penetration testing de dispositivos Internet of Things (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo para embedded security testing basado en Ubuntu 18.04 precargado con herramientas para firmware security testing.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un proveedor implementa verificaciones de firma criptográfica para imágenes de firmware, **la protección contra version rollback (downgrade) suele omitirse**. Cuando el boot- o recovery-loader solo verifica la firma con una clave pública embebida pero no compara la *versión* (o un contador monótono) de la imagen que se está flasheando, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que todavía posee una firma válida** y así reintroducir vulnerabilidades parcheadas.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite la inyección de comandos arbitrarios (aquí — habilitando acceso root mediante clave SSH). Versiones posteriores del firmware introdujeron un filtro de caracteres básico, pero la ausencia de downgrade protection hace que la corrección sea inútil.

### Extracción de firmware desde aplicaciones móviles

Muchos proveedores incluyen imágenes completas de firmware dentro de sus aplicaciones móviles complementarias para que la app pueda actualizar el dispositivo por Bluetooth/Wi‑Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el simple `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualización

* ¿Está el transporte/autenticación del *endpoint de actualización* adecuadamente protegido (TLS + autenticación)?
* ¿Compara el dispositivo los **números de versión** o un **monotonic anti-rollback counter** antes de flashear?
* ¿Se verifica la imagen dentro de una secure boot chain (p. ej., firmas comprobadas por ROM code)?
* ¿El userland code realiza comprobaciones adicionales de validación (p. ej., mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *partial* o *backup* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los anteriores, la plataforma probablemente sea vulnerable a rollback attacks.

## Firmware vulnerable para practicar

Para practicar el descubrimiento de vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerables como punto de partida.

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

## Entrenamiento y Certificación

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
