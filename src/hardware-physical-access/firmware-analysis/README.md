# Análisis de Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introducción**

### Recursos relacionados

{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

El firmware es un software esencial que permite a los dispositivos operar correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que los usuarios interactúan. Se almacena en memoria permanente, asegurando que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que lleva al lanzamiento del sistema operativo. Examinar y potencialmente modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recolección de Información**

**Recolección de información** es un paso inicial crítico para entender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Especificaciones del bootloader
- Diseño de hardware y hojas de datos
- Métricas de la base de código y ubicaciones de origen
- Bibliotecas externas y tipos de licencia
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de código abierto (OSINT)** son invaluables, así como el análisis de cualquier componente de software de código abierto disponible a través de procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para encontrar problemas potenciales.

## **Adquisición del Firmware**

Obtener firmware se puede abordar a través de varios medios, cada uno con su propio nivel de complejidad:

- **Directamente** de la fuente (desarrolladores, fabricantes)
- **Construyéndolo** a partir de instrucciones proporcionadas
- **Descargando** de sitios de soporte oficiales
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo a **almacenamiento en la nube** directamente, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** a través de técnicas de hombre en el medio
- **Extrayendo** del dispositivo a través de conexiones como **UART**, **JTAG** o **PICit**
- **Esnifando** solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y utilizando **puntos finales de actualización codificados**
- **Volcando** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, utilizando herramientas de hardware apropiadas

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
Si no encuentras mucho con esas herramientas, verifica la **entropía** de la imagen con `binwalk -E <bin>`, si la entropía es baja, entonces es poco probable que esté encriptada. Si la entropía es alta, es probable que esté encriptada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados dentro del firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtener el Sistema de Archivos

Con las herramientas comentadas anteriormente como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk generalmente lo extrae dentro de una **carpeta nombrada como el tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción Manual del Sistema de Archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el desplazamiento del sistema de archivos y tallar el sistema de archivos comprimido** del binario y **extraer manualmente** el sistema de archivos según su tipo utilizando los pasos a continuación.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecuta el siguiente **dd command** para extraer el sistema de archivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (utilizado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en el directorio "`squashfs-root`" después.

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis de Firmware

Una vez que se obtiene el firmware, es esencial diseccionarlo para entender su estructura y posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de Análisis Inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivos, extraer cadenas, analizar datos binarios y entender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se verifica la **entropía** con `binwalk -E <bin>`. Una baja entropía sugiere una falta de cifrado, mientras que una alta entropía indica posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extracción del Sistema de Archivos

Usando `binwalk -ev <bin>`, generalmente se puede extraer el sistema de archivos, a menudo en un directorio nombrado según el tipo de sistema de archivos (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no puede reconocer el tipo de sistema de archivos debido a bytes mágicos faltantes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el desplazamiento del sistema de archivos, seguido del comando `dd` para extraer el sistema de archivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, dependiendo del tipo de sistema de archivos (por ejemplo, squashfs, cpio, jffs2, ubifs), se utilizan diferentes comandos para extraer manualmente el contenido.

### Análisis del Sistema de Archivos

Con el sistema de archivos extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a demonios de red inseguros, credenciales codificadas, puntos finales de API, funcionalidades del servidor de actualizaciones, código no compilado, scripts de inicio y binarios compilados para análisis fuera de línea.

**Ubicaciones clave** y **elementos** a inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de vulnerabilidades potenciales
- Binarios incrustados para un análisis más profundo
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para la búsqueda de información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis completo de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Comprobaciones de Seguridad en Binarios Compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben ser examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios de Unix y **PESecurity** para binarios de Windows ayudan a identificar binarios no protegidos que podrían ser explotados.

## Emulando Firmware para Análisis Dinámico

El proceso de emular firmware permite un **análisis dinámico** ya sea de la operación de un dispositivo o de un programa individual. Este enfoque puede encontrar desafíos con dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con arquitectura y endianness coincidentes, como una Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulando Binarios Individuales

Para examinar programas individuales, es crucial identificar el endianness y la arquitectura de CPU del programa.

#### Ejemplo con Arquitectura MIPS

Para emular un binario de arquitectura MIPS, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), se utiliza `qemu-mips`, y para binarios little-endian, `qemu-mipsel` sería la elección.

#### Emulación de Arquitectura ARM

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Emulación de Sistema Completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras, facilitan la emulación completa de firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis Dinámico en Práctica

En esta etapa, se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso a la shell del sistema operativo y al sistema de archivos. La emulación puede no imitar perfectamente las interacciones de hardware, lo que requiere reinicios ocasionales de la emulación. El análisis debe revisar el sistema de archivos, explotar páginas web y servicios de red expuestos, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles vulnerabilidades de puerta trasera.

## Técnicas de Análisis en Tiempo de Ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer puntos de interrupción e identificar vulnerabilidades a través de fuzzing y otras técnicas.

## Explotación Binaria y Prueba de Concepto

Desarrollar un PoC para vulnerabilidades identificadas requiere un profundo entendimiento de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de tiempo de ejecución en sistemas embebidos son raras, pero cuando están presentes, técnicas como Return Oriented Programming (ROP) pueden ser necesarias.

## Sistemas Operativos Preparados para Análisis de Firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas Operativos Preparados para Analizar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución destinada a ayudar a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos de Internet de las Cosas (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo de pruebas de seguridad embebido basado en Ubuntu 18.04 precargado con herramientas de pruebas de seguridad de firmware.

## Ataques de Downgrade de Firmware y Mecanismos de Actualización Inseguros

Incluso cuando un proveedor implementa verificaciones de firma criptográfica para imágenes de firmware, **la protección contra retrocesos de versión (downgrade) se omite con frecuencia**. Cuando el bootloader o el recovery-loader solo verifica la firma con una clave pública embebida pero no compara la *versión* (o un contador monótono) de la imagen que se está flasheando, un atacante puede instalar legítimamente un **firmware más antiguo y vulnerable que aún tiene una firma válida** y así reintroducir vulnerabilidades corregidas.

Flujo de trabajo típico del ataque:

1. **Obtener una imagen firmada más antigua**
* Obtenerla del portal de descarga pública del proveedor, CDN o sitio de soporte.
* Extraerla de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un APK de Android bajo `assets/firmware/`).
* Recuperarla de repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Subir o servir la imagen al dispositivo** a través de cualquier canal de actualización expuesto:
* Interfaz web, API de aplicación móvil, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen puntos finales HTTP(S) *no autenticados* que aceptan blobs de firmware codificados en Base64, los decodifican del lado del servidor y activan la recuperación/actualización.
3. Después del downgrade, explotar una vulnerabilidad que fue corregida en la versión más nueva (por ejemplo, un filtro de inyección de comandos que se agregó más tarde).
4. Opcionalmente, flashear la imagen más reciente de nuevo o deshabilitar actualizaciones para evitar detección una vez que se obtiene persistencia.

### Ejemplo: Inyección de Comandos Después del Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (degradado), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite la inyección de comandos arbitrarios (aquí – habilitando el acceso root basado en clave SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra degradaciones hace que la solución sea irrelevante.

### Extracción de Firmware de Aplicaciones Móviles

Muchos proveedores empaquetan imágenes de firmware completas dentro de sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo a través de Bluetooth/Wi-Fi. Estos paquetes se almacenan comúnmente sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el simple `unzip` te permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualización

* ¿Está adecuadamente protegida la *autenticación/transporte del endpoint de actualización* (TLS + autenticación)?
* ¿Compara el dispositivo **números de versión** o un **contador anti-retroceso monotónico** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de arranque seguro (por ejemplo, firmas verificadas por código ROM)?
* ¿El código de espacio de usuario realiza verificaciones adicionales de coherencia (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parciales* o *de respaldo* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los anteriores, la plataforma probablemente sea vulnerable a ataques de retroceso.

## Firmware vulnerable para practicar

Para practicar la detección de vulnerabilidades en firmware, utiliza los siguientes proyectos de firmware vulnerables como punto de partida.

- OWASP IoTGoat
- [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
- El Proyecto de Firmware de Router Damn Vulnerable
- [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
- Router ARM Damn Vulnerable (DVAR)
- [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
- ARM-X
- [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
- VM 2.0 de Azeria Labs
- [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
- Dispositivo IoT Damn Vulnerable (DVID)
- [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referencias

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Entrenamiento y Certificación

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
