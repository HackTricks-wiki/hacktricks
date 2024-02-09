# Análisis de Firmware

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## **Introducción**

El firmware es un software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, asegurando que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que lleva al inicio del sistema operativo. Examinar y potencialmente modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recopilación de Información**

La **recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Especificaciones del cargador de arranque
- Diseño de hardware y hojas de datos
- Métricas de la base de código y ubicaciones de origen
- Bibliotecas externas y tipos de licencias
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de código abierto (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible a través de procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para encontrar problemas potenciales.

## **Adquisición del Firmware**

La obtención del firmware puede abordarse a través de varios medios, cada uno con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Compilándolo** siguiendo las instrucciones proporcionadas
- **Descargándolo** desde sitios de soporte oficiales
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo al almacenamiento **en la nube** directamente, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas de hombre en el medio
- **Extrayéndolo** del dispositivo a través de conexiones como **UART**, **JTAG** o **PICit**
- **Esperando** solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y utilizando **puntos finales de actualización codificados**
- **Volcando** desde el cargador de arranque o la red
- **Quitando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, utilizando herramientas de hardware apropiadas

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
Si no encuentras mucho con esas herramientas, verifica la **entropía** de la imagen con `binwalk -E <bin>`, si la entropía es baja, entonces es poco probable que esté encriptada. Si la entropía es alta, es probable que esté encriptada (o comprimida de alguna manera).

Además, puedes utilizar estas herramientas para extraer **archivos incrustados dentro del firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obteniendo el Sistema de Archivos

Con las herramientas mencionadas anteriormente como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk generalmente lo extrae dentro de una **carpeta con el nombre del tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción Manual del Sistema de Archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos en sus firmas**. En estos casos, utiliza binwalk para **encontrar el desplazamiento del sistema de archivos y tallar el sistema de archivos comprimido** del binario y **extraer manualmente** el sistema de archivos según su tipo siguiendo los pasos a continuación.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecuta el siguiente **comando dd** tallando el sistema de archivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Para squashfs (utilizado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en el directorio "`squashfs-root`" posteriormente.

* Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

* Para sistemas de archivos ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## Analizando Firmware

Una vez que se obtiene el firmware, es esencial diseccionarlo para comprender su estructura y posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de Análisis Inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (referido como `<bin>`). Estos comandos ayudan a identificar tipos de archivos, extraer cadenas, analizar datos binarios y comprender los detalles de particiones y sistemas de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de encriptación de la imagen, se verifica la **entropía** con `binwalk -E <bin>`. Una baja entropía sugiere una falta de encriptación, mientras que una alta entropía indica posible encriptación o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspección de archivos.

### Extracción del Sistema de Archivos

Usando `binwalk -ev <bin>`, generalmente se puede extraer el sistema de archivos, a menudo en un directorio con el nombre del tipo de sistema de archivos (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos debido a la falta de bytes mágicos, es necesario realizar una extracción manual. Esto implica usar `binwalk` para localizar el desplazamiento del sistema de archivos, seguido por el comando `dd` para extraer el sistema de archivos:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
### Análisis del Sistema de Archivos

Con el sistema de archivos extraído, comienza la búsqueda de fallas de seguridad. Se presta atención a los demonios de red inseguros, credenciales codificadas, puntos finales de API, funcionalidades del servidor de actualización, código no compilado, scripts de inicio y binarios compilados para análisis sin conexión.

**Ubicaciones clave** e **elementos** a inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuario
- Certificados SSL y claves en **etc/ssl**
- Archivos de configuración y scripts en busca de vulnerabilidades potenciales
- Binarios integrados para análisis adicional
- Servidores web comunes de dispositivos IoT y binarios

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para búsqueda de información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) para análisis exhaustivo de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Verificaciones de Seguridad en Binarios Compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben ser examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios de Windows ayudan a identificar binarios desprotegidos que podrían ser explotados.

## Emulación de Firmware para Análisis Dinámico

El proceso de emular firmware permite el **análisis dinámico** de la operación de un dispositivo o de un programa individual. Este enfoque puede enfrentar desafíos con dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con arquitectura y endianness coincidentes, como una Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulación de Binarios Individuales

Para examinar programas individuales, es crucial identificar la endianness y la arquitectura de la CPU del programa.

#### Ejemplo con Arquitectura MIPS

Para emular un binario de arquitectura MIPS, se puede utilizar el siguiente comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### Emulación de Arquitectura ARM

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Emulación de Sistema Completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras, facilitan la emulación completa de firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis Dinámico en la Práctica

En esta etapa, se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener acceso a la shell del sistema operativo y al sistema de archivos. La emulación puede no replicar perfectamente las interacciones de hardware, lo que puede requerir reinicios ocasionales de la emulación. El análisis debe revisar el sistema de archivos, explotar páginas web expuestas y servicios de red, y explorar vulnerabilidades en el cargador de arranque. Las pruebas de integridad del firmware son críticas para identificar posibles vulnerabilidades de puerta trasera.

## Técnicas de Análisis en Tiempo de Ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer puntos de interrupción e identificar vulnerabilidades a través de técnicas de fuzzing y otras.

## Explotación de Binarios y Prueba de Concepto

Desarrollar un PoC para vulnerabilidades identificadas requiere un profundo entendimiento de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de tiempo de ejecución binario en sistemas integrados son raras, pero cuando están presentes, pueden ser necesarias técnicas como la Programación Orientada a Retornos (ROP).

## Sistemas Operativos Preparados para Análisis de Firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas Operativos Preparados para Analizar Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución diseñada para ayudarte a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos de Internet de las cosas (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo de pruebas de seguridad integrada basado en Ubuntu 18.04 precargado con herramientas de pruebas de seguridad de firmware.

## Firmware Vulnerable para Practicar

Para practicar descubriendo vulnerabilidades en firmware, utiliza los siguientes proyectos de firmware vulnerables como punto de partida.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* Proyecto de Firmware de Enrutador Muy Vulnerable (DVRF)
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Enrutador ARM Muy Vulnerable (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Dispositivo IoT Muy Vulnerable (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referencias

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Hacking Práctico de IoT: La Guía Definitiva para Atacar el Internet de las Cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Entrenamiento y Certificación

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
