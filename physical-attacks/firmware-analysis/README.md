# Análisis de Firmware

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introducción

El firmware es un tipo de software que proporciona comunicación y control sobre los componentes de hardware de un dispositivo. Es el primer código que ejecuta un dispositivo. Generalmente, **inicia el sistema operativo** y proporciona servicios de ejecución muy específicos para los programas mediante la **comunicación con varios componentes de hardware**. La mayoría, si no todos, los dispositivos electrónicos tienen firmware.

Los dispositivos almacenan el firmware en **memoria no volátil**, como ROM, EPROM o memoria flash.

Es importante **examinar** el **firmware** y luego intentar **modificarlo**, porque podemos descubrir muchos problemas de seguridad durante este proceso.

## **Recolección de información y reconocimiento**

Durante esta etapa, recopila la mayor cantidad de información posible sobre el objetivo para entender su composición general y tecnología subyacente. Intenta recopilar lo siguiente:

* Arquitectura(s) de CPU soportadas
* Plataforma del sistema operativo
* Configuraciones del bootloader
* Esquemas de hardware
* Hojas de datos
* Estimaciones de líneas de código (LoC)
* Ubicación del repositorio de código fuente
* Componentes de terceros
* Licencias de código abierto (por ejemplo, GPL)
* Registros de cambios
* IDs de la FCC
* Diagramas de diseño y flujo de datos
* Modelos de amenazas
* Informes de pruebas de penetración anteriores
* Tickets de seguimiento de errores (por ejemplo, Jira y plataformas de recompensas por errores como BugCrowd o HackerOne)

Donde sea posible, adquiere datos utilizando herramientas y técnicas de inteligencia de fuentes abiertas (OSINT). Si se utiliza software de código abierto, descarga el repositorio y realiza análisis estáticos tanto manuales como automatizados contra la base de código. A veces, los proyectos de software de código abierto ya utilizan herramientas de análisis estático gratuitas proporcionadas por proveedores que ofrecen resultados de escaneo como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore).

## Obtención del Firmware

Hay diferentes maneras con distintos niveles de dificultad para descargar el firmware

* **Directamente** del equipo de desarrollo, fabricante/proveedor o cliente
* **Construir desde cero** utilizando guías proporcionadas por el fabricante
* Desde el **sitio de soporte del proveedor**
* Consultas de **Google dork** dirigidas a extensiones de archivos binarios y plataformas de intercambio de archivos como Dropbox, Box y Google Drive
* Es común encontrar imágenes de firmware a través de clientes que suben contenidos a foros, blogs o comentan en sitios donde contactaron al fabricante para solucionar un problema y les proporcionaron firmware a través de un archivo zip o una unidad flash enviada.
* Ejemplo: `intitle:"Netgear" intext:"Firmware Download"`
* Descargar compilaciones desde ubicaciones de almacenamiento de proveedores de la nube expuestas como los buckets de Amazon Web Services (AWS) S3 (con herramientas como [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* **Hombre en el medio** (MITM) comunicación del dispositivo durante **actualizaciones**
* Extraer directamente **del hardware** a través de **UART**, **JTAG**, **PICit**, etc.
* Capturar **comunicación serial** dentro de los componentes de hardware para **solicitudes de servidor de actualización**
* A través de un **punto final codificado** dentro de las aplicaciones móviles o gruesas
* **Volcado** de firmware desde el **bootloader** (por ejemplo, U-boot) a almacenamiento flash o a través de la **red** vía **tftp**
* Retirar el **chip de flash** (por ejemplo, SPI) o MCU de la placa para análisis y extracción de datos fuera de línea (ÚLTIMO RECURSO).
* Necesitarás un programador de chips compatible para el almacenamiento flash y/o el MCU.

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

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obteniendo el Sistema de Archivos

Con las herramientas mencionadas anteriormente como `binwalk -ev <bin>` deberías haber podido **extraer el sistema de archivos**.\
Binwalk generalmente lo extrae dentro de una **carpeta nombrada como el tipo de sistema de archivos**, que generalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción Manual del Sistema de Archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el desplazamiento del sistema de archivos y tallar el sistema de archivos comprimido** del binario y **extraer manualmente** el sistema de archivos de acuerdo con su tipo utilizando los pasos a continuación.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente **comando dd** para extraer el sistema de archivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Para squashfs (usado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán en el directorio "`squashfs-root`" después.

* Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

* Para sistemas de archivos ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Analizando el Sistema de Archivos

Ahora que tienes el sistema de archivos es hora de empezar a buscar malas prácticas como:

* **Daemons de red inseguros** antiguos como telnetd (a veces los fabricantes renombran los binarios para disimular)
* **Credenciales codificadas** (nombres de usuario, contraseñas, claves API, claves SSH y variantes de puertas traseras)
* **Puntos finales de API codificados** y detalles del servidor backend
* **Funcionalidad del servidor de actualización** que podría usarse como punto de entrada
* **Revisar código no compilado y scripts de inicio** en busca de ejecución de código remoto
* **Extraer binarios compilados** para ser usados en análisis fuera de línea con un desensamblador para pasos futuros

Algunas **cosas interesantes que buscar** dentro del firmware:

* etc/shadow y etc/passwd
* listar el directorio etc/ssl
* buscar archivos relacionados con SSL como .pem, .crt, etc.
* buscar archivos de configuración
* buscar archivos de script
* buscar otros archivos .bin
* buscar palabras clave como admin, password, remote, claves de AWS, etc.
* buscar servidores web comunes usados en dispositivos IoT
* buscar binarios comunes como ssh, tftp, dropbear, etc.
* buscar funciones prohibidas en C
* buscar funciones vulnerables a inyección de comandos comunes
* buscar URLs, direcciones de correo electrónico y direcciones IP
* y más…

Herramientas que buscan este tipo de información (aunque siempre debes echar un vistazo manual y familiarizarte con la estructura del sistema de archivos, las herramientas pueden ayudarte a encontrar **cosas ocultas**):

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Increíble script de bash que en este caso es útil para buscar **información sensible** dentro del sistema de archivos. Simplemente **chroot dentro del sistema de archivos del firmware y ejecútalo**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Script de bash para buscar información sensible potencial
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core):
* Identificación de componentes de software como sistema operativo, arquitectura de CPU y componentes de terceros junto con su información de versión asociada
* Extracción del sistema de archivos del firmware (s) de imágenes
* Detección de certificados y claves privadas
* Detección de implementaciones débiles mapeadas a la Enumeración de Debilidades Comunes (CWE)
* Detección basada en firmas y alimentación de vulnerabilidades
* Análisis de comportamiento estático básico
* Comparación (diff) de versiones de firmware y archivos
* Emulación en modo usuario de binarios del sistema de archivos usando QEMU
* Detección de mitigaciones binarias como NX, DEP, ASLR, canarios de pila, RELRO y FORTIFY_SOURCE
* API REST
* y más...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer es una herramienta para analizar imágenes de sistemas de archivos (ext2/3/4), FAT/VFat, SquashFS, UBIFS, archivos de archivo cpio y contenido de directorios utilizando un conjunto de reglas configurables.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): Una Herramienta de Análisis de Seguridad de Firmware IoT de Software Libre
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): Esta es una reescritura completa del proyecto original ByteSweep en Go.
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ está diseñado como la herramienta central de análisis de firmware para pentesters. Admite el proceso completo de análisis de seguridad comenzando con el proceso de _extracción de firmware_, realizando _análisis estático_ y _análisis dinámico_ a través de la emulación y finalmente generando un informe. _EMBA_ descubre automáticamente posibles puntos débiles y vulnerabilidades en el firmware. Ejemplos son binarios inseguros, componentes de software antiguos y desactualizados, scripts potencialmente vulnerables o contraseñas codificadas.

{% hint style="warning" %}
Dentro del sistema de archivos también puedes encontrar **código fuente** de programas (que siempre debes **revisar**), pero también **binarios compilados**. Estos programas podrían estar de alguna manera expuestos y debes **descompilar** y **revisar** para posibles vulnerabilidades.

Herramientas como [**checksec.sh**](https://github.com/slimm609/checksec.sh) pueden ser útiles para encontrar binarios no protegidos. Para binarios de Windows podrías usar [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Emulando el Firmware

La idea de emular el Firmware es poder realizar un **análisis dinámico** del dispositivo **en funcionamiento** o de un **programa individual**.

{% hint style="info" %}
A veces, la emulación parcial o completa **puede no funcionar debido a dependencias de hardware o arquitectura**. Si la arquitectura y la endianness coinciden con un dispositivo que posees, como una raspberry pie, el sistema de archivos raíz o un binario específico se puede transferir al dispositivo para pruebas adicionales. Este método también se aplica a máquinas virtuales preconstruidas que usan la misma arquitectura y endianness que el objetivo.
{% endhint %}

### Emulación Binaria

Si solo quieres emular un programa para buscar vulnerabilidades, primero necesitas identificar su endianness y la arquitectura de CPU para la cual fue compilado.

#### Ejemplo MIPS
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Ahora puedes **emular** el ejecutable busybox usando **QEMU**.
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Debido a que el ejecutable **está** compilado para **MIPS** y sigue el orden de bytes **big-endian**, utilizaremos el emulador **`qemu-mips`** de QEMU. Para emular ejecutables **little-endian**, tendríamos que seleccionar el emulador con el sufijo `el` (`qemu-mipsel`):
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Ejemplo ARM
```bash
file bin/busybox
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Emulación:
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Emulación Completa del Sistema

Existen varias herramientas, basadas en **qemu** en general, que te permitirán emular el firmware completo:

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
* Necesitas instalar varias cosas, configurar postgres, luego ejecutar el script extractor.py para extraer el firmware, usar el script getArch.sh para obtener la arquitectura. Después, usar los scripts tar2db.py y makeImage.sh para almacenar información de la imagen extraída en la base de datos y generar una imagen QEMU que podemos emular. Luego, usar el script inferNetwork.sh para obtener las interfaces de red, y finalmente usar el script run.sh, que se crea automáticamente en la carpeta ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
* Esta herramienta depende de firmadyne y automatiza el proceso de emular el firmware utilizando firmadynee. necesitas configurar `fat.config` antes de usarlo: `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Análisis Dinámico**

En esta etapa deberías tener o un dispositivo ejecutando el firmware para atacar o el firmware siendo emulado para atacar. En cualquier caso, es altamente recomendable que también tengas **una shell en el OS y el sistema de archivos que se está ejecutando**.

Ten en cuenta que a veces si estás emulando el firmware **algunas actividades dentro de la emulación fallarán** y podrías necesitar reiniciar la emulación. Por ejemplo, una aplicación web podría necesitar obtener información de un dispositivo con el que el dispositivo original está integrado pero la emulación no está emulando.

Deberías **revisar el sistema de archivos** como ya hicimos en un **paso anterior ya que en el entorno en ejecución podría haber nueva información accesible.**

Si **páginas web** están expuestas, leyendo el código y teniendo acceso a ellas deberías **probarlas**. En hacktricks puedes encontrar mucha información sobre diferentes técnicas de hacking web.

Si **servicios de red** están expuestos deberías intentar atacarlos. En hacktricks puedes encontrar mucha información sobre diferentes técnicas de hacking de servicios de red. También podrías intentar hacer fuzzing con **fuzzers** de red y protocolo como [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz), y [kitty](https://github.com/cisco-sas/kitty).

Deberías comprobar si puedes **atacar el bootloader** para obtener una shell de root:

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Deberías probar si el dispositivo está realizando algún tipo de **pruebas de integridad del firmware**, si no, esto permitiría a los atacantes ofrecer firmwares con puertas traseras, instalarlos en dispositivos que otras personas poseen o incluso desplegarlos de forma remota si hay alguna vulnerabilidad de actualización del firmware:

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Las vulnerabilidades de actualización del firmware suelen ocurrir porque, la **integridad** del **firmware** podría **no** ser **validada**, uso de protocolos de **red** **no cifrados**, uso de **credenciales codificadas**, una **autenticación insegura** al componente en la nube que aloja el firmware, e incluso un **registro excesivo e inseguro** (datos sensibles), permitir **actualizaciones físicas** sin verificaciones.

## **Análisis en Tiempo de Ejecución**

El análisis en tiempo de ejecución implica conectarse a un proceso o binario en ejecución mientras un dispositivo está funcionando en su entorno normal o emulado. A continuación, se proporcionan los pasos básicos del análisis en tiempo de ejecución:

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Adjuntar gdb-multiarch o usar IDA para emular el binario
3. Establecer puntos de interrupción para funciones identificadas durante el paso 4 como memcpy, strncpy, strcmp, etc.
4. Ejecutar cadenas de carga útil grandes para identificar desbordamientos o caídas del proceso usando un fuzzer
5. Pasar al paso 8 si se identifica una vulnerabilidad

Herramientas que pueden ser útiles son (no exhaustivas):

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Explotación Binaria**

Después de identificar una vulnerabilidad dentro de un binario en los pasos anteriores, se requiere una prueba de concepto (PoC) adecuada para demostrar el impacto y riesgo en el mundo real. Desarrollar código de explotación requiere experiencia en programación en lenguajes de bajo nivel (por ejemplo, ASM, C/C++, shellcode, etc.) así como conocimiento en la arquitectura objetivo particular (por ejemplo, MIPS, ARM, x86, etc.). El código PoC implica obtener ejecución arbitraria en un dispositivo o aplicación controlando una instrucción en memoria.

No es común que las protecciones de tiempo de ejecución binario (por ejemplo, NX, DEP, ASLR, etc.) estén en su lugar dentro de los sistemas embebidos, sin embargo, cuando esto sucede, pueden ser necesarias técnicas adicionales como la programación orientada a retornos (ROP). ROP permite a un atacante implementar funcionalidad maliciosa arbitraria encadenando código existente en el proceso/binario objetivo conocido como gadgets. Se necesitarán pasos para explotar una vulnerabilidad identificada como un desbordamiento de búfer formando una cadena ROP. Una herramienta que puede ser útil para situaciones como estas es el buscador de gadgets de Capstone o ROPGadget- [https://github.com/JonathanSalwan/ROPgadget](https://github.com/JonathanSalwan/ROPgadget).

Utiliza las siguientes referencias para obtener más orientación:

* [https://azeria-labs.com/writing-arm-shellcode/](https://azeria-labs.com/writing-arm-shellcode/)
* [https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/](https://www.corelan.be/index.php/category/security/exploit-writing-tutorials/)

## OSs Preparados para Analizar Firmware

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución destinada a ayudarte a realizar evaluaciones de seguridad y pentesting de dispositivos de Internet de las Cosas (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo de pruebas de seguridad embebido basado en Ubuntu 18.04 precargado con herramientas de pruebas de seguridad de firmware.

## Firmware Vulnerable para Practicar

Para practicar el descubrimiento de vulnerabilidades en firmware, utiliza los siguientes proyectos de firmware vulnerables como punto de partida.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Referencias

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Entrenamiento y Certificación

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repos de github** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
