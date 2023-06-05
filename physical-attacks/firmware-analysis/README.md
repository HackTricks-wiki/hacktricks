# Análisis de Firmware

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introducción

El firmware es un tipo de software que proporciona comunicación y control sobre los componentes de hardware de un dispositivo. Es el primer código que ejecuta un dispositivo. Por lo general, **inicia el sistema operativo** y proporciona servicios de tiempo de ejecución muy específicos para los programas mediante la **comunicación con varios componentes de hardware**. La mayoría, si no todos, los dispositivos electrónicos tienen firmware.

Los dispositivos almacenan el firmware en **memoria no volátil**, como ROM, EPROM o memoria flash.

Es importante **examinar** el **firmware** y luego intentar **modificarlo**, porque podemos descubrir muchos problemas de seguridad durante este proceso.

## **Recopilación de información y reconocimiento**

Durante esta etapa, recopile tanta información sobre el objetivo como sea posible para comprender su composición general y la tecnología subyacente. Intente recopilar lo siguiente:

* Arquitectura(s) de CPU compatibles
* Plataforma del sistema operativo
* Configuraciones del cargador de arranque
* Esquemas de hardware
* Hojas de datos
* Estimaciones de líneas de código (LoC)
* Ubicación del repositorio de código fuente
* Componentes de terceros
* Licencias de código abierto (por ejemplo, GPL)
* Registros de cambios
* Identificaciones de la Comisión Federal de Comunicaciones (FCC)
* Diagramas de diseño y flujo de datos
* Modelos de amenazas
* Informes anteriores de pruebas de penetración
* Boletos de seguimiento de errores (por ejemplo, Jira y plataformas de recompensa de errores como BugCrowd o HackerOne)

Cuando sea posible, adquiera datos utilizando herramientas y técnicas de inteligencia de código abierto (OSINT). Si se utiliza software de código abierto, descargue el repositorio y realice tanto análisis estático manual como automatizado contra la base de código. A veces, los proyectos de software de código abierto ya utilizan herramientas de análisis estático gratuitas proporcionadas por proveedores que proporcionan resultados de escaneo como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore).

## Obteniendo el Firmware

Existen diferentes formas con diferentes niveles de dificultad para descargar el firmware

* **Directamente** del equipo de desarrollo, fabricante/proveedor o cliente
* **Construir desde cero** utilizando guías proporcionadas por el fabricante
* Desde el **sitio de soporte** del proveedor
* Consultas de búsqueda de **Google dork** dirigidas a extensiones de archivos binarios y plataformas de intercambio de archivos como Dropbox, Box y Google Drive
  * Es común encontrar imágenes de firmware a través de clientes que cargan contenido en foros, blogs o comentan en sitios donde contactaron al fabricante para solucionar un problema y se les dio firmware a través de un zip o una unidad flash enviada.
  * Ejemplo: `intitle:"Netgear" intext:"Firmware Download"`
* Descargar compilaciones de ubicaciones de almacenamiento de proveedores de nube expuestas como los buckets de Amazon Web Services (AWS) (con herramientas como [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner))
* Comunicación de dispositivo **man-in-the-middle** (MITM) durante **actualizaciones**
* Extraer directamente **desde el hardware** a través de **UART**, **JTAG**, **PICit**, etc.
* Espiar la **comunicación serial** dentro de los componentes de hardware para **solicitudes de servidor de actualización**
* A través de un **punto final codificado** dentro de las aplicaciones móviles o gruesas
* **Volcado** de firmware desde el **cargador de arranque** (por ejemplo, U-boot) al almacenamiento flash o a través de la **red** a través de **tftp**
* Eliminando el **chip flash** (por ejemplo, SPI) o MCU de la placa para análisis sin conexión y extracción de datos (ÚLTIMO RECURSO).
  * Necesitará un programador de chips compatible para el almacenamiento flash y / o el MCU.

## Analizando el firmware

Ahora que **tiene el firmware**, debe extraer información sobre él para saber cómo tratarlo. Diferentes herramientas que puede utilizar para eso:
```bash
file <bin>  
strings -n8 <bin> 
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out  
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si no encuentras mucho con esas herramientas, verifica la **entropía** de la imagen con `binwalk -E <bin>`. Si la entropía es baja, es poco probable que esté encriptado. Si la entropía es alta, es probable que esté encriptado (o comprimido de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados dentro del firmware**:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obteniendo el sistema de archivos

Con las herramientas mencionadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk generalmente lo extrae dentro de una **carpeta con el nombre del tipo de sistema de archivos**, que generalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tiene el byte mágico del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el desplazamiento del sistema de archivos y tallar el sistema de archivos comprimido** del binario y **extraer manualmente** el sistema de archivos según su tipo utilizando los siguientes pasos.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecute el siguiente comando **dd** para tallar el sistema de archivos Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs 

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternativamente, también se podría ejecutar el siguiente comando:

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

### Analizando el sistema de archivos

Ahora que tiene el sistema de archivos, es hora de empezar a buscar malas prácticas como:

* **Demonios de red inseguros** heredados, como telnetd (a veces los fabricantes renombran los binarios para disfrazarlos)
* **Credenciales codificadas** (nombres de usuario, contraseñas, claves de API, claves SSH y variantes de puerta trasera)
* **Puntos finales de API codificados** y detalles del servidor backend
* Funcionalidad de **servidor de actualización** que podría ser utilizada como punto de entrada
* **Revisar el código no compilado y los scripts de inicio** para la ejecución remota de código
* **Extraer binarios compilados** para su análisis sin conexión con un desensamblador para futuros pasos

Algunas **cosas interesantes para buscar** dentro del firmware:

* etc/shadow y etc/passwd
* listar el directorio etc/ssl
* buscar archivos relacionados con SSL como .pem, .crt, etc.
* buscar archivos de configuración
* buscar archivos de script
* buscar otros archivos .bin
* buscar palabras clave como admin, password, remote, claves de AWS, etc.
* buscar servidores web comunes utilizados en dispositivos IoT
* buscar binarios comunes como ssh, tftp, dropbear, etc.
* buscar funciones c prohibidas
* buscar funciones vulnerables comunes de inyección de comandos
* buscar URL, direcciones de correo electrónico y direcciones IP
* y más...

Herramientas que buscan este tipo de información (aunque siempre debe echar un vistazo manual y familiarizarse con la estructura del sistema de archivos, las herramientas pueden ayudarlo a encontrar **cosas ocultas**):

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng)**:** Impresionante script de bash que en este caso es útil para buscar **información sensible** dentro del sistema de archivos. Simplemente **chroot dentro del sistema de archivos del firmware y ejecútelo**.
* [**Firmwalker**](https://github.com/craigz28/firmwalker)**:** Script de bash para buscar información sensible potencial
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core):
  * Identificación de componentes de software como sistema operativo, arquitectura de CPU y componentes de terceros junto con su información de versión asociada
  * Extracción del sistema de archivos del firmware (s) de imágenes
  * Detección de certificados y claves privadas
  * Detección de implementaciones débiles que se asignan a Common Weakness Enumeration (CWE)
  * Detección de vulnerabilidades basadas en alimentación y firma
  * Análisis estático básico del comportamiento
  * Comparación (diff) de versiones y archivos de firmware
  * Emulación de modo de usuario de binarios de sistema de archivos utilizando QEMU
  * Detección de mitigaciones binarias como NX, DEP, ASLR, canarios de pila, RELRO y FORTIFY\_SOURCE
  * REST API
  * y más...
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer): FwAnalyzer es una herramienta para analizar imágenes de sistemas de archivos (ext2/3/4), FAT/VFat, SquashFS, UBIFS, archivos de archivo cpio y contenido de directorio utilizando un conjunto de reglas configurables.
* [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep): Una herramienta de análisis de seguridad de firmware IoT de software libre
* [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go): Esta es una reescritura completa del proyecto ByteSweep original en Go.
* [**EMBA**](https://github.com/e-m-b-a/emba): _EMBA_ está diseñado como la herramienta central de análisis de firmware para los probadores de penetración. Admite todo el proceso de análisis de seguridad que comienza con el proceso de extracción de firmware, realiza análisis estáticos y dinámicos a través de la emulación y, finalmente, genera un informe. _EMBA_ descubre automáticamente posibles puntos débiles y vulnerabilidades en el firmware. Ejemplos son binarios inseguros, componentes de software antiguos y desactualizados, scripts potencialmente vulnerables o contraseñas codificadas.

{% hint style="warning" %}
Dentro del sistema de archivos también puede encontrar **código fuente** de programas (que siempre debe **verificar**), pero también **binarios compilados**. Estos programas podrían estar expuestos de alguna manera y debería **descompilarlos** y **verificarlos** en busca de posibles vulnerabilidades.

Herramientas como [**checksec.sh**](https://github.com/slimm609/checksec.sh) pueden ser útiles para encontrar binarios desprotegidos. Para binarios de Windows, podría usar [**PESecurity**](https://github.com/NetSPI/PESecurity).
{% endhint %}

## Emulando Firmware

La idea de emular el firmware es poder realizar un **análisis dinámico** del dispositivo **en ejecución** o de un **programa individual**.

{% hint style="info" %}
A veces, la emulación parcial o completa **puede no funcionar debido a dependencias de hardware o arquitectura**. Si la arquitectura y el endianness coinciden con un dispositivo de propiedad como una frambuesa, el sistema de archivos raíz o un binario específico se pueden transferir al dispositivo para realizar más pruebas. Este método también se aplica a máquinas virtuales preconstruidas que utilizan la misma arquitectura y endianness que el objetivo.
{% endhint %}

### Emulación binaria

Si solo desea emular un programa para buscar vulnerabilidades, primero debe identificar su endianness y la arquitectura de CPU para la que se compiló.

#### Ejemplo de MIPS
```bash
file ./squashfs-root/bin/busybox
./squashfs-root/bin/busybox: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```
Ahora puedes **emular** el ejecutable de busybox usando **QEMU**.
```bash
 sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Como el ejecutable **está** compilado para **MIPS** y sigue el orden de bytes **big-endian**, usaremos el emulador **`qemu-mips`** de QEMU. Para emular ejecutables **little-endian**, tendríamos que seleccionar el emulador con el sufijo `el` (`qemu-mipsel`).
```bash
qemu-mips -L ./squashfs-root/ ./squashfs-root/bin/ls
100              100.7z           15A6D2.squashfs  squashfs-root    squashfs-root-0
```
#### Ejemplo ARM

---

##### Firmware Extraction

##### Extracción de Firmware

---

##### Firmware Analysis

##### Análisis de Firmware

---

##### Firmware Modification

##### Modificación de Firmware

---

##### Firmware Emulation

##### Emulación de Firmware

---

##### Firmware Reversing

##### Reversión de Firmware

---

##### Firmware Debugging

##### Depuración de Firmware

---

##### Firmware Dumping

##### Volcado de Firmware

---

##### Firmware Encryption

##### Encriptación de Firmware

---

##### Firmware Decryption

##### Desencriptación de Firmware

---

##### Firmware Signature Bypass

##### Salto de Firma de Firmware

---

##### Firmware Injection

##### Inyección de Firmware

---

##### Firmware Backdoor

##### Puerta trasera de Firmware

---

##### Firmware Rootkit

##### Rootkit de Firmware

---

##### Firmware Bootkit

##### Bootkit de Firmware

---

##### Firmware Exploitation

##### Explotación de Firmware

---

##### Firmware Vulnerabilities

##### Vulnerabilidades de Firmware

---

##### Firmware Protection

##### Protección de Firmware

---

##### Firmware Anti-Tampering

##### Anti-Manipulación de Firmware

---

##### Firmware Obfuscation

##### Ofuscación de Firmware

---

##### Firmware Hooking

##### Hooking de Firmware

---

##### Firmware Debugging

##### Depuración de Firmware

---

##### Firmware Analysis Tools

##### Herramientas de Análisis de Firmware
```bash
file bin/busybox                
bin/busybox: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-armhf.so.1, no section header
```
Emulación:
```bash
qemu-arm -L ./squashfs-root/ ./squashfs-root/bin/ls
1C00000.squashfs  B80B6C            C41DD6.xz         squashfs-root     squashfs-root-0
```
### Emulación completa del sistema

Existen varias herramientas, basadas en **qemu** en general, que te permitirán emular el firmware completo:

* [**https://github.com/firmadyne/firmadyne**](https://github.com/firmadyne/firmadyne)**:**
  * Necesitas instalar varias cosas, configurar postgres, luego ejecutar el script extractor.py para extraer el firmware, usar el script getArch.sh para obtener la arquitectura. Luego, usar los scripts tar2db.py y makeImage.sh para almacenar información de la imagen extraída en la base de datos y generar una imagen QEMU que podemos emular. Luego, usar el script inferNetwork.sh para obtener las interfaces de red, y finalmente usar el script run.sh, que se crea automáticamente en la carpeta ./scratch/1/.
* [**https://github.com/attify/firmware-analysis-toolkit**](https://github.com/attify/firmware-analysis-toolkit)**:**
  * Esta herramienta depende de firmadyne y automatiza el proceso de emulación del firmware usando firmadyne. Necesitas configurar `fat.config` antes de usarlo: `sudo python3 ./fat.py IoTGoat-rpi-2.img --qemu 2.5.0`
* [**https://github.com/therealsaumil/emux**](https://github.com/therealsaumil/emux)
* [**https://github.com/getCUJO/MIPS-X**](https://github.com/getCUJO/MIPS-X)
* [**https://github.com/qilingframework/qiling#qltool**](https://github.com/qilingframework/qiling#qltool)

## **Análisis dinámico**

En esta etapa, deberías tener un dispositivo ejecutando el firmware para atacar o el firmware siendo emulado para atacar. En cualquier caso, es muy recomendable que también tengas **una shell en el sistema operativo y el sistema de archivos que se está ejecutando**.

Ten en cuenta que a veces, si estás emulando el firmware, **algunas actividades dentro de la emulación fallarán** y es posible que debas reiniciar la emulación. Por ejemplo, una aplicación web podría necesitar obtener información de un dispositivo con el que está integrado el dispositivo original, pero la emulación no lo está emulando.

Deberías **revisar el sistema de archivos** como ya hicimos en un **paso anterior, ya que en el entorno de ejecución, puede haber nueva información accesible**.

Si se exponen **páginas web**, leyendo el código y teniendo acceso a ellas, deberías **probarlas**. En hacktricks puedes encontrar mucha información sobre diferentes técnicas de hacking web.

Si se exponen **servicios de red**, deberías intentar atacarlos. En hacktricks puedes encontrar mucha información sobre diferentes técnicas de hacking de servicios de red. También podrías intentar fuzzearlos con fuzzers de red y protocolos como [Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer), [boofuzz](https://github.com/jtpereyda/boofuzz) y [kitty](https://github.com/cisco-sas/kitty).

Deberías comprobar si puedes **atacar el cargador de arranque** para obtener una shell de root:

{% content-ref url="bootloader-testing.md" %}
[bootloader-testing.md](bootloader-testing.md)
{% endcontent-ref %}

Deberías probar si el dispositivo está realizando algún tipo de **pruebas de integridad del firmware**, si no es así, esto permitiría a los atacantes ofrecer firmwares con puertas traseras, instalarlos en dispositivos que otras personas poseen e incluso desplegarlos de forma remota si hay alguna vulnerabilidad de actualización de firmware:

{% content-ref url="firmware-integrity.md" %}
[firmware-integrity.md](firmware-integrity.md)
{% endcontent-ref %}

Las vulnerabilidades de actualización de firmware suelen ocurrir porque la **integridad** del **firmware** podría **no** ser **validada**, se usan protocolos de **red** **no** **encriptados**, se usan **credenciales** **codificadas** **en duro**, una **autenticación** **insegura** al componente en la nube que aloja el firmware, e incluso un registro excesivo e inseguro (datos sensibles), permiten **actualizaciones físicas** sin verificaciones.

## **Análisis en tiempo de ejecución**

El análisis en tiempo de ejecución implica adjuntarse a un proceso o binario en ejecución mientras un dispositivo se está ejecutando en su entorno normal o emulado. Los pasos básicos del análisis en tiempo de ejecución se proporcionan a continuación:

1. `sudo chroot . ./qemu-arch -L <optionalLibPath> -g <gdb_port> <binary>`
2. Adjuntar gdb-multiarch o usar IDA para emular el binario
3. Establecer puntos de interrupción para las funciones identificadas durante el paso 4, como memcpy, strncpy, strcmp, etc.
4. Ejecutar cadenas de carga útil grandes para identificar desbordamientos o bloqueos del proceso usando un fuzzer
5. Pasar al paso 8 si se identifica una vulnerabilidad

Las herramientas que pueden ser útiles son (no exhaustivas):

* gdb-multiarch
* [Peda](https://github.com/longld/peda)
* Frida
* ptrace
* strace
* IDA Pro
* Ghidra
* Binary Ninja
* Hopper

## **Explotación binaria**

Después de identificar una vulnerabilidad dentro de un binario de los pasos anteriores, se requiere una prueba de concepto (PoC) adecuada para demostrar el impacto y el riesgo del mundo real. El desarrollo de código de explotación requiere experiencia en programación en lenguajes de nivel inferior (por ejemplo, ASM, C/C++, shellcode, etc.) y antecedentes en la arquitectura de destino particular (por ejemplo, MIPS, ARM, x86, etc.). El código de PoC implica obtener una ejecución arbitraria en un dispositivo o aplicación controlando una instrucción en memoria.

No es común que las protecciones de tiempo de ejecución binarias (por ejemplo, NX, DEP, ASLR, etc.) estén en su lugar dentro de los sistemas integrados, sin embargo, cuando esto sucede, pueden ser necesarias técnicas adicionales como la programación orientada a la devolución (ROP). ROP permite a un atacante implementar funcionalidad maliciosa arbitraria encadenando código existente en el código del proceso/binario objetivo conocido como gadgets. Se deberán tomar medidas para explotar una vulnerabilidad identificada, como un desbordamiento de búfer, formando una cadena ROP. Una herramienta que puede ser útil para situaciones como estas es el buscador de gadgets de Capstone o ROP
