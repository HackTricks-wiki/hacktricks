# Firmware Ontleding

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

### Verwante hulpbronne


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware is essensiële sagteware wat toestelle in staat stel om korrek te funksioneer deur kommunikasie tussen die hardware-komponente en die sagteware wat gebruikers gebruik, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang tot noodsaaklike instruksies het vanaf die oomblik dat dit aangeskakel word, wat uiteindelik tot die launch van die bedryfstelsel lei. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteits kwesbaarhede te identifiseer.

## **Versameling van inligting**

**Versameling van inligting** is ’n kritieke aanvanklike stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik te begryp. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en die operating system waarop dit hardloop
- Bootloader-spesifieke besonderhede
- Hardware-opstelling en datasheets
- Codebase-metrieke en bronlokasies
- Eksterne libraries en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifiserings
- Argitektoniese en vloei-diagramme
- Sekuriteitsassesseringe en geïdentifiseerde kwesbaarhede

Vir hierdie doel is open-source intelligence (OSINT) tools van onskatbare waarde, net soos die analise van enige beskikbare open-source software-komponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Tools soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis static analysis wat benut kan word om potensiële probleme te vind.

## **Verkryging van die Firmware**

Die verkryging van firmware kan op verskeie maniere benader word, elk met sy eie vlak van kompleksiteit:

- **Direk** van die bron (developers, manufacturers)
- **Bouw** dit vanaf voorsieningsinstruksies
- **Aflaai** vanaf amptelike support sites
- Gebruik **Google dork** queries om gehoste firmware-lêers te vind
- Direkte toegang tot **cloud storage**, met tools soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Intersep van **updates** via man-in-the-middle tegnieke
- **Uittreksel** vanaf die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** vir update-versoeke binne toestelkommunikasie
- Identifisering en gebruik van **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of netwerk
- **Verwydering en uitlees** van die stoorchip, wanneer alles anders misluk, met toepaslike hardware-gereedskap

## **Ontleding van die Firmware**

Nou dat jy die firmware het, moet jy inligting daaruit onttrek om te weet hoe om dit te hanteer. Verskeie tools wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie gereedskap vind nie, kyk die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier ge-komprimeer).

Verder kan jy hierdie gereedskap gebruik om **lêers wat in die firmware ingebed is** uit te trek:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te ondersoek.

### Kry die lêerstelsel

Met die vorige genoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêerstelsel uit te trek**.\
Binwalk haal dit gewoonlik uit binne 'n **gids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelsel-uittrekking

Soms sal binwalk nie die magic byte van die lêerstelsel in sy signatures hê nie. In sulke gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die gekomprimeerde lêerstelsel uit die binêre uit te sny** en **manueel die lêerstelsel uit te pak** volgens die tipe met die stappe hieronder.
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

Lêers sal daarna in die `squashfs-root` gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2 lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs lêerstelsels met NAND-flits

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-ontleding

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware-beeld te ontleed en te onttrek.

### Aanvanklike ontledingshulpmiddels

'n Reeks opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (verwys na as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed, en die partisie- en lêerstelselbesonderhede te begryp:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te evalueer, word die **entropie** gecheck met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **ingeslote lêers** word instrumente en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrekking van die lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel onttrek, dikwels in 'n gids genoem na die tipe lêerstelsel (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe kan herken weens ontbrekende magic bytes nie, is handmatige uittrekking noodsaaklik. Dit behels die gebruik van `binwalk` om die offset van die lêerstelsel te vind, gevolg deur die `dd` opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangend van die lêerstelsel-tipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig te onttrek.

### Lêerstelsel-analise

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Aandag word gegee aan insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, en gecompileerde binaries vir offline-analise.

**Belangrike lokasies** en **items** om te ondersoek sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersaanmeldingsinligting
- SSL certificates en keys in **etc/ssl**
- Konfigurasie- en script-lêers vir potensiële kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT device web servers en binaries

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir soektog na sensitiewe inligting
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Sekuriteitskontroles op gecompileerde binaries

Beide source code en gecompileerde binaries wat in die lêerstelsel gevind word, moet deeglik ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix binaries en **PESecurity** vir Windows binaries help om onbeveiligde binaries te identifiseer wat uitgebuit kan word.

## Emulering van firmware vir Dynamic Analysis

Die proses om firmware te emuleer maak dit moontlik om **dynamic analysis** te doen op ofwel 'n toestel se werking of 'n individuele program. Hierdie benadering kan probleme ondervind weens hardware- of argitektuur-afhanklikhede, maar die oordrag van die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende argitektuur en endianness, soos 'n Raspberry Pi, of na 'n pre-built virtual machine, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Om enkelprogramme te ondersoek, is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om 'n MIPS-argitektuur-binêre te emuleer, kan mens die opdrag gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-instrumente te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Argitektuur Emulasie

Vir ARM binaries is die proses soortgelyk, en die `qemu-arm` emulator word vir emulasie gebruik.

### Volledige Stelsel Emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander fasiliteer volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

## Dinamiese Analise in die Praktyk

By hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing gebruik vir analise. Dit is noodsaaklik om shell-toegang tot die OS en filesystem te behou. Emulasie mag nie perfek hardeware-interaksies naboots nie, wat af en toe herstart van die emulasie vereis. Analise moet die filesystem weer besoek, blootgestelde webpages en netwerkdienste uitbuit, en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is kritiek om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime Analise Tegnieke

Runtime-analise behels interaksie met 'n proses of binary in sy bedryfsomgewing, met gebruik van gereedskap soos gdb-multiarch, Frida en Ghidra om breakpoints te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binary-uitbuiting en Proof-of-Concept

Die ontwikkeling van 'n PoC vir geïdentifiseerde kwesbaarhede vereis 'n diep begrip van die teiken-argitektuur en programmering in laevlakprogrammeertale. Binary runtime-beskerming in ingebedde stelsels is skaars, maar wanneer dit teenwoordig is, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Voorbereide OS'e vir Firmware-analise

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help om sekuriteitsassessering en penetration testing van Internet of Things (IoT) devices uit te voer. Dit bespaar baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige tools te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ingebedde sekuriteitstoetsing-bedryfstelsel gebaseer op Ubuntu 18.04, voorafgelaai met firmware-sekuriteitstoetsing-instrumente.

## Firmware Terugrol-aanvalle & Onveilige Opdateringsmeganismes

Selfs wanneer 'n verskaffer kriptografiese handtekeningkontroles vir firmware images implementeer, word **version rollback (downgrade) protection is frequently omitted** gereeld weggelaat. Wanneer die boot- of recovery-loader slegs die handtekening verifieer met 'n embedded public key maar nie die *version* (of 'n monotonic counter) van die image wat ge-flash word vergelyk nie, kan 'n aanvaller wettiglik 'n **ouer, kwesbare firmware wat steeds 'n geldige handtekening dra** installeer en sodoende gepatchte kwesbaarhede herintroduceer.

Tipiese aanval-werkstroom:

1. **Obtain an older signed image**
   * Haal dit vanaf die verskaffer se publieke aflaaipoortaal, CDN of ondersteuningwerf.
   * Ekstraheer dit uit geassosieerde mobile/desktop toepassings (bv. binne 'n Android APK onder `assets/firmware/`).
   * Verkry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, etc.
   * Baie verbruiker-IoT-toestelle openbaar *unauthenticated* HTTP(S) endpoints wat Base64-encoded firmware blobs aanvaar, dit aan die bedienerkant decodeer en recovery/upgrade aktiveer.
3. Na die downgrade, exploit 'n kwesbaarheid wat in die nuwer vrystelling gepatch is (byvoorbeeld 'n command-injection filter wat later bygevoeg is).
4. Opsioneel flash die nuutste image terug of deaktiveer opdaterings om ontdekking te vermy sodra persistensie bereik is.

### Voorbeeld: Command Injection Na Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (downgraded) firmware word die `md5` parameter direk in 'n shell-opdrag gekoppel sonder sanitisering, wat inspuiting van arbitrêre opdragte moontlik maak (hier – enabling SSH key-based root access). Later firmware-weergawe het 'n basiese karakterfilter ingestel, maar die afwesigheid van downgrade protection maak die regstelling sinloos.

### Firmware uittrek uit mobiele apps

Baie verskaffers pak volledige firmware-beeldlêers in hul begeleidende mobiele toepassings sodat die app die toestel oor Bluetooth/Wi‑Fi kan opdateer. Hierdie pakkette word gewoonlik onversleuteld gestoor in die APK/APEX onder paaie soos `assets/fw/` of `res/raw/`. Hulpmiddels soos `apktool`, `ghidra` of selfs net `unzip` laat jou toe om getekende beelde te onttrek sonder om die fisiese hardeware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die beoordeling van update-logika

* Is die transport/authentication van die *update endpoint* behoorlik beskerm (TLS + authentication)?
* Vergelyk die toestel **version numbers** of 'n **monotonic anti-rollback counter** voordat dit ge-flash word?
* Word die image geverifieer binne 'n secure boot chain (bv. signatures deur ROM code nagegaan)?
* Voer userland code addisionele sanity checks uit (bv. allowed partition map, model number)?
* Gebruik *partial* of *backup* update-strome dieselfde validation logic?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback attacks.

## Kwetsbare firmware om op te oefen

Om te oefen met die ontdekking van kwesbaarhede in firmware, gebruik die volgende kwetsbare firmware-projekte as 'n beginpunt.

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

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
