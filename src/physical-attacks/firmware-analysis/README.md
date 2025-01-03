# Firmware Analise

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur die kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang kan verkry tot noodsaaklike instruksies vanaf die oomblik dat dit aangeskakel word, wat lei tot die bekendstelling van die bedryfstelsel. Om firmware te ondersoek en moontlik te wysig, is 'n kritieke stap in die identifisering van sekuriteitskwesbaarhede.

## **Inligting Versameling**

**Inligting versameling** is 'n kritieke aanvanklike stap in die begrip van 'n toestel se samestelling en die tegnologieë wat dit gebruik. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en bedryfstelsel wat dit loop
- Bootloader-spesifikasies
- Hardeware-opstelling en datasheets
- Kodebasis-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenisse en regulerende sertifikate
- Argitektoniese en vloediagramme
- Sekuriteitsassessering en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **oopbron intelligensie (OSINT)** gereedskap van onskatbare waarde, sowel as die analise van enige beskikbare oopbron sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Gereedskap soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële probleme te vind.

## **Die Firmware Verkryging**

Die verkryging van firmware kan op verskillende maniere benader word, elk met sy eie vlak van kompleksiteit:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- **Bou** dit volgens verskafde instruksies
- **Laai** dit af van amptelike ondersteuningswebwerwe
- Gebruik **Google dork** navrae om gehoste firmware-lêers te vind
- Toegang tot **cloud storage** direk, met gereedskap soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interseptering van **opdaterings** via man-in-the-middle tegnieke
- **Ekstraksie** van die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** vir opdateringsversoeke binne toestelkommunikasie
- Identifisering en gebruik van **hardcoded opdatering eindpunte**
- **Dumping** van die bootloader of netwerk
- **Verwydering en lees** van die stoorchip, wanneer alles anders misluk, met toepaslike hardeware gereedskap

## Analisering van die firmware

Nou dat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te behandel. Verskillende gereedskap wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
As jy nie veel met daardie gereedskap vind nie, kyk na die **entropy** van die beeld met `binwalk -E <bin>`, as die entropy laag is, is dit waarskynlik nie geënkripteer nie. As die entropy hoog is, is dit waarskynlik geënkripteer (of op een of ander manier gecomprimeer).

Boonop kan jy hierdie gereedskap gebruik om **lêers wat in die firmware ingebed is** te onttrek:

{{#ref}}
../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Verkryging van die Lêerstelsel

Met die vorige genoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêerstelsel** te **onttrek**.\
Binwalk onttrek dit gewoonlik binne 'n **map wat as die lêerstelseltipe genoem word**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige Lêerstelsel Onttrekking

Soms sal binwalk **nie die magiese byte van die lêerstelsel in sy handtekeninge hê nie**. In hierdie gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die gecomprimeerde lêerstelsel** uit die binêre te sny en die lêerstelsel **handmatig te onttrek** volgens sy tipe met die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel te sny.
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

Lêers sal in die "`squashfs-root`" gids wees daarna.

- CPIO argief lêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2 lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Analise van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware beeld te analiseer en te onttrek.

### Begin Analise Gereedskap

'n Stel opdragte word verskaf vir die aanvanklike inspeksie van die binêre lêer (verwys na `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te analiseer, en die partisie en lêerstelsel besonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die versleutelingstatus van die beeld te evalueer, word die **entropy** nagegaan met `binwalk -E <bin>`. Lae entropy dui op 'n gebrek aan versleuteling, terwyl hoë entropy moontlike versleuteling of kompressie aandui.

Vir die onttrekking van **ingebedde lêers**, word gereedskap en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die Lêerstelsel

Met `binwalk -ev <bin>` kan 'n mens gewoonlik die lêerstelsel onttrek, dikwels in 'n gids wat na die lêerstelseltipe genoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe kan herken weens ontbrekende magic bytes nie, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelseloffset te lokaliseer, gevolg deur die `dd` opdrag om die lêerstelsel uit te sny:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangende van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig te onttrek.

### Lêerstelselanalise

Met die lêerstelsel onttrek, begin die soektog na sekuriteitsfoute. Aandag word gegee aan onveilige netwerkdaemons, hardgecodeerde akrediteerbesonderhede, API-eindpunte, opdateringsbedienerfunksies, nie-gecompileerde kode, opstartskripte, en gecompileerde binêre vir offlinanalise.

**Belangrike plekke** en **items** om te ondersoek sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersakrediteerbesonderhede
- SSL sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir potensiële kwesbaarhede
- Ingebedde binêre vir verdere analise
- Algemene IoT-toestel webbedieners en binêre

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitiewe inligting soektog
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese analise

### Sekuriteitskontroles op Gecompileerde Binêre

Sowel die bronkode as gecompileerde binêre wat in die lêerstelsel gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix binêre en **PESecurity** vir Windows binêre help om onbeskermde binêre te identifiseer wat uitgebuit kan word.

## Emulering van Firmware vir Dynamiese Analise

Die proses van emulering van firmware stel **dynamiese analise** in staat van 'n toestel se werking of 'n individuele program. Hierdie benadering kan uitdagings ondervind met hardeware of argitektuurafhanklikhede, maar die oordrag van die wortellêerstelsel of spesifieke binêre na 'n toestel met ooreenstemmende argitektuur en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtuele masjien, kan verdere toetsing fasiliteer.

### Emulering van Individuele Binêre

Vir die ondersoek van enkele programme, is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS Argitektuur

Om 'n MIPS argitektuur binêre te emuleer, kan 'n mens die opdrag gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-instrumente te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sou `qemu-mipsel` die keuse wees.

#### ARM Argitektuur Emulasie

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat gebruik word vir emulasie.

### Volle Stelsel Emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, fasiliteer volle firmware emulasie, wat die proses outomatiseer en help met dinamiese analise.

## Dinamiese Analise in Praktyk

Op hierdie stadium word 'n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en lêerstelsel te handhaaf. Emulasie mag nie perfek hardeware-interaksies naboots nie, wat af en toe emulasie-herstart vereis. Analise moet die lêerstelsel herbesoek, blootgestelde webbladsye en netwerkdienste benut, en opstartlader kwesbaarhede verken. Firmware integriteitstoetse is krities om potensiële agterdeur kwesbaarhede te identifiseer.

## Tydren Analise Tegnieke

Tydren analise behels interaksie met 'n proses of binary in sy bedryfsomgewing, met behulp van gereedskap soos gdb-multiarch, Frida, en Ghidra om breekpunte in te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

## Binary Exploitatie en Bewys-van-Konsep

Om 'n PoC vir geïdentifiseerde kwesbaarhede te ontwikkel, vereis 'n diep begrip van die teikenargitektuur en programmering in laervlak tale. Binary tydren beskermings in ingebedde stelsels is skaars, maar wanneer dit teenwoordig is, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware Analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware sekuriteitstoetsing, toegerus met nodige gereedskap.

## Voorbereide OS's om Firmware te analiseer

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro wat bedoel is om jou te help om sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT) toestelle uit te voer. Dit spaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige gereedskap te bied.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ingebedde sekuriteitstoetsing bedryfstelsel gebaseer op Ubuntu 18.04 wat vooraf gelaai is met firmware sekuriteitstoetsing gereedskap.

## Kwetsbare firmware om te oefen

Om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmware projekte as 'n beginpunt.

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

## Ver
