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


Firmware ni programu muhimu inayowezesha vifaa kufanya kazi vizuri kwa kusimamia na kuwezesha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji wanazitumia. Imehifadhiwa katika kumbukumbu ya kudumu, ikihakikisha kifaa kinaweza kupata maagizo muhimu tangu linapowashwa, na kusababisha uzinduzi wa operating system. Kuchunguza na labda kubadilisha firmware ni hatua muhimu katika kubaini udhaifu wa usalama.

## **Kukusanya Taarifa**

**Kukusanya taarifa** ni hatua muhimu ya mwanzo kwa kuelewa muundo wa kifaa na teknolojia zinazotumika. Mchakato huu unajumuisha kukusanya data kuhusu:

- Architecture ya CPU na operating system inayoendesha
- Bootloader specifics
- Muundo wa hardware na datasheets
- Metriki za codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Rekodi za masasisho na vyeti vya udhibiti
- Mchoro wa miundo na mtiririko
- Tathmini za usalama na udhaifu uliobainishwa

Kwa madhumuni haya, open-source intelligence (OSINT) tools ni muhimu sana, kama vile uchanganuzi wa vipengele vya programu vinavyopatikana kwa chanzo wazi kupitia ukaguzi wa mikono na wa moja kwa moja. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa static analysis ya bure ambayo inaweza kutumika kutafuta matatizo yanayowezekana.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na ngazi yake ya ugumu:

- **Directly** kutoka kwa chanzo (developers, manufacturers)
- **Building** kutoka kwa maelekezo yaliyotolewa
- **Downloading** kutoka kwenye tovuti za msaada rasmi
- Kutumia **Google dork** queries kutafuta faili za firmware zilizo mwenyeji
- Kupata **cloud storage** moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kupatanisha **updates** kupitia man-in-the-middle techniques
- **Extracting** kutoka kwenye kifaa kupitia muunganisho kama **UART**, **JTAG**, au **PICit**
- **Sniffing** kwa ajili ya ombi za update ndani ya mawasiliano ya kifaa
- Kutambua na kutumia **hardcoded update endpoints**
- **Dumping** kutoka kwa bootloader au mtandao
- **Removing and reading** the storage chip, wakati yote mengine yanashindwa, kwa kutumia vifaa vya vifaa vinavyofaa

## Analyzing the firmware

Sasa unapokuwa na firmware, unahitaji kutoa taarifa kuhusu ili kujua jinsi ya kuitibu. Zana tofauti unaweza kutumia kwa hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) kuchunguza file.

### Kupata Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Utoaji wa filesystem kwa mikono

Sometimes, binwalk will **not have the magic byte of the filesystem in its signatures**. In these cases, use binwalk to **find the offset of the filesystem and carve the compressed filesystem** from the binary and **manually extract** the filesystem according to its type using the steps below.
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
Mbali na hayo, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (ililotumika katika mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitawekwa katika saraka ya `squashfs-root` baadaye.

- Kwa faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystems za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystems za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na vulnerabilities zinazoweza kuwepo. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data muhimu kutoka kwenye firmware image.

### Zana za Uchambuzi wa Awali

Seti ya amri zimetolewa kwa ukaguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kutambua aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa maelezo ya partition na filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Ili kutathmini hali ya usimbaji ya image, **entropy** inakaguliwa kwa kutumia `binwalk -E <bin>`. Entropy ya chini inaashiria ukosefu wa usimbaji, wakati entropy ya juu inaonyesha uwezekano wa usimbaji au ukandaji.

Kwa kutoa **embedded files**, zana na rasilimali kama nyaraka za **file-data-carving-recovery-tools** na **binvis.io** kwa uchunguzi wa faili zinapendekezwa.

### Kutoa mfumo wa faili

Kwa kutumia `binwalk -ev <bin>`, kawaida unaweza kutoa filesystem, mara nyingi ndani ya saraka iitwayo kwa jina la aina ya filesystem (mfano, squashfs, ubifs). Hata hivyo, pale **binwalk** inaposhindwa kutambua aina ya filesystem kwa sababu ya kukosekana kwa magic bytes, uondoaji kwa mkono unahitajika. Hii inahusisha kutumia `binwalk` kutafuta offset ya filesystem, ikifuatiwa na amri ya `dd` kutoa filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (mfano, squashfs, cpio, jffs2, ubifs), amri tofauti zinatumiwa kutoa yaliyomo kwa mikono.

### Filesystem Analysis

Mara filesystem ikitolewa, utafutaji wa dosari za usalama unaanza. Kipaumbele kinatolewa kwa network daemons zisizo salama, hardcoded credentials, API endpoints, functionalities za update server, code isiyochakachwa, startup scripts, na compiled binaries kwa uchunguzi wa offline.

**Key locations** na **items** za kukagua ni pamoja na:

- **etc/shadow** na **etc/passwd** kwa credentials za watumiaji
- SSL certificates na keys katika **etc/ssl**
- Configuration na script files kwa utegemezi wa udhaifu
- Embedded binaries kwa uchunguzi zaidi
- Common IoT device web servers na binaries

Zana kadhaa husaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi wa kina wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), na [**EMBA**](https://github.com/e-m-b-a/emba) kwa static na dynamic analysis

### Security Checks on Compiled Binaries

Pamoja na source code, compiled binaries zilizopatikana katika filesystem lazima zichunguzwe kwa udhaifu. Zana kama **checksec.sh** kwa Unix binaries na **PESecurity** kwa Windows binaries husaidia kubaini binaries zisizo salama ambazo zinaweza kutumiwa.

## Emulating Firmware for Dynamic Analysis

Mchakato wa kuiga firmware unaruhusu **dynamic analysis** ya uendeshaji wa kifaa au programu maalum. Njia hii inaweza kukumbana na changamoto za utegemezi wa vifaa au usanifu, lakini kusafirisha root filesystem au binaries maalum kwenda kifaa chenye usanifu na endianness vinavyolingana, kama Raspberry Pi, au kwenda virtual machine iliyojengwa awali, kunaweza kuwezesha upimaji zaidi.

### Emulating Individual Binaries

Kwa kuchunguza programu za mtu mmoja mmoja, kutambua endianness ya programu na CPU architecture ni muhimu.

#### Example with MIPS Architecture

Ili kuiga binary ya usanifu wa MIPS, mtu anaweza kutumia amri:
```bash
file ./squashfs-root/bin/busybox
```
Na kusakinisha zana muhimu za uigaji:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` inatumiwa, na kwa binaries za little-endian, chaguo ni `qemu-mipsel`.

#### Uiga wa ARM

Kwa binaries za ARM, mchakato ni sawa, na emulator `qemu-arm` hutumika kwa uiga.

### Uiga wa Mfumo Kamili

Vifaa kama [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), na vingine, vinasaidia uiga kamili wa firmware, kuendesha mchakato kwa kiotomatiki na kusaidia katika uchambuzi wa wakati wa utekelezaji.

## Uchambuzi wa Wakati wa Utekelezaji Katika Vitendo

Katika hatua hii, mazingira ya kifaa halisi au yaliyouigizwa yanatumika kwa uchambuzi. Ni muhimu kudumisha ufikiaji wa shell kwa OS na filesystem. Emulation inaweza isilingane kabisa na mwingiliano wa hardware, hivyo mara kwa mara inaweza kuhitaji kuanzishwa upya. Uchambuzi unapaswa kurudia filesystem, exploit webpages na network services zilizofunguliwa, na kuchunguza udhaifu wa bootloader. Majaribio ya uadilifu wa firmware ni muhimu kubaini uwezekano wa backdoor vulnerabilities.

## Mbinu za Uchambuzi za Runtime

Uchambuzi wa runtime unahusisha kuingiliana na mchakato au binary katika mazingira yake ya uendeshaji, kwa kutumia zana kama gdb-multiarch, Frida, na Ghidra kuweka breakpoints na kubaini vulnerabilities kupitia fuzzing na mbinu nyingine.

## Binary Exploitation and Proof-of-Concept

Kuendeleza PoC kwa vulnerabilities zilizotambuliwa kunahitaji uelewa wa kina wa architecture lengwa na uandishi wa programu kwa lugha za chini. Binary runtime protections katika embedded systems ni nadra, lakini pale zinapokuwepo, mbinu kama Return Oriented Programming (ROP) zinaweza kuwa muhimu.

## Prepared Operating Systems for Firmware Analysis

Mifumo ya uendeshaji kama [AttifyOS](https://github.com/adi0x90/attifyos) na [EmbedOS](https://github.com/scriptingxss/EmbedOS) hutoa mazingira yaliyoandaliwa mapema kwa jaribio la usalama wa firmware, yakiwa na zana zote zinazohitajika.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS ni distro inayolenga kukusaidia kufanya security assessment na penetration testing ya vifaa vya Internet of Things (IoT). Inakuhifadhi muda kwa kutoa mazingira yaliyoandaliwa tayari na zana zote muhimu zimewekwa.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Hata pale muuzaji anapotekeleza ukaguzi wa saini za cryptographic kwa firmware images, **version rollback (downgrade) protection is frequently omitted**. Wakati boot- au recovery-loader inathibitisha tu saini kwa kutumia embedded public key lakini haisi kulinganisha *version* (au monotonic counter) ya image inayoflashiwa, mshambuliaji anaweza kwa halali kusanidi na kuflash **older, vulnerable firmware that still bears a valid signature** na hivyo kuirudisha tena vulnerabilities zilizotengenezwa.

Mfano wa mchakato wa shambulio wa kawaida:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Mfano: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo hatarini (downgraded), parameter `md5` imeunganishwa moja kwa moja ndani ya shell command bila kusafishwa, ikiruhusu injection ya amri zisizo na adhabu (hapa – kuwezesha SSH key-based root access). Toleo la baadaye la firmware liliingiza chujio la msingi la herufi, lakini kukosekana kwa ulinzi dhidi ya downgrade hufanya suluhisho hilo kuwa batili.

### Kuchota Firmware kutoka kwa Apps za Mkononi

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya programu zao za kuambatana za mkononi ili app iweze kusasisha kifaa kupitia Bluetooth/Wi-Fi. Vifurushi hivi mara nyingi huhifadhiwa bila kusimbwa ndani ya APK/APEX chini ya njia kama `assets/fw/` au `res/raw/`. Zana kama `apktool`, `ghidra`, au hata plain `unzip` zinakuwezesha kutoa signed images bila kugusa vifaa vya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya ukaguzi ya mantiki ya usasishaji

* Je, usafirishaji/uthibitishaji wa *update endpoint* umehifadhiwa ipasavyo (TLS + authentication)?
* Je, kifaa kinalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya ku-flash?
* Je, image inathibitishwa ndani ya secure boot chain (mfano: signatures zinakaguliwa na ROM code)?
* Je, userland code inafanya ukaguzi wa ziada wa mantiki (mfano: allowed partition map, model number)?
* Je, mtiririko wa masasisho *partial* au *backup* unatumia tena mantiki ile ile ya uthibitishaji?

> 💡  Ikiwa mojawapo ya yaliyotajwa hapo juu inakosekana, jukwaa lina uwezekano mkubwa wa kuwa dhaifu kwa rollback attacks.

## Vulnerable firmware to practice

To practice discovering vulnerabilities in firmware, use the following vulnerable firmware projects as a starting point.

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

## References

- [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [Exploiting zero days in abandoned hardware – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)

## Mafunzo na Cheti

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{{#include ../../banners/hacktricks-training.md}}
