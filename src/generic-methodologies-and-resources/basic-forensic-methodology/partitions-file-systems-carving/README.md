# पार्टिशन/फ़ाइल सिस्टम/कार्विंग

{{#include ../../../banners/hacktricks-training.md}}

## पार्टिशन

एक डिस्क में कई **पार्टिशन** हो सकते हैं: ब्लॉक्स की तार्किक रेंज, न कि भौतिक रूप से अलग स्टोरेज। पार्टिशन के शुरू होने की जगह और लंबाई **लॉजिकल सेक्टर** में मापी जाती है; यह न मानें कि हर इमेज में 512-बाइट सेक्टर होते हैं, क्योंकि 4096-बाइट लॉजिकल सेक्टर भी मौजूद हैं।<sup>[[4]](#references)</sup>

### MBR (मास्टर बूट रिकॉर्ड)

MBR पहला लॉजिकल सेक्टर (LBA 0) लेता है; इसके चार 16-बाइट पार्टिशन एंट्रीज़ बाइट 446 से शुरू होते हैं। इससे पहले के क्षेत्र में बूट कोड होता है और इसमें डिस्क सिग्नेचर भी हो सकता है।<sup>[[4]](#references)</sup>\
यह अधिकतम **4 पार्टिशन** की अनुमति देता है (इनमें से अधिकतम **सिर्फ 1** सक्रिय/**बूट करने योग्य** हो सकता है)। हालांकि, अगर आपको और पार्टिशन चाहिए, तो आप **extended partitions** इस्तेमाल कर सकते हैं। 512-बाइट वाले MBR के आखिरी **दो बाइट** बूट सिग्नेचर **0x55 0xAA** होते हैं। केवल एक पार्टिशन को सक्रिय के रूप में चिह्नित किया जा सकता है।\
512-बाइट लॉजिकल सेक्टर होने पर, MBR के 32-बिट सेक्टर फ़ील्ड एड्रेसिंग को लगभग **2 TiB** (2.2 TB) तक सीमित करते हैं।<sup>[[4]](#references)</sup>

![पार्टिशन - MBR (मास्टर बूट रिकॉर्ड): MBR अधिकतम 2.2TB की अनुमति देता है](<../../../images/image (350).png>)

![पार्टिशन - MBR (मास्टर बूट रिकॉर्ड): MBR अधिकतम 2.2TB की अनुमति देता है](<../../../images/image (304).png>)

अगर Windows इस्तेमाल किया गया है, तो MBR के **बाइट 440 से 443** में **Windows Disk Signature** मिलता है। हार्ड डिस्क का लॉजिकल ड्राइव लेटर Windows Disk Signature पर निर्भर करता है। इस सिग्नेचर को बदलने से Windows बूट नहीं हो पाएगा ([**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**।

![पार्टिशन - MBR (मास्टर बूट रिकॉर्ड): अगर Windows इस्तेमाल किया गया है, तो MBR के बाइट 440 से 443 में Windows Disk Signature मिलता है। हार्ड डिस्क का लॉजिकल ड्राइव लेटर...](<../../../images/image (310).png>)

**फ़ॉर्मैट**

| ऑफ़सेट      | लंबाई     | आइटम                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | बूट कोड           |
| 446 (0x1BE) | 16 (0x10)  | पहला पार्टिशन     |
| 462 (0x1CE) | 16 (0x10)  | दूसरा पार्टिशन    |
| 478 (0x1DE) | 16 (0x10)  | तीसरा पार्टिशन     |
| 494 (0x1EE) | 16 (0x10)  | चौथा पार्टिशन    |
| 510 (0x1FE) | 2 (0x2)    | सिग्नेचर 0x55 0xAA |

**पार्टिशन रिकॉर्ड फ़ॉर्मैट**

| ऑफ़सेट    | लंबाई   | आइटम                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | सक्रिय फ़्लैग (0x80 = बूट करने योग्य)                          |
| 1 (0x01)  | 1 (0x01) | शुरुआती हेड                                             |
| 2 (0x02)  | 1 (0x01) | शुरुआती सेक्टर (बिट 0-5); सिलिंडर के ऊपरी बिट (6- 7) |
| 3 (0x03)  | 1 (0x01) | शुरुआती सिलिंडर के सबसे निचले 8 बिट                           |
| 4 (0x04)  | 1 (0x01) | पार्टिशन टाइप कोड (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | अंतिम हेड                                               |
| 6 (0x06)  | 1 (0x01) | अंतिम सेक्टर (बिट 0-5); सिलिंडर के ऊपरी बिट (6- 7)   |
| 7 (0x07)  | 1 (0x01) | अंतिम सिलिंडर के सबसे निचले 8 बिट                             |
| 8 (0x08)  | 4 (0x04) | पार्टिशन से पहले के सेक्टर (little endian)            |
| 12 (0x0C) | 4 (0x04) | पार्टिशन में मौजूद सेक्टर                                   |

पूरी-डिस्क MBR इमेज में किसी पार्टिशन की जाँच करने के लिए, पहले उसका शुरुआती LBA और लॉजिकल सेक्टर साइज़ पता करें। `mount` में **बाइट ऑफ़सेट** दिया जाता है, LBA नहीं; नीचे दिया गया उदाहरण केवल 512-बाइट सेक्टर वाली उस इमेज के लिए सही है जिसका पार्टिशन LBA 63 से शुरू होता है। अविश्वसनीय इमेज या जर्नल वाले फ़ाइल सिस्टम के लिए, इसके बजाय [Image Acquisition & Mount](../image-acquisition-and-mount.md) में दिया गया पृथक, केवल-पढ़ने वाला वर्कफ़्लो इस्तेमाल करें।<sup>[[5]](#references)[[11]](#references)</sup>

![पार्टिशन - MBR (मास्टर बूट रिकॉर्ड): Linux में MBR माउंट करने के लिए, पहले आपको शुरुआती ऑफ़सेट पता करना होगा (आप fdisk और p कमांड इस्तेमाल कर सकते हैं)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) कंप्यूटर स्टोरेज डिवाइसों पर संग्रहीत डेटा के **ब्लॉकों का स्थान निर्दिष्ट करने** की एक आम योजना है। इसका उपयोग आमतौर पर हार्ड डिस्क ड्राइव जैसे सेकेंडरी स्टोरेज सिस्टम में होता है। LBA एक विशेष रूप से सरल रैखिक एड्रेसिंग योजना है; **ब्लॉकों का स्थान एक पूर्णांक इंडेक्स से निर्धारित होता है**। पहला ब्लॉक LBA 0, दूसरा LBA 1, और इसी तरह आगे होता है।

### GPT (GUID Partition Table)

GUID Partition Table (GPT) हर partition के लिए एक विशिष्ट GUID संग्रहीत करता है और primary तथा backup metadata का उपयोग करता है। इसका लेआउट MBR से इस प्रकार अलग है:<sup>[[4]](#references)</sup>

- **स्थान और आकार**: LBA 0 में एक **protective MBR** होता है। Primary GPT header LBA 1 पर होता है; इसके बाद partition-entry array आता है, और डिस्क के अंत में backup array और header होते हैं। GPT 64-bit LBA fields का उपयोग करता है, जबकि MBR partition entries में 32-bit LBA fields होते हैं।
- **Partition की सीमाएँ**: आम 16-KiB entry array में **128 entries, प्रत्येक 128 bytes की**, होती हैं, लेकिन entries की संख्या header में दर्ज होती है, GPT में पहले से तय नहीं होती। Addressable size logical sector size पर भी निर्भर करता है (512-byte sectors के साथ लगभग **9.4 ZB**)।<sup>[[4]](#references)</sup>
- **Partition के नाम**: अधिकतम 36 Unicode characters वाले partition नाम रखने की सुविधा देता है।

**डेटा की मज़बूती और रिकवरी**:

- **Redundancy**: MBR के विपरीत, GPT partitioning और boot data को एक ही स्थान तक सीमित नहीं रखता। यह डेटा को डिस्क पर दोहराता है, जिससे डेटा की अखंडता और मज़बूती बढ़ती है।
- **Cyclic Redundancy Check (CRC)**: Header और partition-entry array, दोनों का अपना CRC32 होता है। CRC असंगति का पता लगाता है; यह लगातार निगरानी नहीं करता और न ही स्वयं डिस्क की मरम्मत करता है। यदि primary copy अमान्य हो, तो किसी भी रिकवरी से पहले काम करने वाली कॉपी पर last LBA में backup को validate करें।<sup>[[4]](#references)</sup>

**Protective MBR (LBA0)**:

- GPT, protective MBR के ज़रिए backward compatibility बनाए रखता है। यह सुविधा legacy MBR स्थान में होती है, लेकिन इसे इस तरह बनाया गया है कि पुराने MBR-आधारित utilities GPT डिस्क को गलती से overwrite न कर सकें। इससे GPT-formatted डिस्क पर डेटा की अखंडता सुरक्षित रहती है।

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia से](https://en.wikipedia.org/wiki/GUID_Partition_Table)।<sup>[[1]](#references)</sup>

ऐसे operating systems में, जो EFI के बजाय **BIOS** services के ज़रिए **GPT-आधारित boot** का समर्थन करते हैं, पहले sector का उपयोग अब भी **bootloader** code के पहले stage को संग्रहीत करने के लिए किया जा सकता है, लेकिन इसे **GPT** **partitions** को पहचानने के लिए **बदला** जाता है। MBR में मौजूद bootloader को sector size 512 bytes मानकर नहीं चलना चाहिए।

**Partition table header (LBA 1)**

[Wikipedia से](https://en.wikipedia.org/wiki/GUID_Partition_Table)।<sup>[[1]](#references)</sup>

Partition table header डिस्क पर उपयोग किए जा सकने वाले blocks को परिभाषित करता है। यह partition table बनाने वाली partition entries की संख्या और उनका आकार भी निर्धारित करता है (table में offsets 80 और 84)।

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h या 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)little-endian machines पर) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 के लिए Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Little endian में header का आकार (bytes में, आमतौर पर 5Ch 00h 00h 00h या 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | Little endian में header का [CRC32](https://en.wikipedia.org/wiki/CRC32) (offset +0 से header size तक); गणना के दौरान यह field शून्य होता है                             |
| 20 (0x14) | 4 bytes  | Reserved; शून्य होना चाहिए                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (इस header copy का स्थान)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (दूसरी header copy का स्थान)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Partitions के लिए पहला उपयोग योग्य LBA (primary partition table का last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | आखिरी उपयोग योग्य LBA (secondary partition table का पहला LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian में Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Partition entries के array का starting LBA (primary copy में हमेशा 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Array में partition entries की संख्या                                                                                                                                         |
| 84 (0x54) | 4 bytes  | एक partition entry का आकार (आमतौर पर 80h या 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | Little endian में partition entries array का CRC32                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; block के बाकी हिस्से में शून्य होना चाहिए (512 bytes के sector size के लिए 420 bytes; बड़े sector sizes के साथ इससे अधिक हो सकता है)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | विशिष्ट partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | पहला LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | आखिरी LBA (समावेशी, आमतौर पर विषम)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (उदाहरण के लिए, bit 60 read-only दर्शाता है)                                                               |
| 56 (0x38)                   | 72 bytes | Partition का नाम (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partition Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition का नाम (36 UTF-16LE code units)](<../../../images/image (83).png>)

अधिक partition types के लिए देखें [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)।<sup>[[1]](#references)</sup>

### जाँच करना

Forensics image को [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) से mount करने के बाद, आप Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** का उपयोग करके पहला sector जाँच सकते हैं। नीचे दी गई image में **sector 0** पर एक **MBR** का पता लगाया गया और उसकी व्याख्या की गई:

![GPT (GUID Partition Table) - जाँच करना: Forensics image को ArsenalImageMounter से mount करने के बाद, आप Windows tool Active Disk Editor का उपयोग करके पहला sector जाँच सकते हैं। नीचे दी गई...](<../../../images/image (354).png>)

GPT के लिए, **LBA 1** पर primary header में _EFI PART_ signature देखें; LBA 0 में अब भी protective MBR होता है।<sup>[[4]](#references)</sup>

### सूचीबद्ध partitions के बाहर डेटा ढूँढ़ना

हटाई गई partition entry या जानबूझकर छोड़ा गया खाली स्थान, मौजूदा partition map के बाहर filesystem छोड़ सकता है। **सत्यापित raw working copy** पर, unallocated ranges की सूची बनाएँ, फिर संभावित starting LBA को filesystem के रूप में जाँचें। `mmls` और `fsstat` **sector offsets** का उपयोग करते हैं; दोनों को वास्तविक logical sector size दें। GPT metadata sectors को hidden volume न समझें।<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

यदि `fsstat` gap के प्रारंभ में filesystem की पहचान नहीं कर पाता, तो TestDisk में **Analyse → Quick Search** का उपयोग करें, और आवश्यकता पड़ने पर **Deeper Search** चलाएँ। किसी उम्मीदवार की फ़ाइलें देखने के लिए `P` दबाएँ; साक्ष्य पर **Write** न चुनें। GPT images पर `sgdisk --verify disk.img` CRC और मुख्य/बैकअप के बीच सहमति जाँचता है, लेकिन repartitioning के बाद backup header पुराना हो सकता है, इसलिए recovery से पहले filesystem structures के आधार पर उम्मीदवार सीमाओं की पुष्टि करें।<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## File-Systems

### Windows के file-systems की सूची

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system अपने मुख्य घटक—file allocation table—के इर्द-गिर्द बनाया गया है, जो volume के प्रारंभ में स्थित होती है। किसी volume में आमतौर पर **FAT की दो प्रतियाँ** होती हैं, हालांकि BPB एक प्रति की अनुमति देता है। FAT12/16 में root directory एक निश्चित क्षेत्र में होती है; FAT32 अपनी root directory को data area में, `BPB_RootClus` द्वारा निर्दिष्ट cluster पर रखता है।<sup>[[7]](#references)</sup>

Allocation unit एक **cluster** है: `BPB_BytsPerSec × BPB_SecPerClus`, जो आवश्यक नहीं कि 512 bytes हो। FAT type का निर्धारण data clusters की संख्या से होता है, न कि boot sector में मौजूद version string से। Cluster-count की सीमाएँ हैं:<sup>[[7]](#references)</sup>

- **FAT12**: 4,085 से कम data clusters।
- **FAT16**: 4,085 से 65,524 data clusters।
- **FAT32**: कम-से-कम 65,525 data clusters; cluster number के लिए प्रत्येक 32-bit FAT entry के केवल 28 bits का उपयोग होता है।

32-bit file-size field किसी सामान्य file को **2³²−1 bytes** (लगभग 4 GiB से थोड़ा कम) तक सीमित करता है।<sup>[[7]](#references)</sup>

Root directory के प्रमुख घटकों में, विशेषकर FAT12 और FAT16 के लिए, शामिल हैं:

- **File/Folder Name** (अधिकतम 8 characters)
- **Attributes**
- **Creation, Modification और Last Access की तारीखें**
- **FAT Table Address** (file के start cluster को दर्शाता है)
- **File Size**

### EXT

**Ext2** उन partitions के लिए सबसे आम file system है जिन्हें **journaling की आवश्यकता नहीं होती** (**ऐसे partitions जिनमें ज़्यादा बदलाव नहीं होते**), जैसे boot partition। **Ext3/4** में **journaling** होता है और आमतौर पर इनका उपयोग **बाकी partitions** के लिए किया जाता है।

## **Metadata**

कुछ files में metadata होता है। यह जानकारी file की सामग्री के बारे में होती है और कभी-कभी किसी analyst के लिए उपयोगी हो सकती है। File type के आधार पर इसमें ऐसी जानकारी हो सकती है:

- Title
- उपयोग किया गया MS Office Version
- Author
- Creation और last modification की तारीखें
- Camera का Model
- GPS coordinates
- Image की जानकारी

किसी file का metadata पाने के लिए [**exiftool**](https://exiftool.org) और [**Metadiver**](https://www.easymetadata.com/metadiver-2/) जैसे tools का उपयोग कर सकते हैं।

## **Deleted Files की Recovery**

### Logged Deleted Files

जैसा कि पहले देखा गया, file के "deleted" होने के बाद भी कई जगहों पर वह सुरक्षित रह सकती है। ऐसा इसलिए है क्योंकि आमतौर पर file system से file हटाने पर उसे केवल deleted के रूप में चिह्नित किया जाता है, जबकि data को छुआ नहीं जाता। इसलिए files की registries (जैसे MFT) की जाँच करके deleted files ढूँढ़ना संभव है।<sup>[[2]](#references)</sup>

इसके अलावा, OS आमतौर पर file system में हुए बदलावों और backups के बारे में बहुत-सी जानकारी सहेजता है। इसलिए file या उसकी यथासंभव अधिक जानकारी recover करने के लिए इनका उपयोग करने की कोशिश की जा सकती है।

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ऐसी तकनीक है जो **bulk data में files ढूँढ़ने** का प्रयास करती है। इस तरह के tools काम करने के 3 मुख्य तरीके हैं: **file types के headers और footers के आधार पर**, file types की **structures के आधार पर**, और स्वयं **content के आधार पर**।

साधारण header/footer carving यह मानती है कि blocks लगातार जुड़े हुए हैं और file के खंडित होने पर केवल उसका एक fragment दे सकती है। यह पूर्ण सीमा नहीं है: PhotoRec में कुछ खंडित JPEGs के लिए CPU-intensive **Paranoid → bruteforce** विकल्प है, जबकि format-aware fragment reassembly अन्य समर्थित types को recover कर सकता है। वर्तमान fragment-reassembly workflow के लिए [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) देखें।<sup>[[8]](#references)</sup>

File carving के लिए कई tools उपलब्ध हैं; इनमें उन file types को निर्दिष्ट किया जा सकता है जिन्हें आप ढूँढ़ना चाहते हैं।

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving के समान है, लेकिन **पूरी files ढूँढ़ने के बजाय, यह जानकारी के दिलचस्प fragments ढूँढ़ता है**।\
उदाहरण के लिए, logged URLs वाली पूरी file ढूँढ़ने के बजाय, यह तकनीक URLs खोजेगी।

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

ज़ाहिर है, files और उनसे जुड़े logs के कुछ हिस्सों को **"securely" delete** करने के तरीके मौजूद हैं। उदाहरण के लिए, किसी file के **content को कई बार junk data से overwrite** करना, फिर उस file के बारे में **$MFT** और **$LOGFILE** से **logs हटाना**, और **Volume Shadow Copies हटाना** संभव है।<sup>[[3]](#references)</sup>\
आप देख सकते हैं कि यह कार्रवाई करने के बाद भी **अन्य जगहों पर file के अस्तित्व के logs मौजूद हो सकते हैं**। यह सही है, और उन्हें ढूँढ़ना forensics professional के काम का हिस्सा है।

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [हटाई गई files के साक्ष्य के लिए NTFS $I30 (directory) entries को कैसे scan करें](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI specification: GPT disk layout](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit mmls manual](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit fsstat manual](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft FAT specification](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec recovery options](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk से deleted partition की recovery](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk manual](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8) manual](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
