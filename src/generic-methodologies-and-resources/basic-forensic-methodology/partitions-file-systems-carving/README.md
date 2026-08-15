# पार्टिशन/फ़ाइल सिस्टम/Carving

{{#include ../../../banners/hacktricks-training.md}}

## पार्टिशन

किसी hard drive या **SSD disk में data को physically अलग करने के उद्देश्य से अलग-अलग partitions हो सकते हैं**।\
Disk की **minimum** unit **sector** होती है (आमतौर पर यह 512B की बनी होती है)। इसलिए, प्रत्येक partition का size इस size का multiple होना चाहिए।

### MBR (master Boot Record)

यह **boot code के 446B के बाद disk के पहले sector** में allocate होता है। यह sector PC को यह बताने के लिए आवश्यक है कि कौन-सा partition mount किया जाना चाहिए और कहाँ से।\
यह अधिकतम **4 partitions** की अनुमति देता है (अधिकतम **केवल 1** active/**bootable** हो सकता है)। हालांकि, यदि आपको अधिक partitions की आवश्यकता हो, तो आप **extended partitions** का उपयोग कर सकते हैं। इस first sector का **final byte**, boot record signature **0x55AA** होता है। केवल एक partition को active के रूप में mark किया जा सकता है।\
MBR अधिकतम **2.2TB** की अनुमति देता है।

![Partitions - MBR (master Boot Record): MBR अधिकतम 2.2TB की अनुमति देता है](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR अधिकतम 2.2TB की अनुमति देता है](<../../../images/image (304).png>)

MBR के **bytes 440 से 443** में आप **Windows Disk Signature** पा सकते हैं (यदि Windows का उपयोग किया गया हो)। Hard disk का logical drive letter Windows Disk Signature पर निर्भर करता है। इस signature को बदलने से Windows boot होने से रुक सकता है (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**।

![Partitions - MBR (master Boot Record): MBR के bytes 440 से 443 में आप Windows Disk Signature पा सकते हैं (यदि Windows का उपयोग किया गया हो)। Hard disk का logical drive letter...](<../../../images/image (310).png>)

**फ़ॉर्मेट**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Partition Record Format**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Active flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start head                                             |
| 2 (0x02)  | 1 (0x01) | Start sector (bits 0-5); upper bits of cylinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Start cylinder lowest 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partition type code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End head                                               |
| 6 (0x06)  | 1 (0x01) | End sector (bits 0-5); upper bits of cylinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | End cylinder lowest 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sectors preceding partition (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sectors in partition                                   |

Linux में MBR को mount करने के लिए पहले आपको start offset प्राप्त करना होगा (आप `fdisk` और `p` command का उपयोग कर सकते हैं)

![Partitions - MBR (master Boot Record): Linux में MBR को mount करने के लिए पहले आपको start offset प्राप्त करना होगा (आप fdisk और p command का उपयोग कर सकते हैं)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

और फिर निम्नलिखित code का उपयोग करें
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) कंप्यूटर storage devices, विशेष रूप से hard disk drives जैसे secondary storage systems पर संग्रहीत data के **blocks का location निर्दिष्ट करने** के लिए उपयोग की जाने वाली एक सामान्य scheme है। LBA एक विशेष रूप से सरल linear addressing scheme है; **blocks को integer index द्वारा locate किया जाता है**, जिसमें पहला block LBA 0, दूसरा LBA 1 और इसी प्रकार आगे होता है।

### GPT (GUID Partition Table)

GUID Partition Table, जिसे GPT के नाम से जाना जाता है, MBR (Master Boot Record) की तुलना में अपनी enhanced capabilities के कारण पसंद की जाती है। Partitions के लिए अपने **globally unique identifier** के कारण GPT कई तरीकों से अलग है:

- **Location और Size**: GPT और MBR दोनों **sector 0** से शुरू होते हैं। हालांकि, GPT **64bits** पर काम करता है, जबकि MBR 32bits पर।
- **Partition Limits**: GPT Windows systems पर अधिकतम **128 partitions** support करता है और **9.4ZB** तक data accommodate करता है।
- **Partition Names**: यह partitions को अधिकतम 36 Unicode characters का नाम देने की सुविधा प्रदान करता है।

**Data Resilience और Recovery**:

- **Redundancy**: MBR के विपरीत, GPT partitioning और boot data को केवल एक स्थान तक सीमित नहीं रखता। यह data को disk पर replicate करता है, जिससे data integrity और resilience बेहतर होती है।
- **Cyclic Redundancy Check (CRC)**: GPT data integrity सुनिश्चित करने के लिए CRC का उपयोग करता है। यह data corruption की सक्रिय रूप से निगरानी करता है और corruption मिलने पर GPT किसी अन्य disk location से corrupted data recover करने का प्रयास करता है।

**Protective MBR (LBA0)**:

- GPT protective MBR के माध्यम से backward compatibility बनाए रखता है। यह feature legacy MBR space में रहता है, लेकिन इसे इस तरह design किया गया है कि पुराने MBR-based utilities गलती से GPT disks को overwrite न कर दें। इस प्रकार GPT-formatted disks पर data integrity सुरक्षित रहती है।

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Wikipedia से](https://en.wikipedia.org/wiki/GUID_Partition_Table)।<sup>[[1]](#references)</sup>

उन operating systems में जो EFI के बजाय **BIOS** services के माध्यम से **GPT-based boot** support करते हैं, first sector का उपयोग अभी भी **bootloader** code के first stage को store करने के लिए किया जा सकता है, लेकिन इसे **GPT** **partitions** को recognize करने के लिए **modified** किया जाता है। MBR में मौजूद bootloader को sector size को 512 bytes मानकर नहीं चलना चाहिए।

**Partition table header (LBA 1)**

[Wikipedia से](https://en.wikipedia.org/wiki/GUID_Partition_Table)।<sup>[[1]](#references)</sup>

Partition table header disk पर usable blocks को define करता है। यह partition entries की संख्या और size भी define करता है, जो partition table बनाती हैं (table में offsets 80 और 84)।

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h या 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)little-endian machines पर) |
| 8 (0x08)  | 4 bytes  | UEFI 2.8 के लिए Revision 1.0 (00h 00h 01h 00h)                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size little endian में (bytes में, सामान्यतः 5Ch 00h 00h 00h या 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | Header का [CRC32](https://en.wikipedia.org/wiki/CRC32) (offset +0 से header size तक) little endian में, calculation के दौरान यह field zeroed होती है                             |
| 20 (0x14) | 4 bytes  | Reserved; zero होना चाहिए                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (इस header copy का location)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (दूसरी header copy का location)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Partitions के लिए first usable LBA (primary partition table का last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table का first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Mixed endian में Disk GUID                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Partition entries की array का starting LBA (primary copy में हमेशा 2)                                                                                                     |
| 80 (0x50) | 4 bytes  | Array में partition entries की संख्या                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Single partition entry का size (सामान्यतः 80h या 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | Partition entries array का CRC32 little endian में                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; block के शेष भाग के लिए zeroes होना चाहिए (512 bytes के sector size पर 420 bytes; लेकिन बड़े sector sizes के साथ अधिक हो सकता है)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, सामान्यतः odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (उदाहरण के लिए bit 60 read-only दर्शाता है)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

अधिक partition types [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table) में हैं।<sup>[[1]](#references)</sup>

### Inspecting

[**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) के साथ forensics image को mount करने के बाद, आप Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** का उपयोग करके first sector inspect कर सकते हैं। निम्न image में **sector 0** पर एक **MBR** detect और interpret किया गया:

![GPT (GUID Partition Table) - Inspecting: ArsenalImageMounter के साथ forensics image को mount करने के बाद, आप Windows tool Active Disk Editor का उपयोग करके first sector inspect कर सकते हैं। निम्न...](<../../../images/image (354).png>)

यदि यह MBR के बजाय **GPT table** होती, तो **sector 1** में _EFI PART_ signature दिखाई देनी चाहिए थी (जो पिछली image में empty है)।

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system अपने core component, file allocation table, के इर्द-गिर्द design किया गया है, जो volume के आरंभ में स्थित होती है। यह system table की **दो copies** maintain करके data को सुरक्षित रखता है, ताकि एक copy corrupt होने पर भी data integrity बनी रहे। Table और root folder को **fixed location** पर होना आवश्यक है, जो system की startup process के लिए महत्वपूर्ण है।

File system की basic storage unit एक **cluster, सामान्यतः 512B**, होती है, जिसमें कई sectors शामिल होते हैं। FAT समय के साथ इन versions में विकसित हुआ:

- **FAT12**, जो 12-bit cluster addresses support करता है और अधिकतम 4078 clusters (UNIX के साथ 4084) handle करता है।
- **FAT16**, जिसमें 16-bit addresses के कारण अधिकतम 65,517 clusters accommodate किए जा सकते हैं।
- **FAT32**, जिसमें 32-bit addresses के कारण प्रत्येक volume पर प्रभावशाली 268,435,456 clusters की अनुमति है।

सभी FAT versions की एक महत्वपूर्ण limitation **4GB maximum file size** है, जो file size store करने के लिए उपयोग किए जाने वाले 32-bit field द्वारा imposed है।

Root directory के प्रमुख components, विशेष रूप से FAT12 और FAT16 के लिए, इनमें शामिल हैं:

- **File/Folder Name** (अधिकतम 8 characters)
- **Attributes**
- **Creation, Modification, और Last Access Dates**
- **FAT Table Address** (file के start cluster को दर्शाता है)
- **File Size**

### EXT

**Ext2** **not journaling** partitions (**ऐसे partitions जिनमें अधिक बदलाव नहीं होते**) के लिए सबसे common file system है, जैसे boot partition। **Ext3/4** **journaling** हैं और सामान्यतः **बाकी partitions** के लिए उपयोग किए जाते हैं।

## **Metadata**

कुछ files में metadata होता है। यह information file के content से संबंधित होती है और analyst के लिए कभी-कभी interesting हो सकती है, क्योंकि file type के आधार पर इसमें निम्न information हो सकती है:

- Title
- उपयोग किया गया MS Office Version
- Author
- Creation और last modification की Dates
- Camera का Model
- GPS coordinates
- Image information

किसी file का metadata प्राप्त करने के लिए आप [**exiftool**](https://exiftool.org) और [**Metadiver**](https://www.easymetadata.com/metadiver-2/) जैसे tools का उपयोग कर सकते हैं।

## **Deleted Files Recovery**

### Logged Deleted Files

जैसा पहले देखा गया है, कई स्थान ऐसे होते हैं जहां file "deleted" होने के बाद भी saved रहती है। ऐसा इसलिए है क्योंकि सामान्यतः file system से file deletion केवल उसे deleted के रूप में mark करता है, लेकिन data को touch नहीं करता। इसके बाद files की registries (जैसे MFT) inspect करके deleted files ढूंढना संभव होता है।<sup>[[2]](#references)</sup>

OS सामान्यतः file system changes और backups के बारे में बहुत-सी information भी save करता है, इसलिए file या जितनी संभव हो उतनी information recover करने के लिए उनका उपयोग करने का प्रयास किया जा सकता है।

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** एक ऐसी technique है जो **data के bulk में files ढूंढने** का प्रयास करती है। इस प्रकार के tools के काम करने के 3 मुख्य तरीके हैं: **file types के headers और footers पर आधारित**, file types की **structures** पर आधारित और स्वयं **content** पर आधारित।

ध्यान दें कि यह technique **fragmented files को retrieve करने के लिए काम नहीं करती**। यदि कोई file **contiguous sectors में stored नहीं है**, तो यह technique उसे या कम-से-कम उसके किसी भाग को find नहीं कर पाएगी।

ऐसे कई tools हैं जिनका उपयोग आप File Carving के लिए कर सकते हैं और उन file types को specify कर सकते हैं जिन्हें आप search करना चाहते हैं।


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving, File Carving के समान है, लेकिन **complete files ढूंढने के बजाय, यह information के interesting fragments ढूंढता है**।\
उदाहरण के लिए, logged URLs वाली complete file ढूंढने के बजाय, यह technique URLs search करेगी।

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

स्वाभाविक रूप से, files और उनसे संबंधित logs के कुछ भाग को **"securely" delete** करने के तरीके होते हैं। उदाहरण के लिए, किसी file के **content को junk data से कई बार overwrite** करना, फिर उस file से संबंधित **$MFT** और **$LOGFILE** के **logs** को **remove** करना और **Volume Shadow Copies को remove** करना संभव है।<sup>[[3]](#references)</sup>\
आप देख सकते हैं कि यह action करने के बाद भी ऐसे **अन्य parts हो सकते हैं जहां file का existence अभी भी logged हो**, और यह सही है। Forensics professional के काम का एक भाग उन्हें ढूंढना है।

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [NTFS $I30 (directory) entries को deleted files के evidence के लिए scan कैसे करें](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
