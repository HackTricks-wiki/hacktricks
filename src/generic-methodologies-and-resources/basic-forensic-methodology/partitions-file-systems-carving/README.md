# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

A hard drive or an **SSD disk can contain different partitions** with the goal of separating data physically.\
The **minimum** unit of a disk is the **sector** (normally composed of 512B). So, each partition size needs to be multiple of that size.

### MBR (master Boot Record)

It's allocated in the **first sector of the disk after the 446B of the boot code**. This sector is essential to indicate to the PC what and from where a partition should be mounted.\
It allows up to **4 partitions** (at most **just 1** can be active/**bootable**). However, if you need more partitions you can use **extended partitions**. The **final byte** of this first sector is the boot record signature **0x55AA**. Only one partition can be marked as active.\
MBR allows **max 2.2TB**.

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR allows max 2.2TB](<../../../images/image (304).png>)

From the **bytes 440 to the 443** of the MBR you can find the **Windows Disk Signature** (if Windows is used). The logical drive letter of the hard disk depends on the Windows Disk Signature. Changing this signature could prevent Windows from booting (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): From the bytes 440 to the 443 of the MBR you can find the Windows Disk Signature (if Windows is used). The logical drive letter of the hard disk...](<../../../images/image (310).png>)

**Format**

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

In order to mount an MBR in Linux you first need to get the start offset (you can use `fdisk` and the `p` command)

![Partitions - MBR (master Boot Record): In order to mount an MBR in Linux you first need to get the start offset (you can use fdisk and the p command)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

And then use the following code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ni mpangilio wa kawaida unaotumika kwa **kubainisha eneo la blocks** za data zilizohifadhiwa kwenye vifaa vya kuhifadhia data vya kompyuta, kwa ujumla mifumo ya secondary storage kama hard disk drives. LBA ni mpangilio rahisi wa linear addressing; **blocks hupatikana kwa index ya integer**, ambapo block ya kwanza ni LBA 0, ya pili LBA 1, na kadhalika.

### GPT (GUID Partition Table)

GUID Partition Table, inayojulikana kama GPT, hupendelewa kwa uwezo wake ulioimarishwa ikilinganishwa na MBR (Master Boot Record). Ikiwa na **globally unique identifier** kwa partitions, GPT inaonekana kwa njia kadhaa:

- **Eneo na Ukubwa**: GPT na MBR zote huanza kwenye **sector 0**. Hata hivyo, GPT hutumia **64bits**, tofauti na 32bits za MBR.
- **Mipaka ya Partitions**: GPT inasaidia hadi **128 partitions** kwenye Windows systems na inaweza kuhifadhi hadi **9.4ZB** za data.
- **Majina ya Partitions**: Hutoa uwezo wa kutaja partitions kwa hadi characters 36 za Unicode.

**Ustahimilivu na Urejeshaji wa Data**:

- **Redundancy**: Tofauti na MBR, GPT haiweki partitioning na boot data kwenye eneo moja pekee. Inarudia data hii sehemu mbalimbali kwenye disk, hivyo kuongeza data integrity na resilience.
- **Cyclic Redundancy Check (CRC)**: GPT hutumia CRC kuhakikisha data integrity. Hufuatilia data corruption kwa bidii, na inapogunduliwa, GPT hujaribu kurejesha data iliyoharibika kutoka eneo jingine la disk.

**Protective MBR (LBA0)**:

- GPT hudumisha backward compatibility kupitia protective MBR. Kipengele hiki kiko kwenye legacy MBR space lakini kimeundwa kuzuia MBR-based utilities za zamani kuandika kimakosa juu ya GPT disks, hivyo kulinda data integrity kwenye disks zilizo na GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Katika operating systems zinazounga mkono **GPT-based boot kupitia BIOS** services badala ya EFI, sector ya kwanza inaweza pia kutumika kuhifadhi first stage ya **bootloader** code, lakini **imebadilishwa** ili itambue **GPT** **partitions**. Bootloader iliyo kwenye MBR haipaswi kudhani kuwa sector size ni 512 bytes.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Partition table header hufafanua blocks zinazoweza kutumika kwenye disk. Pia hufafanua idadi na ukubwa wa partition entries zinazounda partition table (offsets 80 na 84 kwenye table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)kwenye little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size katika little endian (kwa bytes, kwa kawaida 5Ch 00h 00h 00h au 92 bytes)                                                                                       |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya header (offset +0 hadi header size) katika little endian, huku field hii ikiwekwa zero wakati wa calculation                 |
| 20 (0x14) | 4 bytes  | Reserved; lazima iwe zero                                                                                                                                                    |
| 24 (0x18) | 8 bytes  | Current LBA (location ya header copy hii)                                                                                                                                    |
| 32 (0x20) | 8 bytes  | Backup LBA (location ya header copy nyingine)                                                                                                                                |
| 40 (0x28) | 8 bytes  | First usable LBA kwa partitions (last LBA ya primary partition table + 1)                                                                                                    |
| 48 (0x30) | 8 bytes  | Last usable LBA (first LBA ya secondary partition table − 1)                                                                                                                  |
| 56 (0x38) | 16 bytes | Disk GUID katika mixed endian                                                                                                                                               |
| 72 (0x48) | 8 bytes  | Starting LBA ya array ya partition entries (daima 2 katika primary copy)                                                                                                    |
| 80 (0x50) | 4 bytes  | Idadi ya partition entries katika array                                                                                                                                      |
| 84 (0x54) | 4 bytes  | Ukubwa wa partition entry moja (kwa kawaida 80h au 128)                                                                                                                      |
| 88 (0x58) | 4 bytes  | CRC32 ya partition entries array katika little endian                                                                                                                        |
| 92 (0x5C) | \*       | Reserved; lazima ziwe zeroes kwa sehemu iliyobaki ya block (420 bytes kwa sector size ya 512 bytes; lakini inaweza kuwa zaidi kwa sector sizes kubwa)                         |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, kwa kawaida odd)                                                                         |
| 48 (0x30)                   | 8 bytes  | Attribute flags (mfano bit 60 huashiria read-only)                                                            |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Aina za Partitions**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Jina la partition (36 UTF-16LE code units)](<../../../images/image (83).png>)

Aina zaidi za partitions katika [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Ukaguzi

Baada ya ku-mount forensics image kwa [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sector ya kwanza kwa kutumia Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Katika picha ifuatayo **MBR** iligunduliwa kwenye **sector 0** na kutafsiriwa:

![GPT (GUID Partition Table) - Ukaguzi: Baada ya ku-mount forensics image kwa ArsenalImageMounter, unaweza kukagua sector ya kwanza kwa kutumia Windows tool Active Disk Editor. Katika...](<../../../images/image (354).png>)

Ikiwa ingekuwa **GPT table badala ya MBR**, signature _EFI PART_ inapaswa kuonekana kwenye **sector 1** (ambayo katika picha iliyotangulia iko tupu).

## File-Systems

### Orodha ya Windows file-systems

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system imeundwa kuzunguka sehemu yake kuu, file allocation table, iliyowekwa mwanzoni mwa volume. Mfumo huu hulinda data kwa kudumisha **copies mbili** za table, hivyo kuhakikisha data integrity hata moja ikiwa imeharibika. Table pamoja na root folder lazima ziwe kwenye **fixed location**, jambo muhimu kwa startup process ya mfumo.

Kitengo cha msingi cha storage cha file system ni **cluster, kwa kawaida 512B**, kinachojumuisha sectors kadhaa. FAT imeendelea kupitia versions hizi:

- **FAT12**, inayounga mkono cluster addresses za 12-bit na kushughulikia hadi clusters 4078 (4084 ikiwa na UNIX).
- **FAT16**, inayoongeza addresses za 16-bit, hivyo kuruhusu hadi clusters 65,517.
- **FAT32**, inayosonga mbele zaidi kwa addresses za 32-bit, na kuruhusu clusters 268,435,456 kwa volume.

Kizuizi kikubwa katika FAT versions zote ni **maximum file size ya 4GB**, kinachosababishwa na 32-bit field inayotumika kuhifadhi file size.

Vipengele muhimu vya root directory, hasa kwa FAT12 na FAT16, ni pamoja na:

- **File/Folder Name** (hadi characters 8)
- **Attributes**
- **Creation, Modification, na Last Access Dates**
- **FAT Table Address** (inayoonyesha start cluster ya file)
- **File Size**

### EXT

**Ext2** ndiyo file system inayotumika zaidi kwa partitions **zisizo na journaling** (**partitions zisizobadilika sana**) kama boot partition. **Ext3/4** zina **journaling** na kwa kawaida hutumika kwa **partitions zilizobaki**.

## **Metadata**

Baadhi ya files zina metadata. Taarifa hii inahusu content ya file, ambayo wakati mwingine inaweza kumvutia analyst kwa sababu, kulingana na file type, inaweza kuwa na taarifa kama:

- Title
- MS Office Version iliyotumika
- Author
- Dates za creation na last modification
- Model ya camera
- GPS coordinates
- Image information

Unaweza kutumia tools kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya file.

## **Deleted Files Recovery**

### Logged Deleted Files

Kama ilivyoonekana awali, kuna maeneo kadhaa ambapo file bado huhifadhiwa baada ya "kufutwa". Hii ni kwa sababu kwa kawaida kufutwa kwa file kutoka file system huweka tu alama kuwa limefutwa, lakini data haiguswi. Kwa hiyo, inawezekana kukagua registries za files (kama MFT) na kupata deleted files.<sup>[[2]](#references)</sup>

Pia, OS kwa kawaida huhifadhi taarifa nyingi kuhusu mabadiliko ya file system na backups, hivyo inawezekana kujaribu kuzitumia kurecover file au taarifa nyingi iwezekanavyo.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ni technique inayojaribu **kutafuta files ndani ya bulk ya data**. Kuna njia 3 kuu ambazo tools kama hizi hufanya kazi: **Kwa kutegemea headers na footers za file types**, kwa kutegemea **structures** za file types, na kwa kutegemea **content** yenyewe.

Kumbuka kuwa technique hii **haifanyi kazi kuretrieve fragmented files**. Ikiwa file **haijahifadhiwa katika contiguous sectors**, technique hii haitaweza kuipata au angalau sehemu yake.

Kuna tools kadhaa unazoweza kutumia kwa File Carving, ukibainisha file types unazotaka kutafuta


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving inafanana na File Carving lakini **badala ya kutafuta files kamili, hutafuta fragments zinazovutia** za taarifa.\
Kwa mfano, badala ya kutafuta file kamili iliyo na logged URLs, technique hii itatafuta URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Ni wazi kuwa kuna njia za **kufuta files na sehemu ya logs zinazozihusu kwa "secure"**. Kwa mfano, inawezekana **ku-overwrite content** ya file kwa junk data mara kadhaa, kisha **kuondoa** **logs** kutoka kwenye **$MFT** na **$LOGFILE** zinazohusu file, na **kuondoa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Unaweza kugundua kuwa hata baada ya kufanya kitendo hicho, kunaweza kuwa na **sehemu nyingine ambako kuwepo kwa file bado kumehifadhiwa kwenye logs**, na hilo ni kweli; sehemu ya kazi ya forensics professional ni kuzipata.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Jinsi ya kuscan entries za NTFS $I30 (directory) kwa ushahidi wa deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
