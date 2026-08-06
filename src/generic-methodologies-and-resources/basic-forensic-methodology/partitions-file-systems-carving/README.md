# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Hard drive au **SSD disk inaweza kuwa na partitions tofauti** kwa lengo la kutenganisha data kimwili.\
Kizio cha **chini kabisa** cha disk ni **sector** (kwa kawaida huwa na 512B). Kwa hiyo, ukubwa wa kila partition unahitaji kuwa kizidisho cha ukubwa huo.

### MBR (master Boot Record)

Hutengwa katika **sector ya kwanza ya disk baada ya 446B za boot code**. Sector hii ni muhimu kwa kuonyesha kwa PC partition gani inapaswa ku-mountiwa na kutoka wapi.\
Inaruhusu hadi **partitions 4** (kwa kiwango cha juu **1 tu** inaweza kuwa active/**bootable**). Hata hivyo, ikiwa unahitaji partitions zaidi, unaweza kutumia **extended partitions**. **Byte ya mwisho** ya sector hii ya kwanza ni boot record signature **0x55AA**. Partition moja tu inaweza kuwekwa alama kuwa active.\
MBR inaruhusu kiwango cha juu cha **2.2TB**.

![Partitions - MBR (master Boot Record): MBR inaruhusu kiwango cha juu cha 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR inaruhusu kiwango cha juu cha 2.2TB](<../../../images/image (304).png>)

Kutoka kwenye **bytes 440 hadi 443** za MBR unaweza kupata **Windows Disk Signature** (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk inategemea Windows Disk Signature. Kubadilisha signature hii kunaweza kuzuia Windows ku-boot (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Kutoka kwenye bytes 440 hadi 443 za MBR unaweza kupata Windows Disk Signature (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk...](<../../../images/image (310).png>)

**Muundo**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | First Partition     |
| 462 (0x1CE) | 16 (0x10)  | Second Partition    |
| 478 (0x1DE) | 16 (0x10)  | Third Partition     |
| 494 (0x1EE) | 16 (0x10)  | Fourth Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Muundo wa Partition Record**

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

Ili ku-mount MBR katika Linux, kwanza unahitaji kupata start offset (unaweza kutumia `fdisk` na command ya `p`)

![Partitions - MBR (master Boot Record): Ili ku-mount MBR katika Linux, kwanza unahitaji kupata start offset (unaweza kutumia fdisk na command ya p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Kisha tumia code ifuatayo
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ni scheme ya kawaida inayotumika kwa **kubainisha eneo la blocks** za data zilizohifadhiwa kwenye vifaa vya computer storage, kwa ujumla mifumo ya secondary storage kama hard disk drives. LBA ni scheme rahisi ya linear addressing; **blocks hupatikana kwa kutumia integer index**, ambapo block ya kwanza ni LBA 0, ya pili LBA 1, na kuendelea.

### GPT (GUID Partition Table)

GUID Partition Table, inayojulikana kama GPT, inapendelewa kwa uwezo wake ulioboreshwa ikilinganishwa na MBR (Master Boot Record). Ikiwa na **globally unique identifier** kwa partitions, GPT inajitofautisha kwa njia kadhaa:

- **Eneo na Ukubwa**: GPT na MBR zote huanza kwenye **sector 0**. Hata hivyo, GPT hutumia **64bits**, tofauti na 32bits za MBR.
- **Mipaka ya Partitions**: GPT inasaidia hadi **partitions 128** kwenye Windows systems na inaweza kushughulikia hadi **9.4ZB** za data.
- **Majina ya Partitions**: Hutoa uwezo wa kuzipa partitions majina yenye hadi characters 36 za Unicode.

**Ustahimilivu wa Data na Recovery**:

- **Redundancy**: Tofauti na MBR, GPT haiweki partitioning na boot data katika eneo moja pekee. Huiga data hiyo katika maeneo mbalimbali ya disk, hivyo kuongeza data integrity na resilience.
- **Cyclic Redundancy Check (CRC)**: GPT hutumia CRC kuhakikisha data integrity. Hufuatilia data corruption kikamilifu, na inapogunduliwa, GPT hujaribu kurejesha data iliyoharibika kutoka eneo jingine la disk.

**Protective MBR (LBA0)**:

- GPT hudumisha backward compatibility kupitia protective MBR. Kipengele hiki hukaa kwenye legacy MBR space, lakini kimeundwa kuzuia MBR-based utilities za zamani ku-overwrite disks za GPT kimakosa, hivyo kulinda data integrity kwenye disks zilizoandaliwa kwa GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Katika operating systems zinazounga mkono **GPT-based boot kupitia BIOS** services badala ya EFI, sector ya kwanza inaweza pia kutumika kuhifadhi code ya hatua ya kwanza ya **bootloader**, lakini **modified** ili kutambua **GPT** **partitions**. Bootloader iliyo kwenye MBR haipaswi kudhani kuwa sector size ni 512 bytes.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Partition table header hufafanua blocks zinazoweza kutumika kwenye disk. Pia hufafanua idadi na ukubwa wa partition entries zinazounda partition table (offsets 80 na 84 kwenye table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)kwenye little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size katika little endian (kwa bytes, kwa kawaida 5Ch 00h 00h 00h au 92 bytes)                                                                                       |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya header (offset +0 hadi header size) katika little endian, huku field hii ikiwa zeroed wakati wa calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; lazima iwe zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (eneo la nakala hii ya header)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (eneo la nakala nyingine ya header)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA kwa partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID katika mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA ya array ya partition entries (daima 2 kwenye primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Idadi ya partition entries kwenye array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size ya partition entry moja (kwa kawaida 80h au 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 ya partition entries array katika little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; lazima iwe zeroes kwa sehemu iliyobaki ya block (420 bytes kwa sector size ya 512 bytes; lakini inaweza kuwa kubwa zaidi kwa sector sizes kubwa)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, kwa kawaida odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (kwa mfano, bit 60 inaonyesha read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Jina la partition (36 UTF-16LE code units)](<../../../images/image (83).png>)

Aina zaidi za partitions zinapatikana kwenye [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspecting

Baada ya ku-mount forensics image kwa kutumia [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sector ya kwanza kwa kutumia Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Kwenye image ifuatayo, **MBR** iligunduliwa kwenye **sector 0** na kutafsiriwa:

![GPT (GUID Partition Table) - Inspecting: Baada ya ku-mount forensics image kwa kutumia ArsenalImageMounter, unaweza kukagua sector ya kwanza kwa kutumia Windows tool Active Disk Editor. Kwenye...](<../../../images/image (354).png>)

Ikiwa ilikuwa **GPT table badala ya MBR**, signature _EFI PART_ inapaswa kuonekana kwenye **sector 1** (ambayo kwenye image iliyotangulia ilikuwa tupu).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

**FAT (File Allocation Table)** file system imeundwa kuzunguka component yake kuu, file allocation table, iliyowekwa mwanzoni mwa volume. System hii hulinda data kwa kuhifadhi **copies mbili** za table, hivyo kuhakikisha data integrity hata copy moja ikiwa imeharibika. Table hiyo, pamoja na root folder, lazima iwe katika **fixed location**, jambo muhimu kwa startup process ya system.

Unit ya msingi ya storage ya file system ni **cluster, kwa kawaida 512B**, inayojumuisha sectors kadhaa. FAT imeendelea kupitia versions hizi:

- **FAT12**, inayounga mkono cluster addresses za 12-bit na kushughulikia hadi clusters 4078 (4084 kwa UNIX).
- **FAT16**, iliyoboreshwa hadi addresses za 16-bit, hivyo kuruhusu hadi clusters 65,517.
- **FAT32**, iliyoboreshwa zaidi kwa addresses za 32-bit, ikiruhusu clusters 268,435,456 kwa volume.

Kikomo muhimu katika versions zote za FAT ni **maximum file size ya 4GB**, kinachosababishwa na 32-bit field inayotumika kuhifadhi file size.

Key components za root directory, hasa kwa FAT12 na FAT16, ni pamoja na:

- **File/Folder Name** (hadi characters 8)
- **Attributes**
- **Creation, Modification, na Last Access Dates**
- **FAT Table Address** (inayoonyesha start cluster ya file)
- **File Size**

### EXT

**Ext2** ndiyo file system inayotumika zaidi kwa partitions **zisizotumia journaling** (**partitions zisizobadilika sana**) kama boot partition. **Ext3/4** hutumia **journaling** na kwa kawaida hutumika kwa **partitions zilizobaki**.

## **Metadata**

Baadhi ya files huwa na metadata. Taarifa hii inahusu content ya file, ambayo wakati mwingine inaweza kumvutia analyst kwa kuwa, kulingana na file type, inaweza kuwa na taarifa kama:

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

Kama ilivyoonekana hapo awali, kuna maeneo kadhaa ambako file bado imehifadhiwa baada ya kuwa "deleted". Hii ni kwa sababu kwa kawaida deletion ya file kutoka kwenye file system huiweka tu alama ya kuwa deleted, lakini data haiguswi. Kwa hiyo, inawezekana kukagua registries za files (kama MFT) na kupata deleted files.<sup>[[2]](#references)</sup>

Pia, OS kwa kawaida huhifadhi taarifa nyingi kuhusu mabadiliko ya file system na backups, kwa hiyo inawezekana kujaribu kuzitumia kurecover file au taarifa nyingi iwezekanavyo.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ni technique inayojaribu **kutafuta files ndani ya bulk ya data**. Kuna njia 3 kuu ambazo tools kama hizi hufanya kazi: **Kwa kutegemea headers na footers za file types**, kwa kutegemea **structures** za file types, na kwa kutegemea **content** yenyewe.

Kumbuka kuwa technique hii **haifanyi kazi kuretrieve fragmented files**. Ikiwa file **haijahifadhiwa kwenye contiguous sectors**, basi technique hii haitaweza kuipata, au angalau sehemu yake.

Kuna tools kadhaa unazoweza kutumia kwa File Carving, ukibainisha file types unazotaka kutafuta


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving inafanana na File Carving, lakini **badala ya kutafuta files kamili, hutafuta fragments za taarifa zenye umuhimu**.\
Kwa mfano, badala ya kutafuta file kamili yenye URLs zilizologiwa, technique hii itatafuta URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Ni wazi kuwa kuna njia za **kudelete files na sehemu ya logs zinazozihusu kwa "usalama"**. Kwa mfano, inawezekana **ku-overwrite content** ya file kwa junk data mara kadhaa, kisha **kuondoa** **logs** kutoka kwenye **$MFT** na **$LOGFILE** zinazohusu file hilo, na **kuondoa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Unaweza kugundua kuwa hata baada ya kufanya kitendo hicho, huenda kukawa na **maeneo mengine ambako uwepo wa file bado ume-logiwa**, na hilo ni kweli; sehemu ya kazi ya mtaalamu wa forensics ni kuyapata.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
