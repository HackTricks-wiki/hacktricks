# Partitions/Systems za Faili/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

Hard drive au **SSD disk inaweza kuwa na partitions tofauti** kwa lengo la kutenganisha data kimwili.\
Kizio cha **chini kabisa** cha disk ni **sector** (kwa kawaida huwa na 512B). Kwa hiyo, ukubwa wa kila partition lazima uwe kizidisho cha ukubwa huo.

### MBR (master Boot Record)

Hutengwa katika **sector ya kwanza ya disk baada ya 446B za boot code**. Sector hii ni muhimu kwa kuonyesha kwa PC partition gani inapaswa ku-mountiwa na kutoka wapi.\
Inaruhusu hadi **partitions 4** (angalau **1 tu** inaweza kuwa active/**bootable**). Hata hivyo, ikiwa unahitaji partitions zaidi, unaweza kutumia **extended partitions**. **Byte ya mwisho** ya sector hii ya kwanza ni boot record signature **0x55AA**. Partition moja tu inaweza kuwekwa alama kuwa active.\
MBR inaruhusu hadi **2.2TB**.

![Partitions - MBR (master Boot Record): MBR inaruhusu hadi 2.2TB](<../../../images/image (350).png>)

![Partitions - MBR (master Boot Record): MBR inaruhusu hadi 2.2TB](<../../../images/image (304).png>)

Kutoka kwenye **bytes 440 hadi 443** za MBR unaweza kupata **Windows Disk Signature** (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk inategemea Windows Disk Signature. Kubadilisha signature hii kunaweza kuzuia Windows ku-boot (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitions - MBR (master Boot Record): Kutoka kwenye bytes 440 hadi 443 za MBR unaweza kupata Windows Disk Signature (ikiwa Windows inatumika). Herufi ya logical drive ya hard disk...](<../../../images/image (310).png>)

**Muundo**

| Offset      | Length     | Kipengee                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot code           |
| 446 (0x1BE) | 16 (0x10)  | Partition ya Kwanza     |
| 462 (0x1CE) | 16 (0x10)  | Partition ya Pili    |
| 478 (0x1DE) | 16 (0x10)  | Partition ya Tatu     |
| 494 (0x1EE) | 16 (0x10)  | Partition ya Nne    |
| 510 (0x1FE) | 2 (0x2)    | Signature 0x55 0xAA |

**Muundo wa Partition Record**

| Offset    | Length   | Kipengee                                                   |
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

Ili ku-mount MBR kwenye Linux, kwanza unahitaji kupata start offset (unaweza kutumia `fdisk` na command ya `p`)

![Partitions - MBR (master Boot Record): Ili ku-mount MBR kwenye Linux, kwanza unahitaji kupata start offset (unaweza kutumia fdisk na command ya p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Kisha tumia code ifuatayo
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ni mfumo wa kawaida unaotumika **kubainisha mahali zilipo blocks** za data zilizohifadhiwa kwenye vifaa vya kuhifadhia data vya kompyuta, kwa ujumla mifumo ya secondary storage kama hard disk drives. LBA ni mfumo rahisi wa linear addressing; **blocks hupatikana kwa kutumia integer index**, ambapo block ya kwanza ni LBA 0, ya pili ni LBA 1, na kadhalika.

### GPT (GUID Partition Table)

GUID Partition Table, inayojulikana kama GPT, hupendelewa kwa sababu ya uwezo wake ulioimarishwa ikilinganishwa na MBR (Master Boot Record). GPT ina **globally unique identifier** kwa partitions na hutofautiana kwa njia kadhaa:

- **Mahali na Ukubwa**: GPT na MBR zote huanza kwenye **sector 0**. Hata hivyo, GPT hutumia **64bits**, tofauti na 32bits za MBR.
- **Mipaka ya Partitions**: GPT inasaidia hadi **partitions 128** kwenye mifumo ya Windows na inaweza kushughulikia hadi **9.4ZB** ya data.
- **Majina ya Partitions**: Inaruhusu kuzipa partitions majina yenye hadi herufi 36 za Unicode.

**Ustahimilivu na Urejeshaji wa Data**:

- **Redundancy**: Tofauti na MBR, GPT haihifadhi partitioning na boot data mahali pamoja pekee. Hunakili data hii sehemu mbalimbali za disk, jambo linaloongeza uadilifu na ustahimilivu wa data.
- **Cyclic Redundancy Check (CRC)**: GPT hutumia CRC kuhakikisha uadilifu wa data. Hufuatilia kikamilifu uharibifu wa data, na inapogunduliwa, GPT hujaribu kurejesha data iliyoharibika kutoka sehemu nyingine ya disk.

**Protective MBR (LBA0)**:

- GPT hudumisha backward compatibility kupitia protective MBR. Kipengele hiki kiko kwenye nafasi ya legacy MBR lakini kimeundwa kuzuia utilities za zamani zinazotegemea MBR kuandika juu ya disk za GPT kimakosa, hivyo kulinda uadilifu wa data kwenye disks zilizo na GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Katika operating systems zinazotumia **GPT-based boot kupitia** huduma za **BIOS** badala ya EFI, sector ya kwanza inaweza pia kuendelea kutumika kuhifadhi code ya hatua ya kwanza ya **bootloader**, lakini **imebadilishwa** ili itambue **GPT** **partitions**. Bootloader iliyo kwenye MBR haipaswi kudhani kuwa sector size ni 512 bytes.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Partition table header hufafanua blocks zinazoweza kutumika kwenye disk. Pia hufafanua idadi na ukubwa wa partition entries zinazounda partition table (offsets 80 na 84 kwenye table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h au 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)kwenye little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) kwa UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Ukubwa wa header katika little endian (kwa bytes, kwa kawaida 5Ch 00h 00h 00h au 92 bytes)                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) ya header (offset +0 hadi header size) katika little endian, huku field hii ikiwa zero wakati wa calculation                  |
| 20 (0x14) | 4 bytes  | Imehifadhiwa; lazima iwe zero                                                                                                                                               |
| 24 (0x18) | 8 bytes  | Current LBA (mahali pa nakala hii ya header)                                                                                                                                |
| 32 (0x20) | 8 bytes  | Backup LBA (mahali pa nakala nyingine ya header)                                                                                                                            |
| 40 (0x28) | 8 bytes  | First usable LBA ya partitions (last LBA ya primary partition table + 1)                                                                                                    |
| 48 (0x30) | 8 bytes  | Last usable LBA (first LBA ya secondary partition table − 1)                                                                                                                |
| 56 (0x38) | 16 bytes | Disk GUID katika mixed endian                                                                                                                                               |
| 72 (0x48) | 8 bytes  | Starting LBA ya array ya partition entries (daima 2 kwenye primary copy)                                                                                                    |
| 80 (0x50) | 4 bytes  | Idadi ya partition entries kwenye array                                                                                                                                     |
| 84 (0x54) | 4 bytes  | Ukubwa wa partition entry moja (kwa kawaida 80h au 128)                                                                                                                     |
| 88 (0x58) | 4 bytes  | CRC32 ya partition entries array katika little endian                                                                                                                       |
| 92 (0x5C) | \*       | Imehifadhiwa; lazima iwe zeroes kwa sehemu iliyobaki ya block (420 bytes kwa sector size ya 512 bytes; lakini inaweza kuwa kubwa zaidi kwa sector sizes kubwa)              |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, kwa kawaida odd)                                                                         |
| 48 (0x30)                   | 8 bytes  | Attribute flags (mfano, bit 60 huashiria read-only)                                                           |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Aina zaidi za partitions zinapatikana kwenye [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

### Inspecting

Baada ya kumount forensics image kwa kutumia [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), unaweza kukagua sector ya kwanza kwa kutumia Windows tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Kwenye picha ifuatayo **MBR** iligunduliwa kwenye **sector 0** na kutafsiriwa:

![GPT (GUID Partition Table) - Inspecting: Baada ya kumount forensics image kwa kutumia ArsenalImageMounter, unaweza kukagua sector ya kwanza kwa kutumia Windows tool Active Disk Editor. Kwenye...](<../../../images/image (354).png>)

Ikiwa ingekuwa **GPT table badala ya MBR**, signature _EFI PART_ inapaswa kuonekana kwenye **sector 1** (ambayo kwenye picha iliyotangulia iko tupu).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

File system ya **FAT (File Allocation Table)** imeundwa kuzunguka component yake kuu, file allocation table, iliyowekwa mwanzoni mwa volume. Mfumo huu hulinda data kwa kudumisha **copies mbili** za table, na hivyo kuhakikisha uadilifu wa data hata moja ikiwa imeharibika. Table pamoja na root folder lazima ziwe kwenye **fixed location**, jambo muhimu kwa mchakato wa startup wa mfumo.

Kitengo cha msingi cha storage cha file system ni **cluster, kwa kawaida 512B**, kinachojumuisha sectors kadhaa. FAT imebadilika kupitia versions zifuatazo:

- **FAT12**, inayounga mkono cluster addresses za bits 12 na kushughulikia hadi clusters 4078 (4084 ikiwa na UNIX).
- **FAT16**, iliyoongeza addresses za bits 16, na hivyo kuwezesha hadi clusters 65,517.
- **FAT32**, iliyoboreshwa zaidi kwa addresses za bits 32, na kuruhusu clusters 268,435,456 kwa kila volume.

Kizuizi kikubwa katika versions zote za FAT ni **ukubwa wa juu wa file wa 4GB**, unaowekwa na field ya bits 32 inayotumika kuhifadhi file size.

Components muhimu za root directory, hasa kwa FAT12 na FAT16, zinajumuisha:

- **File/Folder Name** (hadi herufi 8)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (inayoonyesha cluster ya mwanzo ya file)
- **File Size**

### EXT

**Ext2** ndiyo file system inayotumika zaidi kwa partitions **zisizo na journaling** (**partitions ambazo hazibadiliki sana**) kama boot partition. **Ext3/4** zina **journaling** na kwa kawaida hutumika kwa **rest partitions**.

## **Metadata**

Baadhi ya files huwa na metadata. Taarifa hii inahusu maudhui ya file na wakati mwingine inaweza kuwa muhimu kwa analyst, kwa kuwa kulingana na aina ya file inaweza kuwa na taarifa kama:

- Title
- MS Office Version used
- Author
- Dates of creation and last modification
- Model of the camera
- GPS coordinates
- Image information

Unaweza kutumia tools kama [**exiftool**](https://exiftool.org) na [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kupata metadata ya file.

## **Deleted Files Recovery**

### Logged Deleted Files

Kama ilivyoonekana awali, kuna maeneo kadhaa ambapo file bado huhifadhiwa baada ya "kufutwa". Hii ni kwa sababu kwa kawaida kufuta file kutoka kwenye file system huweka tu alama kuwa limefutwa, lakini data haiguswi. Kwa hiyo, inawezekana kukagua registries za files (kama MFT) na kupata deleted files.<sup>[[2]](#references)</sup>

Pia, OS kwa kawaida huhifadhi taarifa nyingi kuhusu mabadiliko ya file system na backups, hivyo inawezekana kujaribu kuzitumia kurejesha file au taarifa nyingi iwezekanavyo.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ni technique inayojaribu **kutafuta files ndani ya bulk ya data**. Kuna njia 3 kuu ambazo tools kama hizi hufanya kazi: **Kwa kutegemea headers na footers za aina za files**, kwa kutegemea **structures** za aina za files, na kwa kutegemea **content** yenyewe.

Kumbuka kuwa technique hii **haifanyi kazi kurejesha fragmented files**. Ikiwa file **haijahifadhiwa kwenye contiguous sectors**, technique hii haitaweza kuipata au angalau sehemu yake.

Kuna tools kadhaa unazoweza kutumia kwa File Carving, ukibainisha aina za files unazotaka kutafuta


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving inafanana na File Carving lakini **badala ya kutafuta files kamili, hutafuta fragments za taarifa zenye kuvutia**.\
Kwa mfano, badala ya kutafuta file kamili yenye URLs zilizologiwa, technique hii itatafuta URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Ni wazi kuwa kuna njia za **kufuta files na sehemu ya logs zake kwa "securely"**. Kwa mfano, inawezekana **kuandika upya content** ya file kwa junk data mara kadhaa, kisha **kuondoa** **logs** kutoka kwenye **$MFT** na **$LOGFILE** zinazohusu file hilo, na **kuondoa Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Unaweza kugundua kuwa hata baada ya kutekeleza hatua hiyo, huenda kukawa na **maeneo mengine ambako uwepo wa file bado umelogiwa**, na hilo ni kweli; sehemu ya kazi ya mtaalamu wa forensics ni kuyapata.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
