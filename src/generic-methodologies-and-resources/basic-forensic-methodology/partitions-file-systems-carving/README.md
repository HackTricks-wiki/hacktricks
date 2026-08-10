# Partisies/Lêerstelsels/Carving

## Partisies

'n Hardeskyf of 'n **SSD-skyf kan verskillende partisies bevat** met die doel om data fisies te skei.\
Die **minimum**-eenheid van 'n skyf is die **sektor** (normaalweg bestaande uit 512B). Dus moet elke partisiegrootte 'n veelvoud van daardie grootte wees.

### MBR (master Boot Record)

Dit word in die **eerste sektor van die skyf, ná die 446B van die boot-kode**, toegeken. Hierdie sektor is noodsaaklik om aan die rekenaar aan te dui wat en waarvandaan 'n partisie gemount moet word.\
Dit laat tot **4 partisies** toe (hoogstens **net 1** kan aktief/**bootable** wees). As jy egter meer partisies benodig, kan jy **extended partitions** gebruik. Die **finale byte** van hierdie eerste sektor is die boot record-handtekening **0x55AA**. Slegs een partisie kan as aktief gemerk word.\
MBR laat 'n **maksimum van 2.2TB** toe.

![Partisies - MBR (master Boot Record): MBR laat 'n maksimum van 2.2TB toe](<../../../images/image (350).png>)

![Partisies - MBR (master Boot Record): MBR laat 'n maksimum van 2.2TB toe](<../../../images/image (304).png>)

Vanaf die **bytes 440 tot 443** van die MBR kan jy die **Windows Disk Signature** vind (indien Windows gebruik word). Die logiese dryfletter van die hardeskyf hang van die Windows Disk Signature af. As hierdie handtekening verander word, kan dit voorkom dat Windows boot (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partisies - MBR (master Boot Record): Vanaf die bytes 440 tot 443 van die MBR kan jy die Windows Disk Signature vind (indien Windows gebruik word). Die logiese dryfletter van die hardeskyf...](<../../../images/image (310).png>)

**Formaat**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot-kode           |
| 446 (0x1BE) | 16 (0x10)  | Eerste partisie     |
| 462 (0x1CE) | 16 (0x10)  | Tweede partisie     |
| 478 (0x1DE) | 16 (0x10)  | Derde partisie      |
| 494 (0x1EE) | 16 (0x10)  | Vierde partisie     |
| 510 (0x1FE) | 2 (0x2)    | Handtekening 0x55 0xAA |

**Partisie-rekordformaat**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktiewe vlag (0x80 = bootable)                         |
| 1 (0x01)  | 1 (0x01) | Begin-head                                             |
| 2 (0x02)  | 1 (0x01) | Beginsektor (bits 0-5); boonste bisse van silinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Laagste 8 bisse van beginsilinder                      |
| 4 (0x04)  | 1 (0x01) | Partisie-tipekode (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Einde-head                                              |
| 6 (0x06)  | 1 (0x01) | Eindsektor (bits 0-5); boonste bisse van silinder (6- 7) |
| 7 (0x07)  | 1 (0x01) | Laagste 8 bisse van eindsilinder                       |
| 8 (0x08)  | 4 (0x04) | Sektore wat die partisie voorafgaan (little endian)    |
| 12 (0x0C) | 4 (0x04) | Sektore in partisie                                    |

Om 'n MBR in Linux te mount, moet jy eers die begin-offset kry (jy kan `fdisk` en die `p`-opdrag gebruik).

![Partisies - MBR (master Boot Record): Om 'n MBR in Linux te mount, moet jy eers die begin-offset kry (jy kan fdisk en die p-opdrag gebruik)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Gebruik dan die volgende kode
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) is ’n algemene skema wat gebruik word om die **ligging van blokke** data te spesifiseer wat op rekenaarstoortoestelle gestoor word, gewoonlik sekondêre stoersisteme soos hardeskywe. LBA is ’n besonder eenvoudige lineêre adresseringskema; **blokke word deur ’n heelgetalindeks gelokaliseer**, met die eerste blok as LBA 0, die tweede as LBA 1, ensovoorts.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekend as GPT, word verkies weens sy verbeterde vermoëns in vergelyking met MBR (Master Boot Record). GPT word onderskei deur sy **globaal unieke identifiseerder** vir partisies en staan op verskeie maniere uit:

- **Ligging en grootte**: Beide GPT en MBR begin by **sektor 0**. GPT werk egter op **64bits**, in teenstelling met MBR se 32bits.
- **Partisiebeperkings**: GPT ondersteun tot **128 partisies** op Windows-stelsels en kan tot **9.4ZB** se data akkommodeer.
- **Partisiename**: Bied die vermoë om partisies met tot 36 Unicode-karakters te benoem.

**Dataweerstand en -herstel**:

- **Redundansie**: Anders as MBR beperk GPT nie partisie- en bootdata tot ’n enkele plek nie. Dit repliseer hierdie data oor die skyf, wat data-integriteit en -weerstand verbeter.
- **Cyclic Redundancy Check (CRC)**: GPT gebruik CRC om data-integriteit te verseker. Dit monitor aktief vir datakorrupsie, en wanneer dit opgespoor word, probeer GPT om die korrupte data vanaf ’n ander skyfligging te herstel.

**Protective MBR (LBA0)**:

- GPT handhaaf terugwaartse versoenbaarheid deur middel van ’n protective MBR. Hierdie funksie is in die legacy MBR-spasie geleë, maar is ontwerp om te voorkom dat ouer MBR-gebaseerde nutsprogramme GPT-skywe per ongeluk oorskryf, en beskerm dus die data-integriteit op GPT-geformateerde skywe.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

In bedryfstelsels wat **GPT-based boot through BIOS**-dienste eerder as EFI ondersteun, kan die eerste sektor steeds gebruik word om die eerste fase van die **bootloader**-kode te stoor, maar dit is **gewysig** om **GPT**-**partisies** te herken. Die bootloader in die MBR moet nie aanvaar dat ’n sektorgrootte van 512 grepe gebruik word nie.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Die partition table header definieer die bruikbare blokke op die skyf. Dit definieer ook die aantal en grootte van die partisie-inskrywings waaruit die partition table bestaan (offsets 80 en 84 in die table).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h of 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)op little-endian-masjiene) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) vir UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, gewoonlik 5Ch 00h 00h 00h of 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) van header (offset +0 tot en met header size) in little endian, met hierdie veld wat tydens berekening op nul gestel word                             |
| 20 (0x14) | 4 bytes  | Gereserveer; moet nul wees                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (ligging van hierdie header-kopie)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (ligging van die ander header-kopie)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Gereserveer; moet vir die res van die blok nulle wees (420 bytes vir ’n sektorgrootte van 512 bytes; maar kan groter wees met groter sektorgroottes)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, gewoonlik onewe)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (bv. bit 60 dui read-only aan)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Meer partition types by [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspecting

Nadat die forensics image met [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemount is, kan jy die eerste sektor met die Windows-tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** inspekteer. In die volgende image is ’n **MBR** op **sektor 0** opgespoor en geïnterpreteer:

![GPT (GUID Partition Table) - Inspecting: Nadat die forensics image met ArsenalImageMounter gemount is, kan jy die eerste sektor met die Windows-tool Active Disk Editor inspekteer. In die...](<../../../images/image (354).png>)

As dit ’n **GPT table in plaas van ’n MBR** was, behoort die signature _EFI PART_ in **sektor 1** te verskyn (wat in die vorige image leeg is).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Die **FAT (File Allocation Table)**-file system is rondom sy kernkomponent ontwerp, naamlik die file allocation table, wat aan die begin van die volume geplaas is. Hierdie stelsel beskerm data deur **twee kopieë** van die table te handhaaf, wat data-integriteit verseker selfs indien een beskadig word. Die table, tesame met die root folder, moet op ’n **vaste ligging** wees, wat noodsaaklik is vir die stelsel se opstartproses.

Die file system se basiese stooreenheid is ’n **cluster, gewoonlik 512B**, wat uit verskeie sektore bestaan. FAT het deur die volgende weergawes ontwikkel:

- **FAT12**, wat 12-bit cluster addresses ondersteun en tot 4078 clusters (4084 met UNIX) kan hanteer.
- **FAT16**, wat na 16-bit addresses verbeter is en sodoende tot 65,517 clusters kan akkommodeer.
- **FAT32**, wat verder met 32-bit addresses gevorder het en ’n indrukwekkende 268,435,456 clusters per volume toelaat.

’n Beduidende beperking oor alle FAT-weergawes heen is die **maksimum lêergrootte van 4GB**, wat deur die 32-bit-veld vir lêergrootteberging opgelê word.

Belangrike komponente van die root directory, veral vir FAT12 en FAT16, sluit in:

- **File/Folder Name** (tot 8 karakters)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (wat die beginkluster van die file aandui)
- **File Size**

### EXT

**Ext2** is die algemeenste file system vir **nie-journaling**-partisies (**partisies wat nie baie verander nie**), soos die boot-partisie. **Ext3/4** gebruik **journaling** en word gewoonlik vir die **oorblywende partisies** gebruik.

## **Metadata**

Sommige files bevat metadata. Hierdie inligting handel oor die inhoud van die file en kan soms vir ’n analyst interessant wees, aangesien dit, afhangend van die file type, inligting kan bevat soos:

- Titel
- MS Office-weergawe wat gebruik is
- Outeur
- Datums van skepping en laaste wysiging
- Model van die kamera
- GPS-koördinate
- Image-inligting

Jy kan tools soos [**exiftool**](https://exiftool.org) en [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gebruik om die metadata van ’n file te verkry.

## **Deleted Files Recovery**

### Logged Deleted Files

Soos voorheen gesien is, is daar verskeie plekke waar die file steeds gestoor word nadat dit "deleted" is. Dit is omdat die deletion van ’n file uit ’n file system gewoonlik net aandui dat dit deleted is, terwyl die data nie aangeraak word nie. Dit is dus moontlik om die registries van die files (soos die MFT) te inspekteer en die deleted files te vind.<sup>[[2]](#references)</sup>

Die OS stoor gewoonlik ook baie inligting oor file system-veranderinge en backups, dus is dit moontlik om dit te probeer gebruik om die file, of soveel moontlik inligting, te herstel.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** is ’n tegniek wat probeer om **files in die groot hoeveelheid data te vind**. Daar is 3 hoofmaniere waarop tools soos hierdie werk: **gebaseer op file types se headers en footers**, gebaseer op file types se **strukture**, en gebaseer op die **inhoud** self.

Let daarop dat hierdie tegniek **nie werk om gefragmenteerde files te herwin nie**. As ’n file **nie in aangrensende sektore gestoor word nie**, sal hierdie tegniek dit nie, of ten minste ’n gedeelte daarvan, kan vind nie.

Daar is verskeie tools wat jy vir File Carving kan gebruik deur die file types aan te dui waarvoor jy wil soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving is soortgelyk aan File Carving, maar **in plaas daarvan om na volledige files te soek, soek dit na interessante fragmente** van inligting.\
Byvoorbeeld, in plaas daarvan om na ’n volledige file te soek wat logged URLs bevat, sal hierdie tegniek na URLs soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Dit is natuurlik moontlik om files en dele van logs daaroor **"securely" te delete**. Dit is byvoorbeeld moontlik om die **inhoud van ’n file** verskeie kere met gemorsdata te **overwrite**, en dan die **logs** van die file uit die **$MFT** en **$LOGFILE** te **remove**, asook die **Volume Shadow Copies** te **remove**.<sup>[[3]](#references)</sup>\
Jy mag opmerk dat daar, selfs nadat daardie aksie uitgevoer is, **ander dele kan wees waar die bestaan van die file steeds gelog word**, en dit is waar; deel van die forensics-professional se werk is om hulle te vind.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Hoe om NTFS $I30 (directory)-inskrywings vir bewyse van deleted files te skandeer](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
