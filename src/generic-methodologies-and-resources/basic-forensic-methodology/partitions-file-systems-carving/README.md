# Partisies/Lêerstelsels/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partisies

'n Hardeskyf of 'n **SSD-skyf kan verskillende partisies bevat** met die doel om data fisies te skei.\
Die **minimum** eenheid van 'n skyf is die **sektor** (normaalweg bestaande uit 512B). Dus moet elke partisiegrootte 'n veelvoud van daardie grootte wees.

### MBR (master Boot Record)

Dit word in die **eerste sektor van die skyf, ná die 446B van die boot-kode**, toegeken. Hierdie sektor is noodsaaklik om aan die rekenaar aan te dui watter partisie gemount moet word en waarvandaan.\
Dit laat tot **4 partisies** toe (hoogstens **net 1** kan aktief/**bootable** wees). As jy egter meer partisies benodig, kan jy **extended partitions** gebruik. Die **laaste byte** van hierdie eerste sektor is die boot-rekord-handtekening **0x55AA**. Slegs een partisie kan as aktief gemerk word.\
MBR laat **maksimaal 2.2TB** toe.

![Partisies - MBR (master Boot Record): MBR laat maksimaal 2.2TB toe](<../../../images/image (350).png>)

![Partisies - MBR (master Boot Record): MBR laat maksimaal 2.2TB toe](<../../../images/image (304).png>)

Vanaf die **grepe 440 tot 443** van die MBR kan jy die **Windows Disk Signature** vind (indien Windows gebruik word). Die logiese dryfletter van die hardeskyf hang van die Windows Disk Signature af. Die verandering van hierdie handtekening kan voorkom dat Windows boot (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partisies - MBR (master Boot Record): Vanaf die grepe 440 tot 443 van die MBR kan jy die Windows Disk Signature vind (indien Windows gebruik word). Die logiese dryfletter van die hardeskyf...](<../../../images/image (310).png>)

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
| 1 (0x01)  | 1 (0x01) | Beginhoof                                             |
| 2 (0x02)  | 1 (0x01) | Beginsektor (bisse 0-5); boonste bisse van silinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Laagste 8 bisse van beginsilinder                     |
| 4 (0x04)  | 1 (0x01) | Partisietipekode (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Eindhoof                                               |
| 6 (0x06)  | 1 (0x01) | Eindsektor (bisse 0-5); boonste bisse van silinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Laagste 8 bisse van eindsilinder                     |
| 8 (0x08)  | 4 (0x04) | Sektore vóór partisie (little endian)                 |
| 12 (0x0C) | 4 (0x04) | Sektore in partisie                                   |

Om 'n MBR in Linux te mount, moet jy eers die begin-offset kry (jy kan `fdisk` en die `p`-opdrag gebruik)

![Partisies - MBR (master Boot Record): Om 'n MBR in Linux te mount, moet jy eers die begin-offset kry (jy kan fdisk en die p-opdrag gebruik)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Gebruik dan die volgende kode
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) is 'n algemene skema wat gebruik word om die **ligging van blokke** data wat op rekenaarbergings toestelle gestoor word, te spesifiseer; gewoonlik sekondêre bergingstelsels soos hardeskyf-aandrywers. LBA is 'n besonder eenvoudige lineêre adresseringskema; **blokke word deur 'n heelgetalindeks opgespoor**, met die eerste blok as LBA 0, die tweede as LBA 1, ensovoorts.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekend as GPT, word verkies weens sy verbeterde vermoëns in vergelyking met MBR (Master Boot Record). GPT is onderskeibaar vanweë sy **globaal unieke identifiseerder** vir partisies en staan op verskeie maniere uit:

- **Ligging en grootte**: Beide GPT en MBR begin by **sektor 0**. GPT werk egter op **64 bits**, in teenstelling met MBR se 32 bits.
- **Partisielimiete**: GPT ondersteun tot **128 partisies** op Windows-stelsels en akkommodeer tot **9.4ZB** data.
- **Partisiename**: Bied die vermoë om partisies met tot 36 Unicode-karakters te benoem.

**Dataweerstandigheid en herstel**:

- **Redundansie**: Anders as MBR beperk GPT nie partisiering- en bootdata tot 'n enkele plek nie. Dit repliseer hierdie data oor die skyf, wat data-integriteit en weerstandigheid verbeter.
- **Cyclic Redundancy Check (CRC)**: GPT gebruik CRC om data-integriteit te verseker. Dit monitor aktief vir datakorrupsie, en wanneer dit bespeur word, probeer GPT om die korrupte data vanaf 'n ander skyfligging te herstel.

**Protective MBR (LBA0)**:

- GPT handhaaf terugwaartse versoenbaarheid deur middel van 'n protective MBR. Hierdie funksie is in die legacy MBR-spasie geleë, maar is ontwerp om te voorkom dat ouer MBR-gebaseerde nutsprogramme GPT-skywe per ongeluk oorskryf, en beskerm dus die data-integriteit op GPT-geformateerde skywe.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

In bedryfstelsels wat **GPT-gebaseerde boot deur BIOS**-dienste eerder as EFI ondersteun, kan die eerste sektor steeds gebruik word om die eerste fase van die **bootloader**-kode te stoor, maar dit word **gewysig** om **GPT**-**partisies** te herken. Die bootloader in die MBR mag nie aanvaar dat 'n sektorgrootte van 512 grepe gebruik word nie.

**Partition table header (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Die partisietabelkop definieer die bruikbare blokke op die skyf. Dit definieer ook die aantal en grootte van die partisiesinskrywings waaruit die partisietabel bestaan (offsets 80 en 84 in die tabel).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)on little-endian machines) |
| 8 (0x08)  | 4 bytes  | Revision 1.0 (00h 00h 01h 00h) for UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Header size in little endian (in bytes, usually 5Ch 00h 00h 00h or 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) of header (offset +0 up to header size) in little endian, with this field zeroed during calculation                             |
| 20 (0x14) | 4 bytes  | Reserved; must be zero                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Current LBA (location of this header copy)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Backup LBA (location of the other header copy)                                                                                                                               |
| 40 (0x28) | 8 bytes  | First usable LBA for partitions (primary partition table last LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Last usable LBA (secondary partition table first LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Disk GUID in mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Starting LBA of an array of partition entries (always 2 in primary copy)                                                                                                     |
| 80 (0x50) | 4 bytes  | Number of partition entries in array                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Size of a single partition entry (usually 80h or 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 of partition entries array in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserved; must be zeroes for the rest of the block (420 bytes for a sector size of 512 bytes; but can be more with larger sector sizes)                                      |

**Partition entries (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Partitions Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Meer partisietipes by [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspeksie

Nadat jy die forensiese image met [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemount het, kan jy die eerste sektor inspekteer deur die Windows-nutsprogram [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** In die volgende image is 'n **MBR** op die **sektor 0** opgespoor en geïnterpreteer:

![GPT (GUID Partition Table) - Inspeksie: Nadat jy die forensiese image met ArsenalImageMounter gemount het, kan jy die eerste sektor inspekteer deur die Windows-nutsprogram Active Disk Editor. In die...](<../../../images/image (354).png>)

As dit 'n **GPT-tabel in plaas van 'n MBR** was, behoort die handtekening _EFI PART_ in die **sektor 1** te verskyn (wat in die vorige image leeg is).

## Lêerstelsels

### Windows-lêerstelsellys

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Die **FAT (File Allocation Table)**-lêerstelsel is rondom sy kernkomponent ontwerp, naamlik die file allocation table, wat aan die begin van die volume geplaas word. Hierdie stelsel beskerm data deur **twee kopieë** van die tabel te onderhou, wat data-integriteit verseker selfs indien een korrup raak. Die tabel, tesame met die wortelgids, moet op 'n **vaste ligging** wees, wat noodsaaklik is vir die stelsel se opstartproses.

Die lêerstelsel se basiese stooreenheid is 'n **cluster, gewoonlik 512B**, wat uit verskeie sektore bestaan. FAT het deur verskeie weergawes ontwikkel:

- **FAT12**, wat 12-bis clusteradresse ondersteun en tot 4078 clusters (4084 met UNIX) hanteer.
- **FAT16**, wat na 16-bis adresse verbeter is en dus tot 65,517 clusters kan akkommodeer.
- **FAT32**, wat verder met 32-bis adresse gevorder het en 'n indrukwekkende 268,435,456 clusters per volume toelaat.

'n Beduidende beperking oor alle FAT-weergawes heen is die **maksimum lêergrootte van 4GB**, wat deur die 32-bis-veld vir die stoor van lêergrootte opgelê word.

Belangrike komponente van die wortelgids, veral vir FAT12 en FAT16, sluit die volgende in:

- **Lêer-/Gidsnaam** (tot 8 karakters)
- **Attributes**
- **Skeppings-, Wysigings- en Laaste Toegangsdatums**
- **FAT-tabeladres** (wat die begincluster van die lêer aandui)
- **Lêergrootte**

### EXT

**Ext2** is die algemeenste lêerstelsel vir **nie-journaling**-partisies (**partisies wat nie baie verander nie**), soos die bootpartisie. **Ext3/4** gebruik **journaling** en word gewoonlik vir die **oorblywende partisies** gebruik.

## **Metadata**

Sommige lêers bevat metadata. Hierdie inligting handel oor die inhoud van die lêer en kan soms vir 'n analyst interessant wees, aangesien dit, afhangend van die lêertipe, inligting soos die volgende kan bevat:

- Titel
- MS Office-weergawe wat gebruik is
- Outeur
- Datums van skepping en laaste wysiging
- Kameramodel
- GPS-koördinate
- Image-inligting

Jy kan tools soos [**exiftool**](https://exiftool.org) en [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gebruik om die metadata van 'n lêer te verkry.

## **Herstel van geskrapte lêers**

### Logged Deleted Files

Soos vroeër gesien is, is daar verskeie plekke waar die lêer steeds gestoor word nadat dit "geskrap" is. Dit is omdat die skrap van 'n lêer uit 'n lêerstelsel gewoonlik slegs aandui dat dit geskrap is, maar die data word nie aangeraak nie. Dit is dus moontlik om die registers van die lêers (soos die MFT) te inspekteer en die geskrapte lêers te vind.<sup>[[2]](#references)</sup>

Die OS stoor gewoonlik ook baie inligting oor lêerstelselveranderinge en backups, dus is dit moontlik om dit te probeer gebruik om die lêer, of soveel moontlik inligting, te herstel.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** is 'n tegniek wat probeer om **lêers in die groot hoeveelheid data te vind**. Daar is 3 hoofmaniere waarop tools soos hierdie werk: **Gebaseer op lêertipeheaders en -footers**, gebaseer op lêertipe-**strukture** en gebaseer op die **inhoud** self.

Let daarop dat hierdie tegniek **nie werk om gefragmenteerde lêers te herwin nie**. Indien 'n lêer **nie in aaneenlopende sektore gestoor word nie**, sal hierdie tegniek dit nie, of ten minste 'n deel daarvan, kan vind nie.

Daar is verskeie tools wat jy vir file Carving kan gebruik deur die lêertipes aan te dui waarna jy wil soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving is soortgelyk aan File Carving, maar **in plaas daarvan om na volledige lêers te soek, soek dit na interessante fragmente** van inligting.\
Byvoorbeeld, in plaas daarvan om na 'n volledige lêer te soek wat gelogde URLs bevat, sal hierdie tegniek na URLs soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Dit is vanselfsprekend dat daar maniere is om lêers en dele van logs oor hulle **"veilig" te skrap**. Dit is byvoorbeeld moontlik om die **inhoud te oorskryf** van 'n lêer verskeie kere met junkdata, en dan die **logs** uit die **$MFT** en **$LOGFILE** oor die lêer te **verwyder**, asook die **Volume Shadow Copies** te **verwyder**.<sup>[[3]](#references)</sup>\
Jy sal dalk opmerk dat daar, selfs nadat daardie handeling uitgevoer is, **ander dele kan wees waar die bestaan van die lêer steeds gelog word**, en dit is korrek; deel van die forensiese professionele persoon se werk is om hulle te vind.

## Verwysings

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
