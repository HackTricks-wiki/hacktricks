# Partisies/Lêerstelsels/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partisies

'n Skyf kan verskeie **partisies** bevat: logiese reekse blokke, nie fisies aparte berging nie. Partisiebeginsels en -lengtes word in **logiese sektore** gemeet; moenie aanvaar dat elke beeld 512-grepe-sektore gebruik nie, want 4096-grepe-logiese sektore bestaan ook.<sup>[[4]](#references)</sup>

### MBR (master Boot Record)

Die MBR beslaan die eerste logiese sektor (LBA 0); sy vier 16-grepe-partisie-inskrywings begin by greep 446. Die voorafgaande area bevat selflaaikode en kan 'n skyfhandtekening insluit.<sup>[[4]](#references)</sup>\
Dit laat tot **4 partisies** toe (hoogstens **net 1** kan aktief/**selflaaibaar** wees). As jy egter meer partisies nodig het, kan jy **uitgebreide partisies** gebruik. Die laaste **twee grepe** van die 512-greep-MBR is die selflaaihandtekening **0x55 0xAA**. Slegs een partisie kan as aktief gemerk word.\
Met 512-greep-logiese sektore beperk MBR se 32-bis-sektorvelde die adresseerbare ruimte tot ongeveer **2 TiB** (2.2 TB).<sup>[[4]](#references)</sup>

![Partisies - MBR (master Boot Record): MBR laat hoogstens 2.2TB toe](<../../../images/image (350).png>)

![Partisies - MBR (master Boot Record): MBR laat hoogstens 2.2TB toe](<../../../images/image (304).png>)

In **grepe 440 tot 443** van die MBR kan jy die **Windows-skyfhandtekening** vind (as Windows gebruik word). Die logiese skyfletter van die hardeskyf hang af van die Windows-skyfhandtekening. As jy hierdie handtekening verander, kan dit voorkom dat Windows selflaai (nutsmiddel: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partisies - MBR (master Boot Record): In grepe 440 tot 443 van die MBR kan jy die Windows-skyfhandtekening vind (as Windows gebruik word). Die logiese skyfletter van die hardeskyf...](<../../../images/image (310).png>)

**Formaat**

| Offset      | Lengte     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Selflaaikode         |
| 446 (0x1BE) | 16 (0x10)  | Eerste partisie     |
| 462 (0x1CE) | 16 (0x10)  | Tweede partisie     |
| 478 (0x1DE) | 16 (0x10)  | Derde partisie      |
| 494 (0x1EE) | 16 (0x10)  | Vierde partisie     |
| 510 (0x1FE) | 2 (0x2)    | Handtekening 0x55 0xAA |

**Partisierekordformaat**

| Offset    | Lengte  | Item                                                          |
| --------- | ------- | ------------------------------------------------------------- |
| 0 (0x00)  | 1 (0x01) | Aktiewe vlag (0x80 = selflaaibaar)                            |
| 1 (0x01)  | 1 (0x01) | Begin-kop                                                      |
| 2 (0x02)  | 1 (0x01) | Beginsektor (bisse 0-5); boonste bisse van silinder (6- 7)    |
| 3 (0x03)  | 1 (0x01) | Laagste 8 bisse van beginsilinder                              |
| 4 (0x04)  | 1 (0x01) | Partisietipekode (0x83 = Linux)                                |
| 5 (0x05)  | 1 (0x01) | Eindkop                                                        |
| 6 (0x06)  | 1 (0x01) | Eindsektor (bisse 0-5); boonste bisse van silinder (6- 7)     |
| 7 (0x07)  | 1 (0x01) | Laagste 8 bisse van eindsilinder                               |
| 8 (0x08)  | 4 (0x04) | Sektore voor die partisie (little endian)                      |
| 12 (0x0C) | 4 (0x04) | Sektore in die partisie                                        |

Om 'n partisie in 'n MBR-beeld van 'n hele skyf te inspekteer, bepaal eers sy begin-LBA en die logiese sektorgrootte. `mount` verwag 'n **greepoffset**, nie 'n LBA nie; die voorbeeld hieronder is slegs geldig vir 'n beeld met 512-greep-sektore waarvan die partisie by LBA 63 begin. Gebruik eerder die geïsoleerde, leesalleen-werkvloei in [Beeldverkryging en -montering](../image-acquisition-and-mount.md) vir onbetroubare beelde of joernaallêerstelsels.<sup>[[5]](#references)[[11]](#references)</sup>

![Partisies - MBR (master Boot Record): Om 'n MBR in Linux te monteer, moet jy eers die begin-offset kry (jy kan fdisk en die p-opdrag gebruik)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logiese blokadressering)**

**Logiese blokadressering** (**LBA**) is ’n algemene skema wat gebruik word om **die ligging van blokke** data op rekenaarstoortoestelle aan te dui, gewoonlik sekondêre stoorsisteme soos hardeskywe. LBA is ’n besonder eenvoudige lineêre adresseringskema; **blokke word met ’n heelgetalindeks aangedui**, waar die eerste blok LBA 0 is, die tweede LBA 1, ensovoorts.

### GPT (GUID Partition Table)

Die GUID Partition Table (GPT) stoor ’n unieke GUID vir elke partisie en gebruik primêre en rugsteunmetadata. Die uitleg daarvan verskil soos volg van MBR:<sup>[[4]](#references)</sup>

- **Ligging en grootte**: LBA 0 bevat ’n **beskermende MBR**. Die primêre GPT-opskrif is by LBA 1; die skikking met partisie-inskrywings volg daarop, en ’n rugsteunskikking en -opskrif is aan die einde van die skyf. GPT gebruik 64-bis LBA-velde, terwyl MBR-partisie-inskrywings 32-bis LBA-velde gebruik.
- **Partisielimiete**: ’n Algemene inskrywingskikking van 16 KiB bevat **128 inskrywings van 128 grepe**, maar die aantal inskrywings word in die opskrif aangeteken en word nie deur GPT vasgestel nie. Die adresseerbare grootte hang ook af van die logiese sektorgrootte (ongeveer **9.4 ZB** met 512-grepe-sektore).<sup>[[4]](#references)</sup>
- **Partisiename**: Bied die moontlikheid om partisies met tot 36 Unicode-karakters te benoem.

**Datarobuustheid en herstel**:

- **Oortolligheid**: Anders as MBR, beperk GPT nie partisionerings- en selflaaidata tot een plek nie. Dit dupliseer hierdie data oor die skyf, wat data-integriteit en -robuustheid verbeter.
- **Sikliese oortolligheidstoets (CRC)**: Die opskrif en die skikking met partisie-inskrywings het elk ’n CRC32. ’n CRC bespeur teenstrydighede; dit monitor nie die skyf deurlopend nie en herstel dit ook nie self nie. As die primêre kopie ongeldig is, valideer die rugsteunkopie by die laaste LBA voordat enige herstel op ’n werkende kopie gedoen word.<sup>[[4]](#references)</sup>

**Beskermende MBR (LBA0)**:

- GPT behou terugwaartse versoenbaarheid deur ’n beskermende MBR. Hierdie funksie is in die verouderde MBR-ruimte geleë, maar is ontwerp om te voorkom dat ouer MBR-gebaseerde nutsprogramme GPT-skywe per ongeluk oorskryf, en beskerm sodoende data-integriteit op GPT-geformateerde skywe.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hibriede MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

In bedryfstelsels wat **GPT-gebaseerde selflaai deur BIOS**-dienste eerder as EFI ondersteun, kan die eerste sektor steeds gebruik word om die eerste fase van die **selflaaiprogram** se kode te stoor, maar dit word **gewysig** om **GPT**-**partisies** te herken. Die selflaaiprogram in die MBR moet nie ’n sektorgrootte van 512 grepe aanvaar nie.

**Partisietabelopskrif (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Die partisietabelopskrif definieer die bruikbare blokke op die skyf. Dit definieer ook die aantal en grootte van die partisiesinskrywings waaruit die partisietabel bestaan (verskuiwings 80 en 84 in die tabel).

| Verskuiwing | Lengte   | Inhoud                                                                                                                                                                       |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Handtekening ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h of 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)op little-endian-masjiene) |
| 8 (0x08)  | 4 bytes  | Hersiening 1.0 (00h 00h 01h 00h) vir UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Opskrifgrootte in little endian (in grepe, gewoonlik 5Ch 00h 00h 00h of 92 grepe)                                                                                              |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) van opskrif (verskuiwing +0 tot by opskrifgrootte) in little endian, met hierdie veld op nul gestel tydens berekening              |
| 20 (0x14) | 4 bytes  | Gereserveer; moet nul wees                                                                                                                                                     |
| 24 (0x18) | 8 bytes  | Huidige LBA (ligging van hierdie kopie van die opskrif)                                                                                                                        |
| 32 (0x20) | 8 bytes  | Rugsteun-LBA (ligging van die ander kopie van die opskrif)                                                                                                                    |
| 40 (0x28) | 8 bytes  | Eerste bruikbare LBA vir partisies (laaste LBA van primêre partisietabel + 1)                                                                                                  |
| 48 (0x30) | 8 bytes  | Laaste bruikbare LBA (eerste LBA van sekondêre partisietabel − 1)                                                                                                              |
| 56 (0x38) | 16 bytes | Skyf-GUID in mixed endian                                                                                                                                                      |
| 72 (0x48) | 8 bytes  | Begin-LBA van ’n skikking met partisie-inskrywings (altyd 2 in die primêre kopie)                                                                                              |
| 80 (0x50) | 4 bytes  | Aantal partisie-inskrywings in die skikking                                                                                                                                    |
| 84 (0x54) | 4 bytes  | Grootte van ’n enkele partisie-inskrywing (gewoonlik 80h of 128)                                                                                                               |
| 88 (0x58) | 4 bytes  | CRC32 van die skikking met partisie-inskrywings in little endian                                                                                                               |
| 92 (0x5C) | \*       | Gereserveer; moet vir die res van die blok nul wees (420 grepe vir ’n sektorgrootte van 512 grepe; kan meer wees met groter sektorgroottes)                                     |

**Partisie-inskrywings (LBA 2–33)**

| GUID-partisie-inskrywingsformaat |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Verskuiwing                      | Lengte   | Inhoud                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partisietipe-GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unieke partisie-GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | Eerste LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Laaste LBA (ingesluit, gewoonlik onewe)                                                                             |
| 48 (0x30)                   | 8 bytes  | Kenmerkvlae (bv. bit 60 dui op leesalleen)                                                               |
| 56 (0x38)                   | 72 bytes | Partisienaam (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-kode-eenhede)                               |

**Partisietipes**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Meer partisietipes by [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Ondersoek

Nadat jy die forensiese beeld met [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemonteer het, kan jy die eerste sektor met die Windows-nutsprogram [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** ondersoek. In die volgende beeld is ’n **MBR** op **sektor 0** bespeur en geïnterpreteer:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

Vir GPT, soek die _EFI PART_-handtekening in die primêre opskrif by **LBA 1**; LBA 0 bevat steeds die beskermende MBR.<sup>[[4]](#references)</sup>

### Vind data buite die gelyste partisies

’n Geskrapte partisiesinskrywing of ’n doelbewus ongebruikte gaping kan ’n lêerstelsel buite die huidige partisietoewysing laat. Lys op ’n **geverifieerde rou werkkopie** die ongeallokeerde reekse, en toets dan ’n moontlike begin-LBA as ’n lêerstelsel. `mmls` en `fsstat` gebruik **sektorverskuiwings**; gee aan albei die werklike logiese sektorgrootte. Moenie GPT-metadata-sektore met ’n versteekte volume verwar nie.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

As `fsstat` nie ’n lêerstelsel aan die begin van die gaping kan identifiseer nie, gebruik TestDisk **Analyse → Quick Search**, en daarna **Deeper Search** indien nodig. Druk `P` op ’n kandidaat om lêers te inspekteer; moenie **Write** op bewysmateriaal kies nie. Op GPT-beelde kontroleer `sgdisk --verify disk.img` die CRC’s en ooreenstemming tussen die hoof- en rugsteunkopieë, maar ’n rugsteunkop kan verouderd wees ná herpartisionering. Bevestig dus kandidaatgrense met lêerstelselstrukture voordat jy herstel.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Lêerstelsels

### Lys van Windows-lêerstelsels

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Die **FAT (File Allocation Table)**-lêerstelsel is ontwerp rondom sy kernkomponent, die lêertoewysingstabel, wat aan die begin van die volume geplaas is. ’n Volume het gewoonlik **twee FAT-kopieë**, hoewel die BPB een toelaat. FAT12/16 plaas die wortelgids in ’n vaste gebied; FAT32 stoor sy wortelgids in die data-area by die kluster wat deur `BPB_RootClus` aangedui word.<sup>[[7]](#references)</sup>

Die toewysingseenheid is ’n **kluster**: `BPB_BytsPerSec × BPB_SecPerClus`, wat nie noodwendig 512 grepe is nie. Die FAT-tipe word bepaal deur die aantal dataklusters, nie deur ’n weergawestring in die selflaaisektor nie. Die grense vir die klusteraantal is:<sup>[[7]](#references)</sup>

- **FAT12**: minder as 4,085 dataklusters.
- **FAT16**: 4,085 tot 65,524 dataklusters.
- **FAT32**: minstens 65,525 dataklusters; slegs 28 bisse van elke 32-bis FAT-inskrywing word vir die klusternommer gebruik.

Die 32-bis-lêergrootteveld beperk ’n gewone lêer tot **2³²−1 grepe** (net minder as 4 GiB).<sup>[[7]](#references)</sup>

Belangrike komponente van die wortelgids, veral vir FAT12 en FAT16, sluit in:

- **Lêer-/vouernaam** (tot 8 karakters)
- **Eienskappe**
- **Datums van skepping, wysiging en laaste toegang**
- **FAT-tabeladres** (wat die lêer se beginkluster aandui)
- **Lêergrootte**

### EXT

**Ext2** is die algemeenste lêerstelsel vir **nie-gejournaliseerde** partisies (**partisies wat nie veel verander nie**), soos die selflaaipartisie. **Ext3/4** is **gejournaliseer** en word gewoonlik vir die **oorblywende partisies** gebruik.

## **Metadata**

Sommige lêers bevat metadata. Hierdie inligting handel oor die lêer se inhoud en kan soms vir ’n ontleder interessant wees, aangesien dit, afhangend van die lêertipe, inligting kan bevat soos:

- Titel
- Weergawe van MS Office wat gebruik is
- Outeur
- Datums van skepping en laaste wysiging
- Kameramodel
- GPS-koördinate
- Beeldinligting

Jy kan nutsgoed soos [**exiftool**](https://exiftool.org) en [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gebruik om die metadata van ’n lêer te verkry.

## **Herstel van geskrapte lêers**

### Aangetekende geskrapte lêers

Soos voorheen gesien is, is daar verskeie plekke waar die lêer steeds gestoor word nadat dit “geskrap” is. Dit is omdat die skrap van ’n lêer uit ’n lêerstelsel dit gewoonlik net as geskrap merk, maar nie aan die data raak nie. Dit is dus moontlik om die lêerregisters (soos die MFT) te ondersoek en geskrapte lêers te vind.<sup>[[2]](#references)</sup>

Die bedryfstelsel stoor ook gewoonlik baie inligting oor lêerstelselveranderinge en rugsteunkopieë. Daarom is dit moontlik om te probeer om die lêer, of soveel moontlik inligting, daarmee te herstel.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** is ’n tegniek wat probeer om **lêers in die groot hoeveelheid data te vind**. Daar is 3 hoofmaniere waarop sulke nutsgoed werk: **op grond van lêertipe-opskrifte en -voettekste**, op grond van lêertipe-**strukture**, en op grond van die **inhoud** self.

Eenvoudige carving op grond van opskrifte/voettekste veronderstel aaneenliggende blokke en kan slegs ’n fragment oplewer wanneer ’n lêer verdeel is. Dit is nie ’n absolute beperking nie: PhotoRec het ’n SVE-intensiewe **Paranoid → bruteforce**-opsie vir sommige gefragmenteerde JPEG’s, terwyl fragmenthermontering wat lêerformate in ag neem, ander ondersteunde tipes kan herstel. Sien [file carving and recovery tools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving) vir ’n huidige werkvloei vir fragmenthermontering.<sup>[[8]](#references)</sup>

Daar is verskeie nutsgoed wat jy vir File Carving kan gebruik deur die lêertipes aan te dui waarna jy wil soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving is soortgelyk aan File Carving, maar **soek eerder na interessante fragmente van inligting as na volledige lêers**.\
Byvoorbeeld, in plaas daarvan om na ’n volledige lêer te soek wat aangetekende URL’s bevat, sal hierdie tegniek na URL’s soek.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Veilige skrap

Daar is natuurlik maniere om lêers en dele van die logboeke daaroor **“veilig” te skrap**. Dit is byvoorbeeld moontlik om die **inhoud** van ’n lêer verskeie kere met gemorsdata **te oorskryf**, en dan die **logboeke** oor die lêer uit die **$MFT** en **$LOGFILE** te **verwyder**, asook die **Volume Shadow Copies** te **verwyder**.<sup>[[3]](#references)</sup>\
Jy sal dalk agterkom dat die lêer se bestaan selfs ná dié handeling steeds op **ander plekke aangeteken** kan wees. Dit is inderdaad so, en ’n deel van die forensiese professionele persoon se werk is om daardie plekke te vind.



## References

- [1] [GUID-partisietabel - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Hoe om NTFS $I30 (gids)-inskrywings te skandeer vir bewyse van geskrapte lêers](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy-diens (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI-spesifikasie: GPT-skyfuitleg](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [The Sleuth Kit se mmls-handleiding](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [The Sleuth Kit se fsstat-handleiding](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft se FAT-spesifikasie](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [PhotoRec-herstelopsies](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [TestDisk-herstel van geskrapte partisies](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [sgdisk-handleiding](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [mount(8)-handleiding](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
