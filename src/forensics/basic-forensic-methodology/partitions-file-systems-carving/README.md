# Partitions/File Systems/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitions

'n Hardeskyf of 'n **SSD-skyf kan verskillende partities bevat** met die doel om data fisies te skei.\
Die **minimum** eenheid van 'n skyf is die **sektor** (normaalweg saamgestel uit 512B). So, elke partisie grootte moet 'n veelvoud van daardie grootte wees.

### MBR (master Boot Record)

Dit is toegeken in die **eerste sektor van die skyf na die 446B van die opstartkode**. Hierdie sektor is noodsaaklik om aan die rekenaar aan te dui wat en van waar 'n partisie gemonteer moet word.\
Dit laat tot **4 partities** toe (max **net 1** kan aktief/**opstartbaar** wees). As jy egter meer partities nodig het, kan jy **uitgebreide partities** gebruik. Die **laaste byte** van hierdie eerste sektor is die opstartrekord handtekening **0x55AA**. Slegs een partisie kan as aktief gemerk word.\
MBR laat **max 2.2TB** toe.

![](<../../../images/image (489).png>)

![](<../../../images/image (490).png>)

Van die **bytes 440 tot 443** van die MBR kan jy die **Windows Disk Signature** vind (as Windows gebruik word). Die logiese skyfletter van die hardeskyf hang af van die Windows Disk Signature. Om hierdie handtekening te verander kan voorkom dat Windows opstart (tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![](<../../../images/image (493).png>)

**Formaat**

| Offset      | Lengte     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Opstartkode         |
| 446 (0x1BE) | 16 (0x10)  | Eerste Partisie     |
| 462 (0x1CE) | 16 (0x10)  | Tweede Partisie     |
| 478 (0x1DE) | 16 (0x10)  | Derde Partisie      |
| 494 (0x1EE) | 16 (0x10)  | Vierde Partisie     |
| 510 (0x1FE) | 2 (0x2)    | Handtekening 0x55 0xAA |

**Partisie Rekord Formaat**

| Offset    | Lengte   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktiewe vlag (0x80 = opstartbaar)                      |
| 1 (0x01)  | 1 (0x01) | Beginkop                                               |
| 2 (0x02)  | 1 (0x01) | Beginsektor (bits 0-5); boonste bits van silinder (6- 7) |
| 3 (0x03)  | 1 (0x01) | Begin silinder laagste 8 bits                           |
| 4 (0x04)  | 1 (0x01) | Partisie tipe kode (0x83 = Linux)                      |
| 5 (0x05)  | 1 (0x01) | Eindkop                                               |
| 6 (0x06)  | 1 (0x01) | Eindsektor (bits 0-5); boonste bits van silinder (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Eind silinder laagste 8 bits                             |
| 8 (0x08)  | 4 (0x04) | Sektore wat die partisie voorafgaan (little endian)    |
| 12 (0x0C) | 4 (0x04) | Sektore in partisie                                   |

Om 'n MBR in Linux te monteer, moet jy eers die begin offset kry (jy kan `fdisk` en die `p` opdrag gebruik)

![](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (12).png>)

En dan die volgende kode gebruik
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logiese blok adressering)**

**Logiese blok adressering** (**LBA**) is 'n algemene skema wat gebruik word om **die ligging van blokke** data wat op rekenaaropbergingsapparate gestoor is, spesifiek sekondêre opbergingsisteme soos hardeskyfskywe, aan te dui. LBA is 'n veral eenvoudige lineêre adressering skema; **blokke word geleë deur 'n heelgetal indeks**, met die eerste blok wat LBA 0 is, die tweede LBA 1, en so aan.

### GPT (GUID Partisie Tabel)

Die GUID Partisie Tabel, bekend as GPT, word verkies vir sy verbeterde vermoëns in vergelyking met MBR (Master Boot Record). Kenmerkend vir sy **globaal unieke identifiseerder** vir partisie, val GPT op verskeie maniere uit:

- **Ligging en Grootte**: Beide GPT en MBR begin by **sektor 0**. GPT werk egter op **64-bits**, in teenstelling met MBR se 32-bits.
- **Partisie Grense**: GPT ondersteun tot **128 partisie** op Windows stelsels en akkommodeer tot **9.4ZB** data.
- **Partisie Nnames**: Bied die vermoë om partisie te benoem met tot 36 Unicode karakters.

**Data Veerkragtigheid en Herstel**:

- **Redundansie**: Anders as MBR, beperk GPT nie partisie en opstartdata tot 'n enkele plek nie. Dit repliseer hierdie data oor die skyf, wat data integriteit en veerkragtigheid verbeter.
- **Cyclic Redundancy Check (CRC)**: GPT gebruik CRC om data integriteit te verseker. Dit monitor aktief vir datakorruptie, en wanneer dit opgespoor word, probeer GPT om die gekorrupte data van 'n ander skyf ligging te herstel.

**Beskermer MBR (LBA0)**:

- GPT handhaaf agterwaartse kompatibiliteit deur 'n beskermende MBR. Hierdie kenmerk woon in die erfenis MBR ruimte, maar is ontwerp om te voorkom dat ouer MBR-gebaseerde nutsprogramme per ongeluk GPT skywe oorskryf, en so die data integriteit op GPT-geformatteerde skywe te beskerm.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (491).png>)

**Hibrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

In bedryfstelsels wat **GPT-gebaseerde opstart deur BIOS** dienste ondersteun eerder as EFI, kan die eerste sektor ook steeds gebruik word om die eerste fase van die **opstartlader** kode te stoor, maar **gewysig** om **GPT** **partisie** te herken. Die opstartlader in die MBR mag nie 'n sektor grootte van 512 bytes aanvaar nie.

**Partisie tabel kop (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)

Die partisie tabel kop definieer die bruikbare blokke op die skyf. Dit definieer ook die aantal en grootte van die partisie inskrywings wat die partisie tabel vorm (offsets 80 en 84 in die tabel).

| Offset    | Lengte   | Inhouds                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Handtekening ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h of 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)op little-endian masjiene) |
| 8 (0x08)  | 4 bytes  | Hersiening 1.0 (00h 00h 01h 00h) vir UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Kopgrootte in little endian (in bytes, gewoonlik 5Ch 00h 00h 00h of 92 bytes)                                                                                                 |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) van kop (offset +0 tot kopgrootte) in little endian, met hierdie veld op nul tydens berekening                             |
| 20 (0x14) | 4 bytes  | Gereserveer; moet nul wees                                                                                                                                                       |
| 24 (0x18) | 8 bytes  | Huidige LBA (ligging van hierdie kopie van die kop)                                                                                                                                   |
| 32 (0x20) | 8 bytes  | Rugsteun LBA (ligging van die ander kopie van die kop)                                                                                                                               |
| 40 (0x28) | 8 bytes  | Eerste bruikbare LBA vir partisie (primêre partisie tabel laaste LBA + 1)                                                                                                       |
| 48 (0x30) | 8 bytes  | Laaste bruikbare LBA (sekondêre partisie tabel eerste LBA − 1)                                                                                                                    |
| 56 (0x38) | 16 bytes | Skyf GUID in gemengde endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Begin LBA van 'n reeks partisie inskrywings (altyd 2 in primêre kopie)                                                                                                     |
| 80 (0x50) | 4 bytes  | Aantal partisie inskrywings in reeks                                                                                                                                         |
| 84 (0x54) | 4 bytes  | Grootte van 'n enkele partisie inskrywing (gewoonlik 80h of 128)                                                                                                                        |
| 88 (0x58) | 4 bytes  | CRC32 van partisie inskrywings reeks in little endian                                                                                                                            |
| 92 (0x5C) | \*       | Gereserveer; moet nul wees vir die res van die blok (420 bytes vir 'n sektor grootte van 512 bytes; maar kan meer wees met groter sektor groottes)                                      |

**Partisie inskrywings (LBA 2–33)**

| GUID partisie inskrywing formaat |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Lengte   | Inhouds                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partisie tipe GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (gemengde endian) |
| 16 (0x10)                   | 16 bytes | Unieke partisie GUID (gemengde endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | Eerste LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Laaste LBA (insluitend, gewoonlik onpare)                                                                             |
| 48 (0x30)                   | 8 bytes  | Kenmerkvlaggies (bv. bit 60 dui op slegs lees)                                                               |
| 56 (0x38)                   | 72 bytes | Partisie naam (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE kode eenhede)                               |

**Partisie Tipes**

![](<../../../images/image (492).png>)

Meer partisie tipes in [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspeksie

Na die montering van die forensiese beeld met [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/), kan jy die eerste sektor inspekteer met die Windows hulpmiddel [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** In die volgende beeld is 'n **MBR** op die **sektor 0** opgespoor en geïnterpreteer:

![](<../../../images/image (494).png>)

As dit 'n **GPT tabel in plaas van 'n MBR** was, moet die handtekening _EFI PART_ in die **sektor 1** verskyn (wat in die vorige beeld leeg is).

## Lêer-Stelsels

### Windows lêer-stelsels lys

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Die **FAT (Lêer Toewysing Tabel)** lêerstelsel is ontwerp rondom sy kernkomponent, die lêer toewysing tabel, wat aan die begin van die volume geleë is. Hierdie stelsel beskerm data deur **twee kopieë** van die tabel te handhaaf, wat data integriteit verseker selfs as een gekorrupteer is. Die tabel, saam met die wortel gids, moet in 'n **vaste ligging** wees, wat noodsaaklik is vir die stelsel se opstartproses.

Die basiese eenheid van opberging in die lêerstelsel is 'n **kluster, gewoonlik 512B**, wat uit verskeie sektore bestaan. FAT het deur weergawes ontwikkel:

- **FAT12**, wat 12-bis kluster adresse ondersteun en tot 4078 klusters hanteer (4084 met UNIX).
- **FAT16**, wat verbeter na 16-bis adresse, wat tot 65,517 klusters akkommodeer.
- **FAT32**, wat verder gevorder het met 32-bis adresse, wat 'n indrukwekkende 268,435,456 klusters per volume toelaat.

'n Belangrike beperking oor FAT weergawes is die **4GB maksimum lêergrootte**, wat deur die 32-bis veld wat vir lêergrootte opberging gebruik word, opgelê word.

Belangrike komponente van die wortel gids, veral vir FAT12 en FAT16, sluit in:

- **Lêer/Gids Naam** (tot 8 karakters)
- **Kenmerke**
- **Skep-, Wysigings- en Laaste Toegang Datums**
- **FAT Tabel Adres** (wat die begin kluster van die lêer aandui)
- **Lêergrootte**

### EXT

**Ext2** is die mees algemene lêerstelsel vir **nie-journaling** partisie (**partisie wat nie veel verander nie**) soos die opstartpartisie. **Ext3/4** is **journaling** en word gewoonlik gebruik vir die **oorige partisie**.

## **Metadata**

Sommige lêers bevat metadata. Hierdie inligting is oor die inhoud van die lêer wat soms interessant vir 'n ontleder kan wees, aangesien dit afhang van die lêer tipe, dit mag inligting soos hê:

- Titel
- MS Office Weergawe gebruik
- Skrywer
- Datums van skepping en laaste wysiging
- Model van die kamera
- GPS koördinate
- Beeld inligting

Jy kan hulpmiddels soos [**exiftool**](https://exiftool.org) en [**Metadiver**](https://www.easymetadata.com/metadiver-2/) gebruik om die metadata van 'n lêer te verkry.

## **Verwyderde Lêers Herstel**

### Geregistreerde Verwyderde Lêers

Soos voorheen gesien, is daar verskeie plekke waar die lêer steeds gestoor is nadat dit "verwyder" is. Dit is omdat die verwydering van 'n lêer uit 'n lêerstelsel gewoonlik net dit as verwyder merk, maar die data word nie aangeraak nie. Dan is dit moontlik om die registrasies van die lêers (soos die MFT) te inspekteer en die verwyderde lêers te vind.

Ook, die OS stoor gewoonlik baie inligting oor lêerstelsel veranderinge en rugsteun, so dit is moontlik om te probeer om dit te gebruik om die lêer of soveel inligting as moontlik te herstel.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Lêer Karving**

**Lêer karving** is 'n tegniek wat probeer om **lêers in die massa data** te vind. Daar is 3 hoof maniere waarop hulpmiddels soos hierdie werk: **Gebaseer op lêer tipe koppe en voete**, gebaseer op lêer tipe **strukture** en gebaseer op die **inhoud** self.

Let daarop dat hierdie tegniek **nie werk om gefragmenteerde lêers te herstel nie**. As 'n lêer **nie in aaneengeskakelde sektore gestoor is nie**, dan sal hierdie tegniek nie in staat wees om dit te vind of ten minste 'n deel daarvan nie.

Daar is verskeie hulpmiddels wat jy kan gebruik vir lêer Karving wat die lêer tipes aandui wat jy wil soek.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stroom **C**arving

Data Stroom Karving is soortgelyk aan Lêer Karving, maar **in plaas daarvan om na volledige lêers te soek, soek dit na interessante fragmente** van inligting.\
Byvoorbeeld, in plaas daarvan om na 'n volledige lêer te soek wat geregistreerde URL's bevat, sal hierdie tegniek na URL's soek.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Veilige Verwydering

Natuurlik is daar maniere om lêers en 'n deel van logs oor hulle **"veilig" te verwyder**. Byvoorbeeld, dit is moontlik om die **inhoud** van 'n lêer met rommeldata verskeie kere te oorskryf, en dan die **logs** van die **$MFT** en **$LOGFILE** oor die lêer te **verwyder**, en die **Volume Shadow Copies** te **verwyder**.\
Jy mag opgemerk het dat selfs wanneer jy daardie aksie uitvoer, daar dalk **ander dele is waar die bestaan van die lêer steeds geregistreer is**, en dit is waar, en 'n deel van die forensiese professionele se werk is om hulle te vind.

## Verwysings

- [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [http://ntfs.com/ntfs-permissions.htm](http://ntfs.com/ntfs-permissions.htm)
- [https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- **iHackLabs Gekwalifiseerde Digitale Forensiese Windows**

{{#include ../../../banners/hacktricks-training.md}}
