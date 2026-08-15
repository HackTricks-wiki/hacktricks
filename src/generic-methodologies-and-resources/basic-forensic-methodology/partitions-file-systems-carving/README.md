# Partitionen/Dateisysteme/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitionen

Eine Festplatte oder ein **SSD-Laufwerk kann verschiedene Partitionen enthalten**, um Daten physisch zu trennen.\
Die **kleinste** Einheit eines Datenträgers ist der **Sektor** (normalerweise bestehend aus 512B). Daher muss jede Partitionsgröße ein Vielfaches dieser Größe sein.

### MBR (Master Boot Record)

Er wird im **ersten Sektor des Datenträgers nach den 446B des Boot-Codes** gespeichert. Dieser Sektor ist entscheidend, um dem PC anzuzeigen, ob und von wo eine Partition gemountet werden soll.\
Er erlaubt bis zu **4 Partitionen** (höchstens **1** davon kann aktiv/**bootfähig** sein). Wenn du jedoch mehr Partitionen benötigst, kannst du **erweiterte Partitionen** verwenden. Das **letzte Byte** dieses ersten Sektors ist die Boot-Record-Signatur **0x55AA**. Nur eine Partition kann als aktiv markiert werden.\
MBR erlaubt **maximal 2,2 TB**.

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2,2 TB](<../../../images/image (350).png>)

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2,2 TB](<../../../images/image (304).png>)

In den **Bytes 440 bis 443** des MBR findest du die **Windows Disk Signature** (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows Disk Signature ab. Eine Änderung dieser Signatur könnte verhindern, dass Windows bootet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitionen - MBR (Master Boot Record): In den Bytes 440 bis 443 des MBR findest du die Windows Disk Signature (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte...](<../../../images/image (310).png>)

**Format**

| Offset      | Länge      | Element             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot-Code           |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition     |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition    |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition    |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA |

**Format des Partitionseintrags**

| Offset    | Länge    | Element                                                |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktives Flag (0x80 = bootfähig)                        |
| 1 (0x01)  | 1 (0x01) | Start-Head                                            |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0–5); obere Zylinderbits (6–7)      |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                  |
| 4 (0x04)  | 1 (0x01) | Partitions-Typcode (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End-Head                                              |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0–5); obere Zylinderbits (6–7)        |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                    |
| 8 (0x08)  | 4 (0x04) | Der Partition vorausgehende Sektoren (Little-Endian)  |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                            |

Um einen MBR unter Linux zu mounten, musst du zunächst den Start-Offset ermitteln (du kannst `fdisk` und den Befehl `p` verwenden).

![Partitionen - MBR (Master Boot Record): Um einen MBR unter Linux zu mounten, musst du zunächst den Start-Offset ermitteln (du kannst fdisk und den Befehl p verwenden)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Verwende anschließend den folgenden Code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ist ein gängiges Schema zur **Angabe der Position von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, im Allgemeinen auf sekundären Speichersystemen wie Festplattenlaufwerken. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index lokalisiert**, wobei der erste Block LBA 0, der zweite LBA 1 usw. ist.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekannt als GPT, wird aufgrund ihrer erweiterten Fähigkeiten gegenüber MBR (Master Boot Record) bevorzugt. GPT zeichnet sich durch ihren **global eindeutigen Bezeichner** für Partitionen aus und bietet mehrere Vorteile:

- **Position und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64bits**, im Gegensatz zu den 32bits von MBR.
- **Partitionslimits**: GPT unterstützt unter Windows bis zu **128 Partitionen** und ermöglicht bis zu **9.4ZB** Daten.
- **Partitionsnamen**: Bietet die Möglichkeit, Partitionen mit bis zu 36 Unicode-Zeichen zu benennen.

**Datenresilienz und Wiederherstellung**:

- **Redundanz**: Anders als MBR beschränkt GPT die Partitions- und Bootdaten nicht auf einen einzigen Ort. Diese Daten werden über die Festplatte repliziert, wodurch Datenintegrität und Resilienz verbessert werden.
- **Cyclic Redundancy Check (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. GPT überwacht aktiv auf Datenbeschädigungen und versucht bei deren Erkennung, die beschädigten Daten von einem anderen Ort auf der Festplatte wiederherzustellen.

**Protective MBR (LBA0)**:

- GPT gewährleistet Abwärtskompatibilität durch einen Protective MBR. Dieses Feature befindet sich im Legacy-MBR-Bereich, ist jedoch so ausgelegt, dass ältere MBR-basierte Dienstprogramme GPT-Festplatten nicht versehentlich überschreiben und dadurch die Datenintegrität von GPT-formatierten Festplatten geschützt wird.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

In Betriebssystemen, die das **GPT-based boot through BIOS**-Verfahren anstelle von EFI unterstützen, kann der erste Sektor weiterhin zum Speichern des Codes der ersten Stufe des **bootloader** verwendet werden, muss jedoch so **modified** werden, dass er **GPT**-**partitions** erkennt. Der bootloader im MBR darf keine Sektorgröße von 512 Bytes voraussetzen.

**Partition table header (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Der Header der Partitionstabelle definiert die nutzbaren Blöcke auf der Festplatte. Außerdem definiert er die Anzahl und Größe der Partitionseinträge, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Signature ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h or 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)on little-endian machines) |
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

Weitere Partitionstypen unter [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspecting

Nachdem das Forensics-Image mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemountet wurde, kann der erste Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** untersucht werden. Im folgenden Bild wurde ein **MBR** auf **Sektor 0** erkannt und interpretiert:

![GPT (GUID Partition Table) - Inspecting: Nachdem das Forensics-Image mit ArsenalImageMounter gemountet wurde, kann der erste Sektor mit dem Windows-Tool Active Disk Editor untersucht werden. Im...](<../../../images/image (354).png>)

Wenn es sich statt um einen MBR um eine **GPT table** handelt, sollte die Signatur _EFI PART_ in **Sektor 1** erscheinen (der im vorherigen Bild leer ist).

## File-Systems

### Windows file-systems list

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)**-Dateisystem ist um seine zentrale Komponente herum aufgebaut: die File Allocation Table, die am Anfang des Volumes positioniert ist. Dieses System schützt Daten, indem es **zwei Kopien** der Tabelle verwaltet und dadurch die Datenintegrität sicherstellt, selbst wenn eine Kopie beschädigt ist. Die Tabelle sowie der Root-Ordner müssen sich an einem **festen Ort** befinden, was für den Startvorgang des Systems entscheidend ist.

Die grundlegende Speichereinheit des Dateisystems ist ein **Cluster, normalerweise 512B**, der aus mehreren Sektoren besteht. FAT hat sich über mehrere Versionen weiterentwickelt:

- **FAT12**, das 12-Bit-Clusteradressen unterstützt und bis zu 4078 Cluster (4084 mit UNIX) verwalten kann.
- **FAT16**, das auf 16-Bit-Adressen erweitert wurde und dadurch bis zu 65.517 Cluster aufnehmen kann.
- **FAT32**, das mit 32-Bit-Adressen eine weitere Erweiterung darstellt und beeindruckende 268.435.456 Cluster pro Volume ermöglicht.

Eine wesentliche Einschränkung aller FAT-Versionen ist die **maximale Dateigröße von 4GB**, die durch das 32-Bit-Feld zur Speicherung der Dateigröße vorgegeben wird.

Zu den wichtigen Komponenten des Root-Verzeichnisses, insbesondere bei FAT12 und FAT16, gehören:

- **File/Folder Name** (bis zu 8 Zeichen)
- **Attributes**
- **Creation, Modification, and Last Access Dates**
- **FAT Table Address** (gibt den Startcluster der Datei an)
- **File Size**

### EXT

**Ext2** ist das häufigste Dateisystem für **not journaling**-Partitionen (**Partitionen, die sich nicht stark verändern**), wie etwa die Boot-Partition. **Ext3/4** verwenden **journaling** und werden normalerweise für die **rest partitions** verwendet.

## **Metadata**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei und können für einen Analysten manchmal interessant sein, da sie je nach Dateityp Informationen enthalten können wie:

- Titel
- Verwendete MS Office-Version
- Autor
- Erstellungs- und Änderungsdatum
- Kameramodell
- GPS-Koordinaten
- Bildinformationen

Mit Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) können die Metadaten einer Datei ausgelesen werden.

## **Deleted Files Recovery**

### Logged Deleted Files

Wie bereits zuvor beschrieben, gibt es mehrere Stellen, an denen die Datei nach dem "Löschen" noch gespeichert ist. Der Grund dafür ist, dass das Löschen einer Datei aus einem Dateisystem normalerweise lediglich markiert, dass sie gelöscht wurde, während die Daten nicht verändert werden. Daher ist es möglich, die Register der Dateien (wie die MFT) zu untersuchen und die gelöschten Dateien zu finden.<sup>[[2]](#references)</sup>

Außerdem speichert das OS normalerweise viele Informationen über Änderungen am Dateisystem und Backups. Daher kann versucht werden, diese zur Wiederherstellung der Datei oder möglichst vieler Informationen zu verwenden.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** ist eine Technik, mit der versucht wird, **Dateien in der Datenmenge zu finden**. Es gibt drei Hauptmethoden, nach denen solche Tools arbeiten: **anhand von Headern und Footern der Dateitypen**, anhand der **Strukturen** der Dateitypen und anhand des **Inhalts** selbst.

Beachte, dass diese Technik **nicht zum Wiederherstellen fragmentierter Dateien geeignet ist**. Wenn eine Datei **nicht in zusammenhängenden Sektoren gespeichert** ist, kann diese Technik sie oder zumindest Teile davon nicht finden.

Es gibt mehrere Tools, die du für File Carving verwenden kannst, wobei du die zu suchenden Dateitypen angibst.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving ähnelt File Carving, sucht jedoch **nicht nach vollständigen Dateien, sondern nach interessanten Informationsfragmenten**.\
Anstatt beispielsweise nach einer vollständigen Datei mit protokollierten URLs zu suchen, sucht diese Technik nach URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Natürlich gibt es Möglichkeiten, Dateien und Teile der Logs über sie **"sicher" zu löschen**. Beispielsweise kann der **Inhalt** einer Datei mehrmals mit nutzlosen Daten **überschrieben** werden. Anschließend können die **Logs** über die Datei aus **$MFT** und **$LOGFILE** entfernt und die **Volume Shadow Copies** gelöscht werden.<sup>[[3]](#references)</sup>\
Du wirst möglicherweise feststellen, dass selbst nach dieser Aktion **an anderen Stellen weiterhin die Existenz der Datei protokolliert sein kann**. Das ist tatsächlich der Fall, und es gehört zu den Aufgaben von Forensics-Experten, diese Stellen zu finden.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [So werden NTFS-$I30-(Verzeichnis-)Einträge auf Hinweise auf gelöschte Dateien untersucht](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
