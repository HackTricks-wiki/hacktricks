# Partitionen/Dateisysteme/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitionen

Eine Festplatte oder ein **SSD disk kann verschiedene Partitionen enthalten**, um Daten physisch zu trennen.\
Die **kleinste** Einheit eines Datenträgers ist der **Sektor** (normalerweise bestehend aus 512B). Daher muss jede Partitionsgröße ein Vielfaches dieser Größe sein.

### MBR (master Boot Record)

Er wird im **ersten Sektor des Datenträgers nach den 446B des Boot-Codes** gespeichert. Dieser Sektor ist entscheidend, um dem PC anzuzeigen, ob und von wo eine Partition gemountet werden soll.\
Er erlaubt bis zu **4 Partitionen** (höchstens **1** davon kann aktiv/**bootable** sein). Wenn du jedoch mehr Partitionen benötigst, kannst du **extended partitions** verwenden. Das **letzte Byte** dieses ersten Sektors ist die Boot-Record-Signatur **0x55AA**. Nur eine Partition kann als aktiv markiert werden.\
MBR erlaubt **maximal 2.2TB**.

![Partitionen - MBR (master Boot Record): MBR erlaubt maximal 2.2TB](<../../../images/image (350).png>)

![Partitionen - MBR (master Boot Record): MBR erlaubt maximal 2.2TB](<../../../images/image (304).png>)

In den **Bytes 440 bis 443** des MBR findest du die **Windows Disk Signature** (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows Disk Signature ab. Das Ändern dieser Signatur könnte verhindern, dass Windows bootet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitionen - MBR (master Boot Record): In den Bytes 440 bis 443 des MBR findest du die Windows Disk Signature (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte...](<../../../images/image (310).png>)

**Format**

| Offset      | Länge     | Element                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot-Code           |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition     |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition    |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition     |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA |

**Format des Partitionseintrags**

| Offset    | Länge   | Element                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktives Flag (0x80 = bootable)                          |
| 1 (0x01)  | 1 (0x01) | Start-Head                                             |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0-5); obere Bits des Zylinders (6- 7) |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                           |
| 4 (0x04)  | 1 (0x01) | Partitionstyp-Code (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | End-Head                                               |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0-5); obere Bits des Zylinders (6- 7)   |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                             |
| 8 (0x08)  | 4 (0x04) | Der Partition vorausgehende Sektoren (little endian)            |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                                   |

Um einen MBR unter Linux zu mounten, musst du zuerst den Start-Offset ermitteln (du kannst `fdisk` und den Befehl `p` verwenden).

![Partitionen - MBR (master Boot Record): Um einen MBR unter Linux zu mounten, musst du zuerst den Start-Offset ermitteln (du kannst fdisk und den Befehl p verwenden)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Verwende anschließend den folgenden Code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ist ein gängiges Schema zur **Angabe des Speicherorts von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, im Allgemeinen auf sekundären Speichersystemen wie Festplattenlaufwerken. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index lokalisiert**, wobei der erste Block LBA 0, der zweite LBA 1 usw. ist.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekannt als GPT, wird aufgrund ihrer erweiterten Funktionen gegenüber MBR (Master Boot Record) bevorzugt. GPT zeichnet sich durch seine **global eindeutige Kennung** für Partitionen aus und bietet mehrere Besonderheiten:

- **Speicherort und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64bits**, im Gegensatz zu den 32bits von MBR.
- **Partitionslimits**: GPT unterstützt auf Windows-Systemen bis zu **128 Partitionen** und kann bis zu **9.4ZB** an Daten verwalten.
- **Partitionsnamen**: Ermöglicht die Benennung von Partitionen mit bis zu 36 Unicode-Zeichen.

**Datenresilienz und Wiederherstellung**:

- **Redundanz**: Im Gegensatz zu MBR beschränkt GPT die Partitions- und Bootdaten nicht auf einen einzigen Speicherort. Es repliziert diese Daten über die Festplatte hinweg und verbessert dadurch Datenintegrität und Resilienz.
- **Cyclic Redundancy Check (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. Es überwacht aktiv auf Datenkorruption und versucht bei deren Erkennung, die beschädigten Daten von einem anderen Speicherort auf der Festplatte wiederherzustellen.

**Protective MBR (LBA0)**:

- GPT gewährleistet durch einen Protective MBR die Abwärtskompatibilität. Diese Funktion befindet sich im Speicherbereich des Legacy-MBR, verhindert jedoch, dass ältere MBR-basierte Utilities GPT-Festplatten versehentlich überschreiben, und schützt dadurch die Datenintegrität von GPT-formatierten Festplatten.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

In Betriebssystemen, die **GPT-basiertes Booten über BIOS**-Dienste statt EFI unterstützen, kann der erste Sektor weiterhin zum Speichern der **Bootloader**-Code der ersten Stufe verwendet werden, der jedoch so **modifiziert** ist, dass er **GPT**-**Partitionen** erkennt. Der Bootloader im MBR darf keine Sektorgröße von 512 Bytes voraussetzen.

**Partitions-Table-Header (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Der Partitions-Table-Header definiert die nutzbaren Blöcke auf der Festplatte. Außerdem definiert er die Anzahl und Größe der Partitionseinträge, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge   | Inhalt                                                                                                                                                                   |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 Bytes  | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)auf Little-Endian-Maschinen) |
| 8 (0x08)  | 4 Bytes  | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 Bytes  | Headergröße in Little-Endian (in Bytes, gewöhnlich 5Ch 00h 00h 00h oder 92 Bytes)                                                                                           |
| 16 (0x10) | 4 Bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis zur Headergröße) in Little-Endian, wobei dieses Feld während der Berechnung auf null gesetzt wird     |
| 20 (0x14) | 4 Bytes  | Reserviert; muss null sein                                                                                                                                                  |
| 24 (0x18) | 8 Bytes  | Aktuelle LBA (Speicherort dieser Header-Kopie)                                                                                                                              |
| 32 (0x20) | 8 Bytes  | Backup-LBA (Speicherort der anderen Header-Kopie)                                                                                                                           |
| 40 (0x28) | 8 Bytes  | Erste nutzbare LBA für Partitionen (letzte LBA der primären Partitionstabelle + 1)                                                                                          |
| 48 (0x30) | 8 Bytes  | Letzte nutzbare LBA (erste LBA der sekundären Partitionstabelle − 1)                                                                                                        |
| 56 (0x38) | 16 Bytes | Festplatten-GUID in gemischter Endianness                                                                                                                                    |
| 72 (0x48) | 8 Bytes  | Start-LBA eines Arrays von Partitionseinträgen (in der primären Kopie immer 2)                                                                                              |
| 80 (0x50) | 4 Bytes  | Anzahl der Partitionseinträge im Array                                                                                                                                      |
| 84 (0x54) | 4 Bytes  | Größe eines einzelnen Partitionseintrags (gewöhnlich 80h oder 128)                                                                                                         |
| 88 (0x58) | 4 Bytes  | CRC32 des Arrays der Partitionseinträge in Little-Endian                                                                                                                   |
| 92 (0x5C) | \*       | Reserviert; muss für den Rest des Blocks aus Nullen bestehen (420 Bytes bei einer Sektorgröße von 512 Bytes; bei größeren Sektorgrößen kann es mehr sein)                  |

**Partitionseinträge (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Länge   | Inhalt                                                                                                        |
| 0 (0x00)                    | 16 Bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (gemischte Endianness) |
| 16 (0x10)                   | 16 Bytes | Eindeutige Partitions-GUID (gemischte Endianness)                                                             |
| 32 (0x20)                   | 8 Bytes  | Erste LBA ([Little-Endian](https://en.wikipedia.org/wiki/Little_endian))                                     |
| 40 (0x28)                   | 8 Bytes  | Letzte LBA (einschließlich, gewöhnlich ungerade)                                                             |
| 48 (0x30)                   | 8 Bytes  | Attribut-Flags (z. B. bezeichnet Bit 60 den Schreibschutz)                                                   |
| 56 (0x38)                   | 72 Bytes | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                           |

**Partition Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 Bytes | Partitionsname (36 UTF-16LE-Codeeinheiten)](<../../../images/image (83).png>)

Weitere Partition Types unter [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Untersuchung

Nachdem das Forensics-Image mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) gemountet wurde, können Sie den ersten Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** untersuchen. Im folgenden Bild wurde ein **MBR** in **Sektor 0** erkannt und interpretiert:

![GPT (GUID Partition Table) - Untersuchung: Nachdem das Forensics-Image mit ArsenalImageMounter gemountet wurde, können Sie den ersten Sektor mit dem Windows-Tool Active Disk Editor untersuchen. Im...](<../../../images/image (354).png>)

Wenn es sich statt um einen MBR um eine **GPT-Tabelle** handelt, sollte die Signatur _EFI PART_ in **Sektor 1** erscheinen (der im vorherigen Bild leer ist).

## Datei-Systeme

### Liste der Windows-Datei-Systeme

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)-Datei-System** ist um seine Kernkomponente, die File Allocation Table, herum aufgebaut, die sich am Anfang des Volumes befindet. Dieses System schützt Daten, indem es **zwei Kopien** der Tabelle verwaltet und dadurch die Datenintegrität sicherstellt, selbst wenn eine Kopie beschädigt wird. Die Tabelle muss sich zusammen mit dem Root-Ordner an einem **festen Speicherort** befinden, was für den Startvorgang des Systems entscheidend ist.

Die grundlegende Speichereinheit des Datei-Systems ist ein **Cluster, gewöhnlich 512B**, der aus mehreren Sektoren besteht. FAT wurde in mehreren Versionen weiterentwickelt:

- **FAT12** unterstützt 12-Bit-Clusteradressen und verarbeitet bis zu 4078 Cluster (4084 mit UNIX).
- **FAT16** erweitert dies auf 16-Bit-Adressen und kann dadurch bis zu 65.517 Cluster aufnehmen.
- **FAT32** verwendet 32-Bit-Adressen und ermöglicht beeindruckende 268.435.456 Cluster pro Volume.

Eine wesentliche Einschränkung aller FAT-Versionen ist die **maximale Dateigröße von 4GB**, die durch das 32-Bit-Feld für die Speicherung der Dateigröße vorgegeben wird.

Zu den wichtigen Komponenten des Root-Verzeichnisses, insbesondere bei FAT12 und FAT16, gehören:

- **Datei-/Ordnername** (bis zu 8 Zeichen)
- **Attribute**
- **Erstellungs-, Änderungs- und Letzter-Zugriff-Daten**
- **Adresse der FAT-Tabelle** (gibt den Startcluster der Datei an)
- **Dateigröße**

### EXT

**Ext2** ist das häufigste Datei-System für **nicht journalende** Partitionen (**Partitionen, die sich nicht häufig ändern**), etwa die Boot-Partition. **Ext3/4** verwenden Journaling und werden normalerweise für die **übrigen Partitionen** verwendet.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei und können für einen Analysten interessant sein, da sie abhängig vom Dateityp beispielsweise folgende Informationen enthalten können:

- Titel
- Verwendete MS-Office-Version
- Autor
- Erstellungsdatum und Datum der letzten Änderung
- Kameramodell
- GPS-Koordinaten
- Bildinformationen

Sie können Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) verwenden, um die Metadaten einer Datei abzurufen.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits zuvor erwähnt, gibt es mehrere Orte, an denen die Datei nach ihrer "Löschung" weiterhin gespeichert ist. Dies liegt daran, dass das Löschen einer Datei aus einem Datei-System normalerweise lediglich ihren Status als gelöscht markiert, die Daten jedoch nicht verändert. Daher ist es möglich, die Register der Dateien (wie die MFT) zu untersuchen und die gelöschten Dateien zu finden.<sup>[[2]](#references)</sup>

Außerdem speichert das Betriebssystem normalerweise viele Informationen über Änderungen am Datei-System und Backups. Daher kann versucht werden, diese zur Wiederherstellung der Datei oder möglichst vieler Informationen zu verwenden.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File Carving** ist eine Technik, die versucht, **Dateien in der Datenmenge zu finden**. Es gibt drei Hauptmethoden, nach denen solche Tools arbeiten: **anhand von Headern und Footern der Dateitypen**, anhand der **Strukturen** der Dateitypen und anhand des **Inhalts** selbst.

Beachten Sie, dass diese Technik **nicht zum Wiederherstellen fragmentierter Dateien geeignet ist**. Wenn eine Datei **nicht in zusammenhängenden Sektoren gespeichert** ist, kann diese Technik sie entweder überhaupt nicht oder zumindest nicht vollständig finden.

Es gibt mehrere Tools, die Sie für File Carving verwenden können, wobei Sie die zu suchenden Dateitypen angeben


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

Offensichtlich gibt es Möglichkeiten, Dateien und Teile der Protokolle über sie **"sicher" zu löschen**. Beispielsweise ist es möglich, den **Inhalt** einer Datei mehrmals mit beliebigen Daten zu **überschreiben**, anschließend die **Protokolle** der Datei aus **$MFT** und **$LOGFILE** zu **entfernen** und die **Volume Shadow Copies** zu **löschen**.<sup>[[3]](#references)</sup>\
Sie werden möglicherweise feststellen, dass selbst nach dieser Aktion **andere Bereiche weiterhin die Existenz der Datei protokollieren** können. Das stimmt, und es gehört zu den Aufgaben von Forensics-Experten, diese Bereiche zu finden.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [So durchsuchen Sie NTFS-$I30-(Verzeichnis-)Einträge nach Beweisen für gelöschte Dateien](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
