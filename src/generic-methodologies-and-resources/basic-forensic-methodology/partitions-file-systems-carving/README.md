# Partitionen/Dateisysteme/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitionen

Eine Festplatte oder ein **SSD-Laufwerk kann verschiedene Partitionen enthalten**, um Daten physisch zu trennen.\
Die **kleinste** Einheit eines Datenträgers ist der **Sektor** (normalerweise bestehend aus 512B). Daher muss jede Partitionsgröße ein Vielfaches dieser Größe sein.

### MBR (Master Boot Record)

Er wird im **ersten Sektor des Datenträgers nach den 446B des Boot-Codes** gespeichert. Dieser Sektor ist entscheidend, um dem PC anzugeben, ob und wo eine Partition gemountet werden soll.\
Er erlaubt bis zu **4 Partitionen** (höchstens **1** davon kann aktiv/**bootfähig** sein). Wenn du jedoch mehr Partitionen benötigst, kannst du **erweiterte Partitionen** verwenden. Das **letzte Byte** dieses ersten Sektors ist die Signatur des Boot Records **0x55AA**. Nur eine Partition kann als aktiv markiert werden.\
MBR erlaubt **maximal 2.2TB**.

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2.2TB](<../../../images/image (350).png>)

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2.2TB](<../../../images/image (304).png>)

In den **Bytes 440 bis 443** des MBR findest du die **Windows Disk Signature** (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows Disk Signature ab. Das Ändern dieser Signatur kann verhindern, dass Windows startet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitionen - MBR (Master Boot Record): In den Bytes 440 bis 443 des MBR findest du die Windows Disk Signature (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte...](<../../../images/image (310).png>)

**Format**

| Offset      | Länge     | Element             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot-Code           |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition     |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition    |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition    |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition    |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA |

**Format des Partitionseintrags**

| Offset    | Länge   | Element                                                |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktives Flag (0x80 = bootfähig)                        |
| 1 (0x01)  | 1 (0x01) | Start-Head                                             |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0-5); obere Bits des Zylinders (6-7) |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                   |
| 4 (0x04)  | 1 (0x01) | Partitionstyp-Code (0x83 = Linux)                      |
| 5 (0x05)  | 1 (0x01) | End-Head                                               |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0-5); obere Bits des Zylinders (6-7)   |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                     |
| 8 (0x08)  | 4 (0x04) | Der Partition vorausgehende Sektoren (Little-Endian)   |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                              |

Um einen MBR unter Linux zu mounten, musst du zuerst den Start-Offset ermitteln (du kannst `fdisk` und den Befehl `p` verwenden).

![Partitionen - MBR (Master Boot Record): Um einen MBR unter Linux zu mounten, musst du zuerst den Start-Offset ermitteln (du kannst fdisk und den Befehl p verwenden)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Und anschließend den folgenden Code verwenden.
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ist ein verbreitetes Schema zur **Angabe des Speicherorts von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, im Allgemeinen auf sekundären Speichersystemen wie Festplattenlaufwerken. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index lokalisiert**, wobei der erste Block LBA 0, der zweite LBA 1 usw. ist.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekannt als GPT, wird aufgrund ihrer erweiterten Funktionen gegenüber MBR (Master Boot Record) bevorzugt. GPT zeichnet sich durch ihre **global eindeutige Kennung** für Partitionen aus und bietet mehrere Vorteile:

- **Position und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64 Bit**, während MBR 32 Bit verwendet.
- **Partitionslimits**: GPT unterstützt unter Windows bis zu **128 Partitionen** und kann bis zu **9,4 ZB** an Daten verwalten.
- **Partitionsnamen**: Ermöglicht die Benennung von Partitionen mit bis zu 36 Unicode-Zeichen.

**Datenresilienz und Wiederherstellung**:

- **Redundanz**: Im Gegensatz zu MBR beschränkt GPT die Partitions- und Bootdaten nicht auf einen einzigen Ort. Sie repliziert diese Daten über den Datenträger hinweg und verbessert dadurch Datenintegrität und Ausfallsicherheit.
- **Cyclic Redundancy Check (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. Das System überwacht aktiv auf Datenkorruption und versucht bei deren Erkennung, die beschädigten Daten von einem anderen Speicherort auf dem Datenträger wiederherzustellen.

**Protective MBR (LBA0)**:

- GPT gewährleistet Abwärtskompatibilität durch einen Protective MBR. Diese Funktion befindet sich im alten MBR-Bereich, verhindert jedoch, dass ältere MBR-basierte Dienstprogramme GPT-Datenträger versehentlich überschreiben, und schützt so die Datenintegrität von GPT-formatierten Datenträgern.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

In Betriebssystemen, die das **GPT-basierte Booten über BIOS**-Dienste anstelle von EFI unterstützen, kann der erste Sektor weiterhin zum Speichern des Codes der ersten Stufe des **Bootloaders** verwendet werden, muss jedoch so **modifiziert** werden, dass er **GPT**-**Partitionen** erkennt. Der Bootloader im MBR darf keine Sektorgröße von 512 Byte voraussetzen.

**Header der Partitionstabelle (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Der Header der Partitionstabelle definiert die nutzbaren Blöcke auf dem Datenträger. Außerdem definiert er die Anzahl und Größe der Partitionseinträge, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge    | Inhalt                                                                                                                                                                      |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 Byte   | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)auf Little-Endian-Systemen) |
| 8 (0x08)  | 4 Byte   | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 Byte   | Headergröße in Little-Endian (in Byte, üblicherweise 5Ch 00h 00h 00h oder 92 Byte)                                                                                           |
| 16 (0x10) | 4 Byte   | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis zur Headergröße) in Little-Endian, wobei dieses Feld während der Berechnung auf null gesetzt wird    |
| 20 (0x14) | 4 Byte   | Reserviert; muss null sein                                                                                                                                                    |
| 24 (0x18) | 8 Byte   | Aktuelle LBA (Position dieser Header-Kopie)                                                                                                                                  |
| 32 (0x20) | 8 Byte   | Backup-LBA (Position der anderen Header-Kopie)                                                                                                                               |
| 40 (0x28) | 8 Byte   | Erste nutzbare LBA für Partitionen (letzte LBA der primären Partitionstabelle + 1)                                                                                           |
| 48 (0x30) | 8 Byte   | Letzte nutzbare LBA (erste LBA der sekundären Partitionstabelle − 1)                                                                                                         |
| 56 (0x38) | 16 Byte  | GUID des Datenträgers in gemischter Endianness                                                                                                                               |
| 72 (0x48) | 8 Byte   | Start-LBA eines Arrays von Partitionseinträgen (in der primären Kopie immer 2)                                                                                               |
| 80 (0x50) | 4 Byte   | Anzahl der Partitionseinträge im Array                                                                                                                                       |
| 84 (0x54) | 4 Byte   | Größe eines einzelnen Partitionseintrags (üblicherweise 80h oder 128)                                                                                                       |
| 88 (0x58) | 4 Byte   | CRC32 des Arrays der Partitionseinträge in Little-Endian                                                                                                                    |
| 92 (0x5C) | \*       | Reserviert; der Rest des Blocks muss aus Nullen bestehen (420 Byte bei einer Sektorgröße von 512 Byte; bei größeren Sektorgrößen kann es mehr sein)                         |

**Partitionseinträge (LBA 2–33)**

| Format eines GUID-Partitionseintrags |          |                                                                                                               |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                               | Länge    | Inhalt                                                                                                        |
| 0 (0x00)                             | 16 Byte  | [Partitionstyp-GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (gemischte Endianness) |
| 16 (0x10)                            | 16 Byte  | Eindeutige Partitions-GUID (gemischte Endianness)                                                             |
| 32 (0x20)                            | 8 Byte   | Erste LBA ([Little-Endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                            | 8 Byte   | Letzte LBA (einschließlich, üblicherweise ungerade)                                                          |
| 48 (0x30)                            | 8 Byte   | Attributflags (z. B. kennzeichnet Bit 60 den Schreibschutz)                                                  |
| 56 (0x38)                            | 72 Byte  | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                            |

**Partition Types**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 Byte | Partitionsname (36 UTF-16LE-Codeeinheiten)](<../../../images/image (83).png>)

Weitere Partition Types unter [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

### Untersuchung

Nach dem Mounten des Forensik-Images mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) kann der erste Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)** untersucht werden.** Im folgenden Bild wurde ein **MBR** in **Sektor 0** erkannt und interpretiert:

![GPT (GUID Partition Table) - Untersuchung: Nach dem Mounten des Forensik-Images mit ArsenalImageMounter kann der erste Sektor mit dem Windows-Tool Active Disk Editor untersucht werden. Im...](<../../../images/image (354).png>)

Wenn es sich stattdessen um eine **GPT-Tabelle und nicht um einen MBR** handelt, sollte die Signatur _EFI PART_ in **Sektor 1** erscheinen (der im vorherigen Bild leer ist).

## Datei-Systeme

### Liste der Windows-Datei-Systeme

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)**-Dateisystem basiert auf seiner Kernkomponente, der Dateizuordnungstabelle, die am Anfang des Volumes positioniert ist. Dieses System schützt die Daten, indem es **zwei Kopien** der Tabelle verwaltet und so die Datenintegrität sicherstellt, selbst wenn eine Kopie beschädigt wird. Die Tabelle sowie der Stammordner müssen sich an einem **festen Speicherort** befinden, was für den Startvorgang des Systems entscheidend ist.

Die grundlegende Speichereinheit des Dateisystems ist ein **Cluster, üblicherweise 512 B**, der aus mehreren Sektoren besteht. FAT wurde in mehreren Versionen weiterentwickelt:

- **FAT12** unterstützt 12-Bit-Clusteradressen und verarbeitet bis zu 4078 Cluster (4084 mit UNIX).
- **FAT16** erweitert dies auf 16-Bit-Adressen und unterstützt dadurch bis zu 65.517 Cluster.
- **FAT32** verwendet 32-Bit-Adressen und ermöglicht beeindruckende 268.435.456 Cluster pro Volume.

Eine wesentliche Einschränkung aller FAT-Versionen ist die **maximale Dateigröße von 4 GB**, die durch das 32-Bit-Feld zur Speicherung der Dateigröße vorgegeben wird.

Zu den wichtigen Komponenten des Stammverzeichnisses, insbesondere bei FAT12 und FAT16, gehören:

- **Datei-/Ordnername** (bis zu 8 Zeichen)
- **Attribute**
- **Erstellungs-, Änderungs- und letzte Zugriffszeiten**
- **Adresse der FAT-Tabelle** (gibt den Startcluster der Datei an)
- **Dateigröße**

### EXT

**Ext2** ist das häufigste Dateisystem für **nicht journalingfähige** Partitionen (**Partitionen, die sich nicht häufig ändern**), beispielsweise die Bootpartition. **Ext3/4** sind **journalingfähig** und werden üblicherweise für die **übrigen Partitionen** verwendet.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei und können für einen Analysten interessant sein, da sie abhängig vom Dateityp beispielsweise folgende Informationen enthalten können:

- Titel
- Verwendete MS Office-Version
- Autor
- Erstellungsdatum und Datum der letzten Änderung
- Kameramodell
- GPS-Koordinaten
- Bildinformationen

Mit Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) können die Metadaten einer Datei ausgelesen werden.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits zuvor beschrieben, gibt es mehrere Stellen, an denen die Datei nach ihrer „Löschung“ weiterhin gespeichert ist. Der Grund dafür ist, dass das Löschen einer Datei aus einem Dateisystem normalerweise lediglich markiert, dass sie gelöscht wurde, während die Daten selbst nicht verändert werden. Daher ist es möglich, die Verzeichnisse der Dateien (z. B. die MFT) zu untersuchen und die gelöschten Dateien zu finden.<sup>[[2]](#references)</sup>

Außerdem speichert das Betriebssystem normalerweise viele Informationen über Änderungen am Dateisystem und Backups. Daher kann man versuchen, diese zur Wiederherstellung der Datei oder möglichst vieler Informationen zu verwenden.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File Carving** ist eine Technik, die versucht, **Dateien in der Gesamtheit der Daten zu finden**. Es gibt drei Hauptmethoden, nach denen Tools dieser Art arbeiten: **anhand von Headern und Footern der Dateitypen**, anhand der **Strukturen** der Dateitypen und anhand des **Inhalts** selbst.

Beachte, dass diese Technik **nicht zum Wiederherstellen fragmentierter Dateien geeignet ist**. Wenn eine Datei **nicht in zusammenhängenden Sektoren gespeichert** ist, kann diese Technik sie entweder gar nicht oder zumindest nicht vollständig finden.

Es gibt mehrere Tools, die für File Carving verwendet werden können, wobei die zu suchenden Dateitypen angegeben werden.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving ähnelt File Carving, sucht jedoch **nicht nach vollständigen Dateien, sondern nach interessanten Informationsfragmenten**.\
Anstatt beispielsweise nach einer vollständigen Datei mit protokollierten URLs zu suchen, sucht diese Technik nach URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Sichere Löschung

Natürlich gibt es Möglichkeiten, Dateien und Teile der sie betreffenden Protokolle **„sicher“ zu löschen**. Beispielsweise kann man den **Inhalt** einer Datei mehrmals mit nutzlosen Daten **überschreiben**, anschließend die **Protokolle** über die Datei aus **$MFT** und **$LOGFILE** **entfernen** und die **Volume Shadow Copies** **löschen**.<sup>[[3]](#references)</sup>\
Es kann auffallen, dass selbst nach dieser Aktion möglicherweise **andere Stellen vorhanden sind, an denen die Existenz der Datei weiterhin protokolliert ist**. Das trifft tatsächlich zu, und es gehört zu den Aufgaben von Forensik-Fachleuten, diese Stellen zu finden.

## Referenzen

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
