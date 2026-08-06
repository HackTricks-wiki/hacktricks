# Partitionen/Dateisysteme/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitionen

Eine Festplatte oder ein **SSD-Laufwerk kann verschiedene Partitionen enthalten**, um Daten physisch voneinander zu trennen.\
Die **kleinste** Einheit eines Datenträgers ist der **Sektor** (normalerweise bestehend aus 512 B). Daher muss jede Partitionsgröße ein Vielfaches dieser Größe sein.

### MBR (Master Boot Record)

Er wird im **ersten Sektor des Datenträgers nach den 446 B des Boot-Codes** gespeichert. Dieser Sektor ist entscheidend, damit der PC weiß, ob und wo eine Partition gemountet werden soll.\
Er erlaubt bis zu **4 Partitionen** (höchstens **1** davon kann aktiv/**bootfähig** sein). Wenn du jedoch mehr Partitionen benötigst, kannst du **erweiterte Partitionen** verwenden. Das **letzte Byte** dieses ersten Sektors ist die Signatur des Boot Records **0x55AA**. Nur eine Partition kann als aktiv markiert werden.\
MBR erlaubt **maximal 2,2 TB**.

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2,2 TB](<../../../images/image (350).png>)

![Partitionen - MBR (Master Boot Record): MBR erlaubt maximal 2,2 TB](<../../../images/image (304).png>)

In den **Bytes 440 bis 443** des MBR findest du die **Windows Disk Signature** (falls Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows Disk Signature ab. Das Ändern dieser Signatur kann verhindern, dass Windows startet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

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

| Offset    | Länge   | Element                                                |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktives Flag (0x80 = bootfähig)                         |
| 1 (0x01)  | 1 (0x01) | Start-Head                                             |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0–5); obere Zylinderbits (6–7)       |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                   |
| 4 (0x04)  | 1 (0x01) | Partitions-Typcode (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | End-Head                                               |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0–5); obere Zylinderbits (6–7)         |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                     |
| 8 (0x08)  | 4 (0x04) | Der Partition vorausgehende Sektoren (Little-Endian)   |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                              |

Um einen MBR unter Linux zu mounten, musst du zunächst den Start-Offset ermitteln (du kannst `fdisk` und den Befehl `p` verwenden).

![Partitionen - MBR (Master Boot Record): Um einen MBR unter Linux zu mounten, musst du zunächst den Start-Offset ermitteln (du kannst fdisk und den Befehl p verwenden)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Verwende anschließend den folgenden Code
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) ist ein übliches Schema zur **Angabe des Speicherorts von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, im Allgemeinen auf sekundären Speichersystemen wie Festplattenlaufwerken. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index lokalisiert**, wobei der erste Block LBA 0, der zweite LBA 1 usw. ist.

### GPT (GUID Partition Table)

Die GUID Partition Table, bekannt als GPT, wird aufgrund ihrer erweiterten Möglichkeiten gegenüber MBR (Master Boot Record) bevorzugt. GPT zeichnet sich durch ihren **global eindeutigen Bezeichner** für Partitionen aus und bietet mehrere Vorteile:

- **Position und Größe**: Sowohl GPT als auch MBR beginnen bei **Sektor 0**. GPT arbeitet jedoch mit **64 Bit**, im Gegensatz zu den 32 Bit von MBR.
- **Partitionslimits**: GPT unterstützt auf Windows-Systemen bis zu **128 Partitionen** und kann bis zu **9,4 ZB** an Daten aufnehmen.
- **Partitionsnamen**: Ermöglicht die Benennung von Partitionen mit bis zu 36 Unicode-Zeichen.

**Datenresilienz und Wiederherstellung**:

- **Redundanz**: Im Gegensatz zu MBR beschränkt GPT die Partitions- und Bootdaten nicht auf einen einzigen Ort. Diese Daten werden über die Festplatte verteilt repliziert, wodurch Datenintegrität und Resilienz verbessert werden.
- **Cyclic Redundancy Check (CRC)**: GPT verwendet CRC, um die Datenintegrität sicherzustellen. Es überwacht aktiv auf Datenbeschädigungen und versucht bei deren Erkennung, die beschädigten Daten von einem anderen Speicherort auf der Festplatte wiederherzustellen.

**Protective MBR (LBA0)**:

- GPT gewährleistet Abwärtskompatibilität durch einen Protective MBR. Diese Funktion befindet sich im Bereich des Legacy-MBR, verhindert jedoch, dass ältere MBR-basierte Dienstprogramme GPT-Festplatten versehentlich überschreiben, und schützt dadurch die Datenintegrität von GPT-formatierten Festplatten.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

In Betriebssystemen, die den **GPT-basierten Bootvorgang über BIOS**-Dienste anstelle von EFI unterstützen, kann der erste Sektor weiterhin zum Speichern des Codes der ersten Stufe des **Bootloaders** verwendet werden, muss jedoch so **modifiziert** werden, dass er **GPT**-**Partitionen** erkennt. Der Bootloader im MBR darf keine Sektorgröße von 512 Bytes voraussetzen.

**Header der Partitionstabelle (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Der Header der Partitionstabelle definiert die nutzbaren Blöcke auf der Festplatte. Außerdem definiert er die Anzahl und Größe der Partitionseinträge, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge   | Inhalt                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 Bytes  | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)auf Little-Endian-Systemen) |
| 8 (0x08)  | 4 Bytes  | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 Bytes  | Headergröße in Little-Endian (in Bytes, normalerweise 5Ch 00h 00h 00h oder 92 Bytes)                                                                                                 |
| 16 (0x10) | 4 Bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis zur Headergröße) in Little-Endian, wobei dieses Feld während der Berechnung auf Null gesetzt wird                             |
| 20 (0x14) | 4 Bytes  | Reserviert; muss Null sein                                                                                                                                                       |
| 24 (0x18) | 8 Bytes  | Aktuelle LBA (Position dieser Header-Kopie)                                                                                                                                   |
| 32 (0x20) | 8 Bytes  | Backup-LBA (Position der anderen Header-Kopie)                                                                                                                               |
| 40 (0x28) | 8 Bytes  | Erste nutzbare LBA für Partitionen (letzte LBA der primären Partitionstabelle + 1)                                                                                                       |
| 48 (0x30) | 8 Bytes  | Letzte nutzbare LBA (erste LBA der sekundären Partitionstabelle − 1)                                                                                                                    |
| 56 (0x38) | 16 Bytes | Festplatten-GUID in gemischter Endianness                                                                                                                                                    |
| 72 (0x48) | 8 Bytes  | Start-LBA eines Arrays von Partitionseinträgen (in der primären Kopie immer 2)                                                                                                     |
| 80 (0x50) | 4 Bytes  | Anzahl der Partitionseinträge im Array                                                                                                                                         |
| 84 (0x54) | 4 Bytes  | Größe eines einzelnen Partitionseintrags (normalerweise 80h oder 128)                                                                                                                        |
| 88 (0x58) | 4 Bytes  | CRC32 des Arrays der Partitionseinträge in Little-Endian                                                                                                                            |
| 92 (0x5C) | \*       | Reserviert; der Rest des Blocks muss aus Nullen bestehen (420 Bytes bei einer Sektorgröße von 512 Bytes, bei größeren Sektorgrößen jedoch mehr)                                      |

**Partitionseinträge (LBA 2–33)**

| GUID-Partitions­eintragsformat |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Länge   | Inhalt                                                                                                      |
| 0 (0x00)                    | 16 Bytes | [Partitionstyp-GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (gemischte Endianness) |
| 16 (0x10)                   | 16 Bytes | Eindeutige Partitions-GUID (gemischte Endianness)                                                                          |
| 32 (0x20)                   | 8 Bytes  | Erste LBA ([Little-Endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 Bytes  | Letzte LBA (einschließlich, normalerweise ungerade)                                                                             |
| 48 (0x30)                   | 8 Bytes  | Attribut-Flags (z. B. bezeichnet Bit 60 den Nur-Lese-Modus)                                                               |
| 56 (0x38)                   | 72 Bytes | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                               |

**Partitionstypen**

![MBR (Master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 Bytes | Partitionsname (36 UTF-16LE-Codeeinheiten)](<../../../images/image (83).png>)

Weitere Partitionstypen unter [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Untersuchung

Nachdem das Forensics-Image mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) eingebunden wurde, kann der erste Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** untersucht werden. Im folgenden Bild wurde ein **MBR** auf **Sektor 0** erkannt und interpretiert:

![GPT (GUID Partition Table) - Untersuchung: Nachdem das Forensics-Image mit ArsenalImageMounter eingebunden wurde, kann der erste Sektor mit dem Windows-Tool Active Disk Editor untersucht werden. Im...](<../../../images/image (354).png>)

Wenn es sich statt um einen MBR um eine **GPT-Tabelle** handelt, sollte die Signatur _EFI PART_ in **Sektor 1** erscheinen (der im vorherigen Bild leer ist).

## Datei-Systeme

### Liste der Windows-Datei-Systeme

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Das **FAT (File Allocation Table)**-Dateisystem basiert auf seiner zentralen Komponente, der File Allocation Table, die am Anfang des Volumes positioniert ist. Dieses System schützt Daten, indem es **zwei Kopien** der Tabelle verwaltet und dadurch die Datenintegrität auch dann sicherstellt, wenn eine Kopie beschädigt ist. Die Tabelle sowie der Root-Ordner müssen sich an einem **festen Speicherort** befinden, was für den Startvorgang des Systems entscheidend ist.

Die grundlegende Speichereinheit des Dateisystems ist ein **Cluster, normalerweise 512 B**, der aus mehreren Sektoren besteht. FAT wurde in mehreren Versionen weiterentwickelt:

- **FAT12**, unterstützt 12-Bit-Clusteradressen und verarbeitet bis zu 4078 Cluster (4084 mit UNIX).
- **FAT16**, erweitert die Adressen auf 16 Bit und ermöglicht dadurch bis zu 65.517 Cluster.
- **FAT32**, verwendet 32-Bit-Adressen und ermöglicht beeindruckende 268.435.456 Cluster pro Volume.

Eine wesentliche Einschränkung aller FAT-Versionen ist die **maximale Dateigröße von 4 GB**, die durch das 32-Bit-Feld zur Speicherung der Dateigröße vorgegeben wird.

Zu den wichtigen Komponenten des Root-Verzeichnisses, insbesondere bei FAT12 und FAT16, gehören:

- **Datei-/Ordnername** (bis zu 8 Zeichen)
- **Attribute**
- **Erstellungs-, Änderungs- und letzte Zugriffsdaten**
- **FAT-Tabellenadresse** (gibt den Startcluster der Datei an)
- **Dateigröße**

### EXT

**Ext2** ist das häufigste Dateisystem für **Partitionen ohne Journaling** (**Partitionen, die sich nicht häufig ändern**), beispielsweise die Boot-Partition. **Ext3/4** verwenden **Journaling** und werden normalerweise für die **übrigen Partitionen** eingesetzt.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Inhalt der Datei und können für einen Analysten interessant sein, da sie abhängig vom Dateityp beispielsweise folgende Informationen enthalten können:

- Titel
- Verwendete MS-Office-Version
- Autor
- Erstellungs- und letzte Änderungsdaten
- Kameramodell
- GPS-Koordinaten
- Bildinformationen

Mit Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) können die Metadaten einer Datei ausgelesen werden.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits zuvor gesehen, gibt es mehrere Orte, an denen die Datei nach ihrer **„Löschung“** weiterhin gespeichert ist. Der Grund dafür ist, dass das Löschen einer Datei aus einem Dateisystem normalerweise lediglich deren Löschstatus markiert, ohne die Daten zu verändern. Daher ist es möglich, die Register der Dateien (z. B. die MFT) zu untersuchen und gelöschte Dateien zu finden.<sup>[[2]](#references)</sup>

Außerdem speichert das Betriebssystem normalerweise viele Informationen über Änderungen am Dateisystem und Backups. Daher kann versucht werden, diese Informationen zur Wiederherstellung der Datei oder möglichst vieler ihrer Daten zu verwenden.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File Carving** ist eine Technik, mit der versucht wird, **Dateien in der Gesamtheit der Daten zu finden**. Es gibt drei Hauptmethoden, wie solche Tools arbeiten: **anhand von Headern und Footern von Dateitypen**, anhand der **Strukturen** von Dateitypen und anhand des **Inhalts** selbst.

Beachte, dass diese Technik **nicht zur Wiederherstellung fragmentierter Dateien funktioniert**. Wenn eine Datei **nicht in zusammenhängenden Sektoren gespeichert** ist, kann diese Technik sie entweder gar nicht oder zumindest nicht vollständig finden.

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

Natürlich gibt es Möglichkeiten, Dateien und Teile der sie betreffenden Logs **„sicher“ zu löschen**. Beispielsweise kann der **Inhalt** einer Datei mehrmals mit nutzlosen Daten **überschrieben** werden. Anschließend können die **Logs** über die Datei aus **$MFT** und **$LOGFILE** entfernt und die **Volume Shadow Copies** gelöscht werden.<sup>[[3]](#references)</sup>\
Möglicherweise stellst du fest, dass selbst nach dieser Aktion **an anderen Stellen weiterhin die Existenz der Datei protokolliert** sein kann. Das trifft zu, und es gehört zu den Aufgaben eines Forensics-Experten, diese Spuren zu finden.

## Referenzen

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
