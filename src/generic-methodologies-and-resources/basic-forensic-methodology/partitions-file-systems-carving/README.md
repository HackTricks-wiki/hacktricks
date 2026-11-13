# Partitionen/Dateisysteme/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partitionen

Ein Datenträger kann mehrere **Partitionen** enthalten: logische Blockbereiche, die keine physisch getrennten Speicherbereiche sind. Anfang und Länge einer Partition werden in **logischen Sektoren** angegeben. Gehen Sie nicht davon aus, dass jedes Image 512-Byte-Sektoren verwendet; es gibt auch logische Sektoren mit 4096 Byte.<sup>[[4]](#references)</sup>

### MBR (Master Boot Record)

Der MBR belegt den ersten logischen Sektor (LBA 0); seine vier 16 Byte großen Partitionseinträge beginnen bei Byte 446. Der davorliegende Bereich enthält Boot-Code und möglicherweise eine Datenträgersignatur.<sup>[[4]](#references)</sup>\
Er erlaubt bis zu **4 Partitionen** (höchstens **1** davon kann aktiv/**bootfähig** sein). Wenn Sie mehr Partitionen benötigen, können Sie jedoch **erweiterte Partitionen** verwenden. Die letzten **zwei Bytes** des 512 Byte großen MBR sind die Boot-Signatur **0x55 0xAA**. Nur eine Partition kann als aktiv markiert werden.\
Bei logischen Sektoren mit 512 Byte begrenzen die 32-Bit-Sektorfelder des MBR die adressierbare Größe auf etwa **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Partitionen - MBR (Master Boot Record): Der MBR unterstützt maximal 2,2 TB](<../../../images/image (350).png>)

![Partitionen - MBR (Master Boot Record): Der MBR unterstützt maximal 2,2 TB](<../../../images/image (304).png>)

In den **Bytes 440 bis 443** des MBR befindet sich die **Windows-Datenträgersignatur** (wenn Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte hängt von der Windows-Datenträgersignatur ab. Eine Änderung dieser Signatur kann verhindern, dass Windows startet (Tool: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partitionen - MBR (Master Boot Record): In den Bytes 440 bis 443 des MBR befindet sich die Windows-Datenträgersignatur (wenn Windows verwendet wird). Der logische Laufwerksbuchstabe der Festplatte...](<../../../images/image (310).png>)

**Format**

| Offset      | Länge      | Element                 |
| ----------- | ---------- | ----------------------- |
| 0 (0x00)    | 446(0x1BE) | Boot-Code               |
| 446 (0x1BE) | 16 (0x10)  | Erste Partition         |
| 462 (0x1CE) | 16 (0x10)  | Zweite Partition        |
| 478 (0x1DE) | 16 (0x10)  | Dritte Partition        |
| 494 (0x1EE) | 16 (0x10)  | Vierte Partition        |
| 510 (0x1FE) | 2 (0x2)    | Signatur 0x55 0xAA       |

**Format des Partitionseintrags**

| Offset    | Länge    | Element                                                |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Aktiv-Flag (0x80 = bootfähig)                          |
| 1 (0x01)  | 1 (0x01) | Start-Head                                             |
| 2 (0x02)  | 1 (0x01) | Startsektor (Bits 0–5); obere Zylinderbits (6–7)       |
| 3 (0x03)  | 1 (0x01) | Niedrigste 8 Bits des Startzylinders                   |
| 4 (0x04)  | 1 (0x01) | Partitionstypcode (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | End-Head                                               |
| 6 (0x06)  | 1 (0x01) | Endsektor (Bits 0–5); obere Zylinderbits (6–7)         |
| 7 (0x07)  | 1 (0x01) | Niedrigste 8 Bits des Endzylinders                     |
| 8 (0x08)  | 4 (0x04) | Der Partition vorangehende Sektoren (Little Endian)    |
| 12 (0x0C) | 4 (0x04) | Sektoren in der Partition                              |

Um eine Partition in einem MBR-Image des gesamten Datenträgers zu untersuchen, ermitteln Sie zunächst ihren Start-LBA und die logische Sektorgröße. `mount` erwartet einen **Byte-Offset**, keinen LBA; das folgende Beispiel gilt nur für ein Image mit 512-Byte-Sektoren, dessen Partition bei LBA 63 beginnt. Verwenden Sie bei nicht vertrauenswürdigen Images oder Journaling-Dateisystemen stattdessen den isolierten, schreibgeschützten Ablauf unter [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partitionen - MBR (Master Boot Record): Um einen MBR unter Linux einzubinden, müssen Sie zuerst den Start-Offset ermitteln (verwenden Sie dazu fdisk und den Befehl p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (Logical Block Addressing)**

**Logical Block Addressing** (**LBA**) ist ein gängiges Verfahren zur **Angabe der Position von Datenblöcken**, die auf Computerspeichergeräten gespeichert sind, im Allgemeinen auf Sekundärspeichern wie Festplatten. LBA ist ein besonders einfaches lineares Adressierungsschema; **Blöcke werden durch einen ganzzahligen Index adressiert**: Der erste Block hat die LBA 0, der zweite die LBA 1 und so weiter.

### GPT (GUID Partition Table)

Die GUID Partition Table (GPT) speichert für jede Partition eine eindeutige GUID und verwendet primäre und Sicherungsmetadaten. Ihr Aufbau unterscheidet sich wie folgt von MBR:<sup>[[4]](#references)</sup>

- **Position und Größe**: LBA 0 enthält einen **Schutz-MBR**. Der primäre GPT-Header befindet sich bei LBA 1; darauf folgt das Array der Partitionseinträge, und am Ende der Festplatte befinden sich ein Sicherungsarray und ein Sicherungsheader. GPT verwendet 64-Bit-LBA-Felder, während MBR-Partitionseinträge 32-Bit-LBA-Felder verwenden.
- **Partitionslimits**: Ein gängiges 16-KiB-Eintragsarray enthält **128 Einträge zu je 128 Byte**, aber die Anzahl der Einträge wird im Header gespeichert und ist nicht durch GPT fest vorgegeben. Die adressierbare Größe hängt außerdem von der logischen Sektorgröße ab (etwa **9,4 ZB** bei 512-Byte-Sektoren).<sup>[[4]](#references)</sup>
- **Partitionsnamen**: Ermöglicht die Benennung von Partitionen mit bis zu 36 Unicode-Zeichen.

**Datenresilienz und Wiederherstellung**:

- **Redundanz**: Anders als MBR beschränkt GPT Partitionierungs- und Bootdaten nicht auf einen einzigen Ort. Diese Daten werden über die Festplatte hinweg repliziert, was die Datenintegrität und Resilienz verbessert.
- **Cyclic Redundancy Check (CRC)**: Sowohl der Header als auch das Array der Partitionseinträge verfügen über eine CRC32. Eine CRC erkennt Inkonsistenzen; sie überwacht die Festplatte nicht kontinuierlich und repariert sie auch nicht selbst. Wenn die primäre Kopie ungültig ist, überprüfen Sie die Sicherungskopie bei der letzten LBA, bevor Sie eine Wiederherstellung an einer Arbeitskopie durchführen.<sup>[[4]](#references)</sup>

**Schutz-MBR (LBA0)**:

- GPT gewährleistet Abwärtskompatibilität mithilfe eines Schutz-MBR. Diese Funktion befindet sich im MBR-Bereich für ältere Systeme, soll aber verhindern, dass ältere MBR-basierte Dienstprogramme GPT-Festplatten versehentlich überschreiben, und so die Datenintegrität auf GPT-formatierten Festplatten schützen.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid-MBR (LBA 0 + GPT)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Bei Betriebssystemen, die **GPT-basiertes Booten über BIOS**-Dienste statt EFI unterstützen, kann der erste Sektor weiterhin zum Speichern der ersten Stufe des **Bootloaders** verwendet werden, muss jedoch so **modifiziert** werden, dass er **GPT**-**Partitionen** erkennt. Der Bootloader im MBR darf nicht von einer Sektorgröße von 512 Byte ausgehen.

**Partitionstabellen-Header (LBA 1)**

[Aus Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Der Partitionstabellen-Header definiert die nutzbaren Blöcke auf der Festplatte. Außerdem legt er die Anzahl und Größe der Partitionseinträge fest, aus denen die Partitionstabelle besteht (Offsets 80 und 84 in der Tabelle).

| Offset    | Länge    | Inhalt                                                                                                                                                                         |
| --------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 0 (0x00)  | 8 Byte   | Signatur ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h oder 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)auf Little-Endian-Systemen) |
| 8 (0x08)  | 4 Byte   | Revision 1.0 (00h 00h 01h 00h) für UEFI 2.8                                                                                                                                    |
| 12 (0x0C) | 4 Byte   | Headergröße in Little Endian (in Byte, normalerweise 5Ch 00h 00h 00h oder 92 Byte)                                                                                            |
| 16 (0x10) | 4 Byte   | [CRC32](https://en.wikipedia.org/wiki/CRC32) des Headers (Offset +0 bis zur Headergröße) in Little Endian; dieses Feld wird während der Berechnung auf null gesetzt           |
| 20 (0x14) | 4 Byte   | Reserviert; muss null sein                                                                                                                                                     |
| 24 (0x18) | 8 Byte   | Aktuelle LBA (Position dieser Headerkopie)                                                                                                                                     |
| 32 (0x20) | 8 Byte   | Sicherungs-LBA (Position der anderen Headerkopie)                                                                                                                              |
| 40 (0x28) | 8 Byte   | Erste nutzbare LBA für Partitionen (letzte LBA der primären Partitionstabelle + 1)                                                                                             |
| 48 (0x30) | 8 Byte   | Letzte nutzbare LBA (erste LBA der sekundären Partitionstabelle − 1)                                                                                                          |
| 56 (0x38) | 16 Byte  | Festplatten-GUID in gemischter Endian-Reihenfolge                                                                                                                              |
| 72 (0x48) | 8 Byte   | Start-LBA eines Arrays von Partitionseinträgen (in der primären Kopie immer 2)                                                                                                 |
| 80 (0x50) | 4 Byte   | Anzahl der Partitionseinträge im Array                                                                                                                                         |
| 84 (0x54) | 4 Byte   | Größe eines einzelnen Partitionseintrags (normalerweise 80h oder 128)                                                                                                          |
| 88 (0x58) | 4 Byte   | CRC32 des Arrays der Partitionseinträge in Little Endian                                                                                                                       |
| 92 (0x5C) | \*       | Reserviert; muss im Rest des Blocks null sein (420 Byte bei einer Sektorgröße von 512 Byte; bei größeren Sektorgrößen kann es mehr sein)                                       |

**Partitionseinträge (LBA 2–33)**

| Format eines GUID-Partitionseintrags |          |                                                                                                               |
| ------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                               | Länge    | Inhalt                                                                                                        |
| 0 (0x00)                             | 16 Byte  | [Partitions-Typ-GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (gemischte Endian-Reihenfolge) |
| 16 (0x10)                            | 16 Byte  | Eindeutige Partitions-GUID (gemischte Endian-Reihenfolge)                                                     |
| 32 (0x20)                            | 8 Byte   | Erste LBA ([Little Endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                            | 8 Byte   | Letzte LBA (einschließlich, normalerweise ungerade)                                                           |
| 48 (0x30)                            | 8 Byte   | Attribut-Flags (z. B. kennzeichnet Bit 60 den Nur-Lese-Modus)                                                |
| 56 (0x38)                            | 72 Byte  | Partitionsname (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE-Codeeinheiten)                            |

**Partitionstypen**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Weitere Partitionstypen unter [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Überprüfen

Nachdem Sie das Forensik-Image mit [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) eingebunden haben, können Sie den ersten Sektor mit dem Windows-Tool [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** überprüfen. Im folgenden Bild wurde im **Sektor 0** ein **MBR** erkannt und interpretiert:

![GPT (GUID Partition Table) - Überprüfen: Nachdem Sie das Forensik-Image mit ArsenalImageMounter eingebunden haben, können Sie den ersten Sektor mit dem Windows-Tool Active Disk Editor überprüfen. Im folgenden Bild...](<../../../images/image (354).png>)

Suchen Sie bei GPT im primären Header bei **LBA 1** nach der Signatur _EFI PART_; LBA 0 enthält weiterhin den Schutz-MBR.<sup>[[4]](#references)</sup>

### Daten außerhalb der aufgeführten Partitionen finden

Ein gelöschter Partitionseintrag oder eine absichtlich nicht genutzte Lücke kann dazu führen, dass sich ein Dateisystem außerhalb der aktuellen Partitionszuordnung befindet. Erstellen Sie auf einer **verifizierten Rohdaten-Arbeitskopie** eine Liste nicht zugeordneter Bereiche und prüfen Sie anschließend, ob eine mögliche Start-LBA zu einem Dateisystem gehört. `mmls` und `fsstat` verwenden **Sektor-Offsets**; geben Sie bei beiden die tatsächliche logische Sektorgröße an. Verwechseln Sie GPT-Metadatensektoren nicht mit einem verborgenen Volume.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Wenn `fsstat` am Anfang der Lücke kein Dateisystem identifizieren kann, verwende TestDisk **Analyse → Quick Search** und bei Bedarf anschließend **Deeper Search**. Drücke bei einem Kandidaten `P`, um Dateien anzuzeigen; wähle bei Beweismitteln nicht **Write**. Bei GPT-Abbildern prüft `sgdisk --verify disk.img` die CRCs und die Übereinstimmung zwischen Haupt- und Sicherungskopie. Ein Sicherungskopfsatz kann nach einer Neupartitionierung jedoch veraltet sein. Gleiche daher die Grenzen möglicher Partitionen vor der Wiederherstellung anhand von Dateisystemstrukturen ab.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Dateisysteme

### Liste der Windows-Dateisysteme

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

Das **FAT-Dateisystem (File Allocation Table)** basiert auf seiner zentralen Komponente, der Dateizuordnungstabelle, die sich am Anfang des Volumes befindet. Ein Volume enthält üblicherweise **zwei FAT-Kopien**, auch wenn die BPB eine Kopie zulässt. FAT12/16 speichern das Stammverzeichnis in einem festen Bereich; FAT32 speichert es im Datenbereich am durch `BPB_RootClus` angegebenen Cluster.<sup>[[7]](#references)</sup>

Die Zuordnungseinheit ist ein **Cluster**: `BPB_BytsPerSec × BPB_SecPerClus` und nicht zwangsläufig 512 Bytes. Der FAT-Typ wird anhand der Anzahl der Datencluster bestimmt, nicht anhand einer Versionszeichenfolge im Bootsektor. Die Grenzen der Clusteranzahl sind:<sup>[[7]](#references)</sup>

- **FAT12**: weniger als 4.085 Datencluster.
- **FAT16**: 4.085 bis 65.524 Datencluster.
- **FAT32**: mindestens 65.525 Datencluster; für die Clusternummer werden nur 28 Bits jedes 32-Bit-FAT-Eintrags verwendet.

Das 32-Bit-Dateigrößenfeld begrenzt reguläre Dateien auf **2³²−1 Bytes** (knapp unter 4 GiB).<sup>[[7]](#references)</sup>

Zu den wichtigsten Komponenten des Stammverzeichnisses, insbesondere bei FAT12 und FAT16, gehören:

- **Datei-/Ordnername** (bis zu 8 Zeichen)
- **Attribute**
- **Erstellungs-, Änderungs- und Zugriffsdatum**
- **FAT-Tabellenadresse** (gibt den Startcluster der Datei an)
- **Dateigröße**

### EXT

**Ext2** ist das verbreitetste Dateisystem für **nicht-journalisierende** Partitionen (**Partitionen, die sich kaum ändern**), etwa die Boot-Partition. **Ext3/4** sind **journalisierend** und werden üblicherweise für die **übrigen Partitionen** verwendet.

## **Metadaten**

Einige Dateien enthalten Metadaten. Diese Informationen beziehen sich auf den Dateiinhalt und können für Analysten interessant sein. Je nach Dateityp können sie beispielsweise Folgendes enthalten:

- Titel
- Verwendete MS-Office-Version
- Autor
- Erstellungs- und letzte Änderungsdaten
- Kameramodell
- GPS-Koordinaten
- Bildinformationen

Mit Tools wie [**exiftool**](https://exiftool.org) und [**Metadiver**](https://www.easymetadata.com/metadiver-2/) kannst du die Metadaten einer Datei auslesen.

## **Wiederherstellung gelöschter Dateien**

### Protokollierte gelöschte Dateien

Wie bereits erwähnt, gibt es verschiedene Stellen, an denen eine Datei nach dem „Löschen“ noch gespeichert ist. Das liegt daran, dass das Löschen einer Datei in einem Dateisystem sie üblicherweise nur als gelöscht markiert, die Daten aber nicht verändert. Daher ist es möglich, die Dateieinträge (wie die MFT) zu untersuchen und gelöschte Dateien zu finden.<sup>[[2]](#references)</sup>

Außerdem speichert das Betriebssystem üblicherweise viele Informationen zu Änderungen am Dateisystem und zu Sicherungen. Daher kann man versuchen, die Datei oder möglichst viele Informationen wiederherzustellen.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File Carving** ist eine Technik, mit der versucht wird, **Dateien in großen Datenmengen zu finden**. Solche Tools arbeiten hauptsächlich auf drei Arten: **anhand von Datei-Headern und -Footern**, anhand der **Struktur** bestimmter Dateitypen oder anhand des **Inhalts** selbst.

Beim einfachen Header-/Footer-Carving wird angenommen, dass Datenblöcke zusammenhängend sind. Ist eine Datei fragmentiert, kann daher nur ein Teil davon gefunden werden. Das ist keine absolute Grenze: PhotoRec bietet für einige fragmentierte JPEGs die CPU-intensive Option **Paranoid → bruteforce**, während die formatbewusste Fragment-Neuzusammensetzung auch andere unterstützte Typen wiederherstellen kann. Einen aktuellen Workflow zur Neuzusammensetzung von Fragmenten findest du unter [File Carving und Wiederherstellungstools](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving).<sup>[[8]](#references)</sup>

Es gibt mehrere Tools für File Carving, bei denen du die zu suchenden Dateitypen angeben kannst.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Datenstrom-Carving**

Datenstrom-Carving ähnelt File Carving, **sucht aber nicht nach vollständigen Dateien, sondern nach interessanten Informationsfragmenten**.\
Anstatt beispielsweise nach einer vollständigen Datei mit protokollierten URLs zu suchen, sucht diese Technik nach URLs.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Sicheres Löschen

Natürlich gibt es Möglichkeiten, Dateien und Teile der dazugehörigen Protokolle **„sicher“ zu löschen**. Beispielsweise kann man den **Inhalt** einer Datei mehrmals mit bedeutungslosen Daten **überschreiben**, anschließend die Protokolleinträge über die Datei aus **$MFT** und **$LOGFILE** **entfernen** und die **Volume Shadow Copies löschen**.<sup>[[3]](#references)</sup>\
Du wirst möglicherweise feststellen, dass selbst danach **an anderen Stellen weiterhin die Existenz der Datei protokolliert sein kann**. Das ist richtig, und solche Stellen zu finden, gehört zu den Aufgaben von Forensikern.



## References

- [1] [GUID-Partitionstabelle – Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [So untersuchst du NTFS-$I30-Verzeichniseinträge auf Hinweise zu gelöschten Dateien](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [UEFI-Spezifikation: GPT-Festplattenlayout](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Handbuch zu mmls von The Sleuth Kit](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Handbuch zu fsstat von The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Microsoft-FAT-Spezifikation](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Wiederherstellungsoptionen von PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Wiederherstellung gelöschter Partitionen mit TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Handbuch zu sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Handbuch zu mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
