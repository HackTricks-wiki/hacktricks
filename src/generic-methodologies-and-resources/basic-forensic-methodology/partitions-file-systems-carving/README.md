# Partycje/Systemy plików/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partycje

Dysk twardy lub **dysk SSD może zawierać różne partycje**, aby fizycznie oddzielać dane.\
**Minimalną** jednostką dysku jest **sektor** (zwykle składający się z 512 B). Dlatego rozmiar każdej partycji musi być wielokrotnością tego rozmiaru.

### MBR (główny rekord rozruchowy)

Jest przydzielany w **pierwszym sektorze dysku, po 446 B kodu rozruchowego**. Ten sektor jest niezbędny do wskazania komputerowi, czy i skąd należy zamontować partycję.\
Umożliwia utworzenie maksymalnie **4 partycji** (najwyżej **1** może być aktywna/**bootowalna**). Jeśli potrzebujesz większej liczby partycji, możesz użyć **partycji rozszerzonych**. **Ostatnie bajty** tego pierwszego sektora zawierają sygnaturę rekordu rozruchowego **0x55AA**. Tylko jedna partycja może być oznaczona jako aktywna.\
MBR obsługuje maksymalnie **2,2 TB**.

![Partycje - MBR (główny rekord rozruchowy): MBR obsługuje maksymalnie 2,2 TB](<../../../images/image (350).png>)

![Partycje - MBR (główny rekord rozruchowy): MBR obsługuje maksymalnie 2,2 TB](<../../../images/image (304).png>)

W **bajtach od 440 do 443** MBR można znaleźć **sygnaturę dysku Windows** (jeśli używany jest Windows). Logiczna litera dysku twardego zależy od sygnatury dysku Windows. Zmiana tej sygnatury może uniemożliwić uruchomienie systemu Windows (narzędzie: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partycje - MBR (główny rekord rozruchowy): W bajtach od 440 do 443 MBR można znaleźć sygnaturę dysku Windows (jeśli używany jest Windows). Logiczna litera dysku twardego...](<../../../images/image (310).png>)

**Format**

| Offset      | Length     | Item                |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Kod rozruchowy      |
| 446 (0x1BE) | 16 (0x10)  | Pierwsza partycja   |
| 462 (0x1CE) | 16 (0x10)  | Druga partycja      |
| 478 (0x1DE) | 16 (0x10)  | Trzecia partycja    |
| 494 (0x1EE) | 16 (0x10)  | Czwarta partycja    |
| 510 (0x1FE) | 2 (0x2)    | Sygnatura 0x55 0xAA |

**Format rekordu partycji**

| Offset    | Length   | Item                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Flaga aktywności (0x80 = bootowalna)                  |
| 1 (0x01)  | 1 (0x01) | Głowica początkowa                                     |
| 2 (0x02)  | 1 (0x01) | Sektor początkowy (bity 0-5); starsze bity cylindra (6-7) |
| 3 (0x03)  | 1 (0x01) | Najniższe 8 bitów cylindra początkowego                 |
| 4 (0x04)  | 1 (0x01) | Kod typu partycji (0x83 = Linux)                       |
| 5 (0x05)  | 1 (0x01) | Głowica końcowa                                         |
| 6 (0x06)  | 1 (0x01) | Sektor końcowy (bity 0-5); starsze bity cylindra (6-7)  |
| 7 (0x07)  | 1 (0x01) | Najniższe 8 bitów cylindra końcowego                    |
| 8 (0x08)  | 4 (0x04) | Sektory poprzedzające partycję (little endian)          |
| 12 (0x0C) | 4 (0x04) | Liczba sektorów w partycji                              |

Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać offset początkowy (możesz użyć `fdisk` i polecenia `p`).

![Partycje - MBR (główny rekord rozruchowy): Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać offset początkowy (możesz użyć fdisk i polecenia p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Następnie użyj poniższego kodu
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) to powszechnie stosowany schemat używany do **określania położenia bloków** danych przechowywanych na urządzeniach pamięci masowej, zazwyczaj w systemach pamięci masowej drugorzędnej, takich jak dyski twarde. LBA jest szczególnie prostym, liniowym schematem adresowania; **bloki są lokalizowane za pomocą indeksu całkowitego**, przy czym pierwszy blok to LBA 0, drugi LBA 1 itd.

### GPT (GUID Partition Table)

GUID Partition Table, znana jako GPT, jest preferowana ze względu na rozszerzone możliwości w porównaniu z MBR (Master Boot Record). Charakterystyczny dla GPT **globalnie unikatowy identyfikator** partycji wyróżnia ten standard na kilka sposobów:

- **Położenie i rozmiar**: Zarówno GPT, jak i MBR rozpoczynają się od **sektora 0**. GPT działa jednak na **64 bitach**, w przeciwieństwie do 32 bitów w MBR.
- **Limity partycji**: GPT obsługuje do **128 partycji** w systemach Windows i pozwala na obsługę do **9,4 ZB** danych.
- **Nazwy partycji**: Umożliwia nadawanie partycjom nazw o długości do 36 znaków Unicode.

**Odporność danych i odzyskiwanie**:

- **Redundancja**: W przeciwieństwie do MBR, GPT nie ogranicza danych partycjonowania i uruchamiania do jednego miejsca. Replikuje te dane na całym dysku, zwiększając integralność i odporność danych.
- **Cyclic Redundancy Check (CRC)**: GPT wykorzystuje CRC do zapewnienia integralności danych. Aktywnie monitoruje uszkodzenia danych, a po ich wykryciu próbuje odzyskać uszkodzone dane z innego miejsca na dysku.

**Protective MBR (LBA0)**:

- GPT zachowuje kompatybilność wsteczną za pomocą protective MBR. Funkcja ta znajduje się w przestrzeni starszego MBR, ale została zaprojektowana tak, aby uniemożliwić starszym narzędziom opartym na MBR przypadkowe nadpisanie dysków GPT, chroniąc tym samym integralność danych na dyskach sformatowanych jako GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

W systemach operacyjnych obsługujących uruchamianie **GPT-based boot through BIOS** zamiast EFI pierwszy sektor może nadal służyć do przechowywania pierwszego etapu kodu **bootloader**a, ale zmodyfikowanego tak, aby rozpoznawał **GPT** **partitions**. Bootloader w MBR nie może zakładać, że rozmiar sektora wynosi 512 bajtów.

**Nagłówek tablicy partycji (LBA 1)**

[From Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)<sup>[[1]](#references)</sup>

Nagłówek tablicy partycji definiuje użyteczne bloki na dysku. Określa również liczbę i rozmiar wpisów partycji tworzących tablicę partycji (przesunięcia 80 i 84 w tabeli).

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

**Wpisy partycji (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [Partition type GUID](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unique partition GUID (mixed endian)                                                                          |
| 32 (0x20)                   | 8 bytes  | First LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                      |
| 40 (0x28)                   | 8 bytes  | Last LBA (inclusive, usually odd)                                                                             |
| 48 (0x30)                   | 8 bytes  | Attribute flags (e.g. bit 60 denotes read-only)                                                               |
| 56 (0x38)                   | 72 bytes | Partition name (36 [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE code units)                               |

**Typy partycji**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Partition name (36 UTF-16LE code units)](<../../../images/image (83).png>)

Więcej typów partycji znajduje się na stronie [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table)

### Inspekcja

Po zamontowaniu obrazu forensics za pomocą [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) można sprawdzić pierwszy sektor przy użyciu narzędzia Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na poniższym obrazie wykryto **MBR** w **sektorze 0** i zinterpretowano go:

![GPT (GUID Partition Table) - Inspecting: After mounting the forensics image with ArsenalImageMounter , you can inspect the first sector using the Windows tool Active Disk Editor . In the...](<../../../images/image (354).png>)

Jeśli zamiast MBR występowałaby **tablica GPT**, sygnatura _EFI PART_ powinna pojawić się w **sektorze 1** (który na poprzednim obrazie jest pusty).

## File-Systems

### Lista systemów plików Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

System plików **FAT (File Allocation Table)** został zaprojektowany wokół swojego podstawowego komponentu, czyli file allocation table, umieszczonej na początku woluminu. System ten chroni dane, przechowując **dwie kopie** tablicy, co zapewnia integralność danych nawet w przypadku uszkodzenia jednej z nich. Tablica wraz z folderem głównym musi znajdować się w **stałej lokalizacji**, co ma kluczowe znaczenie dla procesu uruchamiania systemu.

Podstawową jednostką pamięci systemu plików jest **cluster, zwykle 512B**, składający się z wielu sektorów. FAT ewoluował przez następujące wersje:

- **FAT12**, obsługujący 12-bitowe adresy klastrów i do 4078 klastrów (4084 z UNIX).
- **FAT16**, rozszerzający adresy do 16 bitów, co pozwala na obsługę do 65 517 klastrów.
- **FAT32**, wykorzystujący 32-bitowe adresy i umożliwiający obsługę aż 268 435 456 klastrów na wolumin.

Istotnym ograniczeniem wszystkich wersji FAT jest **maksymalny rozmiar pliku wynoszący 4 GB**, wynikający z 32-bitowego pola używanego do przechowywania rozmiaru pliku.

Najważniejsze elementy katalogu głównego, szczególnie w systemach FAT12 i FAT16, obejmują:

- **Nazwa pliku/folderu** (do 8 znaków)
- **Atrybuty**
- **Daty utworzenia, modyfikacji i ostatniego dostępu**
- **Adres FAT Table** (wskazujący klaster początkowy pliku)
- **Rozmiar pliku**

### EXT

**Ext2** jest najczęściej spotykanym systemem plików dla partycji **not journaling** (**partitions that don't change much**), takich jak partycja rozruchowa. **Ext3/4** obsługują **journaling** i są zwykle używane dla **pozostałych partycji**.

## **Metadata**

Niektóre pliki zawierają metadata. Informacje te dotyczą zawartości pliku i czasami mogą być interesujące dla analityka, ponieważ w zależności od typu pliku mogą zawierać takie dane jak:

- Tytuł
- Użyta wersja MS Office
- Autor
- Daty utworzenia i ostatniej modyfikacji
- Model aparatu
- Współrzędne GPS
- Informacje o obrazie

Do uzyskania metadata pliku można użyć narzędzi takich jak [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/).

## **Odzyskiwanie usuniętych plików**

### Logged Deleted Files

Jak wspomniano wcześniej, istnieje kilka miejsc, w których plik nadal jest zapisany po jego „usunięciu”. Dzieje się tak dlatego, że usunięcie pliku z systemu plików zazwyczaj tylko oznacza go jako usunięty, ale dane nie są modyfikowane. Można więc przeanalizować rejestry plików (takie jak MFT) i znaleźć usunięte pliki.<sup>[[2]](#references)</sup>

System operacyjny zazwyczaj zapisuje również wiele informacji o zmianach w systemie plików i kopiach zapasowych, dlatego można spróbować wykorzystać je do odzyskania pliku lub jak największej ilości informacji.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** to technika, która próbuje **znaleźć pliki w dużej ilości danych**. Istnieją 3 główne sposoby działania takich narzędzi: **na podstawie nagłówków i stopek typów plików**, na podstawie **struktur** typów plików oraz na podstawie samej **zawartości**.

Należy pamiętać, że ta technika **nie działa w przypadku odzyskiwania pofragmentowanych plików**. Jeśli plik **nie jest przechowywany w sąsiadujących sektorach**, technika ta nie będzie w stanie znaleźć go w całości ani przynajmniej jego części.

Istnieje kilka narzędzi, których można użyć do File Carving, wskazując typy plików, których należy szukać.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Data Stream **C**arving

Data Stream Carving jest podobne do File Carving, ale **zamiast szukać kompletnych plików, wyszukuje interesujące fragmenty** informacji.\
Na przykład zamiast szukać kompletnego pliku zawierającego zarejestrowane adresy URL, technika ta wyszukuje adresy URL.

{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Secure Deletion

Oczywiście istnieją sposoby na **„bezpieczne” usuwanie plików i części logów dotyczących tych plików**. Możliwe jest na przykład **kilkukrotne nadpisanie zawartości** pliku losowymi danymi, a następnie **usunięcie** **logów** dotyczących pliku z **$MFT** i **$LOGFILE** oraz **usunięcie Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Można zauważyć, że nawet po wykonaniu tej czynności **w innych miejscach może nadal być zarejestrowane istnienie pliku**. Jest to prawda, a częścią pracy specjalisty forensics jest ich odnalezienie.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [How to scan NTFS $I30 (directory) entries for evidence of deleted files](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

{{#include ../../../banners/hacktricks-training.md}}
