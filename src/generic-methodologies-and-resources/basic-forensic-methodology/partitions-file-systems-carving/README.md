# Partycje/Systemy plików/Carving

## Partycje

Dysk twardy lub **dysk SSD może zawierać różne partycje** w celu fizycznego oddzielenia danych.\
**Minimalną** jednostką dysku jest **sektor** (zwykle składający się z 512 B). Dlatego rozmiar każdej partycji musi być wielokrotnością tej wartości.

### MBR (master Boot Record)

Jest przydzielany w **pierwszym sektorze dysku, po 446 B kodu rozruchowego**. Ten sektor jest niezbędny do wskazania komputerowi, co i skąd należy zamontować jako partycję.\
Pozwala na użycie maksymalnie **4 partycji** (najwyżej **1** może być aktywna/**bootowalna**). Jeśli potrzebujesz większej liczby partycji, możesz użyć **partycji rozszerzonych**. **Ostatni bajt** tego pierwszego sektora to sygnatura rekordu rozruchowego **0x55AA**. Tylko jedna partycja może być oznaczona jako aktywna.\
MBR pozwala na obsługę maksymalnie **2,2 TB**.

![Partycje - MBR (master Boot Record): MBR pozwala na obsługę maksymalnie 2,2 TB](<../../../images/image (350).png>)

![Partycje - MBR (master Boot Record): MBR pozwala na obsługę maksymalnie 2,2 TB](<../../../images/image (304).png>)

W **bajtach od 440 do 443** MBR można znaleźć **sygnaturę dysku Windows** (jeśli używany jest Windows). Logiczna litera dysku twardego zależy od sygnatury dysku Windows. Zmiana tej sygnatury może uniemożliwić uruchomienie systemu Windows (narzędzie: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partycje - MBR (master Boot Record): W bajtach od 440 do 443 MBR można znaleźć sygnaturę dysku Windows (jeśli używany jest Windows). Logiczna litera dysku twardego...](<../../../images/image (310).png>)

**Format**

| Przesunięcie | Długość    | Element             |
| ----------- | ---------- | ------------------- |
| 0 (0x00)    | 446(0x1BE) | Kod rozruchowy      |
| 446 (0x1BE) | 16 (0x10)  | Pierwsza partycja   |
| 462 (0x1CE) | 16 (0x10)  | Druga partycja      |
| 478 (0x1DE) | 16 (0x10)  | Trzecia partycja    |
| 494 (0x1EE) | 16 (0x10)  | Czwarta partycja    |
| 510 (0x1FE) | 2 (0x2)    | Sygnatura 0x55 0xAA |

**Format rekordu partycji**

| Przesunięcie | Długość | Element                                                   |
| --------- | -------- | ------------------------------------------------------ |
| 0 (0x00)  | 1 (0x01) | Flaga aktywności (0x80 = bootowalna)                          |
| 1 (0x01)  | 1 (0x01) | Głowica początkowa                                             |
| 2 (0x02)  | 1 (0x01) | Sektor początkowy (bity 0–5); starsze bity cylindra (6–7) |
| 3 (0x03)  | 1 (0x01) | Najmłodsze 8 bitów cylindra początkowego                           |
| 4 (0x04)  | 1 (0x01) | Kod typu partycji (0x83 = Linux)                     |
| 5 (0x05)  | 1 (0x01) | Głowica końcowa                                               |
| 6 (0x06)  | 1 (0x01) | Sektor końcowy (bity 0–5); starsze bity cylindra (6–7)   |
| 7 (0x07)  | 1 (0x01) | Najmłodsze 8 bitów cylindra końcowego                             |
| 8 (0x08)  | 4 (0x04) | Sektory poprzedzające partycję (little endian)            |
| 12 (0x0C) | 4 (0x04) | Liczba sektorów w partycji                                   |

Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać przesunięcie początkowe (możesz użyć `fdisk` i polecenia `p`)

![Partycje - MBR (master Boot Record): Aby zamontować MBR w systemie Linux, najpierw musisz uzyskać przesunięcie początkowe (możesz użyć fdisk i polecenia p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Następnie użyj poniższego kodu
```bash
#Mount MBR in Linux
mount -o ro,loop,offset=<Bytes>
#63x512 = 32256Bytes
mount -o ro,loop,offset=32256,noatime /path/to/image.dd /media/part/
```
**LBA (Logical block addressing)**

**Logical block addressing** (**LBA**) to powszechny schemat używany do **określania lokalizacji bloków** danych przechowywanych na urządzeniach pamięci masowej, zazwyczaj w systemach pamięci dodatkowej, takich jak dyski twarde. LBA jest szczególnie prostym liniowym schematem adresowania; **bloki są lokalizowane za pomocą indeksu całkowitego**, przy czym pierwszy blok to LBA 0, drugi LBA 1 itd.

### GPT (GUID Partition Table)

GUID Partition Table, znana jako GPT, jest preferowana ze względu na większe możliwości w porównaniu z MBR (Master Boot Record). Wyróżniająca się **globalnie unikatowym identyfikatorem** partycji, GPT ma kilka istotnych cech:

- **Lokalizacja i rozmiar**: Zarówno GPT, jak i MBR rozpoczynają się od **sektora 0**. GPT działa jednak na **64 bitach**, w przeciwieństwie do 32 bitów w MBR.
- **Limity partycji**: GPT obsługuje do **128 partycji** w systemach Windows i pozwala na obsługę do **9,4 ZB** danych.
- **Nazwy partycji**: Umożliwia nadawanie partycjom nazw zawierających do 36 znaków Unicode.

**Odporność danych i odzyskiwanie**:

- **Redundancja**: W przeciwieństwie do MBR, GPT nie ogranicza danych partycjonowania i uruchamiania systemu do jednej lokalizacji. Powiela te dane na całym dysku, zwiększając integralność i odporność danych.
- **Cyclic Redundancy Check (CRC)**: GPT używa CRC do zapewnienia integralności danych. Aktywnie monitoruje uszkodzenia danych, a po ich wykryciu próbuje odzyskać uszkodzone dane z innej lokalizacji na dysku.

**Protective MBR (LBA0)**:

- GPT zachowuje zgodność wsteczną za pomocą protective MBR. Funkcja ta znajduje się w przestrzeni starszego MBR, ale została zaprojektowana tak, aby uniemożliwić starszym narzędziom opartym na MBR przypadkowe nadpisanie dysków GPT, chroniąc w ten sposób integralność danych na dyskach sformatowanych jako GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrid MBR (LBA 0 + GPT)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

W systemach operacyjnych obsługujących uruchamianie oparte na **GPT przez BIOS**, a nie EFI, pierwszy sektor może być nadal używany do przechowywania pierwszego etapu kodu **bootloadera**, ale jest **zmodyfikowany**, aby rozpoznawać **partycje** **GPT**. Bootloader w MBR nie może zakładać, że rozmiar sektora wynosi 512 bajtów.

**Nagłówek tablicy partycji (LBA 1)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Nagłówek tablicy partycji definiuje użyteczne bloki na dysku. Określa również liczbę i rozmiar wpisów partycji tworzących tablicę partycji (przesunięcia 80 i 84 w tabeli).

| Offset    | Length   | Contents                                                                                                                                                                     |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bytes  | Sygnatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h lub 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#_note-8)na maszynach little-endian) |
| 8 (0x08)  | 4 bytes  | Rewizja 1.0 (00h 00h 01h 00h) dla UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bytes  | Rozmiar nagłówka w little endian (w bajtach, zwykle 5Ch 00h 00h 00h lub 92 bajty)                                                                                           |
| 16 (0x10) | 4 bytes  | [CRC32](https://en.wikipedia.org/wiki/CRC32) nagłówka (od offsetu +0 do rozmiaru nagłówka) w little endian, z wyzerowanym tym polem podczas obliczania                       |
| 20 (0x14) | 4 bytes  | Zarezerwowane; musi mieć wartość zero                                                                                                                                         |
| 24 (0x18) | 8 bytes  | Bieżące LBA (lokalizacja tej kopii nagłówka)                                                                                                                                |
| 32 (0x20) | 8 bytes  | Zapasowe LBA (lokalizacja drugiej kopii nagłówka)                                                                                                                           |
| 40 (0x28) | 8 bytes  | Pierwsze użyteczne LBA dla partycji (ostatnie LBA głównej tablicy partycji + 1)                                                                                             |
| 48 (0x30) | 8 bytes  | Ostatnie użyteczne LBA (pierwsze LBA dodatkowej tablicy partycji − 1)                                                                                                       |
| 56 (0x38) | 16 bytes | GUID dysku w mixed endian                                                                                                                                                    |
| 72 (0x48) | 8 bytes  | Początkowe LBA tablicy wpisów partycji (zawsze 2 w kopii głównej)                                                                                                           |
| 80 (0x50) | 4 bytes  | Liczba wpisów partycji w tablicy                                                                                                                                              |
| 84 (0x54) | 4 bytes  | Rozmiar pojedynczego wpisu partycji (zwykle 80h lub 128)                                                                                                                    |
| 88 (0x58) | 4 bytes  | CRC32 tablicy wpisów partycji w little endian                                                                                                                               |
| 92 (0x5C) | \*       | Zarezerwowane; pozostała część bloku musi zawierać zera (420 bajtów dla rozmiaru sektora 512 bajtów, ale przy większych rozmiarach sektorów może być ich więcej)            |

**Wpisy partycji (LBA 2–33)**

| GUID partition entry format |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Offset                      | Length   | Contents                                                                                                      |
| 0 (0x00)                    | 16 bytes | [GUID typu partycji](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mixed endian) |
| 16 (0x10)                   | 16 bytes | Unikatowy GUID partycji (mixed endian)                                                                        |
| 32 (0x20)                   | 8 bytes  | Pierwsze LBA ([little endian](https://en.wikipedia.org/wiki/Little_endian))                                  |
| 40 (0x28)                   | 8 bytes  | Ostatnie LBA (włącznie, zwykle nieparzyste)                                                                    |
| 48 (0x30)                   | 8 bytes  | Flagi atrybutów (np. bit 60 oznacza tryb tylko do odczytu)                                                     |
| 56 (0x38)                   | 72 bytes | Nazwa partycji (36 jednostek kodowych [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                       |

**Typy partycji**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bytes | Nazwa partycji (36 jednostek kodowych UTF-16LE)](<../../../images/image (83).png>)

Więcej typów partycji znajduje się na stronie [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspekcja

Po zamontowaniu obrazu forensics za pomocą [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) można przeanalizować pierwszy sektor przy użyciu narzędzia Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na poniższym obrazie wykryto **MBR** w **sektorze 0** i zinterpretowano go:

![GPT (GUID Partition Table) - Inspekcja: Po zamontowaniu obrazu forensics za pomocą ArsenalImageMounter można przeanalizować pierwszy sektor przy użyciu narzędzia Windows Active Disk Editor. Na...](<../../../images/image (354).png>)

Jeśli zamiast MBR występowałaby **tablica GPT**, w **sektorze 1** powinna pojawić się sygnatura _EFI PART_ (który na poprzednim obrazie jest pusty).

## File-Systems

### Lista systemów plików Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

System plików **FAT (File Allocation Table)** został zaprojektowany wokół swojego głównego komponentu, czyli tablicy alokacji plików, umieszczonej na początku woluminu. System ten chroni dane, przechowując **dwie kopie** tablicy, co zapewnia integralność danych nawet w przypadku uszkodzenia jednej z nich. Tablica wraz z folderem głównym musi znajdować się w **stałej lokalizacji**, co ma kluczowe znaczenie dla procesu uruchamiania systemu.

Podstawową jednostką pamięci systemu plików jest **klaster, zwykle o rozmiarze 512 B**, składający się z wielu sektorów. FAT ewoluował w kilku wersjach:

- **FAT12**, obsługujący 12-bitowe adresy klastrów i do 4078 klastrów (4084 z UNIX).
- **FAT16**, rozszerzający adresy do 16 bitów, a tym samym obsługujący do 65 517 klastrów.
- **FAT32**, wykorzystujący 32-bitowe adresy i umożliwiający obsługę imponującej liczby 268 435 456 klastrów na wolumin.

Istotnym ograniczeniem wszystkich wersji FAT jest **maksymalny rozmiar pliku wynoszący 4 GB**, wynikający z użycia 32-bitowego pola do przechowywania rozmiaru pliku.

Najważniejsze elementy katalogu głównego, zwłaszcza w FAT12 i FAT16, obejmują:

- **Nazwa pliku/folderu** (do 8 znaków)
- **Atrybuty**
- **Daty utworzenia, modyfikacji i ostatniego dostępu**
- **Adres tablicy FAT** (wskazujący klaster początkowy pliku)
- **Rozmiar pliku**

### EXT

**Ext2** jest najczęściej używanym systemem plików dla **partycji bez journalingu** (**partycji, które nie zmieniają się często**), takich jak partycja rozruchowa. **Ext3/4** obsługują **journaling** i są zwykle używane dla **pozostałych partycji**.

## **Metadata**

Niektóre pliki zawierają metadane. Informacje te dotyczą zawartości pliku i czasami mogą być interesujące dla analityka, ponieważ w zależności od typu pliku mogą zawierać takie dane jak:

- Tytuł
- Użyta wersja MS Office
- Autor
- Daty utworzenia i ostatniej modyfikacji
- Model aparatu
- Współrzędne GPS
- Informacje o obrazie

Do uzyskiwania metadanych pliku można używać narzędzi takich jak [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/).

## **Odzyskiwanie usuniętych plików**

### Zarejestrowane usunięte pliki

Jak wspomniano wcześniej, istnieje kilka miejsc, w których plik nadal jest przechowywany po jego „usunięciu”. Dzieje się tak dlatego, że usunięcie pliku z systemu plików zwykle tylko oznacza go jako usunięty, ale dane nie są modyfikowane. Możliwe jest więc przeanalizowanie rejestrów plików (takich jak MFT) i znalezienie usuniętych plików.<sup>[[2]](#references)</sup>

System operacyjny zwykle przechowuje również wiele informacji o zmianach w systemie plików i kopiach zapasowych, dlatego można spróbować użyć ich do odzyskania pliku lub jak największej ilości informacji.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** to technika, która próbuje **znajdować pliki w dużych zbiorach danych**. Istnieją 3 główne sposoby działania takich narzędzi: **na podstawie nagłówków i stopek typów plików**, na podstawie **struktur** typów plików oraz na podstawie samej **zawartości**.

Należy pamiętać, że ta technika **nie działa w przypadku odzyskiwania fragmentarycznych plików**. Jeśli plik **nie jest przechowywany w sąsiadujących sektorach**, technika ta nie będzie w stanie znaleźć pliku lub przynajmniej jego części.

Istnieje kilka narzędzi, których można używać do File Carving, wskazując typy plików, które mają być wyszukiwane.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Carving strumieni danych **C**

Data Stream Carving jest podobny do File Carving, ale **zamiast szukać kompletnych plików, wyszukuje interesujące fragmenty** informacji.\
Na przykład zamiast szukać kompletnego pliku zawierającego zarejestrowane adresy URL, technika ta wyszukuje adresy URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Bezpieczne usuwanie

Oczywiście istnieją sposoby **„bezpiecznego” usuwania plików i części logów na ich temat**. Możliwe jest na przykład wielokrotne **nadpisanie zawartości** pliku losowymi danymi, a następnie **usunięcie** **logów** dotyczących pliku z **$MFT** i **$LOGFILE** oraz **usunięcie Volume Shadow Copies**.<sup>[[3]](#references)</sup>\
Można zauważyć, że nawet po wykonaniu tej czynności mogą istnieć **inne miejsca, w których zarejestrowane jest istnienie pliku**. To prawda, a częścią pracy specjalisty forensics jest ich odnalezienie.

## References

- [1] [GUID Partition Table - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Jak skanować wpisy NTFS $I30 (katalogu) w poszukiwaniu dowodów usuniętych plików](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Volume Shadow Copy Service (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
{{#include ../../../banners/hacktricks-training.md}}
