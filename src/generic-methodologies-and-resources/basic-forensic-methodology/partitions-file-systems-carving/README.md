# Partycje/Systemy plików/Carving

{{#include ../../../banners/hacktricks-training.md}}

## Partycje

Dysk może zawierać wiele **partycji**: logicznych zakresów bloków, a nie fizycznie oddzielnych nośników. Początki i długości partycji mierzy się w **sektorach logicznych**; nie zakładaj, że każdy obraz dysku używa sektorów o rozmiarze 512 bajtów, ponieważ istnieją też sektory logiczne o rozmiarze 4096 bajtów.<sup>[[4]](#references)</sup>

### MBR (główny rekord rozruchowy)

MBR zajmuje pierwszy sektor logiczny (LBA 0); jego cztery 16-bajtowe wpisy partycji zaczynają się od bajtu 446. Poprzedzający je obszar zawiera kod rozruchowy i może zawierać sygnaturę dysku.<sup>[[4]](#references)</sup>\
Pozwala na utworzenie maksymalnie **4 partycji** (aktywna/**rozruchowa** może być najwyżej **1**). Jeśli potrzebujesz więcej partycji, możesz użyć **partycji rozszerzonych**. Ostatnie **dwa bajty** 512-bajtowego MBR to sygnatura rozruchowa **0x55 0xAA**. Tylko jedna partycja może być oznaczona jako aktywna.\
Przy sektorach logicznych o rozmiarze 512 bajtów 32-bitowe pola sektorów MBR ograniczają adresowalną przestrzeń do około **2 TiB** (2,2 TB).<sup>[[4]](#references)</sup>

![Partycje - MBR (główny rekord rozruchowy): MBR obsługuje maksymalnie 2,2 TB](<../../../images/image (350).png>)

![Partycje - MBR (główny rekord rozruchowy): MBR obsługuje maksymalnie 2,2 TB](<../../../images/image (304).png>)

W **bajtach od 440 do 443** MBR znajduje się **sygnatura dysku Windows** (jeśli używany jest system Windows). Litera dysku logicznego zależy od tej sygnatury. Zmiana sygnatury może uniemożliwić uruchomienie systemu Windows (narzędzie: [**Active Disk Editor**](https://www.disk-editor.org/index.html)**)**.

![Partycje - MBR (główny rekord rozruchowy): W bajtach od 440 do 443 MBR znajduje się sygnatura dysku Windows (jeśli używany jest system Windows). Litera dysku logicznego...](<../../../images/image (310).png>)

**Format**

| Przesunięcie | Długość   | Element                       |
| ------------ | --------- | ----------------------------- |
| 0 (0x00)     | 446(0x1BE) | Kod rozruchowy                |
| 446 (0x1BE)  | 16 (0x10) | Pierwsza partycja             |
| 462 (0x1CE)  | 16 (0x10) | Druga partycja                |
| 478 (0x1DE)  | 16 (0x10) | Trzecia partycja              |
| 494 (0x1EE)  | 16 (0x10) | Czwarta partycja              |
| 510 (0x1FE)  | 2 (0x2)   | Sygnatura 0x55 0xAA           |

**Format wpisu partycji**

| Przesunięcie | Długość   | Element                                                        |
| ------------ | --------- | -------------------------------------------------------------- |
| 0 (0x00)     | 1 (0x01)  | Flaga aktywności (0x80 = rozruchowa)                           |
| 1 (0x01)     | 1 (0x01)  | Głowica początkowa                                             |
| 2 (0x02)     | 1 (0x01)  | Sektor początkowy (bity 0–5); starsze bity cylindra (6–7)     |
| 3 (0x03)     | 1 (0x01)  | Najniższe 8 bitów cylindra początkowego                        |
| 4 (0x04)     | 1 (0x01)  | Kod typu partycji (0x83 = Linux)                               |
| 5 (0x05)     | 1 (0x01)  | Głowica końcowa                                                |
| 6 (0x06)     | 1 (0x01)  | Sektor końcowy (bity 0–5); starsze bity cylindra (6–7)        |
| 7 (0x07)     | 1 (0x01)  | Najniższe 8 bitów cylindra końcowego                           |
| 8 (0x08)     | 4 (0x04)  | Liczba sektorów poprzedzających partycję (little endian)       |
| 12 (0x0C)    | 4 (0x04)  | Liczba sektorów w partycji                                     |

Aby sprawdzić partycję w obrazie całego dysku z MBR, najpierw ustal jej początkowy LBA i rozmiar sektora logicznego. `mount` przyjmuje **przesunięcie w bajtach**, a nie LBA; poniższy przykład jest poprawny tylko dla obrazu z sektorami o rozmiarze 512 bajtów, którego partycja zaczyna się od LBA 63. W przypadku niezaufanych obrazów lub systemów plików z dziennikiem użyj zamiast tego odizolowanej procedury tylko do odczytu opisanej w [Image Acquisition & Mount](../image-acquisition-and-mount.md).<sup>[[5]](#references)[[11]](#references)</sup>

![Partycje - MBR (główny rekord rozruchowy): Aby zamontować MBR w systemie Linux, najpierw trzeba ustalić przesunięcie początkowe (można użyć fdisk i polecenia p)](<../../../images/image (413) (3) (3) (3) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

```bash
mmls -b 512 /path/to/image.dd  # Confirm the start LBA from this image
sudo mount -o ro,loop,offset=$((63 * 512)),noatime /path/to/image.dd /media/part/
```

**LBA (adresowanie bloków logicznych)**

**Adresowanie bloków logicznych** (**LBA**) to powszechny sposób **określania lokalizacji bloków** danych przechowywanych na urządzeniach pamięci masowej, zazwyczaj w systemach pamięci masowej drugiego rzędu, takich jak dyski twarde. LBA to szczególnie prosty, liniowy schemat adresowania; **bloki są lokalizowane za pomocą indeksu całkowitego**: pierwszy blok ma numer LBA 0, drugi LBA 1 itd.

### GPT (GUID Partition Table)

GUID Partition Table (GPT) przechowuje unikalny GUID dla każdej partycji oraz używa podstawowych i zapasowych metadanych. Jej układ różni się od MBR w następujący sposób:<sup>[[4]](#references)</sup>

- **Lokalizacja i rozmiar**: LBA 0 zawiera **ochronny MBR**. Podstawowy nagłówek GPT znajduje się w LBA 1; dalej znajduje się tablica wpisów partycji, a zapasowa tablica i nagłówek znajdują się na końcu dysku. GPT używa 64-bitowych pól LBA, podczas gdy wpisy partycji MBR używają pól LBA o szerokości 32 bitów.
- **Limity partycji**: Typowa tablica wpisów o rozmiarze 16 KiB mieści **128 wpisów po 128 bajtów**, ale liczba wpisów jest zapisana w nagłówku, a nie ustalona przez GPT. Adresowalny rozmiar zależy również od rozmiaru sektora logicznego (około **9,4 ZB** przy sektorach 512-bajtowych).<sup>[[4]](#references)</sup>
- **Nazwy partycji**: Możliwość nadawania partycjom nazw o długości do 36 znaków Unicode.

**Odporność danych i odzyskiwanie**:

- **Nadmiarowość**: W przeciwieństwie do MBR, GPT nie ogranicza danych partycjonowania i rozruchowych do jednego miejsca. Powiela te dane na dysku, zwiększając integralność i odporność danych.
- **Cykliczna kontrola nadmiarowa (CRC)**: Nagłówek i tablica wpisów partycji mają osobne sumy CRC32. CRC wykrywa niespójności; nie monitoruje dysku w sposób ciągły ani samodzielnie go nie naprawia. Jeśli podstawowa kopia jest nieprawidłowa, przed odzyskiwaniem na kopii roboczej sprawdź zapasową kopię znajdującą się w ostatnim LBA.<sup>[[4]](#references)</sup>

**Ochronny MBR (LBA0)**:

- GPT zapewnia zgodność wsteczną za pomocą ochronnego MBR. Znajduje się on w obszarze przeznaczonym dla starszego MBR, ale ma zapobiegać przypadkowemu nadpisaniu dysków GPT przez starsze narzędzia oparte na MBR, chroniąc w ten sposób integralność danych na dyskach sformatowanych w GPT.

![https://upload.wikimedia.org/wikipedia/commons/thumb/0/07/GUID_Partition_Table_Scheme.svg/800px-GUID_Partition_Table_Scheme.svg.png](<../../../images/image (1062).png>)

**Hybrydowy MBR (LBA 0 + GPT)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

W systemach operacyjnych obsługujących **rozruch oparty na GPT za pośrednictwem** usług **BIOS**, a nie EFI, pierwszy sektor może nadal służyć do przechowywania kodu pierwszego etapu **bootloadera**, ale **zmodyfikowanego** tak, aby rozpoznawał **partycje** **GPT**. Bootloader w MBR nie może zakładać, że rozmiar sektora wynosi 512 bajtów.

**Nagłówek tablicy partycji (LBA 1)**

[Z Wikipedii](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

Nagłówek tablicy partycji określa użyteczne bloki na dysku. Określa również liczbę i rozmiar wpisów partycji tworzących tablicę partycji (przesunięcia 80 i 84 w tabeli).

| Przesunięcie | Długość  | Zawartość                                                                                                                                                                   |
| --------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0 (0x00)  | 8 bajtów | Sygnatura ("EFI PART", 45h 46h 49h 20h 50h 41h 52h 54h lub 0x5452415020494645ULL[ ](https://en.wikipedia.org/wiki/GUID_Partition_Table#cite_note-8)na maszynach little-endian) |
| 8 (0x08)  | 4 bajty  | Wersja 1.0 (00h 00h 01h 00h) dla UEFI 2.8                                                                                                                                  |
| 12 (0x0C) | 4 bajty  | Rozmiar nagłówka w kolejności little-endian (w bajtach, zwykle 5Ch 00h 00h 00h lub 92 bajty)                                                                                |
| 16 (0x10) | 4 bajty  | [CRC32](https://en.wikipedia.org/wiki/CRC32) nagłówka (od przesunięcia +0 do rozmiaru nagłówka) w kolejności little-endian; podczas obliczania to pole ma wartość zero       |
| 20 (0x14) | 4 bajty  | Zarezerwowane; musi mieć wartość zero                                                                                                                                       |
| 24 (0x18) | 8 bajtów | Bieżące LBA (lokalizacja tej kopii nagłówka)                                                                                                                                 |
| 32 (0x20) | 8 bajtów | Zapasowe LBA (lokalizacja drugiej kopii nagłówka)                                                                                                                           |
| 40 (0x28) | 8 bajtów | Pierwsze użyteczne LBA dla partycji (ostatnie LBA podstawowej tablicy partycji + 1)                                                                                         |
| 48 (0x30) | 8 bajtów | Ostatnie użyteczne LBA (pierwsze LBA zapasowej tablicy partycji − 1)                                                                                                        |
| 56 (0x38) | 16 bajtów | GUID dysku w mieszanej kolejności bajtów                                                                                                                                    |
| 72 (0x48) | 8 bajtów | Początkowe LBA tablicy wpisów partycji (zawsze 2 w kopii podstawowej)                                                                                                       |
| 80 (0x50) | 4 bajty  | Liczba wpisów partycji w tablicy                                                                                                                                             |
| 84 (0x54) | 4 bajty  | Rozmiar pojedynczego wpisu partycji (zwykle 80h lub 128)                                                                                                                     |
| 88 (0x58) | 4 bajty  | CRC32 tablicy wpisów partycji w kolejności little-endian                                                                                                                    |
| 92 (0x5C) | \*       | Zarezerwowane; pozostała część bloku musi zawierać zera (420 bajtów przy rozmiarze sektora 512 bajtów; przy większych sektorach może być ich więcej)                         |

**Wpisy partycji (LBA 2–33)**

| Format wpisu partycji GUID |          |                                                                                                               |
| --------------------------- | -------- | ------------------------------------------------------------------------------------------------------------- |
| Przesunięcie                | Długość  | Zawartość                                                                                                      |
| 0 (0x00)                    | 16 bajtów | [GUID typu partycji](https://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_type_GUIDs) (mieszana kolejność bajtów) |
| 16 (0x10)                   | 16 bajtów | Unikalny GUID partycji (mieszana kolejność bajtów)                                                             |
| 32 (0x20)                   | 8 bajtów  | Pierwsze LBA ([little-endian](https://en.wikipedia.org/wiki/Little_endian))                                    |
| 40 (0x28)                   | 8 bajtów  | Ostatnie LBA (włącznie, zwykle nieparzyste)                                                                     |
| 48 (0x30)                   | 8 bajtów  | Flagi atrybutów (np. bit 60 oznacza tylko do odczytu)                                                           |
| 56 (0x38)                   | 72 bajty  | Nazwa partycji (36 jednostek kodowych [UTF-16](https://en.wikipedia.org/wiki/UTF-16)LE)                        |

**Typy partycji**

![MBR (master Boot Record) - GPT (GUID Partition Table): 56 (0x38) | 72 bajty | Nazwa partycji (36 jednostek kodowych UTF-16LE)](<../../../images/image (83).png>)

Więcej typów partycji: [https://en.wikipedia.org/wiki/GUID_Partition_Table](https://en.wikipedia.org/wiki/GUID_Partition_Table).<sup>[[1]](#references)</sup>

### Inspekcja

Po zamontowaniu obrazu kryminalistycznego za pomocą [**ArsenalImageMounter**](https://arsenalrecon.com/downloads/) możesz sprawdzić pierwszy sektor przy użyciu narzędzia Windows [**Active Disk Editor**](https://www.disk-editor.org/index.html)**.** Na poniższym obrazie wykryto i zinterpretowano **MBR** w **sektorze 0**:

![GPT (GUID Partition Table) - Inspekcja: Po zamontowaniu obrazu kryminalistycznego za pomocą ArsenalImageMounter możesz sprawdzić pierwszy sektor przy użyciu narzędzia Windows Active Disk Editor. Na...](<../../../images/image (354).png>)

W przypadku GPT szukaj sygnatury _EFI PART_ w podstawowym nagłówku w **LBA 1**; LBA 0 nadal zawiera ochronny MBR.<sup>[[4]](#references)</sup>

### Znajdowanie danych poza wymienionymi partycjami

Usunięty wpis partycji lub celowo pozostawiony niewykorzystany obszar może sprawić, że system plików znajdzie się poza bieżącą mapą partycji. Na **zweryfikowanej surowej kopii roboczej** wyświetl nieprzydzielone zakresy, a następnie sprawdź, czy potencjalny początkowy LBA wskazuje na system plików. `mmls` i `fsstat` używają **przesunięć sektorowych**; w obu narzędziach podaj rzeczywisty rozmiar sektora logicznego. Nie pomyl sektorów metadanych GPT z ukrytym woluminem.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
mmls -b 512 -A disk.img                # Unallocated ranges: Start and Length
fsstat -b 512 -o 2048 disk.img       # Replace 2048 with a candidate Start LBA
```

Jeśli `fsstat` nie potrafi zidentyfikować systemu plików na początku luki, użyj TestDisk: **Analyse → Quick Search**, a w razie potrzeby **Deeper Search**. Naciśnij `P` na znalezionej pozycji, aby przejrzeć pliki; nie wybieraj **Write** dla materiału dowodowego. W przypadku obrazów GPT polecenie `sgdisk --verify disk.img` sprawdza sumy CRC i zgodność głównego nagłówka z zapasowym, ale zapasowy nagłówek może być nieaktualny po ponownym partycjonowaniu, dlatego przed odzyskiwaniem potwierdź granice kandydatów na podstawie struktur systemu plików.<sup>[[9]](#references)[[10]](#references)[[4]](#references)</sup>

## Systemy plików

### Lista systemów plików Windows

- **FAT12/16**: MSDOS, WIN95/98/NT/200
- **FAT32**: 95/2000/XP/2003/VISTA/7/8/10
- **ExFAT**: 2008/2012/2016/VISTA/7/8/10
- **NTFS**: XP/2003/2008/2012/VISTA/7/8/10
- **ReFS**: 2012/2016

### FAT

System plików **FAT (File Allocation Table)** opiera się na swoim podstawowym komponencie — tablicy alokacji plików, umieszczonej na początku woluminu. Wolumin zazwyczaj zawiera **dwie kopie FAT**, choć BPB dopuszcza jedną. W systemach FAT12/16 katalog główny znajduje się w stałym obszarze; FAT32 przechowuje go w obszarze danych, w klastrze wskazanym przez `BPB_RootClus`.<sup>[[7]](#references)</sup>

Jednostką alokacji jest **klaster**: `BPB_BytsPerSec × BPB_SecPerClus`; nie musi on mieć 512 bajtów. Typ FAT określa się na podstawie liczby klastrów danych, a nie ciągu wersji w sektorze rozruchowym. Granice liczby klastrów to:<sup>[[7]](#references)</sup>

- **FAT12**: mniej niż 4,085 klastrów danych.
- **FAT16**: od 4,085 do 65,524 klastrów danych.
- **FAT32**: co najmniej 65,525 klastrów danych; do zapisania numeru klastra wykorzystywane jest tylko 28 bitów każdego 32-bitowego wpisu FAT.

32-bitowe pole rozmiaru pliku ogranicza rozmiar zwykłego pliku do **2³²−1 bajtów** (nieco mniej niż 4 GiB).<sup>[[7]](#references)</sup>

Kluczowe elementy katalogu głównego, szczególnie w FAT12 i FAT16, to:

- **Nazwa pliku/folderu** (do 8 znaków)
- **Atrybuty**
- **Daty utworzenia, modyfikacji i ostatniego dostępu**
- **Adres tablicy FAT** (wskazujący klaster początkowy pliku)
- **Rozmiar pliku**

### EXT

**Ext2** to najczęściej używany system plików dla partycji **bez journalingu** (**partycji, które nie zmieniają się zbyt często**), takich jak partycja rozruchowa. **Ext3/4** obsługują **journaling** i są zwykle używane na **pozostałych partycjach**.

## **Metadane**

Niektóre pliki zawierają metadane. Są to informacje o zawartości pliku, które czasem mogą zainteresować analityka. Zależnie od typu pliku mogą obejmować:

- Tytuł
- Wersję MS Office
- Autora
- Daty utworzenia i ostatniej modyfikacji
- Model aparatu
- Współrzędne GPS
- Informacje o obrazie

Do odczytywania metadanych pliku można użyć narzędzi takich jak [**exiftool**](https://exiftool.org) i [**Metadiver**](https://www.easymetadata.com/metadiver-2/).

## **Odzyskiwanie usuniętych plików**

### Usunięte pliki zapisane w logach

Jak wspomniano wcześniej, istnieje kilka miejsc, w których plik nadal jest zapisany po „usunięciu”. Dzieje się tak, ponieważ usunięcie pliku z systemu plików zwykle jedynie oznacza go jako usunięty, nie naruszając danych. Można więc przejrzeć rekordy plików (np. w MFT) i znaleźć usunięte pliki.<sup>[[2]](#references)</sup>

System operacyjny zwykle zapisuje również wiele informacji o zmianach w systemie plików i kopiach zapasowych, więc można spróbować wykorzystać je do odzyskania pliku lub jak największej ilości informacji.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **File Carving**

**File carving** to technika wyszukiwania **plików w dużych zbiorach danych**. Narzędzia tego typu działają na trzy główne sposoby: **na podstawie nagłówków i stopek typów plików**, na podstawie **struktur** plików lub na podstawie samej **zawartości**.

Proste carving oparte na nagłówkach i stopkach zakłada, że bloki są ciągłe, więc w przypadku podziału pliku może zwrócić tylko jego fragment. Nie jest to ograniczenie bezwzględne: PhotoRec oferuje intensywnie wykorzystującą CPU opcję **Paranoid → bruteforce**, która obsługuje niektóre pofragmentowane pliki JPEG, a składanie fragmentów z uwzględnieniem formatu może odzyskać inne obsługiwane typy plików. Aktualny przebieg składania fragmentów opisano w [narzędziach do carvingu i odzyskiwania plików](file-data-carving-recovery-tools.md#scalpel3-fragmented-carving).<sup>[[8]](#references)</sup>

Istnieje kilka narzędzi do carvingu plików, w których można wskazać typy plików do wyszukania.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### **Carving strumieni danych**

Data Stream Carving jest podobny do File Carving, ale **zamiast szukać kompletnych plików, wyszukuje interesujące fragmenty informacji**.\
Na przykład zamiast szukać kompletnego pliku zawierającego zapisane adresy URL, ta technika wyszukuje adresy URL.


{{#ref}}
file-data-carving-recovery-tools.md
{{#endref}}

### Bezpieczne usuwanie

Oczywiście istnieją sposoby na **„bezpieczne” usuwanie plików i części logów, które ich dotyczą**. Można na przykład **kilkukrotnie nadpisać zawartość pliku** losowymi danymi, a następnie **usunąć** z **$MFT** i **$LOGFILE** dotyczące go **logi** oraz **usunąć kopie w tle woluminu**.<sup>[[3]](#references)</sup>\
Można zauważyć, że nawet po wykonaniu tych czynności **istnienie pliku może być nadal odnotowane w innych miejscach**. To prawda, a jednym z zadań specjalisty kryminalistyki cyfrowej jest ich odnalezienie.



## References

- [1] [Tabela partycji GUID - Wikipedia](https://en.wikipedia.org/wiki/GUID_Partition_Table)
- [2] [Jak skanować wpisy NTFS $I30 (katalogu) w poszukiwaniu śladów usuniętych plików](https://www.osforensics.com/faqs-and-tutorials/how-to-scan-ntfs-i30-entries-deleted-files.html)
- [3] [Usługa kopiowania woluminów w tle (VSS)](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)
- [4] [Specyfikacja UEFI: układ dysku GPT](https://uefi.org/specs/UEFI/2.9_A/05_GUID_Partition_Table_Format.html)
- [5] [Podręcznik The Sleuth Kit mmls](https://sleuthkit.org/sleuthkit/man/mmls.html)
- [6] [Podręcznik The Sleuth Kit fsstat](https://www.sleuthkit.org/sleuthkit/man/fsstat.html)
- [7] [Specyfikacja Microsoft FAT](https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf)
- [8] [Opcje odzyskiwania PhotoRec](https://www.cgsecurity.org/testdisk_doc/photorec.html)
- [9] [Odzyskiwanie usuniętych partycji za pomocą TestDisk](https://www.cgsecurity.org/testdisk_doc/partition_recovery.html)
- [10] [Podręcznik sgdisk](https://manpages.debian.org/trixie/gdisk/sgdisk.8.en.html)
- [11] [Podręcznik mount(8)](https://man7.org/linux/man-pages/man8/mount.8.html)
{{#include ../../../banners/hacktricks-training.md}}
