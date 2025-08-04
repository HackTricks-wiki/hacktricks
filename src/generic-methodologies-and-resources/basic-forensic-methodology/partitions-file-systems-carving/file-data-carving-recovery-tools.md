# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Więcej narzędzi w [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używane narzędzie w forensyce do ekstrakcji plików z obrazów to [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i spraw, aby przetworzyło plik w celu znalezienia "ukrytych" plików. Zauważ, że Autopsy jest zaprojektowane do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

> **Aktualizacja 2024-2025** – Wersja **4.21** (wydana w lutym 2025) dodała przebudowany **moduł carvingowy oparty na SleuthKit v4.13**, który jest zauważalnie szybszy w przypadku obrazów wielotera-bajtowych i obsługuje równoległą ekstrakcję na systemach wielordzeniowych.¹ Wprowadzono również mały wrapper CLI (`autopsycli ingest <case> <image>`), co umożliwia skryptowanie carvingu w środowiskach CI/CD lub dużych laboratoriach.
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu znalezienia osadzonej zawartości. Można je zainstalować za pomocą `apt`, a jego źródło znajduje się na [GitHubie](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Uwaga bezpieczeństwa** – Wersje **≤2.3.3** są podatne na lukę **Path Traversal** (CVE-2022-4510). Zaktualizuj (lub izoluj za pomocą kontenera/UID bez uprawnień) przed wydobywaniem nieznanych próbek.

### Foremost

Innym popularnym narzędziem do znajdowania ukrytych plików jest **foremost**. Możesz znaleźć plik konfiguracyjny foremost w `/etc/foremost.conf`. Jeśli chcesz wyszukiwać konkretne pliki, odkomentuj je. Jeśli nic nie odkomentujesz, foremost będzie szukać domyślnie skonfigurowanych typów plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** to kolejne narzędzie, które można wykorzystać do znajdowania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować w pliku konfiguracyjnym (_/etc/scalpel/scalpel.conf_) typy plików, które chcesz, aby zostały wyodrębnione.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

To narzędzie znajduje się w Kali, ale możesz je znaleźć tutaj: <https://github.com/simsong/bulk_extractor>

Bulk Extractor może skanować obraz dowodowy i wydobywać **fragmenty pcap**, **artefakty sieciowe (URL-e, domeny, IP, MAC, e-maile)** oraz wiele innych obiektów **równolegle, używając wielu skanerów**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Przydatne skrypty do przetwarzania po (`bulk_diff`, `bulk_extractor_reader.py`) mogą usunąć duplikaty artefaktów między dwoma obrazami lub przekształcić wyniki do formatu JSON do wchłonięcia przez SIEM.

### PhotoRec

Możesz go znaleźć w <https://www.cgsecurity.org/wiki/TestDisk_Download>

Dostępna jest wersja z interfejsem graficznym i wiersza poleceń. Możesz wybrać **typy plików**, które chcesz, aby PhotoRec wyszukiwał.

![](<../../../images/image (242).png>)

### ddrescue + ddrescueview (obrazowanie uszkodzonych dysków)

Gdy fizyczny dysk jest niestabilny, najlepszą praktyką jest **najpierw go zgrać** i uruchomić narzędzia do wydobywania tylko na obrazie. `ddrescue` (projekt GNU) koncentruje się na niezawodnym kopiowaniu uszkodzonych dysków, jednocześnie prowadząc dziennik nieczytelnych sektorów.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Wersja **1.28** (grudzień 2024) wprowadziła **`--cluster-size`**, co może przyspieszyć obrazowanie dysków SSD o dużej pojemności, gdzie tradycyjne rozmiary sektorów nie są już zgodne z blokami flash.

### Extundelete / Ext4magic (EXT 3/4 undelete)

Jeśli system plików źródłowy oparty jest na Linux EXT, możesz być w stanie odzyskać niedawno usunięte pliki **bez pełnego carvingu**. Oba narzędzia działają bezpośrednio na obrazie tylko do odczytu:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Jeśli system plików był zamontowany po usunięciu, bloki danych mogły już zostać ponownie użyte – w takim przypadku odpowiednie carving (Foremost/Scalpel) jest nadal wymagane.

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) i [narzędzie na stronie internetowej](https://binvis.io/#/).

#### Cechy BinVis

- Wizualny i aktywny **podgląd struktury**
- Wiele wykresów dla różnych punktów skupienia
- Skupienie na częściach próbki
- **Widzenie ciągów i zasobów**, w plikach wykonywalnych PE lub ELF, np.
- Uzyskiwanie **wzorców** do kryptanalizy plików
- **Wykrywanie** algorytmów pakujących lub kodujących
- **Identyfikacja** steganografii na podstawie wzorców
- **Wizualne** porównywanie binarne

BinVis to świetny **punkt wyjścia, aby zapoznać się z nieznanym celem** w scenariuszu black-box.

## Specyficzne narzędzia do carvingu danych

### FindAES

Wyszukuje klucze AES, przeszukując ich harmonogramy kluczy. Może znaleźć klucze 128, 192 i 256 bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) to przepisanie YARA w Rust, wydane w 2024 roku. Jest **10-30× szybsze** niż klasyczna YARA i może być używane do klasyfikacji tysięcy wyciętych obiektów bardzo szybko:
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Przyspieszenie sprawia, że **auto-tagowanie** wszystkich wyodrębnionych plików w dużych śledztwach staje się realistyczne.

## Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby zobaczyć obrazy z terminala.  \
Możesz użyć narzędzia wiersza poleceń linux **pdftotext**, aby przekształcić plik pdf w tekst i go przeczytać.

## Odniesienia

1. Notatki wydania Autopsy 4.21 – <https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21>
{{#include ../../../banners/hacktricks-training.md}}
