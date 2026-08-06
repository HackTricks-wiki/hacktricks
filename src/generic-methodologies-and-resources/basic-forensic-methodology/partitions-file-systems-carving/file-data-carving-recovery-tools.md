# Narzędzia do odzyskiwania i file/data carving

{{#include ../../../banners/hacktricks-training.md}}

## Narzędzia do carvingu i odzyskiwania

Więcej narzędzi znajdziesz na stronie [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używanym narzędziem w informatyce śledczej do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i zaimportuj do niego plik, aby znaleźć „ukryte” pliki. Pamiętaj, że Autopsy zostało stworzone z myślą o obsłudze obrazów dysków i innych rodzajów obrazów, ale nie zwykłych plików.

> **Aktualizacja 2024-2025** – Wersja **4.21** (wydana w lutym 2025 r.) dodała przebudowany **moduł carvingu oparty na SleuthKit v4.13**, który jest zauważalnie szybszy podczas pracy z obrazami o rozmiarze wielu terabajtów i obsługuje równoległe wyodrębnianie w systemach wielordzeniowych. Wprowadzono również niewielki wrapper CLI (`autopsycli ingest <case> <image>`), umożliwiający skryptowanie carvingu w środowiskach CI/CD lub dużych laboratoriach.<sup>[[1]](#references)</sup>
```bash
# Create a case and ingest an evidence image from the CLI (Autopsy ≥4.21)
autopsycli case --create MyCase --base /cases
# ingest with the default ingest profile (includes data-carve module)
autopsycli ingest MyCase /evidence/disk01.E01 --threads 8
```
### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizowania plików binarnych w celu znalezienia osadzonej zawartości. Można je zainstalować za pomocą `apt`, a jego kod źródłowy znajduje się na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Uwaga dotycząca bezpieczeństwa** – Wersje **≤2.3.3** są podatne na **Path Traversal** (CVE-2022-4510). Wykonaj upgrade (lub odizoluj narzędzie za pomocą kontenera/nieuprzywilejowanego UID) przed carvingiem niezaufanych próbek.<sup>[[2]](#references)</sup>

### Foremost

Innym popularnym narzędziem do znajdowania ukrytych plików jest **foremost**. Plik konfiguracyjny foremost znajduje się w `/etc/foremost.conf`. Jeśli chcesz wyszukiwać tylko określone pliki, odkomentuj je. Jeśli niczego nie odkomentujesz, foremost będzie wyszukiwać domyślnie skonfigurowane typy plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** to kolejne narzędzie, którego można użyć do znajdowania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku należy usunąć komentarz z pliku konfiguracyjnego (_/etc/scalpel/scalpel.conf_) przy typach plików, które mają zostać wyodrębnione.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor 2.x

To narzędzie jest dostępne w Kali, ale można je znaleźć tutaj: <https://github.com/simsong/bulk_extractor>

Bulk Extractor może skanować obraz dowodowy i odzyskiwać **fragmenty pcap**, **artefakty sieciowe (URL-e, domeny, adresy IP, adresy MAC, wiadomości e-mail)** oraz wiele innych obiektów **równolegle, przy użyciu wielu skanerów**.
```bash
# Build from source – v2.1.1 (April 2024) requires cmake ≥3.16
git clone https://github.com/simsong/bulk_extractor.git && cd bulk_extractor
mkdir build && cd build && cmake .. && make -j$(nproc) && sudo make install

# Run every scanner, carve JPEGs aggressively and generate a bodyfile
bulk_extractor -o out_folder -S jpeg_carve_mode=2 -S write_bodyfile=y /evidence/disk.img
```
Przydatne skrypty do post-processingu (`bulk_diff`, `bulk_extractor_reader.py`) mogą usuwać duplikaty artefaktów między dwoma obrazami lub konwertować wyniki do formatu JSON na potrzeby importu do SIEM.

### PhotoRec

Można go znaleźć pod adresem <https://www.cgsecurity.org/wiki/TestDisk_Download>

Jest dostępny w wersji GUI oraz CLI. Można wybrać **typy plików**, których PhotoRec ma szukać.

![Uruchom każdy skaner, agresywnie wyszukuj pliki JPEG i wygeneruj bodyfile - PhotoRec: Jest dostępny w wersji GUI oraz CLI. Można wybrać typy plików, których PhotoRec ma szukać](<../../../images/image (242).png>)

### ddrescue + ddrescueview (obrazowanie uszkodzonych dysków)

Gdy dysk fizyczny jest niestabilny, dobrą praktyką jest **najpierw utworzenie jego obrazu**, a dopiero potem uruchamianie narzędzi do carvingu na obrazie. `ddrescue` (projekt GNU) koncentruje się na niezawodnym kopiowaniu uszkodzonych dysków przy jednoczesnym zapisywaniu logu nieczytelnych sektorów.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Wersja **1.28** (grudzień 2024) wprowadziła opcję **`--cluster-size`**, która może przyspieszyć tworzenie obrazów wysokowydajnych SSD, w przypadku których tradycyjne rozmiary sektorów nie są już zgodne z blokami pamięci flash.

### Extundelete / Ext4magic (undelete EXT 3/4)

Jeśli źródłowy system plików jest oparty na Linux EXT, możesz być w stanie odzyskać niedawno usunięte pliki **bez pełnego carvingu**. Oba narzędzia działają bezpośrednio na obrazie tylko do odczytu:
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Fallback to full directory scan; supports extents and inline data
ext4magic disk.img -M -f '*.jpg' -d ./recovered
```
> 🛈 Jeśli system plików został zamontowany po usunięciu, bloki danych mogły już zostać ponownie wykorzystane – w takim przypadku nadal wymagany jest właściwy carving (Foremost/Scalpel).

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) oraz [narzędzie na stronie internetowej](https://binvis.io/#/).

#### Funkcje BinVis

- Wizualna i aktywna **przeglądarka struktury**
- Wiele wykresów dla różnych punktów skupienia
- Skupianie się na fragmentach próbki
- **Wyświetlanie stringów i zasobów**, np. w plikach wykonywalnych PE lub ELF
- Uzyskiwanie **wzorców** do analizy kryptograficznej plików
- **Wykrywanie** algorytmów pakujących lub kodujących
- **Identyfikowanie** steganografii na podstawie wzorców
- **Wizualne** porównywanie plików binarnych

BinVis jest świetnym **punktem wyjścia do zapoznania się z nieznanym celem** w scenariuszu black-box.

## Specific Data Carving Tools

### FindAES

Wyszukuje klucze AES, wyszukując ich harmonogramy kluczy. Potrafi znajdować klucze 128-, 192- i 256-bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) to przepisana w Rust wersja YARA wydana w 2024 roku. Jest **10–30× szybsza** niż klasyczna YARA i może służyć do bardzo szybkiej klasyfikacji tysięcy wyciętych obiektów:<sup>[[3]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yarax -r rules/index.yar out_folder/ --threads 8 --print-meta
```
Przyspieszenie sprawia, że **auto-tagowanie** wszystkich odzyskanych plików w ramach dochodzeń na dużą skalę staje się realistyczne.

## Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby wyświetlać obrazy w terminalu.  \
Możesz użyć linuxowego narzędzia wiersza poleceń **pdftotext**, aby przekształcić plik pdf w tekst i go odczytać.



## Referencje

- [1] [Informacje o wydaniu Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21)
- [2] [Path traversal w binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [3] [YARA nie żyje, niech żyje YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)

{{#include ../../../banners/hacktricks-training.md}}
