# Narzędzia do carvingu i odzyskiwania plików/danych

## Narzędzia do carvingu i odzyskiwania

Więcej narzędzi na stronie [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używanym narzędziem w informatyce śledczej do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i pozwól mu przeanalizować plik w celu znalezienia „ukrytych” plików. Pamiętaj, że Autopsy obsługuje obrazy dysków i inne rodzaje obrazów, ale nie zwykłe pliki.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizowania plików binarnych w celu znalezienia osadzonej zawartości. Można je zainstalować za pomocą `apt`, a jego kod źródłowy znajduje się na stronie [GitHub](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk         # Installation
binwalk firmware.bin             # Display embedded data
binwalk -e firmware.bin          # Extract recognised objects (safe-default)
binwalk --dd " .* " firmware.bin  # Extract *everything* (use with care)
```
⚠️  **Uwaga dotycząca bezpieczeństwa** – Wersje **2.1.2b do 2.3.3** są podatne na **Path Traversal** (CVE-2022-4510); w advisory nie wymieniono żadnej poprawionej wersji pip. Unikaj wyodrębniania niezaufanych próbek za pomocą podatnych wydań lub odizoluj tool za pomocą kontenera/nieuprzywilejowanego UID.<sup>[[4]](#references)</sup>

### Foremost

Innym popularnym narzędziem do znajdowania ukrytych plików jest **foremost**. Plik konfiguracyjny foremost znajduje się w `/etc/foremost.conf`. Jeśli chcesz wyszukiwać tylko określone pliki, usuń znak komentarza przy odpowiednich wpisach. Jeśli nie usuniesz żadnych komentarzy, foremost wyszuka domyślnie skonfigurowane typy plików.
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

W wydaniu v2.1.1 udokumentowano kompilację za pomocą Autotools oraz ustawienie `-S jpeg_carve_mode=2` służące do odzyskiwania wszystkich ciągłych plików JPEG.<sup>[[2]](#references)</sup>
```bash
# Build from source – v2.1.1 (April 2024) requires C++17
git clone --branch v2.1.1 --recurse-submodules https://github.com/simsong/bulk_extractor.git
cd bulk_extractor
./bootstrap.sh
./configure
make -j"$(nproc)"
sudo make install

# Scan an image and carve contiguous JPEGs
bulk_extractor -o out_folder -S jpeg_carve_mode=2 /evidence/disk.img
```
Dołączony `bulk_diff.py` porównuje dwa uruchomienia bulk_extractor, natomiast `bulk_extractor_reader.py` odczytuje raport oraz pliki feature.<sup>[[3]](#references)</sup>

### PhotoRec

Znajdziesz go na stronie <https://www.cgsecurity.org/wiki/TestDisk_Download>

Jest dostępny w wersjach GUI i CLI. Możesz wybrać **typy plików**, których PhotoRec ma szukać.

![Uruchom wszystkie scannery, agresywnie odzyskuj pliki JPEG i wygeneruj bodyfile - PhotoRec: Jest dostępny w wersjach GUI i CLI. Możesz wybrać typy plików, których PhotoRec ma szukać](<../../../images/image (242).png>)

### ddrescue + ddrescueview (tworzenie obrazu uszkodzonych dysków)

Gdy dysk fizyczny jest niestabilny, dobrą praktyką jest **najpierw utworzenie jego obrazu**, a dopiero potem uruchamianie narzędzi carving na obrazie. `ddrescue` (projekt GNU) koncentruje się na niezawodnym kopiowaniu uszkodzonych dysków przy jednoczesnym prowadzeniu dziennika nieczytelnych sektorów.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Opcja **`--cluster-size`** określa, ile sektorów jest kopiowanych jednocześnie; mniejsze wartości mogą pomóc w przypadku wolnych dysków.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (odzyskiwanie usuniętych danych EXT 3/4)

Jeśli źródłowy system plików jest oparty na Linux EXT, możliwe, że uda się odzyskać niedawno usunięte pliki **bez pełnego carvingu**; te narzędzia oparte na journalingu działają na odmontowanym systemie plików lub obrazie tylko do odczytu.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Uwaga dotycząca kompatybilności** – ext4magic jest porzucony; strona projektu ostrzega, że obecne systemy plików nie są już z nim kompatybilne.<sup>[[10]](#references)</sup>

> 🛈 Jeśli system plików został zamontowany po usunięciu, bloki danych mogły już zostać ponownie użyte – w takim przypadku nadal wymagane jest właściwe carving (Foremost/Scalpel).

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) oraz [narzędzie na stronie internetowej](https://binvis.io/#/).

#### Funkcje BinVis

- Wizualna i aktywna **przeglądarka struktury**
- Wiele wykresów dla różnych punktów analizy
- Skupianie się na fragmentach próbki
- **Wyświetlanie ciągów i zasobów**, np. w plikach wykonywalnych PE lub ELF
- Uzyskiwanie **wzorców** do analizy kryptograficznej plików
- **Wykrywanie** algorytmów packera lub kodera
- **Identyfikowanie** Steganography na podstawie wzorców
- **Wizualne** porównywanie binarne

BinVis to świetny **punkt wyjścia do zapoznania się z nieznanym celem** w scenariuszu black-boxing.

## Konkretne narzędzia do data carving

### FindAES

Wyszukuje klucze AES, szukając ich harmonogramów kluczy. Potrafi znaleźć klucze 128-, 192- i 256-bitowe, takie jak używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

### YARA-X (triaging carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) to przepisana w Rust wersja YARA, wprowadzona w 2024 roku; VirusTotal informuje, że niektóre reguły wyrażeń regularnych i złożonych pętli mogą działać znacznie szybciej.<sup>[[5]](#references)</sup> Jej CLI nosi nazwę `yr`, a polecenie `scan` obsługuje skanowanie rekurencyjne, określanie liczby wątków oraz wyświetlanie metadanych.<sup>[[6]](#references)</sup>
```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```
## Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby wyświetlać obrazy w terminalu.  \
Możesz użyć narzędzia wiersza poleceń systemu Linux **pdftotext**, aby przekształcić plik pdf w tekst i go odczytać.



## References

- [1] [Informacje o wydaniu Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [README narzędzi Python bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal w binwalk (CVE-2022-4510) - GitHub Advisory Database](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA nie żyje, niech żyje YARA-X - VirusTotal Blog](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Polecenia CLI YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Podręcznik GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Podręcznik ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projektu ext4magic](https://sourceforge.net/projects/ext4magic/)
{{#include ../../../banners/hacktricks-training.md}}
