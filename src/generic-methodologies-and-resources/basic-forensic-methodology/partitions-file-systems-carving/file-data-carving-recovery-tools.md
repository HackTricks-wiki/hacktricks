# Narzędzia do carvingu i odzyskiwania plików/danych

{{#include ../../../banners/hacktricks-training.md}}

## Narzędzia do carvingu i odzyskiwania

Zawsze wykonuj carving na **zweryfikowanej kopii**, a nie na oryginalnym urządzeniu. Zobacz [Image Acquisition & Mount](../image-acquisition-and-mount.md), aby zapoznać się z procedurami pozyskiwania danych w trybie tylko do odczytu i hashowania.

Więcej narzędzi znajdziesz na stronie [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najpopularniejszym narzędziem używanym w informatyce śledczej do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i uruchom ingest pliku, aby znaleźć „ukryte” pliki. Pamiętaj, że Autopsy obsługuje obrazy dysków i inne rodzaje obrazów, ale nie obsługuje zwykłych plików.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu wykrywania osadzonej zawartości. **Binwalk v3** to przepisana w Rust wersja z automatycznym ekstrakcją (`-e`), surowym carvingiem znanych i nieznanych obiektów (`-c`), rekurencyjnym skanowaniem (Matryoshka) (`-M`) oraz konfigurowalnymi wątkami roboczymi. Projekt zaleca użycie wersji Docker, gdy wymagane są wszystkie zewnętrzne extractory; `cargo install binwalk` instaluje Rust CLI, ale nie te zewnętrzne zależności.<sup>[[11]](#references)</sup>

**Przydatne polecenia v3**:
```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```
Stara recepta v2 `--dd='.*'` nie jest odpowiednikiem v3 dla `-c`; najpierw sprawdź `binwalk --version`, wykonując stare polecenia z CTF/write-upów.<sup>[[11]](#references)</sup>

⚠️  **Uwaga dotycząca bezpieczeństwa** – wersje **od 2.1.2b do 2.3.3** są podatne na **Path Traversal** (CVE-2022-4510); advisory nie wymienia żadnej poprawionej wersji pip. Unikaj ekstrakcji niezaufanych próbek za pomocą podatnych wydań albo odizoluj narzędzie w kontenerze/używając nieuprzywilejowanego UID.<sup>[[4]](#references)</sup>

### Foremost

Innym popularnym narzędziem do znajdowania ukrytych plików jest **foremost**. Plik konfiguracyjny foremost znajdziesz w `/etc/foremost.conf`. Jeśli chcesz wyszukiwać tylko określone pliki, usuń znak komentarza przy odpowiednich wpisach. Jeśli nie usuniesz znaków komentarza, foremost będzie wyszukiwać domyślnie skonfigurowane typy plików.
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

Bulk Extractor może skanować obraz dowodowy i wyodrębniać **fragmenty pcap**, **artefakty sieciowe (adresy URL, domeny, adresy IP, adresy MAC, e-maile)** oraz wiele innych obiektów **równolegle przy użyciu wielu skanerów**.

W wydaniu v2.1.1 opisano kompilację Autotools oraz ustawienie `-S jpeg_carve_mode=2` umożliwiające wyodrębnianie wszystkich ciągłych plików JPEG.<sup>[[2]](#references)</sup>
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
Dołączony `bulk_diff.py` porównuje dwa uruchomienia bulk_extractor, natomiast `bulk_extractor_reader.py` odczytuje raport i pliki feature.<sup>[[3]](#references)</sup>

### PhotoRec

Można go znaleźć na stronie <https://www.cgsecurity.org/wiki/TestDisk_Download>

Jest dostępny w wersji GUI i CLI. Możesz wybrać **file-types**, których PhotoRec ma szukać.

![Uruchom wszystkie skanery, agresywnie odzyskuj pliki JPEG i wygeneruj bodyfile - PhotoRec: Jest dostępny w wersji GUI i CLI. Możesz wybrać file-types, których PhotoRec ma szukać](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (metadata-first)

Przed wykonaniem raw signature carving spróbuj odzyskiwania z uwzględnieniem systemu plików, gdy metadane woluminu nadal mogą być analizowane. Domyślnie `tsk_recover` eksportuje tylko nieprzydzielone pliki; `-a` wybiera pliki przydzielone, a `-e` eksportuje oba typy. W przypadku obrazu całego dysku przekaż do `-o` **start sector** partycji z `mmls` (nie konwertuj go na bajty). Jeśli wejście jest już obrazem partycji, pomiń `-o`.<sup>[[12]](#references)</sup>
```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```
Ten przebieg może zachować nazwy i ścieżki wyprowadzone z systemu plików, których nie można odzyskać metodą carvingu na podstawie nagłówków i stopek; następnie uruchom Foremost, Scalpel lub PhotoRec dla wpisów, których metadane są niedostępne albo nieprzydatne.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (tworzenie obrazów uszkodzonych dysków)

Gdy dysk fizyczny jest niestabilny, dobrą praktyką jest **najpierw utworzenie jego obrazu**, a dopiero potem uruchamianie narzędzi do carvingu na obrazie. `ddrescue` (projekt GNU) koncentruje się na niezawodnym kopiowaniu uszkodzonych dysków przy jednoczesnym zapisywaniu dziennika nieodczytywalnych sektorów.
```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
ddrescueview suspect.log
```
Opcja **`--cluster-size`** kontroluje liczbę sektorów kopiowanych jednocześnie; mniejsze wartości mogą pomóc w przypadku wolnych dysków.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (odzyskiwanie usuniętych plików EXT 3/4)

Jeśli źródłowy system plików jest oparty na Linux EXT, możesz być w stanie odzyskać niedawno usunięte pliki **bez pełnego carvingu**; te narzędzia oparte na dzienniku działają na odmontowanym systemie plików lub obrazie tylko do odczytu.<sup>[[8]](#references)[[9]](#references)</sup>
```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```
> **Uwaga dotycząca kompatybilności** – ext4magic jest porzucony; strona projektu ostrzega, że obecne systemy plików nie są już z nim kompatybilne.<sup>[[10]](#references)</sup>

> 🛈 Jeśli system plików został zamontowany po usunięciu, bloki danych mogły już zostać ponownie użyte – w takim przypadku nadal wymagane jest prawidłowe carving (Foremost/Scalpel).

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) oraz [narzędzie na stronie](https://binvis.io/#/).

#### Funkcje BinVis

- Wizualna i aktywna **przeglądarka struktury**
- Wiele wykresów dla różnych punktów skupienia
- Skupianie się na fragmentach próbki
- **Wyświetlanie ciągów i zasobów**, np. w plikach wykonywalnych PE lub ELF
- Uzyskiwanie **wzorców** do kryptoanalizy plików
- **Wykrywanie** algorytmów pakujących lub kodujących
- **Identyfikowanie** steganografii na podstawie wzorców
- **Wizualne** różnicowanie binarne

BinVis to świetny **punkt wyjścia do zapoznania się z nieznanym celem** w scenariuszu black-boxing.

## Konkretne narzędzia do Data Carving

### FindAES

Wyszukuje klucze AES, wyszukując ich harmonogramy kluczy. Potrafi znaleźć klucze 128-, 192- i 256-bitowe, takie jak używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

### YARA-X (triage carved artefacts)

[YARA-X](https://github.com/VirusTotal/yara-x) to przepisana w Rust wersja YARA wprowadzona w 2024 roku; VirusTotal informuje, że niektóre reguły wyrażeń regularnych i złożonych pętli mogą działać znacznie szybciej.<sup>[[5]](#references)</sup> Jej CLI nosi nazwę `yr`, a polecenie `scan` obsługuje skanowanie rekurencyjne, określanie liczby wątków i wyświetlanie metadanych.<sup>[[6]](#references)</sup>
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
- [11] [README Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: podręcznik tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
{{#include ../../../banners/hacktricks-training.md}}
