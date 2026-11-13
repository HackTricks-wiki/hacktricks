# Narzędzia do carvingu i odzyskiwania plików/danych

{{#include ../../../banners/hacktricks-training.md}}

## Narzędzia do carvingu i odzyskiwania

Carving wykonuj zawsze na **zweryfikowanej kopii**, nigdy na oryginalnym urządzeniu. Zobacz [Pozyskiwanie obrazu i montowanie](../image-acquisition-and-mount.md), aby poznać procedury pozyskiwania danych tylko do odczytu i obliczania skrótów.

Więcej narzędzi znajdziesz na [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używanym w informatyce śledczej narzędziem do wyodrębniania plików z obrazów jest [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i zleć mu analizę pliku, aby znaleźć „ukryte” pliki. Pamiętaj, że Autopsy obsługuje obrazy dysków i inne rodzaje obrazów, ale nie pojedyncze pliki.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu wyszukiwania osadzonych treści. **Binwalk v3** to przepisana w Rust wersja narzędzia, która oferuje automatyczne wyodrębnianie (`-e`), surowy carving znanych i nieznanych obiektów (`-c`), skanowanie rekurencyjne (Matryoshka, `-M`) oraz konfigurowalną liczbę wątków roboczych. Projekt zaleca użycie wersji Docker, jeśli potrzebne są wszystkie zewnętrzne narzędzia do wyodrębniania; `cargo install binwalk` instaluje CLI w Rust, ale nie te zewnętrzne zależności.<sup>[[11]](#references)</sup>

**Przydatne polecenia w v3**:

```bash
cargo install binwalk                 # CLI only; install extractors separately
binwalk firmware.bin                  # Identify embedded content
binwalk -e firmware.bin               # Extract recognised objects
binwalk -c -d carved firmware.bin     # Carve known and unknown objects
binwalk -Me -d extracted firmware.bin # Extract and recursively scan results
binwalk -e -l results.json firmware.bin
```

Stary przepis v2 `--dd='.*'` nie jest odpowiednikiem `-c` w v3; wykonując polecenia ze starych CTF/write-upów, najpierw sprawdź `binwalk --version`.<sup>[[11]](#references)</sup>

⚠️  **Uwaga dotycząca bezpieczeństwa** – wersje **od 2.1.2b do 2.3.3** są podatne na lukę typu **Path Traversal** (CVE-2022-4510); w poradniku nie wskazano poprawionej wersji pip. Unikaj wyodrębniania niezaufanych próbek za pomocą podatnych wersji lub uruchamiaj narzędzie w izolacji, używając kontenera/nieuprzywilejowanego UID.<sup>[[4]](#references)</sup>

### Foremost

Innym popularnym narzędziem do wyszukiwania ukrytych plików jest **foremost**. Plik konfiguracyjny foremost znajduje się w `/etc/foremost.conf`. Jeśli chcesz wyszukać tylko określone pliki, usuń znaki komentarza przy odpowiednich pozycjach. Jeśli nie usuniesz żadnych znaków komentarza, foremost wyszuka domyślnie skonfigurowane typy plików.

```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
# Discovered files will appear inside the folder "output"
```

### **Scalpel**

**Scalpel** to kolejne narzędzie, którego można użyć do znajdowania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku należy usunąć komentarz z typów plików, które mają zostać wyodrębnione, w pliku konfiguracyjnym (_/etc/scalpel/scalpel.conf_).

```bash
sudo apt-get install scalpel
scalpel file.img -o output
```

### Scalpel3 — odzyskiwanie pofragmentowanych plików

Gdy odzyskiwanie najpierw na podstawie metadanych i narzędzia do odzyskiwania plików ciągłych pozostawiają niekompletne pliki podzielone na fragmenty, **Scalpel3** może ponownie złożyć obsługiwane formaty przy użyciu walidatorów plików/bloków. To inna baza kodu niż opisana wyżej starsza komenda `scalpel`. Najpierw utwórz wymagany plik blockmap z **takim samym rozmiarem bloku**, jaki będzie używany podczas odzyskiwania; jeśli rozmiar klastra systemu plików jest znany, sprawdź go za pomocą `fsstat`, a w przeciwnym razie ustal uzasadnioną wartość przed skanowaniem obrazu partycji. Uruchamiaj narzędzie wyłącznie na zweryfikowanej kopii, a wyniki zapisuj na osobnym woluminie.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

```bash
git clone https://github.com/nolaforensix/scalpel3-release.git
cd scalpel3-release && ./init_scalpel3.sh && cd src
./crblockmap -q 4096 /evidence/partition.img /analysis/partition.blockmap
./scalpel3 -Y cpu -q 4096 -w -b -o /analysis/scalpel3 \
  /evidence/partition.img /analysis/partition.blockmap
```

Zastąp `4096` wybranym rozmiarem bloku. `-w` zachowuje obiecujące (**PROMISING**) kandydaty, a także zweryfikowane, natomiast `-b` zapisuje wektory bloków, które pomagają sprawdzić zrekonstruowane układy. Plik oznaczony jako PROMISING lub mający znajome rozszerzenie nie stanowi dowodu pełnego odzyskania danych; przed użyciem zweryfikuj jego zawartość.<sup>[[13]](#references)[[14]](#references)</sup> Aby znaleźć usunięte partycje lub luki przed carvingiem, zobacz [Finding data outside listed partitions](./#finding-data-outside-listed-partitions).

### Bulk Extractor 2.x   

To narzędzie jest dostępne w Kali, ale można je też znaleźć tutaj: <https://github.com/simsong/bulk_extractor>

Bulk Extractor może skanować obraz dowodowy i równolegle wycinać **fragmenty pcap**, **artefakty sieciowe (URL-e, domeny, adresy IP, adresy MAC, e-maile)** oraz wiele innych obiektów, używając wielu skanerów.

W dokumentacji wydania v2.1.1 opisano kompilację z użyciem Autotools oraz ustawienie `-S jpeg_carve_mode=2` służące do wycinania wszystkich ciągłych plików JPEG.<sup>[[2]](#references)</sup>

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

Dołączony `bulk_diff.py` porównuje wyniki dwóch uruchomień bulk_extractor, a `bulk_extractor_reader.py` odczytuje pliki raportów i danych.<sup>[[3]](#references)</sup>

### PhotoRec

Można go znaleźć pod adresem <https://www.cgsecurity.org/wiki/TestDisk_Download>

Jest dostępny w wersji GUI i CLI. Możesz wybrać **typy plików**, których PhotoRec ma szukać.

![Uruchom wszystkie skanery, agresywnie odzyskuj pliki JPEG i wygeneruj bodyfile — PhotoRec: Jest dostępny w wersji GUI i CLI. Możesz wybrać typy plików, których PhotoRec ma szukać](<../../../images/image (242).png>)

### The Sleuth Kit `tsk_recover` (najpierw metadane)

Przed odzyskiwaniem na podstawie surowych sygnatur spróbuj odzyskiwania z uwzględnieniem systemu plików, jeśli metadane woluminu nadal można sparsować. Domyślnie `tsk_recover` eksportuje tylko nieprzydzielone pliki; `-a` wybiera przydzielone pliki, a `-e` eksportuje oba rodzaje. W przypadku obrazu całego dysku przekaż do `-o` **sektor początkowy** partycji, odczytany za pomocą `mmls` (nie przeliczaj go na bajty). Jeśli dane wejściowe są już obrazem partycji, pomiń `-o`.<sup>[[12]](#references)</sup>

```bash
sudo apt install sleuthkit
mmls disk.img                         # Note the partition start sector, e.g. 2048
mkdir recovered-deleted recovered-all
tsk_recover -o 2048 disk.img recovered-deleted/
tsk_recover -e -o 2048 disk.img recovered-all/
```

Ten przebieg może zachować nazwy i ścieżki pochodzące z systemu plików, których nie da się odzyskać przez carving nagłówków i stopek; następnie uruchom Foremost, Scalpel lub PhotoRec dla wpisów z brakującymi lub nieużytecznymi metadanymi.<sup>[[12]](#references)</sup>

### ddrescue + ddrescueview (tworzenie obrazów uszkodzonych dysków)

Gdy dysk fizyczny jest niestabilny, dobrą praktyką jest **najpierw utworzyć jego obraz**, a narzędzia do carvingu uruchamiać dopiero na obrazie. `ddrescue` (projekt GNU) służy do niezawodnego kopiowania uszkodzonych dysków i zapisuje log nieczytelnych sektorów.

```bash
sudo apt install gddrescue ddrescueview   # On Debian-based systems
# First pass – try to get as much data as possible without retries
sudo ddrescue -f -n /dev/sdX suspect.img suspect.log
# Second pass – aggressive, 3 retries on the remaining bad areas
sudo ddrescue -d -r3 /dev/sdX suspect.img suspect.log

# Visualise the status map (green=good, red=bad)
 ddrescueview suspect.log
```

Opcja **`--cluster-size`** określa, ile sektorów jest kopiowanych naraz; mniejsze wartości mogą pomóc w przypadku wolnych dysków.<sup>[[7]](#references)</sup>

### Extundelete / Ext4magic (odzyskiwanie usuniętych plików EXT 3/4)

Jeśli źródłowy system plików jest oparty na Linux EXT, być może uda się odzyskać niedawno usunięte pliki **bez pełnego carvingu**; te narzędzia oparte na dzienniku działają na odmontowanym systemie plików lub obrazie tylko do odczytu.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Attempt journal-based undelete (metadata must still be present)
extundelete disk.img --restore-all

# Multi-stage recovery from an ext4 image
ext4magic disk.img -M -d ./recovered
```

> **Uwaga dotycząca zgodności** – ext4magic nie jest już rozwijany; na stronie projektu ostrzeżono, że obecne systemy plików nie są już z nim zgodne.<sup>[[10]](#references)</sup>

> 🛈 Jeśli system plików został zamontowany po usunięciu pliku, bloki danych mogły już zostać ponownie użyte – w takim przypadku nadal konieczne jest prawidłowe carving (Foremost/Scalpel).

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) i [narzędzie na stronie internetowej](https://binvis.io/#/).

#### Funkcje BinVis

- Wizualna i aktywna **przeglądarka struktury**
- Wiele wykresów dla różnych punktów analizy
- Skupianie się na fragmentach próbki
- **Wyświetlanie ciągów znaków i zasobów**, np. w plikach wykonywalnych PE lub ELF
- Uzyskiwanie **wzorców** do kryptoanalizy plików
- **Wykrywanie** algorytmów packerów lub koderów
- **Identyfikowanie** steganografii na podstawie wzorców
- **Wizualne** porównywanie plików binarnych

BinVis to świetny **punkt wyjścia do poznania nieznanego celu** w scenariuszu black-box.

## Specjalistyczne narzędzia do odzyskiwania danych

### FindAES

Wyszukuje klucze AES, analizując ich harmonogramy kluczy. Potrafi znaleźć klucze 128-, 192- i 256-bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

### YARA-X (wstępna analiza artefaktów odzyskanych przez carving)

[YARA-X](https://github.com/VirusTotal/yara-x) to przepisana w Rust wersja YARA, wprowadzona w 2024 roku; VirusTotal podaje, że niektóre reguły używające wyrażeń regularnych i złożonych pętli mogą działać znacznie szybciej.<sup>[[5]](#references)</sup> Jej CLI nosi nazwę `yr`, a polecenie `scan` obsługuje skanowanie rekurencyjne, określanie liczby wątków i wyświetlanie metadanych.<sup>[[6]](#references)</sup>

```bash
# Scan every carved object produced by bulk_extractor
yr scan --recursive --threads 8 --print-meta rules/index.yar out_folder/
```

## Narzędzia uzupełniające

Możesz użyć [**viu** ](https://github.com/atanunq/viu), aby wyświetlać obrazy w terminalu.  \
Możesz użyć narzędzia wiersza poleceń Linux **pdftotext**, aby przekształcić plik PDF w tekst i go odczytać.







## References

- [1] [Informacje o wydaniu Autopsy 4.21](https://github.com/sleuthkit/autopsy/releases/tag/autopsy-4.21.0)
- [2] [Plik README bulk_extractor v2.1.1](https://github.com/simsong/bulk_extractor/blob/v2.1.1/README.md)
- [3] [Plik README narzędzi Python dla bulk_extractor](https://raw.githubusercontent.com/simsong/bulk_extractor/v2.1.1/python/README.txt)
- [4] [Path traversal w binwalk (CVE-2022-4510) — baza danych porad GitHub](https://github.com/advisories/GHSA-3cm8-v4mc-gppg)
- [5] [YARA nie żyje, niech żyje YARA-X — blog VirusTotal](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html)
- [6] [Polecenia CLI YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/)
- [7] [Podręcznik GNU ddrescue](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html)
- [8] [extundelete](https://extundelete.sourceforge.net/)
- [9] [Podręcznik ext4magic](https://ext4magic.sourceforge.net/manpage_en.html)
- [10] [Status projektu ext4magic](https://sourceforge.net/projects/ext4magic/)
- [11] [Plik README Binwalk v3](https://github.com/ReFirmLabs/binwalk/blob/master/README.md)
- [12] [The Sleuth Kit: podręcznik tsk_recover](https://sleuthkit.org/sleuthkit/man/tsk_recover.html)
- [13] [Plik README Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/README.md)
- [14] [Podręcznik Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/man/scalpel3.1)
- [15] [Przepływ pracy testów Scalpel3](https://github.com/nolaforensix/scalpel3-release/blob/main/src/TESTS/cmdline.test)
{{#include ../../../banners/hacktricks-training.md}}
