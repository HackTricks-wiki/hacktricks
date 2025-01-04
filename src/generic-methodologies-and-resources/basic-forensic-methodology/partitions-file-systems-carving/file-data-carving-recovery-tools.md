# File/Data Carving & Recovery Tools

{{#include ../../../banners/hacktricks-training.md}}

## Carving & Recovery tools

Więcej narzędzi w [https://github.com/Claudio-C/awesome-datarecovery](https://github.com/Claudio-C/awesome-datarecovery)

### Autopsy

Najczęściej używane narzędzie w forensyce do ekstrakcji plików z obrazów to [**Autopsy**](https://www.autopsy.com/download/). Pobierz je, zainstaluj i spraw, aby przetworzyło plik w celu znalezienia "ukrytych" plików. Zauważ, że Autopsy jest zaprojektowane do obsługi obrazów dysków i innych rodzajów obrazów, ale nie prostych plików.

### Binwalk <a href="#binwalk" id="binwalk"></a>

**Binwalk** to narzędzie do analizy plików binarnych w celu znalezienia osadzonych treści. Można je zainstalować za pomocą `apt`, a jego źródło znajduje się na [GitHub](https://github.com/ReFirmLabs/binwalk).

**Przydatne polecenia**:
```bash
sudo apt install binwalk #Insllation
binwalk file #Displays the embedded data in the given file
binwalk -e file #Displays and extracts some files from the given file
binwalk --dd ".*" file #Displays and extracts all files from the given file
```
### Foremost

Innym powszechnym narzędziem do znajdowania ukrytych plików jest **foremost**. Możesz znaleźć plik konfiguracyjny foremost w `/etc/foremost.conf`. Jeśli chcesz wyszukać konkretne pliki, odkomentuj je. Jeśli nic nie odkomentujesz, foremost będzie szukać domyślnie skonfigurowanych typów plików.
```bash
sudo apt-get install foremost
foremost -v -i file.img -o output
#Discovered files will appear inside the folder "output"
```
### **Scalpel**

**Scalpel** to kolejne narzędzie, które można wykorzystać do znajdowania i wyodrębniania **plików osadzonych w pliku**. W tym przypadku będziesz musiał odkomentować w pliku konfiguracyjnym (_/etc/scalpel/scalpel.conf_) typy plików, które chcesz, aby zostały wyodrębnione.
```bash
sudo apt-get install scalpel
scalpel file.img -o output
```
### Bulk Extractor

To narzędzie znajduje się w Kali, ale możesz je znaleźć tutaj: [https://github.com/simsong/bulk_extractor](https://github.com/simsong/bulk_extractor)

To narzędzie może skanować obraz i **wyodrębniać pcaps** w nim, **informacje o sieci (URL-e, domeny, IP, MAC, maile)** i więcej **plików**. Musisz tylko zrobić:
```
bulk_extractor memory.img -o out_folder
```
Przejrzyj **wszystkie informacje**, które narzędzie zgromadziło (hasła?), **analizuj** **pakiety** (przeczytaj [**analizę Pcaps**](../pcap-inspection/index.html)), wyszukaj **dziwne domeny** (domeny związane z **złośliwym oprogramowaniem** lub **nieistniejącymi**).

### PhotoRec

Możesz go znaleźć pod adresem [https://www.cgsecurity.org/wiki/TestDisk_Download](https://www.cgsecurity.org/wiki/TestDisk_Download)

Dostępna jest wersja z interfejsem graficznym i wiersza poleceń. Możesz wybrać **typy plików**, które PhotoRec ma wyszukiwać.

![](<../../../images/image (242).png>)

### binvis

Sprawdź [kod](https://code.google.com/archive/p/binvis/) oraz [stronę narzędzia](https://binvis.io/#/).

#### Cechy BinVis

- Wizualny i aktywny **podgląd struktury**
- Wiele wykresów dla różnych punktów skupienia
- Skupienie na częściach próbki
- **Widzenie ciągów i zasobów** w plikach wykonywalnych PE lub ELF, np.
- Uzyskiwanie **wzorców** do kryptanalizy plików
- **Wykrywanie** algorytmów pakujących lub kodujących
- **Identyfikacja** steganografii na podstawie wzorców
- **Wizualne** porównywanie binarne

BinVis to świetny **punkt wyjścia, aby zapoznać się z nieznanym celem** w scenariuszu black-boxing.

## Specyficzne narzędzia do wydobywania danych

### FindAES

Wyszukuje klucze AES, przeszukując ich harmonogramy kluczy. Może znaleźć klucze 128, 192 i 256 bitowe, takie jak te używane przez TrueCrypt i BitLocker.

Pobierz [tutaj](https://sourceforge.net/projects/findaes/).

## Narzędzia uzupełniające

Możesz użyć [**viu**](https://github.com/atanunq/viu), aby zobaczyć obrazy z terminala.\
Możesz użyć narzędzia wiersza poleceń Linux **pdftotext**, aby przekształcić plik pdf w tekst i go przeczytać.

{{#include ../../../banners/hacktricks-training.md}}
