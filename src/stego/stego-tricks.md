# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Ekstrakcja danych z plików**

### **Binwalk**

Narzędzie do przeszukiwania plików binarnych w poszukiwaniu osadzonych ukrytych plików i danych. Jest instalowane za pomocą `apt`, a jego źródło jest dostępne na [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Odzyskuje pliki na podstawie ich nagłówków i stóp, przydatne dla obrazów png. Zainstalowane za pomocą `apt` z jego źródłem na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Pomaga w przeglądaniu metadanych plików, dostępne [tutaj](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Podobnie jak exiftool, do przeglądania metadanych. Można zainstalować za pomocą `apt`, źródło na [GitHub](https://github.com/Exiv2/exiv2), i ma [oficjalną stronę](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Plik**

Zidentyfikuj typ pliku, z którym masz do czynienia.

### **Ciągi**

Ekstrahuje czytelne ciągi z plików, używając różnych ustawień kodowania do filtrowania wyników.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Porównanie (cmp)**

Przydatne do porównywania zmodyfikowanego pliku z jego oryginalną wersją dostępną w Internecie.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Ekstrakcja ukrytych danych w tekście**

### **Ukryte dane w przestrzeniach**

Niewidoczne znaki w pozornie pustych przestrzeniach mogą ukrywać informacje. Aby wyodrębnić te dane, odwiedź [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Ekstrakcja danych z obrazów**

### **Identyfikacja szczegółów obrazu za pomocą GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) służy do określenia typów plików obrazów i identyfikacji potencjalnych uszkodzeń. Wykonaj poniższe polecenie, aby sprawdzić obraz:
```bash
./magick identify -verbose stego.jpg
```
Aby spróbować naprawić uszkodzony obraz, dodanie komentarza w metadanych może pomóc:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide do ukrywania danych**

Steghide umożliwia ukrywanie danych w plikach `JPEG, BMP, WAV i AU`, zdolnych do osadzania i wydobywania zaszyfrowanych danych. Instalacja jest prosta za pomocą `apt`, a [kod źródłowy jest dostępny na GitHubie](https://github.com/StefanoDeVuono/steghide).

**Polecenia:**

- `steghide info file` ujawnia, czy plik zawiera ukryte dane.
- `steghide extract -sf file [--passphrase password]` wydobywa ukryte dane, hasło opcjonalne.

Aby wydobyć dane przez internet, odwiedź [tę stronę](https://futureboy.us/stegano/decinput.html).

**Atak brute force z Stegcracker:**

- Aby spróbować złamać hasło w Steghide, użyj [stegcracker](https://github.com/Paradoxis/StegCracker.git) w następujący sposób:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg dla plików PNG i BMP**

zsteg specjalizuje się w odkrywaniu ukrytych danych w plikach PNG i BMP. Instalacja odbywa się za pomocą `gem install zsteg`, a jego [źródło na GitHubie](https://github.com/zed-0xff/zsteg).

**Polecenia:**

- `zsteg -a file` stosuje wszystkie metody detekcji na pliku.
- `zsteg -E file` określa ładunek do ekstrakcji danych.

### **StegoVeritas i Stegsolve**

**stegoVeritas** sprawdza metadane, wykonuje transformacje obrazów i stosuje brutalne siłowe ataki LSB, między innymi. Użyj `stegoveritas.py -h`, aby uzyskać pełną listę opcji, oraz `stegoveritas.py stego.jpg`, aby wykonać wszystkie kontrole.

**Stegsolve** stosuje różne filtry kolorów, aby ujawnić ukryte teksty lub wiadomości w obrazach. Jest dostępny na [GitHubie](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT do wykrywania ukrytej zawartości**

Techniki szybkiej transformaty Fouriera (FFT) mogą ujawniać ukrytą zawartość w obrazach. Przydatne zasoby to:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic na GitHubie](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy dla plików audio i obrazów**

Stegpy pozwala na osadzanie informacji w plikach obrazów i audio, wspierając formaty takie jak PNG, BMP, GIF, WebP i WAV. Jest dostępny na [GitHubie](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck do analizy plików PNG**

Aby analizować pliki PNG lub weryfikować ich autentyczność, użyj:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatkowe narzędzia do analizy obrazów**

Aby uzyskać dalsze informacje, rozważ odwiedzenie:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Ekstrakcja danych z audio**

**Steganografia audio** oferuje unikalną metodę ukrywania informacji w plikach dźwiękowych. Różne narzędzia są wykorzystywane do osadzania lub odzyskiwania ukrytej zawartości.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide to wszechstronne narzędzie zaprojektowane do ukrywania danych w plikach JPEG, BMP, WAV i AU. Szczegółowe instrukcje znajdują się w [dokumentacji stego tricks](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

To narzędzie jest kompatybilne z różnymi formatami, w tym PNG, BMP, GIF, WebP i WAV. Aby uzyskać więcej informacji, zapoznaj się z [sekcją Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg jest kluczowe do oceny integralności plików audio, podkreślając szczegółowe informacje i wskazując wszelkie nieprawidłowości.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg doskonale ukrywa i wydobywa dane w plikach WAV, wykorzystując strategię najmniej znaczącego bitu. Jest dostępny na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Komendy obejmują:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound umożliwia szyfrowanie i wykrywanie informacji w plikach dźwiękowych za pomocą AES-256. Można go pobrać z [oficjalnej strony](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Niezastąpione narzędzie do wizualnej i analitycznej inspekcji plików audio, Sonic Visualizer może ujawniać ukryte elementy niewykrywalne innymi metodami. Odwiedź [oficjalną stronę](https://www.sonicvisualiser.org/), aby dowiedzieć się więcej.

### **DTMF Tones - Dial Tones**

Wykrywanie tonów DTMF w plikach audio można osiągnąć za pomocą narzędzi online, takich jak [ten detektor DTMF](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Inne techniki**

### **Binary Length SQRT - QR Code**

Dane binarne, które są kwadratem liczby całkowitej, mogą reprezentować kod QR. Użyj tego fragmentu, aby sprawdzić:
```python
import math
math.sqrt(2500) #50
```
Aby przekonwertować binarne na obraz, sprawdź [dcode](https://www.dcode.fr/binary-image). Aby odczytać kody QR, użyj [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tłumaczenie Braille'a**

Aby przetłumaczyć Braille'a, [Branah Braille Translator](https://www.branah.com/braille-translator) jest doskonałym źródłem.

## **Referencje**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}
