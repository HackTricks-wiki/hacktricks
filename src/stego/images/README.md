# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Większość CTF image stego sprowadza się do jednej z tych kategorii:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Szybkie rozpoznanie

Priorytetowo traktuj dowody na poziomie kontenera przed głęboką analizą zawartości:

- Sprawdź poprawność pliku i zbadaj strukturę: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Wyodrębnij metadane i widoczne ciągi znaków: `exiftool -a -u -g1`, `strings`.
- Sprawdź zawartość osadzoną/dodawaną na końcu pliku: `binwalk` and end-of-file inspection (`tail | xxd`).
- Rozgałęźiaj według kontenera:
- PNG/BMP: bit-planes/LSB oraz anomalie na poziomie chunków.
- JPEG: metadane + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: ekstrakcja klatek, różnicowanie klatek, sztuczki z paletą.

## Bit-planes / LSB

### Technika

PNG/BMP są popularne w CTFach, ponieważ przechowują piksele w sposób, który ułatwia **manipulację na poziomie bitów**. Klasyczny mechanizm ukrywania/wyodrębniania to:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- The **least significant bit** (LSB) każdego kanału zmienia obraz bardzo nieznacznie.
- Atakujący ukrywają dane w tych bitach o niskiej wadze, czasem używając skoku (stride), permutacji lub wyboru per-kanałowego.

Czego się spodziewać w zadaniach:

- Payload znajduje się tylko w jednym kanale (np. `R` LSB).
- Payload znajduje się w kanale alfa.
- Payload jest skompresowany/zakodowany po wyodrębnieniu.
- Wiadomość jest rozproszona po planach bitowych lub ukryta przez XOR pomiędzy planami.

Dodatkowe rodziny, które możesz napotkać (zależne od implementacji):

- **LSB matching** (nie tylko odwracanie bitu, ale dostosowania +/-1, by dopasować docelowy bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload w indeksach kolorów zamiast surowego RGB)
- **Alpha-only payloads** (całkowicie niewidoczne w widoku RGB)

### Narzędzia

#### zsteg

`zsteg` enumeruje wiele wzorców ekstrakcji LSB/bit-plane dla PNG/BMP:
```bash
zsteg -a file.png
```
Repozytorium: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, etc).

Pobierz Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technika

PNG is a chunked format. In many challenges the payload is stored at the container/chunk level rather than in pixel values:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** that hide dimensions or break parsers until fixed

Najważniejsze miejsca w chunkach do sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Polecenia triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na co zwrócić uwagę:

- Dziwne kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunk (pngcheck zazwyczaj wskazuje dokładne przesunięcie)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz głębszego widoku chunków:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Przydatne źródła:

- Specyfikacja PNG (struktura, chunki): https://www.w3.org/TR/PNG/
- Triki formatów plików (PNG/JPEG/GIF — przypadki brzegowe): https://github.com/corkami/docs

## JPEG: metadane, narzędzia w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest kompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi PNG LSB:

- Metadane/komentarze są na poziomie pliku (wysoki sygnał i szybkie do sprawdzenia)
- Narzędzia stego działające w domenie DCT osadzają bity w współczynnikach częstotliwości

Operacyjnie traktuj JPEG jako:

- Kontener dla segmentów metadanych (wysoki sygnał, szybkie do sprawdzenia)
- Skompresowana domena sygnału (współczynniki DCT), w której działają wyspecjalizowane narzędzia stego

### Szybkie sprawdzenia
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Miejsca o wysokim sygnale:

- EXIF/XMP/IPTC metadata
- segment komentarza JPEG (`COM`)
- segmenty aplikacyjne (`APP1` for EXIF, `APPn` for vendor data)

### Popularne narzędzia

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Jeśli masz do czynienia z payloadami steghide w JPEG-ach, rozważ użycie `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Analiza poziomu błędów

ELA uwypukla różne artefakty wynikające z ponownej kompresji; może wskazać obszary, które były edytowane, ale samo w sobie nie jest detektorem stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

Dla obrazów animowanych zakładaj, że wiadomość jest:

- W pojedynczej klatce (łatwe), lub
- Rozsiana między klatkami (kolejność ma znaczenie), lub
- Widoczna tylko po porównaniu kolejnych klatek

### Wyodrębnij klatki
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Następnie traktuj klatki jak zwykłe PNG: `zsteg`, `pngcheck`, channel isolation.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wyodrębnianie klatek)
- `imagemagick`/`magick` do transformacji pojedynczych klatek

Różnicowanie klatek często bywa decydujące:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Osadzanie chronione hasłem

Jeśli podejrzewasz, że osadzenie jest chronione passphrase zamiast manipulacji na poziomie pikseli, zwykle jest to najszybsza metoda.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i umożliwia osadzanie/wyodrębnianie zaszyfrowanych payloadów.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repozytorium: https://github.com/Paradoxis/StegCracker

### stegpy

Obsługuje PNG/BMP/GIF/WebP/WAV.

Repozytorium: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
