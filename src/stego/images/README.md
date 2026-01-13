# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

W większości zadań CTF image stego sprowadza się do jednej z tych kategorii:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Priorytetyzuj dowody na poziomie kontenera zanim przejdziesz do głębokiej analizy zawartości:

- Zwaliduj plik i sprawdź strukturę: `file`, `magick identify -verbose`, format validators (np. `pngcheck`).
- Wyciągnij metadata i widoczne ciągi: `exiftool -a -u -g1`, `strings`.
- Sprawdź osadzoną/dodaną zawartość: `binwalk` i inspekcja końca pliku (`tail | xxd`).
- Postępuj według typu kontenera:
- PNG/BMP: bit-planes/LSB i anomalie na poziomie chunk.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: ekstrakcja klatek, frame differencing, triki z paletą.

## Bit-planes / LSB

### Technique

PNG/BMP są popularne w CTF, ponieważ przechowują piksele w sposób, który ułatwia manipulację na poziomie bitów. Klasyczny mechanizm ukrywania/wyodrębniania to:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- The **least significant bit** (LSB) of each channel changes the image very little.
- Atakujący ukrywają dane w tych niskorzędnych bitach, czasem ze skokiem, permutacją lub wyborem per-kanałowym.

Czego się spodziewać w zadaniach:

- Payload jest tylko w jednym kanale (np. `R` LSB).
- Payload jest w kanale alpha.
- Payload jest skompresowany/zakodowany po ekstrakcji.
- Wiadomość jest rozłożona po bit-planes lub ukryta przez XOR między bit-planes.

Dodatkowe rodziny, na które możesz natrafić (zależne od implementacji):

- **LSB matching** (nie tylko odwracanie bitu, lecz dostosowania +/-1, by dopasować docelowy bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload w indeksach kolorów zamiast surowego RGB)
- **Alpha-only payloads** (całkowicie niewidoczne w widoku RGB)

### Tooling

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/bit-plane dla PNG/BMP:
```bash
zsteg -a file.png
```
Repozytorium: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, transformacje obrazu, brute forcing LSB variants).
- `stegsolve`: ręczne filtry wizualne (channel isolation, plane inspection, XOR, itp).

Pobierz Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT nie jest ekstrakcją LSB; służy w przypadkach, gdy zawartość jest celowo ukryta w przestrzeni częstotliwości lub subtelnych wzorcach.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage webowe często używane w CTF-ach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wnętrze PNG: chunki, uszkodzenia i ukryte dane

### Technika

PNG to format oparty na chunkach. W wielu zadaniach payload jest przechowywany na poziomie kontenera/chunka zamiast w wartościach pikseli:

- **Extra bytes after `IEND`** (wiele programów do podglądu ignoruje bajty na końcu)
- **Non-standard ancillary chunks** przenoszące payloady
- **Corrupted headers** które ukrywają wymiary lub łamią parsery, dopóki nie zostaną naprawione

Chunki warte sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (tekstowe metadane, czasem skompresowane)
- `iCCP` (ICC profile) i inne chunki pomocnicze używane jako nośnik
- `eXIf` (dane EXIF w PNG)

### Polecenia triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na co zwrócić uwagę:

- Nietypowe kombinacje width/height/bit-depth/colour-type
- Błędy CRC/chunków (pngcheck zazwyczaj wskazuje dokładny offset)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz bardziej szczegółowego widoku chunków:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Przydatne odniesienia:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadane, narzędzia w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest skompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi PNG LSB:

- Metadata/comment payloads są na poziomie pliku (high-signal i szybkie do sprawdzenia)
- Narzędzia stego działające w domenie DCT osadzają bity we współczynnikach częstotliwości

Operacyjnie traktuj JPEG jako:

- Kontener dla segmentów metadanych (high-signal, szybkie do sprawdzenia)
- Skompresowaną domenę sygnału (współczynniki DCT), w której działają wyspecjalizowane narzędzia stego

### Szybkie kontrole
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC metadane
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Popularne narzędzia

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA highlights different recompression artifacts; it can point you to regions that were edited, but it’s not a stego detector by itself:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

For animated images, assume the message is:

- In a single frame (easy), or
- Spread across frames (ordering matters), or
- Only visible when you diff consecutive frames

### Wyodrębnij klatki
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, channel isolation.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wydobywanie klatek)
- `imagemagick`/`magick` do transformacji pojedynczych klatek

Porównywanie różnic między klatkami często bywa decydujące:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Kodowanie liczbą pikseli w APNG

- Wykryj kontenery APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnij klatki bez zmiany czasowania: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Odzyskaj payloads zakodowane jako liczba pikseli na klatkę:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Animowane wyzwania mogą zakodować każdy bajt jako liczbę wystąpień określonego koloru w każdej klatce; połączenie tych wartości odtwarza wiadomość.

## Osadzanie chronione hasłem

Jeśli podejrzewasz, że osadzanie jest chronione passphrase zamiast manipulacji na poziomie pikseli, zwykle to najszybsza ścieżka.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i może embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the contents of src/stego/images/README.md (or the excerpt you want translated). I will translate the English text to Polish, preserving all markdown, tags, links, paths and code exactly as requested.
```bash
stegcracker file.jpg wordlist.txt
```
Repozytorium: https://github.com/Paradoxis/StegCracker

### stegpy

Obsługuje PNG/BMP/GIF/WebP/WAV.

Repozytorium: https://github.com/dhsdshdhk/stegpy

## Źródła

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
