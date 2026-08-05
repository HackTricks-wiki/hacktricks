# Steganografia obrazów

{{#include ../../banners/hacktricks-training.md}}

Większość image stego w CTF-ach można przypisać do jednej z tych kategorii:

- LSB/bit-planes (PNG/BMP)
- Ładunki w metadanych/komentarzach
- Nietypowe chunki PNG / naprawa uszkodzeń
- Narzędzia działające w domenie DCT JPEG (OutGuess itd.)
- Oparte na klatkach (GIF/APNG)

## Szybki triage

Przed dogłębną analizą zawartości nadaj priorytet dowodom na poziomie kontenera:

- Zweryfikuj plik i sprawdź jego strukturę: `file`, `magick identify -verbose`, walidatory formatów (np. `pngcheck`).
- Wyodrębnij metadane i widoczne stringi: `exiftool -a -u -g1`, `strings`.
- Sprawdź, czy nie ma osadzonej/dodanej zawartości: `binwalk` oraz inspekcja końca pliku (`tail | xxd`).
- Wybierz ścieżkę na podstawie kontenera:
- PNG/BMP: bit-planes/LSB i anomalie na poziomie chunków.
- JPEG: metadane + narzędzia działające w domenie DCT (rodziny w stylu OutGuess/F5).
- GIF/APNG: ekstrakcja klatek, różnicowanie klatek, triki z paletą.

## Bit-planes / LSB

### Technique

PNG/BMP są popularne w CTF-ach, ponieważ przechowują piksele w sposób ułatwiający **manipulację na poziomie bitów**. Klasyczny mechanizm ukrywania/ekstrakcji polega na tym, że:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **Najmniej znaczący bit** (LSB) każdego kanału bardzo nieznacznie zmienia obraz.
- Napastnicy ukrywają dane w tych bitach niskiego rzędu, czasami używając stride, permutacji lub wyboru kanału dla każdego elementu.

Czego można oczekiwać w challenge'ach:

- payload znajduje się tylko w jednym kanale (np. LSB kanału `R`).
- payload znajduje się w kanale alfa.
- payload jest kompresowany/zakodowany po ekstrakcji.
- Wiadomość jest rozproszona między planes lub ukryta za pomocą XOR między planes.

Dodatkowe rodziny, które możesz napotkać (zależnie od implementacji):

- **LSB matching** (nie tylko odwracanie bitu, ale także korekty +/-1 w celu dopasowania bitu docelowego)
- **Ukrywanie oparte na palecie/indeksie** (indeksowane PNG/GIF: payload znajduje się w indeksach kolorów, a nie w surowych wartościach RGB)
- **Payload wyłącznie w kanale alfa** (całkowicie niewidoczny w widoku RGB)

### Tooling

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/bit-plane dla PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, transformacje obrazu, brute forcing wariantów LSB).
- `stegsolve`: ręczne filtry wizualne (izolowanie kanałów, inspekcja płaszczyzn, XOR itd.).

Pobieranie Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Triki zwiększające widoczność oparte na FFT

FFT nie służy do ekstrakcji LSB; jest używane w przypadkach, gdy zawartość została celowo ukryta w przestrzeni częstotliwości lub w subtelnych wzorcach.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webowy triage jest często używany w CTF-ach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wewnętrzna struktura PNG: chunki, uszkodzenia i ukryte dane

### Technika

PNG jest formatem opartym na chunkach. W wielu challenge'ach payload jest przechowywany na poziomie kontenera/chunka, a nie w wartościach pikseli:

- **Dodatkowe bajty po `IEND`** (wiele przeglądarek je ignoruje)
- **Niestandardowe chunki ancillary** przenoszące payload
- **Uszkodzone nagłówki**, które ukrywają wymiary lub powodują błędy parserów do czasu ich naprawienia

Wysokosygnałowe lokalizacje chunków do sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (metadane tekstowe, czasami skompresowane)
- `iCCP` (profil ICC) oraz inne chunki ancillary używane jako nośnik
- `eXIf` (dane EXIF w PNG)

### Komendy triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na co zwrócić uwagę:

- Nietypowe kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunków (`pngcheck` zwykle wskazuje dokładny offset)
- Ostrzeżenia dotyczące dodatkowych danych po `IEND`

Jeśli potrzebujesz bardziej szczegółowego widoku chunków:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Przydatne materiały:

- Specyfikacja PNG (struktura, chunki): https://www.w3.org/TR/PNG/
- Sztuczki związane z formatami plików (przypadki brzegowe PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadane, narzędzia działające w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest skompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi LSB dla PNG:

- Ładunki metadanych/komentarzy znajdują się na poziomie pliku (są wyraźnym sygnałem i można je szybko sprawdzić)
- Narzędzia stego działające w domenie DCT osadzają bity we współczynnikach częstotliwości

Z punktu widzenia działań operacyjnych traktuj JPEG jako:

- Kontener na segmenty metadanych (wyraźny sygnał, szybka inspekcja)
- Skompresowaną domenę sygnału (współczynniki DCT), w której działają wyspecjalizowane narzędzia stego

### Szybkie sprawdzenia
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Miejsca o wysokiej wartości sygnału:

- Metadane EXIF/XMP/IPTC
- Segment komentarza JPEG (`COM`)
- Segmenty aplikacyjne (`APP1` dla EXIF, `APPn` dla danych dostawcy)

### Typowe narzędzia

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Jeśli masz do czynienia konkretnie z payloads steghide w plikach JPEG, rozważ użycie `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Analiza poziomu błędów

ELA uwidacznia różne artefakty ponownej kompresji; może wskazać regiony, które zostały zmodyfikowane, ale sama w sobie nie jest detektorem stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

W przypadku obrazów animowanych załóż, że wiadomość:

- Znajduje się w pojedynczej klatce (łatwy przypadek), lub
- Jest rozłożona na wiele klatek (kolejność ma znaczenie), lub
- Jest widoczna tylko po wykonaniu diff kolejnych klatek

### Wyodrębnianie klatek
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, izolacja kanałów.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybka ekstrakcja klatek)
- `imagemagick`/`magick` do transformacji poszczególnych klatek

Różnicowanie klatek często jest rozstrzygające:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Kodowanie liczby pikseli APNG

- Wykryj kontenery APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnij klatki bez zmiany synchronizacji czasowej: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Odzyskaj payloads zakodowane jako liczby pikseli dla każdej klatki:
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
Animowane challenges mogą kodować każdy bajt jako liczbę wystąpień określonego koloru w każdej klatce; po połączeniu tych liczności można odtworzyć wiadomość.<sup>[[1]](#references)</sup>

## Osadzanie chronione hasłem

Jeśli podejrzewasz osadzanie chronione passphrase, a nie manipulację na poziomie pikseli, jest to zwykle najszybsza metoda.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i umożliwia osadzanie oraz ekstrakcję zaszyfrowanych payloadów.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repozytorium: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Obsługuje PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Referencje

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
