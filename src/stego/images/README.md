# Steganografia obrazów

{{#include ../../banners/hacktricks-training.md}}

Większość image stego w CTF-ach sprowadza się do jednej z tych kategorii:

- LSB/bit-planes (PNG/BMP)
- Payloady w metadatach/komentarzach
- Dziwne chunki PNG / naprawa uszkodzeń
- Narzędzia działające w domenie DCT JPEG (OutGuess itd.)
- Oparte na klatkach (GIF/APNG)

## Szybki triage

Przed szczegółową analizą zawartości nadaj priorytet dowodom na poziomie kontenera:

- Zweryfikuj plik i sprawdź jego strukturę: `file`, `magick identify -verbose`, walidatory formatów (np. `pngcheck`).
- Wyodrębnij metadane i widoczne stringi: `exiftool -a -u -g1`, `strings`.
- Sprawdź, czy istnieje osadzona/doklejona zawartość: `binwalk` oraz inspekcja końca pliku (`tail | xxd`).
- Wybierz ścieżkę na podstawie kontenera:
- PNG/BMP: bit-planes/LSB oraz anomalie na poziomie chunków.
- JPEG: metadane + narzędzia działające w domenie DCT (rodziny w stylu OutGuess/F5).
- GIF/APNG: ekstrakcja klatek, różnicowanie klatek, triki z paletą.

## Bit-planes / LSB

### Technique

PNG/BMP są popularne w CTF-ach, ponieważ przechowują piksele w sposób ułatwiający **manipulację na poziomie bitów**. Klasyczny mechanizm ukrywania/ekstrakcji wygląda następująco:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **Najmniej znaczący bit** (LSB) każdego kanału zmienia obraz w bardzo niewielkim stopniu.
- Attackers ukrywają dane w tych bitach niższego rzędu, czasami stosując stride, permutację lub wybór kanału.

Czego można oczekiwać w challenge'ach:

- Payload znajduje się tylko w jednym kanale (np. LSB kanału `R`).
- Payload znajduje się w kanale alpha.
- Payload jest skompresowany/zakodowany po ekstrakcji.
- Wiadomość jest rozłożona między planes lub ukryta za pomocą XOR pomiędzy planes.

Dodatkowe rodziny, z którymi można się spotkać (zależnie od implementacji):

- **LSB matching** (nie tylko zmiana bitu, ale także korekty +/-1 w celu dopasowania bitu docelowego)
- **Ukrywanie oparte na palecie/indeksach** (indeksowane PNG/GIF: payload znajduje się w indeksach kolorów, a nie w surowych wartościach RGB)
- **Payload tylko w kanale alpha** (całkowicie niewidoczny w widoku RGB)

### Tooling

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/bit-planes dla PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadata, transformacje obrazu, brute forcing wariantów LSB).
- `stegsolve`: manualne filtry wizualne (izolacja kanałów, inspekcja bit planes, XOR itd.).

Pobieranie Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Triki widoczności oparte na FFT

FFT nie służy do ekstrakcji LSB; jest używane w przypadkach, gdy content jest celowo ukryty w przestrzeni częstotliwości lub w subtelnych wzorcach.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage jest często używane w CTF-ach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wewnętrzna struktura PNG: chunks, corruption i ukryte dane

### Technique

PNG jest formatem opartym na chunks. W wielu challenge’ach payload jest przechowywany na poziomie kontenera/chunk, a nie w wartościach pikseli:

- **Dodatkowe bajty po `IEND`** (wiele viewerów ignoruje końcowe bajty)
- **Niestandardowe ancillary chunks** zawierające payload
- **Uszkodzone nagłówki**, które ukrywają wymiary lub powodują awarie parserów do czasu ich naprawy

Najważniejsze lokalizacje chunks do sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (text metadata, czasami skompresowane)
- `iCCP` (profil ICC) i inne ancillary chunks używane jako carrier
- `eXIf` (dane EXIF w PNG)

### Polecenia triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na co zwrócić uwagę:

- Dziwne kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunk (pngcheck zwykle wskazuje dokładny offset)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz dokładniejszego widoku chunków:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Przydatne materiały:

- specyfikacja PNG (struktura, chunks): https://www.w3.org/TR/PNG/
- sztuczki związane z formatami plików (przypadki brzegowe PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, narzędzia w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest kompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi LSB dla PNG:

- payloady metadata/komentarzy są zapisywane na poziomie pliku (wysoki poziom sygnału i szybkie do sprawdzenia)
- narzędzia stego działające w domenie DCT osadzają bity we współczynnikach częstotliwości

Z operacyjnego punktu widzenia traktuj JPEG jako:

- kontener dla segmentów metadata (wysoki poziom sygnału, szybkie do sprawdzenia)
- skompresowaną domenę sygnału (współczynniki DCT), w której działają wyspecjalizowane narzędzia stego

### Szybkie kontrole
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Miejsca o wysokiej wartości sygnału:

- Metadane EXIF/XMP/IPTC
- Segment komentarza JPEG (`COM`)
- Segmenty aplikacji (`APP1` dla EXIF, `APPn` dla danych dostawcy)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Jeśli masz do czynienia konkretnie z payloadami steghide w plikach JPEG, rozważ użycie `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA uwydatnia różne artefakty ponownej kompresji; może wskazać obszary, które były edytowane, ale sama w sobie nie jest detektorem stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

W przypadku obrazów animowanych załóż, że wiadomość:

- Znajduje się w pojedynczej klatce (łatwy przypadek), lub
- Jest rozłożona na wiele klatek (kolejność ma znaczenie), lub
- Jest widoczna wyłącznie po porównaniu kolejnych klatek

### Wyodrębnianie klatek
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, izolacja kanałów.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wyodrębnianie klatek)
- `imagemagick`/`magick` do transformacji poszczególnych klatek

Różnicowanie klatek często jest rozstrzygające:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Kodowanie liczby pikseli w APNG

- Wykrywanie kontenerów APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnianie klatek bez zmiany ich synchronizacji czasowej: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Odzyskiwanie payloadów zakodowanych jako liczby pikseli dla poszczególnych klatek:
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
Animowane challenge mogą kodować każdy bajt jako liczbę wystąpień określonego koloru w każdej klatce; połączenie tych wartości pozwala odtworzyć wiadomość.<sup>[[1]](#references)</sup>

## Embedding chroniony hasłem

Jeśli podejrzewasz embedding chroniony passphrase zamiast manipulacji na poziomie pikseli, jest to zazwyczaj najszybsza metoda.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` oraz umożliwia embedding/extracting zaszyfrowanych payloadów.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

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
