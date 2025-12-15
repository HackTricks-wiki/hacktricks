# Steganografia obrazów

{{#include ../../banners/hacktricks-training.md}}

Większość zadań CTF dotyczących steganografii obrazów sprowadza się do jednej z poniższych kategorii:

- LSB/bit-planes (PNG/BMP)
- Metadane/treść w komentarzach
- Anomalie chunków PNG / naprawa uszkodzeń
- Narzędzia JPEG DCT-domain (OutGuess, etc)
- Oparte na klatkach (GIF/APNG)

## Szybkie rozpoznanie

Priorytetyzuj dowody na poziomie kontenera przed głęboką analizą zawartości:

- Zwaliduj plik i sprawdź strukturę: `file`, `magick identify -verbose`, walidatory formatu (np. `pngcheck`).
- Wyodrębnij metadane i widoczne ciągi znaków: `exiftool -a -u -g1`, `strings`.
- Sprawdź osadzone/dopisane dane: `binwalk` i inspekcja końca pliku (`tail | xxd`).
- Rozgałęź według kontenera:
- PNG/BMP: bit-planes/LSB i anomalie na poziomie chunków.
- JPEG: metadane + narzędzia DCT-domain (OutGuess/F5-style families).
- GIF/APNG: ekstrakcja klatek, różnicowanie klatek, sztuczki z paletą.

## Bit-planes / LSB

### Technika

PNG/BMP są popularne w CTF-ach, ponieważ przechowują piksele w sposób ułatwiający **manipulacje na poziomie bitów**. Klasyczny mechanizm ukrywania/wyodrębniania to:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **najmniej znaczący bit** (LSB) każdego kanału zmienia obraz bardzo niewiele.
- Atakujący ukrywają dane w tych najniższych bitach, czasami z użyciem kroku (stride), permutacji lub wyboru zależnego od kanału.

Czego oczekiwać w zadaniach:

- Payload znajduje się tylko w jednym kanale (np. `R` LSB).
- Payload jest w kanale alpha.
- Payload jest skompresowany/zakodowany po wyodrębnieniu.
- Wiadomość jest rozproszona po planach lub ukryta przez XOR pomiędzy planami.

Dodatkowe odmiany, na które możesz natrafić (zależne od implementacji):

- **LSB matching** (nie tylko odwracanie bitu, ale dopasowania +/-1, aby uzyskać docelowy bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload w indeksach kolorów zamiast surowego RGB)
- **Alpha-only payloads** (całkowicie niewidoczne w widoku RGB)

### Narzędzia

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/bit-plane dla PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, image transforms, brute forcing LSB variants).
- `stegsolve`: ręczne filtry wizualne (izolacja kanałów, przegląd płaszczyzn, XOR, itd).

Pobierz Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT nie jest ekstrakcją LSB; służy do przypadków, gdy zawartość jest celowo ukryta w przestrzeni częstotliwości lub w subtelnych wzorcach.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage często używane w CTFach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technika

PNG to format oparty na chunkach. W wielu zadaniach payload jest przechowywany na poziomie kontenera/chunka zamiast w wartościach pikseli:

- **Extra bytes after `IEND`** (wiele programów wyświetlających ignoruje bajty końcowe)
- **Non-standard ancillary chunks** przenoszące payloady
- **Corrupted headers**, które ukrywają wymiary lub psują parsery, dopóki nie zostaną naprawione

Kluczowe lokalizacje chunków do sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (metadane tekstowe, czasami skompresowane)
- `iCCP` (profil ICC) i inne chunki pomocnicze używane jako nośnik
- `eXIf` (dane EXIF w PNG)

### Polecenia do triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na co zwrócić uwagę:

- Dziwne kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunk (pngcheck zwykle wskazuje dokładny offset)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz głębszego widoku chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Przydatne źródła:

- Specyfikacja PNG (structure, chunks): https://www.w3.org/TR/PNG/
- Sztuczki związane z formatami plików (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadane, narzędzia działające w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest kompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi PNG LSB:

- Metadata/comment payloads są na poziomie pliku (wysoki sygnał i szybkie do sprawdzenia)
- DCT-domain stego tools umieszczają bity we współczynnikach częstotliwości

Operacyjnie traktuj JPEG jako:

- Kontener dla segmentów metadanych (wysoki sygnał, szybkie do sprawdzenia)
- Skompresowana domena sygnału (współczynniki DCT), w której działają wyspecjalizowane stego tools

### Szybkie kontrole
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
High-signal locations:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Popularne narzędzia

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Jeśli natrafisz na steghide payloads w JPEGach, rozważ użycie `stegseek` (faster bruteforce niż starsze skrypty):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA uwypukla różne artefakty ponownej kompresji; może wskazać obszary, które zostały edytowane, ale samo w sobie nie jest stego detectorem:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Obrazy animowane

### Technika

Dla obrazów animowanych przyjmij, że wiadomość jest:

- W pojedynczej klatce (łatwe), lub
- Rozłożona na wiele klatek (kolejność ma znaczenie), lub
- Widoczna tylko po wykonaniu diff między kolejnymi klatkami

### Wyodrębnij klatki
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Następnie traktuj klatki jak zwykłe PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` for per-frame transforms

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Embedding chroniony hasłem

Jeśli podejrzewasz, że embedding jest chroniony passphrase zamiast manipulacji na poziomie pikseli, to zwykle najszybsza droga.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i może embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Proszę wklej zawartość pliku src/stego/images/README.md (albo jego fragment), a przetłumaczę ją na polski zachowując oryginalne znaczniki Markdown/HTML.
```bash
stegcracker file.jpg wordlist.txt
```
Repozytorium: https://github.com/Paradoxis/StegCracker

### stegpy

Obsługuje PNG/BMP/GIF/WebP/WAV.

Repozytorium: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
