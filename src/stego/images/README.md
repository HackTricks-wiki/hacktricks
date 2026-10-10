# Steganografia obrazów

{{#include ../../banners/hacktricks-training.md}}

Większość stego w obrazach w CTF-ach sprowadza się do jednej z tych kategorii:

- LSB/płaszczyzny bitowe (PNG/BMP)
- Payloady w metadanych/komentarzach
- Dziwne fragmenty PNG / naprawa uszkodzeń
- Narzędzia działające w domenie DCT JPEG (OutGuess itp.)
- Ukrywanie danych w klatkach (GIF/APNG)

## Szybka analiza wstępna

Przed szczegółową analizą zawartości skup się na dowodach dotyczących kontenera:

- Zweryfikuj plik i sprawdź jego strukturę: `file`, `magick identify -verbose`, narzędzia do walidacji formatów (np. `pngcheck`).
- Wyodrębnij metadane i widoczne ciągi znaków: `exiftool -a -u -g1`, `strings`.
- Sprawdź, czy nie ma osadzonej/dodanej na końcu zawartości: `binwalk` i analiza końca pliku (`tail | xxd`).
- Wybierz ścieżkę w zależności od kontenera:
  - PNG/BMP: płaszczyzny bitowe/LSB i anomalie na poziomie fragmentów.
  - JPEG: metadane i narzędzia działające w domenie DCT (rodziny w stylu OutGuess/F5).
  - GIF/APNG: ekstrakcja klatek, różnicowanie klatek, sztuczki z paletą.

## Płaszczyzny bitowe / LSB

### Technika

PNG/BMP są popularne w CTF-ach, ponieważ przechowują piksele w sposób ułatwiający **manipulację na poziomie bitów**. Klasyczny mechanizm ukrywania/wyodrębniania danych polega na tym, że:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **Najmniej znaczący bit** (LSB) każdego kanału zmienia obraz w bardzo niewielkim stopniu.
- Atakujący ukrywają dane w tych bitach niższego rzędu, czasem stosując krok, permutację lub wybór kanału.

Czego można się spodziewać w zadaniach:

- Payload znajduje się tylko w jednym kanale (np. LSB kanału `R`).
- Payload znajduje się w kanale alfa.
- Payload jest kompresowany/kodowany po wyodrębnieniu.
- Wiadomość jest rozłożona na płaszczyznach lub ukryta za pomocą XOR między płaszczyznami.

Dodatkowe rodziny metod, na które możesz się natknąć (zależne od implementacji):

- **Dopasowywanie LSB** (nie tylko odwracanie bitu, ale też zmiany o +/-1, aby dopasować bit docelowy)
- **Ukrywanie oparte na palecie/indeksach** (indeksowane PNG/GIF: payload ukryty w indeksach kolorów zamiast w surowych wartościach RGB)
- **Payloady tylko w kanale alfa** (całkowicie niewidoczne w widoku RGB)

### Narzędzia

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/płaszczyzn bitowych dla PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, transformacje obrazu, brute force wariantów LSB).
- `stegsolve`: ręczne filtry wizualne (izolowanie kanałów, inspekcja płaszczyzn, XOR itd.).

Pobieranie Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Sztuczki zwiększające widoczność oparte na FFT

FFT nie służy do ekstrakcji LSB; przydaje się w przypadkach, gdy zawartość jest celowo ukryta w przestrzeni częstotliwości lub subtelnych wzorach.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Narzędzia internetowe do wstępnej analizy często używane w CTF-ach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wewnętrzna struktura PNG: chunki, uszkodzenia i ukryte dane

### Technika

PNG to format oparty na chunkach. W wielu zadaniach payload jest przechowywany na poziomie kontenera/chunków, a nie w wartościach pikseli:

- **Dodatkowe bajty po `IEND`** (wiele przeglądarek ignoruje końcowe bajty)
- **Niestandardowe chunki pomocnicze** zawierające payloady
- **Uszkodzone nagłówki**, które ukrywają wymiary lub powodują błędy parserów, dopóki nie zostaną naprawione

Chunki, którym warto przyjrzeć się w pierwszej kolejności:

- `tEXt` / `iTXt` / `zTXt` (metadane tekstowe, czasem skompresowane)
- `iCCP` (profil ICC) i inne chunki pomocnicze używane jako nośnik danych
- `eXIf` (dane EXIF w PNG)

### Polecenia do wstępnej analizy

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Na co zwrócić uwagę:

- Nietypowe kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunków (pngcheck zwykle wskazuje dokładny offset)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz dokładniejszego widoku chunków:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Przydatne materiały:

- Specyfikacja PNG (struktura, chunki): https://www.w3.org/TR/PNG/
- Sztuczki z formatami plików (przypadki brzegowe PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadane, narzędzia działające w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele — jest kompresowany w domenie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi PNG LSB:

- Ładunki w metadanych i komentarzach znajdują się na poziomie pliku (łatwo je wykryć i szybko sprawdzić)
- Narzędzia stego działające w domenie DCT osadzają bity we współczynnikach częstotliwościowych

W praktyce traktuj JPEG jako:

- Kontener metadanych (łatwo je wykryć i szybko sprawdzić)
- Skompresowany sygnał (współczynniki DCT), w którym działają wyspecjalizowane narzędzia stego

### Szybkie kontrole

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Lokalizacje o wysokim sygnale:

- Metadane EXIF/XMP/IPTC
- Segment komentarza JPEG (`COM`)
- Segmenty aplikacji (`APP1` dla EXIF, `APPn` dla danych dostawcy)

### Popularne narzędzia

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Jeśli konkretnie masz do czynienia z payloadami steghide w plikach JPEG, rozważ użycie `stegseek` (szybszy brute force niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA uwydatnia różnice w artefaktach ponownej kompresji; może wskazać obszary, które zostały edytowane, ale samo w sobie nie wykrywa steganografii:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

W przypadku obrazów animowanych załóż, że wiadomość jest:

- W pojedynczej klatce (łatwe), lub
- Rozłożona na wiele klatek (kolejność ma znaczenie), lub
- Widoczna tylko po porównaniu kolejnych klatek

### Wyodrębnianie klatek

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, izolowanie kanałów.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wyodrębnianie klatek)
- `imagemagick`/`magick` do przekształcania poszczególnych klatek

Porównywanie różnic między klatkami często przynosi rozstrzygające wyniki:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Kodowanie liczby pikseli w APNG

- Wykryj kontenery APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnij klatki bez zmiany czasu: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Odzyskaj ładunki zakodowane jako liczba pikseli w każdej klatce:

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

Animowane wyzwania mogą kodować każdy bajt jako liczbę pikseli o określonym kolorze w każdej klatce; połączenie tych wartości pozwala odtworzyć wiadomość.<sup>[[1]](#references)</sup>

## Osadzanie chronione hasłem

Jeśli podejrzewasz, że osadzanie jest chronione hasłem, a nie polega na manipulacji na poziomie pikseli, zwykle jest to najszybsza droga.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i umożliwia osadzanie/wyodrębnianie zaszyfrowanych ładunków.

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

## References

- [1] [Flagvent 2025 (średni) — różowy, lista życzeń Świętego Mikołaja, świąteczne metadane, przechwycony szum](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
