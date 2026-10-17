# Steganografia obrazów

{{#include ../../banners/hacktricks-training.md}}

Większość steganografii obrazów w CTF sprowadza się do jednego z tych typów:

- LSB/bit-planes (PNG/BMP)
- Payloady w metadanych/komentarzach
- Nietypowe chunki PNG / naprawa uszkodzeń
- Narzędzia działające w domenie DCT JPEG (OutGuess itp.)
- Ukrywanie danych w klatkach (GIF/APNG)

## Wstępna analiza

Przed szczegółową analizą treści sprawdź dowody na poziomie kontenera:

- Zweryfikuj plik i sprawdź jego strukturę: `file`, `magick identify -verbose`, narzędzia do walidacji formatów (np. `pngcheck`).
- Wyodrębnij metadane i widoczne ciągi znaków: `exiftool -a -u -g1`, `strings`.
- Sprawdź, czy plik zawiera osadzone lub dopisane dane: `binwalk` i analizę końca pliku (`tail | xxd`).
- Wybierz dalszą analizę zależnie od kontenera:
  - PNG/BMP: bit-planes/LSB i anomalie na poziomie chunków.
  - JPEG: metadane i narzędzia działające w domenie DCT (rodziny narzędzi w stylu OutGuess/F5).
  - GIF/APNG: wyodrębnianie klatek, porównywanie klatek i sztuczki z paletą.

## Bit-planes / LSB

### Technika

PNG/BMP są popularne w CTF, ponieważ zapis pikseli ułatwia **manipulację na poziomie bitów**. Klasyczna metoda ukrywania/wyodrębniania danych polega na tym, że:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **Najmniej znaczący bit** (LSB) każdego kanału prawie nie zmienia wyglądu obrazu.
- Atakujący ukrywają dane w bitach o niskiej wadze, czasem stosując krok, permutację lub wybór kanału.

Czego można się spodziewać w zadaniach:

- Payload znajduje się tylko w jednym kanale (np. w LSB kanału `R`).
- Payload znajduje się w kanale alfa.
- Payload jest kompresowany/kodowany po wyodrębnieniu.
- Wiadomość jest rozłożona na kilku płaszczyznach bitowych lub ukryta za pomocą XOR między płaszczyznami.

Inne rodziny metod, na które możesz się natknąć (zależne od implementacji):

- **LSB matching** (zamiast tylko odwracać bit, stosuje korektę +/-1, aby uzyskać docelowy bit)
- **Ukrywanie oparte na palecie/indeksach** (indeksowane PNG/GIF: payload jest ukryty w indeksach kolorów, a nie w surowych wartościach RGB)
- **Payloady wyłącznie w kanale alfa** (całkowicie niewidoczne w widoku RGB)

### Narzędzia

#### zsteg

`zsteg` wylicza wiele wzorców wyodrębniania LSB/bit-planes dla PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, transformacje obrazu, brute forcing wariantów LSB).
- `stegsolve`: ręczne filtry wizualne (izolowanie kanałów, inspekcja płaszczyzn, XOR itd.).

Pobieranie Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Sztuczki zwiększające widoczność oparte na FFT

FFT nie służy do ekstrakcji LSB; przydaje się w przypadkach, gdy zawartość jest celowo ukryta w przestrzeni częstotliwości lub subtelnych wzorach.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Narzędzia internetowe do wstępnej analizy, często używane w CTF-ach:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wewnętrzna struktura PNG: chunki, uszkodzenia i ukryte dane

### Technika

PNG to format oparty na chunkach. W wielu zadaniach payload jest przechowywany na poziomie kontenera/chunków, a nie w wartościach pikseli:

- **Dodatkowe bajty za `IEND`** (wiele przeglądarek ignoruje końcowe bajty)
- **Niestandardowe chunki pomocnicze** zawierające payloady; zobacz [procedurę przeglądania chunków PNG i carvingu](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Uszkodzone nagłówki**, które ukrywają wymiary lub powodują błędy parserów, dopóki nie zostaną naprawione

Najważniejsze lokalizacje chunków do sprawdzenia:

- `tEXt` / `iTXt` / `zTXt` (metadane tekstowe, czasem skompresowane)
- `iCCP` (profil ICC) i inne chunki pomocnicze używane jako nośnik
- `eXIf` (dane EXIF w PNG)

### Polecenia do wstępnej analizy

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Czego szukać:

- Nietypowych kombinacji szerokości/wysokości/głębi bitowej/typu koloru
- Błędów CRC/chunk (pngcheck zwykle wskazuje dokładny offset)
- Ostrzeżeń o dodatkowych danych po `IEND`

Jeśli potrzebujesz dokładniejszego widoku chunków:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Przydatne materiały:

- Specyfikacja PNG (struktura, chunki): https://www.w3.org/TR/PNG/
- Sztuczki związane z formatami plików (przypadki brzegowe PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadane, narzędzia działające w domenie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele; jest kompresowany w domenie DCT. Dlatego narzędzia steganograficzne dla JPEG różnią się od narzędzi LSB dla PNG:

- Ładunki w metadanych i komentarzach są na poziomie pliku (łatwe do wykrycia i szybkiego sprawdzenia)
- Narzędzia steganograficzne działające w domenie DCT osadzają bity we współczynnikach częstotliwości

W praktyce traktuj JPEG jako:

- Kontener na segmenty metadanych (łatwe do wykrycia i szybkiego sprawdzenia)
- Skompresowaną domenę sygnału (współczynniki DCT), w której działają specjalistyczne narzędzia steganograficzne

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

Jeśli masz do czynienia konkretnie z payloadami steghide w plikach JPEG, rozważ użycie `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

## Error Level Analysis

ELA uwydatnia różnice w artefaktach ponownej kompresji; może wskazać obszary, które były edytowane, ale sama w sobie nie wykrywa stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

W przypadku obrazów animowanych załóż, że wiadomość jest:

- W pojedynczej klatce (łatwo), lub
- Rozłożona na wiele klatek (kolejność ma znaczenie), lub
- Widoczna tylko po wykonaniu diff kolejnych klatek

### Wyodrębnianie klatek

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, izolacja kanałów.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wyodrębnianie klatek)
- `imagemagick`/`magick` do przekształcania poszczególnych klatek

Porównywanie różnic między klatkami często daje rozstrzygające wyniki:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Kodowanie liczby pikseli w APNG

- Wykryj kontenery APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnij klatki bez zmiany ich czasu: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Odzyskaj payloady zakodowane jako liczba pikseli w każdej klatce:

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

Animowane wyzwania mogą kodować każdy bajt jako liczbę pikseli o określonym kolorze w każdej klatce; połączenie tych liczb pozwala odtworzyć wiadomość.<sup>[[1]](#references)</sup>

## Osadzanie chronione hasłem

Jeśli podejrzewasz, że osadzanie jest chronione hasłem, a nie wykorzystuje manipulacji na poziomie pikseli, zwykle jest to najszybsza droga.

### steghide

Obsługuje `JPEG, BMP, WAV, AU` i umożliwia osadzanie oraz wyodrębnianie zaszyfrowanych ładunków.

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

- [1] [Flagvent 2025 (Medium) — róż, lista życzeń Świętego Mikołaja, świąteczne metadane, przechwycony szum](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
