# Steganografia obrazowa

{{#include ../../banners/hacktricks-training.md}}

Stego obrazowe w CTF-ach zwykle sprowadza się do jednej z tych kategorii:

- LSB/płaszczyzny bitowe (PNG/BMP)
- Payloady w metadanych/komentarzach
- Nietypowe chunki PNG / naprawa uszkodzeń
- Narzędzia działające w dziedzinie DCT JPEG (OutGuess itp.)
- Techniki oparte na klatkach (GIF/APNG)

## Szybka analiza wstępna

Przed szczegółową analizą zawartości w pierwszej kolejności sprawdź dowody na poziomie kontenera. Zobacz [ogólny workflow stego](../workflow/) dotyczący identyfikacji plików i wycinania danych przed testami specyficznymi dla obrazów.

- Zweryfikuj plik i sprawdź jego strukturę: `file`, `magick identify -verbose`, walidatory formatów (np. `pngcheck`).
- Wyodrębnij metadane i widoczne ciągi znaków: `exiftool -a -u -g1`, `strings`.
- Sprawdź, czy nie ma osadzonych/dodanych danych: `binwalk` i zawartość na końcu pliku (`tail | xxd`).
- Wybierz ścieżkę zależnie od kontenera:
  - PNG/BMP: płaszczyzny bitowe/LSB i anomalie na poziomie chunków.
  - JPEG: metadane oraz narzędzia działające w dziedzinie DCT (rodziny w stylu OutGuess/F5).
  - GIF/APNG: ekstrakcja klatek, porównywanie klatek, sztuczki z paletą.

## Płaszczyzny bitowe / LSB

### Technika

PNG/BMP są popularne w CTF-ach, ponieważ przechowują piksele w sposób ułatwiający **manipulowanie na poziomie bitów**. Klasyczny mechanizm ukrywania/wyodrębniania danych polega na tym, że:

- Każdy kanał piksela (R/G/B/A) ma wiele bitów.
- **Najmniej znaczący bit** (LSB) każdego kanału zmienia obraz w niewielkim stopniu.
- Atakujący ukrywają dane w tych najmniej znaczących bitach, czasem stosując krok, permutację lub wybór konkretnego kanału.

Czego można się spodziewać w zadaniach:

- Payload znajduje się tylko w jednym kanale (np. LSB kanału `R`).
- Payload znajduje się w kanale alfa.
- Payload po wyodrębnieniu jest skompresowany/zakodowany.
- Wiadomość jest rozłożona na płaszczyznach lub ukryta przez XOR między płaszczyznami.

Inne spotykane rodziny technik (zależne od implementacji):

- **LSB matching** (zamiast tylko odwracać bit, stosuje korekty +/-1, aby uzyskać docelowy bit)
- **Ukrywanie oparte na palecie/indeksach** (indeksowane PNG/GIF: payload jest ukryty w indeksach kolorów, a nie w surowych wartościach RGB)
- **Payloady tylko w kanale alfa** (całkowicie niewidoczne w widoku RGB)

### Indeksy palety kolorów indeksowanych

Indeksowany PNG lub GIF przechowuje dla każdego piksela **indeks** palety, a nie trójkę RGB. Dwa indeksy mogą wskazywać ten sam widoczny kolor, więc konwersja do RGB przed analizą może usunąć ukryte różnice. Sprawdź, czy paleta zawiera zduplikowane lub niemal identyczne wpisy, a następnie wygeneruj binarną maskę pikseli używających każdego podejrzanego indeksu. Ta metoda pozwoliła wykryć ukryty tekst i zmiany w kodach QR w niedawnych zadaniach z GIF-ami.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

W przypadku jednoklatkowego indeksowanego PNG (lub **pierwszej klatki** GIF-a) zachowaj tryb `P` w Pillow i zmień `target` na interesujący indeks wskazany przez skrypt. Przy wyborze indeksów sprawdź przezroczystość (`tRNS` lub indeks przezroczystości GIF-a), a także RGB.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

W przypadku animowanych GIF-ów analizuj klatki osobno. Pillow zwykle konwertuje późniejsze klatki do RGB/RGBA podczas kompozytowania; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` zachowuje tryb `P` tylko wtedy, gdy paleta się nie zmienia. Jeśli klatka ma lokalną paletę lub została już skompozytowana, sprawdź jej oryginalne dane klatki z indeksami zamiast traktować piksele przekonwertowane do RGB jako indeksy.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Narzędzia

#### zsteg

`zsteg` wylicza wiele wzorców ekstrakcji LSB/płaszczyzn bitowych dla PNG/BMP:

```bash
zsteg -a file.png
```

Repozytorium: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: uruchamia zestaw transformacji (metadane, transformacje obrazu, brute force wariantów LSB).
- `stegsolve`: ręczne filtry wizualne (izolowanie kanałów, inspekcja płaszczyzn, XOR itd.).

Pobieranie Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Sztuczki zwiększające widoczność oparte na FFT

FFT nie służy do ekstrakcji LSB; używa się jej w przypadkach, gdy zawartość jest celowo ukryta w przestrzeni częstotliwości lub subtelnych wzorach.

- Demo EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Narzędzia internetowe często używane do wstępnej analizy w CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Wewnętrzna struktura PNG: chunki, uszkodzenia i ukryte dane

### Technika

PNG to format oparty na chunkach. W wielu wyzwaniach payload jest przechowywany na poziomie kontenera/chunków, a nie w wartościach pikseli:

- **Dodatkowe bajty za `IEND`** (wiele przeglądarek ignoruje końcowe bajty)
- **Niestandardowe chunki pomocnicze** zawierające payloady; zobacz [workflow przeglądania chunków PNG i wyodrębniania danych](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Uszkodzone nagłówki**, które ukrywają wymiary lub uniemożliwiają parserom przetwarzanie do czasu ich naprawy

Warto sprawdzić chunki o dużym prawdopodobieństwie zawierania danych:

- `tEXt` / `iTXt` / `zTXt` (metadane tekstowe, czasem skompresowane)
- `iCCP` (profil ICC) i inne chunki pomocnicze użyte jako nośnik
- `eXIf` (dane EXIF w PNG)

### Bajty filtrów linii skanowania PNG jako nośnik

PNG przechowuje jeden bajt typu filtra (0–4) przed każdą linią skanowania w zdekompresowanym strumieniu `IDAT`. Te bajty nie są wartościami pikseli; zdekodowane piksele RGB nie zachowują oryginalnych wyborów filtrów, a ponowne kodowanie może je zmienić. Koder może zgodnie ze specyfikacją zmieniać filtry, ale celowe wzory mogą kodować krótką wiadomość; w niedawnym wyzwaniu wartości filtrów 1–4 reprezentowały symbole dwubitowe. Sprawdź **oryginalny plik** i połącz wszystkie dane `IDAT` przed dekompresją. W przypadku poniższych obrazów RGB/RGBA bez przeplotu, 8-bitowych, stride wynosi szerokość pomnożoną przez liczbę kanałów; obrazy Adam7 wymagają szerokości linii skanowania dla poszczególnych przebiegów.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Wyświetlanie bajtów filtrów linii skanowania PNG bez ponownego kodowania</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

</details>

Uruchom polecenie `python3 filters.py suspect.png`. Sprawdź, czy sekwencja filtrów — a nie zdekodowane piksele — odpowiada wiarygodnemu mapowaniu symboli. Wybór mapowania zależy od konkretnego wyzwania; sama zmienność nie jest dowodem na steganografię.<sup>[[3]](#references)[[7]](#references)</sup>

### Polecenia do wstępnej analizy

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Na co zwrócić uwagę:

- Nietypowe kombinacje szerokości/wysokości/głębi bitowej/typu koloru
- Błędy CRC/chunków (pngcheck zwykle wskazuje dokładny offset)
- Ostrzeżenia o dodatkowych danych po `IEND`

Jeśli potrzebujesz dokładniejszego podglądu chunków:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Przydatne materiały:

- Specyfikacja PNG (struktura, chunki): https://www.w3.org/TR/PNG/
- Sztuczki dotyczące formatów plików (przypadki brzegowe PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadane, narzędzia w dziedzinie DCT i ograniczenia ELA

### Technika

JPEG nie jest przechowywany jako surowe piksele — jest kompresowany w dziedzinie DCT. Dlatego narzędzia stego dla JPEG różnią się od narzędzi LSB dla PNG:

- Ładunki w metadanych i komentarzach są na poziomie pliku (łatwe do wykrycia i szybkiego sprawdzenia)
- Narzędzia stego działające w dziedzinie DCT osadzają bity we współczynnikach częstotliwości

W praktyce traktuj JPEG jako:

- Kontener na segmenty metadanych (łatwe do wykrycia i szybkiego sprawdzenia)
- Skompresowaną domenę sygnału (współczynniki DCT), w której działają wyspecjalizowane narzędzia stego

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

Jeśli masz do czynienia konkretnie z ładunkami steghide w plikach JPEG, rozważ użycie `stegseek` (szybszy bruteforce niż starsze skrypty):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA wyróżnia różne artefakty ponownej kompresji; może wskazać obszary, które były edytowane, ale sam w sobie nie wykrywa stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Obrazy animowane

### Technika

W przypadku obrazów animowanych załóż, że wiadomość jest:

- W pojedynczej klatce (łatwo ją znaleźć), lub
- Rozłożona na wielu klatkach (kolejność ma znaczenie), lub
- Widoczna tylko po porównaniu kolejnych klatek

### Wyodrębnianie klatek

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Następnie traktuj klatki jak zwykłe pliki PNG: `zsteg`, `pngcheck`, izolowanie kanałów.

Alternatywne narzędzia:

- `gifsicle --explode anim.gif` (szybkie wyodrębnianie klatek)
- `imagemagick`/`magick` do przekształcania poszczególnych klatek

Porównywanie klatek często daje rozstrzygające wyniki:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Kodowanie liczby pikseli w APNG

- Wykryj kontenery APNG: `exiftool -a -G1 file.png | grep -i animation` lub `file`.
- Wyodrębnij klatki bez zmiany czasu ich wyświetlania: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Animowane zagadki mogą kodować każdy bajt jako liczbę pikseli o określonym kolorze w każdej klatce; połączenie tych wartości odtwarza wiadomość.<sup>[[1]](#references)</sup>

## Osadzanie chronione hasłem

Jeśli podejrzewasz, że osadzona zawartość jest chroniona hasłem, a nie ukryta przez manipulację pikselami, to zazwyczaj najszybsza metoda.

### steghide

Obsługuje formaty `JPEG, BMP, WAV, AU` i umożliwia osadzanie oraz wyodrębnianie zaszyfrowanych danych.

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





## References

- [1] [Flagvent 2025 (Medium) — różowy, lista życzeń Świętego Mikołaja, świąteczne metadane, przechwycony szum](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [write-up HackVent 2024 — Skręcone kolory](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Specyfikacja Portable Network Graphics (PNG), wydanie trzecie](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Głęboko pod wodą coś się kryje](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Formaty plików graficznych Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Specyfikacja GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protokół powidoku — write-up CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
