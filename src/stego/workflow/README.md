# Workflow stego

{{#include ../../banners/hacktricks-training.md}}

Większość problemów ze stego rozwiązuje się szybciej dzięki systematycznej wstępnej analizie niż przez przypadkowe wypróbowywanie narzędzi.

## Główny przebieg

### Szybka lista kontrolna wstępnej analizy

Celem jest sprawne znalezienie odpowiedzi na dwa pytania:

1. Jaki jest rzeczywisty kontener/format?
2. Czy payload znajduje się w metadanych, dołączonych bajtach, osadzonych plikach czy stego na poziomie treści?

#### 1) Zidentyfikuj kontener

```bash
file target
ls -lah target
```

Jeśli `file` i rozszerzenie są niezgodne, sprawdź sygnaturę zamiast ufać rozszerzeniu. `file` opiera się na heurystykach i może dać się zmylić nieprawidłowym lub poliglotycznym wejściem. W razie potrzeby traktuj popularne formaty jako kontenery (na przykład dokumenty OOXML są pakietami ZIP).<sup>[[2]](#references)</sup>

#### 2) Poszukaj metadanych i oczywistych ciągów znaków

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Wypróbuj różne kodowania:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Sprawdź, czy dołączono dane / osadzone pliki

```bash
binwalk target
binwalk -e target
```

Jeśli ekstrakcja się nie powiedzie, ale zostaną zgłoszone sygnatury, ręcznie wytnij dane z odpowiednich offsetów za pomocą `dd` i ponownie uruchom `file` na wyciętym fragmencie.

#### 4) Jeśli to obraz

- Sprawdź anomalie: `magick identify -verbose file`
- Jeśli to PNG/BMP, wylicz bit-plane/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy treść może zostać ujawniona przez transformacje kanałów/bit-plane

#### 5) Jeśli to dźwięk

- Najpierw spektrogram (Sonic Visualiser)
- Dekoduj/sprawdzaj strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli dźwięk przypomina uporządkowane tony, przetestuj dekodowanie DTMF

### Podstawowe narzędzia

Pozwalają wykryć najczęstsze przypadki na poziomie kontenera: payloady w metadanych, dopisane bajty i osadzone pliki ukryte pod innym rozszerzeniem.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

#### Foremost

```bash
foremost -i file
```

Repozytorium projektu: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### plik / ciągi znaków

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Kontenery, dołączone dane i sztuczki poliglotyczne

W wielu zadaniach steganograficznych ukryte dane znajdują się w dodatkowych bajtach za poprawnym plikiem albo w osadzonych archiwach zamaskowanych przez zmianę rozszerzenia.

#### Dołączone dane

Wiele formatów ignoruje końcowe bajty. Plik ZIP/PDF/skrypt można dołączyć do kontenera obrazu lub dźwięku.

Szybkie kontrole:

```bash
binwalk file
tail -c 200 file | xxd
```

Jeśli znasz offset, wyodrębnij dane za pomocą `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Bajty magiczne

Gdy `file` ma problem z rozpoznaniem pliku, sprawdź bajty magiczne za pomocą `xxd` i porównaj je ze znanymi sygnaturami:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Spróbuj 7z i unzip, nawet jeśli rozszerzenie nie wskazuje na ZIP:

```bash
7z l file
unzip -l file
```

### Dziwne przypadki w pobliżu stego

Szybkie linki do wzorców, które często pojawiają się obok stego (QR z danych binarnych, brajl itd.).

#### Kody QR z danych binarnych

Jeśli długość bloba jest kwadratem liczby całkowitej, może zawierać surowe piksele obrazu/kodu QR.

```python
import math
math.isqrt(2500)  # 50
```

Pomocnik do konwersji binarnej na obraz:

- Pomocnik dCode do konwersji binarnej na obraz.<sup>[[5]](#references)</sup>

#### Braille

- Tłumacz Braille’a Branah.<sup>[[6]](#references)</sup>

Więcej zestawów narzędzi steganograficznych i zasobów dotyczących konkretnych technik znajdziesz w dołączonym zestawie stego-toolkit oraz na wyselekcjonowanej liście 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit — Obraz Docker zawierający najpopularniejsze narzędzia steganograficzne](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston i in. — Konwencje otwartego pakowania ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Obraz binarny](https://www.dcode.fr/binary-image)
- [6] [Branah — Tłumacz Braille’a](https://www.branah.com/braille-translator)
- [7] [0xRick — Zasoby dotyczące steganografii](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
