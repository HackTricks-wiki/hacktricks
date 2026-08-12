# Przepływ pracy Stego

{{#include ../../banners/hacktricks-training.md}}

Większość problemów ze Stego można rozwiązać szybciej dzięki systematycznemu triage niż przez losowe wypróbowywanie narzędzi.

## Główny przebieg

### Lista kontrolna szybkiego triage

Celem jest sprawne uzyskanie odpowiedzi na dwa pytania:

1. Jaki jest rzeczywisty kontener/format?
2. Czy payload znajduje się w metadanych, dołączonych bajtach, osadzonych plikach czy w stego na poziomie treści?

#### 1) Zidentyfikuj kontener
```bash
file target
ls -lah target
```
Jeśli `file` i rozszerzenie są ze sobą niezgodne, sprawdź sygnaturę zamiast ufać przyrostkowi. `file` również opiera się na heurystyce i może zostać zmyślone przez niepoprawne lub poliglotyczne dane wejściowe. W razie potrzeby traktuj popularne formaty jako kontenery (na przykład dokumenty OOXML są pakietami ZIP).<sup>[[2]](#references)</sup>

#### 2) Sprawdź metadane i oczywiste ciągi znaków
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Wypróbuj wiele kodowań:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Sprawdź dołączone dane / osadzone pliki
```bash
binwalk target
binwalk -e target
```
Jeśli ekstrakcja się nie powiedzie, ale zostaną zgłoszone sygnatury, ręcznie wytnij offsety za pomocą `dd`, a następnie ponownie uruchom `file` dla wyciętego regionu.

#### 4) Jeśli obraz

- Sprawdź anomalie: `magick identify -verbose file`
- Jeśli PNG/BMP, wylicz bit-planes/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy zawartość może zostać ujawniona przez transformacje kanałów/bit-planes

#### 5) Jeśli audio

- Najpierw spektrogram (Sonic Visualiser)
- Dekoduj/sprawdź strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli audio przypomina ustrukturyzowane tony, przetestuj dekodowanie DTMF

### Podstawowe narzędzia

Wykrywają one częste przypadki na poziomie kontenera: payloady w metadanych, dołączone bajty oraz osadzone pliki ukryte za pomocą rozszerzenia.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

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
### Kontenery, dołączone dane i techniki polyglot

Wiele wyzwań ze steganografii polega na dodatkowych bajtach znajdujących się za prawidłowym plikiem lub na osadzonych archiwach ukrytych pod innym rozszerzeniem.

#### Dołączone payloady

Wiele formatów ignoruje końcowe bajty. Do kontenera obrazu/audio można dołączyć ZIP/PDF/skrypt.

Szybkie sprawdzenia:
```bash
binwalk file
tail -c 200 file | xxd
```
Jeśli znasz offset, użyj `dd` do carvingu:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Gdy `file` nie może rozpoznać pliku, wyszukaj magic bytes za pomocą `xxd` i porównaj je ze znanymi sygnaturami:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Wypróbuj `7z` i `unzip`, nawet jeśli rozszerzenie nie wskazuje na format zip:
```bash
7z l file
unzip -l file
```
### Osobliwości związane ze stego

Szybkie odnośniki do wzorców, które regularnie pojawiają się obok stego (QR z danych binarnych, brajl itp.).

#### Kody QR z danych binarnych

Jeśli długość blobu jest pełnym kwadratem, może on zawierać surowe piksele obrazu/QR.
```python
import math
math.isqrt(2500)  # 50
```
Pomocnik binary-to-image:

- Pomocnik dCode binary-image.<sup>[[5]](#references)</sup>

#### Braille

- Tłumacz Braille firmy Branah.<sup>[[6]](#references)</sup>

Szersze zestawy narzędzi steganograficznych i zasoby dotyczące konkretnych technik znajdziesz w dołączonym stego-toolkit oraz na wyselekcjonowanej liście 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Obraz Docker z najpopularniejszymi narzędziami steganograficznymi](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Konwencje ECMA-376 dotyczące pakowania Open Packaging](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Obraz binarny](https://www.dcode.fr/binary-image)
- [6] [Branah — Tłumacz Braille'a](https://www.branah.com/braille-translator)
- [7] [0xRick - Zasoby dotyczące steganografii](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
