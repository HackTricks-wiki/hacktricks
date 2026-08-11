# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Większość zadań stego można rozwiązać szybciej dzięki systematycznemu triage niż przez losowe wypróbowywanie narzędzi.

## Główny przebieg

### Szybka checklista triage

Celem jest sprawne uzyskanie odpowiedzi na dwa pytania:

1. Jaki jest rzeczywisty kontener/format?
2. Czy payload znajduje się w metadanych, dołączonych bajtach, osadzonych plikach czy w stego na poziomie zawartości?

#### 1) Zidentyfikuj kontener
```bash
file target
ls -lah target
```
Jeśli `file` i rozszerzenie są niezgodne, sprawdź sygnaturę zamiast ufać rozszerzeniu. `file` również działa heurystycznie i może zostać zmy­lony przez uszkodzone dane lub dane polyglot. W razie potrzeby traktuj popularne formaty jako kontenery (na przykład dokumenty OOXML są pakietami ZIP).<sup>[[2]](#references)</sup>

#### 2) Szukaj metadanych i oczywistych ciągów znaków
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
Jeśli ekstrakcja zakończy się niepowodzeniem, ale zostaną zgłoszone sygnatury, ręcznie wytnij offsety za pomocą `dd`, a następnie ponownie uruchom `file` na wyciętym regionie.

#### 4) Jeśli obraz

- Sprawdź anomalie: `magick identify -verbose file`
- Jeśli to PNG/BMP, wylicz bit-plane/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy zawartość może zostać ujawniona przez transformacje kanałów/plane

#### 5) Jeśli audio

- Najpierw wykonaj spektrogram (Sonic Visualiser)
- Dekoduj/sprawdź strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli audio przypomina ustrukturyzowane tony, przetestuj dekodowanie DTMF

### Podstawowe narzędzia

Wykrywają one często spotykane przypadki na poziomie kontenera: payloady w metadanych, dołączone bajty oraz osadzone pliki ukryte przez rozszerzenie.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repozytorium: https://github.com/ReFirmLabs/binwalk

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
### Kontenery, dołączone dane i sztuczki polyglot

Wiele wyzwań ze steganografii polega na dodatkowych bajtach znajdujących się za poprawnym plikiem lub na osadzonych archiwach ukrytych za pomocą rozszerzenia.

#### Dołączone payloady

Wiele formatów ignoruje końcowe bajty. Do kontenera obrazu/audio można dołączyć plik ZIP/PDF/skrypt.

Szybkie sprawdzenia:
```bash
binwalk file
tail -c 200 file | xxd
```
Jeśli znasz przesunięcie, wykonaj carving za pomocą `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Bajty magiczne

Gdy `file` nie potrafi rozpoznać pliku, poszukaj bajtów magicznych za pomocą `xxd` i porównaj je ze znanymi sygnaturami:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Try `7z` and `unzip`, even if the extension doesn’t say zip:
```bash
7z l file
unzip -l file
```
### Osobliwości związane ze stego

Szybkie odnośniki do wzorców, które regularnie pojawiają się obok stego (QR-from-binary, braille itp.).

#### Kody QR z danych binarnych

Jeśli długość bloba jest idealnym kwadratem, może on zawierać surowe piksele obrazu/kodu QR.
```python
import math
math.isqrt(2500)  # 50
```
Pomocnik konwertowania danych binarnych na obraz:

- Pomocnik dCode do konwersji danych binarnych na obraz.<sup>[[5]](#references)</sup>

#### Braille

- Tłumacz alfabetu Braille'a Branah.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Obraz Docker zawierający najpopularniejsze narzędzia do steganografii](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Konwencje ECMA-376 dotyczące pakowania Open Packaging](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Obraz binarny](https://www.dcode.fr/binary-image)
- [6] [Branah — Tłumacz alfabetu Braille'a](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
