# Workflow stego

{{#include ../../banners/hacktricks-training.md}}

Większość problemów ze stego rozwiązuje się szybciej dzięki systematycznemu triage niż przez losowe wypróbowywanie narzędzi.

## Główny przebieg

### Lista kontrolna szybkiego triage

Celem jest sprawne uzyskanie odpowiedzi na dwa pytania:

1. Jaki jest rzeczywisty kontener/format?
2. Czy payload znajduje się w metadata, dołączonych bajtach, osadzonych plikach czy w stego na poziomie zawartości?

#### 1) Zidentyfikuj kontener
```bash
file target
ls -lah target
```
Jeśli `file` i rozszerzenie się nie zgadzają, zaufaj `file`. W razie potrzeby traktuj popularne formaty jako kontenery (np. dokumenty OOXML są plikami ZIP).

#### 2) Poszukaj metadanych i oczywistych ciągów znaków
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
Jeśli ekstrakcja się nie powiedzie, ale zostaną zgłoszone sygnatury, ręcznie wytnij offsety za pomocą `dd`, a następnie ponownie uruchom `file` na wyciętym regionie.

#### 4) Jeśli obraz

- Sprawdź anomalie: `magick identify -verbose file`
- Jeśli PNG/BMP, wylicz bit-planes/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy zawartość może zostać ujawniona przez transformacje kanałów/bit-planes

#### 5) Jeśli audio

- Najpierw spectrogram (Sonic Visualiser)
- Dekoduj/sprawdź strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli audio przypomina ustrukturyzowane tony, przetestuj dekodowanie DTMF

### Podstawowe narzędzia

Wykrywają one najczęstsze przypadki na poziomie kontenera: payloady w metadanych, dołączone bajty oraz osadzone pliki zamaskowane przez rozszerzenie.<sup>[[1]](#references)</sup>

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
Repozytorium: https://github.com/korczis/foremost

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

Wiele wyzwań steganograficznych polega na dodatkowych bajtach znajdujących się za poprawnym plikiem lub na osadzonych archiwach ukrytych pod innym rozszerzeniem.

#### Dołączone payloady

Wiele formatów ignoruje końcowe bajty. Do kontenera obrazu/audio można dołączyć ZIP/PDF/skrypt.

Szybkie sprawdzenia:
```bash
binwalk file
tail -c 200 file | xxd
```
Jeśli znasz offset, wyodrębnij za pomocą `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Gdy `file` ma problem z rozpoznaniem pliku, wyszukaj magic bytes za pomocą `xxd` i porównaj je ze znanymi sygnaturami:
```bash
xxd -g 1 -l 32 file
```
#### Zip pod przebraniem

Spróbuj użyć `7z` i `unzip`, nawet jeśli rozszerzenie nie wskazuje na format zip:
```bash
7z l file
unzip -l file
```
### Near-stego oddities

Szybkie linki do wzorców, które regularnie pojawiają się obok stego (QR-from-binary, brajl itd.).

#### QR codes from binary

Jeśli długość bloba jest pełnym kwadratem, może on zawierać surowe piksele obrazu/QR.
```python
import math
math.isqrt(2500)  # 50
```
Pomocnik binary-to-image:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Referencje

- [1] [DominicBreuker/stego-toolkit - Docker image with the most popular steganography tools bundled together](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
