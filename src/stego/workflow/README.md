# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Większość problemów stego rozwiązuje się szybciej dzięki systematycznemu triage niż przez próbowanie losowych narzędzi.

## Core flow

### Quick triage checklist

Celem jest szybkie odpowiedzenie na dwa pytania:

1. Jaki jest rzeczywisty container/format?
2. Czy payload znajduje się w metadata, appended bytes, embedded files, czy w content-level stego?

#### 1) Zidentyfikuj container
```bash
file target
ls -lah target
```
Jeśli `file` i rozszerzenie się nie zgadzają, zaufaj `file`. Traktuj popularne formaty jako kontenery, gdy to stosowne (np. dokumenty OOXML są plikami ZIP).

#### 2) Szukaj metadanych i oczywistych ciągów znaków
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Spróbuj różnych kodowań:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Sprawdź dopisane dane / osadzone pliki
```bash
binwalk target
binwalk -e target
```
Jeśli ekstrakcja się nie powiedzie, ale pojawią się sygnatury, ręcznie wycinaj offsety za pomocą `dd` i ponownie uruchom `file` na wyciętym regionie.

#### 4) Jeśli obraz

- Zbadaj anomalie: `magick identify -verbose file`
- Jeśli PNG/BMP, wypisz płaszczyzny bitowe/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy zawartość może być ujawniona przez przekształcenia kanałów/płaszczyzn

#### 5) Jeśli audio

- Najpierw spektrogram (Sonic Visualiser)
- Dekoduj/przeanalizuj strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli audio przypomina uporządkowane tony, sprawdź dekodowanie DTMF

### Podstawowe narzędzia

Te narzędzia łapią przypadki na poziomie kontenera o wysokiej częstotliwości: metadata payloads, appended bytes, and embedded files disguised by extension.

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
I don't have access to external repos. Please paste the contents of src/stego/workflow/README.md (or the portion you want translated). I'll translate the English text to Polish following your rules.
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Kontenery, dołączone dane i sztuczki polyglot

Wiele steganography challenges polega na dodatkowych bajtach po prawidłowym pliku lub na osadzonych archiwach ukrytych przez rozszerzenie.

#### Dołączone payloady

Wiele formatów ignoruje końcowe bajty. Do kontenera obrazu/dźwięku można dołączyć ZIP/PDF/script.

Szybkie sprawdzenia:
```bash
binwalk file
tail -c 200 file | xxd
```
Jeśli znasz offset, carve za pomocą `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magiczne bajty

Gdy `file` nie potrafi określić typu, poszukaj magicznych bajtów za pomocą `xxd` i porównaj ze znanymi sygnaturami:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Spróbuj `7z` i `unzip`, nawet jeśli rozszerzenie nie wskazuje zip:
```bash
7z l file
unzip -l file
```
### Near-stego dziwności

Szybkie linki do wzorców, które regularnie pojawiają się obok stego (QR-from-binary, braille, etc).

#### QR codes from binary

Jeśli długość bloba jest kwadratem liczby całkowitej, może to być surowe piksele obrazu/QR.
```python
import math
math.isqrt(2500)  # 50
```
Narzędzie do konwersji binarnego na obraz:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Listy referencyjne

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
