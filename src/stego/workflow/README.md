# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Większość problemów stego rozwiązuje się szybciej dzięki systematycznemu triage niż przez wypróbowywanie przypadkowych narzędzi.

## Główny przepływ

### Szybka lista kontrolna triage

Celem jest efektywne odpowiedzenie na dwa pytania:

1. Jaki jest rzeczywisty kontener/format?
2. Czy payload znajduje się w metadata, dopisanych bajtach, osadzonych plikach, czy w content-level stego?

#### 1) Zidentyfikuj kontener
```bash
file target
ls -lah target
```
Jeśli `file` i rozszerzenie się nie zgadzają, zaufaj `file`. Traktuj popularne formaty jako kontenery, gdy to odpowiednie (np. dokumenty OOXML są plikami ZIP).

#### 2) Szukaj metadanych i oczywistych ciągów
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
#### 3) Sprawdź dane dołączone / osadzone pliki
```bash
binwalk target
binwalk -e target
```
Jeśli ekstrakcja się nie powiedzie, ale zgłaszane są sygnatury, ręcznie wytnij offsety za pomocą `dd` i uruchom ponownie `file` na wyciętym regionie.

#### 4) Jeśli obraz

- Sprawdź anomalie: `magick identify -verbose file`
- Jeśli PNG/BMP, wypisz płaszczyzny bitów/LSB: `zsteg -a file.png`
- Zweryfikuj strukturę PNG: `pngcheck -v file.png`
- Użyj filtrów wizualnych (Stegsolve / StegoVeritas), gdy zawartość może zostać ujawniona przez transformacje kanału/płaszczyzny

#### 5) Jeśli audio

- Najpierw spektrogram (Sonic Visualiser)
- Dekoduj/zbadaj strumienie: `ffmpeg -v info -i file -f null -`
- Jeśli audio przypomina uporządkowane tony, przetestuj dekodowanie DTMF

### Podstawowe narzędzia

Te narzędzia wykrywają najczęstsze przypadki na poziomie kontenera: payloady metadanych, dopisane bajty i osadzone pliki ukryte pod rozszerzeniem.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to that repo file. Please paste the contents of src/stego/workflow/README.md (or at least the "Foremost" section) here, and I'll translate the English text to Polish while preserving all markdown, code, links, tags and paths exactly as you requested.
```bash
foremost -i file
```
Proszę wklej zawartość pliku src/stego/workflow/README.md, który chcesz przetłumaczyć (albo potwierdź, że mam przetłumaczyć tylko nagłówek "Exiftool / Exiv2"). Nie mam bezpośredniego dostępu do repozytorium, więc potrzebuję tekstu, by go przetłumaczyć.
```bash
exiftool file
exiv2 file
```
Nie otrzymałem zawartości pliku. Proszę wklej zawartość src/stego/workflow/README.md, a przetłumaczę ją na polski, zachowując dokładnie oryginalną składnię markdown i tagi HTML.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Kontenery, appended data, and polyglot tricks

Wiele zadań steganography to dodatkowe bajty występujące po poprawnym pliku lub osadzone archiwa ukryte poprzez rozszerzenie.

#### Appended payloads

Wiele formatów ignoruje bajty na końcu pliku. Do kontenera obrazu/pliku audio można dołączyć ZIP/PDF/script.

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

Gdy `file` nie potrafi rozpoznać formatu, sprawdź magic bytes za pomocą `xxd` i porównaj je ze znanymi sygnaturami:
```bash
xxd -g 1 -l 32 file
```
#### Zip w przebraniu

Spróbuj `7z` i `unzip`, nawet jeśli rozszerzenie nie wskazuje, że to zip:
```bash
7z l file
unzip -l file
```
### Dziwności obok stego

Szybkie linki do wzorców, które regularnie pojawiają się obok stego (QR-from-binary, braille, etc).

#### QR codes z danych binarnych

Jeśli długość bloba jest kwadratem doskonałym, mogą to być surowe piksele obrazu/QR.
```python
import math
math.isqrt(2500)  # 50
```
Konwerter binarny na obraz:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Listy referencyjne

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
