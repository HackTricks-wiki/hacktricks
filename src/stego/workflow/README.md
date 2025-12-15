# Stego Werksvloei

{{#include ../../banners/hacktricks-training.md}}

Die meeste stego-probleme word vinniger opgelos deur sistematiese triage as deur lukrake gereedskap te probeer.

## Kernvloei

### Vinnige triage-kontrolelys

Die doel is om twee vrae doeltreffend te beantwoord:

1. Wat is die werklike houer/formaat?
2. Is die payload in metadata, appended bytes, embedded files, of content-level stego?

#### 1) Identifiseer die houer
```bash
file target
ls -lah target
```
As `file` en die uitbreiding verskil, vertrou `file`. Behandel algemene formate as houers waar toepaslik (bv., OOXML-dokumente is ZIP-lêers).

#### 2) Soek na metadata en ooglopende strings
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Probeer verskeie enkoderinge:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Kontroleer vir aangehegte data / ingebedde lêers
```bash
binwalk target
binwalk -e target
```
As ekstraksie misluk maar handtekeninge gerapporteer word, kap handmatig offsets met `dd` uit en voer weer `file` uit op die uitgekapte streek.

#### 4) As dit 'n beeld is

- Inspekteer anomalieë: `magick identify -verbose file`
- As PNG/BMP, enumereer bit-vlakke/LSB: `zsteg -a file.png`
- Valideer PNG-struktuur: `pngcheck -v file.png`
- Gebruik visuele filters (Stegsolve / StegoVeritas) wanneer inhoud deur kanaal-/vlaktransformasies onthul kan word

#### 5) As dit 'n klanklêer is

- Spektrogram eers (Sonic Visualiser)
- Dekodeer/inspekteer strome: `ffmpeg -v info -i file -f null -`
- As die klank na gestruktureerde tone lyk, toets DTMF-dekodering

### Basiese gereedskap

Hierdie vang die hoë-frekwensie houervlak-gevalle: metadata payloads, aangehegte bytes, en ingeslote lêers wat deur die uitbreiding verskuil is.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I need the contents of src/stego/workflow/README.md to translate. Please paste the file text here (or the sections you want translated).
```bash
foremost -i file
```
#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
Stuur asseblief die inhoud van src/stego/workflow/README.md wat jy wil hê ek moet na Afrikaans vertaal. Ek sal nie code, tags, paths, links of spesifieke tegniese terme vertaal nie.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, appended data, and polyglot tricks

Baie steganography-uitdagings bevat ekstra bytes ná 'n geldige lêer, of ingeslote argiewe vermom deur die uitbreiding.

#### Aangehegte payloads

Baie formate ignoreer agterliggende bytes. 'n ZIP/PDF/script kan aan 'n image/audio container aangeheg word.

Vinnige kontroles:
```bash
binwalk file
tail -c 200 file | xxd
```
As jy 'n offset ken, carve met `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magiese bytes

Wanneer `file` verward is, kyk vir magiese bytes met `xxd` en vergelyk dit met bekende handtekeninge:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-vermomming

Probeer `7z` en `unzip` selfs al sê die uitbreiding nie zip nie:
```bash
7z l file
unzip -l file
```
### Naby-stego eienaardighede

Vinnige skakels na patrone wat gereeld naby stego verskyn (QR-from-binary, braille, ens.).

#### QR-kodes vanaf binary

As die lengte van 'n blob 'n perfekte vierkant is, kan dit rou piksele vir 'n beeld/QR wees.
```python
import math
math.isqrt(2500)  # 50
```
Binêr-naar-beeld helper:

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Verwysingslyste

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
