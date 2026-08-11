# Stego-werkvloei

{{#include ../../banners/hacktricks-training.md}}

Die meeste stego-probleme word vinniger deur sistematiese triage opgelos as deur lukrake tools te probeer.

## Kernvloei

### Kontrolelys vir vinnige triage

Die doel is om twee vrae doeltreffend te beantwoord:

1. Wat is die werklike container/format?
2. Is die payload in metadata, appended bytes, embedded files, of content-level stego?

#### 1) Identifiseer die container
```bash
file target
ls -lah target
```
Indien `file` en die uitbreiding nie ooreenstem nie, ondersoek die signature eerder as om die suffix te vertrou. `file` is ook heuristies en kan deur misvormde of polyglot-invoer mislei word. Behandel algemene formate as containers waar toepaslik (byvoorbeeld, OOXML-dokumente is ZIP-packages).<sup>[[2]](#references)</sup>

#### 2) Soek metadata en ooglopende stringe
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Probeer veelvuldige enkoderings:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Kontroleer vir bygevoegde data / ingebedde lêers
```bash
binwalk target
binwalk -e target
```
If extraction misluk maar signatures gerapporteer word, carve offsets handmatig met `dd` en voer `file` weer op die gecarvde area uit.

#### 4) Indien beeld

- Inspekteer anomalieë: `magick identify -verbose file`
- Indien PNG/BMP, lys bit-planes/LSB: `zsteg -a file.png`
- Valideer PNG-struktuur: `pngcheck -v file.png`
- Gebruik visuele filters (Stegsolve / StegoVeritas) wanneer inhoud deur channel/plane-transformasies onthul kan word

#### 5) Indien audio

- Spectrogram eerste (Sonic Visualiser)
- Decodeer/inspekteer streams: `ffmpeg -v info -i file -f null -`
- Indien die audio soos gestruktureerde tone klink, toets DTMF decoding

### Basiese tools

Hierdie vang algemene container-level-gevalle op: metadata payloads, bygevoegde bytes en embedded files wat deur ’n uitbreiding vermom word.<sup>[[1]](#references)[[3]](#references)</sup>

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
Projekbewaarplek: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### lêer / stringe
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, aangehegte data en polyglot-truuks

Baie steganografie-uitdagings bestaan uit ekstra grepe ná ’n geldige lêer, of ingebedde argiewe wat deur die uitbreiding vermom word.

#### Aangehegte payloads

Baie formate ignoreer agteraanliggende grepe. ’n ZIP/PDF/script kan aan ’n beeld-/klankcontainer aangeheg word.

Vinnige kontroles:
```bash
binwalk file
tail -c 200 file | xxd
```
As jy ’n offset ken, carve met `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Wanneer `file` verward is, soek met `xxd` na magic bytes en vergelyk dit met bekende handtekeninge:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Probeer `7z` en `unzip` selfs al dui die uitbreiding nie op zip nie:
```bash
7z l file
unzip -l file
```
### Nabygeleë stego-eienaardighede

Vinnige skakels vir patrone wat gereeld langs stego voorkom (QR vanaf binêr, braille, ens.).

#### QR-kodes vanaf binêr

As ’n blob-lengte ’n volmaakte kwadraat is, kan dit rou pixels vir ’n image/QR wees.
```python
import math
math.isqrt(2500)  # 50
```
Binary-to-image helper:

- dCode binary-image helper.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille translator.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image met die gewildste steganography-tools saamgebundel](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Open Packaging Conventions](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binary Image](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille Translator](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
