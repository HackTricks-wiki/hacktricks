# Stego-werksvloei

{{#include ../../banners/hacktricks-training.md}}

Die meeste stego-probleme word vinniger opgelos deur sistematiese triage as deur lukrake tools te probeer.

## Kernvloei

### Vinnige triage-kontrolelys

Die doel is om twee vrae doeltreffend te beantwoord:

1. Wat is die werklike houer/formaat?
2. Is die payload in metadata, aangehegte grepe, embedded files, of content-level stego?

#### 1) Identifiseer die houer
```bash
file target
ls -lah target
```
As `file` en die uitbreiding nie ooreenstem nie, vertrou `file`. Behandel algemene formate as houers waar toepaslik (bv. OOXML-dokumente is ZIP-lêers).

#### 2) Soek metadata en ooglopende stringe
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Probeer verskeie enkoderings:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Kontroleer vir aangehegte data / ingebedde lêers
```bash
binwalk target
binwalk -e target
```
As extraction misluk maar signatures gerapporteer word, carve offsets handmatig met `dd` en voer `file` weer op die gecarvde streek uit.

#### 4) As beeld

- Inspekteer anomalieë: `magick identify -verbose file`
- As PNG/BMP, enumereer bit-planes/LSB: `zsteg -a file.png`
- Valideer PNG-struktuur: `pngcheck -v file.png`
- Gebruik visuele filters (Stegsolve / StegoVeritas) wanneer inhoud deur kanaal/vlak-transformasies onthul kan word

#### 5) As audio

- Spektrogram eerste (Sonic Visualiser)
- Dekodeer/inspekteer streams: `ffmpeg -v info -i file -f null -`
- As die audio soos gestruktureerde tone klink, toets DTMF-dekodering

### Basiese gereedskap

Hierdie vang die algemene container-vlak-gevalle vas: metadata-payloads, aangehegte grepe en ingebedde lêers wat deur hul uitbreiding vermom word.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### lêer / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Houers, appended data en polyglot-truuks

Baie steganography-uitdagings behels ekstra grepe ná ’n geldige lêer, of embedded archives wat deur hul uitbreiding vermom word.

#### Appended payloads

Baie formate ignoreer trailing bytes. ’n ZIP/PDF/script kan aan ’n image/audio-container appended word.

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

Wanneer `file` onseker is, soek met `xxd` na magic bytes en vergelyk dit met bekende handtekeninge:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Probeer `7z` en `unzip` selfs al dui die uitbreiding nie op zip nie:
```bash
7z l file
unzip -l file
```
### Naby-stego-afwykings

Vinnige skakels vir patrone wat gereeld langs stego voorkom (QR-from-binary, braille, ens.).

#### QR-kodes from binary

As ’n blob-lengte ’n volmaakte vierkant is, kan dit rou pixels vir ’n beeld/QR wees.
```python
import math
math.isqrt(2500)  # 50
```
Binêr-na-beeld-helper:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Verwysings

- [1] [DominicBreuker/stego-toolkit - Docker image met die gewildste steganography-tools saamgebundel](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
