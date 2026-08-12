# Stego Workflow

{{#include ../../banners/hacktricks-training.md}}

Die meeste stego-probleme word vinniger deur sistematiese triage opgelos as deur lukrake tools te probeer.

## Kernvloei

### Vinnige triage-kontrolelys

Die doel is om twee vrae doeltreffend te beantwoord:

1. Wat is die werklike container/formaat?
2. Is die payload in metadata, appended bytes, embedded files, of content-level stego?

#### 1) Identifiseer die container
```bash
file target
ls -lah target
```
As `file` en die uitbreiding nie ooreenstem nie, ondersoek die signature eerder as om die suffix te vertrou. `file` is ook heuristies en kan deur malformed of polyglot input verwar word. Behandel algemene formate as containers wanneer dit gepas is (byvoorbeeld, OOXML-dokumente is ZIP-pakkette).<sup>[[2]](#references)</sup>

#### 2) Soek na metadata en ooglopende strings
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
#### 3) Kontroleer vir aangehegte data / ingebedde lêers
```bash
binwalk target
binwalk -e target
```
As extraction fails but signatures are reported, manually carve offsets with `dd` and re-run `file` on the carved region.

#### 4) As beeld

- Inspect anomalies: `magick identify -verbose file`
- If PNG/BMP, enumerate bit-planes/LSB: `zsteg -a file.png`
- Validate PNG structure: `pngcheck -v file.png`
- Use visual filters (Stegsolve / StegoVeritas) when content may be revealed by channel/plane transforms

#### 5) As oudio

- Spectrogram first (Sonic Visualiser)
- Decode/inspect streams: `ffmpeg -v info -i file -f null -`
- If the audio resembles structured tones, test DTMF decoding

### Basiese gereedskap

These catch high-frequency container-level cases: metadata payloads, appended bytes, and embedded files disguised by extension.<sup>[[1]](#references)[[3]](#references)</sup>

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
### Houers, aangehegte data en polyglot-truuks

Baie steganography-uitdagings bestaan uit ekstra grepe ná ’n geldige lêer, of ingebedde argiewe wat deur ’n uitbreiding versteek word.

#### Aangehegte payloads

Baie formate ignoreer agterblywende grepe. ’n ZIP/PDF/script kan aan ’n image/audio-houer geheg word.

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
#### Magic bytes

Wanneer `file` onseker is, soek na magic bytes met `xxd` en vergelyk dit met bekende handtekeninge:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Probeer `7z` en `unzip`, selfs al dui die uitbreiding nie op zip nie:
```bash
7z l file
unzip -l file
```
### Naby-stego-afwykings

Vinnige skakels vir patrone wat gereeld langs stego voorkom (QR-from-binary, braille, ens.).

#### QR codes from binary

As die lengte van ’n blob ’n volmaakte kwadraat is, kan dit rou pixels vir ’n image/QR wees.
```python
import math
math.isqrt(2500)  # 50
```
Binary-na-beeld-hulpmiddel:

- dCode binary-beeld-hulpmiddel.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille-vertaler.<sup>[[6]](#references)</sup>

Vir breër versamelings van steganography-hulpmiddels en tegniekspesifieke hulpbronne, sien die gebundelde stego-toolkit en 0xRick se saamgestelde lys.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker-beeld met die gewildste steganography-hulpmiddels saamgebundel](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376-konvensies vir oop verpakking](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binêre beeld](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille-vertaler](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganography-hulpbronne](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
