# Stego-werkvloei

{{#include ../../banners/hacktricks-training.md}}

Die meeste stego-probleme word vinniger opgelos met sistematiese triage as deur lukrake nutsmiddels te probeer.

## Kernvloei

### Vinnige triage-kontrolelys

Die doel is om twee vrae doeltreffend te beantwoord:

1. Wat is die werklike houer/formaat?
2. Is die payload in metadata, bygevoegde grepe, ingebedde lêers of inhoudsvlak-stego?

#### 1) Identifiseer die houer

```bash
file target
ls -lah target
```

As `file` en die uitbreiding nie ooreenstem nie, ondersoek die handtekening eerder as om die agtervoegsel te vertrou. `file` is ook heuristies en kan deur misvormde of polyglot-invoer mislei word. Behandel algemene formate waar toepaslik as houers (OOXML-dokumente is byvoorbeeld ZIP-pakkette).<sup>[[2]](#references)</sup>

#### 2) Soek na metadata en duidelike stringe

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

#### 3) Kyk vir bygevoegde data / ingebedde lêers

```bash
binwalk target
binwalk -e target
```

As ekstraksie misluk maar handtekeninge aangemeld word, kerf die offsets handmatig met `dd` uit en voer `file` weer op die uitgekerfde streek uit.

#### 4) As dit ’n beeld is

- Inspekteer afwykings: `magick identify -verbose file`
- As dit PNG/BMP is, lys bit-vlakke/LSB: `zsteg -a file.png`
- Valideer die PNG-struktuur: `pngcheck -v file.png`
- Gebruik visuele filters (Stegsolve / StegoVeritas) wanneer inhoud deur kanaal-/vlak-transformasies onthul kan word

#### 5) As dit oudio is

- Spektrogram eerste (Sonic Visualiser)
- Dekodeer/inspekteer strome: `ffmpeg -v info -i file -f null -`
- As die oudio soos gestruktureerde tone klink, toets DTMF-dekodering

### Basiese gereedskap

Dit vang algemene gevalle op houervlak op: metadata-ladings, aangehegte grepe en ingebedde lêers wat deur ’n lêeruitbreiding vermom word.<sup>[[1]](#references)[[3]](#references)</sup>

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

#### lêer / strings

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Houers, aangehegte data en polyglot-truuks

Baie steganografie-uitdagings behels ekstra grepe ná ’n geldige lêer, of argiewe wat deur hul lêeruitbreiding verbloem word.

#### Aangehegte payloads

Baie formate ignoreer agteraanstaande grepe. ’n ZIP/PDF/script kan aan ’n beeld-/klankhouer geheg word.

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

Wanneer `file` deurmekaar is, soek na magic bytes met `xxd` en vergelyk dit met bekende handtekeninge:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Probeer `7z` en `unzip`, selfs al dui die lêeruitbreiding nie op zip nie:

```bash
7z l file
unzip -l file
```

### Naby-stego-afwykings

Vinnige skakels na patrone wat dikwels langs stego voorkom (QR uit binary, braille, ens.).

#### QR-kodes uit binary

As ’n blob se lengte ’n volmaakte vierkant is, kan dit rou pixels vir ’n beeld/QR wees.

```python
import math
math.isqrt(2500)  # 50
```

Binêr-na-beeld-hulpmiddel:

- dCode binêre-beeld-hulpmiddel.<sup>[[5]](#references)</sup>

#### Braille

- Branah Braille-vertaler.<sup>[[6]](#references)</sup>

Vir breër versamelings steganografie-nutsprogramme en tegniekspesifieke bronne, sien die saamgevoegde stego-toolkit en 0xRick se saamgestelde lys.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker-beeld met die gewildste steganografie-nutsprogramme saamgevoeg](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 Oop Pakketkonvensies](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [korczis/foremost](https://github.com/ReFirmLabs/binwalk)
- [4] [ReFirmLabs/binwalk](https://github.com/korczis/foremost)
- [5] [dCode — Binêre beeld](https://www.dcode.fr/binary-image)
- [6] [Branah — Braille-vertaler](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganografiebronne](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
