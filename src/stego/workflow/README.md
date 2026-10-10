# Stego tok rada

{{#include ../../banners/hacktricks-training.md}}

Većina stego zadataka rešava se brže sistematskom trijažom nego isprobavanjem nasumičnih alata.

## Osnovni tok

### Brza kontrolna lista za trijažu

Cilj je da efikasno odgovorite na dva pitanja:

1. Koji je stvarni kontejner/format?
2. Da li je payload u metapodacima, dodatim bajtovima, ugrađenim datotekama ili stego sadržaju?

#### 1) Identifikujte kontejner

```bash
file target
ls -lah target
```

Ako se `file` i ekstenzija ne podudaraju, proverite potpis umesto da verujete sufiksu. `file` se takođe oslanja na heuristiku i može ga zbuniti neispravan ili poliglotski ulaz. U odgovarajućim slučajevima tretirajte uobičajene formate kao kontejnere (na primer, OOXML dokumenti su ZIP paketi).<sup>[[2]](#references)</sup>

#### 2) Potražite metapodatke i očigledne stringove

```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```

Isprobajte više kodiranja:

```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```

#### 3) Proverite da li postoje naknadno dodati podaci / ugrađene datoteke

```bash
binwalk target
binwalk -e target
```

Ako ekstrakcija ne uspe, ali se prijave potpisi, ručno izdvojite offsete pomoću `dd` i ponovo pokrenite `file` nad izdvojenim regionom.

#### 4) Ako je slika

- Pregledajte anomalije: `magick identify -verbose file`
- Ako je PNG/BMP, ispitajte bit-plane/LSB: `zsteg -a file.png`
- Proverite strukturu PNG-a: `pngcheck -v file.png`
- Koristite vizuelne filtere (Stegsolve / StegoVeritas) ako se sadržaj može otkriti transformacijama kanala/ravni

#### 5) Ako je audio

- Najpre napravite spektrogram (Sonic Visualiser)
- Dekodirajte/pregledajte tokove: `ffmpeg -v info -i file -f null -`
- Ako audio podseća na strukturirane tonove, isprobajte DTMF dekodiranje

### Osnovni alati

Ovi alati otkrivaju česte slučajeve na nivou kontejnera: payload-e u metapodacima, dodate bajtove i ugrađene datoteke prikrivene ekstenzijom.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk

```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```

Repozitorijum: https://github.com/ReFirmLabs/binwalk

#### Foremost

```bash
foremost -i file
```

Repozitorijum projekta: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2

```bash
exiftool file
exiv2 file
```

#### fajl / stringovi

```bash
file file
strings -n 6 file
```

#### cmp

```bash
cmp original.jpg stego.jpg -b -l
```

### Kontejneri, dodati podaci i trikovi s poliglotima

Mnogi steganografski izazovi sadrže dodatne bajtove nakon ispravne datoteke ili ugrađene arhive prikrivene ekstenzijom.

#### Dodati sadržaji

Mnogi formati ignorišu završne bajtove. ZIP/PDF/skripta može se dodati na kraj kontejnera slike/zvuka.

Brze provere:

```bash
binwalk file
tail -c 200 file | xxd
```

Ako znate pomeraj, izdvojite pomoću `dd`:

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Magični bajtovi

Kada je `file` zbunjen, potražite magične bajtove pomoću `xxd` i uporedite ih sa poznatim potpisima:

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Probajte `7z` i `unzip` čak i ako ekstenzija ne ukazuje na ZIP:

```bash
7z l file
unzip -l file
```

### Neobičnosti povezane sa stego

Brze veze ka obrascima koji se često pojavljuju uz stego (QR kodovi iz binarnih podataka, Brajevo pismo itd.).

#### QR kodovi iz binarnih podataka

Ako je dužina blob-a savršen kvadrat, možda je reč o sirovim pikselima slike/QR koda.

```python
import math
math.isqrt(2500)  # 50
```

Pomoćnik za pretvaranje binarnog zapisa u sliku:

- dCode pomoćnik za pretvaranje binarnog zapisa u sliku.<sup>[[5]](#references)</sup>

#### Braille

- Branah prevodilac za Brailleovo pismo.<sup>[[6]](#references)</sup>

Za šire zbirke steganografskih alata i resurse za specifične tehnike pogledajte objedinjeni stego-toolkit i pažljivo odabranu listu 0xRick-a.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker slika sa objedinjenim najpopularnijim steganografskim alatima](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 konvencije za otvoreno pakovanje](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binarna slika](https://www.dcode.fr/binary-image)
- [6] [Branah — Prevodilac za Brailleovo pismo](https://www.branah.com/braille-translator)
- [7] [0xRick - Steganografski resursi](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
