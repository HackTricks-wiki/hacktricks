# Stego tok rada

{{#include ../../banners/hacktricks-training.md}}

Većina stego problema rešava se brže sistematskom trijažom nego nasumičnim isprobavanjem alata.

## Osnovni tok

### Kontrolna lista za brzu trijažu

Cilj je efikasno odgovoriti na dva pitanja:

1. Koji je stvarni kontejner/format?
2. Da li se payload nalazi u metapodacima, dodatim bajtovima, ugrađenim datotekama ili u content-level stego tehnici?

#### 1) Identifikujte kontejner
```bash
file target
ls -lah target
```
Ako se `file` i ekstenzija ne podudaraju, verujte komandi `file`. Kada je prikladno, tretirajte uobičajene formate kao kontejnere (npr. OOXML dokumenti su ZIP datoteke).

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
#### 3) Proverite dodate podatke / ugrađene datoteke
```bash
binwalk target
binwalk -e target
```
Ako ekstrakcija ne uspe, ali se prijave potpisi, ručno izdvojte offsete pomoću `dd`, a zatim ponovo pokrenite `file` nad izdvojenim regionom.

#### 4) Ako je slika

- Proverite anomalije: `magick identify -verbose file`
- Ako je PNG/BMP, nabrojte bit-plane/LSB: `zsteg -a file.png`
- Proverite strukturu PNG-a: `pngcheck -v file.png`
- Koristite vizuelne filtere (Stegsolve / StegoVeritas) kada sadržaj može biti otkriven transformacijama kanala/plane-a

#### 5) Ako je audio

- Prvo napravite spektrogram (Sonic Visualiser)
- Dekodirajte/pregledajte stream-ove: `ffmpeg -v info -i file -f null -`
- Ako audio podseća na strukturisane tonove, testirajte DTMF decoding

### Osnovni alati

Ovi alati otkrivaju najčešće slučajeve na nivou kontejnera: payload u metapodacima, dodate bajtove i ugrađene fajlove sakrivene ekstenzijom.<sup>[[1]](#references)</sup>

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
Repozitorijum: https://github.com/korczis/foremost

#### Exiftool / Exiv2
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
### Kontejneri, dodati podaci i polyglot trikovi

Mnogi steganography izazovi podrazumevaju dodatne bajtove nakon validne datoteke ili ugrađene arhive maskirane ekstenzijom.

#### Dodati payload-i

Mnogi formati ignorišu završne bajtove. ZIP/PDF/script mogu biti dodati image/audio kontejneru.

Brze provere:
```bash
binwalk file
tail -c 200 file | xxd
```
Ako znate ofset, izdvojte pomoću `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magični bajtovi

Kada je `file` zbunjen, potražite magične bajtove pomoću `xxd` i uporedite ih sa poznatim potpisima:
```bash
xxd -g 1 -l 32 file
```
#### Zip pod maskom

Isprobaj `7z` i `unzip` čak i ako ekstenzija ne ukazuje da je u pitanju zip:
```bash
7z l file
unzip -l file
```
### Neobičnosti povezane sa stego tehnikom

Brze veze ka obrascima koji se često pojavljuju uz stego (QR iz binarnog zapisa, brajevo pismo itd.).

#### QR kodovi iz binarnog zapisa

Ako je dužina blob-a savršen kvadrat, on može predstavljati sirove piksele slike/QR koda.
```python
import math
math.isqrt(2500)  # 50
```
Pomoćni alat za konverziju binarnog zapisa u sliku:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Brajevo pismo

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Reference

- [1] [DominicBreuker/stego-toolkit - Docker image sa najpopularnijim steganografskim alatima objedinjenim na jednom mestu](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
