# Stego tok rada

{{#include ../../banners/hacktricks-training.md}}

Većina stego zadataka rešava se brže sistematskim trijažom nego nasumičnim isprobavanjem alata.

## Osnovni tok

### Kontrolna lista za brzu trijažu

Cilj je efikasno odgovoriti na dva pitanja:

1. Koji je stvarni kontejner/format?
2. Da li se payload nalazi u metapodacima, dodatim bajtovima, ugrađenim datotekama ili u stego sadržaja?

#### 1) Identifikujte kontejner
```bash
file target
ls -lah target
```
Ako se `file` i ekstenzija ne podudaraju, ispitajte signature umesto da verujete sufiksu. `file` je takođe heuristički alat i može biti zbunjen neispravnim ili polyglot ulazom. Tretirajte uobičajene formate kao containere kada je to prikladno (na primer, OOXML dokumenti su ZIP paketi).<sup>[[2]](#references)</sup>

#### 2) Potražite metapodatke i očigledne stringove
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Pokušajte sa više kodiranja:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Proverite dodate podatke / ugrađene datoteke
```bash
binwalk target
binwalk -e target
```
Ako ekstrakcija ne uspe, ali su potpisi prijavljeni, ručno izdvojte offsete pomoću `dd` i ponovo pokrenite `file` nad izdvojenim regionom.

#### 4) Ako je slika

- Proverite anomalije: `magick identify -verbose file`
- Ako je PNG/BMP, izlistajte bit-plane/LSB: `zsteg -a file.png`
- Proverite strukturu PNG-a: `pngcheck -v file.png`
- Koristite vizuelne filtere (Stegsolve / StegoVeritas) kada sadržaj može biti otkriven transformacijama kanala/plane-ova

#### 5) Ako je audio

- Prvo napravite spektrogram (Sonic Visualiser)
- Dekodirajte/proverite streams: `ffmpeg -v info -i file -f null -`
- Ako audio podseća na strukturisane tonove, testirajte DTMF dekodiranje

### Osnovni alati

Oni otkrivaju najčešće slučajeve na nivou containera: payload u metapodacima, dodate bajtove i embedded fajlove maskirane ekstenzijom.<sup>[[1]](#references)[[3]](#references)</sup>

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
Repozitorijum projekta: `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### datoteka / stringovi
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Kontejneri, dodati podaci i polyglot trikovi

Mnogi steganografski izazovi sastoje se od dodatnih bajtova nakon ispravne datoteke ili ugrađenih arhiva sakrivenih ekstenzijom.

#### Dodati payload-i

Mnogi formati ignorišu završne bajtove. ZIP/PDF/script može biti dodat kontejneru slike ili audio zapisa.

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
#### Magic bytes

Kada je `file` zbunjen, potražite magic bytes pomoću `xxd` i uporedite ih sa poznatim potpisima:
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Probajte `7z` i `unzip` čak i ako ekstenzija ne ukazuje na zip:
```bash
7z l file
unzip -l file
```
### Neobičnosti povezane sa stego

Brze veze ka obrascima koji se često pojavljuju uz stego (QR iz binarnih podataka, brajevo pismo itd.).

#### QR kodovi iz binarnih podataka

Ako je dužina blob-a savršen kvadrat, on može predstavljati sirove piksele za sliku/QR.
```python
import math
math.isqrt(2500)  # 50
```
Pomoćni alat za konverziju binarnog zapisa u sliku:

- dCode alat za konverziju binarnog zapisa u sliku.<sup>[[5]](#references)</sup>

#### Brajevo pismo

- Branah prevodilac za Brajevo pismo.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Docker image sa najpopularnijim alatima za steganografiju](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — ECMA-376 konvencije za otvoreno pakovanje](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Binarna slika](https://www.dcode.fr/binary-image)
- [6] [Branah — Prevodilac za Brajevo pismo](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
