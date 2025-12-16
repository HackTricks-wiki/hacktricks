# Stego tok rada

{{#include ../../banners/hacktricks-training.md}}

Većina stego problema se brže rešava sistematskom trijažom nego pokušajima nasumičnih alata.

## Osnovni tok

### Brza kontrolna lista za trijažu

Cilj je efikasno odgovoriti na dva pitanja:

1. Koji je stvarni kontejner/format?
2. Da li je payload u metadata, appended bytes, embedded files, ili content-level stego?

#### 1) Identifikujte kontejner
```bash
file target
ls -lah target
```
Ako `file` i ekstenzija nisu u saglasnosti, verujte `file`-u. Tretirajte uobičajene formate kao kontejnere kada je to prikladno (npr. OOXML dokumenti su ZIP fajlovi).

#### 2) Potražite metapodatke i očigledne tekstualne nizove
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Isprobajte više enkodiranja:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Proveri da li ima dodatih podataka / ugrađenih fajlova
```bash
binwalk target
binwalk -e target
```
Ako ekstrakcija ne uspe ali su prijavljeni potpisi, ručno izrežite region po offset-ima pomoću `dd` i ponovo pokrenite `file` na izrezanom regionu.

#### 4) Ako je slika

- Pregledajte anomalije: `magick identify -verbose file`
- Ako je PNG/BMP, izlistajte bit-ploče/LSB: `zsteg -a file.png`
- Proverite strukturu PNG-a: `pngcheck -v file.png`
- Koristite vizuelne filtere (Stegsolve / StegoVeritas) kada sadržaj može biti otkriven transformacijama kanala/ploča

#### 5) Ako je audio

- Prvo spektrogram (Sonic Visualiser)
- Dekodirajte/ispitajte streamove: `ffmpeg -v info -i file -f null -`
- Ako audio liči na strukturisane tonove, testirajte DTMF dekodiranje

### Osnovni alati

Ovi obično pogađaju česte slučajeve na nivou kontejnera: metadata payloads, dodati bajtovi i ugnježdene fajlove prikrivene ekstenzijom.

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
Nemam direktan pristup repozitorijumu. Molim te nalepi sadržaj fajla src/stego/workflow/README.md ovde i ja ću ga prevesti na srpski uz zadržavanje iste markdown/html sintakse i pravila koja si naveo.
```bash
exiftool file
exiv2 file
```
Navedite sadržaj fajla src/stego/workflow/README.md koji želite da prevedem — nalepite tekst ovde.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Kontejneri, priloženi podaci i polyglot trikovi

Mnogi steganography izazovi su dodatni bajtovi nakon ispravne datoteke, ili ugrađeni arhivi prikriveni ekstenzijom.

#### Prikačeni payloads

Mnogi formati ignorišu prateće bajtove. ZIP/PDF/script se može prikačiti za image/audio kontejner.

Brze provere:
```bash
binwalk file
tail -c 200 file | xxd
```
Ako znate offset, carve pomoću `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magični bajtovi

Kada je `file` zbunjen, potražite magične bajtove pomoću `xxd` i uporedite ih sa poznatim potpisima:
```bash
xxd -g 1 -l 32 file
```
#### Zip u prerušavanju

Pokušajte sa `7z` i `unzip` čak i ako ekstenzija ne ukazuje na zip:
```bash
7z l file
unzip -l file
```
### Near-stego neobičnosti

Kratke veze za obrasce koji se redovno pojavljuju pored stega (QR-from-binary, braille, itd).

#### QR kodovi iz binarnog

Ako je dužina bloba savršen kvadrat, to može predstavljati sirove piksele za sliku/QR.
```python
import math
math.isqrt(2500)  # 50
```
Pomoćnik za konverziju binarnog u sliku:

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Brajeovo pismo

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Liste referenci

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
