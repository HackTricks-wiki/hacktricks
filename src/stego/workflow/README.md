# Stego tok rada

{{#include ../../banners/hacktricks-training.md}}

Većina stego problema se brže rešava sistematskom trijažom nego isprobavanjem nasumičnih alata.

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
Ako `file` i ekstenzija ne odgovaraju, veruj `file`. Smatraj uobičajene formate kontejnerima kada je to prikladno (npr. OOXML dokumenti su ZIP fajlovi).

#### 2) Potraži metapodatke i očigledne strings
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Probajte više kodiranja:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Proveri dodatne podatke / ugrađene datoteke
```bash
binwalk target
binwalk -e target
```
Ako ekstrakcija ne uspe, ali su prijavljeni potpisi, ručno izrežite regione koristeći `dd` i ponovo pokrenite `file` na izrezanom delu.

#### 4) Ako je slika

- Ispitajte anomalije: `magick identify -verbose file`
- Ako je PNG/BMP, ispitajte bit-planes/LSB: `zsteg -a file.png`
- Proverite strukturu PNG-a: `pngcheck -v file.png`
- Koristite vizuelne filtere (Stegsolve / StegoVeritas) kada sadržaj može biti otkriven transformacijom kanala ili slojeva

#### 5) Ako je audio

- Prvo spektrogram (Sonic Visualiser)
- Dekodirajte/ispitajte tokove: `ffmpeg -v info -i file -f null -`
- Ako audio podseća na strukturisane tonove, testirajte DTMF dekodiranje

### Bread-and-butter tools

Ovi pokrivaju visokofrekventne slučajeve na nivou kontejnera: metapodaci, dodati bajtovi i ugrađene datoteke prikrivenе ekstenzijom.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
I don't have access to the repository files. Please paste the full contents of src/stego/workflow/README.md here (or the portion you want translated). I'll translate the English text to Serbian and keep all markdown/html tags, links and paths exactly as they are.
```bash
foremost -i file
```
Ne mogu direktno pristupiti repozitorijumu. Pošaljite sadržaj fajla src/stego/workflow/README.md (ili nalepite sirovi markdown ovde) i ja ću ga prevesti na srpski, pritom zadržavajući identičnu markdown/html sintaksu, linkove, putanje, tagove i kod koji ne treba prevoditi.
```bash
exiftool file
exiv2 file
```
I don't have the contents of src/stego/workflow/README.md. Please paste the file text (or the strings) you want translated to Serbian, and I'll translate it following the rules you specified.
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Containers, dodati podaci i polyglot trikovi

Mnogi steganography izazovi su dodatni bajtovi nakon validne datoteke, ili ugrađeni arhivi prikriveni promenom ekstenzije.

#### Priloženi payloads

Mnogi formati ignorišu prateće bajtove. ZIP/PDF/script mogu se dodati na image/audio container.

Brze provere:
```bash
binwalk file
tail -c 200 file | xxd
```
Ako znate offset, carve sa `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Kada je `file` zbunjen, potraži magic bytes koristeći `xxd` i uporedi sa poznatim potpisima:
```bash
xxd -g 1 -l 32 file
```
#### Zip u prerušavanju

Probajte `7z` i `unzip` čak i ako ekstenzija ne kaže zip:
```bash
7z l file
unzip -l file
```
### Neobičnosti u blizini stego

Brze veze za obrasce koji se često pojavljuju pored stego (QR-from-binary, braille, itd).

#### QR kodovi iz binarnog

Ako je dužina bloba savršen kvadrat, to može predstavljati sirove piksele slike ili QR koda.
```python
import math
math.isqrt(2500)  # 50
```
Pomoćnik za pretvaranje binarnog u sliku:

- https://www.dcode.fr/binary-image

#### Brajevo pismo

- https://www.branah.com/braille-translator

## Liste referenci

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
