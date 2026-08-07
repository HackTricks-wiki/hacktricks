# Steganografija slika

{{#include ../../banners/hacktricks-training.md}}

Većina CTF image stego zadataka svodi se na jednu od sledećih kategorija:

- LSB/bit-plane (PNG/BMP)
- Payload-i u metapodacima/komentarima
- Neobičnosti PNG chunk-ova / popravka oštećenja
- JPEG DCT-domain alati (OutGuess itd.)
- Zasnovano na frame-ovima (GIF/APNG)

## Brza trijaža

Dajte prednost dokazima na nivou kontejnera pre detaljne analize sadržaja:

- Validirajte fajl i pregledajte strukturu: `file`, `magick identify -verbose`, validatori formata (npr. `pngcheck`).
- Izvucite metapodatke i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite da li postoji ugrađen/dodat sadržaj: `binwalk` i pregled kraja fajla (`tail | xxd`).
- Grananje prema kontejneru:
- PNG/BMP: bit-plane/LSB i anomalije na nivou chunk-ova.
- JPEG: metapodaci + DCT-domain alati (familije u stilu OutGuess/F5).
- GIF/APNG: ekstrakcija frame-ova, poređenje razlika između frame-ova, trikovi sa paletom.

## Bit-plane / LSB

### Tehnika

PNG/BMP su popularni u CTF-ovima jer čuvaju piksele na način koji olakšava **manipulaciju na nivou bitova**. Klasičan mehanizam za skrivanje/ekstrakciju je:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- **Najmanje značajan bit** (LSB) svakog kanala veoma malo menja sliku.
- Napadači skrivaju podatke u tim bitovima nižeg reda, ponekad koristeći stride, permutaciju ili izbor kanala.

Šta možete očekivati u izazovima:

- Payload je samo u jednom kanalu (npr. `R` LSB).
- Payload je u alpha kanalu.
- Payload je kompresovan/enkodovan nakon ekstrakcije.
- Poruka je raspoređena kroz plane ili sakrivena pomoću XOR-a između plane-ova.

Dodatne familije sa kojima se možete susresti (zavisno od implementacije):

- **LSB matching** (ne samo promena bita, već +/-1 prilagođavanja radi podudaranja ciljnog bita)
- **Skrivanje zasnovano na paleti/indeksu** (indeksirani PNG/GIF: payload je u indeksima boja, a ne u sirovim RGB vrednostima)
- **Payload samo u alpha kanalu** (potpuno nevidljiv u RGB prikazu)

### Alati

#### zsteg

`zsteg` nabraja mnoge LSB/bit-plane obrasce za ekstrakciju iz PNG/BMP fajlova:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metapodaci, transformacije slike, brute forcing LSB varijanti).
- `stegsolve`: ručni vizuelni filteri (izdvajanje kanala, inspekcija ravni, XOR itd.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trikovi vidljivosti zasnovani na FFT-u

FFT nije LSB ekstrakcija; koristi se u slučajevima kada je sadržaj namerno sakriven u frekvencijskom prostoru ili suptilnim obrascima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based trijaža se često koristi u CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG interne strukture: chunk-ovi, korupcija i skriveni podaci

### Tehnika

PNG je format zasnovan na chunk-ovima. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a, a ne u vrednostima piksela:

- **Dodatni bajtovi nakon `IEND`** (mnogi prikazivači ignorišu završne bajtove)
- **Nestandardni ancillary chunk-ovi** koji sadrže payload
- **Korumpirana zaglavlja** koja skrivaju dimenzije ili onemogućavaju parserima rad dok se ne poprave

Lokacije chunk-ova koje treba posebno proveriti:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad kompresovani)
- `iCCP` (ICC profil) i drugi ancillary chunk-ovi koji se koriste kao nosioci
- `eXIf` (EXIF podaci u PNG-u)

### Komande za trijažu
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Šta tražiti:

- Neobične kombinacije width/height/bit-depth/colour-type
- CRC/chunk greške (pngcheck obično ukazuje na tačan offset)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam je potreban detaljniji prikaz chunk-ova:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Korisne reference:

- PNG specifikacija (struktura, chunks): https://www.w3.org/TR/PNG/
- Trikovi formata datoteka (rubni slučajevi PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools i ograničenja ELA

### Technique

JPEG se ne čuva kao sirovi pikseli; kompresuje se u DCT domenu. Zato se JPEG stego tools razlikuju od PNG LSB tools:

- Metadata/comment payloads su na nivou fajla (visok signal i brzi za proveru)
- DCT-domain stego tools ugrađuju bitove u frekvencijske koeficijente

Operativno, JPEG tretirajte kao:

- Container za metadata segmente (visok signal i brz za proveru)
- Kompresovani signalni domen (DCT coefficients) u kom rade specijalizovani stego tools

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Lokacije sa jakim signalom:

- EXIF/XMP/IPTC metadata
- JPEG segment komentara (`COM`)
- Application segmenti (`APP1` za EXIF, `APPn` za podatke dobavljača)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako se konkretno susrećete sa steghide payloadima u JPEG datotekama, razmotrite korišćenje alata `stegseek` (bruteforce je brži nego kod starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Analiza nivoa greške

ELA ističe različite artefakte ponovne kompresije; može da ukaže na regione koji su menjani, ali sama po sebi nije stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Kod animiranih slika pretpostavite da se poruka nalazi:

- U jednom frejmu (jednostavno), ili
- Raspoređena kroz frejmove (redosled je važan), ili
- Vidljiva samo kada napravite diff uzastopnih frejmova

### Izdvajanje frejmova
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Zatim tretirajte frejmove kao obične PNG-ove: `zsteg`, `pngcheck`, izolacija kanala.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije pojedinačnih frejmova

Upoređivanje razlika između frejmova često je presudno:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Detektujte APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` ili `file`.
- Izdvojte frejmove bez promene vremenskog rasporeda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Oporavite payload-e kodirane kao broj piksela po frejmu:
```python
from PIL import Image
import glob
out = []
for f in sorted(glob.glob('frames/frame_*.png')):
counts = Image.open(f).getcolors()
target = dict(counts).get((255, 0, 255, 255))  # adjust the target color
out.append(target or 0)
print(bytes(out).decode('latin1'))
```
Animirani izazovi mogu kodirati svaki bajt kao broj pojavljivanja određene boje u svakom frejmu; spajanjem tih brojeva rekonstruiše se poruka.<sup>[[1]](#references)</sup>

## Umetanje zaštićeno lozinkom

Ako sumnjate da je embedding zaštićen lozinkom, a ne zasnovan na manipulaciji nivoa piksela, ovo je obično najbrži put.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može da umeće/izdvaja šifrovane payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo: https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Reference

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
