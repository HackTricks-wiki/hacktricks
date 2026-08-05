# Steganografija slika

{{#include ../../banners/hacktricks-training.md}}

Većina CTF image stego tehnika svodi se na jednu od sledećih kategorija:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk anomalije / popravka oštećenja
- JPEG DCT-domain alati (OutGuess itd.)
- Frame-based (GIF/APNG)

## Brza trijaža

Dajte prednost dokazima na nivou containera pre detaljne analize sadržaja:

- Validirajte file i pregledajte strukturu: `file`, `magick identify -verbose`, format validators (npr. `pngcheck`).
- Izdvojite metadata i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite embedded/appended content: `binwalk` i pregled kraja file-a (`tail | xxd`).
- Grananje prema container-u:
- PNG/BMP: bit-planes/LSB i anomalije na nivou chunk-ova.
- JPEG: metadata + DCT-domain alati (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP su popularni u CTF-ovima jer čuvaju pixel-e na način koji olakšava **bit-level manipulation**. Klasičan mehanizam za skrivanje/izdvajanje je:

- Svaki pixel channel (R/G/B/A) ima više bitova.
- **Least significant bit** (LSB) svakog channel-a veoma malo menja sliku.
- Attackers skrivaju podatke u tim bitovima nižeg reda, ponekad koristeći stride, permutation ili izbor channel-a po channel-u.

Šta možete očekivati u challenges:

- Payload je samo u jednom channel-u (npr. `R` LSB).
- Payload je u alpha channel-u.
- Payload je compressed/encoded nakon extraction-a.
- Poruka je raspoređena kroz planes ili skrivena pomoću XOR-a između planes.

Dodatne families sa kojima se možete susresti (zavisi od implementation-a):

- **LSB matching** (ne samo flipping bit-a, već +/-1 adjustments radi usklađivanja sa target bit-om)
- **Palette/index-based hiding** (indexed PNG/GIF: payload je u color indices umesto u raw RGB)
- **Alpha-only payloads** (potpuno nevidljiv u RGB view-u)

### Tooling

#### zsteg

`zsteg` enumerira mnoge LSB/bit-plane extraction patterns za PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metapodaci, transformacije slike, brute forcing LSB varijanti).
- `stegsolve`: ručni vizuelni filteri (izolacija kanala, pregled bit-plane-a, XOR itd.).

Preuzimanje alata Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Trikovi za uočljivost zasnovani na FFT-u

FFT nije LSB ekstrakcija; koristi se u slučajevima kada je sadržaj namerno sakriven u frekvencijskom prostoru ili suptilnim obrascima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web alati za početnu analizu često se koriste u CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG interne strukture: chunk-ovi, oštećenja i skriveni podaci

### Tehnika

PNG je format organizovan u chunk-ove. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a, a ne u vrednostima piksela:

- **Dodatni bajtovi nakon `IEND`** (mnogi pregledači ignorišu bajtove na kraju datoteke)
- **Nestandardni ancillary chunk-ovi** koji sadrže payload
- **Oštećena zaglavlja** koja skrivaju dimenzije ili onemogućavaju parserima obradu dok se ne poprave

Lokacije chunk-ova koje treba detaljno proveriti:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad kompresovani)
- `iCCP` (ICC profil) i drugi ancillary chunk-ovi koji se koriste kao nosači
- `eXIf` (EXIF podaci u PNG-u)

### Komande za početnu analizu
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na šta obratiti pažnju:

- Neobične kombinacije širine/visine/bit-depth/colour-type
- CRC/chunk greške (`pngcheck` obično ukazuje na tačan offset)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam je potreban detaljniji prikaz chunk-ova:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Korisne reference:

- PNG specification (struktura, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metapodaci, alati za DCT domen i ograničenja ELA

### Tehnika

JPEG se ne čuva kao sirovi pikseli; kompresuje se u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Payload-i u metapodacima/komentarima su na nivou fajla (visok signal i brzi su za proveru)
- Stego alati za DCT domen ugrađuju bitove u frekvencijske koeficijente

Operativno, JPEG posmatrajte kao:

- Kontejner za segmente metapodataka (visok signal i brzi su za proveru)
- Kompresovani signalni domen (DCT koeficijenti) u kojem rade specijalizovani stego alati

### Brze provere
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Lokacije sa visokim signalom:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` za EXIF, `APPn` za vendor data)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako se konkretno susrećete sa steghide payloads u JPEG datotekama, razmotrite korišćenje alata `stegseek` (brži bruteforce od starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može ukazati na regione koji su izmenjeni, ali sam po sebi nije stego detector:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Kod animiranih slika, pretpostavite da je poruka:

- U jednom frejmu (jednostavno), ili
- Raspoređena kroz frejmove (redosled je važan), ili
- Vidljiva samo kada uporedite uzastopne frejmove

### Izdvojite frejmove
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Zatim tretirajte frejmove kao obične PNG-ove: `zsteg`, `pngcheck`, izolacija kanala.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije po frejmu

Izdvajanje razlika između frejmova često je presudno:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG kodiranje broja piksela

- Detektujte APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` ili `file`.
- Izdvojte frejmove bez promene tajminga: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Obnovite payload-e kodirane kao broj piksela po frejmu:
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
Animirani izazovi mogu kodirati svaki bajt kao broj pojavljivanja određene boje u svakom frejmu; spajanjem tih brojeva rekonstruše se poruka.<sup>[[1]](#references)</sup>

## Ugrađivanje zaštićeno lozinkom

Ako sumnjate da je ugrađivanje zaštićeno passphrase-om, a ne manipulacijom na nivou piksela, ovo je obično najbrži put.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može da embed/extract šifrovane payload-e.
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
