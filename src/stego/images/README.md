# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Većina CTF image stego zadataka svodi se na jednu od ovih kategorija:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioritizujte dokaze na nivou kontejnera pre dubinske analize sadržaja:

- Proverite fajl i pregledajte strukturu: `file`, `magick identify -verbose`, format validators (npr. `pngcheck`).
- Izvucite metapodatke i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite ugrađeni/dodat sadržaj: `binwalk` i inspekcija kraja fajla (`tail | xxd`).
- Dalje postupajte prema tipu kontejnera:
- PNG/BMP: bit-planes/LSB i anomalije na nivou chunk-ova.
- JPEG: metapodaci + DCT-domain alati (OutGuess/F5-style families).
- GIF/APNG: ekstrakcija frejmova, poređenje frejmova, trikovi sa paletom.

## Bit-planes / LSB

### Technique

PNG/BMP su popularni na CTF-ovima jer čuvaju pixele na način koji olakšava manipulaciju na nivou bita. Klasičan mehanizam skrivanje/ekstrakcija je:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- **least significant bit** (LSB) svakog kanala menja sliku vrlo malo.
- Napadači skrivaju podatke u tim niskorangiranim bitovima, ponekad sa stride-om, permutacijom ili izborom po kanalu.

Šta očekivati u zadacima:

- Payload je samo u jednom kanalu (npr. `R` LSB).
- Payload je u alpha kanalu.
- Payload je kompresovan/enkodovan nakon ekstrakcije.
- Poruka je raspoređena po planovima ili skrivena putem XOR-a između planova.

Dodatne varijante na koje možete naići (zavisno od implementacije):

- **LSB matching** (ne samo preokretanje bita, već +/-1 podešavanja da bi se dobio ciljni bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload u indeksima boja umesto raw RGB)
- **Alpha-only payloads** (potpuno nevidljivo u RGB prikazu)

### Tooling

#### zsteg

`zsteg` navodi mnoge LSB/bit-plane obrasce za ekstrakciju za PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: ručni vizuelni filteri (channel isolation, plane inspection, XOR, itd).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT nije LSB extraction; koristi se za slučajeve kada je sadržaj namerno sakriven u frekvencijskoj domeni ili u suptilnim šablonima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Veb-trijaža često se koristi na CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Tehnika

PNG je format podeljen na chunk-ove. U mnogim izazovima payload je smešten na nivou kontejnera/chunk-a umesto u vrednostima piksela:

- **Dodatni bajtovi posle `IEND`** (mnogi pregledači ignorišu završne bajtove)
- **Nestandardni ancillary chunks** koji nose payloads
- **Oštećeni headeri** koji skrivaju dimenzije ili naruše parsere dok se ne poprave

Mesta u chunk-ovima koja vredi proveriti:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metadata, ponekad kompresovan)
- `iCCP` (ICC profile) i druge ancillary chunks korišćene kao nosač
- `eXIf` (EXIF data in PNG)

### Komande za trijažu
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na šta obratiti pažnju:

- Neobične kombinacije width/height/bit-depth/colour-type
- CRC/chunk greške (pngcheck obično pokazuje tačan offset)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam treba dublji prikaz chunk-ova:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Korisne reference:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- Trikovi sa formatima fajlova (PNG/JPEG/GIF rubni slučajevi): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Tehnika

JPEG se ne čuva kao sirovi pikseli; komprimovan je u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Podaci u metapodacima/komentarima su na nivou fajla (jak signal i brzo za proveru)
- DCT-domain stego alati ugrađuju bitove u frekvencijske koeficijente

Operativno, tretirajte JPEG kao:

- Kontejner za segmente metapodataka (jak signal, brzo za proveru)
- Komprimovan signalni domen (DCT koeficijenti) u kojem rade specijalizovani stego alati

### Brze provere
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Lokacije visokog signala:

- EXIF/XMP/IPTC metapodaci
- JPEG segment komentara (`COM`)
- Aplikacioni segmenti (`APP1` za EXIF, `APPn` za podatke proizvođača)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

If you are specifically facing steghide payloads in JPEGs, consider using `stegseek` (faster bruteforce than older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može ukazati na regione koji su izmenjeni, ali nije stego detector sam po sebi:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Za animirane slike, pretpostavite da je poruka:

- U jednom frejmu (lako), ili
- Raspodeljena kroz frejmove (redosled je bitan), ili
- Vidljiva samo kada napravite diff uzastopnih frejmova

### Ekstrakcija frejmova
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Zatim tretirajte frejmove kao obične PNG-ove: `zsteg`, `pngcheck`, channel isolation.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije po frejmu

Frame differencing je često presudno:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Ugradnja zaštićena lozinkom

Ako sumnjate da je embedding zaštićen passphrase-om umesto manipulacije na nivou piksela, ovo je obično najbrži put.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Nisam dobio sadržaj fajla. Molim vas nalepite pun sadržaj fajla src/stego/images/README.md koji želite da prevedem na srpski.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
