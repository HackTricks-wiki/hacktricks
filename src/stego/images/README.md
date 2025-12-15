# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Većina CTF image stego problema svodi se na jednu od sledećih kategorija:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Prioritet dajte dokazima na nivou kontejnera pre dubinske analize sadržaja:

- Potvrdite fajl i pregledajte strukturu: `file`, `magick identify -verbose`, alatke za validaciju formata (npr. `pngcheck`).
- Ekstrahujte metapodatke i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite za ugrađeni/dodat sadržaj: `binwalk` i inspekcija kraja fajla (`tail | xxd`).
- Razvrstavanje po kontejneru:
- PNG/BMP: bit-planes/LSB i anomalije na nivou chunk-ova.
- JPEG: metapodaci + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: ekstrakcija frejmova, frame differencing, trikovi sa paletom.

## Bit-planes / LSB

### Technique

PNG/BMP su popularni na CTF-ovima jer čuvaju piksele na način koji olakšava **manipulaciju na nivou bita**. Klasičan mehanizam za skrivanje/izvlačenje je:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- The **least significant bit** (LSB) svakog kanala menja sliku vrlo malo.
- Napadači skrivaju podatke u tim nisko-rangiranim bitovima, ponekad sa stride-om, permutacijom, ili izborom po kanalu.

Šta očekivati u zadacima:

- Payload je u samo jednom kanalu (npr. `R` LSB).
- Payload je u alpha kanalu.
- Payload je kompresovan/kodovan nakon ekstrakcije.
- Poruka je raspoređena preko planova ili sakrivena putem XOR-a između planova.

Dodatne varijante na koje možete naići (zavisno od implementacije):

- **LSB matching** (ne samo prevrnuti bit, već +/-1 prilagođavanja da bi se dobio ciljni bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload u indeksima boja umesto u raw RGB)
- **Alpha-only payloads** (potpuno nevidljivo u RGB prikazu)

### Tooling

#### zsteg

`zsteg` izlistava mnoge LSB/bit-plane obrasce ekstrakcije za PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: ručni vizuelni filteri (channel isolation, plane inspection, XOR, itd).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT nije LSB ekstrakcija; koristi se u slučajevima gde je sadržaj namerno sakriven u frekvencijskoj oblasti ili suptilnim šablonima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-bazirana trijaža često korišćena na CTF-ovima:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Interna struktura PNG: chunks, korupcija i sakriveni podaci

### Tehnika

PNG je format zasnovan na chunk-ovima. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a umesto u vrednostima piksela:

- **Extra bytes after `IEND`** (mnogi pregledači ignorišu prateće bajtove)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** koji sakrivaju dimenzije ili ruše parsere dok se ne isprave

Ključne lokacije chunk-ova za proveru:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) i drugi ancillary chunks koji se koriste kao carrier
- `eXIf` (EXIF data in PNG)

### Komande za trijažu
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na šta treba obratiti pažnju:

- Neobične kombinacije width/height/bit-depth/colour-type
- CRC/chunk greške (pngcheck obično ukazuje na tačan offset)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako vam treba dublji prikaz chunk-ova:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Useful references:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metapodaci, DCT-domain alati, and ELA ograničenja

### Tehnika

JPEG se ne čuva kao sirovi pikseli; kompresovan je u DCT domenu. Zbog toga se JPEG stego alati razlikuju od PNG LSB alata:

- Metapodaci/komentar payloads su na nivou fajla (high-signal i brzo za pregled)
- DCT-domain stego alati umeću bitove u frekvencijske koeficijente

Operativno, tretirajte JPEG kao:

- Kontejner za segmente metapodataka (high-signal, brzo za pregled)
- Kompresovan signalni domen (DCT koeficijenti) gde operišu specijalizovani stego alati

### Brze provere
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Mesta visokog signala:

- EXIF/XMP/IPTC metapodaci
- JPEG segment komentara (`COM`)
- Aplikacioni segmenti (`APP1` for EXIF, `APPn` for vendor data)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako imate steghide payloads u JPEG-ovima, razmislite o korišćenju `stegseek` (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA ističe različite artefakte ponovne kompresije; može ukazati na oblasti koje su izmenjene, ali sama po sebi nije detektor stega:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Animirane slike

### Tehnika

Za animirane slike, pretpostavite da je poruka:

- U jednom frejmu (lako), ili
- Raspoređena preko frejmova (redosled je bitan), ili
- Vidljiva samo kada napravite diff uzastopnih frejmova

### Ekstrakcija frejmova
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Zatim tretirajte frejmove kao normalne PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije po frejmu

Frame differencing je često presudno:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Umetanje zaštićeno lozinkom

Ako sumnjate da je umetanje zaštićeno passphrase-om umesto manipulacije na nivou piksela, ovo je obično najbrži put.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Molim vas zalepite sadržaj fajla src/stego/images/README.md ovde (ili omogućite pristup repozitorijumu). Kada primim sadržaj, prevešću ga na srpski zadržavajući istu markdown i html sintaksu i ne prevodeći kod, putanje, linkove, nazive tehnika, ni specijalne tagove.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
