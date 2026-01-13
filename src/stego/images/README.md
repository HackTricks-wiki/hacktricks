# Steganografija slika

{{#include ../../banners/hacktricks-training.md}}

Većina CTF image stego se svodi na jednu od ovih kategorija:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Brza trijaža

Prioritet stavite na dokaze na nivou kontejnera pre detaljne analize sadržaja:

- Potvrdite fajl i pregledajte strukturu: `file`, `magick identify -verbose`, format validators (npr. `pngcheck`).
- Izvucite metadata i vidljive stringove: `exiftool -a -u -g1`, `strings`.
- Proverite ugrađeni/dodati sadržaj: `binwalk` i inspekcija kraja fajla (`tail | xxd`).
- Granajte prema kontejneru:
- PNG/BMP: bit-planes/LSB i anomalije na nivou chunk-a.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: ekstrakcija frejmova, poređenje frejmova, trikovi sa paletom.

## Bit-planes / LSB

### Tehnika

PNG/BMP su popularni u CTF-ovima jer čuvaju piksele na način koji olakšava **manipulaciju na nivou bita**. Klasičan mehanizam skrivanja/ekstrakcije je:

- Svaki kanal piksela (R/G/B/A) ima više bitova.
- **najmanje značajan bit** (LSB) svakog kanala menja sliku vrlo malo.
- Napadači kriju podatke u tim niskorangiranim bitovima, ponekad sa stride-om, permutacijom ili izborom po kanalu.

Šta očekivati u challenge-ima:

- Payload je samo u jednom kanalu (npr. `R` LSB).
- Payload je u alpha channel-u.
- Payload je kompresovan/kodiran nakon ekstrakcije.
- Poruka je raširena preko planova ili skrivena putem XOR između planova.

Dodatne familije na koje možete naići (zavisno od implementacije):

- **LSB matching** (not just flipping the bit, but +/-1 adjustments to match target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Alati

#### zsteg

`zsteg` navodi mnoge LSB/bit-plane pattern-e za ekstrakciju iz PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: pokreće niz transformacija (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: ručni vizuelni filteri (channel isolation, plane inspection, XOR, itd).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT nije LSB ekstrakcija; koristi se za slučajeve gde je sadržaj namerno skriven u frekventnom prostoru ili u suptilnim šablonima.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage često korišćen u CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG interno: chunk-ovi, korupcija i skriveni podaci

### Tehnika

PNG je format podeljen na chunk-ove. U mnogim izazovima payload se čuva na nivou kontejnera/chunk-a umesto u vrednostima piksela:

- **Dodatni bajtovi nakon `IEND`** (mnogi pregledači ignorišu završne bajtove)
- **Nestandardni ancillary chunk-ovi** koji nose payload
- **Oštećena zaglavlja** koja skrivaju dimenzije ili lome parsere dok se ne isprave

Mesta chunk-ova na koja treba obratiti pažnju:

- `tEXt` / `iTXt` / `zTXt` (tekstualni metapodaci, ponekad kompresovani)
- `iCCP` (ICC profile) i drugi ancillary chunk-ovi korišćeni kao nosači
- `eXIf` (EXIF podaci u PNG)

### Komande za trijažu
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Na šta obratiti pažnju:

- Neobične width/height/bit-depth/colour-type kombinacije
- CRC/chunk greške (pngcheck obično pokazuje tačan offset)
- Upozorenja o dodatnim podacima nakon `IEND`

Ako ti treba detaljniji pregled chunk-ova:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Korisne reference:

- PNG specification (struktura, chunks): https://www.w3.org/TR/PNG/
- Trikovi formata fajla (PNG/JPEG/GIF rubni slučajevi): https://github.com/corkami/docs

## JPEG: metapodaci, DCT-domain alati, i ograničenja ELA

### Tehnika

JPEG nije čuvan kao sirovi pikseli; komprimovan je u DCT domenu. Zato se JPEG stego alati razlikuju od PNG LSB alata:

- Metadata/komentar payloadi su na nivou fajla (visok signal i brzo za pregled)
- DCT-domain stego alati ugrađuju bitove u frekvencijske koeficijente

Operativno, posmatrajte JPEG kao:

- Kontejner za segmente metapodataka (visok signal, brzo za pregled)
- Komprimovan signalni domen (DCT koeficijenti) gde rade specijalizovani stego alati

### Brze provere
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Lokacije sa visokim signalom:

- EXIF/XMP/IPTC metapodaci
- JPEG segment komentara (`COM`)
- Aplikacioni segmenti (`APP1` for EXIF, `APPn` for vendor data)

### Uobičajeni alati

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ako se konkretno suočavate sa steghide payload-ovima u JPEG-ovima, razmislite o korišćenju `stegseek` (brži bruteforce od starijih skripti):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

- ELA ističe različite artefakte ponovne kompresije; može ukazati na regione koji su uređivani, ali sam po sebi nije stego detektor:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Animirane slike

### Tehnika

Za animirane slike, pretpostavite da je poruka:

- U jednom frejmu (lako), ili
- Raspoređena preko frejmova (redosled je bitan), ili
- Vidljiva samo kada uradite diff uzastopnih frejmova

### Ekstrakcija frejmova
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Zatim tretiraj frejmove kao obične PNG-ove: `zsteg`, `pngcheck`, channel isolation.

Alternativni alati:

- `gifsicle --explode anim.gif` (brzo izdvajanje frejmova)
- `imagemagick`/`magick` za transformacije po frejmu

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Otkrij APNG kontejnere: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Izdvoji frejmove bez re-tajminga: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Oporavi payloads kodirane brojem piksela po frejmu:
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
Animirani izazovi mogu kodirati svaki bajt kao broj pojavljivanja određene boje u svakom frejmu; konkatenacijom tih brojeva rekonstruiše se poruka.

## Umetanje zaštićeno lozinkom

Ako sumnjate da je ugradnja zaštićena passphrase-om umesto manipulacije na nivou piksela, ovo je obično najbrži put.

### steghide

Podržava `JPEG, BMP, WAV, AU` i može da umeće/ekstrahuje šifrovane payload-e.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Podržava PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Reference

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
