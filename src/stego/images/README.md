# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF image stego kom neer op een van hierdie kategorieë:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Gee voorkeur aan bewyse op houervlak voor diep inhoud-analise:

- Validate the file and inspect structure: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extract metadata and visible strings: `exiftool -a -u -g1`, `strings`.
- Check for embedded/appended content: `binwalk` and end-of-file inspection (`tail | xxd`).
- Branch by container:
- PNG/BMP: bit-planes/LSB and chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP is gewild in CTFs omdat hulle pixels stoor op 'n manier wat bit-vlak manipulasie maklik maak. Die klassieke hide/extract-meganisme is:

- Each pixel channel (R/G/B/A) has multiple bits.
- The **least significant bit** (LSB) of each channel changes the image very little.
- Attackers hide data in those low-order bits, sometimes with a stride, permutation, or per-channel choice.

Wat om in challenges te verwag:

- Die payload is slegs in één kanaal (e.g., `R` LSB).
- Die payload is in die alpha channel.
- Payload is compressed/encoded after extraction.
- Die boodskap is oor plane versprei of weggesteek via XOR tussen plane.

Additional families you may encounter (implementation-dependent):

- **LSB matching** (not just flipping the bit, but +/-1 adjustments to match target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Tooling

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer 'n reeks transforms uit (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: handmatige visuele filters (channel isolation, plane inspection, XOR, etc).

Stegsolve aflaai: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is nie LSB extraction nie; dit is vir gevalle waar inhoud opsetlik in frekwensieruimte of subtiele patrone weggesteek is.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-gebaseerde triage wat dikwels in CTFs gebruik word:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Tegniek

PNG is 'n chunked formaat. In baie uitdagings word die payload op die container/chunk-vlak gestoor eerder as in pixelwaardes:

- **Ekstra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Nie-standaard ancillary chunks** carrying payloads
- **Gekorrupte headers** wat dimensies verberg of parsers breek totdat dit reggemaak word

Hoë-signaal chunk-lokasies om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage-opdragte
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Waarop om te let:

- Abnormale breedte/hoogte/bit-diepte/kleur-tipe kombinasies
- CRC/chunk-foute (pngcheck wys gewoonlik na die presiese offset)
- Waarskuwings oor ekstra data ná `IEND`

As jy 'n dieper chunk-oorsig benodig:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nuttige verwysings:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, en ELA beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit is in die DCT-domein gekomprimeer. Daarom verskil JPEG stego tools van PNG LSB tools:

- Metadata/comment payloads is op lêervlak (hoë sein en vinnig om na te kyk)
- DCT-domain stego tools inkorporeer bits in frekwensie-koëffisiënte

Operasioneel, beskou JPEG as:

- ’n houer vir metadata-segmente (hoë sein, vinnig om te inspekteer)
- ’n gekomprimeerde sein-domein (DCT-koëffisiënte) waar gespesialiseerde stego tools werk

### Vinnige kontroles
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Hoë seinliggings:

- EXIF/XMP/IPTC metagegewens
- JPEG-kommentaarsegment (`COM`)
- Toepassingssegmente (`APP1` for EXIF, `APPn` for verskafferdata)

### Common tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide payloads in JPEGs te doen het, oorweeg om `stegseek` te gebruik (vinnigere bruteforce as ouer scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou wys na streke wat gewysig is, maar dit is nie 'n stego-detector op sigself nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, neem aan die boodskap is:

- In 'n enkele raam (maklik), of
- Versprei oor rame (volgorde tel), of
- Slegs sigbaar wanneer jy opeenvolgende rame diff

### Ekstraheer rame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandel dan rame soos normale PNG's: `zsteg`, `pngcheck`, channel isolation.

Alternatiewe gereedskap:

- `gifsicle --explode anim.gif` (vinnige raam-uittrekking)
- `imagemagick`/`magick` vir per-raam transformasies

Raamonderskeiding is dikwels deurslaggewend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Wagwoord-beskermde inkapseling

As jy vermoed dat inkapseling deur 'n passphrase beskerm word eerder as pixelvlak-manipulasie, is dit gewoonlik die vinnigste pad.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Ek kan nie die repo direk aflaai nie. Plak asseblief die inhoud van src/stego/images/README.md hier, dan vertaal ek dit na Afrikaans en behou presies dieselfde markdown-/HTML-sintaksis.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
