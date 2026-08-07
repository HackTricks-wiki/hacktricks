# Beeldsteganografie

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF-beeldstego val in een van hierdie kategorieë:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, ens.)
- Frame-based (GIF/APNG)

## Vinnige triage

Prioritiseer bewyse op containervlak voordat jy diepgaande inhoudsanalise doen:

- Valideer die lêer en inspekteer die struktuur: `file`, `magick identify -verbose`, format validators (bv. `pngcheck`).
- Ekstraheer metadata en sigbare stringe: `exiftool -a -u -g1`, `strings`.
- Kyk vir embedded/appended content: `binwalk` en inspeksie van die lêereinde (`tail | xxd`).
- Vertak volgens container:
- PNG/BMP: bit-planes/LSB en chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Tegniek

PNG/BMP is gewild in CTFs omdat hulle pixels op ’n manier stoor wat **bit-level manipulation** maklik maak. Die klassieke hide/extract-meganisme is:

- Elke pixel channel (R/G/B/A) het verskeie bits.
- Die **least significant bit** (LSB) van elke channel verander die beeld baie min.
- Attackers verberg data in hierdie low-order bits, soms met ’n stride, permutation of per-channel choice.

Wat om in challenges te verwag:

- Die payload is in slegs een channel (bv. `R` LSB).
- Die payload is in die alpha channel.
- Payload is compressed/encoded ná extraction.
- Die boodskap is oor planes versprei of via XOR tussen planes versteek.

Additional families wat jy moontlik sal teëkom (implementation-dependent):

- **LSB matching** (nie net flipping van die bit nie, maar +/-1 adjustments om by die target bit te pas)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices eerder as raw RGB)
- **Alpha-only payloads** (heeltemal onsigbaar in RGB view)

### Gereedskap

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer ’n reeks transforms uit (metadata, beeldtransformasies, brute-forcing van LSB-variante).
- `stegsolve`: handmatige visuele filters (kanaalisolasie, vlak-inspeksie, XOR, ens.).

Stegsolve-aflaai: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-gebaseerde sigbaarheidstruuks

FFT is nie LSB-ekstraksie nie; dit is vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone versteek word.

- EPFL-demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage word dikwels in CTFs gebruik:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-internals: chunks, korrupsie en versteekte data

### Tegniek

PNG is ’n chunk-gebaseerde formaat. In baie uitdagings word die payload op die container-/chunk-vlak gestoor eerder as in pixelwaardes:

- **Ekstra grepe ná `IEND`** (baie viewers ignoreer grepe aan die einde)
- **Nie-standaard ancillary chunks** wat payloads bevat
- **Korrupte headers** wat dimensies verberg of parsers laat faal totdat dit reggestel word

Hoë-seinsterkte chunk-liggings om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (teksmetadata, soms saamgepers)
- `iCCP` (ICC-profiel) en ander ancillary chunks wat as ’n draer gebruik word
- `eXIf` (EXIF-data in PNG)

### Triage-opdragte
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Waarna om te soek:

- Vreemde width/height/bit-depth/colour-type-kombinasies
- CRC/chunk-foute (`pngcheck` wys gewoonlik na die presiese offset)
- Waarskuwings oor bykomende data ná `IEND`

As jy ’n meer gedetailleerde chunk-aansig benodig:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nuttige verwysings:

- PNG-spesifikasie (struktuur, chunks): https://www.w3.org/TR/PNG/
- Lêerformaat-truuks (PNG/JPEG/GIF-hoekgevalle): https://github.com/corkami/docs

## JPEG: metadata, DCT-domein-tools en ELA-beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit word in die DCT-domein saamgepers. Daarom verskil JPEG stego tools van PNG LSB-tools:

- Metadata-/kommentaar-payloads is lêervlak (high-signal en vinnig om te inspekteer)
- DCT-domein-stego-tools embed bits in frekwensiekoëffisiënte

Operasioneel, behandel JPEG as:

- ’n Houer vir metadata-segmente (high-signal, vinnig om te inspekteer)
- ’n Saamgeperste seindomein (DCT-koëffisiënte) waar gespesialiseerde stego-tools werk

### Vinnige kontroles
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Liggings met 'n hoë seinwaarde:

- EXIF/XMP/IPTC-metadata
- JPEG-kommentaarsegment (`COM`)
- Toepassingsegmente (`APP1` vir EXIF, `APPn` vir verskafferdata)

### Algemene tools

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide payloads in JPEG's te doen kry, oorweeg dit om `stegseek` te gebruik (vinniger bruteforce as ouer scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou na areas wys wat gewysig is, maar dit is nie op sigself 'n stego-detector nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, neem aan dat die boodskap:

- In 'n enkele raam is (maklik), of
- Oor rame versprei is (volgorde is belangrik), of
- Slegs sigbaar is wanneer opeenvolgende rame vergelyk word

### Onttrek rame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandel rame dan soos normale PNG's: `zsteg`, `pngcheck`, kanaalisolasie.

Alternatiewe hulpmiddels:

- `gifsicle --explode anim.gif` (vinnige raamekstraksie)
- `imagemagick`/`magick` vir transformasies per raam

Raamverskilbepaling is dikwels deurslaggewend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG-piekseltelling-enkodering

- Detect APNG-houers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Onttrek rame sonder om die tydsberekening te wysig: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Herwin payloads wat as piekseltellings per raam geënkodeer is:
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
Geanimeerde uitdagings kan elke byte enkodeer as die telling van ’n spesifieke kleur in elke raam; deur die tellings aaneen te skakel, word die boodskap gerekonstrueer.<sup>[[1]](#references)</sup>

## Wagwoordbeskermde embedding

As jy vermoed dat embedding deur ’n passphrase beskerm word eerder as deur pixelvlak-manipulasie, is dit gewoonlik die vinnigste pad.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan geënkripteerde payloads embed/ekstraheer.
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

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Verwysings

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
