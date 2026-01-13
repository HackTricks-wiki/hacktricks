# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF image stego val in een van hierdie kategorieë:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Vinnige triage

Gee prioriteit aan kontainervlakbewyse voordat jy die inhoud diep ontleed:

- Valideer die lêer en ondersoek die struktuur: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Trek metadata en sigbare strings uit: `exiftool -a -u -g1`, `strings`.
- Kyk vir ingeslote/toegevoegde inhoud: `binwalk` en end-of-file inspeksie (`tail | xxd`).
- Vertak volgens kontainer:
- PNG/BMP: bit-planes/LSB en chunk-vlak anomalieë.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Tegniek

PNG/BMP is gewild in CTFs omdat hulle pixels stoor op 'n manier wat bitvlak-manipulasie maklik maak. Die klassieke verberg/uittrek-meganisme is:

- Elke pixelkanaal (R/G/B/A) het meerdere bits.
- Die **least significant bit** (LSB) van elke kanaal verander die beeld baie min.
- Aanvallers verberg data in daardie lae-orde-bits, soms met 'n stride, permutasie, of per-kanaal keuse.

Wat om te verwag in challenges:

- Die payload is slegs in een kanaal (bv. `R` LSB).
- Die payload is in die alpha channel.
- Payload is gecomprimeer/geënkodeer na uittrekking.
- Die boodskap is oor vlakke versprei of verberg deur XOR tussen vlakke.

Addisionele families wat jy mag teëkom (implementering-afhanklik):

- **LSB matching** (nie net die bit omdraai nie, maar +/-1-aanpassings om by die teikenbit te pas)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in kleurindekse eerder as rou RGB)
- **Alpha-only payloads** (heeltemal onsigbaar in RGB-uitsig)

### Tooling

#### zsteg

`zsteg` som baie LSB/bit-plane uittrekmuster op vir PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer 'n reeks transformaties uit (metadata, beeldtransformasies, brute forcing LSB variants).
- `stegsolve`: handmatige visuele filters (kanaalisolasie, plane-inspeksie, XOR, ens.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-gebaseerde sigbaarheidstrieke

FFT is nie LSB-ekstraksie nie; dit is vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone weggesteek word.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage wat dikwels in CTFs gebruik word:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG interne: chunks, korrupsie, en verborge data

### Tegniek

PNG is 'n chunked-formaat. In baie uitdagings word die payload op die container/chunk-vlak gestoor eerder as in pixelwaardes:

- **Extra bytes after `IEND`** (baie kykprogramme ignoreer aanhangende bytes)
- **Non-standard ancillary chunks** wat payloads dra
- **Corrupted headers** wat dimensies wegsteek of parsers laat breek totdat dit reggemaak word

Hoogsignaal chunk-ligginge om na te kyk:

- `tEXt` / `iTXt` / `zTXt` (teksmetadata, soms gecomprimeer)
- `iCCP` (ICC-profiel) en ander ancillary chunks wat as draer gebruik word
- `eXIf` (EXIF-data in PNG)

### Triage-kommando's
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Waar om na te soek:

- Vreemde breedte/hoogte/bit-diepte/kleurtipe-kombinasies
- CRC/chunk-foute (pngcheck wys gewoonlik na die presiese offset)
- Waarskuwings oor bykomende data na `IEND`

As jy 'n dieper chunk-oorsig nodig het:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nuttige verwysings:

- PNG spesifikasie (struktuur, chunks): https://www.w3.org/TR/PNG/
- Truuks vir lêerformate (PNG/JPEG/GIF randgevalle): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, en ELA-beperkings

### Tegniek

JPEG word nie as ruwe pixels gestoor nie; dit is saamgepers in die DCT-domein. Daarom verskil JPEG stego tools van PNG LSB tools:

- Metadata/comment payloads is op lêervlak (hoë sein en vinnig om te inspekteer)
- DCT-domain stego tools voeg bits in frekwensie-koëffisiënte in

Operasioneel, beskou JPEG as:

- 'n houer vir metadata-segmente (hoë sein, vinnig om te inspekteer)
- 'n saamgeperste sein-domein (DCT-koëffisiënte) waar gespesialiseerde stego tools werk

### Vinnige kontroles
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Hoë-sein liggings:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Algemene gereedskap

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek te make het met steghide payloads in JPEGs, oorweeg om `stegseek` te gebruik (vinnigere bruteforce as ouer skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou na gebiede wys wat gewysig is, maar dit is op sigself nie 'n stego-detektor nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, veronderstel die boodskap is:

- In 'n enkele raam (maklik), of
- Versprei oor rame (volgorde is belangrik), of
- Slegs sigbaar wanneer jy diff opeenvolgende rame

### Ekstraheer rame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandel dan rame soos normale PNGs: `zsteg`, `pngcheck`, channel isolation.

Alternatiewe gereedskap:

- `gifsicle --explode anim.gif` (vinnige raam-ekstraksie)
- `imagemagick`/`magick` vir per-raam transformasies

Frame differencing is dikwels beslissend:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Detecteer APNG containers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Ekstraheer frames sonder her-tydstelling: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Herwin payloads wat gekodeer is as pikseltellings per frame:
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
Geanimeerde uitdagings kan elke byte enkodeer as die telling van 'n spesifieke kleur in elke raam; deur die tellings aanmekaar te koppel, word die boodskap herbou.

## Wagwoord-beskermde embedding

As jy vermoed dat die embedding deur 'n passphrase beskerm word eerder as deur pikselvlakmanipulasie, is dit gewoonlik die vinnigste pad.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan geënkripteerde payloads embed/extract.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I can't fetch files from the repository directly. Please paste the full contents of src/stego/images/README.md here (the markdown text you want translated). I'll translate the relevant English text to Afrikaans and preserve all markdown, links, paths and tags exactly as you requested.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Verwysings

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
