# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF image stego val in een van hierdie kategorieë:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Vinnige triage

Prioritiseer kontenervlak-bewyse voor diep inhoudsanalise:

- Valideer die lêer en inspekteer die struktuur: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Ekstraheer metadata en sigbare strings: `exiftool -a -u -g1`, `strings`.
- Kyk vir ingesluit/aangehegte inhoud: `binwalk` en end-of-file inspeksie (`tail | xxd`).
- Vertak volgens kontener:
- PNG/BMP: bit-planes/LSB en chunk-vlak anomalieë.
- JPEG: metadata + DCT-domain gereedskap (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Techniek

PNG/BMP is gewild in CTFs omdat hulle pixels stoor op 'n wyse wat bitvlakmanipulasie maklik maak. Die klassieke verberg/onttrek-meganisme is:

- Elke pixelkanaal (R/G/B/A) het verskeie bits.
- Die minst-beduidende bit (LSB) van elke kanaal verander die beeld baie min.
- Aanvallers verberg data in daardie lae-orde bits, soms met 'n stride, permutasie, of per-kanaal keuse.

Wat om in uitdagings te verwag:

- Die payload is slegs in een kanaal (e.g., `R` LSB).
- Die payload is in die alpha-kanaal.
- Payload is saamgepers/geënkodeer na onttrekking.
- Die boodskap is oor planes versprei of versteek via XOR tussen planes.

Addisionele families wat jy mag teëkom (implementasie-afhanklik):

- **LSB matching** (nie net die bit omdraaien nie, maar +/-1-aanpassings om by die teikenbit te pas)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in kleur-indekse eerder as rou RGB)
- **Alpha-only payloads** (heeltemal onsigbaar in RGB-uitsig)

### Gereedskap

#### zsteg

`zsteg` som baie LSB/bit-plane uittrekmusters vir PNG/BMP op:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer 'n reeks transforms uit (metadata, image transforms, brute forcing LSB-variante).
- `stegsolve`: handmatige visuele filters (kanaal isolasie, plane inspeksie, XOR, ens).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is nie LSB-ekstraksie nie; dit is vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone weggesteek is.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage wat dikwels in CTFs gebruik word:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Tegniek

PNG is 'n chunked formaat. In baie uitdagings word die payload op die container/chunk-vlak gestoor eerder as in pixelwaardes:

- **Ekstra bytes na `IEND`** (baie kykerprogramme ignoreer agterblywende bytes)
- **Nie-standaard ancillary chunks** wat payloads dra
- **Gekorrupte headers** wat dimensies wegsteek of parsers breek totdat dit herstel is

Hoë-signaal chunk-ligginge om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (tekstmetadata, soms gekomprimeer)
- `iCCP` (ICC profile) en ander ancillary chunks wat as draer gebruik word
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Waarop om te kyk:

- Vreemde width/height/bit-depth/colour-type kombinasies
- CRC/chunk errors (pngcheck wys gewoonlik na die presiese offset)
- Waarskuwings oor addisionele data na `IEND`

As jy 'n dieper chunk-uitsig benodig:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Nuttige verwysings:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metagegewens, DCT-domain tools, en ELA-beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit word in die DCT domain gekomprimeer. Daarom verskil JPEG stego tools van PNG LSB tools:

- Metagegewens/kommentaar-payloads is lêervlak (hoog sein en vinnig om te inspekteer)
- DCT-domain stego tools inkorporeer bits in frekwensie-koëffisiënte

Operasioneel, hanteer JPEG as:

- ’n houer vir metagegewens-segmente (hoog sein, vinnig om te inspekteer)
- ’n gekomprimeerde seinedomein (DCT coefficients) waar gespesialiseerde stego tools funksioneer

### Vinnige kontrole
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Hoë-sein lokasies:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Algemene gereedskap

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide payloads in JPEGs te make het, oorweeg om `stegseek` te gebruik (faster bruteforce than older scripts):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou na gebiede lei wat gewysig is, maar dit is nie self 'n stego detector nie:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, veronderstel die boodskap is:

- In 'n enkele raam (maklik), of
- Versprei oor rame (volgorde is belangrik), of
- Slegs sigbaar wanneer jy opeenvolgende rame diff

### Onttrek rame
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Behandel frames dan soos normale PNG's: `zsteg`, `pngcheck`, channel isolation.

Alternatiewe gereedskap:

- `gifsicle --explode anim.gif` (vinnige frame-ekstraksie)
- `imagemagick`/`magick` vir per-frame transformasies

Frame differencing is often decisive:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Wagwoord-beskermde inbedding

As jy vermoed dat die inbedding deur 'n passphrase beskerm word eerder as deur pikselvlakmanipulasie, is dit gewoonlik die vinnigste roete.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the exact contents of src/stego/images/README.md (the markdown you want translated). I will translate the English text to Afrikaans and preserve all code, links, tags, paths and markdown/HTML syntax.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
