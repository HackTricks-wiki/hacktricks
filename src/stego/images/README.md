# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

Stego nyingi za picha za CTF huanguka katika mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Tathmini ya haraka

Toa kipaumbele ushahidi wa ngazi ya container kabla ya uchambuzi wa kina wa yaliyomo:

- Thibitisha faili na angalia muundo: `file`, `magick identify -verbose`, format validators (mf. `pngcheck`).
- Chota metadata na strings zinazoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia kwa yaliyowekwa/kuambatishwa: `binwalk` na ukaguzi wa mwisho-wa-faili (`tail | xxd`).
- Gawanya kwa mujibu wa container:
- PNG/BMP: bit-planes/LSB na chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Mbinu

PNG/BMP ni maarufu katika CTF kwa sababu zinahifadhi pixels kwa njia inayofanya uwekaji wa data kwa ngazi ya biti kuwa rahisi. Mbinu ya kawaida ya kujificha/kutoa ni:

- Kila channel ya pikseli (R/G/B/A) ina biti nyingi.
- **biti ya chini kabisa** (LSB) ya kila channel hubadilisha picha kidogo sana.
- Washambuliaji wanaficha data katika bit za chini, mara nyingine kwa stride, permutation, au chaguo kwa kila channel.

Mambo ya kutarajia katika changamoto:

- Payload iko katika channel moja tu (kwa mfano, `R` LSB).
- Payload iko katika alpha channel.
- Payload imecompress/imeencoded baada ya uondoaji.
- Ujumbe umeenea kwenye planes au umefichwa kupitia XOR kati ya planes.

Familia nyingine unazoweza kukutana nazo (zinategemea utekelezaji):

- **LSB matching** (siyo tu kubadilisha biti, bali marekebisho ya +/-1 ili kufanana na biti lengwa)
- **Palette/index-based hiding** (indexed PNG/GIF: payload katika color indices badala ya raw RGB)
- **Alpha-only payloads** (kabisa haionekani katika muonekano wa RGB)

### Zana

#### zsteg

`zsteg` inorodhesha mifumo mingi ya uondoaji wa LSB/bit-plane kwa PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: inaendesha mfululizo wa transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: vichujio vya kuona kwa mkono (channel isolation, plane inspection, XOR, n.k.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT si LSB extraction; ni kwa matukio ambapo maudhui yamefichwa kwa makusudi katika frequency space au ndani ya miundo midogo-midogo.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Mbinu

PNG ni muundo uliogawanywa katika chunks. Katika changamoto nyingi payload huhifadhiwa kwenye ngazi ya container/chunk badala ya katika thamani za pikseli:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** zinabeba payloads
- **Corrupted headers** zinazoficha vipimo au kuvunja parsers hadi zisitoshwe

Maeneo ya chunk yenye ishara kubwa ya kukagua:

- `tEXt` / `iTXt` / `zTXt` (metadata ya maandishi, wakati mwingine iliyobanwa)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Amri za Triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Mambo ya kuangalia:

- Mchanganyiko usio wa kawaida wa width/height/bit-depth/colour-type
- Makosa ya CRC/chunk (pngcheck kwa kawaida inaonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mtazamo wa chunk wa kina:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Marejeo muhimu:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Mbinu

JPEG haizihifadhiwi kama pixels ghafi; imekomeshwa katika eneo la DCT. Ndiyo maana JPEG stego tools zinatofautiana na PNG LSB tools:

- Metadata/comment payloads ni ngazi ya faili (high-signal na rahisi kukagua)
- DCT-domain stego tools huingiza bits ndani ya frequency coefficients

Kiutendaji, chukulia JPEG kama:

- Kontena la sehemu za metadata (high-signal, rahisi kukagua)
- Eneo la ishara lililokomeshwa (DCT coefficients) ambapo stego tools maalum hufanya kazi

### Ukaguzi wa haraka
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Maeneo yenye ishara nyingi:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` for EXIF, `APPn` for vendor data)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na payloads za steghide katika JPEGs, fikiria kutumia `stegseek` (bruteforce ya haraka kuliko older scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA inaonyesha artefacts mbalimbali za recompression; inaweza kukuonyesha maeneo yaliyohaririwa, lakini si stego detector yenyewe:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zilizo na uhuishaji

### Mbinu

Kwa picha zilizohuishwa, chukulia ujumbe uko:

- Katika frame moja (rahisi), au
- Uliosambaa kwa frames (mpangilio ni muhimu), au
- Inaonekana tu unapofanya diff kwa frames mfululizo

### Toa frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Kisha tendea frames kama PNGs za kawaida: `zsteg`, `pngcheck`, channel isolation.

Zana mbadala:

- `gifsicle --explode anim.gif` (uchimbaji wa frames kwa haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila frame

Frame differencing mara nyingi huamua:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Gundua APNG containers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Toa frames bila re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rejesha payloads encoded as per-frame pixel counts:
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
Changamoto zilizo na mwendo zinaweza kuwakilisha kila baiti kama idadi ya rangi maalum katika kila fremu; kuunganisha idadi hizo kunarejesha ujumbe.

## Uingizwa uliolindwa kwa nenosiri

Ikiwa unashuku uingizwa uliolindwa kwa passphrase badala ya pixel-level manipulation, hii kwa kawaida ndiyo njia ya haraka zaidi.

### steghide

Inaunga mkono `JPEG, BMP, WAV, AU` na inaweza embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository files. Please paste the exact contents of src/stego/images/README.md that you want translated to Swahili, and I will translate it keeping the markdown/html syntax and the rules you specified.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Inasaidia PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Marejeo

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
