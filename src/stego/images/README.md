# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

CTF nyingi za image stego hupungua kuwa mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Payloads za metadata/comments
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, n.k.)
- Frame-based (GIF/APNG)

## Quick triage

Tanguliza ushahidi wa kiwango cha container kabla ya deep content analysis:

- Thibitisha file na kagua structure: `file`, `magick identify -verbose`, format validators (k.m., `pngcheck`).
- Extract metadata na visible strings: `exiftool -a -u -g1`, `strings`.
- Kagua embedded/appended content: `binwalk` na ukaguzi wa mwisho wa file (`tail | xxd`).
- Gawa kulingana na container:
- PNG/BMP: bit-planes/LSB na chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP ni maarufu katika CTF kwa sababu huhifadhi pixels kwa njia inayorahisisha **bit-level manipulation**. Njia ya kawaida ya kuficha/kutoa data ni:

- Kila pixel channel (R/G/B/A) ina bits nyingi.
- **Least significant bit** (LSB) ya kila channel hubadilisha image kwa kiwango kidogo sana.
- Attackers huficha data kwenye low-order bits hizo, wakati mwingine kwa stride, permutation, au uchaguzi wa kila channel.

Mambo ya kutarajia katika challenges:

- Payload iko kwenye channel moja pekee (k.m., `R` LSB).
- Payload iko kwenye alpha channel.
- Payload ime-compress/encoded baada ya extraction.
- Message imesambazwa katika planes au imefichwa kwa kutumia XOR kati ya planes.

Familia za ziada unazoweza kukutana nazo (kulingana na implementation):

- **LSB matching** (si kubadilisha bit pekee, bali kutumia marekebisho ya +/-1 ili kulinganisha target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload iko kwenye color indices badala ya raw RGB)
- **Alpha-only payloads** (haionekani kabisa katika RGB view)

### Tooling

#### zsteg

`zsteg` huorodhesha extraction patterns nyingi za LSB/bit-plane kwa PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: huendesha mfululizo wa transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: visual filters za manual (channel isolation, plane inspection, XOR, n.k.).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT si LSB extraction; hutumika katika hali ambapo content imefichwa kimakusudi kwenye frequency space au patterns hafifu.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage hutumiwa mara nyingi kwenye CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG ni format yenye chunks. Katika challenges nyingi, payload huhifadhiwa kwenye kiwango cha container/chunk badala ya pixel values:

- **Extra bytes after `IEND`** (viewers wengi hupuuza trailing bytes)
- **Non-standard ancillary chunks** zinazobeba payloads
- **Corrupted headers** zinazoficha dimensions au kuvuruga parsers hadi zirekebishwe

High-signal chunk locations za kukagua:

- `tEXt` / `iTXt` / `zTXt` (text metadata, wakati mwingine compressed)
- `iCCP` (ICC profile) na ancillary chunks nyingine zinazotumika kama carrier
- `eXIf` (EXIF data katika PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cha kutafuta:

- Mchanganyiko usio wa kawaida wa `width`/`height`/`bit-depth`/`colour-type`
- Makosa ya CRC/chunk (`pngcheck` kwa kawaida huonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mwonekano wa kina zaidi wa chunks:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Marejeo muhimu:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Mbinu

JPEG haihifadhiwi kama raw pixels; imebanwa katika DCT domain. Ndiyo sababu JPEG stego tools hutofautiana na PNG LSB tools:

- Metadata/comment payloads ziko katika kiwango cha faili (high-signal na ni rahisi kukagua)
- DCT-domain stego tools huingiza bits kwenye frequency coefficients

Kiutendaji, ichukulie JPEG kama:

- Container ya metadata segments (high-signal, ni rahisi kukagua)
- Compressed signal domain (DCT coefficients) ambako specialized stego tools hufanya kazi

### Ukaguzi wa haraka
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Maeneo yenye ishara muhimu:

- EXIF/XMP/IPTC metadata
- JPEG comment segment (`COM`)
- Application segments (`APP1` kwa EXIF, `APPn` kwa vendor data)

### Tools za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na steghide payloads katika JPEGs, fikiria kutumia `stegseek` (bruteforce ya haraka kuliko scripts za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA huangazia artifacts tofauti za recompression; inaweza kukuonyesha maeneo yaliyohaririwa, lakini si stego detector yenyewe:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zinazojiendesha

### Technique

Kwa picha zinazojiendesha, chukulia kuwa ujumbe:

- Uko katika frame moja (rahisi), au
- Umesambazwa katika frames (mpangilio ni muhimu), au
- Unaonekana tu unapofanya diff ya frames zinazofuatana

### Extract frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Kisha shughulikia fremu kama PNG za kawaida: `zsteg`, `pngcheck`, utenganishaji wa channel.

Zana mbadala:

- `gifsicle --explode anim.gif` (uchimbaji wa fremu kwa haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila fremu

Ulinganishaji wa tofauti kati ya fremu mara nyingi huwa wa kuamua:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Usimbaji wa APNG kwa kuhesabu pikseli

- Tambua kontena za APNG: `exiftool -a -G1 file.png | grep -i animation` au `file`.
- Toa fremu bila kubadilisha muda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rejesha payloads zilizowekwa msimbo kama idadi ya pikseli kwa kila fremu:
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
Changamoto za picha zilizohuishwa zinaweza kuweka kila byte kama idadi ya rangi fulani katika kila fremu; kuunganisha hesabu hizo hurejesha ujumbe.<sup>[[1]](#references)</sup>

## Uwekaji unaolindwa kwa nenosiri

Ikiwa unashuku kuwa embedding inalindwa na passphrase badala ya pixel-level manipulation, hii kwa kawaida ndiyo njia ya haraka zaidi.

### steghide

Inaauni `JPEG, BMP, WAV, AU` na inaweza ku-embed/extract payloads zilizosimbwa.
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

Inasaidia PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Marejeo

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
