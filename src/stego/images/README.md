# Steganography ya Picha

{{#include ../../banners/hacktricks-training.md}}

CTF image stego nyingi huangukia katika mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage ya haraka

Paisha ushahidi wa kiwango cha container kabla ya uchanganuzi wa kina wa maudhui:

- Thibitisha faili na kagua muundo: `file`, `magick identify -verbose`, format validators (mfano, `pngcheck`).
- Extract metadata na strings zinazoonekana: `exiftool -a -u -g1`, `strings`.
- Kagua content iliyopachikwa au kuongezwa: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Gawa kulingana na container:
- PNG/BMP: bit-planes/LSB na anomalies za kiwango cha chunk.
- JPEG: metadata + DCT-domain tooling (families za mtindo wa OutGuess/F5).
- GIF/APNG: frame extraction, frame differencing, palette tricks.

## Bit-planes / LSB

### Mbinu

PNG/BMP ni maarufu katika CTFs kwa sababu huhifadhi pixels kwa njia inayorahisisha **bit-level manipulation**. Mechanism ya kawaida ya kuficha/kutoa ni:

- Kila pixel channel (R/G/B/A) ina bits nyingi.
- **Least significant bit** (LSB) ya kila channel hubadilisha picha kwa kiwango kidogo sana.
- Washambuliaji huficha data katika bits hizo za mpangilio wa chini, wakati mwingine kwa kutumia stride, permutation, au uchaguzi wa channel kwa channel.

Mambo ya kutarajia katika challenges:

- Payload iko katika channel moja pekee (kwa mfano, `R` LSB).
- Payload iko katika alpha channel.
- Payload ime-compressiwa/encoded baada ya extraction.
- Ujumbe umeenezwa katika planes au umefichwa kupitia XOR kati ya planes.

Familia za ziada unazoweza kukutana nazo (inategemea implementation):

- **LSB matching** (si kubadilisha bit pekee, bali kutumia marekebisho ya +/-1 ili kuendana na target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload iko katika color indices badala ya raw RGB)
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
- `stegsolve`: manual visual filters (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Mbinu za kuonyesha zinazotumia FFT

FFT si LSB extraction; hutumika katika hali ambapo content imefichwa kimakusudi kwenye frequency space au patterns zisizo dhahiri.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage hutumiwa mara nyingi katika CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Mihimili ya ndani ya PNG: chunks, corruption, na hidden data

### Mbinu

PNG ni format yenye chunks. Katika challenges nyingi, payload huhifadhiwa kwenye kiwango cha container/chunk badala ya pixel values:

- **Extra bytes baada ya `IEND`** (viewers wengi hupuuza trailing bytes)
- **Non-standard ancillary chunks** zenye payloads
- **Corrupted headers** zinazoficha dimensions au kuvuruga parsers hadi zirekebishwe

Maeneo ya chunks yenye signal kubwa ya kukaguliwa:

- `tEXt` / `iTXt` / `zTXt` (text metadata, wakati mwingine ikiwa compressed)
- `iCCP` (ICC profile) na ancillary chunks nyingine zinazotumiwa kama carrier
- `eXIf` (EXIF data katika PNG)

### Amri za Triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Cha kutafuta:

- Michanganyiko isiyo ya kawaida ya width/height/bit-depth/colour-type
- Hitilafu za CRC/chunk (`pngcheck` kwa kawaida huonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mwonekano wa kina zaidi wa chunk:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Marejeo muhimu:

- PNG specification (muundo, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Technique

JPEG haihifadhiwi kama pixels ghafi; hubanwa katika DCT domain. Ndiyo sababu JPEG stego tools hutofautiana na PNG LSB tools:

- Metadata/comment payloads huwa katika kiwango cha faili (high-signal na rahisi kukagua)
- DCT-domain stego tools huingiza bits katika frequency coefficients

Kiutendaji, ichukulie JPEG kama:

- Container ya metadata segments (high-signal, rahisi kukagua)
- Compressed signal domain (DCT coefficients) ambamo specialized stego tools hufanya kazi

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Maeneo yenye signal ya juu:

- Metadata ya EXIF/XMP/IPTC
- Sehemu ya maoni ya JPEG (`COM`)
- Sehemu za application (`APP1` kwa EXIF, `APPn` kwa data ya vendor)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakabiliwa hasa na steghide payloads kwenye JPEGs, fikiria kutumia `stegseek` (bruteforce ya haraka kuliko scripts za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Uchambuzi wa Kiwango cha Hitilafu

ELA huonyesha artifacts tofauti za recompression; inaweza kukuelekeza kwenye maeneo yaliyohaririwa, lakini si stego detector yenyewe:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zenye uhuishaji

### Mbinu

Kwa picha zenye uhuishaji, chukulia kwamba ujumbe uko:

- Kwenye frame moja (rahisi), au
- Umesambazwa kwenye frames (mpangilio ni muhimu), au
- Unaonekana tu unapofanya diff ya frames zinazofuatana

### Toa frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Kisha shughulikia frames kama PNG za kawaida: `zsteg`, `pngcheck`, channel isolation.

Zana mbadala:

- `gifsicle --explode anim.gif` (uchimbaji wa frames kwa haraka)
- `imagemagick`/`magick` kwa transforms za kila frame

Frame differencing mara nyingi huwa na umuhimu wa kuamua:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### APNG pixel-count encoding

- Detect APNG containers: `exiftool -a -G1 file.png | grep -i animation` au `file`.
- Extract frames without re-timing: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Recover payloads encoded as per-frame pixel counts:
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
Changamoto za animated zinaweza ku-encode kila byte kama idadi ya rangi maalum katika kila frame; kuunganisha hesabu hizo kunaunda upya ujumbe.<sup>[[1]](#references)</sup>

## Uingizaji unaolindwa na nenosiri

Ikiwa unashuku kuwa uingizaji umelindwa na passphrase badala ya pixel-level manipulation, hii kwa kawaida ndiyo njia ya haraka zaidi.

### steghide

Inaunga mkono `JPEG, BMP, WAV, AU` na inaweza ku-embed/extract payloads zilizosimbwa.
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
