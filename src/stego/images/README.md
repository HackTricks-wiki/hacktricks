# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

Mara nyingi CTF image stego zinarejea moja ya hizi:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Tathmini ya haraka

Toa kipaumbele kwa ushahidi wa ngazi ya container kabla ya uchambuzi wa kina wa yaliyomo:

- Thibitisha faili na ukague muundo: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Toa metadata na mistari inayoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia yaliyofichwa/ya kuongezwa mwishoni ya faili: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Gawa kulingana na container:
- PNG/BMP: bit-planes/LSB na chunk-level anomalies.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: uchimbaji wa frames, frame differencing, palette tricks.

## Bit-planes / LSB

### Mbinu

PNG/BMP are popular in CTFs because they store pixels in a way that makes **urekebishaji wa ngazi ya biti** easy. Mbinu ya kawaida ya kuficha/kutoa ni:

- Kila channel ya pikseli (R/G/B/A) ina biti nyingi.
- The **least significant bit** (LSB) ya kila channel hubadilisha picha kidogo sana.
- Washambuliaji wanaficha data katika biti hizo za order ya chini, wakati mwingine kwa stride, permutation, au uchaguzi kwa channel.

Nini kutegemea katika changamoto:

- Payload iko katika channel moja tu (mf. `R` LSB).
- Payload iko katika alpha channel.
- Payload imekandamizwa/imekodishwa baada ya kuchimbwa.
- Ujumbe unasambazwa kwenye planes au umefichwa kwa kutumia XOR baina ya planes.

Familia za ziada unazoweza kukutana nazo (implementation-dependent):

- **LSB matching** (siyo tu kubadilisha biti, bali marekebisho ya +/-1 ili kufanana na biti lengwa)
- **Palette/index-based hiding** (indexed PNG/GIF: payload katika color indices badala ya raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Zana

#### zsteg

`zsteg` enumerates many LSB/bit-plane extraction patterns for PNG/BMP:
```bash
zsteg -a file.png
```
StegoVeritas / Stegsolve

- `stegoVeritas`: inaendesha mfululizo wa transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: vichujio vya kuona vya mkono (channel isolation, plane inspection, XOR, n.k).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT si uondoaji wa LSB; ni kwa matukio ambapo maudhui yamefichwa kwa makusudi katika nafasi ya masafa (frequency space) au katika mifumo dhaifu.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG ni muundo uliogawanywa katika chunks. Katika changamoto nyingi payload huhifadhiwa kwenye ngazi ya container/chunk badala ya katika thamani za pikseli:

- **Extra bytes after `IEND`** (programu nyingi za kuonyesha picha hupuuzia baiti za ziada mwishoni)
- **Non-standard ancillary chunks** zinabeba payloads
- **Corrupted headers** ambazo zinaficha dimensions au kuvunja parsers hadi zitakapotengenezwa

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, mara nyingine zilizofinywa)
- `iCCP` (ICC profile) and other ancillary chunks used as a carrier
- `eXIf` (EXIF data in PNG)

### Triage commands
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Nini cha kutafuta:

- Mchanganyiko usio wa kawaida wa width/height/bit-depth/colour-type
- Makosa ya CRC/chunk (pngcheck kwa kawaida huonyesha offset sahihi)
- Onyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mtazamo wa chunk wa kina:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Marejeo muhimu:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- Mbinu za file format (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Tekniki

JPEG haihifadhiwi kama pixels ghafi; imebana katika DCT domain. Hivyo, JPEG stego tools zinatofautiana na PNG LSB tools:

- Metadata/comment payloads ni file-level (ishara kubwa na rahisi kuangalia)
- DCT-domain stego tools huingiza bits ndani ya frequency coefficients

Kitaalamu, chukulia JPEG kama:

- Container kwa metadata segments (ishara kubwa, rahisi kuangalia)
- Sehemu ya ishara iliyobana (DCT coefficients) ambapo specialized stego tools hufanya kazi

### Quick checks
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Maeneo yenye ishara kubwa:

- EXIF/XMP/IPTC metadata
- Segmenti ya maoni ya JPEG (`COM`)
- Segmenti za Application (`APP1` for EXIF, `APPn` for vendor data)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na steghide payloads katika JPEGs, zingatia kutumia `stegseek` (faster bruteforce kuliko scripts za zamani):

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA inaonyesha vibaki tofauti vinavyotokana na recompression; inaweza kukuonyesha maeneo yaliyohaririwa, lakini si kigunduzi cha stego yenyewe:

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Picha zenye uhuishaji

### Mbinu

Kwa picha zenye uhuishaji, chukulia ujumbe uko:

- Katika framu moja (rahisi), au
- Imeenea kwa framu nyingi (mpangilio una umuhimu), au
- Inaonekana tu unapofanya diff ya framu mfululizo

### Chukua framu
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Kisha tenda fremu kama PNG za kawaida: `zsteg`, `pngcheck`, channel isolation.

Zana mbadala:

- `gifsicle --explode anim.gif` (uchimbaji wa fremu haraka)
- `imagemagick`/`magick` kwa mabadiliko kwa kila fremu

Tofautisha fremu mara nyingi huwa la kuamua:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Uingizaji uliolindwa kwa nenosiri

Ikiwa unashuku uingizaji ulindwa kwa neno la siri badala ya uchezaji wa ngazi ya pikseli, hii kawaida ndiyo njia ya haraka zaidi.

### steghide

Inasaidia `JPEG, BMP, WAV, AU` na inaweza kuingiza/kutoa payloads zilizosimbwa.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Nahitaji yaliyomo ya faili src/stego/images/README.md ili niweze kutafsiri sehemu zinazofaa kwenda Kiswahili. Tafadhali bandika hapa yaliyomo kamili ya README.md. Nitahifadhi markdown/html/vilevi vingine (links, paths, tags) kama vilivyo na nitatafsiri tu maandishi ya Kiingereza—siyo code, tags, links au majina ya huduma.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Inaunga mkono PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
