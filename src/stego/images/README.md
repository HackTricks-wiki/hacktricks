# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

Wengi wa image stego za CTF hupunguka kwenye mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Tathmini ya haraka

Toa kipaumbele kwa ushahidi wa ngazi ya container kabla ya uchambuzi wa kina wa yaliyomo:

- Thibitisha faili na chunguza muundo: `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Chukua metadata na vigezo vinavyoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia kwa maudhui yaliyowekwa/yaliyowekewa: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Gawa kulingana na container:
- PNG/BMP: bit-planes/LSB na anomali za chunk-level.
- JPEG: metadata + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: uchimbaji wa fremu, frame differencing, mbinu za palette.

## Bit-planes / LSB

### Mbinu

PNG/BMP zinapendwa katika CTF kwa sababu zinaweka pikseli kwa njia inayofanya **mabadiliko ya ngazi ya biti** kuwa rahisi. Mchakato wa kawaida wa kuficha/kuchukua ni:

- Kila chaneli ya pikseli (R/G/B/A) ina bits nyingi.
- The **least significant bit** (LSB) ya kila chaneli hubadilisha picha kidogo sana.
- Wavamizi huficha data katika bits hizo za ngazi ya chini, wakati mwingine kwa stride, permutation, au uchaguzi kwa kila chaneli.

Mambo ya kutarajia katika changamoto:

- Payload iko kwenye chaneli moja tu (mfano, `R` LSB).
- Payload iko kwenye alpha channel.
- Payload imekandwa/imekodwa baada ya kutolewa.
- Ujumbe umeenea kote katika planes au umefichwa kwa kutumia XOR kati ya planes.

Aina nyingine utakazokutana nazo (zinategemea utekelezaji):

- **LSB matching** (si tu kugeuza biti, bali marekebisho ya +/-1 ili kufanana na biti lengwa)
- **Palette/index-based hiding** (indexed PNG/GIF: payload katika viashiria vya rangi badala ya raw RGB)
- **Alpha-only payloads** (kabisa isiyoonekana katika muonekano wa RGB)

### Zana

#### zsteg

`zsteg` inaorodhesha mifumo mingi ya uondoaji wa LSB/bit-plane kwa PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: inaendesha mfululizo wa transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: filters za kuona za mkono (channel isolation, plane inspection, XOR, etc).

Kupakua Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT si utaratibu wa kutoa LSB; inatumika katika kesi ambapo yaliyomo yamefichwa kwa makusudi katika frequency space au katika mifumo midogo.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage za mtandaoni zinazotumika mara kwa mara katika CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Ndani ya PNG: chunks, uharibifu, na data zilizofichwa

### Mbinu

PNG ni format yenye chunks. Katika changamoto nyingi payload huhifadhiwa kwenye ngazi ya container/chunk badala ya katika thamani za pixel:

- **Bytes za ziada baada ya `IEND`** (programu nyingi za kuonyesha hupuuzia trailing bytes)
- **Non-standard ancillary chunks** zinabeba payloads
- **Headers zilizoharibika** ambazo zinaficha dimensions au kuvunja parsers hadi zitakaposahihishwa

Maeneo ya chunks yenye ishara za juu ya kukagua:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (ICC profile) na chunks nyingine za ancillary zinazotumika kama carrier
- `eXIf` (EXIF data in PNG)

### Amri za triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Vitu vya kuangalia:

- Mchanganyiko wa ajabu wa width/height/bit-depth/colour-type
- Makosa ya CRC/chunk (pngcheck kwa kawaida inaonyesha offset kamili)
- Onyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji muonekano wa chunk wa kina zaidi:
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Marejeo muhimu:

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG: metadata, DCT-domain tools, and ELA limitations

### Mbinu

JPEG haijihifadhi kama pixels ghafi; imefinywa katika DCT domain. Ndiyo maana JPEG stego tools zinatofautiana na PNG LSB tools:

- Metadata/comment payloads ni za ngazi ya faili (high-signal na rahisi kuzipitia)
- DCT-domain stego tools huingiza bits ndani ya frequency coefficients

Kitekelezaji, chukulia JPEG kama:

- Kontena kwa metadata segments (high-signal, rahisi kuzipitia)
- Sehemu ya ishara iliyofinywa (DCT coefficients) ambapo stego tools maalum hufanya kazi

### Ukaguzi wa haraka
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Maeneo yenye ishara nyingi:

- EXIF/XMP/IPTC metadata
- Sehemu ya maoni ya JPEG (`COM`)
- Sehemu za Application (`APP1` for EXIF, `APPn` for vendor data)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na steghide payloads katika JPEGs, fikiria kutumia `stegseek` (bruteforce ya haraka kuliko scripts za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA inaonyesha artefakti tofauti za recompression; inaweza kukuonyesha maeneo yaliyohaririwa, lakini yenyewe si kigunduzi cha stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zenye uhuishaji

### Mbinu

Kwa picha zenye uhuishaji, chukua kuwa ujumbe uko:

- Katika fremu moja (rahisi), au
- Umegawanywa kwa fremu (mpangilio una maana), au
- Unaonekana tu unapofanya diff kwa fremu mfululizo

### Chukua fremu
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Kisha chukulia frames kama PNG za kawaida: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (uchimbaji wa frames wa haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila frame

Kutofautisha frames mara nyingi huwa muhimu:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Password-protected embedding

Ikiwa unadhani embedding imefungwa kwa passphrase badala ya pixel-level manipulation, hii kawaida ndiyo njia ya haraka zaidi.

### steghide

Inasaidia `JPEG, BMP, WAV, AU` na inaweza embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
I don't have access to the repository contents. Please paste the exact contents of src/stego/images/README.md (or at least the "### StegCracker" section) here and I will translate the relevant English text to Swahili, preserving all markdown, tags, links and code exactly as requested.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Inaunga mkono PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
