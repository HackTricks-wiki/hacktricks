# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

Stego ya picha katika CTF nyingi huangukia katika mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Payloads kwenye metadata/maoni
- Urekebishaji wa hitilafu za PNG chunks
- Zana za JPEG DCT-domain (OutGuess, n.k.)
- Mbinu za kutumia fremu (GIF/APNG)

## Ukaguzi wa haraka

Tanguliza ushahidi wa kiwango cha kontena kabla ya uchanganuzi wa kina wa maudhui:

- Thibitisha faili na kagua muundo: `file`, `magick identify -verbose`, vikagua fomati (k.m., `pngcheck`).
- Toa metadata na maandishi yanayoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia maudhui yaliyopachikwa/kuongezwa: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Chagua mbinu kulingana na kontena:
  - PNG/BMP: bit-planes/LSB na kasoro za kiwango cha chunk.
  - JPEG: metadata na zana za DCT-domain (familia za mtindo wa OutGuess/F5).
  - GIF/APNG: utoaji wa fremu, utofautishaji wa fremu, mbinu za palette.

## Bit-planes / LSB

### Mbinu

PNG/BMP ni maarufu katika CTF kwa sababu huhifadhi pikseli kwa namna inayorahisisha **udanganyifu wa bit-level**. Mbinu ya kawaida ya kuficha/kutoa ni:

- Kila channel ya pikseli (R/G/B/A) ina bits nyingi.
- **Least significant bit** (LSB) ya kila channel hubadilisha picha kwa kiwango kidogo sana.
- Washambuliaji huficha data kwenye bits hizo za mpangilio wa chini, wakati mwingine kwa kutumia stride, permutation au uchaguzi wa channel kwa channel.

Mambo ya kutarajia kwenye changamoto:

- Payload iko kwenye channel moja tu (k.m., LSB ya `R`).
- Payload iko kwenye channel ya alpha.
- Payload imebanwa/imesimbwa baada ya kutolewa.
- Ujumbe umesambazwa kwenye planes au umefichwa kwa kutumia XOR kati ya planes.

Familia nyingine unazoweza kukutana nazo (hutegemea utekelezaji):

- **LSB matching** (si kubadilisha bit tu, bali marekebisho ya +/-1 ili kuendana na bit lengwa)
- **Kuficha kwa kutumia palette/index** (PNG/GIF za indexed: payload kwenye color indices badala ya RGB ghafi)
- **Payload ya alpha pekee** (haionekani kabisa katika mwonekano wa RGB)

### Zana

#### zsteg

`zsteg` huhesabu mifumo mingi ya utoaji wa LSB/bit-plane kwa PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: hutumia mfululizo wa mabadiliko (metadata, mabadiliko ya picha, na kujaribu kwa nguvu variants za LSB).
- `stegsolve`: vichujio vya kuona vinavyotumika kwa mikono (kutenganisha channels, kukagua planes, XOR, n.k.).

Pakua Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Mbinu za kuona kwa kutumia FFT

FFT si uchimbaji wa LSB; hutumika katika hali ambapo maudhui yamefichwa kimakusudi kwenye frequency space au kwenye mifumo fiche.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage inayotegemea wavuti hutumiwa mara nyingi katika CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Mambo ya ndani ya PNG: chunks, uharibifu na data iliyofichwa

### Mbinu

PNG ni umbizo linalotumia chunks. Katika changamoto nyingi, payload huhifadhiwa kwenye kiwango cha container/chunk badala ya thamani za pixels:

- **Baiti za ziada baada ya `IEND`** (viewers nyingi hupuuza baiti zinazofuata)
- **Chunks zisizo za kawaida za ancillary** zinazobeba payloads; tazama [mchakato wa kuchunguza chunks za PNG na kuchonga data](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Headers zilizoharibika** zinazoficha vipimo au kuzuia parsers kufanya kazi hadi zirekebishwe

Maeneo muhimu ya chunks ya kukagua:

- `tEXt` / `iTXt` / `zTXt` (metadata ya maandishi, wakati mwingine imebanwa)
- `iCCP` (ICC profile) na chunks nyingine za ancillary zinazotumika kubeba data
- `eXIf` (data ya EXIF ndani ya PNG)

### Amri za uchunguzi wa awali

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cha kuangalia:

- Mchanganyiko usio wa kawaida wa upana/urefu/bit-depth/colour-type
- Makosa ya CRC/chunk (pngcheck kwa kawaida huonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mwonekano wa kina zaidi wa chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Marejeo muhimu:

- Vipimo vya PNG (muundo, chunks): https://www.w3.org/TR/PNG/
- Mbinu za fomati za faili (hali za kipekee za PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, zana za DCT-domain, na mapungufu ya ELA

### Mbinu

JPEG haihifadhiwi kama pixels ghafi; hubanwa katika DCT domain. Ndiyo sababu zana za JPEG stego hutofautiana na zana za PNG LSB:

- Metadata/comment payloads ziko katika kiwango cha faili (rahisi kugundua na kukagua haraka)
- Zana za DCT-domain hupachika bits katika frequency coefficients

Kwa matumizi ya kawaida, ichukulie JPEG kama:

- Kontena la metadata segments (rahisi kugundua na kukagua haraka)
- Signal domain iliyobanwa (DCT coefficients) ambamo zana maalum za stego hufanya kazi

### Ukaguzi wa haraka

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Maeneo yenye viashiria vingi:

- Metadata ya EXIF/XMP/IPTC
- Segmenti ya maoni ya JPEG (`COM`)
- Segmenti za programu (`APP1` za EXIF, `APPn` za data ya vendor)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakabiliwa mahsusi na payload za steghide kwenye JPEG, zingatia kutumia `stegseek` (bruteforce ya kasi zaidi kuliko script za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Uchambuzi wa Kiwango cha Hitilafu

ELA huonyesha tofauti za artifacts za recompression; inaweza kukuongoza kwenye maeneo yaliyohaririwa, lakini yenyewe si detector ya stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zilizohuishwa

### Mbinu

Kwa picha zilizohuishwa, chukulia kuwa ujumbe:

- Uko kwenye fremu moja (rahisi), au
- Umesambazwa kwenye fremu (mpangilio ni muhimu), au
- Unaonekana tu unapofanya diff ya fremu zinazofuatana

### Toa fremu

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Kisha shughulikia fremu kama PNG za kawaida: `zsteg`, `pngcheck`, kutenganisha chaneli.

Zana mbadala:

- `gifsicle --explode anim.gif` (utoaji wa fremu haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila fremu

Kulinganisha tofauti za fremu mara nyingi hutoa jibu la mwisho:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Usimbaji wa APNG kwa idadi ya pikseli

- Tambua kontena za APNG: `exiftool -a -G1 file.png | grep -i animation` au `file`.
- Toa fremu bila kubadilisha muda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rejesha payloads zilizosimbwa kama idadi ya pikseli kwa kila fremu:

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

Changamoto za uhuishaji zinaweza kusimba kila byte kama idadi ya rangi maalum katika kila fremu; kuunganisha idadi hizo kunaunda upya ujumbe.<sup>[[1]](#references)</sup>

## Uingizaji unaolindwa kwa nenosiri

Ikiwa unashuku kuwa data imefichwa kwa kutumia passphrase badala ya mabadiliko katika kiwango cha pixel, hii kwa kawaida ndiyo njia ya haraka zaidi.

### steghide

Inasaidia `JPEG, BMP, WAV, AU` na inaweza kuficha/kutoa payloads zilizosimbwa kwa njia fiche.

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



## References

- [1] [Flagvent 2025 (Medium) — pink, Orodha ya Matamanio ya Santa, Metadata ya Krismasi, Kelele Iliyorekodiwa](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
