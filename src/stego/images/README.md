# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

Stego ya picha katika CTF nyingi huangukia katika mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Payload za metadata/maoni
- Hitilafu za PNG chunk / kurekebisha uharibifu
- Zana za JPEG DCT-domain (OutGuess, n.k.)
- Zinazotumia fremu (GIF/APNG)

## Uchunguzi wa haraka

Tanguliza ushahidi wa kiwango cha container kabla ya kuchambua maudhui kwa kina. Tazama [mtiririko wa jumla wa stego](../workflow/) kwa utambuzi wa faili na uchimbaji wa data kabla ya kufanya majaribio mahususi ya picha.

- Thibitisha faili na kagua muundo: `file`, `magick identify -verbose`, validators za format (k.m., `pngcheck`).
- Toa metadata na maandishi yanayoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia maudhui yaliyopachikwa/yaliyoongezwa: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Chagua njia kulingana na container:
  - PNG/BMP: bit-planes/LSB na hitilafu za kiwango cha chunk.
  - JPEG: metadata + zana za DCT-domain (familia za mtindo wa OutGuess/F5).
  - GIF/APNG: kutoa fremu, kulinganisha tofauti za fremu, mbinu za palette.

## Bit-planes / LSB

### Mbinu

PNG/BMP ni maarufu katika CTF kwa sababu huhifadhi pikseli kwa namna inayorahisisha **udanganyifu wa kiwango cha bit**. Mbinu ya kawaida ya kuficha/kutoa ni:

- Kila channel ya pikseli (R/G/B/A) ina bit nyingi.
- **Bit isiyo na uzito mkubwa zaidi** (LSB) ya kila channel hubadilisha picha kwa kiwango kidogo sana.
- Washambuliaji huficha data katika bit hizo za chini, wakati mwingine kwa kutumia hatua maalum, mpangilio upya, au kuchagua channel mahususi.

Mambo ya kutarajia katika changamoto:

- Payload iko kwenye channel moja tu (k.m., LSB ya `R`).
- Payload iko kwenye alpha channel.
- Payload hubanwa/huwekwa msimbo baada ya kutolewa.
- Ujumbe husambazwa kwenye planes au kufichwa kupitia XOR kati ya planes.

Familia nyingine unazoweza kukutana nazo (hutegemea utekelezaji):

- **LSB matching** (si kubadilisha bit tu, bali kurekebisha kwa +/-1 ili kuendana na bit lengwa)
- **Kuficha kwa kutumia palette/index** (PNG/GIF za indexed: payload hufichwa kwenye color indices badala ya RGB ghafi)
- **Payload za alpha pekee** (hazionekani kabisa kwenye mwonekano wa RGB)

### Indices za palette ya rangi zilizoorodheshwa

PNG au GIF ya indexed huhifadhi **index** ya palette kwa kila pikseli, si RGB triplet. Indices mbili zinaweza kuonyesha rangi ileile, hivyo kubadilisha kuwa RGB kabla ya uchanganuzi kunaweza kufuta tofauti iliyofichwa. Kagua entries za palette zinazojirudia au zinazokaribiana, kisha tengeneza binary mask ya pikseli zinazotumia kila index inayotia shaka. Mbinu hii imefichua maandishi yaliyofichwa na mabadiliko ya QR code katika changamoto za hivi karibuni za GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Kwa PNG ya indexed yenye fremu moja (au **fremu ya kwanza** ya GIF), dumisha hali ya Pillow `P` na ubadilishe `target` iwe index ya kuvutia iliyoripotiwa na script. Kagua uwazi (`tRNS` au index ya uwazi ya GIF) pamoja na RGB unapochagua indices.<sup>[[3]](#references)[[5]](#references)</sup>

```python
from PIL import Image
im = Image.open("suspect.png")
assert im.mode == "P", "requires indexed pixels; do not convert to RGB"
used = sorted(set(im.getdata()))
palette = im.getpalette()
for i in used:
    same = [j for j in used if j != i and palette[3*i:3*i+3] == palette[3*j:3*j+3]]
    if same:
        print(i, "shares RGB with", same)
target = 1  # replace with an index to isolate
mask = bytes(255 if i == target else 0 for i in im.getdata())
Image.frombytes("L", im.size, mask).save("index-mask.png")
```

Kwa GIF zilizohuishwa, kagua fremu moja baada ya nyingine. Pillow kwa kawaida hubadilisha fremu zinazofuata kuwa RGB/RGBA wakati wa kuzichanganya; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` huhifadhi hali ya `P` ikiwa tu palette haibadiliki. Ikiwa fremu ina palette ya ndani au tayari imechanganywa, kagua data asili ya fremu yenye faharasa badala ya kuchukulia pikseli zilizobadilishwa kuwa RGB kama faharasa.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Zana

#### zsteg

`zsteg` huhesabu mifumo mingi ya uchimbaji wa LSB/bit-plane kwa PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: huendesha mfululizo wa mabadiliko (metadata, mabadiliko ya picha, na kujaribu kwa nguvu tofauti za LSB).
- `stegsolve`: vichujio vya kuona vinavyotumika kwa mikono (kutenga channel, kukagua planes, XOR, n.k.).

Pakua Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Mbinu za kutumia FFT kuonyesha yaliyofichwa

FFT si njia ya kutoa LSB; hutumika pale maudhui yanapofichwa kimakusudi kwenye frequency space au mifumo fiche.

- Demo ya EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage inayotegemea wavuti hutumiwa mara nyingi katika CTF:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Undani wa PNG: chunks, uharibifu, na data iliyofichwa

### Mbinu

PNG ni format inayoundwa na chunks. Katika changamoto nyingi, payload huhifadhiwa kwenye kiwango cha container/chunk badala ya thamani za pixel:

- **Baiti za ziada baada ya `IEND`** (viewers nyingi hupuuza baiti zinazofuata)
- **Chunks za ziada zisizo za kawaida** zinazobeba payload; tazama [utaratibu wa kutembea kwenye PNG chunks na kuchonga data](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Headers zilizoharibika** zinazoficha vipimo au kuzuia parsers kufanya kazi hadi zirekebishwe

Maeneo muhimu ya chunks ya kukagua:

- `tEXt` / `iTXt` / `zTXt` (metadata ya maandishi, wakati mwingine imebanwa)
- `iCCP` (ICC profile) na chunks nyingine za ziada zinazotumika kama vibebaji
- `eXIf` (data ya EXIF katika PNG)

### Baiti za kichujio cha scanline za PNG kama kibebaji

PNG huhifadhi baiti moja ya aina ya kichujio (0–4) kabla ya kila scanline kwenye stream ya `IDAT` iliyofunguliwa. Baiti hizi si thamani za pixel; RGB pixels zilizofunguliwa hazihifadhi chaguo asilia za vichujio, na kusimba upya kunaweza kuzibadilisha. Encoder inaweza kubadilisha vichujio kihalali, lakini mifumo iliyowekwa kimakusudi inaweza kusimba ujumbe mfupi; changamoto ya hivi karibuni ilitumia thamani za kichujio 1–4 kama alama za biti mbili. Kagua **faili asilia** na uunganishe data yote ya `IDAT` kabla ya kuifungua. Kwa hali ifuatayo ya RGB/RGBA ya biti 8 isiyo na interlace, stride ni upana ukizidishwa kwa idadi ya channel; picha za Adam7 zinahitaji upana wa scanline maalum kwa kila pass.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Orodhesha baiti za kichujio cha scanline za PNG bila kusimba upya</summary>

```python
from pathlib import Path
import struct, sys, zlib
b = Path(sys.argv[1]).read_bytes()
assert b[:8] == b"\x89PNG\r\n\x1a\n"
w, h, depth, color, comp, method, interlace = struct.unpack(">IIBBBBB", b[16:29])
assert (depth, color, comp, method, interlace) in ((8, 2, 0, 0, 0), (8, 6, 0, 0, 0))
stride = w * (3 if color == 2 else 4)
off, parts = 8, []
while off + 12 <= len(b):
    n = int.from_bytes(b[off:off+4], "big")
    kind = b[off+4:off+8]
    assert off + n + 12 <= len(b)
    if kind == b"IDAT":
        parts.append(b[off+8:off+8+n])
    off += n + 12
    if kind == b"IEND":
        break
raw = zlib.decompress(b"".join(parts))
assert len(raw) == h * (stride + 1)
filters = raw[::stride+1]
assert all(f <= 4 for f in filters)
print(filters.hex(" "))
```

Endesha kwa kutumia `python3 filters.py suspect.png`. Angalia kama mfuatano wa filters, badala ya pikseli zilizofasiriwa, unafuata ramani ya alama inayokubalika. Ramani inayochaguliwa hutegemea changamoto; tofauti pekee si uthibitisho wa steganography.<sup>[[3]](#references)[[7]](#references)</sup>

### Amri za uchunguzi wa awali

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Cha kuangalia:

- Mchanganyiko usio wa kawaida wa upana/urefu/kina cha biti/aina ya rangi
- Hitilafu za CRC/chunk (pngcheck kwa kawaida huonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mwonekano wa kina zaidi wa chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Marejeleo muhimu:

- Uainisho wa PNG (muundo, chunks): https://www.w3.org/TR/PNG/
- Mbinu za fomati za faili (hali za kipekee za PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, zana za DCT-domain, na mipaka ya ELA

### Mbinu

JPEG haihifadhiwi kama pikseli ghafi; hubanwa katika DCT domain. Ndiyo maana zana za JPEG stego hutofautiana na zana za PNG LSB:

- Payloads za metadata/maoni huwa katika kiwango cha faili (huashiria sana na hukaguliwa haraka)
- Zana za DCT-domain huficha biti kwenye frequency coefficients

Kwa matumizi ya kiutendaji, ichukulie JPEG kama:

- Container ya metadata segments (huashiria sana na hukaguliwa haraka)
- Signal domain iliyobanwa (DCT coefficients) ambamo zana maalum za stego hufanya kazi

### Ukaguzi wa haraka

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Maeneo yenye ishara nyingi:

- Metadata ya EXIF/XMP/IPTC
- Sehemu ya maoni ya JPEG (`COM`)
- Sehemu za programu (`APP1` kwa EXIF, `APPn` kwa data ya vendor)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na payloads za steghide kwenye JPEG, zingatia kutumia `stegseek` (bruteforce ya haraka kuliko scripts za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA huangazia artifacts tofauti za recompression; inaweza kukuonyesha maeneo yaliyohaririwa, lakini yenyewe si kigunduzi cha stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zilizohuishwa

### Mbinu

Kwa picha zilizohuishwa, chukulia kwamba ujumbe uko:

- Katika fremu moja (rahisi), au
- Umesambazwa kwenye fremu mbalimbali (mpangilio ni muhimu), au
- Unaonekana tu unapolinganisha fremu zinazofuatana

### Toa fremu

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Kisha zichukulie fremu kama PNG za kawaida: `zsteg`, `pngcheck`, kutenga channel.

Zana mbadala:

- `gifsicle --explode anim.gif` (hutoa fremu haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila fremu

Ulinganishaji wa tofauti kati ya fremu mara nyingi huwa wa kuamua:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Usimbaji wa hesabu ya pikseli ya APNG

- Tambua kontena za APNG: `exiftool -a -G1 file.png | grep -i animation` au `file`.
- Toa fremu bila kubadilisha muda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rejesha payloads zilizosimbwa kwa kutumia hesabu za pikseli kwa kila fremu:

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

Changamoto za uhuishaji zinaweza kusimba kila byte kama idadi ya pikseli za rangi fulani katika kila fremu; kuunganisha idadi hizo huunda upya ujumbe.<sup>[[1]](#references)</sup>

## Password-protected embedding

Ikiwa unashuku kuwa embedding imelindwa kwa passphrase badala ya manipulation ya kiwango cha pikseli, hii huwa njia ya haraka zaidi.

### steghide

Inaauni `JPEG, BMP, WAV, AU` na inaweza kupachika/kutoa payloads zilizosimbwa kwa njia fiche.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Repozitori: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Inasaidia PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Orodha ya Matakwa ya Santa, Metadata ya Krismasi, Kelele Zilizorekodiwa](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [Maelezo ya HackVent 2024 — Rangi Zilizopindishwa](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Vipimo vya Portable Network Graphics (PNG), Toleo la Tatu](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Ndani kabisa chini ya maji kuna kitu](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Miundo ya faili za picha ya Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Vipimo vya GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Itifaki ya Afterimage — Maelezo ya CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
