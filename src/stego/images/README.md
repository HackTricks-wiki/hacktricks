# Steganografia ya Picha

{{#include ../../banners/hacktricks-training.md}}

Stego ya picha katika CTF nyingi huangukia katika mojawapo ya makundi haya:

- LSB/bit-planes (PNG/BMP)
- Payload za metadata/maoni
- Dosari za PNG chunk / urekebishaji wa uharibifu
- Zana za JPEG DCT-domain (OutGuess, n.k.)
- Zinazotegemea fremu (GIF/APNG)

## Uchunguzi wa haraka

Tanguliza ushahidi wa kiwango cha kontena kabla ya uchanganuzi wa kina wa maudhui:

- Thibitisha faili na kagua muundo: `file`, `magick identify -verbose`, zana za kuthibitisha fomati (kwa mfano, `pngcheck`).
- Toa metadata na maandishi yanayoonekana: `exiftool -a -u -g1`, `strings`.
- Angalia maudhui yaliyopachikwa/kuongezwa: `binwalk` na ukaguzi wa mwisho wa faili (`tail | xxd`).
- Chagua njia kulingana na kontena:
  - PNG/BMP: bit-planes/LSB na hitilafu za kiwango cha chunk.
  - JPEG: metadata pamoja na zana za DCT-domain (familia za mtindo wa OutGuess/F5).
  - GIF/APNG: utoaji wa fremu, utofautishaji wa fremu, mbinu za palette.

## Bit-planes / LSB

### Mbinu

PNG/BMP hutumika sana katika CTF kwa sababu huhifadhi pikseli kwa namna inayorahisisha **udanganyifu wa kiwango cha bit**. Mbinu ya kawaida ya kuficha/kutoa ni:

- Kila chaneli ya pikseli (R/G/B/A) ina bit nyingi.
- **Least significant bit** (LSB) ya kila chaneli hubadilisha picha kwa kiwango kidogo sana.
- Washambuliaji huficha data katika bit za mpangilio wa chini, wakati mwingine kwa kutumia stride, mpangilio wa permutation, au chaguo la chaneli moja moja.

Mambo ya kutarajia katika changamoto:

- Payload iko katika chaneli moja tu (kwa mfano, LSB ya `R`).
- Payload iko kwenye alpha channel.
- Payload imeshinikizwa/kusimbwa baada ya kutolewa.
- Ujumbe umesambazwa kwenye planes au umefichwa kwa kutumia XOR kati ya planes.

Familia nyingine unazoweza kukutana nazo (hutegemea utekelezaji):

- **LSB matching** (si kubadilisha bit tu, bali kurekebisha kwa +/-1 ili ilingane na bit lengwa)
- **Kuficha kwa kutumia palette/index** (PNG/GIF za indexed: payload katika color indices badala ya RGB ghafi)
- **Payload za alpha pekee** (hazionekani kabisa katika mwonekano wa RGB)

### Zana

#### zsteg

`zsteg` huhesabu mifumo mingi ya utoaji wa LSB/bit-plane kwa PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: huendesha mfululizo wa transforms (metadata, image transforms, brute forcing ya variants za LSB).
- `stegsolve`: vichujio vya kuona vya kutumia mwenyewe (kutenganisha channels, kukagua planes, XOR, n.k.).

Pakua Stegsolve: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Mbinu za kubaini yaliyofichwa kwa kutumia FFT

FFT si njia ya kutoa LSB; hutumika pale ambapo maudhui yamefichwa kimakusudi kwenye frequency space au kwenye patterns zisizo dhahiri.

- Demo ya EPFL: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Triage inayotegemea wavuti hutumiwa mara nyingi kwenye CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Vipengele vya ndani vya PNG: chunks, uharibifu na data iliyofichwa

### Mbinu

PNG ni format inayotumia chunks. Katika changamoto nyingi, payload huhifadhiwa kwenye kiwango cha container/chunk badala ya kuhifadhiwa kwenye thamani za pixels:

- **Bytes za ziada baada ya `IEND`** (viewers nyingi hupuuza bytes za ziada)
- **Chunks zisizo za kawaida za ancillary** zinazobeba payloads
- **Headers zilizoharibika** zinazoficha vipimo au kuvuruga parsers hadi zirekebishwe

Maeneo muhimu ya chunks ya kukagua:

- `tEXt` / `iTXt` / `zTXt` (text metadata, wakati mwingine ikiwa imebanwa)
- `iCCP` (ICC profile) na chunks nyingine za ancillary zinazotumika kubebea data
- `eXIf` (EXIF data katika PNG)

### Amri za triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Unachopaswa kutafuta:

- Mchanganyiko usio wa kawaida wa upana/urefu/bit-depth/aina ya rangi
- Hitilafu za CRC/chunk (pngcheck kwa kawaida huonyesha offset halisi)
- Maonyo kuhusu data ya ziada baada ya `IEND`

Ikiwa unahitaji mwonekano wa kina zaidi wa chunk:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Marejeleo muhimu:

- Uainisho wa PNG (muundo, chunks): https://www.w3.org/TR/PNG/
- Mbinu za format za faili (hali za kipekee za PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG: metadata, zana za DCT-domain, na vikwazo vya ELA

### Mbinu

JPEG haihifadhiwi kama pikseli ghafi; hubanwa katika DCT domain. Ndiyo maana zana za stego za JPEG hutofautiana na zana za PNG LSB:

- Payload za metadata/maoni ziko kwenye kiwango cha faili (rahisi kuzitambua na kuzikagua haraka)
- Zana za stego za DCT-domain hupachika biti kwenye frequency coefficients

Kwa matumizi ya kawaida, ichukulie JPEG kama:

- Kontena la metadata segments (rahisi kuzitambua na kuzikagua haraka)
- Kikoa cha signal iliyobanwa (DCT coefficients) ambamo zana maalum za stego hufanya kazi

### Ukaguzi wa haraka

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Maeneo yenye ishara nyingi:

- Metadata ya EXIF/XMP/IPTC
- Sehemu ya maoni ya JPEG (`COM`)
- Sehemu za programu (`APP1` za EXIF, `APPn` za data ya vendor)

### Zana za kawaida

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Ikiwa unakutana hasa na payloads za steghide kwenye JPEG, fikiria kutumia `stegseek` (bruteforce ya kasi zaidi kuliko scripts za zamani):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA huangazia tofauti za vizalia vya recompression; inaweza kukuongoza kwenye maeneo yaliyohaririwa, lakini yenyewe si detector ya stego:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Picha zilizohuishwa

### Mbinu

Kwa picha zilizohuishwa, chukulia kwamba ujumbe uko:

- Katika fremu moja (rahisi), au
- Umesambazwa katika fremu (mpangilio ni muhimu), au
- Unaonekana tu unapolinganisha fremu zinazofuatana

### Toa fremu zilizotenganishwa

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Kisha shughulikia fremu kama PNG za kawaida: `zsteg`, `pngcheck`, kutenganisha chaneli.

Zana mbadala:

- `gifsicle --explode anim.gif` (hutoa fremu kwa haraka)
- `imagemagick`/`magick` kwa mabadiliko ya kila fremu

Ulinganishaji wa tofauti kati ya fremu mara nyingi huwa ndio wa kuamua:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Usimbaji wa idadi ya pikseli wa APNG

- Tambua kontena za APNG: `exiftool -a -G1 file.png | grep -i animation` au `file`.
- Toa fremu bila kubadilisha muda: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Rejesha payload zilizofichwa kwa kusimba idadi ya pikseli kwa kila fremu:

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

Changamoto za uhuishaji zinaweza kusimba kila byte kama idadi ya rangi mahususi katika kila fremu; kuunganisha idadi hizo kunarejesha ujumbe.<sup>[[1]](#references)</sup>

## Password-protected embedding

Ikiwa unashuku kuwa embedding imelindwa kwa passphrase badala ya manipulation ya kiwango cha pixel, kwa kawaida hii ndiyo njia ya haraka zaidi.

### steghide

Inasaidia `JPEG, BMP, WAV, AU` na inaweza ku-embed/kutoa payload zilizosimbwa kwa njia fiche.

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

- [1] [Flagvent 2025 (Medium) — pink, Orodha ya Matamanio ya Santa, Metadata ya Krismasi, Kelele Zilizorekodiwa](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
