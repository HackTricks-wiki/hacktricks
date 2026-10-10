# Beeldsteganografie

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF-beeldstego val in een van hierdie kategorieë:

- LSB/bitvlakke (PNG/BMP)
- Metadata-/kommentaarpayloads
- Vreemde PNG-chunks / herstel van korrupsie
- JPEG DCT-domeinnutsgoed (OutGuess, ens.)
- Raamgebaseerd (GIF/APNG)

## Vinnige triage

Prioritiseer bewyse op houervlak voordat jy inhoud diepgaande ontleed:

- Valideer die lêer en inspekteer die struktuur: `file`, `magick identify -verbose`, formaatvalideerders (bv. `pngcheck`).
- Onttrek metadata en sigbare stringe: `exiftool -a -u -g1`, `strings`.
- Kyk vir ingebedde/aangehegte inhoud: `binwalk` en inspeksie van die einde van die lêer (`tail | xxd`).
- Kies volgens houer:
  - PNG/BMP: bitvlakke/LSB en afwykings op chunk-vlak.
  - JPEG: metadata + DCT-domeingereedskap (OutGuess/F5-tipe families).
  - GIF/APNG: raamonttrekking, raamverskille, palettoertjies.

## Bitvlakke / LSB

### Tegniek

PNG/BMP is gewild in CTF's omdat hulle pixels stoor op ’n manier wat **manipulasie op bisvlak** maklik maak. Die klassieke versteek-/onttrekmeganisme is:

- Elke pixelkanaal (R/G/B/A) het verskeie bisse.
- Die **minste beduidende bis** (LSB) van elke kanaal verander die beeld baie min.
- Aanvallers versteek data in dié lae-orde bisse, soms met ’n stapgrootte, permutasie of kanaalkeuse.

Wat om in uitdagings te verwag:

- Die payload is net in een kanaal (bv. die `R` LSB).
- Die payload is in die alfakanaal.
- Die payload word ná onttrekking saamgepers/geënkodeer.
- Die boodskap is oor vlakke versprei of met XOR tussen vlakke versteek.

Bykomende families wat jy kan teëkom (afhangend van die implementering):

- **LSB passing** (nie net die bis omkeer nie, maar +/-1-aanpassings om by die teikenbis te pas)
- **Palet-/indeksgebaseerde versteeking** (geïndekseerde PNG/GIF: payload in kleurindekse eerder as rou RGB)
- **Slegs-alfa-payloads** (heeltemal onsigbaar in die RGB-aansig)

### Gereedskap

#### zsteg

`zsteg` lys baie LSB-/bitvlak-onttrekkingspatrone vir PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer ’n reeks transformasies uit (metadata, beeldtransformasies, brute forcing van LSB-variante).
- `stegsolve`: handmatige visuele filters (kanaalisolasie, vlakinspeksie, XOR, ens.).

Stegsolve-aflaai: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-gebaseerde sigbaarheidstruuks

FFT is nie LSB-ekstraksie nie; dit is vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone versteek word.

- EPFL-demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage word dikwels in CTF’s gebruik:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-internals: chunks, korrupsie en versteekte data

### Tegniek

PNG is ’n formaat wat uit chunks bestaan. In baie uitdagings word die payload op die houer-/chunk-vlak gestoor eerder as in pixelwaardes:

- **Ekstra grepe ná `IEND`** (baie kykers ignoreer agteraanstaande grepe)
- **Nie-standaard ancillary chunks** wat payloads bevat
- **Korrupte opskrifte** wat dimensies versteek of parsers laat misluk totdat dit reggemaak word

Chunks met belangrike leidrade om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (teksmetadata, soms saamgepers)
- `iCCP` (ICC-profiel) en ander ancillary chunks wat as draers gebruik word
- `eXIf` (EXIF-data in PNG)

### Triage-opdragte

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Waarna om te kyk:

- Vreemde kombinasies van breedte/hoogte/bitdiepte/kleurtipe
- CRC-/chunk-foute (pngcheck wys gewoonlik die presiese offset)
- Waarskuwings oor bykomende data ná `IEND`

As jy ’n dieper chunk-aansig nodig het:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nuttige verwysings:

- PNG-spesifikasie (struktuur, chunks): https://www.w3.org/TR/PNG/
- Lêerformaattruuks (PNG/JPEG/GIF-randgevalle): https://github.com/corkami/docs

## JPEG: metadata, DCT-domeinnutsgoed en ELA-beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit word in die DCT-domein saamgepers. Daarom verskil JPEG-stego-nutsgoed van PNG LSB-nutsgoed:

- Metadata-/opmerking-payloads is op lêervlak (duidelike sein en vinnig om te inspekteer)
- DCT-domeinstego-nutsgoed bed die bisse in frekwensiekoëffisiënte in

Beskou JPEG in die praktyk as:

- ’n Houer vir metadatasegmente (duidelike sein, vinnig om te inspekteer)
- ’n Saamgeperste seindomein (DCT-koëffisiënte) waarin gespesialiseerde stego-nutsgoed werk

### Vinnige kontroles

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Hoësein-liggings:

- EXIF/XMP/IPTC-metadata
- JPEG-opmerkingssegment (`COM`)
- Toepassingsegmente (`APP1` vir EXIF, `APPn` vir verskafferdata)

### Algemene nutsmiddels

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide-payloads in JPEG's te doen het, oorweeg dit om `stegseek` te gebruik (vinniger brute force as ouer skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA beklemtoon verskillende artefakte van herkompressie; dit kan jou wys na areas wat gewysig is, maar is nie op sy eie 'n stego-detektor nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, neem aan dat die boodskap:

- In 'n enkele raam is (maklik), of
- Oor rame versprei is (volgorde is belangrik), of
- Slegs sigbaar is wanneer opeenvolgende rame met mekaar vergelyk word

### Onttrek rame

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Behandel rame dan soos gewone PNG's: `zsteg`, `pngcheck`, kanaalisolasie.

Alternatiewe nutsgoed:

- `gifsicle --explode anim.gif` (vinnige rame-ekstraksie)
- `imagemagick`/`magick` vir transformasies per raam

Raamverskil-analise is dikwels deurslaggewend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-piekseltellingkodering

- Bespeur APNG-houers: `exiftool -a -G1 file.png | grep -i animation` of `file`.
- Onttrek rame sonder om die tydsberekening aan te pas: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Herwin loonvragte wat as piekseltellings per raam geënkodeer is:

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

Geanimeerde uitdagings kan elke byte enkodeer as die aantal pixels van ’n spesifieke kleur in elke raam; deur die getalle aaneen te voeg, word die boodskap gerekonstrueer.<sup>[[1]](#references)</sup>

## Wagwoordbeskermde inbedding

As jy vermoed dat die inbedding deur ’n wagwoordfrase beskerm word eerder as deur manipulasie op pixelvlak, is dit gewoonlik die vinnigste manier.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan geënkripteerde loonvragte inbed en onttrek.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Bewaarplek: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Bewaarplek: https://github.com/Paradoxis/StegCracker

### stegpy

Ondersteun PNG/BMP/GIF/WebP/WAV.

Bewaarplek: https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pienk, Kersvader se wenslys, Kersfees-metadata, vasgelegde geraas](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
