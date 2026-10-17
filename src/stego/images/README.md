# Beeldsteganografie

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF-beeldstego val in een van hierdie kategorieë:

- LSB/bit-vlakke (PNG/BMP)
- Metadata-/kommentaar-payloads
- PNG-chunk-afwykings / herstel van korrupsie
- JPEG DCT-domein-gereedskap (OutGuess, ens.)
- Raamgebaseer (GIF/APNG)

## Vinnige triage

Prioritiseer bewyse op houervlak voordat jy die inhoud diep ontleed:

- Valideer die lêer en inspekteer die struktuur: `file`, `magick identify -verbose`, formaatvalideerders (bv. `pngcheck`).
- Onttrek metadata en sigbare stringe: `exiftool -a -u -g1`, `strings`.
- Kyk vir ingebedde/bygevoegde inhoud: `binwalk` en inspeksie van die lêereinde (`tail | xxd`).
- Kies ’n roete volgens die houer:
  - PNG/BMP: bit-vlakke/LSB en afwykings op chunk-vlak.
  - JPEG: metadata + DCT-domein-gereedskap (OutGuess/F5-stylfamilies).
  - GIF/APNG: raamonttrekking, raamverskille, palettruuks.

## Bit-vlakke / LSB

### Tegniek

PNG/BMP is gewild in CTF’s omdat hulle pixels stoor op ’n manier wat **manipulasie op bitvlak** maklik maak. Die klassieke versteek-/onttrekmeganisme is:

- Elke pixelkanaal (R/G/B/A) het verskeie bisse.
- Die **minste betekenisvolle bis** (LSB) van elke kanaal verander die beeld baie min.
- Aanvallers versteek data in daardie lae-bisposisies, soms met ’n stapgrootte, permutasie of kanaalkeuse.

Wat om in uitdagings te verwag:

- Die payload is in net een kanaal (bv. R se LSB).
- Die payload is in die alfakanaal.
- Die payload word ná onttrekking saamgepers/geënkodeer.
- Die boodskap is oor vlakke versprei of met XOR tussen vlakke versteek.

Bykomende families wat jy kan teëkom (afhanklik van die implementering):

- **LSB-aanpassing** (nie net die bis omkeer nie, maar aanpassings van +/-1 om by die teikenbis te pas)
- **Palet-/indeksgebaseerde versteeking** (geïndekseerde PNG/GIF: payload in kleurindekse eerder as rou RGB)
- **Slegs-alfakanaal-payloads** (heeltemal onsigbaar in ’n RGB-aansig)

### Gereedskap

#### zsteg

`zsteg` tel baie LSB-/bitvlak-onttrekkingspatrone vir PNG/BMP op:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer ’n reeks transformasies uit (metadata, beeldtransformasies, brute-forcing van LSB-variante).
- `stegsolve`: handmatige visuele filters (kanaalisolasie, vlakinspeksie, XOR, ens.).

Stegsolve-aflaai: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-gebaseerde sigbaarheidstruuks

FFT is nie LSB-ekstraksie nie; dit is vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone versteek word.

- EPFL-demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage wat dikwels in CTFs gebruik word:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-internals: chunks, korrupsie en versteekte data

### Tegniek

PNG is ’n chunk-gebaseerde formaat. In baie uitdagings word die payload op die container-/chunk-vlak gestoor, eerder as in pixelwaardes:

- **Ekstra grepe ná `IEND`** (baie kykers ignoreer agteraan gevoegde grepe)
- **Nie-standaard ancillary chunks** wat payloads bevat; sien die [PNG chunk-walker- en carving-werkvloei](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Korrupte opskrifte** wat dimensies versteek of parsers laat faal totdat dit reggestel word

Belangrike chunk-liggings om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (teksmetadata, soms saamgepers)
- `iCCP` (ICC-profiel) en ander ancillary chunks wat as draer gebruik word
- `eXIf` (EXIF-data in PNG)

### Triage-opdragte

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Waarna om te kyk:

- Vreemde breedte-/hoogte-/bisdiepte-/kleurtipekombinasies
- CRC-/chunk-foute (pngcheck wys gewoonlik die presiese offset)
- Waarskuwings oor bykomende data ná `IEND`

As jy ’n meer gedetailleerde chunk-aansig nodig het:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nuttige verwysings:

- PNG-spesifikasie (struktuur, chunks): https://www.w3.org/TR/PNG/
- Lêerformaat-truuks (PNG/JPEG/GIF-randgevalle): https://github.com/corkami/docs

## JPEG: metadata, DCT-domeinnutsgoed en ELA-beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit word in die DCT-domein saamgepers. Daarom verskil JPEG-stego-nutsgoed van PNG LSB-nutsgoed:

- Metadata-/kommentaar-payloads is op lêervlak (hoë seinwaarde en vinnig om te inspekteer)
- DCT-domein-stego-nutsgoed bed die bits in frekwensiekoëffisiënte in

Beskou JPEG prakties as:

- ’n Houer vir metadatasegmente (hoë seinwaarde, vinnig om te inspekteer)
- ’n Saamgeperste seindomein (DCT-koëffisiënte) waarin gespesialiseerde stego-nutsgoed werk

### Vinnige kontroles

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Hoë-sein-liggings:

- EXIF/XMP/IPTC-metadata
- JPEG-kommentaarsegment (`COM`)
- Toepassingsegmente (`APP1` vir EXIF, `APPn` vir verskafferdata)

### Algemene nutsmiddels

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide-payloads in JPEGs werk, oorweeg dit om `stegseek` te gebruik (vinniger brute force as ouer skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou na streke wys wat geredigeer is, maar dit is nie op sy eie ’n stego-detector nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Vir geanimeerde beelde, neem aan dat die boodskap:

- In ’n enkele raam is (maklik), of
- Oor rame versprei is (volgorde maak saak), of
- Slegs sigbaar is wanneer jy opeenvolgende rame diff

### Rame onttrek

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Behandel rame soos normale PNG's: `zsteg`, `pngcheck`, kanaalisolasie.

Alternatiewe nutsmiddels:

- `gifsicle --explode anim.gif` (vinnige raamonttrekking)
- `imagemagick`/`magick` vir transformasies per raam

Raamvergelyking is dikwels deurslaggewend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-piksel-telling-enkodering

- Bespeur APNG-houers: `exiftool -a -G1 file.png | grep -i animation` of `file`.
- Onttrek rame sonder om die tydsberekening te verander: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Herwin loonvragte wat as pikseltellings per raam geënkodeer is:

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

Geanimeerde uitdagings kan elke byte enkodeer as die aantal kere wat ’n spesifieke kleur in elke frame voorkom; deur die tellings aan mekaar te voeg, word die boodskap gerekonstrueer.<sup>[[1]](#references)</sup>

## Wagwoordbeskermde inbedding

As jy vermoed dat die inbedding met ’n wagfrase beskerm word eerder as deur pixelvlakmanipulasie, is dit gewoonlik die vinnigste benadering.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan geënkripteerde payloads inbed of uittrek.

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

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — pienk, Kersvader se wenslys, Kersfees-metadata, vasgelegde geraas](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
