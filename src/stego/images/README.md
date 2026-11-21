# Beeldsteganografie

{{#include ../../banners/hacktricks-training.md}}

Die meeste CTF-beeldstego val in een van die volgende kategorieë:

- LSB/bit-planes (PNG/BMP)
- Metadata-/comment-payloads
- PNG-chunk-afwykings / herstel van korrupsie
- JPEG DCT-domain-tools (OutGuess, ens.)
- Raamgebaseer (GIF/APNG)

## Vinnige aanvanklike ondersoek

Gee bewyse op containervlak voorkeur bo diep inhoudsontleding. Sien die [algemene stego-werkvloei](../workflow/) vir lêeridentifikasie en carving voordat jy beeldspesifieke toetse uitvoer.

- Valideer die lêer en ondersoek die struktuur: `file`, `magick identify -verbose`, formaatvalideerders (bv. `pngcheck`).
- Onttrek metadata en sigbare strings: `exiftool -a -u -g1`, `strings`.
- Kyk vir ingebedde/bygevoegde inhoud: `binwalk` en inspeksie van die lêereinde (`tail | xxd`).
- Kies ’n rigting volgens die container:
  - PNG/BMP: bit-planes/LSB en afwykings op chunk-vlak.
  - JPEG: metadata + DCT-domain-gereedskap (OutGuess/F5-agtige families).
  - GIF/APNG: raamonttrekking, verskilbepaling tussen rame, palettruuks.

## Bit-planes / LSB

### Tegniek

PNG/BMP is gewild in CTF’s omdat hulle pixels stoor op ’n manier wat **bitvlak-manipulasie** maklik maak. Die klassieke versteek-/onttrekkingsmetode werk soos volg:

- Elke pixelkanaal (R/G/B/A) het verskeie bisse.
- Die **minste beduidende bis** (LSB) van elke kanaal verander die beeld baie min.
- Aanvallers versteek data in daardie laeorde-bisse, soms met ’n stride, permutasie of keuse van kanaal per kanaal.

Wat jy in uitdagings kan verwag:

- Die payload is in slegs een kanaal (bv. die `R` LSB).
- Die payload is in die alfakanaal.
- Die payload word ná onttrekking saamgepers/geënkodeer.
- Die boodskap is oor bit-planes versprei of via XOR tussen bit-planes versteek.

Bykomende families wat jy kan teëkom (afhangend van die implementering):

- **LSB matching** (nie net die bis omkeer nie, maar aanpassings van +/-1 om by die teikenbis te pas)
- **Palette/index-based hiding** (geïndekseerde PNG/GIF: payload in kleurindekse eerder as rou RGB)
- **Alpha-only payloads** (heeltemal onsigbaar in die RGB-aansig)

### Geïndekseerde-kleurpaletindekse

’n Geïndekseerde PNG of GIF stoor ’n palet**indeks** per pixel, nie ’n RGB-drietal nie. Twee indekse kan na dieselfde sigbare kleur verwys, dus kan omskakeling na RGB voordat jy dit ontleed die versteekte onderskeid uitwis. Ondersoek duplikaat- of byna-duplikaatpaletinskrywings en lewer dan ’n binêre masker van pixels met elke verdagte indeks. Dit het versteekte teks en QR-kodeveranderinge in onlangse GIF-uitdagings onthul.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Vir ’n geïndekseerde PNG met een raam (of die **eerste raam** van ’n GIF), behou Pillow se `P`-modus en verander `target` na ’n interessante indeks wat deur die skrip gerapporteer word. Gaan deursigtigheid (`tRNS` of GIF-deursigtigheidsindeks) sowel as RGB na wanneer jy indekse kies.<sup>[[3]](#references)[[5]](#references)</sup>

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

Vir geanimeerde GIF's, inspekteer rame afsonderlik. Pillow skakel gewoonlik latere rame na RGB/RGBA om wanneer dit saamgestel word; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` behou P-modus slegs solank die palet nie verander nie. As 'n raam 'n plaaslike palet het of reeds saamgestel is, inspekteer die oorspronklike geïndekseerde raamdata eerder as om RGB-omgeskakelde pixels as indekse te behandel.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Gereedskap

#### zsteg

`zsteg` lys baie LSB-/bitvlak-ekstraksiepatrone vir PNG/BMP:

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: voer ’n reeks transformasies uit (metadata, beeldtransformasies, brute-forsering van LSB-variante).
- `stegsolve`: handmatige visuele filters (kanaalisolasie, vlakinspeksie, XOR, ens.).

Stegsolve-aflaai: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-gebaseerde sigbaarheidstruuks

FFT is nie LSB-ekstraksie nie; dit word gebruik vir gevalle waar inhoud doelbewus in frekwensieruimte of subtiele patrone versteek is.

- EPFL-demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Webgebaseerde triage wat dikwels in CTF’s gebruik word:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG-internals: stukke, korrupsie en versteekte data

### Tegniek

PNG is ’n stukgebaseerde formaat. In baie uitdagings word die loonvrag op houer-/stukvlak gestoor, eerder as in pixelwaardes:

- **Ekstra grepe ná `IEND`** (baie kykers ignoreer agteraanhangende grepe)
- **Nie-standaard hulpstukke** wat loonvragte bevat; sien die [PNG-stukstapper en uitsny-werkvloei](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **Korrupte opskrifte** wat dimensies versteek of ontleders laat faal totdat dit reggestel is

Stukke met ’n hoë seinwaarde om na te gaan:

- `tEXt` / `iTXt` / `zTXt` (teksmetadata, soms saamgepers)
- `iCCP` (ICC-profiel) en ander hulpstukke wat as draer gebruik word
- `eXIf` (EXIF-data in PNG)

### PNG-skandeerlyn-filtergrepe as draer

PNG stoor een filtertipegreep (0–4) voor elke skandeerlyn in die gedekomprimeerde `IDAT`-stroom. Hierdie grepe is nie pixelwaardes nie; gedekodeerde RGB-pixels behou nie die oorspronklike filterkeuses nie, en herkodering kan dit verander. ’n Enkodeerder kan filters wettiglik laat wissel, maar doelbewuste patrone kan ’n klein boodskap enkodeer; ’n onlangse uitdaging het filterwaardes 1–4 as tweebis-simbole gebruik. Inspekteer die **oorspronklike lêer** en voeg al die `IDAT`-data saam voordat jy dit dekomprimeer. Vir die volgende nie-geïnterlinieerde 8-bis RGB/RGBA-geval is die stapwydte die breedte maal die kanaaltelling; Adam7-beelde vereis skandeerlynwydtes spesifiek vir elke deurloop.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Lys PNG-skandeerlyn-filtergrepe sonder herkodering</summary>

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

</details>

Voer dit uit as `python3 filters.py suspect.png`. Kontroleer of die filtervolgorde, eerder as die gedekodeerde pixels, ’n geloofwaardige simboolkartering volg. Die keuse van kartering is uitdagingspesifiek; variasie alleen is nie bewys van steganografie nie.<sup>[[3]](#references)[[7]](#references)</sup>

### Triage-opdragte

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

Waarna om te kyk:

- Vreemde kombinasies van breedte/hoogte/bisdiepte/kleurtipe
- CRC-/chunk-foute (pngcheck wys gewoonlik die presiese offset)
- Waarskuwings oor bykomende data ná `IEND`

As jy ’n meer gedetailleerde chunk-aansig nodig het:

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Nuttige verwysings:

- PNG-spesifikasie (struktuur, chunks): https://www.w3.org/TR/PNG/
- Lêerformaattruuks (PNG/JPEG/GIF-hoekgevalle): https://github.com/corkami/docs

## JPEG: metadata, DCT-domeinnutsgoed en ELA-beperkings

### Tegniek

JPEG word nie as rou pixels gestoor nie; dit word in die DCT-domein saamgepers. Daarom verskil JPEG-stego-nutsgoed van PNG LSB-nutsgoed:

- Metadata-/kommentaar-payloads is op lêervlak (hoë seinwaarde en vinnig om te inspekteer)
- Stego-nutsgoed in die DCT-domein plaas bisse in frekwensiekoëffisiënte in

Behandel JPEG in die praktyk as:

- ’n Houer vir metadatasegmente (hoë seinwaarde, vinnig om te inspekteer)
- ’n Saamgeperste seindomein (DCT-koëffisiënte) waarin gespesialiseerde stego-nutsgoed werk

### Vinnige kontroles

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Plekke met sterk aanduidings:

- EXIF/XMP/IPTC-metadata
- JPEG-kommentaarsegment (`COM`)
- Toepassingsegmente (`APP1` vir EXIF, `APPn` vir verskafferdata)

### Algemene nutsgoed

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

As jy spesifiek met steghide-payloads in JPEG's te doen het, oorweeg dit om `stegseek` te gebruik (vinniger bruteforce as ouer skripte):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Foutvlak-analise

ELA beklemtoon verskillende herkompressie-artefakte; dit kan jou na areas lei wat geredigeer is, maar is nie op sigself 'n stego-detektor nie:

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Geanimeerde beelde

### Tegniek

Neem by geanimeerde beelde aan dat die boodskap:

- In 'n enkele raam is (maklik), of
- Oor rame versprei is (die volgorde maak saak), of
- Slegs sigbaar is wanneer opeenvolgende rame vergelyk word

### Rame onttrek

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Behandel rame dan soos gewone PNG's: `zsteg`, `pngcheck`, kanaal-isolasie.

Alternatiewe nutsmiddels:

- `gifsicle --explode anim.gif` (vinnige raamekstraksie)
- `imagemagick`/`magick` vir transformasies per raam

Raamverskille is dikwels deurslaggewend:

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### APNG-piekseltellingkodering

- Bespeur APNG-houers: `exiftool -a -G1 file.png | grep -i animation` or `file`.
- Onttrek rame sonder hertydsberekening: `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Herwin loonvragte wat as piekseltellings per raam gekodeer is:

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

Geanimeerde uitdagings kan elke byte enkodeer as die aantal kere wat ’n spesifieke kleur in elke raam voorkom; deur die tellings aaneen te voeg, word die boodskap gerekonstrueer.<sup>[[1]](#references)</sup>

## Inbedding met wagwoordbeskerming

As jy vermoed dat die inbedding met ’n wagwoordfrase beskerm word eerder as deur manipulasie op pixelvlak, is dit gewoonlik die vinnigste manier.

### steghide

Ondersteun `JPEG, BMP, WAV, AU` en kan geënkripteerde payloads inbed en onttrek.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Bewaarplek: https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Ondersteun PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — pink, Santa se wenslys, Kersfees-metadata, vasgelegde geraas](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [HackVent 2024-verslag — verwronge kleure](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Portable Network Graphics (PNG)-spesifikasie, derde uitgawe](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — diep onder is daar iets in die water](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Pillow-beeldlêerformate — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [GIF89a-spesifikasie](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Afterimage Protocol — CTF-verslag](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
