# Stéganographie dans les images

{{#include ../../banners/hacktricks-training.md}}

La stégo dans les images en CTF se réduit généralement à l’un de ces cas :

- LSB/plans de bits (PNG/BMP)
- Payloads dans les métadonnées/commentaires
- Anomalies ou réparation de chunks PNG
- Outils du domaine DCT JPEG (OutGuess, etc.)
- Contenu basé sur des frames (GIF/APNG)

## Triage rapide

Privilégiez les indices au niveau du conteneur avant l’analyse approfondie du contenu. Consultez le [workflow général de stégo](../workflow/) pour l’identification des fichiers et l’extraction de données avant les tests spécifiques aux images.

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, validateurs de format (par exemple, `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Recherchez du contenu intégré ou ajouté à la fin du fichier : `binwalk` et inspection de la fin du fichier (`tail | xxd`).
- Choisissez l’approche selon le conteneur :
  - PNG/BMP : plans de bits/LSB et anomalies au niveau des chunks.
  - JPEG : métadonnées et outils du domaine DCT (familles de type OutGuess/F5).
  - GIF/APNG : extraction de frames, comparaison de frames, astuces avec les palettes.

## Plans de bits / LSB

### Technique

Les PNG/BMP sont populaires dans les CTF, car ils stockent les pixels d’une manière qui facilite la **manipulation au niveau des bits**. Le mécanisme classique de dissimulation/extraction est le suivant :

- Chaque canal de pixel (R/G/B/A) possède plusieurs bits.
- Le **bit de poids faible** (LSB) de chaque canal modifie très peu l’image.
- Les attaquants dissimulent des données dans ces bits de poids faible, parfois en utilisant un pas, une permutation ou un choix de canal spécifique.

À quoi s’attendre dans les challenges :

- Le payload se trouve dans un seul canal (par exemple, le LSB de `R`).
- Le payload se trouve dans le canal alpha.
- Le payload est compressé/encodé après son extraction.
- Le message est réparti entre plusieurs plans ou dissimulé à l’aide d’un XOR entre les plans.

Autres familles que vous pourriez rencontrer (selon l’implémentation) :

- **LSB matching** (il ne s’agit pas simplement d’inverser le bit, mais d’ajuster la valeur de +/-1 pour correspondre au bit cible)
- **Dissimulation basée sur la palette/les indices** (PNG/GIF indexés : le payload se trouve dans les indices de couleur plutôt que dans les valeurs RGB brutes)
- **Payloads uniquement dans le canal alpha** (complètement invisibles en vue RGB)

### Indices de palette des couleurs indexées

Un PNG ou GIF indexé stocke un **indice** de palette par pixel, et non un triplet RGB. Deux indices peuvent correspondre à la même couleur visible : la conversion en RGB avant l’analyse peut donc effacer la distinction cachée. Inspectez les entrées de palette dupliquées ou presque identiques, puis générez un masque binaire des pixels utilisant chaque indice suspect. Cette méthode a permis de révéler du texte caché et des modifications de QR codes dans de récents challenges GIF.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>

Pour un PNG indexé à une seule frame (ou la **première frame** d’un GIF), conservez le mode `P` de Pillow et remplacez `target` par un indice intéressant indiqué par le script. Vérifiez la transparence (`tRNS` ou l’indice de transparence du GIF) ainsi que le RGB lors du choix des indices.<sup>[[3]](#references)[[5]](#references)</sup>

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

Pour les GIF animés, examinez les images séparément. Pillow convertit normalement les images suivantes en RGB/RGBA lors de la composition ; `GifImagePlugin.LOADING_STRATEGY = GifImagePlugin.LoadingStrategy.RGB_AFTER_DIFFERENT_PALETTE_ONLY` conserve le mode `P` uniquement tant que la palette ne change pas. Si une image possède une palette locale ou a déjà été composée, examinez plutôt ses données d’image indexées d’origine au lieu de traiter les pixels convertis en RGB comme des indices.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

### Outils

#### zsteg

`zsteg` énumère de nombreux motifs d’extraction LSB/plans de bits pour PNG/BMP :

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas` : exécute une série de transformations (métadonnées, transformations d’image, brute force de variantes LSB).
- `stegsolve` : filtres visuels manuels (isolation des canaux, inspection des plans, XOR, etc.).

Téléchargement de Stegsolve : https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Astuces de visibilité basées sur la FFT

La FFT n’est pas une méthode d’extraction LSB ; elle sert dans les cas où le contenu est délibérément masqué dans l’espace fréquentiel ou dans des motifs subtils.

- Démo EPFL : http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier : https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic : https://github.com/0xcomposure/FFTStegPic

Outils de triage Web souvent utilisés dans les CTF :

- Aperi’Solve : https://aperisolve.com/
- StegOnline : https://stegonline.georgeom.net/

## Internes des PNG : chunks, corruption et données cachées

### Technique

Le PNG est un format composé de chunks. Dans de nombreux défis, le payload est stocké au niveau du conteneur/des chunks plutôt que dans les valeurs des pixels :

- **Octets supplémentaires après `IEND`** (de nombreux visualiseurs ignorent les octets de fin)
- **Chunks auxiliaires non standard** contenant des payloads ; voir le [parcours des chunks PNG et le workflow d’extraction](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **En-têtes corrompus** qui masquent les dimensions ou empêchent les parseurs de fonctionner jusqu’à leur correction

Emplacements de chunks à forte probabilité à examiner :

- `tEXt` / `iTXt` / `zTXt` (métadonnées textuelles, parfois compressées)
- `iCCP` (profil ICC) et autres chunks auxiliaires utilisés comme support
- `eXIf` (données EXIF dans le PNG)

### Octets de filtre des lignes de balayage PNG comme support

Le PNG stocke un octet de type de filtre (0–4) avant chaque ligne de balayage dans le flux `IDAT` décompressé. Ces octets ne sont pas des valeurs de pixel ; les pixels RGB décodés ne préservent pas les choix de filtre d’origine, et un réencodage peut les modifier. Un encodeur peut légitimement varier les filtres, mais des motifs délibérés peuvent encoder un petit message ; un défi récent utilisait les valeurs de filtre 1–4 comme symboles de deux bits. Inspectez le **fichier d’origine** et concaténez toutes les données `IDAT` avant de les décompresser. Pour le cas suivant d’image non entrelacée, 8 bits, RGB/RGBA, le pas correspond à la largeur multipliée par le nombre de canaux ; les images Adam7 nécessitent des largeurs de lignes de balayage spécifiques à chaque passe.<sup>[[3]](#references)[[7]](#references)</sup>

<details>
<summary>Lister les octets de filtre des lignes de balayage PNG sans réencodage</summary>

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

Exécutez-le avec `python3 filters.py suspect.png`. Vérifiez si la séquence de filtres, plutôt que les pixels décodés, suit une correspondance plausible avec des symboles. Le choix de la correspondance dépend du challenge ; la variation à elle seule ne prouve pas la présence de stéganographie.<sup>[[3]](#references)[[7]](#references)</sup>

### Commandes de triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

À rechercher :

- Combinaisons inhabituelles de largeur/hauteur/profondeur de bits/type de couleur
- Erreurs de CRC/chunk (pngcheck indique généralement l’offset exact)
- Avertissements concernant des données supplémentaires après `IEND`

Si vous avez besoin d’une vue plus détaillée des chunks :

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Références utiles :

- Spécification PNG (structure, chunks) : https://www.w3.org/TR/PNG/
- Astuces sur les formats de fichiers (cas particuliers de PNG/JPEG/GIF) : https://github.com/corkami/docs

## JPEG : métadonnées, outils du domaine DCT et limites de l’ELA

### Technique

JPEG n’est pas stocké sous forme de pixels bruts ; il est compressé dans le domaine DCT. C’est pourquoi les outils de stéganographie JPEG diffèrent des outils LSB pour PNG :

- Les charges utiles des métadonnées et des commentaires sont au niveau du fichier (signal fort et inspection rapide)
- Les outils de stéganographie dans le domaine DCT intègrent des bits dans les coefficients de fréquence

En pratique, considérez JPEG comme :

- Un conteneur de segments de métadonnées (signal fort, inspection rapide)
- Un domaine de signal compressé (coefficients DCT) dans lequel des outils de stéganographie spécialisés opèrent

### Vérifications rapides

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Emplacements à fort signal :

- Métadonnées EXIF/XMP/IPTC
- Segment de commentaire JPEG (`COM`)
- Segments d’application (`APP1` pour EXIF, `APPn` pour les données du fabricant)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEG, envisagez d’utiliser `stegseek` (bruteforce plus rapide que les anciens scripts) :

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Analyse du niveau d’erreur

L’ELA met en évidence différentes artefacts de recompression ; elle peut vous orienter vers les régions modifiées, mais ne permet pas à elle seule de détecter la stéganographie :

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Images animées

### Technique

Pour les images animées, partez du principe que le message est :

- Dans une seule image (facile), ou
- Réparti sur plusieurs images (l’ordre compte), ou
- Visible uniquement lorsque vous comparez des images consécutives

### Extraire les images

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Traitez ensuite les images comme des PNG classiques : `zsteg`, `pngcheck`, isolation des canaux.

Outils alternatifs :

- `gifsicle --explode anim.gif` (extraction rapide des images)
- `imagemagick`/`magick` pour les transformations image par image

La différence entre les images est souvent décisive :

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Encodage par nombre de pixels APNG

- Détecter les conteneurs APNG : `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraire les frames sans modifier leur timing : `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Récupérer les payloads encodés sous forme de nombre de pixels par frame :

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

Les défis animés peuvent encoder chaque octet sous forme du nombre de pixels d’une couleur spécifique dans chaque frame ; la concaténation des nombres reconstitue le message.<sup>[[1]](#references)</sup>

## Dissimulation protégée par mot de passe

Si vous soupçonnez une dissimulation protégée par une phrase secrète plutôt qu’une manipulation au niveau des pixels, c’est généralement la méthode la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et permet d’intégrer ou d’extraire des payloads chiffrés.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Dépôt : https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Dépôt : https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Dépôt : https://github.com/dhsdshdhk/stegpy





## References

- [1] [Flagvent 2025 (Medium) — rose, la liste de souhaits du Père Noël, métadonnées de Noël, bruit capturé](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [write-up HackVent 2024 — couleurs déformées](https://www.bigigloo.de/download/Write-Up_HackVent_2024.pdf)
- [3] [Spécification Portable Network Graphics (PNG), troisième édition](https://www.w3.org/TR/png-3/)
- [4] [XESXOR — Au fond, il y a quelque chose dans l’eau](https://www.xesxor.com/writeups/custom-other-deep-down-there-s-something-in-the-water)
- [5] [Formats de fichiers image de Pillow — GIF](https://pillow.readthedocs.io/en/stable/handbook/image-file-formats.html)
- [6] [Spécification GIF89a](https://giflib.sourceforge.net/gifstandard/GIF89a.html)
- [7] [Protocole Afterimage — write-up CTF](https://github.com/Team-Cyfer-Trace/Crest-CTF-2.0-Writeup-by-Cyfer-Trace/blob/main/stegno/Afterimage-Protocol/writeup.md)
{{#include ../../banners/hacktricks-training.md}}
