# Stéganographie d’image

{{#include ../../banners/hacktricks-training.md}}

La stégo d’image dans la plupart des CTF se résume à l’une de ces catégories :

- LSB/plans de bits (PNG/BMP)
- Charges utiles dans les métadonnées/commentaires
- Anomalies de chunks PNG / réparation de corruption
- Outils du domaine DCT JPEG (OutGuess, etc.)
- Basée sur les frames (GIF/APNG)

## Triage rapide

Commencez par examiner les éléments au niveau du conteneur avant d’analyser le contenu en profondeur :

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, validateurs de format (p. ex., `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Recherchez du contenu intégré/ajouté : `binwalk` et inspection de la fin du fichier (`tail | xxd`).
- Orientez l’analyse selon le conteneur :
  - PNG/BMP : plans de bits/LSB et anomalies au niveau des chunks.
  - JPEG : métadonnées + outils du domaine DCT (familles de type OutGuess/F5).
  - GIF/APNG : extraction des frames, comparaison des frames, astuces sur les palettes.

## Plans de bits / LSB

### Technique

Les PNG/BMP sont populaires dans les CTF car ils stockent les pixels d’une manière qui facilite la **manipulation au niveau des bits**. Le mécanisme classique de dissimulation/extraction est le suivant :

- Chaque canal de pixel (R/G/B/A) comporte plusieurs bits.
- Le **bit de poids faible** (LSB) de chaque canal modifie très peu l’image.
- Les attaquants cachent des données dans ces bits de poids faible, parfois avec un pas, une permutation ou un choix de canal.

Ce à quoi vous pouvez vous attendre dans les défis :

- La charge utile se trouve dans un seul canal (p. ex., le LSB de `R`).
- La charge utile se trouve dans le canal alpha.
- La charge utile est compressée/encodée après extraction.
- Le message est réparti entre plusieurs plans ou caché à l’aide d’un XOR entre les plans.

Autres familles que vous pourriez rencontrer (selon l’implémentation) :

- **LSB matching** (ne consiste pas seulement à inverser le bit, mais à effectuer des ajustements de +/-1 pour correspondre au bit cible)
- **Dissimulation basée sur la palette/l’index** (PNG/GIF indexés : la charge utile se trouve dans les indices de couleur plutôt que dans les valeurs RGB brutes)
- **Charges utiles uniquement dans le canal alpha** (complètement invisibles en vue RGB)

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

La FFT ne sert pas à extraire les LSB ; elle est utile lorsque du contenu est délibérément caché dans l’espace fréquentiel ou dans des motifs subtils.

- Démo EPFL : http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier : https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic : https://github.com/0xcomposure/FFTStegPic

Outils Web de triage souvent utilisés dans les CTF :

- Aperi’Solve : https://aperisolve.com/
- StegOnline : https://stegonline.georgeom.net/

## Fonctionnement interne des PNG : chunks, corruption et données cachées

### Technique

Le PNG est un format constitué de chunks. Dans de nombreux challenges, le payload est stocké au niveau du conteneur ou des chunks plutôt que dans les valeurs des pixels :

- **Octets supplémentaires après `IEND`** (de nombreux visionneurs ignorent les octets de fin)
- **Chunks auxiliaires non standard** contenant des payloads
- **En-têtes corrompus** qui masquent les dimensions ou empêchent les parseurs de fonctionner jusqu’à leur correction

Emplacements de chunks à examiner en priorité :

- `tEXt` / `iTXt` / `zTXt` (métadonnées textuelles, parfois compressées)
- `iCCP` (profil ICC) et autres chunks auxiliaires utilisés comme support
- `eXIf` (données EXIF dans un PNG)

### Commandes de triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

À rechercher :

- Combinaisons inhabituelles de largeur/hauteur/profondeur de bits/type de couleur
- Erreurs de CRC/de chunk (`pngcheck` indique généralement l’offset exact)
- Avertissements concernant des données supplémentaires après `IEND`

Si vous avez besoin d’une vue plus détaillée des chunks :

```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```

Références utiles :

- Spécification PNG (structure, chunks) : https://www.w3.org/TR/PNG/
- Astuces sur les formats de fichier (cas particuliers de PNG/JPEG/GIF) : https://github.com/corkami/docs

## JPEG : métadonnées, outils du domaine DCT et limites de l’ELA

### Technique

JPEG n’est pas stocké sous forme de pixels bruts ; il est compressé dans le domaine DCT. C’est pourquoi les outils de stego pour JPEG diffèrent des outils LSB pour PNG :

- Les payloads de métadonnées/commentaires sont au niveau du fichier (faciles à repérer et à inspecter rapidement)
- Les outils de stego dans le domaine DCT intègrent des bits dans les coefficients de fréquence

En pratique, considérez JPEG comme :

- Un conteneur de segments de métadonnées (faciles à repérer et à inspecter rapidement)
- Un domaine de signal compressé (coefficients DCT) dans lequel opèrent des outils de stego spécialisés

### Vérifications rapides

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

Emplacements à fort signal :

- Métadonnées EXIF/XMP/IPTC
- Segment de commentaire JPEG (`COM`)
- Segments d’application (`APP1` pour EXIF, `APPn` pour les données du fournisseur)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEG, pensez à utiliser `stegseek` (bruteforce plus rapide que les anciens scripts) :

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA met en évidence les différents artefacts de recompression ; cela peut vous orienter vers les zones qui ont été modifiées, mais ce n’est pas en soi un détecteur de stéganographie :

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

Autres outils :

- `gifsicle --explode anim.gif` (extraction rapide des images)
- `imagemagick`/`magick` pour les transformations image par image

La comparaison différentielle des images est souvent déterminante :

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Encodage APNG par nombre de pixels

- Détecter les conteneurs APNG : `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraire les frames sans modifier leur timing : `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Récupérer les payloads encodés sous forme de nombres de pixels par frame :

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

Les défis animés peuvent encoder chaque octet sous forme du nombre de pixels d’une couleur donnée dans chaque image ; la concaténation des nombres permet de reconstituer le message.<sup>[[1]](#references)</sup>

## Insertion protégée par mot de passe

Si vous pensez que l’insertion est protégée par une phrase secrète plutôt que réalisée par manipulation au niveau des pixels, c’est généralement la méthode la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et permet d’insérer ou d’extraire des payloads chiffrés.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Dépôt : https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo : https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Repo : https://github.com/dhsdshdhk/stegpy

## References

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
