# Stéganographie d’image

{{#include ../../banners/hacktricks-training.md}}

La plupart des techniques de stego d’image dans les CTF se répartissent dans l’une de ces catégories :

- LSB/bit-planes (PNG/BMP)
- Payloads dans les métadonnées/commentaires
- Particularités des chunks PNG / réparation de la corruption
- Outils du domaine DCT JPEG (OutGuess, etc.)
- Techniques basées sur les frames (GIF/APNG)

## Triage rapide

Priorisez les éléments relatifs au conteneur avant l’analyse approfondie du contenu :

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, validateurs de format (p. ex. `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Vérifiez la présence de contenu intégré/ajouté : `binwalk` et inspectez la fin du fichier (`tail | xxd`).
- Orientez l’analyse selon le conteneur :
- PNG/BMP : bit-planes/LSB et anomalies au niveau des chunks.
- JPEG : métadonnées + outils du domaine DCT (familles de type OutGuess/F5).
- GIF/APNG : extraction des frames, différenciation des frames, techniques liées aux palettes.

## Bit-planes / LSB

### Technique

Les formats PNG/BMP sont populaires dans les CTF, car ils stockent les pixels d’une manière qui facilite la **manipulation au niveau des bits**. Le mécanisme classique de dissimulation/extraction est le suivant :

- Chaque canal de pixel (R/G/B/A) possède plusieurs bits.
- Le **bit de poids faible** (LSB) de chaque canal modifie très peu l’image.
- Les attaquants dissimulent des données dans ces bits de poids faible, parfois avec un stride, une permutation ou une sélection par canal.

Ce que vous pouvez rencontrer dans les challenges :

- Le payload se trouve dans un seul canal (p. ex. le LSB de `R`).
- Le payload se trouve dans le canal alpha.
- Le payload est compressé/encodé après l’extraction.
- Le message est réparti sur plusieurs plans ou dissimulé via un XOR entre les plans.

Autres familles que vous pouvez rencontrer (selon l’implémentation) :

- **LSB matching** (il ne s’agit pas simplement d’inverser le bit, mais d’effectuer des ajustements de +/-1 pour correspondre au bit cible)
- **Dissimulation basée sur la palette/les index** (PNG/GIF indexé : le payload se trouve dans les index de couleur plutôt que dans les valeurs RGB brutes)
- **Payload uniquement dans l’alpha** (complètement invisible dans une vue RGB)

### Outils

#### zsteg

`zsteg` énumère de nombreux modèles d’extraction LSB/bit-plane pour les fichiers PNG/BMP :
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas` : exécute une batterie de transforms (métadonnées, transforms d’image, brute forcing de variantes LSB).
- `stegsolve` : filtres visuels manuels (isolation des channels, inspection des planes, XOR, etc.).

Téléchargement de Stegsolve : https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Astuces de visibilité basées sur la FFT

La FFT n’est pas une extraction LSB ; elle est utilisée lorsque le contenu est délibérément caché dans le domaine fréquentiel ou dans des patterns subtils.

- Démo EPFL : http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier : https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic : https://github.com/0xcomposure/FFTStegPic

Le triage basé sur le Web est souvent utilisé dans les CTF :

- Aperi’Solve : https://aperisolve.com/
- StegOnline : https://stegonline.georgeom.net/

## Internals PNG : chunks, corruption et données cachées

### Technique

PNG est un format composé de chunks. Dans de nombreux challenges, le payload est stocké au niveau du container/chunk plutôt que dans les valeurs des pixels :

- **Octets supplémentaires après `IEND`** (de nombreux viewers ignorent les octets finaux)
- **Chunks ancillary non standard** contenant des payloads
- **Headers corrompus** qui masquent les dimensions ou empêchent les parsers de fonctionner jusqu’à leur correction

Emplacements de chunks à examiner en priorité :

- `tEXt` / `iTXt` / `zTXt` (métadonnées textuelles, parfois compressées)
- `iCCP` (profil ICC) et autres chunks ancillary utilisés comme carriers
- `eXIf` (données EXIF dans PNG)

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
- Astuces de formats de fichiers (cas particuliers PNG/JPEG/GIF) : https://github.com/corkami/docs

## JPEG : métadonnées, outils du domaine DCT et limites de l’ELA

### Technique

JPEG n’est pas stocké sous forme de pixels bruts ; il est compressé dans le domaine DCT. C’est pourquoi les outils de stego pour JPEG diffèrent des outils LSB pour PNG :

- Les payloads de métadonnées/commentaires sont au niveau du fichier (signal élevé et inspection rapide)
- Les outils de stego du domaine DCT intègrent des bits dans les coefficients de fréquence

En pratique, considérez JPEG comme :

- Un conteneur pour les segments de métadonnées (signal élevé, inspection rapide)
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
- Segments d'application (`APP1` pour EXIF, `APPn` pour les données du fournisseur)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEG, envisagez d'utiliser `stegseek` (bruteforce plus rapide que les anciens scripts) :

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA met en évidence différents artefacts de recompression ; il peut vous orienter vers les régions qui ont été modifiées, mais ce n'est pas un détecteur stego en soi :

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Images animées

### Technique

Pour les images animées, partez du principe que le message est :

- Dans une seule frame (facile), ou
- Réparti entre plusieurs frames (l'ordre est important), ou
- Visible uniquement lorsque vous faites la différence entre des frames consécutives

### Extraire les frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Traitez ensuite les frames comme des PNG normaux : `zsteg`, `pngcheck`, isolation des canaux.

Outils alternatifs :

- `gifsicle --explode anim.gif` (extraction rapide des frames)
- `imagemagick`/`magick` pour les transformations image par image

La différence entre les frames est souvent décisive :
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Encodage APNG par comptage de pixels

- Détecter les conteneurs APNG : `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraire les frames sans modifier le timing : `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Récupérer les payloads encodés sous forme de comptages de pixels par frame :
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
Les challenges animés peuvent encoder chaque byte sous forme du nombre de pixels d’une couleur spécifique dans chaque frame ; la concaténation de ces nombres reconstruit le message.<sup>[[1]](#references)</sup>

## Embedding protégé par mot de passe

Si vous suspectez un embedding protégé par une passphrase plutôt qu’une manipulation au niveau des pixels, il s’agit généralement de la voie la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et permet d’embedder ou d’extraire des payloads chiffrés.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Repo : https://github.com/StefanoDeVuono/steghide

### StegCracker
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Références

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
