# Stéganographie d’image

{{#include ../../banners/hacktricks-training.md}}

La stéganographie d’image dans la plupart des CTF se résume à l’un de ces cas :

- LSB/plans de bits (PNG/BMP)
- Payloads dans les métadonnées/commentaires
- Anomalies dans les chunks PNG / réparation de fichiers corrompus
- Outils opérant dans le domaine DCT des JPEG (OutGuess, etc.)
- Images basées sur des frames (GIF/APNG)

## Triage rapide

Priorisez les éléments au niveau du conteneur avant d’analyser le contenu en profondeur :

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, validateurs de format (p. ex., `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Recherchez du contenu intégré ou ajouté à la fin du fichier : `binwalk` et inspection de la fin du fichier (`tail | xxd`).
- Choisissez une piste selon le conteneur :
  - PNG/BMP : plans de bits/LSB et anomalies au niveau des chunks.
  - JPEG : métadonnées et outils opérant dans le domaine DCT (familles de type OutGuess/F5).
  - GIF/APNG : extraction des frames, comparaison entre frames, astuces liées aux palettes.

## Plans de bits / LSB

### Technique

Les formats PNG/BMP sont populaires dans les CTF, car ils stockent les pixels d’une manière qui facilite la **manipulation au niveau des bits**. Le mécanisme classique de dissimulation/extraction est le suivant :

- Chaque canal de pixel (R/G/B/A) comporte plusieurs bits.
- Le **bit de poids faible** (LSB) de chaque canal modifie très peu l’image.
- Les attaquants dissimulent des données dans ces bits de poids faible, parfois avec un pas, une permutation ou un choix de canal spécifique.

À quoi s’attendre dans les challenges :

- Le payload est dans un seul canal (p. ex., le LSB de `R`).
- Le payload est dans le canal alpha.
- Le payload est compressé/encodé après extraction.
- Le message est réparti entre plusieurs plans ou dissimulé par XOR entre les plans.

Autres familles que vous pourriez rencontrer (selon l’implémentation) :

- **LSB matching** (ne consiste pas seulement à inverser le bit, mais à ajuster la valeur de +/-1 pour correspondre au bit cible)
- **Dissimulation basée sur une palette/un index** (PNG/GIF indexés : le payload est dans les indices de couleur plutôt que dans les valeurs RGB brutes)
- **Payloads uniquement dans le canal alpha** (complètement invisibles dans une vue RGB)

### Outils

#### zsteg

`zsteg` énumère de nombreux modèles d’extraction LSB/de plans de bits pour les fichiers PNG/BMP :

```bash
zsteg -a file.png
```

Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas` : exécute une série de transformations (métadonnées, transformations d’image, brute force de variantes LSB).
- `stegsolve` : filtres visuels manuels (isolation des canaux, inspection des plans, XOR, etc.).

Téléchargement de Stegsolve : https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### Astuces de visibilité basées sur la FFT

La FFT n’est pas une méthode d’extraction LSB ; elle sert lorsque du contenu est délibérément caché dans l’espace fréquentiel ou dans des motifs subtils.

- Démo EPFL : http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier : https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic : https://github.com/0xcomposure/FFTStegPic

Outils de triage web souvent utilisés dans les CTF :

- Aperi’Solve : https://aperisolve.com/
- StegOnline : https://stegonline.georgeom.net/

## Fonctionnement interne des PNG : chunks, corruption et données cachées

### Technique

Le PNG est un format composé de chunks. Dans de nombreux challenges, le payload est stocké au niveau du conteneur ou des chunks plutôt que dans les valeurs des pixels :

- **Octets supplémentaires après `IEND`** (de nombreux visualiseurs ignorent les octets en fin de fichier)
- **Chunks auxiliaires non standard** contenant des payloads ; voir le [parcours des chunks PNG et le workflow de carving](../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/png-tricks.md#extract-ancillary-chunk-payloads).
- **En-têtes corrompus** qui masquent les dimensions ou empêchent les parsers de fonctionner jusqu’à leur réparation

Emplacements de chunks particulièrement intéressants à examiner :

- `tEXt` / `iTXt` / `zTXt` (métadonnées textuelles, parfois compressées)
- `iCCP` (profil ICC) et d’autres chunks auxiliaires utilisés comme support
- `eXIf` (données EXIF dans les PNG)

### Commandes de triage

```bash
magick identify -verbose file.png
pngcheck -v file.png
```

À rechercher :

- Des combinaisons inhabituelles de largeur/hauteur/profondeur de bits/type de couleur
- Des erreurs CRC/de chunk (pngcheck indique généralement l’offset exact)
- Des avertissements concernant des données supplémentaires après `IEND`

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

Le JPEG n’est pas stocké sous forme de pixels bruts ; il est compressé dans le domaine DCT. C’est pourquoi les outils de stéganographie JPEG diffèrent des outils LSB pour PNG :

- Les charges utiles des métadonnées/commentaires se trouvent au niveau du fichier (signal fort, inspection rapide)
- Les outils de stéganographie du domaine DCT intègrent des bits dans les coefficients fréquentiels

En pratique, considérez le JPEG comme :

- Un conteneur de segments de métadonnées (signal fort, inspection rapide)
- Un domaine de signal compressé (coefficients DCT) dans lequel opèrent des outils de stéganographie spécialisés

### Vérifications rapides

```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```

High-signal locations:

- Métadonnées EXIF/XMP/IPTC
- Segment de commentaire JPEG (`COM`)
- Segments d’application (`APP1` pour EXIF, `APPn` pour les données du fournisseur)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEG, envisagez d’utiliser `stegseek` (bruteforce plus rapide que les anciens scripts) :

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

L’ELA met en évidence différents artefacts de recompression ; elle peut vous orienter vers les zones modifiées, mais ne détecte pas les stego à elle seule :

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Images animées

### Technique

Pour les images animées, partez du principe que le message est :

- Dans une seule frame (facile), ou
- Réparti sur plusieurs frames (l’ordre est important), ou
- Visible uniquement lorsque vous comparez deux frames consécutives

### Extraire les frames

```bash
ffmpeg -i anim.gif frame_%04d.png
```

Traitez ensuite les frames comme des PNG normaux : `zsteg`, `pngcheck`, isolation des canaux.

Autres outils :

- `gifsicle --explode anim.gif` (extraction rapide des frames)
- `imagemagick`/`magick` pour les transformations frame par frame

La comparaison des frames est souvent décisive :

```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```

### Encodage par nombre de pixels APNG

- Détecter les conteneurs APNG : `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraire les frames sans modifier leur durée : `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
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

Les défis animés peuvent encoder chaque octet sous forme du nombre de pixels d’une couleur donnée dans chaque image ; la concaténation des nombres reconstitue le message.<sup>[[1]](#references)</sup>

## Intégration protégée par mot de passe

Si vous soupçonnez une intégration protégée par une phrase secrète plutôt qu’une manipulation au niveau des pixels, c’est généralement la méthode la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et permet d’intégrer ou d’extraire des données chiffrées.

```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```

Dépôt : https://github.com/StefanoDeVuono/steghide

### StegCracker

```bash
stegcracker file.jpg wordlist.txt
```

Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy



## References

- [1] [Flagvent 2025 (Medium) — pink, Liste de souhaits du Père Noël, Métadonnées de Noël, Bruit capturé](https://0xdf.gitlab.io/flagvent2025/medium)
{{#include ../../banners/hacktricks-training.md}}
