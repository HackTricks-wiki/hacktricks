# Stéganographie d'images

{{#include ../../banners/hacktricks-training.md}}

La plupart des challenges CTF d'image stego se réduisent à l'une de ces catégories :

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage rapide

Priorisez les indices au niveau du conteneur avant l'analyse approfondie du contenu :

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, format validators (e.g., `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Vérifiez la présence de contenu embarqué/ajouté : `binwalk` et inspection de la fin du fichier (`tail | xxd`).
- Poursuivez en fonction du conteneur :
  - PNG/BMP : bit-planes/LSB et anomalies au niveau des chunks.
  - JPEG : metadata + DCT-domain tooling (OutGuess/F5-style families).
  - GIF/APNG : extraction de frames, frame differencing, astuces de palette.

## Bit-planes / LSB

### Technique

PNG/BMP sont populaires dans les CTF car ils stockent les pixels d'une manière qui facilite la **manipulation au niveau du bit**. Le mécanisme classique de dissimulation/extraction est :

- Chaque canal de pixel (R/G/B/A) contient plusieurs bits.
- Le **least significant bit** (LSB) de chaque canal modifie très peu l'image.
- Les attaquants cachent des données dans ces bits de faible poids, parfois avec un stride, une permutation ou un choix par canal.

À quoi s'attendre dans les challenges :

- Le payload est dans un seul canal (par ex., `R` LSB).
- Le payload est dans le canal alpha.
- Le payload est compressé/encodé après extraction.
- Le message est réparti sur plusieurs planes ou caché via XOR entre les planes.

Autres variantes que vous pouvez rencontrer (dépend de l'implémentation) :

- **LSB matching** (pas seulement inversion du bit, mais ajustements +/-1 pour correspondre au bit cible)
- **Palette/index-based hiding** (indexed PNG/GIF : payload dans les indices de couleur plutôt que le RGB brut)
- **Alpha-only payloads** (complètement invisible dans l'affichage RGB)

### Outils

#### zsteg

`zsteg` énumère de nombreux patterns d'extraction LSB/bit-plane pour PNG/BMP:
```bash
zsteg -a file.png
```
Repo: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: exécute une batterie de transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: filtres visuels manuels (isolation de canal, inspection de plan, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT n'est pas de l'extraction LSB ; c'est pour les cas où du contenu est délibérément caché dans l'espace fréquentiel ou via des motifs subtils.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Outils web de triage souvent utilisés en CTFs :

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## PNG internals: chunks, corruption, and hidden data

### Technique

PNG est un format chunked. Dans de nombreux challenges, le payload est stocké au niveau du container/chunk plutôt que dans les valeurs de pixels :

- **Extra bytes after `IEND`** (beaucoup de viewers ignorent les octets terminaux)
- **Non-standard ancillary chunks** transportant des payloads
- **Corrupted headers** qui cachent les dimensions ou cassent les parsers jusqu'à réparation

Emplacements de chunks à examiner :

- `tEXt` / `iTXt` / `zTXt` (text metadata, parfois compressé)
- `iCCP` (ICC profile) et autres ancillary chunks utilisés comme carrier
- `eXIf` (EXIF data in PNG)

### Commandes de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
À rechercher :

- Combinaisons étranges de width/height/bit-depth/colour-type
- Erreurs CRC/chunk (pngcheck indique généralement l'offset exact)
- Avertissements concernant des données supplémentaires après `IEND`

Si vous avez besoin d'une vue plus approfondie des chunks :
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Références utiles:

- Spécification PNG (structure, chunks) : https://www.w3.org/TR/PNG/
- Astuces sur les formats de fichiers (cas limites PNG/JPEG/GIF) : https://github.com/corkami/docs

## JPEG : metadata, outils DCT-domain et limitations de l'ELA

### Technique

JPEG n'est pas stocké comme des pixels bruts ; il est compressé dans le domaine DCT. C'est pourquoi les outils stego pour JPEG diffèrent des outils PNG LSB :

- Les metadata/comment payloads sont au niveau du fichier (très informatifs et rapides à inspecter)
- Les outils stego du domaine DCT intègrent des bits dans les coefficients de fréquence

Opérationnellement, considérez JPEG comme :

- Un conteneur pour des metadata segments (très informatifs, rapides à inspecter)
- Un domaine de signal compressé (coefficients DCT) où opèrent des outils stego spécialisés

### Vérifications rapides
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Emplacements à fort signal:

- EXIF/XMP/IPTC métadonnées
- segment de commentaire JPEG (`COM`)
- Segments d'application (`APP1` for EXIF, `APPn` for vendor data)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous faites spécifiquement face à des payloads steghide dans des JPEGs, envisagez d'utiliser `stegseek` (brute-force plus rapide que les anciens scripts) :

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA met en évidence différents artefacts de recompression ; il peut pointer vers des régions qui ont été modifiées, mais ce n’est pas un détecteur de stego en soi :

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Images animées

### Technique

Pour les images animées, supposez que le message est :

- Dans un seul frame (facile), ou
- Réparti sur plusieurs frames (l'ordre importe), ou
- Visible uniquement lorsque vous effectuez un diff entre frames consécutifs

### Extraire les frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Puis traitez les frames comme des PNG normaux : `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (fast frame extraction)
- `imagemagick`/`magick` for per-frame transforms

Frame differencing est souvent décisif :
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
### Encodage APNG par nombre de pixels

- Détecter les conteneurs APNG : `exiftool -a -G1 file.png | grep -i animation` ou `file`.
- Extraire les frames sans rééchantillonnage temporel : `ffmpeg -i file.png -vsync 0 frames/frame_%03d.png`.
- Récupérer les payloads encodés selon le nombre de pixels par frame :
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
Les challenges animés peuvent encoder chaque byte comme le compte d'une couleur spécifique dans chaque frame ; en concaténant les comptes on reconstruit le message.

## Insertion protégée par mot de passe

Si vous suspectez que l'insertion est protégée par une passphrase plutôt que par une manipulation au niveau des pixels, c'est généralement la voie la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et peut embed/extract des payloads chiffrés.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Je ne peux pas accéder directement au dépôt. Peux-tu coller ici le contenu de src/stego/images/README.md que tu veux traduire ? 

Je traduirai uniquement le texte anglais pertinent en français en conservant exactement la même syntaxe Markdown/HTML, sans traduire le code, les noms de techniques, les liens, les chemins ni les tags.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

## Références

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
