# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La plupart des challenges CTF d'image stego se réduisent à l'une de ces catégories :

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Triage rapide

Priorisez les preuves au niveau du conteneur avant l'analyse approfondie du contenu :

- Validez le fichier et inspectez sa structure : `file`, `magick identify -verbose`, validateurs de format (par ex., `pngcheck`).
- Extraire les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Vérifiez la présence de contenu embarqué/ajouté : `binwalk` et inspection de fin de fichier (`tail | xxd`).
- Faites le tri selon le conteneur :
- PNG/BMP: bit-planes/LSB and chunk-level anomalies.
- JPEG: métadonnées + DCT-domain tooling (OutGuess/F5-style families).
- GIF/APNG: extraction de frames, frame differencing, palette tricks.

## Bit-planes / LSB

### Technique

PNG/BMP are popular in CTFs because they store pixels in a way that makes **bit-level manipulation** easy. The classic hide/extract mechanism is:

- Each pixel channel (R/G/B/A) has multiple bits.
- The **least significant bit** (LSB) of each channel changes the image very little.
- Attackers hide data in those low-order bits, sometimes with a stride, permutation, or per-channel choice.

What to expect in challenges:

- The payload is in one channel only (e.g., `R` LSB).
- The payload is in the alpha channel.
- Payload is compressed/encoded after extraction.
- The message is spread across planes or hidden via XOR between planes.

Additional families you may encounter (implementation-dependent):

- **LSB matching** (not just flipping the bit, but +/-1 adjustments to match target bit)
- **Palette/index-based hiding** (indexed PNG/GIF: payload in color indices rather than raw RGB)
- **Alpha-only payloads** (completely invisible in RGB view)

### Tooling

#### zsteg

`zsteg` énumère de nombreux schémas d'extraction LSB/bit-plane pour PNG/BMP:
```bash
zsteg -a file.png
```
Dépôt: https://github.com/zed-0xff/zsteg

#### StegoVeritas / Stegsolve

- `stegoVeritas`: exécute une série de transformations (métadonnées, transformations d'image, brute forcing des variantes LSB).
- `stegsolve`: filtres visuels manuels (isolation de canal, inspection de plans, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT n'est pas une extraction LSB ; il sert pour les cas où le contenu est délibérément caché dans l'espace fréquentiel ou des motifs subtils.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage souvent utilisé dans les CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internes du PNG : chunks, corruption et données cachées

### Technique

PNG est un format par chunks. Dans de nombreux défis la charge utile est stockée au niveau du conteneur/chunk plutôt que dans les valeurs de pixels :

- **Extra bytes after `IEND`** (beaucoup de visionneurs ignorent les octets finaux)
- **Non-standard ancillary chunks** transportant des payloads
- **En-têtes corrompus** qui cachent les dimensions ou cassent les parseurs jusqu'à leur correction

Emplacements de chunks à fort signal à examiner :

- `tEXt` / `iTXt` / `zTXt` (métadonnées textuelles, parfois compressées)
- `iCCP` (ICC profile) et autres chunks auxiliaires utilisés comme support
- `eXIf` (données EXIF dans le PNG)

### Commandes de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Ce qu'il faut rechercher :

- Combinaisons étranges de largeur/hauteur/profondeur-en-bits/type-de-couleur
- Erreurs CRC/chunk (pngcheck indique généralement l'offset exact)
- Avertissements concernant des données supplémentaires après `IEND`

Si vous avez besoin d'une vue plus approfondie des chunks :
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Références utiles :

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- Astuces sur les formats de fichiers (cas particuliers PNG/JPEG/GIF): https://github.com/corkami/docs

## JPEG : metadata, outils opérant dans le domaine DCT, et limites d'ELA

### Technique

JPEG n'est pas stocké en pixels bruts ; il est compressé dans le domaine DCT. C'est pourquoi les outils stego pour JPEG diffèrent des outils LSB pour PNG :

- Metadata/comment payloads sont au niveau du fichier (high-signal et rapides à inspecter)
- Les outils stego opérant dans le domaine DCT intègrent des bits dans les coefficients de fréquence

Opérationnellement, considérez JPEG comme :

- Un conteneur pour des segments metadata (high-signal, rapides à inspecter)
- Un domaine de signal compressé (coefficients DCT) où opèrent des outils stego spécialisés

### Vérifications rapides
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Emplacements à forte probabilité :

- métadonnées EXIF/XMP/IPTC
- Segment de commentaire JPEG (`COM`)
- Segments d'application (`APP1` pour EXIF, `APPn` pour les données du fournisseur)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEGs, envisagez d'utiliser `stegseek` (brute force plus rapide que les scripts plus anciens) :

- https://github.com/RickdeJager/stegseek

### Error Level Analysis

ELA met en évidence différents artefacts de recompression ; il peut indiquer des régions qui ont été modifiées, mais ce n'est pas un détecteur de stego en soi :

- https://29a.ch/sandbox/2012/imageerrorlevelanalysis/

## Images animées

### Technique

Pour les images animées, supposez que le message se trouve :

- Dans une seule image (facile), ou
- Réparti sur plusieurs images (l'ordre importe), ou
- Visible uniquement lorsque vous effectuez un diff entre des images consécutives

### Extraire les images
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Traitez ensuite les frames comme des PNG normaux : `zsteg`, `pngcheck`, isolation des canaux.

Outils alternatifs :

- `gifsicle --explode anim.gif` (extraction rapide des frames)
- `imagemagick`/`magick` pour des transformations par frame

La différence entre frames est souvent décisive :
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Embedding protégé par mot de passe

Si vous suspectez un embedding protégé par une passphrase plutôt qu'une manipulation au niveau des pixels, c'est généralement la voie la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et peut embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Je n’ai pas accès direct au dépôt. Peux-tu coller ici le contenu de src/stego/images/README.md (ou uniquement la section "StegCracker") à traduire ? Je ferai la traduction en français en conservant exactement la syntaxe markdown/HTML, les chemins et les tags.
```bash
stegcracker file.jpg wordlist.txt
```
Repo: https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Repo: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
