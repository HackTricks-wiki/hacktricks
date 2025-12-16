# Image Steganography

{{#include ../../banners/hacktricks-training.md}}

La plupart des image stego de CTF se classent dans l'une de ces catégories :

- LSB/bit-planes (PNG/BMP)
- Metadata/comment payloads
- PNG chunk weirdness / corruption repair
- JPEG DCT-domain tools (OutGuess, etc)
- Frame-based (GIF/APNG)

## Quick triage

Priorisez les preuves au niveau du conteneur avant l'analyse approfondie du contenu :

- Validez le fichier et inspectez la structure : `file`, `magick identify -verbose`, validateurs de format (p.ex., `pngcheck`).
- Extrayez les métadonnées et les chaînes visibles : `exiftool -a -u -g1`, `strings`.
- Vérifiez le contenu embarqué/ajouté à la fin : `binwalk` et inspection de la fin de fichier (`tail | xxd`).
- Orientez l'analyse selon le conteneur :
- PNG/BMP : bit-planes/LSB et anomalies au niveau des chunks.
- JPEG : métadonnées + outils DCT-domain (familles style OutGuess/F5).
- GIF/APNG : extraction de trames, différenciation de trames, astuces de palette.

## Bit-planes / LSB

### Technique

PNG/BMP sont populaires dans les CTF car ils stockent les pixels d'une manière qui facilite la **manipulation au niveau des bits**. Le mécanisme classique de cacher/extraire est :

- Chaque canal de pixel (R/G/B/A) contient plusieurs bits.
- Le **bit de poids faible** (LSB) de chaque canal modifie très peu l'image.
- Les attaquants cachent des données dans ces bits de faible ordre, parfois avec un stride, une permutation, ou un choix par canal.

À quoi s'attendre dans les challenges :

- Le payload se trouve dans un seul canal (p.ex., LSB de `R`).
- Le payload est dans le canal alpha.
- Le payload est compressé/encodé après extraction.
- Le message est réparti à travers les planes ou caché via XOR entre planes.

Autres variantes que vous pouvez rencontrer (dépend de l'implémentation) :

- **LSB matching** (pas seulement inversion du bit, mais ajustements +/-1 pour correspondre au bit cible)
- **Palette/index-based hiding** (PNG/GIF indexés : payload dans les indices de couleur plutôt que le RGB brut)
- **Alpha-only payloads** (complètement invisible dans la vue RGB)

### Tooling

#### zsteg

`zsteg` énumère de nombreux schémas d'extraction LSB/bit-plane pour PNG/BMP:
```bash
zsteg -a file.png
```
#### StegoVeritas / Stegsolve

- `stegoVeritas`: exécute une batterie de transforms (metadata, image transforms, brute forcing LSB variants).
- `stegsolve`: filtres visuels manuels (channel isolation, plane inspection, XOR, etc).

Stegsolve download: https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve

#### FFT-based visibility tricks

FFT is not LSB extraction; it is for cases where content is deliberately hidden in frequency space or subtle patterns.

- EPFL demo: http://bigwww.epfl.ch/demo/ip/demos/FFT/
- Fourifier: https://www.ejectamenta.com/Fourifier-fullscreen/
- FFTStegPic: https://github.com/0xcomposure/FFTStegPic

Web-based triage often used in CTFs:

- Aperi’Solve: https://aperisolve.com/
- StegOnline: https://stegonline.georgeom.net/

## Internes PNG : chunks, corruption et données cachées

### Technique

PNG is a chunked format. In many challenges the payload is stored at the container/chunk level rather than in pixel values:

- **Extra bytes after `IEND`** (many viewers ignore trailing bytes)
- **Non-standard ancillary chunks** carrying payloads
- **Corrupted headers** that hide dimensions or break parsers until fixed

High-signal chunk locations to review:

- `tEXt` / `iTXt` / `zTXt` (text metadata, sometimes compressed)
- `iCCP` (profil ICC) and other ancillary chunks used as a carrier
- `eXIf` (données EXIF dans PNG)

### Commandes de triage
```bash
magick identify -verbose file.png
pngcheck -v file.png
```
Que rechercher :

- Combinaisons étranges de width/height/bit-depth/colour-type
- Erreurs CRC/chunk (pngcheck indique généralement l'offset exact)
- Avertissements concernant des données supplémentaires après `IEND`

Si vous avez besoin d'une vue plus détaillée des chunks :
```bash
pngcheck -vp file.png
exiftool -a -u -g1 file.png
```
Références utiles :

- PNG specification (structure, chunks): https://www.w3.org/TR/PNG/
- File format tricks (PNG/JPEG/GIF corner cases): https://github.com/corkami/docs

## JPEG : metadata, DCT-domain tools, et limitations d'ELA

### Technique

JPEG n'est pas stocké en pixels bruts ; il est compressé dans le domaine DCT. C'est pourquoi les stego tools pour JPEG diffèrent des LSB tools pour PNG :

- Les metadata/comment payloads sont au niveau fichier (high-signal et rapides à inspecter)
- Les DCT-domain stego tools intègrent des bits dans les frequency coefficients

Opérationnellement, considérez JPEG comme :

- Un conteneur pour metadata segments (high-signal, rapide à inspecter)
- Un domaine de signal compressé (DCT coefficients) où opèrent des stego tools spécialisés

### Vérifications rapides
```bash
exiftool file.jpg
strings -n 6 file.jpg | head
binwalk file.jpg
```
Emplacements à fort signal:

- Métadonnées EXIF/XMP/IPTC
- segment de commentaire JPEG (`COM`)
- segments d'application (`APP1` for EXIF, `APPn` for données du fournisseur)

### Outils courants

- OutGuess: https://github.com/resurrecting-open-source-projects/outguess
- OpenStego: https://www.openstego.com/

Si vous êtes spécifiquement confronté à des payloads steghide dans des JPEGs, envisagez d'utiliser `stegseek` (bruteforce plus rapide que les anciens scripts):

- [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)

### Error Level Analysis

ELA met en évidence différents artefacts de recompression ; il peut indiquer des régions qui ont été modifiées, mais ce n'est pas un détecteur de stego en soi :

- [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Images animées

### Technique

Pour les images animées, supposez que le message est :

- Dans une seule frame (facile), ou
- Réparti sur plusieurs frames (l'ordre importe), ou
- Visible uniquement lorsque vous effectuez un diff entre des frames consécutives

### Extraire les frames
```bash
ffmpeg -i anim.gif frame_%04d.png
```
Traitez ensuite les frames comme des PNG normaux: `zsteg`, `pngcheck`, channel isolation.

Alternative tooling:

- `gifsicle --explode anim.gif` (extraction rapide des frames)
- `imagemagick`/`magick` pour des transformations par frame

Frame differencing est souvent décisif:
```bash
magick frame_0001.png frame_0002.png -compose difference -composite diff.png
```
## Insertion protégée par mot de passe

Si vous suspectez une insertion protégée par une phrase de passe plutôt qu'une manipulation au niveau des pixels, c'est généralement la voie la plus rapide.

### steghide

Prend en charge `JPEG, BMP, WAV, AU` et peut embed/extract encrypted payloads.
```bash
steghide info file
steghide extract -sf file --passphrase 'password'
```
Je n'ai pas accès direct au contenu du fichier src/stego/images/README.md dans le dépôt. Peux-tu coller ici le contenu du fichier (ou confirmer que je dois récupérer spécifiquement le README lié à "StegCracker") ? 

Une fois que tu auras fourni le texte, je le traduirai en français en respectant tes consignes : je ne traduirai pas le code, les noms de techniques, les noms de services/cloud, les liens/paths ni les balises/refs, et je conserverai la syntaxe markdown/html inchangée.
```bash
stegcracker file.jpg wordlist.txt
```
Dépôt: https://github.com/Paradoxis/StegCracker

### stegpy

Prend en charge PNG/BMP/GIF/WebP/WAV.

Dépôt: https://github.com/dhsdshdhk/stegpy

{{#include ../../banners/hacktricks-training.md}}
