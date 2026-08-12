# Workflow Stego

{{#include ../../banners/hacktricks-training.md}}

La plupart des problèmes de stego se résolvent plus rapidement grâce à un triage systématique plutôt qu'en essayant des outils au hasard.

## Flux principal

### Checklist de triage rapide

L'objectif est de répondre efficacement à deux questions :

1. Quel est le véritable conteneur/format ?
2. Le payload se trouve-t-il dans les métadonnées, des octets ajoutés, des fichiers intégrés ou du stego au niveau du contenu ?

#### 1) Identifier le conteneur
```bash
file target
ls -lah target
```
Si `file` et l’extension ne concordent pas, examinez la signature au lieu de faire confiance au suffixe. `file` est également heuristique et peut être induit en erreur par des entrées malformées ou polyglottes. Traitez les formats courants comme des conteneurs lorsque cela est pertinent (par exemple, les documents OOXML sont des packages ZIP).<sup>[[2]](#references)</sup>

#### 2) Recherchez les métadonnées et les chaînes évidentes
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Essayez plusieurs encodages :
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Vérifier la présence de données ajoutées / fichiers intégrés
```bash
binwalk target
binwalk -e target
```
Si l’extraction échoue mais que des signatures sont signalées, extrayez manuellement les offsets avec `dd`, puis réexécutez `file` sur la région extraite.

#### 4) Si image

- Inspectez les anomalies : `magick identify -verbose file`
- Pour les fichiers PNG/BMP, énumérez les bit-planes/LSB : `zsteg -a file.png`
- Validez la structure PNG : `pngcheck -v file.png`
- Utilisez des filtres visuels (Stegsolve / StegoVeritas) lorsque le contenu peut être révélé par des transformations de canaux/plans

#### 5) Si audio

- Commencez par le spectrogramme (Sonic Visualiser)
- Décodez/inspectez les streams : `ffmpeg -v info -i file -f null -`
- Si l’audio ressemble à des tonalités structurées, testez le décodage DTMF

### Outils essentiels

Ces outils détectent les cas fréquents au niveau des containers : payloads de métadonnées, octets ajoutés et fichiers embarqués déguisés par leur extension.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Repo: https://github.com/ReFirmLabs/binwalk

#### Foremost
```bash
foremost -i file
```
Dépôt du projet : `korczis/foremost`.<sup>[[4]](#references)</sup>

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### fichier / chaînes
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Conteneurs, données ajoutées et techniques de polyglottes

De nombreux challenges de stéganographie consistent en octets supplémentaires après un fichier valide ou en archives intégrées dont l’extension a été modifiée.

#### Payloads ajoutés

De nombreux formats ignorent les octets de fin. Un ZIP/PDF/script peut être ajouté à un conteneur d’image ou audio.

Vérifications rapides :
```bash
binwalk file
tail -c 200 file | xxd
```
Si vous connaissez un offset, faites du carving avec `dd` :
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Lorsque `file` est confus, recherchez les magic bytes avec `xxd` et comparez-les aux signatures connues :
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Essayez `7z` et `unzip` même si l’extension n’indique pas qu’il s’agit d’un fichier zip :
```bash
7z l file
unzip -l file
```
### Anomalies proches de stego

Liens rapides vers les motifs qui apparaissent régulièrement à proximité de stego (QR-from-binary, braille, etc.).

#### QR codes from binary

Si la longueur d'un blob est un carré parfait, il peut s'agir de pixels bruts pour une image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Assistant de conversion binaire en image :

- Assistant binary-image de dCode.<sup>[[5]](#references)</sup>

#### Braille

- Traducteur Braille de Branah.<sup>[[6]](#references)</sup>

Pour des collections plus larges d'utilitaires de steganography et de ressources spécifiques aux techniques, consultez le stego-toolkit inclus et la liste organisée par 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Image Docker regroupant les outils de steganography les plus populaires](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Conventions ECMA-376 pour le packaging ouvert](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Image binaire](https://www.dcode.fr/binary-image)
- [6] [Branah — Traducteur Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Ressources de steganography](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
