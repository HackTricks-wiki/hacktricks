# Flux de travail Stego

{{#include ../../banners/hacktricks-training.md}}

La plupart des problèmes stego se résolvent plus rapidement par un triage systématique que par l'utilisation d'outils aléatoires.

## Flux principal

### Liste de contrôle de triage rapide

L'objectif est de répondre efficacement à deux questions :

1. Quel est le véritable conteneur/format ?
2. Le payload est-il dans les metadata, des appended bytes, des embedded files, ou du content-level stego ?

#### 1) Identifier le conteneur
```bash
file target
ls -lah target
```
Si `file` et l'extension diffèrent, faites confiance à `file`. Considérez les formats courants comme des conteneurs lorsque cela est approprié (p. ex., les documents OOXML sont des fichiers ZIP).

#### 2) Recherchez les métadonnées et les chaînes évidentes
```bash
exiftool target
strings -n 6 target | head
strings -n 6 target | tail
```
Essayez plusieurs encodages:
```bash
strings -e l -n 6 target | head
strings -e b -n 6 target | head
```
#### 3) Vérifier les données ajoutées / les fichiers intégrés
```bash
binwalk target
binwalk -e target
```
Si l'extraction échoue mais que des signatures sont signalées, extrayez manuellement les offsets avec `dd` et relancez `file` sur la région extraite.

#### 4) Si image

- Inspectez les anomalies : `magick identify -verbose file`
- Si PNG/BMP, énumérez les bit-planes/LSB : `zsteg -a file.png`
- Validez la structure PNG : `pngcheck -v file.png`
- Utilisez des filtres visuels (Stegsolve / StegoVeritas) lorsque le contenu peut être révélé par des transformations de canal/plan

#### 5) Si audio

- Commencez par le spectrogramme (Sonic Visualiser)
- Décoder/inspecter les flux : `ffmpeg -v info -i file -f null -`
- Si l'audio ressemble à des tonalités structurées, testez le décodage DTMF

### Outils de base

Ils traitent les cas fréquents au niveau du conteneur : metadata payloads, appended bytes, et embedded files déguisés par l'extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Je n'ai pas le contenu de src/stego/workflow/README.md. Collez ici le texte à traduire (ou fournissez le passage précis) et je le traduirai en français en respectant vos consignes.
```bash
foremost -i file
```
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
### Containers, appended data, and polyglot tricks

Beaucoup de challenges de steganography consistent en des octets supplémentaires après un fichier valide, ou en des archives intégrées déguisées par l'extension.

#### Appended payloads

De nombreux formats ignorent les octets de fin. Un ZIP/PDF/script peut être ajouté à un image/audio container.

Fast checks:
```bash
binwalk file
tail -c 200 file | xxd
```
Si vous connaissez un offset, carve avec `dd`:
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Octets magiques

Quand `file` est confus, cherchez les octets magiques avec `xxd` et comparez-les aux signatures connues :
```bash
xxd -g 1 -l 32 file
```
#### Zip déguisé

Essayez `7z` et `unzip` même si l'extension n'indique pas zip:
```bash
7z l file
unzip -l file
```
### Particularités proches de stego

Liens rapides pour les motifs qui apparaissent régulièrement à côté de stego (QR-from-binary, braille, etc).

#### QR codes à partir de données binaires

Si la longueur d'un blob est un carré parfait, il peut s'agir de pixels bruts pour une image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Outil binaire-vers-image :

- https://www.dcode.fr/binary-image

#### Braille

- https://www.branah.com/braille-translator

## Listes de référence

- https://0xrick.github.io/lists/stego/
- https://github.com/DominicBreuker/stego-toolkit

{{#include ../../banners/hacktricks-training.md}}
