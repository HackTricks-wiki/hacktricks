# Flux de travail Stego

{{#include ../../banners/hacktricks-training.md}}

La plupart des problèmes stego se résolvent plus rapidement grâce à un triage systématique que par l'essai d'outils aléatoires.

## Flux principal

### Checklist de triage rapide

L'objectif est de répondre efficacement à deux questions :

1. Quel est le véritable conteneur/format ?
2. Le payload est-il dans metadata, appended bytes, embedded files, ou content-level stego ?

#### 1) Identifier le conteneur
```bash
file target
ls -lah target
```
Si `file` et l'extension ne correspondent pas, faites confiance à `file`. Considérez les formats courants comme des conteneurs lorsque c'est approprié (par ex., les documents OOXML sont des fichiers ZIP).

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
#### 3) Vérifier la présence de données ajoutées / de fichiers intégrés
```bash
binwalk target
binwalk -e target
```
Si l'extraction échoue mais que des signatures sont signalées, carve manuellement les offsets avec `dd` et relancez `file` sur la carved region.

#### 4) Si image

- Inspecter les anomalies : `magick identify -verbose file`
- Si PNG/BMP, énumérer les bit-planes/LSB : `zsteg -a file.png`
- Valider la structure PNG : `pngcheck -v file.png`
- Utiliser des filtres visuels (Stegsolve / StegoVeritas) lorsque le contenu peut être révélé par des channel/plane transforms

#### 5) Si audio

- Commencer par le spectrogramme (Sonic Visualiser)
- Décoder/inspecter les streams : `ffmpeg -v info -i file -f null -`
- Si l'audio ressemble à des tons structurés, tester le décodage DTMF

### Outils essentiels

Ils couvrent les cas fréquents au niveau du container : metadata payloads, appended bytes, et embedded files déguisés par l'extension.

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
#### Foremost
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
### Conteneurs, données ajoutées et polyglot tricks

De nombreux défis de steganography consistent en des octets supplémentaires après un fichier valide, ou des archives intégrées déguisées par leur extension.

#### Appended payloads

De nombreux formats ignorent les octets en fin de fichier. Un ZIP/PDF/script peut être ajouté à un conteneur image/audio.

Vérifications rapides:
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

Quand `file` est confus, cherchez les octets magiques avec `xxd` et comparez-les aux signatures connues:
```bash
xxd -g 1 -l 32 file
```
#### Zip déguisé

Essayez `7z` et `unzip` même si l'extension n'indique pas zip:
```bash
7z l file
unzip -l file
```
### Anomalies proches du stego

Liens rapides pour des motifs qui apparaissent régulièrement à proximité du stego (QR-from-binary, braille, etc).

#### Codes QR à partir d'un binaire

Si la longueur d'un blob est un carré parfait, il peut s'agir de pixels bruts pour une image/QR.
```python
import math
math.isqrt(2500)  # 50
```
Outil d'aide binaire-vers-image :

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Listes de référence

- [https://0xrick.github.io/lists/stego/](https://0xrick.github.io/lists/stego/)
- [https://github.com/DominicBreuker/stego-toolkit](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
