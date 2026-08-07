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
Si `file` et l’extension ne correspondent pas, faites confiance à `file`. Traitez les formats courants comme des conteneurs lorsque cela est pertinent (par exemple, les documents OOXML sont des fichiers ZIP).

#### 2) Rechercher les métadonnées et les chaînes évidentes
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

- Inspecter les anomalies : `magick identify -verbose file`
- Pour PNG/BMP, énumérer les bit-planes/LSB : `zsteg -a file.png`
- Valider la structure PNG : `pngcheck -v file.png`
- Utiliser des filtres visuels (Stegsolve / StegoVeritas) lorsque le contenu peut être révélé par des transformations de channel/plane

#### 5) Si audio

- Spectrogramme en premier (Sonic Visualiser)
- Décoder/inspecter les streams : `ffmpeg -v info -i file -f null -`
- Si l’audio ressemble à des tonalités structurées, tester le décodage DTMF

### Outils essentiels

Ces outils détectent les cas fréquents au niveau des containers : payloads de metadata, bytes ajoutés en fin de fichier et fichiers embedded déguisés par leur extension.<sup>[[1]](#references)</sup>

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
Repo: https://github.com/korczis/foremost

#### Exiftool / Exiv2
```bash
exiftool file
exiv2 file
```
#### file / strings
```bash
file file
strings -n 6 file
```
#### cmp
```bash
cmp original.jpg stego.jpg -b -l
```
### Conteneurs, données ajoutées et astuces polyglottes

De nombreux challenges de stéganographie consistent en octets supplémentaires après un fichier valide, ou en archives intégrées dont l’extension a été déguisée.

#### Payloads ajoutés

De nombreux formats ignorent les octets finaux. Un ZIP/PDF/script peut être ajouté à un conteneur image/audio.

Vérifications rapides :
```bash
binwalk file
tail -c 200 file | xxd
```
Si vous connaissez un offset, utilisez `dd` pour faire du carving :
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

Essayez `7z` et `unzip` même si l’extension n’indique pas qu’il s’agit d’une archive zip :
```bash
7z l file
unzip -l file
```
### Bizarreries proches de stego

Liens rapides vers des motifs qui apparaissent régulièrement à proximité de stego (QR codes à partir de binaire, braille, etc.).

#### QR codes à partir de binaire

Si la longueur d’un blob est un carré parfait, il peut s’agir de pixels bruts pour une image/QR code.
```python
import math
math.isqrt(2500)  # 50
```
Aide à la conversion binaire en image :

- [https://www.dcode.fr/binary-image](https://www.dcode.fr/binary-image)

#### Braille

- [https://www.branah.com/braille-translator](https://www.branah.com/braille-translator)

## Références

- [1] [DominicBreuker/stego-toolkit - Image Docker regroupant les outils de steganography les plus populaires](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../../banners/hacktricks-training.md}}
