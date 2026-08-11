# Flux de travail Stego

{{#include ../../banners/hacktricks-training.md}}

La plupart des problèmes de stego sont résolus plus rapidement grâce à un triage systématique plutôt qu'en essayant des outils au hasard.

## Flux principal

### Checklist de triage rapide

L'objectif est de répondre efficacement à deux questions :

1. Quel est le conteneur/format réel ?
2. Le payload se trouve-t-il dans les métadonnées, des octets ajoutés, des fichiers intégrés ou du stego au niveau du contenu ?

#### 1) Identifier le conteneur
```bash
file target
ls -lah target
```
Si `file` et l’extension ne correspondent pas, examinez la signature au lieu de faire confiance au suffixe. `file` est également heuristique et peut être induit en erreur par une entrée malformée ou polyglotte. Traitez les formats courants comme des conteneurs lorsque cela est pertinent (par exemple, les documents OOXML sont des packages ZIP).<sup>[[2]](#references)</sup>

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
Si l'extraction échoue mais que des signatures sont signalées, récupérez manuellement les offsets avec `dd`, puis exécutez à nouveau `file` sur la région récupérée.

#### 4) Si image

- Inspectez les anomalies : `magick identify -verbose file`
- Si PNG/BMP, énumérez les bit-planes/LSB : `zsteg -a file.png`
- Validez la structure PNG : `pngcheck -v file.png`
- Utilisez des filtres visuels (Stegsolve / StegoVeritas) lorsque le contenu peut être révélé par des transformations de canal/plane

#### 5) Si audio

- Commencez par le spectrogramme (Sonic Visualiser)
- Décodez/inspectez les streams : `ffmpeg -v info -i file -f null -`
- Si l'audio ressemble à des tonalités structurées, testez le décodage DTMF

### Outils essentiels

Ils détectent les cas fréquents au niveau des conteneurs : payloads de métadonnées, octets ajoutés et fichiers intégrés déguisés par leur extension.<sup>[[1]](#references)[[3]](#references)</sup>

#### Binwalk
```bash
binwalk file
binwalk -e file
binwalk --dd '.*' file
```
Dépôt : https://github.com/ReFirmLabs/binwalk

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
### Conteneurs, données ajoutées et astuces polyglottes

De nombreux défis de stéganographie consistent en octets supplémentaires après un fichier valide, ou en archives intégrées dont l’extension a été modifiée.

#### Payloads ajoutés

De nombreux formats ignorent les octets de fin. Un ZIP/PDF/script peut être ajouté à un conteneur d’image/audio.

Vérifications rapides :
```bash
binwalk file
tail -c 200 file | xxd
```
Si vous connaissez un offset, extrayez avec `dd` :
```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```
#### Magic bytes

Lorsque `file` ne parvient pas à identifier correctement le fichier, recherchez les magic bytes avec `xxd` et comparez-les aux signatures connues :
```bash
xxd -g 1 -l 32 file
```
#### Zip-in-disguise

Essayez `7z` et `unzip` même si l’extension n’indique pas qu’il s’agit d’une archive zip :
```bash
7z l file
unzip -l file
```
### Anomalies proches de la stéganographie

Liens rapides vers des motifs qui apparaissent régulièrement à côté de la stéganographie (QR à partir de binaire, braille, etc.).

#### QR codes à partir de binaire

Si la longueur d'un blob est un carré parfait, il peut s'agir de pixels bruts pour une image/ un QR.
```python
import math
math.isqrt(2500)  # 50
```
Outil de conversion binaire vers image :

- Outil dCode de conversion binaire en image.<sup>[[5]](#references)</sup>

#### Braille

- Traducteur Braille de Branah.<sup>[[6]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Image Docker contenant les outils de stéganographie les plus populaires](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Conventions de packaging ouvert ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Image binaire](https://www.dcode.fr/binary-image)
- [6] [Branah — Traducteur Braille](https://www.branah.com/braille-translator)
{{#include ../../banners/hacktricks-training.md}}
