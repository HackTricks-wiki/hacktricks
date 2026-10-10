# Flux de travail de stéganographie

{{#include ../../banners/hacktricks-training.md}}

La plupart des problèmes de stéganographie se résolvent plus rapidement avec un triage systématique qu’en essayant des outils au hasard.

## Flux principal

### Liste de contrôle pour un triage rapide

L’objectif est de répondre efficacement à deux questions :

1. Quel est le véritable conteneur/format ?
2. Le payload se trouve-t-il dans les métadonnées, dans des octets ajoutés, dans des fichiers intégrés ou dans le contenu lui-même ?

#### 1) Identifier le conteneur

```bash
file target
ls -lah target
```

Si `file` et l’extension ne correspondent pas, examinez la signature au lieu de vous fier au suffixe. `file` repose aussi sur des heuristiques et peut être induit en erreur par des entrées malformées ou polyglottes. Traitez les formats courants comme des conteneurs lorsque c’est pertinent (par exemple, les documents OOXML sont des packages ZIP).<sup>[[2]](#references)</sup>

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

#### 3) Vérifier la présence de données ajoutées / de fichiers intégrés

```bash
binwalk target
binwalk -e target
```

Si l’extraction échoue mais que des signatures sont signalées, récupérez manuellement les offsets avec `dd`, puis relancez `file` sur la région récupérée.

#### 4) Si c’est une image

- Examinez les anomalies : `magick identify -verbose file`
- Pour les fichiers PNG/BMP, énumérez les bit-planes/LSB : `zsteg -a file.png`
- Validez la structure PNG : `pngcheck -v file.png`
- Utilisez des filtres visuels (Stegsolve / StegoVeritas) si le contenu peut être révélé par des transformations de canal/plan

#### 5) Si c’est de l’audio

- Commencez par le spectrogramme (Sonic Visualiser)
- Décodez/examinez les flux : `ffmpeg -v info -i file -f null -`
- Si l’audio ressemble à des tonalités structurées, testez le décodage DTMF

### Outils courants

Ils détectent les cas fréquents au niveau du conteneur : charges utiles de métadonnées, octets ajoutés et fichiers intégrés dissimulés par l’extension.<sup>[[1]](#references)[[3]](#references)</sup>

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

Dans de nombreux challenges de stéganographie, des octets supplémentaires suivent un fichier valide, ou des archives intégrées sont déguisées par leur extension.

#### Charges utiles ajoutées

De nombreux formats ignorent les octets finaux. Un ZIP, un PDF ou un script peut être ajouté à un conteneur image/audio.

Vérifications rapides :

```bash
binwalk file
tail -c 200 file | xxd
```

Si vous connaissez un offset, faites une extraction avec `dd` :

```bash
dd if=file of=carved.bin bs=1 skip=<offset>
file carved.bin
```

#### Octets magiques

Quand `file` est désorienté, recherchez les octets magiques avec `xxd` et comparez-les aux signatures connues :

```bash
xxd -g 1 -l 32 file
```

#### Zip-in-disguise

Essayez `7z` et `unzip`, même si l’extension n’indique pas qu’il s’agit d’un fichier ZIP :

```bash
7z l file
unzip -l file
```

### Curiosités proches du stego

Liens rapides vers des motifs souvent associés au stego (QR code à partir de données binaires, braille, etc.).

#### QR codes à partir de données binaires

Si la longueur d’un blob est un carré parfait, il peut s’agir des pixels bruts d’une image ou d’un QR code.

```python
import math
math.isqrt(2500)  # 50
```

Aide de conversion binaire-image :

- Aide dCode pour convertir du binaire en image.<sup>[[5]](#references)</sup>

#### Braille

- Traducteur Braille de Branah.<sup>[[6]](#references)</sup>

Pour découvrir des collections plus vastes d’utilitaires de stéganographie et de ressources dédiées à des techniques spécifiques, consultez le stego-toolkit fourni et la liste sélectionnée par 0xRick.<sup>[[1]](#references)[[7]](#references)</sup>

## References

- [1] [DominicBreuker/stego-toolkit - Image Docker regroupant les outils de stéganographie les plus populaires](https://github.com/DominicBreuker/stego-toolkit)
- [2] [Daston et al. — Conventions d’empaquetage ouvert ECMA-376](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [3] [ReFirmLabs/binwalk](https://github.com/ReFirmLabs/binwalk)
- [4] [korczis/foremost](https://github.com/korczis/foremost)
- [5] [dCode — Image binaire](https://www.dcode.fr/binary-image)
- [6] [Branah — Traducteur Braille](https://www.branah.com/braille-translator)
- [7] [0xRick - Ressources de stéganographie](https://0xrick.github.io/lists/stego/)
{{#include ../../banners/hacktricks-training.md}}
