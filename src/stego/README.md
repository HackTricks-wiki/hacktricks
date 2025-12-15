# Stego

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur **la recherche et l'extraction de données cachées** dans des fichiers (images/audio/vidéo/documents/archives) et sur la steganography basée sur du texte.

Si vous êtes ici pour des attaques cryptographiques, allez à la section **Crypto**.

## Point d'entrée

Abordez la steganography comme un problème de forensics : identifiez le container réel, énumérez les emplacements à fort signal (metadata, données ajoutées, fichiers embarqués), puis appliquez ensuite les techniques d'extraction au niveau du contenu.

### Flux de travail & triage

Un flux de travail structuré qui priorise l'identification du container, l'inspection des metadata/strings, le carving, et les bifurcations spécifiques au format.
{{#ref}}
workflow/README.md
{{#endref}}

### Images

Où se trouve la plupart du stego en CTF : LSB/bit-planes (PNG/BMP), bizarreries de chunks/format de fichier, outils JPEG, et astuces pour GIF multi-frames.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Messages en spectrogramme, insertion LSB d'échantillons, et tonalités du clavier téléphonique (DTMF) sont des motifs récurrents.
{{#ref}}
audio/README.md
{{#endref}}

### Texte

Si le texte s'affiche normalement mais se comporte de façon inattendue, considérez les homoglyphes Unicode, les caractères zero-width, ou un encodage basé sur les espaces blancs.
{{#ref}}
text/README.md
{{#endref}}

### Documents

Les PDFs et fichiers Office sont d'abord des containers ; les attaques tournent généralement autour des fichiers/flux embarqués, des graphes d'objets/relation, et de l'extraction ZIP.
{{#ref}}
documents/README.md
{{#endref}}

### Malware et steganography de type delivery

La livraison de payload utilise fréquemment des fichiers à l'apparence valide (p.ex., GIF/PNG) qui contiennent des payloads textuels délimités par des marqueurs, plutôt que du camouflage au niveau des pixels.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
