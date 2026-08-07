# Stego

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur **la recherche et l'extraction de données cachées** dans des fichiers (images/audio/vidéo/documents/archives) ainsi que sur la stéganographie basée sur le texte.

Si vous cherchez des attaques cryptographiques, consultez la section **Crypto**.

## Point de départ

Abordez la stéganographie comme un problème de forensics : identifiez le véritable conteneur, examinez les emplacements à forte probabilité (métadonnées, données ajoutées, fichiers intégrés), puis appliquez les techniques d'extraction adaptées au contenu.

### Flux de travail et triage

Un flux de travail structuré qui donne la priorité à l'identification du conteneur, à l'inspection des métadonnées et des chaînes, au carving, puis à l'orientation vers le format approprié.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

C'est là que se trouve la majorité de la stégo des CTF : LSB/bit-planes (PNG/BMP), particularités des chunks et des formats de fichiers, outils JPEG et astuces liées aux GIF multi-images.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Les messages dans les spectrogrammes, l'intégration LSB dans les échantillons et les tonalités des touches de téléphone (DTMF) sont des schémas récurrents.

{{#ref}}
audio/README.md
{{#endref}}

### Texte

Si le texte s'affiche normalement mais se comporte de manière inattendue, envisagez les homoglyphes Unicode, les caractères de largeur nulle ou l'encodage basé sur les espaces blancs.

{{#ref}}
text/README.md
{{#endref}}

### Documents

Les PDF et les fichiers Office sont d'abord des conteneurs ; les attaques reposent généralement sur des fichiers/flux intégrés, des graphes d'objets et de relations, ainsi que sur l'extraction de ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Stéganographie liée aux malwares et à la distribution

La distribution de payloads utilise fréquemment des fichiers d'apparence valide (par exemple, GIF/PNG) qui contiennent des payloads textuels délimités par des marqueurs, plutôt qu'une dissimulation au niveau des pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
