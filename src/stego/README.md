# Stéganographie

{{#include ../banners/hacktricks-training.md}}

Cette section se concentre sur la **recherche et l'extraction de données cachées** dans des images, fichiers audio, vidéos, documents, archives et textes. La stéganographie dissimule l'existence d'une communication en intégrant des données dans d'autres données.<sup>[[1]](#references)</sup>

Si vous êtes ici pour les attaques cryptographiques, consultez la section **Crypto**.

## Point d'entrée

Abordez la stéganographie comme un problème de forensics : identifiez le véritable conteneur, répertoriez les emplacements à fort signal (métadonnées, données ajoutées, fichiers intégrés), puis appliquez uniquement les techniques d'extraction au niveau du contenu.

### Workflow et triage

Un workflow structuré qui donne la priorité à l'identification du conteneur, à l'inspection des métadonnées et des chaînes de caractères, au carving et à l'orientation vers des branches spécifiques au format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

C'est dans ce domaine que se trouve la majorité de la stéganographie des CTF : LSB/bit-planes (PNG/BMP), particularités des chunks et des formats de fichiers, outils JPEG et astuces avec les GIF multi-images.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Les messages dans les spectrogrammes, l'intégration LSB dans les échantillons et les tonalités des claviers téléphoniques (DTMF) sont des schémas récurrents.

{{#ref}}
audio/README.md
{{#endref}}

### Texte

Si le texte s'affiche normalement, mais se comporte de manière inattendue, envisagez les homoglyphes Unicode, les caractères de largeur nulle ou l'encodage basé sur les espaces blancs.

{{#ref}}
text/README.md
{{#endref}}

### Documents

Les PDF et les fichiers Office sont avant tout des conteneurs ; les attaques reposent généralement sur les fichiers/flux intégrés, les graphes d'objets et de relations, ainsi que l'extraction ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Stéganographie dans les malwares et de type delivery

La livraison de payloads peut utiliser des fichiers d'apparence valide, tels que des images GIF ou PNG, qui transportent des payloads textuels délimités par des marqueurs au lieu de dissimuler des données dans les pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossaire du NIST CSRC - Stéganographie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
