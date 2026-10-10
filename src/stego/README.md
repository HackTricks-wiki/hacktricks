# Stego

{{#include ../banners/hacktricks-training.md}}

Cette section porte sur la **recherche et l’extraction de données cachées** dans des images, fichiers audio et vidéo, documents, archives et textes. La stéganographie dissimule l’existence d’une communication en intégrant des données dans d’autres données.<sup>[[1]](#references)</sup>

Si vous cherchez des attaques cryptographiques, consultez la section **Crypto**.

## Point d’entrée

Abordez la stéganographie comme un problème de criminalistique numérique : identifiez le véritable conteneur, examinez les emplacements les plus susceptibles de contenir des données (métadonnées, données ajoutées à la fin, fichiers intégrés), puis appliquez des techniques d’extraction adaptées au contenu.

### Workflow et triage

Un workflow structuré qui privilégie l’identification du conteneur, l’inspection des métadonnées et des chaînes de caractères, l’extraction de données et les pistes propres à chaque format.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

C’est là que se trouvent la plupart des techniques de stéganographie des CTF : LSB/plans de bits (PNG/BMP), particularités des chunks et des formats de fichiers, outils JPEG et astuces utilisant plusieurs frames GIF.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Les messages dans les spectrogrammes, l’intégration de données dans les LSB des échantillons et les tonalités du clavier téléphonique (DTMF) sont des motifs récurrents.

{{#ref}}
audio/README.md
{{#endref}}

### Texte

Si un texte s’affiche normalement, mais se comporte de manière inattendue, pensez aux homoglyphes Unicode, aux caractères de largeur nulle ou au codage fondé sur les espaces blancs.

{{#ref}}
text/README.md
{{#endref}}

### Documents

Les PDF et les fichiers Office sont avant tout des conteneurs ; les attaques portent généralement sur les fichiers ou flux intégrés, les graphes d’objets et de relations, et l’extraction ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Malware et stéganographie de type livraison

La livraison de payloads peut s’appuyer sur des fichiers d’apparence valide, comme des images GIF ou PNG, contenant des payloads textuels délimités par des marqueurs plutôt que des données cachées dans les pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glossaire NIST CSRC - Stéganographie](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
