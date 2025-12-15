# Stéganographie des documents

{{#include ../../banners/hacktricks-training.md}}

Les documents sont souvent de simples conteneurs :

- PDF (fichiers intégrés, streams)
- Office OOXML (`.docx/.xlsx/.pptx` sont des ZIPs)
- Formats hérités RTF / OLE

## PDF

### Technique

Le PDF est un conteneur structuré avec des objets, des streams, et éventuellement des fichiers intégrés. Dans les CTFs vous devez souvent :

- Extraire les pièces jointes intégrées
- Décompresser/aplatisser les flux d'objets pour pouvoir rechercher le contenu
- Identifier les objets cachés (JS, images intégrées, flux étranges)

### Vérifications rapides
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Puis recherchez dans `out.pdf` des objets/chaînes suspects.

## Office OOXML

### Technique

Considérez OOXML comme un graphe de relations ZIP + XML ; les payloads se cachent souvent dans les médias, les relations, ou des parties personnalisées inhabituelles.

OOXML files are ZIP containers. That means:

- Le document est un arbre de répertoires composé de fichiers XML et de ressources.
- Les fichiers `_rels/` de relation peuvent pointer vers des ressources externes ou des parties cachées.
- Les données intégrées résident fréquemment dans `word/media/`, dans des parties XML personnalisées, ou dans des relations inhabituelles.

### Vérifications rapides
```bash
7z l file.docx
7z x file.docx -oout
```
Ensuite, inspectez :

- `word/document.xml`
- `word/_rels/` pour les relations externes
- médias intégrés dans `word/media/`

{{#include ../../banners/hacktricks-training.md}}
