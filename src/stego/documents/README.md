# Stéganographie de documents

{{#include ../../banners/hacktricks-training.md}}

Les documents sont souvent de simples conteneurs :

- PDF (fichiers intégrés, flux)
- Office OOXML (`.docx/.xlsx/.pptx` sont des ZIP)
- Formats RTF / OLE historiques

## PDF

### Technique

PDF est un conteneur structuré composé d’objets, de flux et de fichiers éventuellement intégrés. Dans les CTFs, vous devez souvent :

- Extraire les pièces jointes intégrées
- Décompresser/aplatir les flux d’objets afin de pouvoir rechercher du contenu
- Identifier les objets cachés (JS, images intégrées, flux inhabituels)

### Vérifications rapides
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Recherchez ensuite des objets/chaînes suspects dans `out.pdf`.

## Office OOXML

### Technique

Traitez OOXML comme un graphe de relations composé de ZIP + XML ; les payloads se cachent souvent dans les médias, les relations ou des parties personnalisées inhabituelles.

Les fichiers OOXML sont des conteneurs ZIP. Cela signifie que :

- Le document est une arborescence de fichiers XML et de ressources.
- Les fichiers de relations `_rels/` peuvent pointer vers des ressources externes ou des parties masquées.
- Les données intégrées se trouvent fréquemment dans `word/media/`, les parties XML personnalisées ou des relations inhabituelles.

### Vérifications rapides
```bash
7z l file.docx
7z x file.docx -oout
```
Inspectez ensuite :

- `word/document.xml`
- `word/_rels/` pour les relations externes
- les médias intégrés dans `word/media/`


{{#include ../../banners/hacktricks-training.md}}
