# Stéganographie dans les documents

{{#include ../../banners/hacktricks-training.md}}

De nombreux formats de documents sont des conteneurs structurés plutôt que de simples flux de données :<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (fichiers intégrés, flux)
- Office OOXML (`.docx/.xlsx/.pptx` sont des ZIP)
- Documents RTF et OLE/Compound File Binary hérités. RTF stocke les mots de contrôle et les groupes dans un format orienté texte, tandis que les fichiers composés OLE exposent une hiérarchie d'objets de stockage et de flux similaire à un système de fichiers ; les deux nécessitent une inspection spécifique au format pour rechercher des données cachées ou intégrées.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Technique

Les fichiers PDF peuvent contenir des objets, des flux, du JavaScript et des fichiers intégrés. Lors de l'analyse, les tâches courantes comprennent :

- Extraire les pièces jointes intégrées.
- Développer les flux d'objets afin de faciliter l'inspection des objets.
- Identifier le JavaScript, les images intégrées et les flux inhabituels.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Vérifications rapides
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
La combinaison `--qdf --object-streams=disable` produit une représentation plus lisible et supprime les flux d’objets, ce qui facilite l’inspection manuelle.<sup>[[2]](#references)</sup> Recherchez ensuite les objets et chaînes suspects dans `out.pdf`.

## Office OOXML

### Technique

Les fichiers Office Open XML (`.docx`, `.xlsx` et `.pptx`) utilisent les Open Packaging Conventions : un package basé sur ZIP composé de parties et de fichiers XML de relations.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Considérez le package comme un graphe de relations et inspectez les médias, les relations externes et les parties personnalisées inhabituelles.

En pratique :

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

## References

- [1] [Manuel pdfdetach de Poppler](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Documentation de qpdf - mode QDF et flux d’objets](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Principes fondamentaux des Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Formats de fichiers Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Introduction au format de fichier binaire Compound File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Référence de la spécification RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
