# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}

Pour plus d’informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Voici simplement un résumé :<sup>[[2]](#references)</sup>

Les documents Microsoft Office se présentent souvent dans des formats anciens comme RTF et les formats DOC, XLS et PPT basés sur OLE/CFBF, ou dans des formats plus récents **Office Open XML (OOXML)** comme DOCX, XLSX et PPTX. Les documents Office peuvent contenir du contenu actif, comme des macros, ce qui en fait des vecteurs courants de phishing et de malware. Les fichiers OOXML sont des conteneurs ZIP dont l’arborescence et le contenu XML peuvent être examinés en les décompressant.<sup>[[1]](#references)[[2]](#references)</sup>

Pour explorer la structure des fichiers OOXML, la commande permettant de décompresser un document et la structure obtenue sont présentées. Des techniques de dissimulation de données dans ces fichiers ont été documentées, témoignant de l’innovation continue en matière de dissimulation de données dans les challenges CTF.<sup>[[2]](#references)</sup>

Pour l’analyse, **oletools** et **OfficeDissector** offrent des ensembles d’outils complets pour examiner les documents OLE et OOXML. Ils permettent de détecter et d’analyser les macros intégrées, qui servent souvent à diffuser des malwares, généralement en téléchargeant et en exécutant d’autres payloads malveillants. L’analyse des macros VBA peut être effectuée sans Microsoft Office à l’aide de LibreOffice, qui permet le débogage avec des points d’arrêt et des variables de surveillance.<sup>[[2]](#references)</sup>

L’installation et l’utilisation de **oletools** sont simples : des commandes sont fournies pour l’installer avec pip et extraire les macros des documents. Dans Word, les macros automatiques incluent `AutoExec` et `AutoOpen`, tandis que `Document_Open` est une procédure déclenchée à l’ouverture du document.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Analyse des macros VBA : code inutile et UserForms

## Code inutile

Les macros peuvent contenir du **code inaccessible ou sans pertinence**, destiné à ralentir l’analyse. Repérez les conditions constantes et déterminez le comportement accessible avant de consacrer du temps à l’analyse d’une branche. L’exemple ci-dessous utilise une condition `If` qui ne peut jamais être vraie pour dissimuler du code inutile.

![Une macro Word contenant une branche conditionnelle inaccessible avec du code inutile](<../../../images/image (369).png>)

## Formulaires de macro

Les UserForms VBA peuvent stocker des données dans des contrôles tels que des zones de texte. Comme les formulaires, les cadres et les pages peuvent chacun exposer une collection `Controls`, les analystes doivent parcourir toute la hiérarchie des contrôles plutôt que de se fier uniquement à ce qu’affiche le formulaire. L’exemple ci-dessous stocke des données dissimulées dans des zones de texte qui se chevauchent.<sup>[[6]](#references)</sup>

Lors d’une analyse dynamique, la fonction VBA `GetObject` peut récupérer un objet Automation à partir d’un fichier ou se connecter à un serveur Automation déjà actif. Les macros peuvent utiliser cet accès aux objets pour atteindre des données qui ne sont pas visibles dans le document ; inspectez l’objet renvoyé ainsi que l’arborescence des contrôles du UserForm.<sup>[[7]](#references)</sup>

![Un UserForm de macro contenant des données dissimulées dans des zones de texte qui se chevauchent](<../../../images/image (344).png>)

Pour les documents Office chiffrés par mot de passe, consultez le [workflow de récupération hors ligne guidé par la grammaire](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Pour les fichiers Revit RFA utilisant OLE/CFBF, consultez [le recalcul d’ECC, gzip contrôlé et l’exploitation du désérialiseur](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md) ; ce workflow d’exploitation de l’analyseur est distinct du triage des documents Office.

## References

- [1] [Documentation OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Documentation d’olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Macros automatiques (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Événement Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Collections, contrôles et objets (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Fonction `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
