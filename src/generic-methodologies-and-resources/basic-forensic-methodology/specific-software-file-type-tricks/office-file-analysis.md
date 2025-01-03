# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}

Pour plus d'informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci est juste un résumé :

Microsoft a créé de nombreux formats de documents Office, les deux principaux types étant les **formats OLE** (comme RTF, DOC, XLS, PPT) et les **formats Office Open XML (OOXML)** (tels que DOCX, XLSX, PPTX). Ces formats peuvent inclure des macros, ce qui en fait des cibles pour le phishing et les logiciels malveillants. Les fichiers OOXML sont structurés comme des conteneurs zip, permettant une inspection par décompression, révélant la hiérarchie des fichiers et des dossiers ainsi que le contenu des fichiers XML.

Pour explorer les structures de fichiers OOXML, la commande pour décompresser un document et la structure de sortie sont fournies. Des techniques pour cacher des données dans ces fichiers ont été documentées, indiquant une innovation continue dans la dissimulation de données au sein des défis CTF.

Pour l'analyse, **oletools** et **OfficeDissector** offrent des ensembles d'outils complets pour examiner à la fois les documents OLE et OOXML. Ces outils aident à identifier et analyser les macros intégrées, qui servent souvent de vecteurs pour la livraison de logiciels malveillants, téléchargeant et exécutant généralement des charges utiles malveillantes supplémentaires. L'analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le débogage avec des points d'arrêt et des variables de surveillance.

L'installation et l'utilisation de **oletools** sont simples, avec des commandes fournies pour l'installation via pip et l'extraction de macros à partir de documents. L'exécution automatique des macros est déclenchée par des fonctions telles que `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
