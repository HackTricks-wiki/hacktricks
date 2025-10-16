# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}


Pour plus d'informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci n'est qu'un résumé :

Microsoft a créé de nombreux formats de documents Office, dont deux types principaux sont les **OLE formats** (comme RTF, DOC, XLS, PPT) et les **Office Open XML (OOXML) formats** (tels que DOCX, XLSX, PPTX). Ces formats peuvent inclure des macros, ce qui en fait des cibles pour le phishing et les malwares. Les fichiers OOXML sont structurés comme des containers zip, ce qui permet de les inspecter en les décompressant (ou en utilisant unzip), révélant la hiérarchie de fichiers et dossiers ainsi que le contenu des fichiers XML.

Pour explorer la structure des fichiers OOXML, la commande pour unzipper un document et la structure de sortie sont fournies. Des techniques pour cacher des données dans ces fichiers ont été documentées, montrant une innovation continue dans la dissimulation de données au sein des challenges CTF.

Pour l'analyse, **oletools** et **OfficeDissector** offrent des ensembles d'outils complets pour examiner à la fois les documents OLE et OOXML. Ces outils aident à identifier et analyser les macros embarquées, qui servent souvent de vecteurs pour la distribution de malwares, téléchargeant et exécutant typiquement des payloads malveillants additionnels. L'analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le debugging avec des points d'arrêt et des variables à surveiller.

L'installation et l'utilisation de **oletools** sont simples : des commandes sont fournies pour l'installation via pip et l'extraction des macros depuis des documents. L'exécution automatique des macros est déclenchée par des fonctions comme `AutoOpen`, `AutoExec`, ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation OLE Compound File : Autodesk Revit RFA – recalcul ECC et gzip contrôlé

Les modèles Revit RFA sont stockés en tant que [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Le modèle sérialisé se trouve sous storage/stream :

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Disposition clé de `Global\Latest` (observée sur Revit 2025) :

- Header
- GZIP-compressed payload (le graphe d'objets sérialisé réel)
- Zero padding
- Suffixe Error-Correcting Code (ECC)

Revit répare automatiquement de petites perturbations du flux en utilisant le suffixe ECC et rejettera les flux qui ne correspondent pas à l'ECC. Par conséquent, éditer naïvement les octets compressés ne persistera pas : vos modifications sont soit annulées, soit le fichier est rejeté. Pour assurer un contrôle octet-par-octet de ce que le désérialiseur voit, vous devez :

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Flux de travail pratique pour patching/fuzzing des contenus RFA :

1) Extraire le document OLE Compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier Global\Latest selon la discipline gzip/ECC

- Déconstruire `Global/Latest`: garder l'en-tête, gunzip le payload, modifier des bytes, puis gzip à nouveau en utilisant des paramètres deflate compatibles avec Revit.
- Préserver le zero-padding et recalculer le trailer ECC afin que les nouveaux bytes soient acceptés par Revit.
- Si vous avez besoin d'une reproduction déterministe octet par octet, construisez un wrapper minimal autour des DLLs de Revit pour invoquer ses chemins gzip/gunzip et le calcul ECC (comme démontré dans la recherche), ou réutilisez tout helper disponible qui reproduit ces sémantiques.

3) Reconstruire le OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Remarques:

- CompoundFileTool écrit les storages/streams sur le système de fichiers en échappant les caractères invalides dans les noms NTFS ; le chemin de flux recherché est exactement `Global/Latest` dans l'arborescence de sortie.
- Lors de livraisons d'attaques massives via des plugins d'écosystème qui récupèrent des RFAs depuis cloud storage, assurez-vous que votre RFA patché passe d'abord les vérifications d'intégrité de Revit en local (gzip/ECC corrects) avant toute injection réseau.

Exploitation insight (pour guider quels octets placer dans la payload gzip) :

- Le désérialiseur de Revit lit un index de classe sur 16 bits et construit un objet. Certains types sont non‑polymorphes et n'ont pas de vtables ; l'abus du mécanisme de destructeur conduit à une confusion de type où le moteur exécute un appel indirect via un pointeur contrôlé par l'attaquant.
- Choisir `AString` (index de classe `0x1F`) place un pointeur heap contrôlé par l'attaquant à l'offset 0 de l'objet. Pendant la boucle de destructeur, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs de ces objets dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (“weird machine”), et organisez un stack pivot vers une ROP chain x64 conventionnelle.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD for reverse/taint; désactivez page heap avec TTD pour garder les traces compactes.
- Un proxy local (p.ex., Fiddler) peut simuler la delivery supply-chain en échangeant des RFAs dans le trafic plugin pour les tests.

## Références

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
