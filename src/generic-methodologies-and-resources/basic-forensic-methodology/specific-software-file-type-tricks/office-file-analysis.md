# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}


Pour plus d'informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci n'est qu'un résumé :

Microsoft a créé de nombreux formats de documents Office, avec deux types principaux étant les **OLE formats** (comme RTF, DOC, XLS, PPT) et les **Office Open XML (OOXML) formats** (tels que DOCX, XLSX, PPTX). Ces formats peuvent contenir des macros, ce qui en fait des cibles pour le phishing et les malwares. Les fichiers OOXML sont structurés comme des conteneurs zip, ce qui permet de les inspecter en les décompressant, révélant la hiérarchie des fichiers et dossiers et le contenu des fichiers XML.

Pour explorer la structure des fichiers OOXML, la commande pour décompresser un document et la structure de sortie sont fournies. Des techniques pour dissimuler des données dans ces fichiers ont été documentées, indiquant une innovation continue dans la dissimulation de données au sein des challenges CTF.

Pour l'analyse, **oletools** et **OfficeDissector** offrent des ensembles d'outils complets pour examiner à la fois les documents OLE et OOXML. Ces outils aident à identifier et analyser les macros embarquées, qui servent souvent de vecteurs pour la distribution de malwares, téléchargeant et exécutant généralement des payloads malveillants supplémentaires. L'analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le débogage avec breakpoints et watch variables.

L'installation et l'utilisation de **oletools** sont simples, des commandes sont fournies pour l'installation via pip et l'extraction des macros depuis les documents. L'exécution automatique des macros est déclenchée par des fonctions comme `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Les modèles Revit RFA sont stockés en tant que [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Le modèle sérialisé se trouve sous storage/stream :

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Structure clé de `Global\Latest` (observée sur Revit 2025) :

- Header
- GZIP-compressed payload (le véritable graphe d'objets sérialisé)
- Zero padding
- Code de correction d'erreurs (ECC) trailer

Revit réparera automatiquement les petites perturbations du stream en utilisant la bande ECC et rejettera les streams qui ne correspondent pas à l'ECC. Donc, éditer naïvement les octets compressés ne persistera pas : vos modifications sont soit annulées, soit le fichier est rejeté. Pour garantir un contrôle octet-par-oitre de ce que le désérialiseur voit, vous devez :

- Recompresser avec une implémentation gzip compatible Revit (pour que les octets compressés que Revit produit/accepte correspondent à ce qu'il attend).
- Recalculer la bande ECC sur le flux avec padding afin que Revit accepte le flux modifié sans le réparer automatiquement.

Flux de travail pratique pour patching/fuzzing du contenu RFA :

1) Explorer le document OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier Global\Latest avec la discipline gzip/ECC

- Déconstruire `Global/Latest` : conserver l'en-tête, gunzip le payload, muter les octets, puis gzip à nouveau en utilisant des paramètres de deflate compatibles Revit.
- Préserver le zero-padding et recomputer le trailer ECC pour que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d'une reproduction déterministe octet par octet, construire un wrapper minimal autour des DLLs de Revit pour invoquer ses chemins gzip/gunzip et le calcul ECC (comme démontré dans la recherche), ou ré-utiliser tout helper disponible qui réplique ces sémantiques.

3) Reconstruire le document OLE composé
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes :

- CompoundFileTool écrit les storages/streams sur le système de fichiers en échappant les caractères invalides pour les noms NTFS ; le chemin de stream que vous voulez est exactement `Global/Latest` dans l'arborescence de sortie.
- Lors de la livraison d'attaques massives via des plugins d'écosystème qui fetch RFAs depuis cloud storage, assurez-vous que votre RFA patché passe d'abord les vérifications d'intégrité de Revit en local (gzip/ECC correct) avant de tenter une injection réseau.

Exploitation insight (to guide what bytes to place in the gzip payload) :

- Le désérialiseur Revit lit un index de classe 16 bits et construit un objet. Certains types sont non‑polymorphes et n'ont pas de vtables ; abuser du traitement des destructeurs provoque une confusion de type où le moteur exécute un appel indirect via un pointeur contrôlé par l'attaquant.
- Choisir `AString` (index de classe `0x1F`) place un pointeur heap contrôlé par l'attaquant à l'offset 0 de l'objet. Pendant la boucle des destructeurs, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placer plusieurs de ces objets dans le graphe sérialisé afin que chaque itération de la boucle de destructeur exécute un gadget (“weird machine”), et organiser un stack pivot vers une chaîne x64 ROP conventionnelle.

Voir les détails Windows x64 pivot/gadget building ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

et des recommandations générales ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils :

- CompoundFileTool (OSS) pour extraire/reconstruire les fichiers OLE compound : https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD pour reverse/taint ; désactiver page heap avec TTD pour garder les traces compactes.
- Un proxy local (p.ex., Fiddler) peut simuler une livraison supply-chain en échangeant des RFAs dans le trafic de plugin pour les tests.

## Références

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
