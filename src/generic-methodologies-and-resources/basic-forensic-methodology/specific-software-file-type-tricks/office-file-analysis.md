# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}


Pour plus d’informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Voici simplement un résumé :<sup>[[4]](#references)</sup>

Microsoft a créé de nombreux formats de documents Office, dont les deux principaux types sont les **formats OLE** (tels que RTF, DOC, XLS, PPT) et les formats **Office Open XML (OOXML)** (tels que DOCX, XLSX, PPTX). Ces formats peuvent inclure des macros, ce qui en fait des cibles pour le phishing et les malwares. Les fichiers OOXML sont structurés comme des conteneurs zip, ce qui permet de les inspecter en les décompressant et de révéler la hiérarchie des fichiers et des dossiers ainsi que le contenu des fichiers XML.

Pour explorer les structures des fichiers OOXML, la commande permettant de décompresser un document ainsi que la structure de sortie sont fournies. Des techniques permettant de cacher des données dans ces fichiers ont été documentées, ce qui montre l’innovation continue dans la dissimulation de données lors des défis CTF.

Pour l’analyse, **oletools** et **OfficeDissector** proposent des ensembles complets d’outils pour examiner les documents OLE et OOXML. Ces outils permettent d’identifier et d’analyser les macros intégrées, qui servent souvent de vecteurs pour la distribution de malwares, généralement en téléchargeant et en exécutant des payloads malveillants supplémentaires. L’analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le debugging avec des breakpoints et des watch variables.

L’installation et l’utilisation de **oletools** sont simples, avec des commandes fournies pour l’installer via pip et extraire les macros des documents. L’exécution automatique des macros est déclenchée par des fonctions telles que `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation de fichiers OLE Compound File : Autodesk Revit RFA – recalcul de l’ECC et gzip contrôlé

Les modèles Revit RFA sont stockés dans un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (également appelé CFBF). Le modèle sérialisé se trouve sous storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage : `Global`
- Stream : `Latest` → `Global\Latest`

Structure clé de `Global\Latest` (observée dans Revit 2025) :

- En-tête
- Payload compressé avec GZIP (le graphe d’objets sérialisé réel)
- Bourrage nul
- Trailer d’Error-Correcting Code (ECC)

Revit répare automatiquement les petites perturbations du stream à l’aide du trailer ECC et rejette les streams qui ne correspondent pas à l’ECC. Par conséquent, modifier naïvement les octets compressés ne sera pas persistant : vos changements sont soit annulés, soit le fichier est rejeté. Pour garantir un contrôle octet par octet de ce que voit le désérialiseur, vous devez :

- Recompresser avec une implémentation gzip compatible avec Revit (afin que les octets compressés produits/acceptés par Revit correspondent à ceux attendus).
- Recalculer le trailer ECC sur le stream rempli afin que Revit accepte le stream modifié sans le réparer automatiquement.

Workflow pratique pour patcher/fuzzer le contenu des RFA :<sup>[[1]](#references)</sup>

1) Développer le document OLE Compound File
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier `Global\Latest` en respectant la discipline gzip/ECC

- Déconstruisez `Global/Latest` : conservez l’en-tête, décompressez le payload avec gunzip, modifiez les octets, puis recompressez avec gzip en utilisant des paramètres deflate compatibles avec Revit.
- Préservez le remplissage de zéros et recalculez le trailer ECC afin que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d’une reproduction déterministe octet par octet, créez un wrapper minimal autour des DLL de Revit pour appeler ses chemins gzip/gunzip et effectuer le calcul ECC (comme démontré dans les recherches), ou réutilisez tout helper disponible qui reproduit ces sémantiques.

3) Reconstruire le document composé OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes :<sup>[[1]](#references)</sup>

- CompoundFileTool écrit les storages/streams dans le filesystem en échappant les caractères invalides dans les noms NTFS ; le chemin du stream recherché est exactement `Global/Latest` dans l'arborescence de sortie.
- Lors de la diffusion d'attaques massives via des plugins d'ecosystem qui récupèrent des RFA depuis un cloud storage, assurez-vous que votre RFA patché passe d'abord localement les contrôles d'intégrité de Revit (`gzip/ECC correct`) avant de tenter une injection réseau.

Exploitation insight (pour guider les octets à placer dans le payload gzip) :<sup>[[1]](#references)</sup>

- Le désérialiseur de Revit lit un index de classe de 16 bits et construit un objet. Certains types sont non polymorphes et ne possèdent pas de vtables ; l'exploitation de la gestion du destructeur provoque une type confusion où le moteur exécute un appel indirect via un pointeur contrôlé par l'attaquant.
- La sélection de `AString` (index de classe `0x1F`) place un pointeur de heap contrôlé par l'attaquant à l'offset 0 de l'objet. Pendant la boucle du destructeur, Revit exécute en pratique :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs objets de ce type dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (« weird machine »), et organisez un stack pivot vers une chaîne ROP x64 conventionnelle.

Consultez les détails de construction de pivots/gadgets Windows x64 ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

ainsi que les conseils généraux sur le ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils :<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) pour développer/reconstruire des fichiers composés OLE : https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD pour le reverse/taint ; désactivez le page heap avec TTD afin de conserver des traces compactes.
- Un proxy local (par ex. Fiddler) peut simuler une livraison de supply chain en remplaçant les RFA dans le trafic des plugins à des fins de test.

## Références

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentation OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
