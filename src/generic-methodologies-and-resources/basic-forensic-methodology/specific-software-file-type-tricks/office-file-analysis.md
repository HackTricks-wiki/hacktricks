# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}


Pour plus d’informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci n’est qu’un résumé :<sup>[[4]](#references)</sup>

Microsoft a créé de nombreux formats de documents Office, dont les deux principaux types sont les **formats OLE** (comme RTF, DOC, XLS et PPT) et les **formats Office Open XML (OOXML)** (tels que DOCX, XLSX et PPTX). Ces formats peuvent inclure des macros, ce qui en fait des cibles pour le phishing et les malwares. Les fichiers OOXML sont structurés comme des conteneurs zip, ce qui permet de les inspecter en les décompressant afin de révéler la hiérarchie des fichiers et dossiers ainsi que le contenu des fichiers XML.

Pour explorer les structures des fichiers OOXML, la commande permettant de décompresser un document ainsi que la structure de sortie sont fournies. Des techniques permettant de dissimuler des données dans ces fichiers ont été documentées, ce qui indique une innovation continue dans la dissimulation de données au sein des challenges CTF.

Pour l’analyse, **oletools** et **OfficeDissector** proposent des toolsets complets pour examiner les documents OLE et OOXML. Ces outils permettent d’identifier et d’analyser les macros intégrées, qui servent souvent de vecteurs pour la diffusion de malwares, généralement en téléchargeant et en exécutant des payloads malveillants supplémentaires. L’analyse des macros VBA peut être réalisée sans Microsoft Office en utilisant Libre Office, qui permet le debugging avec des breakpoints et des watch variables.

L’installation et l’utilisation de **oletools** sont simples, avec des commandes fournies pour l’installation via pip et l’extraction des macros depuis des documents. L’exécution automatique des macros est déclenchée par des fonctions telles que `AutoOpen`, `AutoExec` ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation de fichiers OLE Compound File : Autodesk Revit RFA – recomputation de l’ECC et gzip contrôlé

Les modèles Revit RFA sont stockés sous forme de [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (également appelé CFBF). Le modèle sérialisé se trouve sous storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Structure clé de `Global\Latest` (observée sur Revit 2025) :

- En-tête
- Payload compressé avec GZIP (le véritable graphe d’objets sérialisé)
- Remplissage de zéros
- Trailer d’Error-Correcting Code (ECC)

Revit répare automatiquement les petites perturbations du stream à l’aide du trailer ECC et rejette les streams qui ne correspondent pas à l’ECC. Par conséquent, modifier naïvement les octets compressés ne sera pas conservé : vos modifications sont soit annulées, soit le fichier est rejeté. Pour garantir un contrôle octet par octet de ce que voit le deserializer, vous devez :

- Recompresser avec une implémentation gzip compatible avec Revit (afin que les octets compressés produits/acceptés par Revit correspondent à ceux attendus).
- Recalculer le trailer ECC sur le stream complété afin que Revit accepte le stream modifié sans le réparer automatiquement.

Workflow pratique pour patcher/fuzzer le contenu des RFA :<sup>[[1]](#references)</sup>

1) Développer le document OLE compound averti
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier `Global\Latest` avec gzip/ECC

- Déconstruire `Global/Latest` : conserver l’en-tête, décompresser le payload avec gunzip, modifier les octets, puis recompresser avec gzip en utilisant des paramètres deflate compatibles avec Revit.
- Préserver le zero-padding et recalculer le trailer ECC afin que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d’une reproduction déterministe, octet par octet, créez un wrapper minimal autour des DLL de Revit pour appeler ses chemins gzip/gunzip et effectuer le calcul ECC (comme démontré dans la recherche), ou réutilisez un helper disponible qui reproduit ces sémantiques.

3) Reconstruire le document composé OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes :<sup>[[1]](#references)</sup>

- CompoundFileTool écrit les storages/streams dans le système de fichiers en utilisant un échappement pour les caractères invalides dans les noms NTFS ; le chemin du stream recherché est exactement `Global/Latest` dans l’arborescence de sortie.
- Lors de la diffusion d’attaques de masse via des plugins de l’écosystème qui récupèrent des RFA depuis un cloud storage, vérifiez d’abord localement que votre RFA patché passe les contrôles d’intégrité de Revit (gzip/ECC corrects) avant de tenter une injection réseau.

Informations utiles pour l’exploitation (pour déterminer les octets à placer dans le payload gzip) :<sup>[[1]](#references)</sup>

- Le désérialiseur de Revit lit un index de classe de 16 bits et construit un objet. Certains types sont non polymorphes et ne possèdent pas de vtables ; l’abus de la gestion du destructeur provoque une type confusion, dans laquelle le moteur exécute un appel indirect via un pointeur contrôlé par l’attaquant.
- Le choix de `AString` (index de classe `0x1F`) place un pointeur de heap contrôlé par l’attaquant à l’offset 0 de l’objet. Pendant la boucle du destructeur, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs objets de ce type dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (« weird machine »), puis préparez un stack pivot vers une chaîne ROP x64 conventionnelle.

Consultez les détails sur le pivot/gadget building x64 sous Windows ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

et les conseils généraux sur le ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils :<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) pour étendre/reconstruire des fichiers compound OLE : https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD pour le reverse/taint ; désactivez le page heap avec TTD afin de conserver des traces compactes.
- Un proxy local (par exemple, Fiddler) peut simuler une livraison via supply chain en remplaçant les RFA dans le trafic des plugins à des fins de test.

## Références

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
