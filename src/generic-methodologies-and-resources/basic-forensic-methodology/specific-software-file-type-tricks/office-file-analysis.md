# Analyse des fichiers Office

Pour plus d'informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci n'est qu'un résumé :<sup>[[4]](#references)</sup>

Les documents Microsoft Office se présentent couramment sous forme de formats hérités tels que RTF et DOC, XLS et PPT basés sur OLE/CFBF, ou sous forme de formats plus récents **Office Open XML (OOXML)** tels que DOCX, XLSX et PPTX. Les documents Office peuvent contenir du contenu actif tel que des macros, ce qui en fait des vecteurs courants de phishing et de malware. Les fichiers OOXML sont des conteneurs ZIP dont la hiérarchie des fichiers et le contenu XML peuvent être inspectés en les décompressant.<sup>[[3]](#references)[[4]](#references)</sup>

Pour explorer les structures des fichiers OOXML, la commande permettant de décompresser un document ainsi que la structure de sortie sont présentées. Des techniques permettant de dissimuler des données dans ces fichiers ont été documentées, ce qui indique une innovation continue dans la dissimulation de données au sein des challenges CTF.<sup>[[4]](#references)</sup>

Pour l'analyse, **oletools** et **OfficeDissector** proposent des toolsets complets pour examiner les documents OLE et OOXML. Ces outils aident à identifier et à analyser les macros intégrées, qui servent souvent de vecteurs de diffusion de malware et téléchargent et exécutent généralement des payloads malveillants supplémentaires. L'analyse des macros VBA peut être réalisée sans Microsoft Office en utilisant Libre Office, qui permet le debugging avec des breakpoints et des variables de surveillance.<sup>[[4]](#references)</sup>

L'installation et l'utilisation de **oletools** sont simples, avec des commandes permettant l'installation via pip et l'extraction des macros à partir de documents. Dans Word, les macros automatiques incluent `AutoExec` et `AutoOpen`, tandis que `Document_Open` est une procédure d'événement d'ouverture.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation de fichiers OLE Compound File : Autodesk Revit RFA – recalcul de l’ECC et gzip contrôlé

Les modèles Revit RFA sont stockés sous forme d’[OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (également appelé CFBF). Le modèle sérialisé se trouve sous storage/stream :<sup>[[1]](#references)[[3]](#references)</sup>

- Storage : `Global`
- Stream : `Latest` → `Global\Latest`

Structure principale de `Global\Latest` (observée sur Revit 2025) :

- En-tête
- Payload compressé avec GZIP (le graphe d’objets sérialisé réel)
- Remplissage nul
- Trailer de code correcteur d’erreurs (ECC)

Revit répare automatiquement les petites perturbations du stream à l’aide du trailer ECC et rejette les streams qui ne correspondent pas à l’ECC. Par conséquent, modifier naïvement les octets compressés ne sera pas conservé : vos modifications sont soit annulées, soit le fichier est rejeté. Pour garantir un contrôle octet par octet de ce que voit le désérialiseur, vous devez :<sup>[[1]](#references)</sup>

- Recompresser avec une implémentation gzip compatible avec Revit (afin que les octets compressés produits/acceptés par Revit correspondent à ceux attendus).
- Recalculer le trailer ECC sur le stream complété afin que Revit accepte le stream modifié sans le réparer automatiquement.

Workflow pratique pour patcher/fuzzer le contenu des RFA :<sup>[[1]](#references)</sup>

1) Développer le document OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier `Global\Latest` avec une gestion rigoureuse de gzip/ECC

- Déconstruire `Global/Latest` : conserver l’en-tête, décompresser le payload avec gunzip, modifier les octets, puis recompresser avec gzip en utilisant les paramètres deflate compatibles avec Revit.
- Préserver le remplissage par des zéros et recalculer le trailer ECC afin que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d’une reproduction déterministe octet par octet, créez un wrapper minimal autour des DLL de Revit pour appeler ses chemins gzip/gunzip et son calcul ECC (comme démontré dans les travaux de recherche), ou réutilisez tout helper disponible qui reproduit ces sémantiques.

3) Reconstruire le document composé OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool écrit les storages/streams dans le filesystem en échappant les caractères invalides dans les noms NTFS ; le chemin du stream recherché est exactement `Global/Latest` dans l’arborescence de sortie.
- Lors de la distribution de mass attacks via des plugins de l’écosystème qui récupèrent des RFA depuis un cloud storage, assurez-vous que votre RFA patché passe d’abord localement les contrôles d’intégrité de Revit (gzip/ECC corrects) avant de tenter une network injection.

Exploitation insight (pour déterminer quels octets placer dans le payload gzip) :<sup>[[1]](#references)</sup>

- Le deserializer de Revit lit un class index de 16 bits et construit un objet. Certains types sont non polymorphiques et ne possèdent pas de vtables ; l’abus de la gestion du destructeur provoque une type confusion où le moteur exécute un indirect call via un pointeur contrôlé par l’attaquant.
- Le choix de `AString` (class index `0x1F`) place un heap pointer contrôlé par l’attaquant à l’offset 0 de l’objet. Pendant la boucle du destructeur, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs objets de ce type dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (« weird machine »), et organisez un stack pivot vers une chaîne ROP x64 conventionnelle.

Consultez les détails sur le pivot/la construction de gadgets Windows x64 ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

et les conseils généraux sur la ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils :<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) pour développer/reconstruire des fichiers OLE compound : https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD pour l’ reverse/taint ; désactivez le page heap avec TTD afin de conserver des traces compactes.
- Un proxy local (par exemple, Fiddler) peut simuler une livraison par supply chain en remplaçant les RFA dans le trafic des plugins à des fins de test.

## References

- [1] [Création d’un exploit RCE complet à partir d’un crash lors de l’analyse d’un fichier RFA Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Fichier compound OLE (CFBF), documentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentation d’olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Événement Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
