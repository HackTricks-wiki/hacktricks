# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}

Pour plus d’informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Voici simplement un résumé :<sup>[[4]](#references)</sup>

Les documents Microsoft Office apparaissent couramment sous forme de formats historiques tels que RTF et DOC, XLS et PPT basés sur OLE/CFBF, ou sous forme de formats plus récents **Office Open XML (OOXML)** tels que DOCX, XLSX et PPTX. Les documents Office peuvent contenir du contenu actif, comme des macros, ce qui en fait des vecteurs courants de phishing et de malware. Les fichiers OOXML sont des conteneurs ZIP dont la hiérarchie des fichiers et le contenu XML peuvent être inspectés en les décompressant.<sup>[[3]](#references)[[4]](#references)</sup>

Pour explorer les structures de fichiers OOXML, la commande permettant de décompresser un document ainsi que la structure de sortie sont fournies. Des techniques permettant de dissimuler des données dans ces fichiers ont été documentées, ce qui témoigne d’une innovation continue dans la dissimulation de données au sein des challenges CTF.<sup>[[4]](#references)</sup>

Pour l’analyse, **oletools** et **OfficeDissector** offrent des toolsets complets pour examiner les documents OLE et OOXML. Ces outils aident à identifier et à analyser les macros intégrées, qui servent souvent de vecteurs pour la diffusion de malware, en téléchargeant et en exécutant généralement des payloads malveillants supplémentaires. L’analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le debugging avec des breakpoints et des watch variables.<sup>[[4]](#references)</sup>

L’installation et l’utilisation de **oletools** sont simples, avec des commandes permettant l’installation via pip et l’extraction des macros à partir de documents. Dans Word, les macros automatiques incluent `AutoExec` et `AutoOpen`, tandis que `Document_Open` est une procédure d’événement d’ouverture.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation de fichiers OLE Compound File : Autodesk Revit RFA – recomputation ECC et gzip contrôlé

Les modèles Revit RFA sont stockés sous forme d’[OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (également appelé CFBF). Le modèle sérialisé se trouve dans storage/stream :<sup>[[1]](#references)[[3]](#references)</sup>

- Storage : `Global`
- Stream : `Latest` → `Global\Latest`

Structure clé de `Global\Latest` (observée sur Revit 2025) :

- En-tête
- Payload compressé avec GZIP (le graphe d’objets sérialisé réel)
- Padding nul
- Trailer de code correcteur d’erreurs (ECC)

Revit répare automatiquement les petites perturbations du stream à l’aide du trailer ECC et rejette les streams qui ne correspondent pas à l’ECC. Par conséquent, modifier naïvement les octets compressés ne sera pas conservé : vos modifications sont soit annulées, soit le fichier est rejeté. Pour garantir un contrôle octet par octet de ce que voit le désérialiseur, vous devez :<sup>[[1]](#references)</sup>

- Recompresser avec une implémentation gzip compatible avec Revit (afin que les octets compressés produits/acceptés par Revit correspondent à ceux attendus).
- Recalculer le trailer ECC sur le stream complété par du padding afin que Revit accepte le stream modifié sans le réparer automatiquement.

Workflow pratique pour patcher/fuzzer le contenu des fichiers RFA :<sup>[[1]](#references)</sup>

1) Développer le document OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Modifier `Global\Latest` avec une discipline gzip/ECC

- Déconstruire `Global/Latest` : conserver l’en-tête, décompresser le payload avec gunzip, modifier les octets, puis recomprimer avec gzip en utilisant des paramètres deflate compatibles avec Revit.
- Préserver le zero-padding et recalculer le trailer ECC afin que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d’une reproduction déterministe octet par octet, créer un wrapper minimal autour des DLL de Revit afin d’appeler ses chemins gzip/gunzip et son calcul ECC (comme démontré dans la recherche), ou réutiliser tout helper disponible qui reproduit ces sémantiques.

3) Reconstruire le document composé OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool écrit les storages/streams dans le système de fichiers en échappant les caractères invalides dans les noms NTFS ; le chemin du stream recherché est exactement `Global/Latest` dans l’arborescence de sortie.
- Lors de la diffusion d’attaques massives via des plugins d’écosystème qui récupèrent des RFA depuis un cloud storage, assurez-vous que votre RFA patché passe d’abord localement les contrôles d’intégrité de Revit (gzip/ECC corrects) avant de tenter une injection réseau.

Insight sur l’exploitation (pour déterminer quels octets placer dans le payload gzip) :<sup>[[1]](#references)</sup>

- Le désérialiseur de Revit lit un index de classe de 16 bits et construit un objet. Certains types sont non polymorphes et ne possèdent pas de vtables ; l’abus de la gestion du destructeur provoque un type confusion où le moteur exécute un appel indirect via un pointeur contrôlé par l’attaquant.
- Le choix de `AString` (index de classe `0x1F`) place un pointeur de heap contrôlé par l’attaquant à l’offset 0 de l’objet. Pendant la boucle de destruction, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs objets de ce type dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (« weird machine »), puis organisez un stack pivot vers une chaîne ROP x64 conventionnelle.

Consultez les détails concernant le pivot et la construction de gadgets x64 sous Windows ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

et les indications générales sur la ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outillage :<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) pour développer/reconstruire des fichiers composés OLE : https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD pour le reverse/taint ; désactivez le page heap avec TTD afin de conserver des traces compactes.
- Un proxy local (par exemple Fiddler) peut simuler une livraison via la chaîne d'approvisionnement en remplaçant les RFA dans le trafic des plugins à des fins de test.

## References

- [1] [Création d'un exploit RCE complet à partir d'un crash lors de l'analyse d'un fichier RFA Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Fichier composé OLE (CFBF), documentation](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentation d'olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automatiques (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Événement Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
