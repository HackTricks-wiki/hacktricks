# Analyse des fichiers Office

{{#include ../../../banners/hacktricks-training.md}}

Pour plus d’informations, consultez [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Voici simplement un résumé :<sup>[[4]](#references)</sup>

Les documents Microsoft Office se présentent couramment sous des formats anciens tels que RTF et DOC, XLS et PPT basés sur OLE/CFBF, ou sous des formats plus récents **Office Open XML (OOXML)** tels que DOCX, XLSX et PPTX. Les documents Office peuvent contenir du contenu actif, comme des macros, ce qui en fait des vecteurs courants de phishing et de malware. Les fichiers OOXML sont des conteneurs ZIP dont la hiérarchie de fichiers et le contenu XML peuvent être examinés en les décompressant.<sup>[[3]](#references)[[4]](#references)</sup>

Pour explorer la structure des fichiers OOXML, la commande permettant de décompresser un document et la structure obtenue sont présentées. Des techniques de dissimulation de données dans ces fichiers ont été documentées, témoignant de l’innovation continue en matière de dissimulation de données dans les défis CTF.<sup>[[4]](#references)</sup>

Pour l’analyse, **oletools** et **OfficeDissector** proposent des ensembles d’outils complets permettant d’examiner les documents OLE et OOXML. Ces outils aident à identifier et à analyser les macros intégrées, qui servent souvent de vecteurs de diffusion de malware et téléchargent et exécutent généralement d’autres charges utiles malveillantes. L’analyse des macros VBA peut être effectuée sans Microsoft Office à l’aide de LibreOffice, qui permet le débogage avec des points d’arrêt et des variables de surveillance.<sup>[[4]](#references)</sup>

L’installation et l’utilisation de **oletools** sont simples ; des commandes sont fournies pour l’installer avec pip et extraire les macros des documents. Dans Word, les macros automatiques comprennent `AutoExec` et `AutoOpen`, tandis que `Document_Open` est une procédure d’événement d’ouverture.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Pour les documents Office chiffrés par mot de passe, consultez le [workflow de récupération hors ligne basé sur une grammaire](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploitation d’un fichier composé OLE : Autodesk Revit RFA – recalcul de l’ECC et gzip contrôlé

Les modèles Revit RFA sont stockés dans un [fichier composé OLE](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aussi appelé CFBF). Le modèle sérialisé se trouve dans le stockage/flux :<sup>[[1]](#references)[[3]](#references)</sup>

- Stockage : `Global`
- Flux : `Latest` → `Global\Latest`

Structure de `Global\Latest` (observée dans Revit 2025) :

- En-tête
- Charge utile compressée en GZIP (le graphe d’objets sérialisé proprement dit)
- Remplissage nul
- Bande-annonce du code de correction d’erreurs (ECC)

Revit répare automatiquement les petites perturbations du flux à l’aide de la bande-annonce ECC et rejette les flux qui ne correspondent pas à l’ECC. Par conséquent, une modification naïve des octets compressés ne sera pas conservée : vos modifications sont soit annulées, soit le fichier est rejeté. Pour contrôler avec précision les octets reçus par le désérialiseur, vous devez :<sup>[[1]](#references)</sup>

- Recompresser avec une implémentation gzip compatible avec Revit (afin que les octets compressés produits/acceptés par Revit correspondent à ce qu’il attend).
- Recalculer la bande-annonce ECC sur le flux complété afin que Revit accepte le flux modifié sans le réparer automatiquement.

Workflow pratique pour modifier ou fuzz les contenus RFA :<sup>[[1]](#references)</sup>

1) Développer le document composé OLE.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Modifier `Global\Latest` en respectant les règles gzip/ECC

- Décomposer `Global/Latest` : conserver l’en-tête, décompresser la charge utile avec gunzip, modifier les octets, puis la recompresser avec gzip en utilisant des paramètres deflate compatibles avec Revit.
- Préserver le remplissage par des zéros et recalculer la bande-annonce ECC afin que Revit accepte les nouveaux octets.
- Pour une reproduction déterministe octet par octet, créer un wrapper minimal autour des DLL de Revit afin d’appeler ses fonctions gzip/gunzip et de calcul ECC (comme le montrent les recherches), ou réutiliser un helper disponible qui reproduit ces comportements.

3) Reconstruire le document composé OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes :<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool écrit les storages/streams dans le système de fichiers en échappant les caractères interdits dans les noms NTFS ; le chemin du stream recherché est exactement `Global/Latest` dans l’arborescence de sortie.
- Pour lancer des attaques de masse via des plugins d’écosystème qui récupèrent des RFA depuis un stockage cloud, assurez-vous que votre RFA patché passe d’abord localement les vérifications d’intégrité de Revit (gzip/ECC corrects), avant toute tentative d’injection réseau.

Éléments d’exploitation (pour guider le choix des octets à placer dans le payload gzip) :<sup>[[1]](#references)</sup>

- Le désérialiseur de Revit lit un index de classe sur 16 bits et instancie un objet. Certains types ne sont pas polymorphes et n’ont pas de vtables ; en abusant de la gestion du destructeur, on obtient une confusion de types qui amène le moteur à exécuter un appel indirect via un pointeur contrôlé par l’attaquant.
- Choisir `AString` (index de classe `0x1F`) place un pointeur de tas contrôlé par l’attaquant à l’offset 0 de l’objet. Pendant la boucle du destructeur, Revit exécute effectivement :

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Placez plusieurs objets de ce type dans le graphe sérialisé afin que chaque itération de la boucle du destructeur exécute un gadget (« weird machine »), puis configurez un stack pivot vers une chaîne ROP x64 classique.

Voir les détails de construction de pivots/gadgets Windows x64 ici :

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

et les recommandations générales sur la ROP ici :

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils :<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) pour extraire/reconstruire des fichiers composés OLE : https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD pour l’ingénierie inverse et le suivi de taint ; désactivez le page heap avec TTD pour garder des traces compactes.
- Un proxy local (p. ex., Fiddler) peut simuler la livraison via la chaîne d’approvisionnement en remplaçant les RFA dans le trafic des plug-ins à des fins de test.

## References

- [1] [Créer un exploit RCE complet à partir d’un crash dans l’analyse des fichiers RFA d’Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentation sur les fichiers composés OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guide de terrain Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentation d’olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automatiques (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Événement Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
