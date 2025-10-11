# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ceci n'est qu'un résumé :

Microsoft a créé de nombreux formats de documents Office, avec deux types principaux étant **OLE formats** (comme RTF, DOC, XLS, PPT) et **Office Open XML (OOXML) formats** (tels que DOCX, XLSX, PPTX). Ces formats peuvent inclure des macros, ce qui en fait des cibles pour le phishing et les malware. Les fichiers OOXML sont structurés en conteneurs zip, permettant une inspection en les décompressant, révélant la hiérarchie de fichiers et dossiers ainsi que le contenu des fichiers XML.

Pour explorer la structure des fichiers OOXML, la commande pour décompresser un document et la structure de sortie sont fournies. Des techniques pour dissimuler des données dans ces fichiers ont été documentées, montrant une innovation continue dans la dissimulation de données au sein des challenges CTF.

Pour l'analyse, **oletools** et **OfficeDissector** offrent des ensembles d'outils complets pour examiner à la fois les documents OLE et OOXML. Ces outils aident à identifier et analyser les macros embarquées, qui servent souvent de vecteurs pour la livraison de malware, téléchargeant et exécutant typiquement des charges utiles malveillantes supplémentaires. L'analyse des macros VBA peut être effectuée sans Microsoft Office en utilisant Libre Office, qui permet le débogage avec points d'arrêt et variables de surveillance.

L'installation et l'utilisation de **oletools** sont simples, avec des commandes fournies pour installer via pip et extraire les macros des documents. L'exécution automatique des macros est déclenchée par des fonctions comme `AutoOpen`, `AutoExec`, ou `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – recalcul ECC et gzip contrôlé

Les modèles RFA de Revit sont stockés comme un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Le modèle sérialisé se trouve sous storage/stream :

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Structure clé de `Global\Latest` (observée sur Revit 2025) :

- Header
- GZIP-compressed payload (le véritable graphe d'objets sérialisé)
- Zero padding
- Bande de code correcteur d'erreurs (ECC)

Revit répare automatiquement les petites perturbations du flux en utilisant la bande ECC et rejettera les flux qui ne correspondent pas à l'ECC. Par conséquent, éditer naïvement les octets compressés ne persistera pas : vos modifications sont soit annulées, soit le fichier est rejeté. Pour garantir un contrôle au niveau des octets sur ce que voit le désérialiseur, vous devez :

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Flux de travail pratique pour patching/fuzzing du contenu RFA :

1) Ouvrir le document OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Éditer Global\Latest avec la discipline gzip/ECC

- Déconstruire `Global/Latest` : conserver l'en-tête, gunzip le payload, muter les octets, puis gzip de nouveau en utilisant des paramètres deflate compatibles avec Revit.
- Préserver le zero-padding et recalculer le ECC trailer pour que les nouveaux octets soient acceptés par Revit.
- Si vous avez besoin d'une reproduction déterministe octet par octet, créer un wrapper minimal autour des DLLs de Revit pour invoquer ses chemins gzip/gunzip et le calcul ECC (comme démontré dans la recherche), ou réutiliser tout helper disponible qui réplique ces sémantiques.

3) Reconstruire le document composé OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool écrit storages/streams sur le filesystem en échappant les caractères invalides dans les noms NTFS ; le stream path que vous voulez est exactement `Global/Latest` dans l'output tree.
- Lors de la livraison d'attaques massives via ecosystem plugins qui fetchent des RFAs depuis cloud storage, assurez-vous que votre RFA patché passe d'abord les integrity checks de Revit localement (gzip/ECC correct) avant d'essayer une network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Le Revit deserializer lit un 16-bit class index et construit un object. Certains types sont non‑polymorphic et n'ont pas de vtables ; abuser du destructor handling provoque une type confusion où le engine exécute un indirect call via un attacker-controlled pointer.
- Choisir `AString` (class index `0x1F`) place un attacker-controlled heap pointer à l'object offset 0. Pendant la destructor loop, Revit exécute effectivement :
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Placez plusieurs de ces objets dans le graphe sérialisé afin que chaque itération de la destructor loop exécute un gadget (“weird machine”), et arrangez un stack pivot vers une chaîne ROP x64 conventionnelle.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Outils:

- CompoundFileTool (OSS) pour déployer/reconstruire les OLE compound files : https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD pour reverse/taint ; désactivez page heap avec TTD pour garder les traces compactes.
- Un proxy local (p. ex. Fiddler) peut simuler la livraison de la chaîne d'approvisionnement en échangeant des RFAs dans le trafic de plugin pour les tests.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
