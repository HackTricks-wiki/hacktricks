# Office-lêerontleding

{{#include ../../../banners/hacktricks-training.md}}


Vir verdere inligting, kyk [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:

Microsoft het verskeie Office-dokumentformate geskep, met twee hooftipes: **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML)-formate** (soos DOCX, XLSX, PPTX). Hierdie formate kan macros bevat, wat dit teikens maak vir phishing en malware. OOXML-lêers is gestruktureer as zip-behouers, wat inspeksie deur uitpak toelaat en die lêer- en gids-hiërargie sowel as die XML-inhoud openbaar maak.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument uit te pak en die uitvoerstruktuur gegee. Tegnieke om data in hierdie lêers te verberg is gedokumenteer, wat voortdurende innovasie in data-versteek binne CTF-uitdagings aandui.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapsstelle om beide OLE- en OOXML-dokumente te ondersoek. Hierdie gereedskap help om ingeslote macros te identifiseer en te analiseer, wat dikwels as vektore vir malware-lewering dien, gewoonlik deur addisionele kwaadwillige payloads af te laai en uit te voer. Analise van VBA-macros kan sonder Microsoft Office uitgevoer word deur Libre Office te gebruik, wat debugging met breakpoints en watch variables toelaat.

Installasie en gebruik van **oletools** is reguit, met opdragte gegee om via pip te installeer en macros uit dokumente te onttrek. Outomatiese uitvoering van macros word veroorsaak deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File uitbuiting: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA models word gestoor as 'n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Die geserialiseerde model is onder storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleutelstruktuur van `Global\Latest` (waargenome op Revit 2025):

- Header
- GZIP-gekomprimeerde payload (die werklike geserialiseerde objekgrafiek)
- Nul-opvulling
- Error-Correcting Code (ECC) trailer

Revit sal klein versteurings aan die stroom outomaties herstel deur die ECC-trailer te gebruik en sal strome wat nie met die ECC ooreenstem nie verwerp. Daarom sal naïef bewerkte bytes in die gekompresseerde area nie volhoubaar wees nie: jou veranderings word óf teruggedra óf die lêer word verwerp. Om byte-nauwkeurige beheer oor wat die deserialiseerder sien te verseker, moet jy:

- Hergenereer met 'n Revit-verenigbare gzip-implementasie (sodat die gekompresseerde bytes wat Revit produseer/aanvaar ooreenstem met wat dit verwag).
- Herbereken die ECC-trailer oor die met nul-opvulling gepadde stroom sodat Revit die gewysigde stroom sal aanvaar sonder om dit outomaties te herstel.

Praktiese werkvloeistap vir patching/fuzzing van RFA-inhoud:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Bewerk Global\Latest met gzip/ECC-prosedure

- Dekonstrueer `Global/Latest`: behou die header, gunzip die payload, muteer bytes, en gzip dan terug met Revit-kompatibele deflate-parameters.
- Bewaar zero-padding en herbereken die ECC-trailer sodat die nuwe bytes deur Revit aanvaar word.
- As jy deterministiese byte-for-byte reproduksie benodig, bou 'n minimale wrapper rondom Revit’s DLLs om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek repliseer.

3) Herbou die OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Aantekeninge:

- CompoundFileTool skryf storages/streams na die lêerstelsel met ontsnapping vir karakters wat ongeldig is in NTFS-namme; die stream-pad wat jy wil hê is presies `Global/Latest` in die uitsetboom.
- Wanneer jy massale aanvalle lewer via ecosisteem-plugins wat RFAs uit cloud storage haal, maak seker dat jou gepatchede RFA eers plaaslik Revit se integriteitskontroles slaag (gzip/ECC korrek) voordat jy netwerkinjeksie probeer.

Uitbuitingsinsig (om te lei watter bytes om in die gzip payload te plaas):

- Die Revit deserializer lees 'n 16-bit class index en konstrueer 'n object. Sekere types is non‑polymorphic en het geen vtables nie; die misbruik van destructor handling lewer 'n type confusion waar die engine 'n indirect call uitvoer deur 'n attacker-controlled pointer.
- Die keuse van `AString` (class index `0x1F`) plaas 'n attacker-controlled heap pointer by object offset 0. Tydens die destructor loop voer Revit effektief uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas verskeie sulke voorwerpe in die geserialiseerde graf sodat elke iterasie van die destructor-lus een gadget (“weird machine”) uitvoer, en reël ’n stack pivot in ’n konvensionele x64 ROP-ketting.

Sien Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

en algemene ROP-riglyne hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:

- CompoundFileTool (OSS) om OLE compound files uit te brei/herbou: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD vir reverse/taint; skakel page heap af met TTD om spore kompakt te hou.
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain aflewering simuleer deur RFAs in plugin-verkeer te ruil vir toetsing.

## Verwysings

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
