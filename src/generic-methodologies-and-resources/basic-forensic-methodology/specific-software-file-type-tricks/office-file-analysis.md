# Ontleding van Office-lêers

{{#include ../../../banners/hacktricks-training.md}}


Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:<sup>[[4]](#references)</sup>

Microsoft het baie Office-dokumentformate geskep, met twee hoofsoorte: **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML)-formate** (soos DOCX, XLSX, PPTX). Hierdie formate kan macros insluit, wat hulle teikens vir phishing en malware maak. OOXML-lêers is as zip-houers gestruktureer, wat inspeksie deur dit te onttrek moontlik maak en die lêer- en vouerhiërargie sowel as die inhoud van XML-lêers openbaar.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument te unzip en die uitsetstruktuur gegee. Tegnieke om data in hierdie lêers te versteek, is gedokumenteer, wat daarop dui dat daar voortdurend vernuwing in dataverberging binne CTF-uitdagings plaasvind.

Vir analise bied **oletools** en **OfficeDissector** omvattende toolsets vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie tools help om ingebedde macros te identifiseer en te ontleed, wat dikwels as vektore vir malware-aflewering dien en gewoonlik addisionele malicious payloads aflaai en uitvoer. VBA-macros kan sonder Microsoft Office ontleed word deur Libre Office te gebruik, wat debugging met breakpoints en watch variables moontlik maak.

Die installering en gebruik van **oletools** is eenvoudig, met opdragte wat voorsien word om dit via pip te installeer en macros uit dokumente te onttrek. Outomatiese uitvoering van macros word deur funksies soos `AutoOpen`, `AutoExec` of `Document_Open` geaktiveer.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA-modelle word as 'n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ook bekend as CFBF) gestoor. Die geserialiseerde model is onder storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleuteluitleg van `Global\Latest` (waargeneem op Revit 2025):

- Header
- GZIP-saamgepersde payload (die werklike geserialiseerde objekgrafiek)
- Nul-padding
- Error-Correcting Code (ECC)-sleepwa

Revit sal klein wysigings aan die stream outomaties herstel deur die ECC-sleepwa te gebruik, en sal streams wat nie met die ECC ooreenstem nie, verwerp. Daarom sal die naïewe wysiging van die saamgeperste grepe nie behoue bly nie: jou veranderinge word óf teruggedraai óf die lêer word verwerp. Om akkurate beheer op greepvlak te verseker oor wat die deserialiseerder sien, moet jy:

- Herkomprimeer met 'n Revit-versoenbare gzip-implementering (sodat die saamgeperste grepe wat Revit produseer/aanvaar, ooreenstem met wat dit verwag).
- Herbereken die ECC-sleepwa oor die gepadde stream sodat Revit die gewysigde stream sal aanvaar sonder om dit outomaties te herstel.

Praktiese werkvloei vir die patching/fuzzing van RFA-inhoud:<sup>[[1]](#references)</sup>

1) Brei die OLE compound document uit
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Wysig Global\Latest met gzip/ECC-dissipline

- Ontleed `Global/Latest`: behou die header, gunzip die payload, wysig die grepe, en gzip dit daarna weer met Revit-versoenbare deflate-parameters.
- Behou zero-padding en bereken die ECC-trailer opnuut sodat die nuwe grepe deur Revit aanvaar word.
- Indien jy deterministiese byte-vir-byte-reproduksie benodig, bou ’n minimale wrapper rondom Revit se DLLs om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek repliseer.

3) Bou die OLE compound document weer op
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)</sup>

- CompoundFileTool skryf storages/streams na die lêerstelsel met escaping vir karakters wat ongeldig is in NTFS-name; die stream-pad wat jy wil hê, is presies `Global/Latest` in die uitvoerboom.
- Wanneer mass attacks via ekosisteem-plugins gelewer word wat RFA's vanaf cloud storage ophaal, verseker dat jou patched RFA Revit se integrity checks plaaslik slaag (gzip/ECC korrek) voordat jy network injection probeer.

Exploitation-insig (om te bepaal watter bytes in die gzip payload geplaas moet word):<sup>[[1]](#references)</sup>

- Die Revit deserializer lees ’n 16-bit class index en konstrueer ’n object. Sekere tipes is non-polymorphic en het nie vtables nie; deur destructor-hantering te misbruik, ontstaan ’n type confusion waar die engine ’n indirect call deur ’n attacker-controlled pointer uitvoer.
- Deur `AString` (class index `0x1F`) te kies, word ’n attacker-controlled heap pointer by object offset 0 geplaas. Tydens die destructor-lus voer Revit effektief die volgende uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas verskeie sulke objekte in die serialized graph sodat elke iterasie van die destructor-loop een gadget (“weird machine”) uitvoer, en reël ’n stack pivot na ’n konvensionele x64 ROP chain.

Sien Windows x64 pivot/gadget-bou-besonderhede hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

en algemene ROP-leiding hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) om OLE compound files uit te brei/herbou: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD vir reverse/taint; deaktiveer page heap met TTD om traces kompak te hou.
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain delivery simuleer deur RFAs in plugin-verkeer om te ruil vir toetsing.

## Verwysings

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
