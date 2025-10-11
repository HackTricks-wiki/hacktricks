# Office-lêerontleding

{{#include ../../../banners/hacktricks-training.md}}


Vir meer inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n opsomming:

Microsoft het baie kantoor-dokumentformate geskep, met twee hooftipes wat **OLE formats** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML) formats** (soos DOCX, XLSX, PPTX) is. Hierdie formate kan macros bevat, wat hulle teikens maak vir phishing en malware. OOXML-lêers is gestruktureer as zip-containers, wat inspeksie deur uitpak moontlik maak en die lêer- en gidshiërargie en XML-lêerinhalte openbaar.

Om OOXML-lêerstrukture te verken, word die opdrag om 'n dokument uit te pak en die uitsetstruktuur gegee. Tegnieke om data in hierdie lêers te versteek is gedokumenteer, wat voortdurende innovasie in dataverborge binne CTF-uitdagings aandui.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapstelle om beide OLE- en OOXML-dokumente te ondersoek. Hierdie gereedskap help om ingesluitde macros te identifiseer en te ontleed, wat dikwels as vektore vir malware-aflewering dien en tipies addisionele kwaadwillige payloads aflaai en uitvoer. Ontleding van VBA-macros kan sonder Microsoft Office gedoen word deur Libre Office te gebruik, wat debugging met breakpoints en watch-variabeles toelaat.

Installasie en gebruik van **oletools** is reguit, met opdragte vir installasie via pip en vir die onttrekking van macros uit dokumente. Outomatiese uitvoering van macros word geaktiveer deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File eksploitasie: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA-modelle word gestoor as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Die gesserialiseerde model is onder storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleutelstruktuur van `Global\Latest` (waargeneem op Revit 2025):

- Header
- GZIP-compressed payload (die werklike gesserialiseerde objekgrafiek)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit sal klein perturbasies aan die stroom outo-herstel met behulp van die ECC-trailer en sal strome wat nie met die ECC ooreenstem weier. Daarom sal naïef die gekomprimeerde bytes wysig nie volhoubaar wees: jou veranderinge word óf teruggedraai óf die lêer word geweier. Om byte-akkurate beheer oor wat die deserialiseerder sien te verseker, moet jy:

- Herkomprimeer met 'n Revit-kompatibele gzip-implementering (sodat die gekomprimeerde bytes wat Revit produseer/aanvaar ooreenstem met wat dit verwag).
- Herbereken die ECC-trailer oor die gevulde stroom sodat Revit die gemodifiseerde stroom sal aanvaar sonder om dit outo te herstel.

Praktiese werkvloei vir patching/fuzzing van RFA-inhoud:

1) Brei die OLE compound document uit
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Wysig Global\Latest volgens gzip/ECC-reëls

- Ontleed `Global/Latest`: behou die header, gunzip die payload, muteer bytes, en gzip dit terug met Revit-geskikte deflate-parameters.
- Behou zero-padding en herbereken die ECC-trailer sodat die nuwe bytes deur Revit aanvaar word.
- As jy deterministiese byte-vir-byte reproduksie benodig, bou 'n minimale wrapper rondom Revit’s DLLs om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare hulpmiddel wat hierdie semantiek repliseer.

3) Herbou die OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Aantekeninge:

- CompoundFileTool skryf storages/streams na die lêerstelsel en ontsnap karakters wat ongeldig is in NTFS-name; die streampad wat jy benodig is presies `Global/Latest` in die uitvoerboom.
- Wanneer jy massale aanvalle via ecosystem plugins lewer wat RFAs uit cloud storage haal, maak seker dat jou gepatchte RFA eers plaaslik Revit se integriteitskontroles deurstaan (gzip/ECC correct) voordat jy netwerk-inspuiting probeer.

Uitbuitingsinsig (om te lei watter bytes in die gzip payload geplaas moet word):

- Die Revit deserializer lees 'n 16-bit class index en konstrueer 'n object. Sekere tipes is nie-polimorfies en het geen vtables nie; die misbruik van destructor-handling gee 'n type confusion waar die engine 'n indirect call deur 'n attacker-controlled pointer uitvoer.
- Die keuse van `AString` (class index `0x1F`) plaas 'n attacker-controlled heap pointer by object offset 0. Tydens die destructor-loop voer Revit effektief die volgende uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas verskeie sulke objects in die serialized graph sodat elke iterasie van die destructor loop een gadget (“weird machine”) uitvoer, en reël ’n stack pivot in ’n konvensionele x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:

- CompoundFileTool (OSS) om OLE compound files uit te brei/herbou: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD vir reverse/taint; skakel page heap af met TTD om spore kompakt te hou.
- ’n plaaslike proxy (bv. Fiddler) kan voorsieningsketting-lewering simuleer deur RFAs in plugin verkeer te ruil vir toetsing.

## Verwysings

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
