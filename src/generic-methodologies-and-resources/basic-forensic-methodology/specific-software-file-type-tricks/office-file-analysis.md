# Office-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}


Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is slegs ’n opsomming:<sup>[[4]](#references)</sup>

Microsoft het baie Office-dokumentformate geskep, met twee hooftipes: **OLE-formate** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML)-formate** (soos DOCX, XLSX, PPTX). Hierdie formate kan makro's insluit, wat hulle teikens vir phishing en malware maak. OOXML-lêers is as zip-houers gestruktureer, wat inspeksie deur uitpak moontlik maak en die lêer- en vouerhiërargie sowel as die inhoud van XML-lêers blootlê.

Om OOXML-lêerstrukture te verken, word die opdrag om ’n dokument uit te pak en die uitvoerstruktuur verskaf. Tegnieke om data in hierdie lêers te versteek, is gedokumenteer, wat voortdurende innovasie in dataverberging binne CTF-uitdagings aandui.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende toolsets vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie tools help om ingebedde makro's te identifiseer en te ontleed, wat dikwels as vektore vir malware-aflewering dien en tipies addisionele kwaadwillige payloads aflaai en uitvoer. Ontleding van VBA-makro's kan sonder Microsoft Office gedoen word deur Libre Office te gebruik, wat debugging met breekpunte en watch variables moontlik maak.

Installering en gebruik van **oletools** is eenvoudig, met opdragte wat verskaf word vir installering via pip en die onttrekking van makro's uit dokumente. Outomatiese uitvoering van makro's word deur funksies soos `AutoOpen`, `AutoExec` of `Document_Open` geaktiveer.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA-modelle word gestoor as ’n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ook bekend as CFBF). Die geserialiseerde model is onder storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleuteluitleg van `Global\Latest` (waargeneem op Revit 2025):

- Header
- GZIP-gekomprimeerde payload (die werklike geserialiseerde objekgrafiek)
- Zero padding
- Error-Correcting Code (ECC)-trailer

Revit sal klein wysigings aan die stream outomaties herstel deur die ECC-trailer te gebruik en sal streams verwerp wat nie met die ECC ooreenstem nie. Daarom sal die direkte wysiging van die compressed bytes nie behoue bly nie: jou veranderinge word óf teruggestel óf die lêer word verwerp. Om byte-akkurate beheer te verseker oor wat die deserializer sien, moet jy:

- Herkomprimeer met ’n Revit-versoenbare gzip-implementering (sodat die compressed bytes wat Revit produseer/aanvaar ooreenstem met wat dit verwag).
- Herbereken die ECC-trailer oor die gepadde stream sodat Revit die gewysigde stream aanvaar sonder om dit outomaties te herstel.

Praktiese workflow vir die patching/fuzzing van RFA-inhoud:<sup>[[1]](#references)</sup>

1) Brei die OLE compound document uit
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Redigeer Global\Latest met gzip/ECC-dissipline

- Ontleed `Global/Latest`: behou die header, gunzip die payload, wysig die bytes, en gzip dit dan weer met Revit-compatible deflate-parameters.
- Behou zero-padding en herbereken die ECC-trailer sodat die nuwe bytes deur Revit aanvaar word.
- Indien jy deterministiese byte-vir-byte-reproduksie benodig, bou ’n minimale wrapper rondom Revit se DLLs om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek repliseer.

3) Bou die OLE compound document weer op
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)</sup>

- CompoundFileTool skryf storages/streams na die lêerstelsel met escaping vir karakters wat ongeldig is in NTFS-name; die stream path wat jy benodig, is presies `Global/Latest` in die uitvoerboom.
- Wanneer mass attacks via ecosystem plugins gelewer word wat RFA's uit cloud storage haal, maak seker dat jou patched RFA eers plaaslik Revit se integrity checks slaag (gzip/ECC korrek) voordat jy network injection probeer.

Exploitation insight (om te rig watter bytes in die gzip payload geplaas moet word):<sup>[[1]](#references)</sup>

- Die Revit deserializer lees 'n 16-bit class index en konstrueer 'n objek. Sekere tipes is non-polymorphic en het nie vtables nie; misbruik van destructor handling lei tot 'n type confusion waar die engine 'n indirect call deur 'n attacker-controlled pointer uitvoer.
- Deur `AString` (class index `0x1F`) te kies, word 'n attacker-controlled heap pointer by object offset 0 geplaas. Tydens die destructor loop voer Revit effektief die volgende uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas veelvuldige sulke objekte in die serialized graph sodat elke iterasie van die destructor loop een gadget (“weird machine”) uitvoer, en reël ’n stack pivot na ’n konvensionele x64 ROP chain.

Sien Windows x64 pivot/gadget-bou-besonderhede hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

en algemene ROP-riglyne hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) om OLE compound files uit te brei/herbou: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD vir reverse/taint; deaktiveer page heap met TTD om traces kompak te hou.
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain delivery simuleer deur RFA’s in plugin-verkeer om te ruil vir testing.

## Verwysings

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
