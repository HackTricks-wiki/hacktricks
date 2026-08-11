# Office-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hierdie is slegs ’n opsomming:<sup>[[4]](#references)</sup>

Microsoft Office-dokumente verskyn algemeen as legacy-formate soos RTF en OLE/CFBF-gebaseerde DOC, XLS en PPT, of as nuwer **Office Open XML (OOXML)**-formate soos DOCX, XLSX en PPTX. Office-dokumente kan aktiewe inhoud soos macros bevat, wat hulle algemene phishing- en malware-draers maak. OOXML-lêers is ZIP-containers waarvan die lêerhiërargie en XML-inhoud geïnspekteer kan word deur hulle uit te pak.<sup>[[3]](#references)[[4]](#references)</sup>

Om OOXML-lêerstrukture te verken, word die command om ’n dokument uit te pak en die uitvoerstruktuur verskaf. Tegnieke om data in hierdie lêers te versteek, is gedokumenteer, wat voortdurende innovasie in dataverberging binne CTF-challenges aandui.<sup>[[4]](#references)</sup>

Vir analise bied **oletools** en **OfficeDissector** omvattende toolsets vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie tools help met die identifisering en analise van ingebedde macros, wat dikwels as vektore vir malware-aflewering dien en gewoonlik addisionele malicious payloads aflaai en uitvoer. Analise van VBA-macros kan sonder Microsoft Office uitgevoer word deur Libre Office te gebruik, wat debugging met breakpoints en watch variables moontlik maak.<sup>[[4]](#references)</sup>

Installasie en gebruik van **oletools** is eenvoudig, met commands wat verskaf word vir installering via pip en die onttrekking van macros uit dokumente. In Word sluit outomatiese macros `AutoExec` en `AutoOpen` in, terwyl `Document_Open` ’n open-event procedure is.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA-modelle word as ’n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ook bekend as CFBF) gestoor. Die geserialiseerde model is onder storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleuteluitleg van `Global\Latest` (waargeneem op Revit 2025):

- Kopskrif
- GZIP-saamgeperste loonvrag (die werklike geserialiseerde objekgrafiek)
- Nul-opvulling
- Error-Correcting Code (ECC)-sleepdata

Revit sal klein wysigings aan die stream outomaties herstel deur die ECC-sleepdata te gebruik en sal streams wat nie met die ECC ooreenstem nie, verwerp. Daarom sal die eenvoudige wysiging van die saamgeperste grepe nie behoue bly nie: jou veranderinge word óf teruggestel óf die lêer word verwerp. Om akkurate beheer te verseker oor die grepe wat die deserialiseerder sien, moet jy:<sup>[[1]](#references)</sup>

- Herkomprimeer met ’n Revit-versoenbare gzip-implementering (sodat die saamgeperste grepe wat Revit produseer/aanvaar, ooreenstem met wat dit verwag).
- Herbereken die ECC-sleepdata oor die opgevulde stream sodat Revit die gewysigde stream sal aanvaar sonder om dit outomaties te herstel.

Praktiese werksvloei vir die patch/fuzzing van RFA-inhoud:<sup>[[1]](#references)</sup>

1) Brei die OLE compound document uit.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Wysig Global\Latest met gzip/ECC-dissipline

- Ontleed `Global/Latest`: behou die kopskrif, gunzip die payload, muteer grepe, en gzip dit dan weer met Revit-versoenbare deflate-parameters.
- Behou nulvulling en bereken die ECC-trailer weer sodat die nuwe grepe deur Revit aanvaar word.
- Indien jy deterministiese reproduksie byte vir byte benodig, bou ’n minimale wrapper rondom Revit se DLL’s om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek repliseer.

3) Herbou die OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool skryf storages/streams na die lêerstelsel met escaping vir karakters wat ongeldig is in NTFS-name; die stream path wat jy benodig, is presies `Global/Latest` in die uitvoerboom.
- Wanneer mass attacks via ecosystem plugins gelewer word wat RFAs van cloud storage aflaai, maak seker dat jou patched RFA eers plaaslik Revit se integrity checks slaag (gzip/ECC korrek) voordat jy network injection probeer.

Exploitation insight (om te bepaal watter bytes in die gzip payload geplaas moet word):<sup>[[1]](#references)</sup>

- Die Revit deserializer lees ’n 16-bit class index en konstrueer ’n object. Sekere tipes is non-polymorphic en het nie vtables nie; deur destructor handling te misbruik, ontstaan ’n type confusion waar die engine ’n indirect call deur ’n attacker-controlled pointer uitvoer.
- Deur `AString` (class index `0x1F`) te kies, word ’n attacker-controlled heap pointer by object offset 0 geplaas. Tydens die destructor loop voer Revit effektief die volgende uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas meerdere sulke objekte in die geserialiseerde grafiek sodat elke iterasie van die destructor-lus een gadget (“weird machine”) uitvoer, en reël ’n stack pivot na ’n konvensionele x64 ROP chain.

Sien besonderhede oor Windows x64 pivot/gadget-bou hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

en algemene ROP-riglyne hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) om OLE compound files uit te brei/herbou: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD vir reverse/taint; deaktiveer page heap met TTD om traces kompak te hou.
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain delivery simuleer deur RFA’s in plugin-verkeer om te ruil vir toetsing.

## References

- [1] [Die vervaardiging van ’n volledige exploit RCE vanaf ’n crash in Autodesk Revit RFA-lêer-parsing (ZDI-blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF)-dokumentasie](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF-veldgids](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-dokumentasie (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open-gebeurtenis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
