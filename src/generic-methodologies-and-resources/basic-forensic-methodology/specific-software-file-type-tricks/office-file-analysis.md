# Office-lêerontleding

{{#include ../../../banners/hacktricks-training.md}}


Vir verdere inligting, sien [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net 'n samevatting:

Microsoft het baie Office-dokumentformate geskep, met twee hooftipes: **OLE formats** (soos RTF, DOC, XLS, PPT) en **Office Open XML (OOXML) formats** (bv. DOCX, XLSX, PPTX). Hierdie formate kan macros bevat, wat hulle teikens maak vir phishing en malware. OOXML-lêers is gestruktureer as zip-behouers, wat inspeksie deur uitpak moontlik maak en die lêer- en gids-hierargie sowel as die XML-inhoud openbaar.

Om OOXML-lêerstrukture te ondersoek, is die opdrag om 'n dokument uit te pak en die uitvoerstruktuur gegee. Tegnieke om data in hierdie lêers te versteek is gedokumenteer, wat voortdurende innovasie in data-versteeking binne CTF-uitdagings aandui.

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskap vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie gereedskap help om ingebedde macros te identifiseer en te ontleed, wat dikwels as vektore vir malware-aflewering dien deur gewoonlik addisionele kwaadwillige payloads af te laai en uit te voer. Analise van VBA-macros kan sonder Microsoft Office gedoen word deur Libre Office te gebruik, wat debugging met breakpoints en watch variables toelaat.

Installasie en gebruik van **oletools** is reguit vorentoe, met opdragte vir installasie via pip en die onttrekking van macros uit dokumente. Outomatiese uitvoering van macros word geaktiveer deur funksies soos `AutoOpen`, `AutoExec`, of `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modelle word gestoor as 'n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Die geserialiseerde model is onder storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleutel-uitleg van `Global\Latest` (waargeneem op Revit 2025):

- Header
- GZIP-gecomprimeerde payload (die werklike geserialiseerde objekgrafiek)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit sal klein versteurings aan die stroom outomaties herstel met die ECC-trailer en sal strome verwerp wat nie met die ECC ooreenstem nie. Daarom sal naïef die gekomprimeerde bytes wysig nie volhard nie: jou veranderinge word óf teruggedra óf die lêer word verwerp. Om byt-akkurate beheer te verseker oor wat die deserialiser sien, moet jy:

- Herkomprimeer met 'n Revit-compatible gzip-implementering (sodat die gecomprimeerde bytes wat Revit produseer/aanvaar ooreenstem met wat dit verwag).
- Herbereken die ECC-trailer oor die opgevulde stroom sodat Revit die gewysigde stroom sal aanvaar sonder om dit outomaties te herstel.

Praktiese werkvloei vir patching/fuzzing RFA-inhoud:

1) Brei die OLE compound-dokument uit
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Wysig Global\Latest met gzip/ECC-dissipline

- Ontleed `Global/Latest`: behou die header, gunzip die payload, muteer die bytes, en gzip dit terug met Revit-compatible deflate parameters.
- Behou zero-padding en herbereken die ECC trailer sodat die nuwe bytes deur Revit aanvaar word.
- As jy deterministiese byte-for-byte reproduksie nodig het, bou 'n minimale wrapper rondom Revit’s DLLs om sy gzip/gunzip paths en ECC computation aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantics repliseer.

3) Herbou die OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Aantekeninge:

- CompoundFileTool skryf storages/streams na die lêerstelsel met ontsnapping vir karakters ongeldig in NTFS-names; die streampad wat jy wil hê is presies `Global/Latest` in die uitvoerboom.
- Wanneer jy massale aanvalle lewer via ecosystem plugins wat RFAs uit cloud storage haal, verseker dat jou gepatchte RFA eers plaaslik Revit se integriteitskontroles deurstaan (gzip/ECC korrek) voordat jy netwerk-injektie probeer.

Exploitation insight (om te lei watter bytes in die gzip payload geplaas moet word):

- Die Revit deserializer lees 'n 16-bit klasindeks en konstrueer 'n objek. Sekere tipes is non‑polymorphic en ontbreek vtables; deur destructor-hantering te misbruik ontstaan 'n type confusion waar die engine 'n indirekte oproep deur 'n aanvaller-beheerde pointer uitvoer.
- Die keuse van `AString` (class index `0x1F`) plaas 'n aanvaller-beheerde heap pointer by objek-offset 0. Tydens die destructor loop voer Revit effektief uit:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas verskeie sulke objekte in die geseerialiseerde graf sodat elke iterasie van die destrukteur-lus een gadget (“weird machine”) uitvoer, en reël 'n stack pivot in 'n konvensionele x64 ROP chain.

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
- IDA Pro + WinDBG TTD vir reverse/taint; deaktiveer page heap met TTD om traces kompakt te hou.
- 'n plaaslike proxy (bv. Fiddler) kan supply-chain levering simuleer deur RFAs in plugin-verkeer te ruil vir toetsing.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
