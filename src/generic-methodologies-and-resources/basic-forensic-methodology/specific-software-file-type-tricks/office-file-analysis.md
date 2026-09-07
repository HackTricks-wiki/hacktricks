# Office-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is slegs ’n opsomming:<sup>[[4]](#references)</sup>

Microsoft Office-dokumente verskyn algemeen as legacy-formate soos RTF en OLE/CFBF-gebaseerde DOC, XLS en PPT, of as nuwer **Office Open XML (OOXML)**-formate soos DOCX, XLSX en PPTX. Office-dokumente kan aktiewe inhoud soos macros bevat, wat hulle algemene phishing- en malware-draers maak. OOXML-lêers is ZIP-houers waarvan die lêerhiërargie en XML-inhoud geïnspekteer kan word deur hulle uit te pak.<sup>[[3]](#references)[[4]](#references)</sup>

Om OOXML-lêerstrukture te verken, word die command om ’n dokument uit te pak en die uitvoerstruktuur gegee. Tegnieke om data in hierdie lêers te versteek, is gedokumenteer, wat voortgesette innovasie in dataverberging binne CTF-uitdagings aandui.<sup>[[4]](#references)</sup>

Vir analise bied **oletools** en **OfficeDissector** omvattende toolsets vir die ondersoek van beide OLE- en OOXML-dokumente. Hierdie tools help om ingebedde macros te identifiseer en te ontleed, wat dikwels as vektore vir malware-aflewering dien en gewoonlik addisionele malicious payloads aflaai en uitvoer. Analise van VBA-macros kan sonder Microsoft Office gedoen word deur Libre Office te gebruik, wat debugging met breakpoints en watch variables moontlik maak.<sup>[[4]](#references)</sup>

Installasie en gebruik van **oletools** is eenvoudig, met commands wat verskaf word om dit via pip te installeer en macros uit dokumente te onttrek. In Word sluit automatic macros `AutoExec` en `AutoOpen` in, terwyl `Document_Open` ’n open-event-prosedure is.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Vir wagwoord-geënkripteerde Office-dokumente, sien die [grammatika-gedrewe offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Ontginning van OLE Compound File: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA-modelle word in ’n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ook bekend as CFBF) gestoor. Die geserialiseerde model is onder storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Sleuteluitleg van `Global\Latest` (waargeneem op Revit 2025):

- Kopskrif
- GZIP-saamgeperste loonvrag (die werklike geserialiseerde objekgrafiek)
- Nulvulling
- Error-Correcting Code (ECC)-agtervoegsel

Revit sal klein wysigings aan die stream outomaties herstel met behulp van die ECC-agtervoegsel en sal streams verwerp wat nie met die ECC ooreenstem nie. Daarom sal die direkte wysiging van die saamgeperste grepe nie behoue bly nie: jou veranderinge word óf teruggestel óf die lêer word verwerp. Om akkurate beheer op greepvlak te verseker oor wat die deserialiseerder sien, moet jy:<sup>[[1]](#references)</sup>

- Hersaampers met ’n Revit-versoenbare gzip-implementering (sodat die saamgeperste grepe wat Revit produseer/aanvaar, ooreenstem met wat dit verwag).
- Die ECC-agtervoegsel oor die gevulde stream herbereken sodat Revit die gewysigde stream aanvaar sonder om dit outomaties te herstel.

Praktiese workflow vir die patching/fuzzing van RFA-inhoud:<sup>[[1]](#references)</sup>

1) Brei die OLE compound document uit.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Deconstrueer `Global\Latest` met gzip/ECC-dissipline

- Deconstrueer `Global/Latest`: behou die header, gunzip die payload, muteer die bytes, en gzip dit dan weer met Revit-compatible deflate parameters.
- Behou zero-padding en bereken die ECC-trailer weer sodat die nuwe bytes deur Revit aanvaar word.
- As jy deterministiese byte-vir-byte-reproduksie benodig, bou ’n minimale wrapper rondom Revit se DLLs om sy gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek repliseer.

3) Bou die OLE compound document weer op.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):<sup>[[1]](#references)</sup>

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Plaas verskeie sulke objekte in die serialized graph sodat elke iterasie van die destructor loop een gadget (“weird machine”) uitvoer, en reël ’n stack pivot na ’n konvensionele x64 ROP chain.

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
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain delivery simuleer deur RFAs in plugin-verkeer om te ruil vir toetsing.

## References

- [1] [Die skep van ’n volledige RCE-exploit uit ’n crash in Autodesk Revit RFA File Parsing (ZDI-blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF)-dokumentasie](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF-veldgids](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-dokumentasie (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
