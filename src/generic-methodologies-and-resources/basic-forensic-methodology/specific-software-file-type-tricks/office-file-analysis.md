# Office-lêerontleding

{{#include ../../../banners/hacktricks-training.md}}

Vir verdere inligting, kyk na [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Dit is net ’n opsomming:<sup>[[4]](#references)</sup>

Microsoft Office-dokumente kom gewoonlik voor as ouer formate soos RTF en OLE/CFBF-gebaseerde DOC, XLS en PPT, of as nuwer **Office Open XML (OOXML)**-formate soos DOCX, XLSX en PPTX. Office-dokumente kan aktiewe inhoud soos makro’s bevat, wat hulle algemene draers van phishing en malware maak. OOXML-lêers is ZIP-houers waarvan die lêerhiërargie en XML-inhoud ondersoek kan word deur hulle uit te pak.<sup>[[3]](#references)[[4]](#references)</sup>

Die opdrag om ’n dokument uit te pak en die uitvoerstruktuur word gegee om OOXML-lêerstrukture te verken. Tegnieke om data in hierdie lêers weg te steek, is gedokumenteer, wat dui op voortdurende innovasie in die versteek van data binne CTF-uitdagings.<sup>[[4]](#references)</sup>

Vir ontleding bied **oletools** en **OfficeDissector** omvattende gereedskapstelle om beide OLE- en OOXML-dokumente te ondersoek. Hierdie gereedskap help om ingebedde makro’s te identifiseer en te ontleed, wat dikwels as afleweringsvektore vir malware dien en gewoonlik bykomende kwaadwillige loonvragte aflaai en uitvoer. VBA-makro’s kan ontleed word sonder Microsoft Office deur LibreOffice te gebruik, wat ontfouting met breekpunte en dophouveranderlikes moontlik maak.<sup>[[4]](#references)</sup>

Die installering en gebruik van **oletools** is eenvoudig, met opdragte wat gegee word om dit via pip te installeer en makro’s uit dokumente te onttrek. In Word sluit outomatiese makro’s `AutoExec` en `AutoOpen` in, terwyl `Document_Open` ’n oopgebeurtenisprosedure is.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Vir wagwoord-geënkripteerde Office-dokumente, sien die [grammatika-gedrewe offline-herstelwerkvloei](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## OLE Compound File-uitbuiting: Autodesk Revit RFA – ECC-herberekening en beheerde gzip

Revit RFA-modelle word as ’n [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (ook bekend as CFBF) gestoor. Die geserialiseerde model is in die volgende storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Uitleg van `Global\Latest` (waargeneem in Revit 2025):

- Header
- GZIP-saamgepersde payload (die werklike geserialiseerde objekgrafiek)
- Nul-opvulling
- Error-Correcting Code (ECC)-voetskrif

Revit herstel klein veranderings aan die stream outomaties met die ECC-voetskrif en verwerp streams wat nie met die ECC ooreenstem nie. Daarom sal wysigings aan die saamgepersde grepe op ’n naïewe manier nie behoue bly nie: jou veranderinge word óf teruggedraai óf die lêer word verwerp. Om byte-akkurate beheer te verseker oor wat die deserialiseerder sien, moet jy:<sup>[[1]](#references)</sup>

- Her-saampers met ’n Revit-versoenbare gzip-implementering (sodat die saamgepersde grepe wat Revit produseer/aanvaar ooreenstem met wat dit verwag).
- Die ECC-voetskrif oor die opgevulde stream herbereken sodat Revit die gewysigde stream aanvaar sonder om dit outomaties te herstel.

Praktiese werkvloei om RFA-inhoud te patch/fuzz:<sup>[[1]](#references)</sup>

1) Vou die OLE-saamgestelde dokument uit.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Wysig `Global/Latest` met gzip/ECC-dissipline

- Ontleed `Global/Latest`: behou die kopskrif, gunzip die payload, wysig grepe en gzip dit dan weer met Revit-versoenbare deflate-parameters.
- Behou nul-opvulling en herbereken die ECC-sleepstuk sodat Revit die nuwe grepe aanvaar.
- As jy deterministiese reproduksie byte vir byte nodig het, bou ’n minimale omhulsel om Revit se DLL’s om die gzip/gunzip-paaie en ECC-berekening aan te roep (soos in navorsing gedemonstreer), of hergebruik enige beskikbare helper wat hierdie semantiek naboots.

3) Herbou die OLE-saamgestelde dokument.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool skryf storages/streams na die lêerstelsel, met escaping vir karakters wat ongeldig is in NTFS-name; die stream-pad wat jy soek, is presies `Global/Latest` in die uitvoerboom.
- Wanneer jy massa-aanvalle lewer via ekosisteem-inproppe wat RFA’s vanaf wolkberging ophaal, maak seker dat jou aangepaste RFA Revit se integriteitskontroles plaaslik slaag (gzip/ECC korrek) voordat jy netwerkinspuiting probeer.

Exploit-insig (om te bepaal watter grepe in die gzip-payload geplaas moet word):<sup>[[1]](#references)</sup>

- Die Revit-deserialiseerder lees ’n 16-bis-klasindeks en skep ’n objek. Sekere tipes is nie-polimorfies en het nie vtables nie; misbruik van destructor-hantering veroorsaak ’n tipeverwarring waar die enjin ’n indirekte oproep deur ’n aanvallerbeheerde wyser uitvoer.
- Deur `AString` (klasindeks `0x1F`) te kies, word ’n aanvallerbeheerde heap-wyser by objekverskuiwing 0 geplaas. Tydens die destructor-lus voer Revit in wese die volgende uit:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Plaas verskeie sulke objekte in die geserialiseerde grafiek sodat elke iterasie van die destructor-lus een gadget (“weird machine”) uitvoer, en rangskik ’n stack pivot na ’n konvensionele x64 ROP-ketting.

Sien besonderhede oor Windows x64-pivot/gadget-bou hier:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

en algemene ROP-riglyne hier:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Gereedskap:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) om OLE-saamgestelde lêers uit te brei/herbou: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD vir omgekeerde analise/taint-analise; deaktiveer page heap met TTD om spore kompak te hou.
- ’n Plaaslike proxy (bv. Fiddler) kan supply-chain-aflewering simuleer deur RFA’s in plugin-verkeer om te ruil vir toetsing.

## References

- [1] [Bou van ’n volledige RCE-exploit vanaf ’n crash tydens die ontleding van ’n Autodesk Revit RFA-lêer (ZDI-blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE-saamgestelde lêer (CFBF)-dokumentasie](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF-veldgids](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba-dokumentasie (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Outo-makro’s (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open-gebeurtenis (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
