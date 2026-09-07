# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Nyaraka za Microsoft Office mara nyingi huonekana kama formats za zamani kama RTF na DOC, XLS, na PPT zinazotegemea OLE/CFBF, au kama formats mpya za **Office Open XML (OOXML)** kama DOCX, XLSX, na PPTX. Nyaraka za Office zinaweza kuwa na maudhui amilifu kama macros, hivyo kuwa njia za kawaida za phishing na malware. Faili za OOXML ni ZIP containers ambazo file hierarchy na XML contents zake zinaweza kuchunguzwa kwa kuzifungua kwa unzip.<sup>[[3]](#references)[[4]](#references)</sup>

Ili kuchunguza miundo ya faili za OOXML, command ya kufungua document kwa unzip pamoja na output structure vimetolewa. Techniques za kuficha data katika faili hizi zimeandikwa, zikionyesha ubunifu unaoendelea katika kuficha data ndani ya CTF challenges.<sup>[[4]](#references)</sup>

Kwa analysis, **oletools** na **OfficeDissector** hutoa toolsets pana za kuchunguza documents za OLE na OOXML. Tools hizi husaidia kutambua na kuchanganua macros zilizopachikwa, ambazo mara nyingi hutumika kama vectors za kuwasilisha malware, kwa kawaida zikidownload na kuexecute malicious payloads za ziada. Analysis ya VBA macros inaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, inayoruhusu debugging kwa breakpoints na watch variables.<sup>[[4]](#references)</sup>

Installation na matumizi ya **oletools** ni rahisi, huku commands za kuinstall kupitia pip na kutoa macros kutoka kwenye documents zikitolewa. Katika Word, automatic macros zinajumuisha `AutoExec` na `AutoOpen`, huku `Document_Open` ikiwa open-event procedure.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Kwa nyaraka za Office zilizosimbwa kwa password, tazama [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Udukuzi wa OLE Compound File: Autodesk Revit RFA – ECC recomputation na controlled gzip

Miundo ya Revit RFA huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserialishwa iko chini ya storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (ulionekana kwenye Revit 2025):

- Kichwa
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserialishwa)
- Padding yenye zero
- ECC trailer

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia ECC trailer na itakataa streams ambazo haziendani na ECC. Kwa hiyo, kuhariri compressed bytes moja kwa moja hakutadumu: mabadiliko yako yatabadilishwa au faili itakataliwa. Ili kuhakikisha udhibiti sahihi wa bytes za kile ambacho deserializer itaona, lazima:<sup>[[1]](#references)</sup>

- Ubanishe tena kwa kutumia gzip implementation inayoendana na Revit (ili compressed bytes ambazo Revit inazalisha/kukubali zilingane na inachotarajia).
- Uhesabu upya ECC trailer juu ya stream yenye padding ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Workflow ya vitendo ya kupatch/kufuzz RFA contents:<sup>[[1]](#references)</sup>

1) Panua OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa kufuata utaratibu wa gzip/ECC

- Chambua `Global/Latest`: hifadhi header, tumia gunzip kwenye payload, badilisha bytes, kisha tumia gzip tena kwa vigezo vya deflate vinavyooana na Revit.
- Hifadhi zero-padding na uhesabu upya trailer ya ECC ili bytes mpya zikubalike na Revit.
- Ikiwa unahitaji uzalishaji unaoweza kurudiwa wa byte kwa byte, tengeneza wrapper ndogo inayotumia DLL za Revit kuendesha njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa kwenye utafiti), au tumia tena helper yoyote inayorudia semantics hizi.

3) Unda upya hati ya OLE compound.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye mfumo wa faili kwa kutumia escaping kwa herufi zisizokubalika katika majina ya NTFS; stream path unayotaka ni `Global/Latest` hasa katika output tree.
- Unapowasilisha mass attacks kupitia ecosystem plugins zinazopakua RFA kutoka cloud storage, hakikisha RFA yako iliyorekebishwa inapita ukaguzi wa integrity wa Revit locally kwanza (gzip/ECC ikiwa sahihi) kabla ya kujaribu network injection.

Exploitation insight (ya kuongoza ni bytes zipi za kuweka kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma 16-bit class index na kuunda object. Aina fulani si polymorphic na hazina vtables; kutumia vibaya utunzaji wa destructor huzalisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na attacker.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na attacker kwenye object offset 0. Wakati wa destructor loop, Revit kimsingi hutekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka objects kama hizi nyingi kwenye serialized graph ili kila iteration ya destructor loop itekeleze gadget moja (“weird machine”), na panga stack pivot iingie kwenye conventional x64 ROP chain.

Angalia maelezo ya Windows x64 pivot/gadget building hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

na mwongozo wa jumla wa ROP hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) ya kupanua/kutengeneza upya OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap kwa TTD ili kuweka traces katika ukubwa mdogo.
- Local proxy (kwa mfano, Fiddler) inaweza kuiga supply-chain delivery kwa kubadilisha RFAs katika plugin traffic kwa ajili ya testing.

## References

- [1] [Kutengeneza Full Exploit RCE kutokana na Crash katika Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Nyaraka za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Mwongozo wa Forensics CTF Field](https://trailofbits.github.io/ctf/forensics/)
- [5] [Nyaraka za olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
