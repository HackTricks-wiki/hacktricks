# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}


Kwa maelezo zaidi, angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Microsoft imeunda miundo mingi ya hati za office, ambapo aina kuu mbili ni **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Miundo hii inaweza kujumuisha macros, hivyo kuwa malengo ya phishing na malware. Faili za OOXML zimeundwa kama zip containers, zinazoruhusu ukaguzi kwa kuzifungua kwa unzip, na kufichua mpangilio wa faili na folda pamoja na maudhui ya faili za XML.

Ili kuchunguza miundo ya faili za OOXML, command ya kufungua document kwa unzip na muundo wa output imetolewa. Mbinu za kuficha data ndani ya faili hizi zimeandikwa, zikionyesha ubunifu unaoendelea katika kuficha data ndani ya CTF challenges.

Kwa ajili ya analysis, **oletools** na **OfficeDissector** hutoa toolsets pana za kuchunguza documents za OLE na OOXML. Tools hizi husaidia kutambua na kuchambua macros zilizopachikwa, ambazo mara nyingi hutumika kama vectors za kupeleka malware, kwa kawaida kwa kupakua na ku-execute malicious payloads za ziada. Analysis ya VBA macros inaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, inayoruhusu debugging kwa kutumia breakpoints na watch variables.

Installation na matumizi ya **oletools** ni rahisi, huku commands zikitolewa kwa ajili ya kui-install kupitia pip na kutoa macros kutoka kwenye documents. Automatic execution ya macros huchochewa na functions kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Utumiaji wa OLE Compound File: Autodesk Revit RFA – ECC recomputation na gzip inayodhibitiwa

Miundo ya Revit RFA huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserializwa iko chini ya storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (ulioonekana kwenye Revit 2025):

- Header
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserializwa)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia ECC trailer, na itakataa streams ambazo hazilingani na ECC. Kwa hiyo, kuhariri bytes zilizobanwa moja kwa moja hakutadumu: mabadiliko yako ama yatabadilishwa au file itakataliwa. Ili kuhakikisha udhibiti sahihi wa bytes ambazo deserializer itaona, lazima:

- Ubanze tena kwa kutumia gzip implementation inayooana na Revit (ili compressed bytes zinazotengenezwa/kukubaliwa na Revit zilingane na inachotarajia).
- Uhesabu tena ECC trailer juu ya stream iliyopatiwa padding ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Workflow ya kutekeleza patching/fuzzing ya RFA contents:<sup>[[1]](#references)</sup>

1) Panua OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa nidhamu ya gzip/ECC

- Vunja `Global/Latest`: hifadhi header, gunzip payload, badilisha bytes, kisha gzip tena ukitumia vigezo vya deflate vinavyooana na Revit.
- Hifadhi zero-padding na ukokotoe upya ECC trailer ili bytes mpya zikubaliwe na Revit.
- Ikiwa unahitaji reproduction ya byte-for-byte yenye determinism, tengeneza wrapper ndogo inayozunguka DLLs za Revit ili kuita njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa kwenye research), au tumia tena helper yoyote inayorudia semantics hizi.

3) Jenga upya OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye filesystem kwa kutumia escaping kwa herufi zisizokubalika katika majina ya NTFS; stream path unayotaka ni `Global/Latest` haswa katika output tree.
- Unapowasilisha mass attacks kupitia ecosystem plugins zinazochukua RFAs kutoka cloud storage, hakikisha RFA yako iliyorekebishwa inapita ukaguzi wa integrity wa Revit ndani ya mfumo kwanza (gzip/ECC zikiwa sahihi) kabla ya kujaribu network injection.

Exploitation insight (ili kuelekeza bytes za kuweka kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma 16-bit class index na huunda object. Aina fulani si za polymorphic na hazina vtables; kutumia vibaya utunzaji wa destructor husababisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na attacker.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na attacker kwenye object offset 0. Wakati wa destructor loop, Revit hutekeleza kwa ufanisi:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka objects nyingi kama hizo katika graph iliyoserializwa ili kila iteration ya destructor loop itekeleze gadget moja (“weird machine”), na panga stack pivot kuingia kwenye conventional x64 ROP chain.

Tazama maelezo ya Windows x64 pivot/gadget building hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

na mwongozo wa jumla wa ROP hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) ya kupanua/kujenga upya OLE compound files: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap ukitumia TTD ili traces zibaki fupi.
- Local proxy (kwa mfano, Fiddler) inaweza kuiga supply-chain delivery kwa kubadilisha RFAs katika plugin traffic kwa ajili ya testing.

## Marejeo

- [1] [Kutengeneza Full Exploit RCE kutokana na Crash katika Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
