# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}


Kwa taarifa zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda miundo mingi ya nyaraka za Office, ikiwa na aina mbili kuu kuwa **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Miundo hii inaweza kujumuisha macros, na hivyo kuwa malengo ya phishing na malware. Faili za OOXML zimepangwa kama makontena ya zip, kuruhusu ukaguzi kwa kuzipu, ikifichua muundo wa faili na folda pamoja na yaliyomo ya faili za XML.

Ili kuchunguza miundo ya faili za OOXML, amri ya kuunzip nyaraka na muundo wa matokeo zinatolewa. Mbinu za kuficha data ndani ya faili hizi zimeelezewa, zikionyesha uvumbuzi unaoendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** zinatoa seti za zana za kina kwa kuchunguza nyaraka za OLE na OOXML. Zana hizi husaidia kutambua na kuchambua macros zilizojengwa ndani, ambazo mara nyingi hutumika kama vektori vya utoaji wa malware, kawaida kupakua na kutekeleza mizigo mbaya ya ziada. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu debugging kwa breakpoints na watch variables.

Ufungaji na matumizi ya **oletools** ni rahisi, na amri zinatolewa kwa kufunga kupitia pip na kuchukua macros kutoka kwa nyaraka. Utekelezaji otomatiki wa macros unachochewa na functions kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Utekelezaji wa OLE Compound File: Autodesk Revit RFA – upya-hesabu wa ECC na gzip iliyodhibitiwa

Revit RFA models zimehifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Mpangilio muhimu wa `Global\Latest` (uliyoonekana kwenye Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit itafanya matengenezo ya moja kwa moja kwa mabadiliko madogo kwenye stream kwa kutumia trailer ya ECC na itakataa streams ambazo hazilingani na ECC. Kwa hivyo, kuhariri kwa kawaida baiti zilizokandamizwa hakutadumu: mabadiliko yako yatafutwa au faili itakataliwa. Ili kuhakikisha udhibiti wa usahihi wa baiti juu ya kile deserializer inaona lazima:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Mtiririko wa vitendo kwa patching/fuzzing ya yaliyomo ya RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa utaratibu wa gzip/ECC

- Changanua `Global/Latest`: hifadhi header, gunzip payload, badilisha bytes, kisha gzip tena ukitumia vigezo vya deflate vinavyolingana na Revit.
- Hifadhi zero-padding na rekebisha tena ECC trailer ili bytes mpya zikubaliwe na Revit.
- Ikiwa unahitaji deterministic byte-for-byte reproduction, jenga minimal wrapper karibu na Revit’s DLLs ili invoke njia zake za gzip/gunzip na ECC computation (kama ilivyoonyeshwa katika tafiti), au tumia tena helper yoyote inayopatikana inayorudia semantics hizi.

3) Jenga upya OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Vidokezo:

- CompoundFileTool huandika storages/streams kwenye mfumo wa faili na kufanya escaping kwa herufi zisizo halali katika majina ya NTFS; njia ya stream unayotaka ni hasa `Global/Latest` kwenye mti wa output.
- Unapotoa mashambulizi kwa wingi kupitia plugins za ecosystem zinazopakua RFAs kutoka cloud storage, hakikisha RFA yako iliyorekebishwa inapita ukaguzi wa integriti wa Revit lokalini kwanza (gzip/ECC sahihi) kabla ya kujaribu kuingiza mtandaoni.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit deserializer husoma 16-bit class index na kujenga object. Aina fulani ni non‑polymorphic na hazina vtables; kutumia destructor handling husababisha type confusion ambapo engine inatekeleza indirect call kupitia attacker-controlled pointer.
- Kuchagua `AString` (class index `0x1F`) kunaweka attacker-controlled heap pointer kwenye object offset 0. Wakati wa destructor loop, Revit kwa ufanisi inatekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka vitu vingi vya aina hiyo katika grafu iliyoseriwalishwa ili kila iteresheni ya destructor loop itekeleze gadget moja (“weird machine”), na panga stack pivot kuelekea katika conventional x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) kwa ajili ya kupanua/kujenga upya OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD kwa ajili ya reverse/taint; ondoa page heap wakati wa TTD ili kuweka traces kuwa ndogo.
- Proxy ya ndani (mf., Fiddler) inaweza kuiga utoaji wa supply-chain kwa kubadilisha RFAs katika trafiki ya plugin kwa ajili ya majaribio.

## Marejeo

- [Kuunda Full Exploit RCE kutoka kwa Crash katika Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [Nyaraka za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
