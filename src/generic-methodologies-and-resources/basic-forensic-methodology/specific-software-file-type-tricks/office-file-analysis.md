# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}


Kwa taarifa zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft ameunda aina nyingi za hati za Office, huku aina kuu mbili zikikuwa **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Faili hizi zinaweza kuwa na macros, jambo linalowafanya lengo la phishing na malware. Faili za OOXML zimeundwa kama kontena za zip, zikiyoruhusu uchunguzi kwa kuzifungua (unzip), na kuonyesha muundo wa faili na folda pamoja na yaliyomo ya faili za XML.

Ili kuchunguza miundo ya faili za OOXML, amri ya kuzipu kufungua hati na muundo wa matokeo imetolewa. Mbinu za kuficha data ndani ya faili hizi zimeandikwa, zikionyesha ubunifu unaoendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** hutoa seti kamili za zana za kuchunguza hati za OLE na OOXML. Zana hizi husaidia kubaini na kuchambua macros zilizojumuishwa, ambazo mara nyingi hutumika kama vector za usambazaji wa malware, kawaida kupakua na kutekeleza mizigo ya ziada yenye madhara. Uchambuzi wa VBA macros unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu debugging kwa kutumia breakpoints na watch variables.

Usanidi na matumizi ya **oletools** ni rahisi, na amri zimetolewa kwa kusanidi kupitia pip na kutoa macros kutoka kwa hati. Utekelezaji wa moja kwa moja wa macros unaanzishwa na functions kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – Kuhesabu tena ECC na gzip uliodhibitiwa

Modeli za Revit RFA zinahifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserialiwa iko chini ya storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Mpangilio muhimu wa `Global\Latest` (ulioonekana kwenye Revit 2025):

- Header
- GZIP-compressed payload (grafu ya vitu iliyoserialiwa halisi)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit itajirekebisha wenyewe matatizo madogo ya stream kwa kutumia ECC trailer na itakataa stream ambazo hazilingani na ECC. Kwa hivyo, kuhariri kwa ujinga byte zilizokompress hupitishi: mabadiliko yako yanarudishwa au faili inakataliwa. Ili kuhakikisha udhibiti wa byte-accurate juu ya kile deserializer inaona lazima:

- Recompress na utekelezaji wa gzip unaolingana na Revit (ili byte zilizokompress ambazo Revit hutengeneza/zinakubali ziendane na anayotegemea).
- Recompute ECC trailer juu ya stream iliyopadded ili Revit ikubali stream iliyobadilishwa bila kujirekebisha yenyewe.

Mtiririko wa vitendo kwa patching/fuzzing ya yaliyomo ya RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa nidhamu ya gzip/ECC

- Changanua `Global/Latest`: hifadhi header, gunzip payload, badilisha bytes, kisha gzip tena ukitumia Revit-compatible deflate parameters.
- Hifadhi zero-padding na hesabu upya ECC trailer ili bytes mpya zikubaliwe na Revit.
- Ikiwa unahitaji uzalishaji wa deterministiki byte-kwa-byte, jenga wrapper ndogo karibu na DLLs za Revit ili kuitisha njia zake za gzip/gunzip na uhesabu wa ECC (kama ilivyothibitishwa katika utafiti), au tumia tena msaada wowote uliopo unaorudia mantiki hizi.

3) Jenga tena OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Vidokezo:

- CompoundFileTool inaandika storages/streams kwenye mfumo wa faili na hutumia escaping kwa tabia za herufi ambazo si halali katika majina ya NTFS; njia ya stream unayotaka ni hasa `Global/Latest` kwenye mti wa pato.
- Unapotuma mashambulizi ya wingi kupitia ecosystem plugins zinazopakua RFAs kutoka cloud storage, hakikisha RFA yako iliyopachiwa inapita ukaguzi wa uadilifu wa Revit mahali hapo kwanza (gzip/ECC correct) kabla ya kujaribu network injection.

Exploitation insight (kuongoza ni bytes gani kuweka katika gzip payload):

- The Revit deserializer husoma 16-bit class index na huunda object. Aina fulani ni non‑polymorphic na hazina vtables; kutumia destructor handling husababisha type confusion ambapo engine inatekeleza indirect call kupitia attacker-controlled pointer.
- Kuchagua `AString` (class index `0x1F`) huweka attacker-controlled heap pointer katika object offset 0. Katika mzunguko wa destructor, Revit kwa ufanisi inatekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka vitu vingi vya aina hiyo katika serialized graph ili kila iteresheni ya destructor loop itekeleze gadget moja (“weird machine”), na panga stack pivot kuelekea conventional x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:

- CompoundFileTool (OSS) ili kupanua/kujenga tena OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap kwa TTD ili kuweka traces ndogo.
- Proxy ya ndani (mf., Fiddler) inaweza kuiga delivery ya supply-chain kwa kubadilisha RFAs katika plugin traffic kwa ajili ya majaribio.

## Marejeo

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
