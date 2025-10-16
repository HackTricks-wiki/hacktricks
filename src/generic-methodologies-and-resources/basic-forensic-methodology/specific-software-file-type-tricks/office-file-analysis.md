# Uchambuzi wa mafaili ya Office

{{#include ../../../banners/hacktricks-training.md}}


Kwa habari zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Hii ni muhtasari tu:

Microsoft imeunda miundo mingi ya hati za Office, aina kuu mbili ikiwa ni **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Miundo hii inaweza kujumuisha macros, kufanya iwe lengo la phishing na malware. Faili za OOXML zimepangwa kama zip containers, zikiruhusu ukaguzi kwa kuzipu, kuonyesha muundo wa faili na folda pamoja na yaliyomo ya faili za XML.

Ili kuchunguza muundo wa faili za OOXML, amri ya ku-unzip hati na muundo wa matokeo yameonyeshwa. Mbinu za kuficha data kwenye faili hizi zimeandikwa, zikionyesha uvumbuzi unaoendelea katika kuficha data ndani ya changamoto za CTF.

Kwa uchambuzi, **oletools** na **OfficeDissector** zinatoa seti kamili za zana za kuchambua hati za OLE na OOXML. Zana hizi husaidia kubaini na kuchambua macros zilizojazwa, ambazo mara nyingi hutumika kama vektori vya delivery ya malware, kwa kawaida kupakua na kutekeleza payloads za ziada zenye madhara. Uchambuzi wa VBA macros unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo inaruhusu debugging kwa breakpoints na watch variables.

Ufungaji na matumizi ya **oletools** ni rahisi, na amri zimewekwa kwa ajili ya kusanidi kupitia pip na kutoa macros kutoka kwa hati. Utekelezaji wa moja kwa moja wa macros unasababishwa na functions kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Modeli za Revit RFA zimehifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia inajulikana kama CFBF). Mfano ulioserialized upo chini ya storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Mpangilio muhimu wa `Global\Latest` (ulioonekana kwenye Revit 2025):

- Kichwa
- Payload iliyobanwa kwa GZIP (grafu ya vitu iliyoserialized kwa kweli)
- Padding ya sifuri
- Trailer ya Error-Correcting Code (ECC)

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia trailer ya ECC na itakataa streams ambazo hazilingani na ECC. Kwa hiyo, kuhariri kwa ujinga bytes zilizobanwa haitadumu: mabadiliko yako yatawekwa nyuma au faili itakataliwa. Ili kuhakikisha udhibiti sahihi kwa kila byte juu ya kile deserializer kinachosoma lazima:

- Fanya recompress kwa kutumia utekelezaji wa gzip unaoendana na Revit (ili bytes zilizobanwa ambazo Revit inazalisha/inakubali ziwe sawa na anavyotarajia).
- Hesabu tena trailer ya ECC juu ya stream iliyopandishwa ili Revit ikubali stream iliyobadilishwa bila kuirekebisha kiotomatiki.

Mtiririko wa kazi wa vitendo kwa ajili ya patching/fuzzing ya yaliyomo ya RFA:

1) Panua nyaraka za OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa kanuni za gzip/ECC

- Vunja `Global/Latest`: hifadhi header, fanya gunzip kwa payload, badilisha bytes, kisha gzip tena ukitumia parameta za deflate zinazolingana na Revit.
- Hifadhi zero-padding na hesabisha upya ECC trailer ili bytes mpya ziruhusiwe na Revit.
- Ikiwa unahitaji uzalishaji wa byte kwa byte ulio thabiti, jenga wrapper ndogo inayozunguka DLLs za Revit ili kuita njia zake za gzip/gunzip na utekelezaji wa ECC (kama ilivyoonyeshwa katika utafiti), au tumia tena msaidizi yoyote uliopo unaorudia semaantiki hizi.

3) Jenga upya OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Maelezo:

- CompoundFileTool inaandika storages/streams kwenye filesystem kwa ku-escape characters ambazo sio halali katika majina ya NTFS; njia ya stream unayotaka ni hasa `Global/Latest` katika mti wa output.
- Unapofanya mashambulizi kwa wingi kupitia plugins za ecosystem zinazopakua RFAs kutoka cloud storage, hakikisha RFA yako iliyorekebishwa inapita ukaguzi wa uadilifu wa Revit lokal kwanza (gzip/ECC sahihi) kabla ya kujaribu network injection.

Exploitation insight (kuongoza ni bytes gani kuwekwa katika gzip payload):

- Revit deserializer inasoma 16-bit class index na kujenga object. Aina fulani ni non‑polymorphic na hazina vtables; kutumia destructor handling vibaya husababisha type confusion ambapo engine inafanya indirect call kupitia attacker-controlled pointer.
- Kuchagua `AString` (class index `0x1F`) kunaweka attacker-controlled heap pointer katika object offset 0. Wakati wa destructor loop, Revit kwa ufanisi inatekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka vitu vingi vya aina hii ndani ya grafu iliyoserialishwa ili kila iteresheni ya loop ya destructor itekeleze gadget moja (“weird machine”), na panga stack pivot ndani ya mnyororo wa kawaida wa x64 ROP.

Tazama maelezo ya kujenga Windows x64 pivot/gadget hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

na mwongozo wa jumla wa ROP hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:

- CompoundFileTool (OSS) kwa kupanua/kujenga upya OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap kwa TTD ili traces ziwe fupi.
- Proxy ya ndani (kwa mfano, Fiddler) inaweza kuiga utolewaji wa supply-chain kwa kubadilisha RFAs katika traffic ya plugin kwa ajili ya upimaji.

## Marejeo

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
