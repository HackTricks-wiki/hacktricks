# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}


Kwa maelezo zaidi angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Microsoft imeunda miundo mingi ya hati za office, huku aina kuu mbili zikiwa **OLE formats** (kama RTF, DOC, XLS, PPT) na **Office Open XML (OOXML) formats** (kama DOCX, XLSX, PPTX). Miundo hii inaweza kujumuisha macros, hivyo kuwa malengo ya phishing na malware. Faili za OOXML zimeundwa kama zip containers, hivyo kuruhusu ukaguzi kupitia kuzifungua kwa unzip, jambo linalofichua mpangilio wa faili na folda pamoja na maudhui ya faili za XML.

Ili kuchunguza miundo ya faili za OOXML, command ya kufungua document kwa unzip pamoja na muundo wa output imetolewa. Mbinu za kuficha data ndani ya faili hizi zimeandikwa, jambo linaloonyesha ubunifu unaoendelea katika ufichaji wa data ndani ya CTF challenges.

Kwa ajili ya analysis, **oletools** na **OfficeDissector** hutoa toolsets pana za kuchunguza documents za OLE na OOXML. Tools hizi husaidia kutambua na kuchanganua macros zilizopachikwa, ambazo mara nyingi hutumika kama vectors za kusambaza malware, kwa kawaida kwa kupakua na kutekeleza malicious payloads za ziada. Analysis ya VBA macros inaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, inayoruhusu debugging kwa kutumia breakpoints na watch variables.

Installation na matumizi ya **oletools** ni rahisi, huku commands zikitolewa kwa ajili ya kusakinisha kupitia pip na kutoa macros kutoka kwenye documents. Automatic execution ya macros huchochewa na functions kama `AutoOpen`, `AutoExec`, au `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Unyonyaji wa OLE Compound File: Autodesk Revit RFA – ECC recomputation na controlled gzip

Revit RFA models huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserialishwa iko chini ya storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (uliobainika kwenye Revit 2025):

- Kichwa
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserialishwa)
- Padding ya zero
- ECC trailer

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia ECC trailer na itakataa streams ambazo hazilingani na ECC. Kwa hivyo, kuhariri bytes zilizobanwa bila mpangilio hakutadumu: mabadiliko yako yatarejeshwa au file itakataliwa. Ili kuhakikisha udhibiti sahihi wa byte juu ya kile ambacho deserializer itaona, lazima:

- Ubanie tena kwa kutumia gzip implementation inayooana na Revit (ili bytes zilizobanwa zinazozalishwa/kukubaliwa na Revit zilingane na inachotarajia).
- Uhesabu upya ECC trailer kwenye stream yenye padding ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Workflow ya kivitendo ya kupatch/fuzz RFA contents:<sup>[[1]](#references)</sup>

1) Panua OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa kufuata kanuni za gzip/ECC

- Vunja `Global/Latest`: hifadhi header, gunzip payload, badilisha bytes, kisha gzip tena ukitumia deflate parameters zinazoendana na Revit.
- Hifadhi zero-padding na uhesabu upya ECC trailer ili bytes mpya zikubaliwe na Revit.
- Ikiwa unahitaji reproduction ya deterministic byte-for-byte, unda wrapper ndogo kuzunguka Revit’s DLLs ili kuita njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa kwenye research), au tumia helper inayopatikana inayorudia semantics hizi.

3) Unda upya OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Maelezo:<sup>[[1]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye filesystem kwa kutumia escaping kwa herufi zisizokubalika katika majina ya NTFS; stream path unayoihitaji ni `Global/Latest` hasa katika output tree.
- Unapowasilisha mass attacks kupitia ecosystem plugins zinazochukua RFAs kutoka cloud storage, hakikisha RFA yako iliyopatchiwa inapita integrity checks za Revit locally kwanza (gzip/ECC ziko sahihi) kabla ya kujaribu network injection.

Ufahamu wa exploitation (wa kuongoza ni bytes zipi za kuweka kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma class index ya biti 16 na huunda object. Aina fulani si za polymorphic na hazina vtables; kutumia vibaya destructor handling husababisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na attacker.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na attacker katika object offset 0. Wakati wa destructor loop, Revit kimsingi hutekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka vitu vingi kama hivyo kwenye graph iliyoserializwa ili kila iteration ya destructor loop itekeleze gadget moja (“weird machine”), kisha panga stack pivot kuingia kwenye conventional x64 ROP chain.

Angalia maelezo ya Windows x64 pivot/gadget building hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

na mwongozo wa jumla wa ROP hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) ya kupanua/kutengeneza upya OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap ukitumia TTD ili traces zibaki fupi.
- Local proxy (kwa mfano, Fiddler) inaweza kuiga supply-chain delivery kwa kubadilisha RFAs kwenye plugin traffic kwa ajili ya testing.

## Marejeo

- [1] [Kutengeneza Full Exploit RCE kutokana na Crash katika Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Nyaraka za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Mwongozo wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
