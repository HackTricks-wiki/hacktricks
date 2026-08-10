# Uchambuzi wa faili za Office

Kwa maelezo zaidi, angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Nyaraka za Microsoft Office kwa kawaida huonekana kama formats za zamani kama RTF na DOC, XLS, na PPT zinazotegemea OLE/CFBF, au kama formats mpya za **Office Open XML (OOXML)** kama DOCX, XLSX, na PPTX. Nyaraka za Office zinaweza kuwa na active content kama macros, hivyo ni carriers za kawaida za phishing na malware. Faili za OOXML ni ZIP containers ambazo file hierarchy na XML contents zake zinaweza kuchunguzwa kwa kuzifungua kwa unzip.<sup>[[3]](#references)[[4]](#references)</sup>

Ili kuchunguza miundo ya faili za OOXML, command ya kufungua document kwa unzip pamoja na output structure imetolewa. Techniques za kuficha data ndani ya faili hizi zimeandikwa, jambo linaloonyesha ubunifu unaoendelea katika kuficha data ndani ya CTF challenges.<sup>[[4]](#references)</sup>

Kwa analysis, **oletools** na **OfficeDissector** hutoa toolsets pana za kuchunguza nyaraka za OLE na OOXML. Tools hizi husaidia kutambua na kuchanganua macros zilizopachikwa, ambazo mara nyingi hutumiwa kama vectors za kusambaza malware, kwa kawaida kwa kupakua na kutekeleza malicious payloads za ziada. Analysis ya VBA macros inaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo huruhusu debugging kwa kutumia breakpoints na watch variables.<sup>[[4]](#references)</sup>

Installation na matumizi ya **oletools** ni rahisi, huku commands zikitolewa kwa ajili ya kusakinisha kupitia pip na kutoa macros kutoka kwenye documents. Katika Word, automatic macros zinajumuisha `AutoExec` na `AutoOpen`, huku `Document_Open` ikiwa ni open-event procedure.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Unyonyaji wa OLE Compound File: Autodesk Revit RFA – uhesabuji upya wa ECC na gzip inayodhibitiwa

Miundo ya Revit RFA huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserialishwa iko chini ya storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (ulionekana kwenye Revit 2025):

- Kichwa
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserialishwa)
- Padding ya sifuri
- Trailer ya Error-Correcting Code (ECC)

Revit itajikarabati kiotomatiki inapobaini mabadiliko madogo kwenye stream kwa kutumia trailer ya ECC, na itakataa streams zisizolingana na ECC. Kwa hivyo, kuhariri bytes zilizobanwa moja kwa moja hakutadumu: mabadiliko yako yanaweza kurejeshwa au faili kukataliwa. Ili kuhakikisha udhibiti sahihi wa bytes ambazo deserializer itaona, lazima:<sup>[[1]](#references)</sup>

- Ubanishe tena kwa kutumia gzip implementation inayooana na Revit (ili bytes zilizobanwa zinazozalishwa/kubaliwa na Revit zilingane na inachotarajia).
- Uhesabu upya trailer ya ECC juu ya stream iliyopakiwa padding, ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Mtiririko wa vitendo wa kupachika marekebisho au kufanya fuzzing ya maudhui ya RFA:<sup>[[1]](#references)</sup>

1) Panua OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri Global\Latest kwa kuzingatia gzip/ECC

- Vunja `Global/Latest`: hifadhi header, gunzip payload, badilisha bytes, kisha gzip tena ukitumia vigezo vya deflate vinavyoendana na Revit.
- Hifadhi zero-padding na ukokote upya trailer ya ECC ili bytes mpya zikubaliwe na Revit.
- Ikiwa unahitaji reproduction ya bytes kwa usahihi na kwa namna ileile kila mara, tengeneza wrapper ndogo inayozunguka DLL za Revit ili kuita njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa katika utafiti), au tumia tena helper yoyote inayorudia semantics hizi.

3) Jenga upya OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Maelezo:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye filesystem huku ikitumia escaping kwa herufi zisizoruhusiwa katika majina ya NTFS; stream path unayotaka ni hasa `Global/Latest` kwenye output tree.
- Unapowasilisha mass attacks kupitia ecosystem plugins zinazochukua RFAs kutoka cloud storage, hakikisha RFA yako iliyopatchiwa inapita kwanza ukaguzi wa integrity wa Revit locally (gzip/ECC sahihi) kabla ya kujaribu network injection.

Ufahamu wa exploitation (wa kuongoza ni bytes zipi ziwekwe kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma class index ya biti 16 na kuunda object. Aina fulani si za polymorphic na hazina vtables; kutumia vibaya utunzaji wa destructor husababisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na attacker.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na attacker kwenye object offset 0. Wakati wa destructor loop, Revit kwa ufanisi hutekeleza:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka objects nyingi kama hizi kwenye serialized graph ili kila iteration ya destructor loop itekeleze gadget moja (“weird machine”), kisha panga stack pivot kuingia kwenye conventional x64 ROP chain.

Maelezo ya kujenga Windows x64 pivot/gadget yanapatikana hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

na mwongozo wa jumla wa ROP unapatikana hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) ya kupanua/kutengeneza upya OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap kwa TTD ili kuweka traces zikiwa fupi.
- Local proxy (kwa mfano, Fiddler) inaweza kuiga supply-chain delivery kwa kubadilisha RFAs kwenye plugin traffic kwa ajili ya testing.

## References

- [1] [Kutengeneza Full Exploit RCE kutokana na Crash katika Uchanganuzi wa Autodesk Revit RFA File (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
