# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo zaidi, angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Nyaraka za Microsoft Office kwa kawaida huonekana kama formats za zamani kama RTF na DOC, XLS, na PPT zenye msingi wa OLE/CFBF, au kama formats mpya za **Office Open XML (OOXML)** kama DOCX, XLSX, na PPTX. Nyaraka za Office zinaweza kuwa na active content kama macros, jambo linalozifanya kuwa carriers wa kawaida wa phishing na malware. Faili za OOXML ni ZIP containers ambazo file hierarchy na XML contents zake zinaweza kukaguliwa kwa kuzifungua kwa unzip.<sup>[[3]](#references)[[4]](#references)</sup>

Ili kuchunguza miundo ya faili za OOXML, amri ya kufungua document kwa unzip na output structure zimetolewa. Techniques za kuficha data katika faili hizi zimeandikwa, zikionyesha ubunifu unaoendelea katika kuficha data ndani ya CTF challenges.<sup>[[4]](#references)</sup>

Kwa uchanganuzi, **oletools** na **OfficeDissector** hutoa toolsets kamili za kuchunguza nyaraka za OLE na OOXML. Tools hizi husaidia kutambua na kuchanganua embedded macros, ambazo mara nyingi hutumiwa kama vectors za kuwasilisha malware, kwa kawaida zikidownload na kutekeleza malicious payloads za ziada. Uchanganuzi wa VBA macros unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, inayowezesha debugging kwa kutumia breakpoints na watch variables.<sup>[[4]](#references)</sup>

Installation na matumizi ya **oletools** ni rahisi, huku commands zikitolewa kwa ajili ya kusakinisha kupitia pip na kutoa macros kutoka kwenye documents. Katika Word, automatic macros zinajumuisha `AutoExec` na `AutoOpen`, huku `Document_Open` ikiwa open-event procedure.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation ya OLE Compound File: Autodesk Revit RFA – ECC recomputation na controlled gzip

Miundo ya Revit RFA huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserializwa iko chini ya storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (ulionekana kwenye Revit 2025):

- Kichwa
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserializwa)
- Padding ya zero
- Trailer ya Error-Correcting Code (ECC)

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia trailer ya ECC na itakataa streams ambazo hazilingani na ECC. Kwa hiyo, kuhariri bytes zilizobanwa moja kwa moja hakutadumu: mabadiliko yako yatarejeshwa au faili itakataliwa. Ili kuhakikisha udhibiti sahihi wa bytes juu ya kile ambacho deserializer itaona, lazima:<sup>[[1]](#references)</sup>

- Ucompress tena kwa kutumia implementation ya gzip inayoendana na Revit (ili bytes zilizobanwa zinazozalishwa/kukubaliwa na Revit zilingane na inachotarajiwa).
- Uhesabu tena trailer ya ECC juu ya stream iliyo na padding ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Mtiririko wa vitendo wa kupatch/fuzz RFA contents:<sup>[[1]](#references)</sup>

1) Panua OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Hariri `Global\Latest` kwa kufuata taratibu za gzip/ECC

- Vunja `Global/Latest`: hifadhi header, tumia gunzip kwenye payload, badilisha bytes, kisha tumia gzip tena kwa kutumia vigezo vya deflate vinavyooana na Revit.
- Hifadhi zero-padding na ukokote upya trailer ya ECC ili bytes mpya zikubalike na Revit.
- Ikiwa unahitaji reproduction ya deterministic byte-for-byte, tengeneza wrapper ndogo karibu na DLL za Revit ili kuita njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa kwenye utafiti), au tumia tena helper yoyote inayorudia semantics hizi.

3) Jenga upya OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye filesystem kwa kutumia escaping kwa characters zisizokubalika katika majina ya NTFS; stream path unayoitaka ni `Global/Latest` haswa katika output tree.
- Unapowasilisha mass attacks kupitia ecosystem plugins zinazopakua RFAs kutoka cloud storage, hakikisha RFA yako iliyopatchiwa inapita integrity checks za Revit locally kwanza (gzip/ECC zikiwa sahihi) kabla ya kujaribu network injection.

Exploitation insight (ya kuongoza ni bytes gani ziwekwe kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma 16-bit class index na huunda object. Aina fulani si non‑polymorphic na hazina vtables; kutumia vibaya destructor handling husababisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na attacker.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na attacker kwenye object offset 0. Wakati wa destructor loop, Revit hutekeleza kwa ufanisi:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Weka objects nyingi kama hizi katika serialized graph ili kila iteration ya destructor loop itekeleze gadget moja (“weird machine”), na panga stack pivot kuingia kwenye conventional x64 ROP chain.

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
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap ukitumia TTD ili traces zibaki fupi.
- Local proxy (k.m., Fiddler) inaweza kuiga supply-chain delivery kwa kubadilisha RFAs katika plugin traffic kwa ajili ya testing.

## References

- [1] [Kutengeneza Full Exploit RCE kutokana na Crash katika Uchanganuzi wa Autodesk Revit RFA File (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Mwongozo wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
