# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo zaidi, angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[4]](#references)</sup>

Nyaraka za Microsoft Office mara nyingi hutumia miundo ya zamani kama RTF na DOC, XLS, na PPT zinazotegemea OLE/CFBF, au miundo mipya ya **Office Open XML (OOXML)** kama DOCX, XLSX, na PPTX. Nyaraka za Office zinaweza kuwa na maudhui amilifu kama macros, hivyo hutumiwa mara nyingi kusambaza phishing na malware. Faili za OOXML ni kontena za ZIP ambazo mpangilio wa faili na maudhui ya XML yanaweza kuchunguzwa kwa kuzifungua kwa unzip.<sup>[[3]](#references)[[4]](#references)</sup>

Ili kuchunguza muundo wa faili za OOXML, amri ya kufungua waraka kwa unzip na muundo wa matokeo yake vimeonyeshwa. Mbinu za kuficha data katika faili hizi zimeandikwa, jambo linaloonyesha ubunifu unaoendelea katika kuficha data kwenye changamoto za CTF.<sup>[[4]](#references)</sup>

Kwa uchanganuzi, **oletools** na **OfficeDissector** hutoa seti kamili ya zana za kuchunguza nyaraka za OLE na OOXML. Zana hizi husaidia kutambua na kuchanganua macros zilizopachikwa, ambazo mara nyingi hutumiwa kusambaza malware na kwa kawaida hupakua na kutekeleza payloads nyingine hasidi. Macros za VBA zinaweza kuchanganuliwa bila Microsoft Office kwa kutumia Libre Office, inayowezesha utatuzi kwa kutumia breakpoints na watch variables.<sup>[[4]](#references)</sup>

Kusakinisha na kutumia **oletools** ni rahisi; amri za kuisakinisha kupitia pip na kutoa macros kutoka kwenye nyaraka zimeonyeshwa. Katika Word, macros zinazojiendesha ni pamoja na `AutoExec` na `AutoOpen`, huku `Document_Open` ikiwa utaratibu wa tukio la kufungua waraka.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Kwa nyaraka za Office zilizosimbwa kwa nenosiri, angalia [mtiririko wa kazi wa urejeshaji wa offline unaoongozwa na grammar](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Unyonyaji wa OLE Compound File: Autodesk Revit RFA – kukokotoa upya ECC na gzip inayodhibitiwa

Miundo ya Revit RFA huhifadhiwa kama [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (pia huitwa CFBF). Modeli iliyoserialishwa iko chini ya storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Muundo muhimu wa `Global\Latest` (ulionekana kwenye Revit 2025):

- Header
- Payload iliyobanwa kwa GZIP (object graph halisi iliyoserialishwa)
- Zero padding
- Trela ya Error-Correcting Code (ECC)

Revit itarekebisha kiotomatiki mabadiliko madogo kwenye stream kwa kutumia trela ya ECC, na itakataa stream zisizolingana na ECC. Kwa hiyo, kuhariri tu byte zilizobanwa hakutahifadhi mabadiliko: ama mabadiliko yako yatabatilishwa au faili itakataliwa. Ili kuhakikisha udhibiti sahihi wa byte juu ya kile deserializer itakachopokea, lazima:<sup>[[1]](#references)</sup>

- Ubanie tena kwa kutumia utekelezaji wa gzip unaooana na Revit (ili byte zilizobanwa zinazozalishwa/kukubaliwa na Revit zilingane na inachotarajia).
- Ukokotoe upya trela ya ECC juu ya stream yenye padding ili Revit ikubali stream iliyorekebishwa bila kuirekebisha kiotomatiki.

Mtiririko wa kazi wa vitendo wa kurekebisha/kufuzz maudhui ya RFA:<sup>[[1]](#references)</sup>

1) Panua hati ya OLE compound.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Hariri `Global\Latest` kwa kuzingatia gzip/ECC

- Chambua `Global/Latest`: hifadhi kichwa, fungua payload kwa gunzip, badilisha byte, kisha ifunge tena kwa gzip ukitumia vigezo vya deflate vinavyoendana na Revit.
- Hifadhi padding ya sifuri na ukokotoe upya trailer ya ECC ili Revit ikubali byte mpya.
- Ikiwa unahitaji uzalishaji thabiti wa byte kwa byte, tengeneza wrapper ndogo inayotumia DLL za Revit kuita njia zake za gzip/gunzip na ukokotoaji wa ECC (kama ilivyoonyeshwa kwenye utafiti), au tumia tena helper yoyote inayopatikana inayotekeleza semantiki hizi.

3) Jenga upya hati ya OLE compound.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool huandika storages/streams kwenye filesystem na kutumia escaping kwa herufi zisizokubalika katika majina ya NTFS; njia ya stream unayotaka ni `Global/Latest` hasa katika output tree.
- Unapowasilisha mashambulizi ya kiwango kikubwa kupitia ecosystem plugins zinazopakua RFAs kutoka cloud storage, hakikisha RFA yako iliyopachikwa kiraka inapita ukaguzi wa uadilifu wa Revit locally kwanza (gzip/ECC ni sahihi) kabla ya kujaribu network injection.

Exploitation insight (kuongoza ni bytes zipi za kuweka kwenye gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer husoma 16-bit class index na kuunda object. Aina fulani si polymorphic na hazina vtables; kutumia vibaya ushughulikiaji wa destructor husababisha type confusion ambapo engine hutekeleza indirect call kupitia pointer inayodhibitiwa na mshambulizi.
- Kuchagua `AString` (class index `0x1F`) huweka heap pointer inayodhibitiwa na mshambulizi kwenye object offset 0. Wakati wa destructor loop, Revit hutekeleza kwa ufanisi:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Weka vitu vingi kama hivi kwenye grafu iliyoserialishwa ili kila mzunguko wa kitanzi cha destructor utekeleze gadget moja (“weird machine”), kisha panga stack pivot iingie kwenye mnyororo wa kawaida wa x64 ROP.

Tazama maelezo ya kujenga pivot/gadget za Windows x64 hapa:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

na mwongozo wa jumla wa ROP hapa:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Zana:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) ya kufungua/kujenga upya faili za OLE compound: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD kwa reverse/taint; zima page heap kwa TTD ili kuweka traces fupi.
- Proxy ya ndani (kwa mfano, Fiddler) inaweza kuiga uwasilishaji wa supply chain kwa kubadilisha RFA kwenye trafiki ya plugin wakati wa majaribio.

## References

- [1] [Kutengeneza exploit kamili ya RCE kutokana na crash wakati wa kuchanganua faili ya Autodesk Revit RFA (blogu ya ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Nyaraka za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Mwongozo wa uwanjani wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Nyaraka za olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Tukio la Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
