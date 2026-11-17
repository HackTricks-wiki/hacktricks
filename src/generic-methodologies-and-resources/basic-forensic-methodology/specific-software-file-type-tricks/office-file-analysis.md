# Uchambuzi wa faili za Office

{{#include ../../../banners/hacktricks-training.md}}

Kwa maelezo zaidi, angalia [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Huu ni muhtasari tu:<sup>[[2]](#references)</sup>

Nyaraka za Microsoft Office mara nyingi hupatikana katika miundo ya zamani kama RTF na DOC, XLS, na PPT zinazotumia OLE/CFBF, au katika miundo mipya zaidi ya **Office Open XML (OOXML)** kama DOCX, XLSX, na PPTX. Nyaraka za Office zinaweza kuwa na maudhui amilifu kama macros, hivyo hutumiwa sana kusambaza phishing na malware. Faili za OOXML ni kontena za ZIP ambazo mpangilio wake wa faili na maudhui ya XML yanaweza kukaguliwa kwa kuzifungua kwa unzip.<sup>[[1]](#references)[[2]](#references)</sup>

Ili kuchunguza miundo ya faili za OOXML, amri ya kufungua hati kwa unzip na muundo wa matokeo vimetolewa. Mbinu za kuficha data ndani ya faili hizi zimeandikwa, jambo linaloonyesha ubunifu unaoendelea katika kuficha data kwenye changamoto za CTF.<sup>[[2]](#references)</sup>

Kwa uchanganuzi, **oletools** na **OfficeDissector** hutoa seti kamili ya zana za kuchunguza nyaraka za OLE na OOXML. Zana hizi husaidia kutambua na kuchanganua macros zilizopachikwa, ambazo mara nyingi hutumiwa kusambaza malware na kwa kawaida hupakua na kutekeleza payloads nyingine hasidi. Uchambuzi wa macros za VBA unaweza kufanywa bila Microsoft Office kwa kutumia Libre Office, ambayo huruhusu utatuzi kwa kutumia breakpoints na watch variables.<sup>[[2]](#references)</sup>

Kusakinisha na kutumia **oletools** ni rahisi; amri za kusakinisha kupitia pip na kutoa macros kutoka kwenye nyaraka zimetolewa. Katika Word, macros za kiotomatiki ni pamoja na `AutoExec` na `AutoOpen`, huku `Document_Open` ikiwa ni utaratibu wa tukio la kufungua hati.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Uchambuzi wa macro za VBA: junk code na UserForms

## Junk Code

Macro zinaweza kuwa na **code isiyoweza kufikiwa au isiyo muhimu** iliyokusudiwa kuchelewesha uchanganuzi. Tambua masharti yasiyobadilika na fuatilia tabia inayoweza kufikiwa kabla ya kutumia muda kuchunguza tawi. Mfano ulio hapa chini unatumia sharti la `If` ambalo haliwezi kamwe kuwa kweli ili kuficha junk code.

![A Word macro containing an unreachable conditional branch with junk code](<../../../images/image (369).png>)

## Fomu za Macro

VBA UserForms zinaweza kuhifadhi data katika vidhibiti kama vile visanduku vya maandishi. Kwa kuwa fomu, fremu na kurasa zinaweza kila moja kutoa mkusanyiko wa `Controls`, wachanganuzi wanapaswa kuorodhesha safu nzima ya vidhibiti badala ya kutegemea tu kile kinachoonyeshwa na fomu. Mfano ulio hapa chini huhifadhi data iliyofichwa katika visanduku vya maandishi vinavyoingiliana.<sup>[[6]](#references)</sup>

Wakati wa uchanganuzi wa nguvu, kitendakazi cha VBA `GetObject` kinaweza kupata kitu cha Automation kutoka kwenye faili au kuunganishwa na seva ya Automation ambayo tayari inaendeshwa. Macro zinaweza kutumia ufikiaji huo wa kitu kufikia data ambayo haionekani wazi katika hati; kagua kitu kilichorejeshwa na mti wa vidhibiti wa UserForm.<sup>[[7]](#references)</sup>

![A macro UserForm with data concealed in overlapping text boxes](<../../../images/image (344).png>)

Kwa hati za Office zilizosimbwa kwa nenosiri, angalia [mchakato wa urejeshaji wa offline unaoongozwa na grammar](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Kwa faili za Revit RFA zinazotumia OLE/CFBF, angalia [ukokotoaji upya wa ECC, gzip inayodhibitiwa, na utumiaji wa udhaifu wa deserializer](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); mchakato huo wa kutumia udhaifu wa parser ni tofauti na uchunguzi wa awali wa hati za Office.

## References

- [1] [Nyaraka za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Mwongozo wa Uwanjani wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [3] [Nyaraka za olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Tukio la Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Mikusanyiko, vidhibiti na vitu (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - Kitendakazi cha `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
