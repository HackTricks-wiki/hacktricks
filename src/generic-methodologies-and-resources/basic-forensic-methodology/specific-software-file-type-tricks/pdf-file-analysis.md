# Uchambuzi wa faili za PDF

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Muundo wa PDF unajulikana kwa uchangamano wake na uwezekano wa kuficha data, hivyo kuwa kiini cha changamoto za forensic za CTF. Unachanganya vipengele vya maandishi ya kawaida na vitu vya binary, ambavyo vinaweza kubanwa au kusimbwa kwa njia fiche, na unaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, unaweza kurejelea [nyenzo za utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) za Didier Stevens, au kutumia zana kama text editor au editor maalum ya PDF kama Origami.

Kwa uchunguzi au urekebishaji wa kina wa PDFs, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDFs inaweza kufichwa katika:

- Tabaka zisizoonekana
- Muundo wa metadata wa XMP wa Adobe
- Matoleo ya nyongeza
- Maandishi yenye rangi sawa na mandharinyuma
- Maandishi yaliyo nyuma ya picha au picha zinazopishana
- Maoni yasiyoonyeshwa

Kwa uchanganuzi maalum wa PDF, Python libraries kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kutengeneza scripts maalum za kuchanganua. Zaidi ya hayo, uwezo wa PDF wa kuhifadhi data iliyofichwa ni mkubwa sana hivi kwamba nyenzo kama mwongozo wa NSA kuhusu hatari na hatua za kukabiliana nazo kwenye PDF, ingawa haupatikani tena katika eneo lake la awali, bado una maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [mbinu za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) wa Ange Albertini vinaweza kutoa usomaji zaidi kuhusu mada hii.<sup>[[4]](#references)[[5]](#references)</sup>

## Vipengele hasidi vya kawaida

Washambuliaji mara nyingi hutumia vibaya vitu na vitendo maalum vya PDF vinavyojiendesha vinapofunguliwa au mtumiaji anapovishughulikia. Maneno muhimu ya kutafuta:

* **/OpenAction, /AA** – vitendo vinavyojiendesha vinapofunguliwa au wakati wa matukio maalum.
* **/JS, /JavaScript** – JavaScript iliyopachikwa (mara nyingi imefichwa au imegawanywa kati ya vitu).
* **/Launch, /SubmitForm, /URI, /GoToE** – viwezeshaji vya kuzindua michakato ya nje / URL.
* **/RichMedia, /Flash, /3D** – vitu vya multimedia vinavyoweza kuficha payloads.
* **/EmbeddedFile /Filespec** – viambatisho vya faili (EXE, DLL, OLE, n.k.).
* **/ObjStm, /XFA, /AcroForm** – object streams au forms zinazotumiwa vibaya mara nyingi kuficha shell-code.
* **Masasisho ya nyongeza** – alama nyingi za %%EOF au thamani kubwa sana ya **/Prev** zinaweza kuashiria data iliyoongezwa baada ya kusainiwa ili kukwepa AV.

Tokens zozote kati ya zilizotajwa hapo juu zikionekana pamoja na strings zinazotia shaka (powershell, cmd.exe, calc.exe, base64, n.k.), PDF inahitaji uchanganuzi wa kina zaidi.

---

## Muhtasari wa uchanganuzi tuli

Mifano iliyo hapa chini inatumia interfaces za command-line zilizoandikwa za `pdf-parser.py`, qpdf, na pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```

Kuweka picha ndani ya PDF ionekane yenye pikseli kubwa hakuondoi pikseli zake za msingi. Ikiwa hati inayosomeka inaonekana kuficha credential kwa njia hii, toa picha iliyopachikwa kwa ukaguzi wa offline ulioidhinishwa; matokeo hutegemea picha na rejeleo linalofaa, na urejeshaji wa kuona haujahakikishwa. Nenosiri lililorejeshwa bado linahitaji kuthibitishwa kivyake dhidi ya akaunti ambayo ruhusa zake ni muhimu. Usiweke uchimbaji wa PDF au urejeshaji wa picha katika uchanganuzi wa kawaida wa uorodheshaji wa host.

Miradi mingine muhimu (inayodumishwa kikamilifu 2023-2025):
* **pdfcpu** – maktaba/CLI ya Go inayoweza kuthibitisha, kusimbua, kutoa, kuboresha na kudhibiti PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – zana ya kuona inayotumia browser na kuonyesha grafu ya object na streams.
* **PyMuPDF** – bindings za Python zinazoweza kuandikiwa script, kwa kukagua PDF na kutoa kurasa kama picha za raster. Chukulia parser/renderer kama eneo la mashambulizi la faili zisizoaminika na uiendeshe ndani ya mazingira ya uchanganuzi yaliyotengwa ipasavyo.<sup>[[8]](#references)</sup>

---

## Mbinu za hivi karibuni za mashambulizi (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC iliripoti mbinu inayoongeza faili ya MHT iliyoundwa na Word na macros za VBA kwenye PDF, huku ikihifadhi magic ya PDF na pia kufunguka katika Word. Zana za uchanganuzi za PDF pekee, sandboxes au antivirus zinaweza kukosa macro kwa sababu tabia hasidi hutokea faili inapofunguliwa kama Word; tafuta alama ya `<w:WordDocument>` pamoja na viashiria vingine vya MHT.<sup>[[2]](#references)</sup>
* **Mashambulizi ya Shadow dhidi ya PDF zilizotiwa saini** – washambuliaji wanaweza kuweka maudhui yaliyofichwa kwenye PDF kabla haijatiwa saini, kisha kuongeza incremental update inayobadilisha marejeleo ya catalog au object ili programu za kuonyesha faili zionyeshe maudhui yaliyofichwa huku saini ya awali ikiendelea kuwa halali. Mbinu hii inaweza kukwepa programu za kuonyesha faili zinazochukulia masasisho hayo kuwa yasiyo na madhara.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe imekadiria udhaifu huu muhimu kuwa use-after-free unaoweza kusababisha utekelezaji wa msimbo holela; APSB24-29 ilichapishwa Mei 14, 2024.<sup>[[3]](#references)</sup>

---

## Kiolezo kifupi cha kanuni ya YARA

```yara
rule Suspicious_PDF_AutoExec {
    meta:
        description = "Generic detection of PDFs with auto-exec actions and JS"
        author      = "HackTricks"
        last_update = "2025-07-20"
    strings:
        $pdf_magic = { 25 50 44 46 }          // %PDF
        $aa        = "/AA" ascii nocase
        $openact   = "/OpenAction" ascii nocase
        $js        = "/JS" ascii nocase
    condition:
        $pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```

---

## Vidokezo vya kujilinda

1. **Sakinisha viraka haraka** – tumia toleo la hivi karibuni la Continuous track la Acrobat/Reader; mashambulizi mengi ya RCE yaliyoonekana porini hutumia udhaifu wa n-day uliorekebishwa miezi kadhaa awali.
2. **Ondoa active content kwenye gateway** – tumia sanitizer maalum inayodhibitiwa na sera au bidhaa ya CDR inayoondoa JavaScript, faili zilizopachikwa, launch actions, fomu na multimedia waziwazi. `qpdf --qdf` hurahisisha ukaguzi wa PDF objects, huku pdfcpu ikitoa vipengele vya uthibitishaji na urekebishaji; hakuna amri kati ya hizi inayothibitisha peke yake kwamba active content imeondolewa.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – badilisha PDF kuwa picha (au PDF/A) kwenye sandbox host ili kuhifadhi mwonekano wake huku ukitupa active objects.
4. **Zuia vipengele visivyotumika mara nyingi** – mipangilio ya “Enhanced Security” ya Reader ya matumizi ya kampuni inaruhusu kuzima JavaScript, multimedia na uonyeshaji wa 3D.
5. **Elimu kwa watumiaji** – social engineering (ujumbe wa udanganyifu wa ankara na wasifu wa kazi) bado ndiyo njia ya awali ya mashambulizi; wafundishe wafanyakazi kutuma viambatisho vinavyotiliwa shaka kwa IR.

## References

- [1] [Mwongozo wa Uwanjani wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Kukwepa ugunduzi kwa kupachika faili hasidi ya Word ndani ya faili la PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Taarifa ya Usalama ya Adobe – Sasisho la usalama linapatikana kwa Adobe Acrobat na Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - Mbinu za hila za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Mashambulizi ya Shadow: Kuficha na Kubadilisha Maudhui katika PDF Zilizotiwa Saini](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Mafunzo ya PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Chaguo za mstari wa amri za qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
