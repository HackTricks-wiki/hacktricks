# Uchambuzi wa faili za PDF

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Muundo wa PDF unajulikana kwa uchangamano wake na uwezekano wa kuficha data, jambo linaloufanya uwe muhimu katika changamoto za CTF forensics. Unachanganya vipengele vya maandishi wazi na objects za binary, ambazo zinaweza kubanwa au kusimbwa kwa encryption, na unaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, unaweza kurejelea [maudhui ya utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) ya Didier Stevens, au kutumia tools kama text editor au PDF-specific editor kama Origami.

Kwa uchunguzi wa kina au manipulation ya PDFs, tools kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDFs inaweza kufichwa katika:

- Layers zisizoonekana
- Muundo wa XMP metadata wa Adobe
- Incremental generations
- Maandishi yenye rangi inayofanana na background
- Maandishi yaliyo nyuma ya images au images zinazopishana
- Comments zisizoonyeshwa

Kwa custom PDF analysis, Python libraries kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kutengeneza parsing scripts maalum. Zaidi ya hayo, uwezekano wa PDF kuhifadhi data iliyofichwa ni mkubwa sana kiasi kwamba resources kama mwongozo wa NSA kuhusu hatari na countermeasures za PDF, ingawa haupo tena kwenye location yake ya awali, bado hutoa maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) wa Ange Albertini vinaweza kutoa usomaji zaidi kuhusu mada hii.<sup>[[4]](#references)[[5]](#references)</sup>

## Constructs hasidi za Kawaida

Attackers mara nyingi hutumia vibaya PDF objects na actions maalum ambazo hujiendesha document inapofunguliwa au kuingiliana nayo. Keywords zinazofaa kutafutwa:

* **/OpenAction, /AA** – actions za kiotomatiki zinazotekelezwa wakati wa kufungua au kwenye events maalum.
* **/JS, /JavaScript** – JavaScript iliyowekwa ndani (mara nyingi ikiwa imefichwa kwa obfuscation au imegawanywa katika objects kadhaa).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects zinazoweza kuficha payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, n.k.).
* **/ObjStm, /XFA, /AcroForm** – object streams au forms ambazo hutumiwa vibaya mara nyingi kuficha shell-code.
* **Incremental updates** – markers nyingi za %%EOF au **/Prev** offset kubwa sana zinaweza kuashiria data iliyoongezwa baada ya signing ili kukwepa AV.

Token zozote za awali zinapoonekana pamoja na strings zinazotiliwa shaka (powershell, cmd.exe, calc.exe, base64, n.k.), PDF inastahili kufanyiwa uchambuzi wa kina zaidi.

---

## Cheat-sheet ya Static analysis

Mifano iliyo hapa chini hutumia interfaces za command-line zilizorekodiwa za `pdf-parser.py`, qpdf, na pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Miradi ya ziada muhimu (inayodumishwa kikamilifu 2023-2025):
* **pdfcpu** – library/CLI ya Go inayoweza kuthibitisha, kufungua encryption, kutoa, kuboresha, na kudhibiti PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizer inayotumia browser, inayowasilisha object graph na streams.
* **PyMuPDF** – Python bindings zinazoweza kutumiwa kwa scripts kukagua PDFs na kuwasilisha kurasa kama picha za raster. Ichukulie parser/renderer kama attack surface ya faili zisizoaminika na iendeshe ndani ya mazingira ya uchanganuzi yaliyotengwa ipasavyo.<sup>[[8]](#references)</sup>

---

## Mbinu za hivi karibuni za mashambulizi (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC iliripoti mbinu inayoongeza faili ya MHT iliyoundwa na Word yenye VBA macros kwenye PDF, huku ikihifadhi PDF magic na pia kufunguka katika Word. Zana za uchanganuzi za PDF pekee, sandboxes, au antivirus zinaweza kukosa macro kwa sababu tabia hasidi hutokea inapofunguliwa kama Word; tafuta alama ya `<w:WordDocument>` pamoja na viashiria vingine vya MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – washambuliaji wanaweza kuweka maudhui yaliyofichwa kwenye PDF kabla ya kusainiwa, kisha kuongeza incremental update inayobadilisha catalog au object references ili viewers waonyeshe maudhui yaliyofichwa huku signature ya awali ikiendelea kuwa halali. Mbinu hii inaweza kukwepa viewers wanaoainisha updates kama zisizo na madhara.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe imeainisha vulnerability hii muhimu kama use-after-free inayoweza kusababisha arbitrary code execution; APSB24-29 ilichapishwa tarehe 14 Mei 2024.<sup>[[3]](#references)</sup>

---

## Kiolezo kifupi cha sheria ya YARA
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

1. **Fanya patch haraka** – weka Acrobat/Reader kwenye Continuous track ya hivi karibuni; chains nyingi za RCE zilizozingatiwa porini hutumia vulnerabilities za n-day zilizorekebishwa miezi kadhaa iliyopita.
2. **Ondoa active content kwenye gateway** – tumia sanitizer maalum inayodhibitiwa na policy au bidhaa ya CDR ambayo huondoa JavaScript, embedded files, launch actions, forms, na multimedia. `qpdf --qdf` hurahisisha kukagua PDF objects, huku pdfcpu ikitoa vipengele vya validation na manipulation; hakuna command kati ya hizo peke yake inayothibitisha kuwa active content imeondolewa.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – badilisha PDFs kuwa images (au PDF/A) kwenye sandbox host ili kuhifadhi visual fidelity huku ukiondoa active objects.
4. **Zuia features zinazotumiwa mara chache** – mipangilio ya enterprise ya “Enhanced Security” kwenye Reader inaruhusu kuzima JavaScript, multimedia na 3D rendering.
5. **Elimu kwa watumiaji** – social engineering (invoice & resume lures) bado ni initial vector; wafundishe wafanyakazi ku-forward attachments zinazotiliwa shaka kwa IR.

## References

- [1] [Mwongozo wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Bypass ya detection kwa ku-embed Word file hasidi ndani ya PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available kwa Adobe Acrobat na Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - mbinu za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Kuficha na kubadilisha content kwenye Signed PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Mafunzo ya PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Chaguo za command-line za qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
