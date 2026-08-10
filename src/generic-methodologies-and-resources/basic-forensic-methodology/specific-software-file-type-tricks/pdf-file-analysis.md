# Uchambuzi wa Faili za PDF

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Muundo wa PDF unajulikana kwa ugumu wake na uwezo wa kuficha data, jambo linaloufanya uwe muhimu katika changamoto za CTF forensics. Unachanganya vipengele vya maandishi wazi na vitu vya binary, ambavyo vinaweza kubanwa au kusimbwa kwa njia fiche, na unaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea [nyenzo ya utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) ya Didier Stevens, au kutumia tools kama text editor au PDF-specific editor kama Origami.

Kwa uchunguzi wa kina au manipulation ya PDFs, tools kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDFs inaweza kufichwa katika:

- Invisible layers
- Muundo wa XMP metadata wa Adobe
- Incremental generations
- Maandishi yenye rangi sawa na background
- Maandishi yaliyo nyuma ya images au images zinazopishana
- Comments zisizoonyeshwa

Kwa uchambuzi maalum wa PDF, Python libraries kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda parsing scripts maalum. Zaidi ya hayo, uwezo wa PDF wa kuhifadhi data iliyofichwa ni mkubwa sana hivi kwamba resources kama mwongozo wa NSA kuhusu PDF risks na countermeasures, ingawa haupo tena katika eneo lake la awali, bado hutoa maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) wa Ange Albertini vinaweza kutoa usomaji zaidi kuhusu mada hii.<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackers mara nyingi hutumia vibaya PDF objects na actions maalum ambazo hujiendesha moja kwa moja document inapofunguliwa au mtumiaji anapoingiliana nayo. Keywords zinazofaa kutafutwa:

* **/OpenAction, /AA** – automatic actions zinazotekelezwa wakati wa kufungua au wakati wa matukio maalum.
* **/JS, /JavaScript** – JavaScript iliyopachikwa (mara nyingi ikiwa imefichwa kwa obfuscation au imegawanywa katika objects kadhaa).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects zinazoweza kuficha payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, n.k.).
* **/ObjStm, /XFA, /AcroForm** – object streams au forms ambazo hutumiwa mara nyingi kuficha shell-code.
* **Incremental updates** – markers nyingi za %%EOF au offset kubwa sana ya **/Prev** zinaweza kuashiria data iliyoongezwa baada ya signing ili kukwepa AV.

Token yoyote kati ya zilizotangulia inapoonekana pamoja na strings zinazotia shaka (powershell, cmd.exe, calc.exe, base64, n.k.), PDF hiyo inastahili uchambuzi wa kina zaidi.

---

## Static analysis cheat-sheet

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
Miradi mingine muhimu (inayodumishwa kikamilifu 2023-2025):
* **pdfcpu** – Go library/CLI inayoweza kuthibitisha, kufungua usimbaji, kutoa, kuboresha, na kudhibiti PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizer ya browser inayochora object graph na streams.
* **PyMuPDF** – Python bindings zinazoweza kuandikwa kwa scripts kwa ajili ya kukagua PDFs na ku-render kurasa kuwa raster images. Chukulia parser/renderer kama attack surface ya faili zisizoaminika na iendeshe ndani ya analysis environment iliyotengwa ipasavyo.<sup>[[8]](#references)</sup>

---

## Mbinu za hivi karibuni za attack (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC iliripoti technique inayoongeza MHT file iliyoundwa na Word yenye VBA macros kwenye PDF, huku ikihifadhi PDF magic na pia kufunguka katika Word. PDF-only analysis tools, sandboxes, au antivirus zinaweza kukosa macro kwa sababu malicious behavior hutokea inapofunguliwa kama Word; tafuta marker ya `<w:WordDocument>` pamoja na MHT indicators nyingine.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers wanaweza kuweka content iliyofichwa kwenye PDF kabla haijasainiwa, kisha kuongeza incremental update inayobadilisha catalog au object references ili viewers waonyeshe content iliyofichwa huku original signature ikiendelea kuwa valid. Technique hii inaweza kukwepa viewers wanaoainisha updates kama zisizo na madhara.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe inalipima vulnerability hii critical kama use-after-free inayoweza kusababisha arbitrary code execution; APSB24-29 ilichapishwa Mei 14, 2024.<sup>[[3]](#references)</sup>

---

## Muundo wa haraka wa rule ya YARA
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

1. **Fanya patch haraka** – tumia Acrobat/Reader kwenye mkondo wa hivi karibuni wa Continuous; minyororo mingi ya RCE iliyozingatiwa porini hutumia udhaifu wa n-day uliorekebishwa miezi kadhaa iliyopita.
2. **Ondoa active content kwenye gateway** – tumia sanitizer au bidhaa ya CDR iliyoundwa mahsusi na kudhibitiwa na sera, ambayo huondoa wazi JavaScript, embedded files, launch actions, forms na multimedia. `qpdf --qdf` hurahisisha ukaguzi wa PDF objects, huku pdfcpu ikitoa vipengele vya validation na manipulation; hakuna command kati ya hizi pekee inayothibitisha kuwa active content imeondolewa.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – badilisha PDFs kuwa images (au PDF/A) kwenye sandbox host ili kuhifadhi uaminifu wa mwonekano huku ukiondoa active objects.
4. **Zuia vipengele visivyotumika mara kwa mara** – mipangilio ya “Enhanced Security” ya enterprise kwenye Reader inaruhusu kuzima JavaScript, multimedia na 3D rendering.
5. **Elimu kwa watumiaji** – social engineering (mitego ya invoice na resume) bado ni initial vector; wafundishe wafanyakazi kutuma attachments zinazotiliwa shaka kwa IR.

## References

- [1] [Mwongozo wa Uwanja wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Njia ya kukwepa detection kwa kuingiza Word file yenye malicious ndani ya PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update inapatikana kwa Adobe Acrobat na Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - mbinu za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Kuficha na kubadilisha Content kwenye Signed PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Chaguo za qpdf command-line](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
