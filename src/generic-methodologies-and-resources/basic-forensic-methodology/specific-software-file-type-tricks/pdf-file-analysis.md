# Uchambuzi wa faili za PDF

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Muundo wa PDF unajulikana kwa ugumu wake na uwezekano wa kuficha data, hivyo kuufanya kuwa eneo muhimu katika changamoto za CTF forensics. Unachanganya vipengele vya maandishi wazi na objects za binary, ambazo huenda zikawa zimebanwa au kusimbwa kwa njia fiche, na unaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) ya Didier Stevens, au kutumia zana kama text editor au PDF-specific editor kama Origami.

Kwa uchunguzi wa kina au manipulation ya PDFs, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDFs inaweza kufichwa katika:

- Invisible layers
- XMP metadata format ya Adobe
- Incremental generations
- Maandishi yenye rangi inayofanana na background
- Maandishi yaliyo nyuma ya images au images zinazopishana
- Maoni yasiyoonyeshwa

Kwa uchambuzi maalum wa PDF, Python libraries kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda parsing scripts maalum. Zaidi ya hayo, uwezekano wa PDF wa kuhifadhi data iliyofichwa ni mkubwa sana hivi kwamba resources kama mwongozo wa NSA kuhusu PDF risks and countermeasures, ingawa hauhostiwi tena katika eneo lake la awali, bado hutoa maarifa muhimu. [Copy ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) wa Ange Albertini vinaweza kutoa usomaji zaidi kuhusu mada hii.

## Malicious Constructs za Kawaida

Attackers mara nyingi hutumia vibaya objects na actions maalum za PDF ambazo hutekelezwa kiotomatiki document inapofunguliwa au kuingiliana nayo. Keywords zinazofaa kutafutwa:

* **/OpenAction, /AA** – actions za kiotomatiki zinazotekelezwa wakati wa kufungua au kwenye events maalum.
* **/JS, /JavaScript** – JavaScript iliyopachikwa (mara nyingi imefichwa kwa obfuscation au imegawanywa katika objects).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects zinazoweza kuficha payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, n.k.).
* **/ObjStm, /XFA, /AcroForm** – object streams au forms ambazo hutumiwa vibaya kwa kawaida kuficha shell-code.
* **Incremental updates** – markers nyingi za %%EOF au offset kubwa sana ya **/Prev** zinaweza kuashiria data iliyoongezwa baada ya signing ili kupita AV.

Wakati token zozote za awali zinapoonekana pamoja na strings za kutiliwa shaka (powershell, cmd.exe, calc.exe, base64, n.k.), PDF hiyo inastahili uchambuzi wa kina zaidi.

---

## Cheat-sheet ya static analysis
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
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
Miradi ya ziada yenye manufaa (inayotunzwa kikamilifu 2023-2025):
* **pdfcpu** – Go library/CLI yenye uwezo wa *lint*, *decrypt*, *extract*, *compress* na *sanitize* PDFs.
* **pdf-inspector** – visualizer ya msingi wa browser inayochora object graph na streams.
* **PyMuPDF (fitz)** – Python engine inayoweza kuscriptiwa na inayoweza kuchora kurasa kwa usalama kuwa picha ili kuanzisha embedded JS katika hardened sandbox.

---

## Mbinu za hivi karibuni za mashambulizi (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ilibaini threat actors wakiongeza Word document ya MHT yenye VBA macros baada ya **%%EOF** ya mwisho, na kutengeneza file ambalo ni PDF halali na DOC halali. AV engines zinazochanganua PDF layer pekee hukosa macro. Static PDF keywords ni safi, lakini `file` bado huchapisha `%PDF`. Chukulia PDF yoyote ambayo pia ina string `<w:WordDocument>` kuwa highly suspicious.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries hutumia vibaya incremental update feature kuingiza **/Catalog** ya pili yenye malicious `/OpenAction`, huku wakiweka first revision iliyo benign ikiwa signed. Tools zinazokagua xref table ya kwanza pekee hupitwa.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – function iliyo vulnerable katika **CoolType.dll** inaweza kufikiwa kupitia embedded CIDType2 fonts, na kuruhusu remote code execution kwa privileges za user mara crafted document inapofunguliwa. Ilirekebishwa katika APSB24-29, Mei 2024.<sup>[[3]](#references)</sup>

---

## YARA quick rule template
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

1. **Fanya patch haraka** – weka Acrobat/Reader kwenye track ya hivi karibuni ya Continuous; minyororo mingi ya RCE iliyozingatiwa porini hutumia udhaifu wa n-day uliorekebishwa miezi kadhaa iliyopita.
2. **Ondoa active content kwenye gateway** – tumia `pdfcpu sanitize` au `qpdf --qdf --remove-unreferenced` kuondoa JavaScript, faili zilizopachikwa na launch actions kutoka kwenye PDFs zinazoingia.
3. **Content Disarm & Reconstruction (CDR)** – badilisha PDFs kuwa picha (au PDF/A) kwenye sandbox host ili kuhifadhi uaminifu wa mwonekano huku ukiondoa active objects.
4. **Zuia vipengele visivyotumiwa mara kwa mara** – mipangilio ya “Enhanced Security” ya enterprise kwenye Reader inaruhusu kuzima JavaScript, multimedia na 3D rendering.
5. **Elimu kwa watumiaji** – social engineering (vishawishi vya invoice na resume) bado ni initial vector; wafundishe wafanyakazi ku-forward attachments zinazotia shaka kwa IR.

## Marejeleo

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
