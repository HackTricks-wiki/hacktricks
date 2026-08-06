# Uchambuzi wa faili ya PDF

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Muundo wa PDF unajulikana kwa utata wake na uwezekano wa kuficha data, jambo linaloufanya kuwa muhimu katika changamoto za CTF forensics. Unachanganya vipengele vya maandishi wazi na binary objects, ambavyo vinaweza kuwa compressed au encrypted, na unaweza kujumuisha scripts katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, unaweza kurejelea [nyenzo za utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) za Didier Stevens, au kutumia tools kama text editor au PDF-specific editor kama Origami.

Kwa uchunguzi wa kina au manipulation ya PDFs, tools kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data iliyofichwa ndani ya PDFs inaweza kufichwa katika:

- Invisible layers
- Muundo wa XMP metadata wa Adobe
- Incremental generations
- Maandishi yenye rangi inayofanana na background
- Maandishi yaliyo nyuma ya images au images zinazopishana
- Comments zisizoonyeshwa

Kwa custom PDF analysis, Python libraries kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda parsing scripts maalum. Zaidi ya hayo, uwezo wa PDF kuhifadhi data iliyofichwa ni mkubwa sana kiasi kwamba resources kama mwongozo wa NSA kuhusu PDF risks na countermeasures, ingawa hauhostwi tena katika eneo lake la awali, bado hutoa maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) wa Ange Albertini vinaweza kutoa usomaji zaidi kuhusu mada hii.<sup>[[4]](#references)[[5]](#references)</sup>

## Common Malicious Constructs

Attackers mara nyingi hutumia vibaya PDF objects na actions maalum ambazo hutekelezwa automatically document inapofunguliwa au inapoingiliana. Keywords zinazofaa kutafutwa:

* **/OpenAction, /AA** – automatic actions zinazotekelezwa wakati wa kufungua au wakati wa events maalum.
* **/JS, /JavaScript** – JavaScript iliyowekwa ndani (mara nyingi ikiwa obfuscated au imegawanywa katika objects kadhaa).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects zinazoweza kuficha payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, n.k.).
* **/ObjStm, /XFA, /AcroForm** – object streams au forms ambazo hutumiwa vibaya mara nyingi kuficha shell-code.
* **Incremental updates** – markers nyingi za %%EOF au **/Prev** offset kubwa sana zinaweza kuashiria data iliyoongezwa baada ya signing ili kukwepa AV.

Tokens zozote zilizotajwa hapo awali zinapoonekana pamoja na strings zinazotiliwa shaka (powershell, cmd.exe, calc.exe, base64, n.k.), PDF inastahili kufanyiwa uchambuzi wa kina zaidi.

---

## Muhtasari wa static analysis
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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – library/CLI ya Go inayoweza *lint*, *decrypt*, *extract*, *compress* na *sanitize* PDFs.
* **pdf-inspector** – visualizer ya browser inayochora object graph na streams.
* **PyMuPDF (fitz)** – engine ya Python inayoweza kuandikwa script, na inaweza kuchora kurasa kuwa picha kwa usalama ili kuendesha embedded JS katika sandbox iliyoimarishwa.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC ilibaini kuwa threat actors wanaongeza Word document inayotumia MHT yenye VBA macros baada ya **%%EOF** ya mwisho, na kutengeneza file ambalo ni PDF halali na DOC halali kwa wakati mmoja. AV engines zinazochanganua PDF layer pekee hukosa macro hiyo. Static PDF keywords ni safi, lakini `file` bado huchapisha `%PDF`. Chukulia PDF yoyote ambayo pia ina string `<w:WordDocument>` kuwa yenye mashaka makubwa.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries hutumia vibaya incremental update feature kuingiza **/Catalog** ya pili yenye malicious `/OpenAction`, huku wakihifadhi first revision iliyo benign na signed. Tools zinazokagua xref table ya kwanza pekee hupitwa.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – function iliyo vulnerable katika **CoolType.dll** inaweza kufikiwa kupitia CIDType2 fonts zilizowekwa ndani, na kuruhusu remote code execution kwa privileges za user mara tu crafted document inapofunguliwa. Ilipatiwa patch katika APSB24-29, Mei 2024.<sup>[[3]](#references)</sup>

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

1. **Fanya patching haraka** – weka Acrobat/Reader kwenye Continuous track ya hivi karibuni; minyororo mingi ya RCE iliyoonekana in the wild hutumia n-day vulnerabilities zilizorekebishwa miezi kadhaa iliyopita.
2. **Ondoa active content kwenye gateway** – tumia `pdfcpu sanitize` au `qpdf --qdf --remove-unreferenced` kuondoa JavaScript, embedded files na launch actions kutoka kwenye PDFs zinazoingia.
3. **Content Disarm & Reconstruction (CDR)** – badilisha PDFs kuwa images (au PDF/A) kwenye sandbox host ili kuhifadhi mwonekano huku ukiondoa active objects.
4. **Zuia features zinazotumiwa mara chache** – mipangilio ya enterprise ya “Enhanced Security” katika Reader inaruhusu kuzima JavaScript, multimedia na 3D rendering.
5. **Elimu kwa watumiaji** – social engineering (vishawishi vya invoice na resume) bado ni initial vector; wafundishe wafanyakazi kupeleka attachments zinazotia shaka kwa IR.

## Marejeo

- [1] [Mwongozo wa Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass kwa ku-embed Word file hasidi ndani ya PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update inapatikana kwa Adobe Acrobat na Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - mbinu za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
