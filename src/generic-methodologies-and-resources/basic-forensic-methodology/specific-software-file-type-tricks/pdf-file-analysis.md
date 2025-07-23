# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**Kwa maelezo zaidi angalia:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Muundo wa PDF unajulikana kwa ugumu wake na uwezo wa kuficha data, na kufanya kuwa kitovu cha changamoto za forensics za CTF. Inachanganya vipengele vya maandiko ya kawaida na vitu vya binary, ambavyo vinaweza kuwa vimepandikizwa au kufichwa, na vinaweza kujumuisha skripti katika lugha kama JavaScript au Flash. Ili kuelewa muundo wa PDF, mtu anaweza kurejelea [nyenzo za utangulizi](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) za Didier Stevens, au kutumia zana kama mhariri wa maandiko au mhariri maalum wa PDF kama Origami.

Kwa uchambuzi wa kina au usindikaji wa PDFs, zana kama [qpdf](https://github.com/qpdf/qpdf) na [Origami](https://github.com/mobmewireless/origami-pdf) zinapatikana. Data zilizofichwa ndani ya PDFs zinaweza kufichwa katika:

- Tabaka zisizoonekana
- Muundo wa metadata wa XMP na Adobe
- Vizazi vya ongezeko
- Maandishi yenye rangi sawa na ya nyuma
- Maandishi nyuma ya picha au picha zinazovutana
- Maoni yasiyoonyeshwa

Kwa uchambuzi wa PDF wa kawaida, maktaba za Python kama [PeepDF](https://github.com/jesparza/peepdf) zinaweza kutumika kuunda skripti za uchambuzi maalum. Zaidi, uwezo wa PDF wa kuhifadhi data iliyofichwa ni mkubwa kiasi kwamba rasilimali kama mwongozo wa NSA kuhusu hatari za PDF na hatua za kukabiliana, ingawa haupo tena kwenye eneo lake la awali, bado hutoa maarifa muhimu. [Nakala ya mwongozo](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) na mkusanyiko wa [hila za muundo wa PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) za Ange Albertini zinaweza kutoa kusoma zaidi juu ya mada hiyo.

## Common Malicious Constructs

Wavamizi mara nyingi wanatumia vitu maalum vya PDF na vitendo ambavyo vinatekelezwa kiotomatiki wakati hati inafunguliwa au inapoingiliana nayo. Maneno muhimu ya kutafuta:

* **/OpenAction, /AA** – vitendo vya kiotomatiki vinavyotekelezwa wakati wa kufungua au kwenye matukio maalum.
* **/JS, /JavaScript** – JavaScript iliyojumuishwa (mara nyingi imefichwa au kugawanywa kati ya vitu).
* **/Launch, /SubmitForm, /URI, /GoToE** – uzinduzi wa mchakato wa nje / URL.
* **/RichMedia, /Flash, /3D** – vitu vya multimedia ambavyo vinaweza kuficha mzigo.
* **/EmbeddedFile /Filespec** – viambatisho vya faili (EXE, DLL, OLE, nk.).
* **/ObjStm, /XFA, /AcroForm** – mstreams ya vitu au fomu ambazo mara nyingi hutumiwa kuficha shell-code.
* **Incremental updates** – alama nyingi za %%EOF au offset kubwa sana ya **/Prev** inaweza kuashiria data iliyoongezwa baada ya kusaini ili kupita AV.

Wakati yoyote ya alama zilizotajwa hapo juu inapoonekana pamoja na nyuzi za kutatanisha (powershell, cmd.exe, calc.exe, base64, nk.) PDF inastahili uchambuzi wa kina.

---

## Static analysis cheat-sheet
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
* **pdfcpu** – Go library/CLI able to *lint*, *decrypt*, *extract*, *compress* and *sanitize* PDFs.
* **pdf-inspector** – browser-based visualizer that renders the object graph and streams.
* **PyMuPDF (fitz)** – scriptable Python engine that can safely render pages to images to detonate embedded JS in a hardened sandbox.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC iliona wahalifu wakiongeza hati ya Word inayotumia MHT yenye VBA macros baada ya **%%EOF** ya mwisho, ikizalisha faili ambayo ni PDF halali na DOC halali. Injini za AV zinazochambua tu safu ya PDF zinakosa macro. Maneno ya PDF ya statiki ni safi, lakini `file` bado inachapisha `%PDF`. Chukulia PDF yoyote ambayo pia ina mfuatano `<w:WordDocument>` kama yenye shaka kubwa.
* **Shadow-incremental updates (2024)** – maadui wanatumia kipengele cha sasisho la kuongeza ili kuingiza **/Catalog** ya pili yenye `/OpenAction` mbaya huku wakihifadhi toleo la kwanza lililosainiwa kuwa la kawaida. Zana zinazochunguza tu jedwali la xref la kwanza zinapita.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – kazi dhaifu ya **CoolType.dll** inaweza kufikiwa kutoka kwa fonti za CIDType2 zilizojumuishwa, ikiruhusu utekelezaji wa msimbo wa mbali kwa ruhusa za mtumiaji mara hati iliyoundwa inafunguliwa. Imefanyiwa marekebisho katika APSB24-29, Mei 2024.

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

## Vidokezo vya Kuzuia

1. **Pata haraka** – weka Acrobat/Reader kwenye njia ya hivi karibuni ya Kuendelea; mnyororo mwingi wa RCE unaoshuhudiwa katika mazingira ya kawaida unatumia udhaifu wa n-siku uliofanyiwa marekebisho miezi kadhaa iliyopita.
2. **Ondoa maudhui ya kazi kwenye lango** – tumia `pdfcpu sanitize` au `qpdf --qdf --remove-unreferenced` kuondoa JavaScript, faili zilizojumuishwa na vitendo vya uzinduzi kutoka kwa PDFs zinazokuja.
3. **Kutoa Maudhui & Ujenzi (CDR)** – badilisha PDFs kuwa picha (au PDF/A) kwenye mwenyeji wa sandbox ili kuhifadhi uaminifu wa kuona wakati wa kuondoa vitu vya kazi.
4. **Zuia vipengele ambavyo havitumiki mara kwa mara** – mipangilio ya “Usalama Ulioimarishwa” katika Reader inaruhusu kuzima JavaScript, multimedia na uwasilishaji wa 3D.
5. **Elimu ya Mtumiaji** – uhandisi wa kijamii (vichocheo vya ankara na wasifu) unabaki kuwa njia ya awali; wafundishe wafanyakazi kupeleka viambatisho vya kushangaza kwa IR.

## Marejeleo

* JPCERT/CC – “MalDoc katika PDF – Kupita kwa ugunduzi kwa kuingiza faili ya Word yenye uharibifu ndani ya faili ya PDF” (Agosti 2023)
* Adobe – Sasisho la usalama kwa Acrobat na Reader (APSB24-29, Mei 2024)


{{#include ../../../banners/hacktricks-training.md}}
