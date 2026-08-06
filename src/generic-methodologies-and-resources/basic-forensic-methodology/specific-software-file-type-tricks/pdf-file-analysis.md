# PDF-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, kyk na:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te verberg, wat dit 'n fokuspunt vir CTF-forensics-uitdagings maak. Dit kombineer plain-text-elemente met binêre objekte, wat moontlik saamgepers of geënkripteer kan wees, en kan scripts in tale soos JavaScript of Flash insluit. Om PDF-struktuur te verstaan, kan 'n mens na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of tools soos 'n text editor of 'n PDF-spesifieke editor soos Origami gebruik.

Vir diepgaande verkenning of manipulasie van PDFs is tools soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Verborge data binne PDFs kan versteek wees in:

- Onsigbare lae
- XMP metadata-formaat deur Adobe
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter beelde of oorvleuelende beelde
- Kommentaar wat nie vertoon word nie

Vir pasgemaakte PDF-analise kan Python libraries soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om pasgemaakte parsing-scripts te skep. Verder is die PDF se potensiaal vir die berging van verborge data so groot dat resources soos die NSA-gids oor PDF-risiko's en teenmaatreëls, hoewel dit nie meer by die oorspronklike ligging gehuisves word nie, steeds waardevolle insigte bied. 'n [Kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en 'n versameling van [PDF-format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini kan verdere leesstof oor die onderwerp bied.<sup>[[4]](#references)[[5]](#references)</sup>

## Algemene kwaadwillige constructs

Aanvallers misbruik dikwels spesifieke PDF-objekte en actions wat outomaties uitgevoer word wanneer die dokument oopgemaak of daarmee interaksie gehad word. Sleutelwoorde waarna dit die moeite werd is om te soek:

* **/OpenAction, /AA** – outomatiese actions wat tydens oopmaak of spesifieke events uitgevoer word.
* **/JS, /JavaScript** – ingebedde JavaScript (dikwels geobfuskeer of oor objekte verdeel).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers vir eksterne prosesse / URLs.
* **/RichMedia, /Flash, /3D** – multimedia-objekte wat payloads kan versteek.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, ens.).
* **/ObjStm, /XFA, /AcroForm** – object streams of forms wat algemeen misbruik word om shell-code te versteek.
* **Inkrementele updates** – meerdere %%EOF-markers of 'n baie groot **/Prev**-offset kan daarop dui dat data ná signing aangeheg is om AV te omseil.

Wanneer enige van die vorige tokens saam met verdagte strings (powershell, cmd.exe, calc.exe, base64, ens.) verskyn, verdien die PDF dieper analise.

---

## Cheat-sheet vir static analysis
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
Additional useful projects (aktief onderhou 2023-2025):
* **pdfcpu** – Go-biblioteek/CLI wat PDF's kan *lint*, *decrypt*, *extract*, *compress* en *sanitize*.
* **pdf-inspector** – blaaiergebaseerde visualiseerder wat die objekgrafiek en streams weergee.
* **PyMuPDF (fitz)** – scriptbare Python-enjin wat bladsye veilig na beelde kan weergee om ingebedde JS in 'n geharde sandbox te detoneer.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC het waargeneem dat threat actors 'n MHT-gebaseerde Word-dokument met VBA-makro's ná die finale **%%EOF** byvoeg, wat 'n lêer produseer wat beide 'n geldige PDF en 'n geldige DOC is. AV-enjins wat slegs die PDF-laag ontleed, mis die makro. Statiese PDF-sleutelwoorde is skoon, maar `file` druk steeds `%PDF`. Behandel enige PDF wat ook die string `<w:WordDocument>` bevat as uiters verdag.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries misbruik die incremental update-funksie om 'n tweede **/Catalog** met kwaadwillige `/OpenAction` in te voeg terwyl die eerste, benign revision onderteken bly. Tools wat slegs die eerste xref-tabel inspekteer, word omseil.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – 'n kwesbare funksie in **CoolType.dll** kan vanaf ingebedde CIDType2-fonts bereik word, wat remote code execution met die gebruiker se privileges moontlik maak sodra 'n vervaardigde dokument oopgemaak word. Gepatch in APSB24-29, Mei 2024.<sup>[[3]](#references)</sup>

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

## Verdedigingswenke

1. **Pleister vinnig** – hou Acrobat/Reader op die nuutste Continuous track; die meeste RCE-kettings wat in die wild waargeneem word, benut n-day-kwesbaarhede wat maande tevore reggemaak is.
2. **Verwyder aktiewe inhoud by die gateway** – gebruik `pdfcpu sanitize` of `qpdf --qdf --remove-unreferenced` om JavaScript, ingebedde lêers en launch actions uit inkomende PDF's te verwyder.
3. **Content Disarm & Reconstruction (CDR)** – skakel PDF's op 'n sandbox-host na beelde (of PDF/A) om visuele getrouheid te behou terwyl aktiewe objekte weggegooi word.
4. **Blokkeer selde gebruikte kenmerke** – Reader se onderneming-“Enhanced Security”-instellings laat toe dat JavaScript, multimedia en 3D-rendering gedeaktiveer word.
5. **Gebruikersopleiding** – social engineering (faktuur- en CV-lokmiddels) bly die aanvanklike vektor; leer werknemers om verdagte aanhegsels aan IR aan te stuur.

## Verwysings

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
