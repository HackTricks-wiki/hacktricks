# PDF-lêeranalise

**Vir verdere besonderhede, kyk na:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te versteek, wat dit 'n fokuspunt vir CTF-forensika-uitdagings maak. Dit kombineer plain-text-elemente met binêre objekte, wat moontlik saamgepers of geënkripteer kan wees, en kan scripts in tale soos JavaScript of Flash insluit. Om die PDF-struktuur te verstaan, kan 'n mens na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of tools soos 'n teksredigeerder of 'n PDF-spesifieke redigeerder soos Origami gebruik.

Vir diepgaande ondersoek of manipulering van PDFs is tools soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Versteekte data binne PDFs kan in die volgende versteek wees:

- Onsigbare lae
- XMP-metadataformaat deur Adobe
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter beelde of oorvleuelende beelde
- Kommentaar wat nie vertoon word nie

Vir pasgemaakte PDF-analise kan Python-biblioteke soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om pasgemaakte parsing-scripts te skep. Verder is die PDF se potensiaal vir die berging van versteekte data so omvangryk dat hulpbronne soos die NSA-gids oor PDF-risiko's en teenmaatreëls, hoewel dit nie meer by sy oorspronklike ligging gehuisves word nie, steeds waardevolle insigte bied. 'n [Kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en 'n versameling van [PDF-formaat-truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini kan verdere leesstof oor die onderwerp bied.<sup>[[4]](#references)[[5]](#references)</sup>

## Algemene kwaadwillige konstruksies

Aanvallers misbruik dikwels spesifieke PDF-objekte en aksies wat outomaties uitgevoer word wanneer die dokument oopgemaak of daarmee interaksie gehad word. Sleutelwoorde waarna dit die moeite werd is om te soek:

* **/OpenAction, /AA** – outomatiese aksies wat by oopmaak of tydens spesifieke gebeurtenisse uitgevoer word.
* **/JS, /JavaScript** – ingebedde JavaScript (dikwels geobfuskeer of oor objekte versprei).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers vir eksterne prosesse / URLs.
* **/RichMedia, /Flash, /3D** – multimedia-objekte wat payloads kan versteek.
* **/EmbeddedFile /Filespec** – lêeraanhegsels (EXE, DLL, OLE, ens.).
* **/ObjStm, /XFA, /AcroForm** – objekstrome of vorms wat algemeen misbruik word om shell-code te versteek.
* **Inkrementele opdaterings** – veelvuldige %%EOF-merkers of 'n baie groot **/Prev**-offset kan aandui dat data ná ondertekening aangeheg is om AV te omseil.

Wanneer enige van die vorige tokens saam met verdagte strings (powershell, cmd.exe, calc.exe, base64, ens.) verskyn, verdien die PDF diepgaande ontleding.

---

## Cheat-sheet vir statiese analise

Die voorbeelde hieronder gebruik die gedokumenteerde command-line interfaces van `pdf-parser.py`, qpdf en pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Bykomende nuttige projects (aktief onderhou 2023-2025):
* **pdfcpu** – Go-biblioteek/CLI wat PDFs kan valideer, dekripteer, onttrek, optimaliseer en manipuleer.<sup>[[9]](#references)</sup>
* **pdf-inspector** – blaaiergebaseerde visualiseerder wat die objekgrafiek en streams weergee.
* **PyMuPDF** – scriptbare Python-bindings vir die inspeksie van PDFs en die weergawe van bladsye na rasterbeelde. Behandel die parser/renderer as 'n onbetroubare-lêer-aanvalsoppervlak en laat dit binne 'n toepaslik geïsoleerde analysis environment loop.<sup>[[8]](#references)</sup>

---

## Onlangse aanvalstegnieke (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC het 'n tegniek gerapporteer wat 'n Word-geskepte MHT-lêer met VBA-makro's aan 'n PDF heg, terwyl die PDF magic behoue bly en die lêer ook in Word oopmaak. PDF-only analysis tools, sandboxes of antivirus kan die makro mis omdat die malicious behavior plaasvind wanneer dit as Word oopgemaak word; soek na die `<w:WordDocument>`-merker saam met ander MHT-indikators.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – aanvallers kan versteekte inhoud in 'n PDF plaas voordat dit onderteken word, en dan 'n incremental update byvoeg wat catalogus- of objekverwysings verander sodat viewers die versteekte inhoud vertoon terwyl die oorspronklike handtekening geldig bly. Die tegniek kan viewers ontduik wat sulke updates as harmless klassifiseer.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe beoordeel hierdie kritieke kwesbaarheid as 'n use-after-free wat tot arbitrary code execution kan lei; APSB24-29 is op 14 Mei 2024 gepubliseer.<sup>[[3]](#references)</sup>

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

1. **Pleisters vinnig installeer** – hou Acrobat/Reader op die nuutste Continuous-track; die meeste RCE-kettings wat in die wild waargeneem word, buit n-day-kwesbaarhede uit wat maande tevore reggestel is.
2. **Verwyder aktiewe inhoud by die gateway** – gebruik ’n doelgeboude, beleidbeheerde sanitizer- of CDR-produk wat JavaScript, ingebedde lêers, launch actions, forms en multimedia uitdruklik verwyder. `qpdf --qdf` maak PDF-objekte makliker om te inspekteer, terwyl pdfcpu validation- en manipulation-kenmerke bied; geen van die opdragte alleen is bewys dat aktiewe inhoud verwyder is nie.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – omskep PDFs na beelde (of PDF/A) op ’n sandbox-host om visuele getrouheid te behou terwyl aktiewe objekte weggegooi word.
4. **Blokkeer kenmerke wat selde gebruik word** – enterprise-“Enhanced Security”-instellings in Reader laat toe dat JavaScript, multimedia en 3D-rendering gedeaktiveer word.
5. **Gebruikersopleiding** – social engineering (invoice- en resume-lokmiddels) bly die aanvanklike vektor; leer werknemers om verdagte aanhangsels aan IR aan te stuur.

## References

- [1] [Forensics CTF-veldhandleiding](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass deur ’n malicious Word-lêer in ’n PDF-lêer in te bed](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update beskikbaar vir Adobe Acrobat en Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopie van die handleiding](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF-formaat-truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Versteek en vervang inhoud in ondertekende PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF-tutoriaal](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf-opdragreëlopsies](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
