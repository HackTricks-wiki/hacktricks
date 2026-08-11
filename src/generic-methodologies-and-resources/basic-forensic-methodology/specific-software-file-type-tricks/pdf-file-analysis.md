# PDF-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, kyk na:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te verberg, wat dit ’n fokuspunt vir CTF-forensika-uitdagings maak. Dit kombineer platteteks-elemente met binêre objekte, wat moontlik saamgepers of geënkripteer kan wees, en kan scripts in tale soos JavaScript of Flash insluit. Om PDF-struktuur te verstaan, kan ’n mens na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of gereedskap soos ’n teksredigeerder of ’n PDF-spesifieke redigeerder soos Origami gebruik.

Vir in-diepte ondersoek of manipulering van PDF’s is gereedskap soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Verborge data binne PDF’s kan op die volgende maniere versteek word:

- Onsigbare lae
- XMP-metadataformaat deur Adobe
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter prente of oorvleuelende prente
- Kommentaar wat nie vertoon word nie

Vir pasgemaakte PDF-analise kan Python-biblioteke soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om pasgemaakte ontleed-scripts te skep. Verder is die PDF se potensiaal vir die berging van verborge data so omvangryk dat hulpbronne soos die NSA-gids oor PDF-risiko’s en teenmaatreëls, hoewel dit nie meer by sy oorspronklike ligging aangebied word nie, steeds waardevolle insigte bied. ’n [Kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en ’n versameling [PDF-formaat-truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini kan verdere leesstof oor die onderwerp bied.<sup>[[4]](#references)[[5]](#references)</sup>

## Algemene kwaadwillige konstruksies

Aanvallers misbruik dikwels spesifieke PDF-objekte en aksies wat outomaties uitgevoer word wanneer die dokument oopgemaak word of daarmee interaksie plaasvind. Sleutelwoorde waarna gesoek moet word:

* **/OpenAction, /AA** – outomatiese aksies wat tydens oopmaak of spesifieke gebeurtenisse uitgevoer word.
* **/JS, /JavaScript** – ingebedde JavaScript (dikwels geobfuskereer of oor objekte verdeel).
* **/Launch, /SubmitForm, /URI, /GoToE** – lanseerders vir eksterne prosesse / URL’s.
* **/RichMedia, /Flash, /3D** – multimedia-objekte wat payloads kan versteek.
* **/EmbeddedFile /Filespec** – lêeraanhegsels (EXE, DLL, OLE, ens.).
* **/ObjStm, /XFA, /AcroForm** – objekstrome of vorms wat dikwels misbruik word om shell-code te versteek.
* **Inkrementele opdaterings** – veelvuldige %%EOF-merkers of ’n baie groot **/Prev**-offset kan aandui dat data ná ondertekening aangeheg is om AV te omseil.

Wanneer enige van die vorige tokens saam met verdagte strings (powershell, cmd.exe, calc.exe, base64, ens.) voorkom, verdien die PDF dieper analise.

---

## Kontrolelys vir statiese analise

Die voorbeelde hieronder gebruik die gedokumenteerde opdragreël-koppelvlakke van `pdf-parser.py`, qpdf en pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Bykomende nuttige projekte (aktief onderhou 2023-2025):
* **pdfcpu** – Go-biblioteek/CLI wat PDF’s kan valideer, dekripteer, uittrek, optimaliseer en manipuleer.<sup>[[9]](#references)</sup>
* **pdf-inspector** – blaaiergebaseerde visualiseerder wat die objekgrafiek en streams weergee.
* **PyMuPDF** – scriptbare Python-bindings vir die inspeksie van PDF’s en die weergawe van bladsye na rasterbeelde. Behandel die parser/renderer as ’n onbetroubare-lêer-aanvalsoppervlak en laat dit binne ’n toepaslik geïsoleerde analise-omgewing loop.<sup>[[8]](#references)</sup>

---

## Onlangse aanvalstegnieke (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC het ’n tegniek gerapporteer wat ’n Word-geskepte MHT-lêer met VBA-makro’s aan ’n PDF heg, terwyl die PDF magic behoue bly en dit ook in Word oopmaak. PDF-only-analisehulpmiddels, sandboxes of antivirus kan die makro mis omdat die kwaadwillige gedrag plaasvind wanneer dit as Word oopgemaak word; soek na die `<w:WordDocument>`-merker saam met ander MHT-aanwysers.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – aanvallers kan versteekte inhoud in ’n PDF plaas voordat dit onderteken word en dan ’n inkrementele opdatering byvoeg wat katalogus- of objekverwysings verander sodat viewers die versteekte inhoud vertoon terwyl die oorspronklike handtekening geldig bly. Die tegniek kan viewers omseil wat sulke opdaterings as skadeloos klassifiseer.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe beoordeel hierdie kritieke kwesbaarheid as ’n use-after-free wat tot arbitrêre kode-uitvoering kan lei; APSB24-29 is op 14 Mei 2024 gepubliseer.<sup>[[3]](#references)</sup>

---

## Vinnige YARA-reëlsjabloon
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

1. **Patch vinnig** – hou Acrobat/Reader op die nuutste Continuous track; die meeste RCE chains wat in die wild waargeneem word, benut n-day vulnerabilities wat maande tevore reggestel is.
2. **Verwyder aktiewe inhoud by die gateway** – gebruik ’n doelgeboude, beleidsbeheerde sanitizer- of CDR-produk wat JavaScript, ingebedde lêers, launch actions, vorms en multimedia uitdruklik verwyder. `qpdf --qdf` maak PDF-objects makliker om te inspekteer, terwyl pdfcpu validation- en manipulation-features verskaf; geen van die twee commands alleen bewys dat aktiewe inhoud verwyder is nie.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – skakel PDFs op ’n sandbox host na beelde (of PDF/A) om visuele getrouheid te behou terwyl aktiewe objects weggegooi word.
4. **Blokkeer selde gebruikte features** – Reader se “Enhanced Security”-instellings vir ondernemings laat toe dat JavaScript, multimedia en 3D-rendering gedeaktiveer word.
5. **Gebruikersopleiding** – social engineering (faktuur- en CV-lokmiddels) bly die aanvanklike vector; leer werknemers om verdagte attachments na IR aan te stuur.

## References

- [1] [Forensics CTF Veldgids](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Opsporingsomseiling deur ’n kwaadwillige Word-lêer in ’n PDF-lêer in te bed](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update beskikbaar vir Adobe Acrobat en Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF-formaat-truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Verberging en vervanging van inhoud in getekende PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF-tutoriaal](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
