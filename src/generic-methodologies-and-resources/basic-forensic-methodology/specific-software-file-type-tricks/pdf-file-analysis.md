# PDF-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, kyk na:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te verberg, wat dit ’n fokuspunt vir CTF-forensiese uitdagings maak. Dit kombineer gewone teks met binêre objek­te, wat moontlik saamgepers of geënkripteer is, en kan skrifte in tale soos JavaScript of Flash insluit. Om die PDF-struktuur te verstaan, kan jy na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of nutsgoed soos ’n teksredigeerder of ’n PDF-spesifieke redigeerder soos Origami gebruik.

Vir deeglike ondersoek of manipulasie van PDF’s is nutsgoed soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Versteekte data in PDF’s kan weggesteek wees in:

- Onsigbare lae
- Adobe se XMP-metadataformaat
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter beelde of oorvleuelende beelde
- Kommentaar wat nie vertoon word nie

Vir pasgemaakte PDF-analise kan Python-biblioteke soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om pasgemaakte ontledingskrifte te skryf. Die PDF se potensiaal om versteekte data te stoor, is boonop so groot dat bronne soos die NSA-gids oor PDF-risiko’s en teenmaatreëls steeds waardevolle insigte bied, hoewel dit nie meer op die oorspronklike plek aangebied word nie. ’n [Kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en ’n versameling [PDF-formattruuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini bied verdere leesstof oor die onderwerp.<sup>[[4]](#references)[[5]](#references)</sup>

## Algemene kwaadwillige konstruksies

Aanvallers misbruik dikwels spesifieke PDF-objekte en -aksies wat outomaties uitgevoer word wanneer die dokument oopgemaak word of daarmee gewerk word. Sleutelwoorde waarna jy kan soek:

* **/OpenAction, /AA** – outomatiese aksies wat uitgevoer word wanneer die dokument oopgemaak word of tydens spesifieke gebeurtenisse.
* **/JS, /JavaScript** – ingebedde JavaScript (dikwels verduister of oor verskeie objekte verdeel).
* **/Launch, /SubmitForm, /URI, /GoToE** – lanseerders vir eksterne prosesse / URL’s.
* **/RichMedia, /Flash, /3D** – multimedia-objekte wat loonvragte kan versteek.
* **/EmbeddedFile /Filespec** – lêeraanhegsels (EXE, DLL, OLE, ens.).
* **/ObjStm, /XFA, /AcroForm** – objekstrome of vorms wat dikwels misbruik word om shell-code te versteek.
* **Inkrementele opdaterings** – veelvuldige %%EOF-merkers of ’n baie groot **/Prev**-verskuiwing kan aandui dat data ná ondertekening aangeheg is om AV te omseil.

Wanneer enige van die voorafgaande tekens saam met verdagte stringe (powershell, cmd.exe, calc.exe, base64, ens.) voorkom, verdien die PDF verdere ontleding.

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

Pixelering van ’n prent binne ’n PDF verwyder nie die onderliggende pixels nie. As ’n leesbare dokument lyk asof dit ’n geloofsbrief op hierdie manier verberg, onttrek die ingebedde prent vir gemagtigde vanlyn inspeksie; die resultaat hang van die prent en ’n geskikte verwysing af, en visuele herstel is nie gewaarborg nie. ’n Herstelde wagwoord moet steeds afsonderlik teen die rekening waarvan die voorregte saak maak, geverifieer word. Moenie ’n PDF-onttrekkings- of prentherstelstap by ’n roetinegasheerenumerasieskandering insluit nie.

Bykomende nuttige projekte (aktief onderhou in 2023-2025):
* **pdfcpu** – Go-biblioteek/CLI wat PDF’s kan valideer, dekripteer, onttrek, optimaliseer en manipuleer.<sup>[[9]](#references)</sup>
* **pdf-inspector** – blaaiergebaseerde visualiseerder wat die objekgrafiek en strome weergee.
* **PyMuPDF** – skripbare Python-bindings om PDF’s te inspekteer en bladsye as rasterprente weer te gee. Behandel die ontleder/weergawe-enjin as ’n aanvalsvlak vir onbetroubare lêers en laat dit binne ’n toepaslik geïsoleerde analise-omgewing loop.<sup>[[8]](#references)</sup>

---

## Onlangse aanvalstegnieke (2023-2025)

* **MalDoc in PDF-polyglot (2023)** – JPCERT/CC het ’n tegniek gerapporteer wat ’n Word-geskepte MHT-lêer met VBA-makro’s aan ’n PDF heg, sodat die PDF magic behoue bly, maar die lêer ook in Word oopmaak. PDF-ontledingsnutsgoed, sandboxes of antivirus kan die makro miskyk omdat die kwaadwillige gedrag plaasvind wanneer die lêer as Word-dokument oopgemaak word; soek na die `<w:WordDocument>`-merker saam met ander MHT-aanwysers.<sup>[[2]](#references)</sup>
* **Shadow-aanvalle op ondertekende PDF’s** – aanvallers kan versteekte inhoud in ’n PDF plaas voordat dit onderteken word, en dan ’n inkrementele opdatering byvoeg wat katalogus- of objekverwysings verander sodat kykers die versteekte inhoud vertoon terwyl die oorspronklike handtekening geldig bly. Die tegniek kan kykers ontduik wat sulke opdaterings as onskadelik klassifiseer.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe beoordeel hierdie kritieke kwesbaarheid as ’n use-after-free wat tot arbitrêre kode-uitvoering kan lei; APSB24-29 is op 14 Mei 2024 gepubliseer.<sup>[[3]](#references)</sup>

---

## YARA-vinnigreël-sjabloon

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

## Defensive wenke

1. **Pas pleisters vinnig toe** – hou Acrobat/Reader op die nuutste Continuous-kanaal; die meeste RCE-kettings wat in die natuur waargeneem is, benut n-day-kwesbaarhede wat maande tevore reggemaak is.
2. **Verwyder aktiewe inhoud by die gateway** – gebruik ’n doelgeboude, beleidsbeheerde sanitiseerder of CDR-produk wat JavaScript, ingebedde lêers, launch actions, vorms en multimedia uitdruklik verwyder. `qpdf --qdf` maak PDF-objekte makliker om te inspekteer, terwyl pdfcpu validerings- en manipulasiekenmerke bied; nie een van die opdragte alleen bewys dat aktiewe inhoud verwyder is nie.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – skakel PDF’s op ’n sandbox-gasheer na beelde (of PDF/A) om, sodat die visuele getrouheid behoue bly terwyl aktiewe objekte weggegooi word.
4. **Blokkeer kenmerke wat selde gebruik word** – Reader se ondernemingsinstellings vir “Enhanced Security” laat toe dat JavaScript, multimedia en 3D-weergawe gedeaktiveer word.
5. **Gebruikersopleiding** – social engineering (lokmiddels met fakture en CV’s) bly die aanvanklike aanvalvektor; leer werknemers om verdagte aanhegsels na IR aan te stuur.

## References

- [1] [Forensiese CTF-veldgids](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Omseiling van opsporing deur ’n kwaadwillige Word-lêer in ’n PDF-lêer in te bed](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe-sekuriteitsbulletin – Sekuriteitsopdatering beskikbaar vir Adobe Acrobat en Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF-formaattruuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Skadu-aanvalle: Verberging en vervanging van inhoud in ondertekende PDF’s](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF-tutoriaal](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf-opdragreëlopsies](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
