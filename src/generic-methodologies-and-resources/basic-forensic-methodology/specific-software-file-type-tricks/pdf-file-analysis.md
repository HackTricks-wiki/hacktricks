# PDF-lêeranalise

{{#include ../../../banners/hacktricks-training.md}}

**Vir verdere besonderhede, kyk:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Die PDF-formaat is bekend vir sy kompleksiteit en potensiaal om data te verberg, wat dit 'n fokuspunt maak vir CTF forensiese uitdagings. Dit kombineer teks-elemente met binêre objekte, wat gecomprimeer of versleuteld kan wees, en kan skripte in tale soos JavaScript of Flash insluit. Om die PDF-struktuur te verstaan, kan 'n mens na Didier Stevens se [inleidende materiaal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) verwys, of gereedskap soos 'n teksredigeerder of 'n PDF-spesifieke redigeerder soos Origami gebruik.

Vir diepgaande verkenning of manipulasie van PDFs, is gereedskap soos [qpdf](https://github.com/qpdf/qpdf) en [Origami](https://github.com/mobmewireless/origami-pdf) beskikbaar. Verborge data binne PDFs kan verborge wees in:

- Onsigbare lae
- XMP-metadataformaat deur Adobe
- Inkrementele generasies
- Teks met dieselfde kleur as die agtergrond
- Teks agter beelde of oorvleuelende beelde
- Nie-vertande kommentaar

Vir pasgemaakte PDF-analise kan Python-biblioteke soos [PeepDF](https://github.com/jesparza/peepdf) gebruik word om op maat gemaakte parsingskripte te skep. Verder is die PDF se potensiaal vir verborge datastoor so groot dat hulpbronne soos die NSA-gids oor PDF-risiko's en teenmaatreëls, hoewel nie meer op sy oorspronklike plek gehos te word nie, steeds waardevolle insigte bied. 'n [kopie van die gids](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) en 'n versameling van [PDF-formaat truuks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) deur Ange Albertini kan verdere leesstof oor die onderwerp bied.

## Algemene Kwaadwillige Konstruksies

Aanvallers misbruik dikwels spesifieke PDF-objekte en aksies wat outomaties uitgevoer word wanneer die dokument geopen of mee geinteraksie word. Sleutelwoorde wat die moeite werd is om na te soek:

* **/OpenAction, /AA** – outomatiese aksies wat uitgevoer word by opening of op spesifieke gebeurtenisse.
* **/JS, /JavaScript** – ingebedde JavaScript (dikwels obfuskeer of oor verskillende objekte verdeel).
* **/Launch, /SubmitForm, /URI, /GoToE** – eksterne proses / URL-lancerings.
* **/RichMedia, /Flash, /3D** – multimedia-objekte wat payloads kan verberg.
* **/EmbeddedFile /Filespec** – lêer-aanhegsels (EXE, DLL, OLE, ens.).
* **/ObjStm, /XFA, /AcroForm** – objekstrome of vorms wat algemeen misbruik word om shell-code te verberg.
* **Inkrementele opdaterings** – verskeie %%EOF-merkers of 'n baie groot **/Prev** offset kan aandui dat data na ondertekening bygevoeg is om AV te omseil.

Wanneer enige van die vorige tokens saam met verdagte stringe (powershell, cmd.exe, calc.exe, base64, ens.) verskyn, verdien die PDF 'n dieper analise.

---

## Statiese analise spiekbrief
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
Aanvullende nuttige projekte (aktief onderhoude 2023-2025):
* **pdfcpu** – Go biblioteek/CLI wat in staat is om *lint*, *dekripteer*, *onttrek*, *komprimeer* en *skoonmaak* PDFs.
* **pdf-inspector** – blaai-gebaseerde visualiseerder wat die objekgrafiek en strome weergee.
* **PyMuPDF (fitz)** – skripbare Python-enjin wat bladsye veilig na beelde kan weergee om ingebedde JS in 'n versterkte sandkas te ontplof.

---

## Onlangse aanvalstegnieke (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC het bedreigingsakteurs waargeneem wat 'n MHT-gebaseerde Word-dokument met VBA-makros by die finale **%%EOF** voeg, wat 'n lêer produseer wat beide 'n geldige PDF en 'n geldige DOC is. AV enjin wat net die PDF-laag ontleed, mis die makro. Statiese PDF-sleutels is skoon, maar `file` druk steeds `%PDF`. Behandel enige PDF wat ook die string `<w:WordDocument>` bevat as hoogs verdag.
* **Shadow-incremental updates (2024)** – teenstanders misbruik die inkrementele opdateringsfunksie om 'n tweede **/Catalog** met kwaadwillige `/OpenAction` in te voeg terwyl die goedaardige eerste weergawe onderteken bly. Gereedskap wat net die eerste xref-tabel inspekteer, word omseil.
* **Font parsing UAF-ketting – CVE-2024-30284 (Acrobat/Reader)** – 'n kwesbare **CoolType.dll** funksie kan bereik word vanaf ingebedde CIDType2 skrifte, wat afstandkode-uitvoering met die voorregte van die gebruiker moontlik maak sodra 'n vervaardigde dokument geopen word. Gepatch in APSB24-29, Mei 2024.

---

## YARA vinnige reël sjabloon
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

## Verdedigende wenke

1. **Patches vinnig** – hou Acrobat/Reader op die nuutste Continue spoor; die meeste RCE-kettings wat in die natuur waargeneem is, benut n-dag kwesbaarhede wat maande vroeër reggestel is.
2. **Verwyder aktiewe inhoud by die poort** – gebruik `pdfcpu sanitize` of `qpdf --qdf --remove-unreferenced` om JavaScript, ingebedde lêers en lanseer aksies uit inkomende PDF's te verwyder.
3. **Inhoud Ontwapening & Heropbou (CDR)** – omskep PDF's na beelde (of PDF/A) op 'n sandbox-gasheer om visuele getrouheid te behou terwyl aktiewe voorwerpe weggegooi word.
4. **Blokkeer selde-gebruikte funksies** – ondernemings “Verbeterde Sekuriteit” instellings in Reader laat die deaktivering van JavaScript, multimedia en 3D-rendering toe.
5. **Gebruiker opvoeding** – sosiale ingenieurswese (faktuur & CV lokmiddels) bly die aanvanklike vektor; leer werknemers om verdagte aanhangsels na IR te stuur.

## Verwysings

* JPCERT/CC – “MalDoc in PDF – Detectie omseiling deur 'n kwaadwillige Word-lêer in 'n PDF-lêer in te sluit” (Aug 2023)
* Adobe – Sekuriteitsopdatering vir Acrobat en Reader (APSB24-29, Mei 2024)


{{#include ../../../banners/hacktricks-training.md}}
