# Analiza PDF datoteka

{{#include ../../../banners/hacktricks-training.md}}

**Za dodatne detalje pogledajte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF format je poznat po svojoj složenosti i mogućnosti prikrivanja podataka, zbog čega je često u fokusu CTF forensics izazova. Kombinuje elemente običnog teksta sa binarnim objektima, koji mogu biti kompresovani ili šifrovani, i može da sadrži skripte napisane u jezicima kao što su JavaScript ili Flash. Za razumevanje strukture PDF-a može se koristiti [uvodni materijal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa ili alati poput text editora ili PDF-specific editora kao što je Origami.

Za detaljno istraživanje ili manipulisanje PDF datotekama dostupni su alati poput [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Skriveni podaci u PDF datotekama mogu se nalaziti u:

- Nevidljivim slojevima
- XMP metadata formatu kompanije Adobe
- Inkrementalnim generacijama
- Tekstu iste boje kao pozadina
- Tekstu iza slika ili slikama koje se preklapaju
- Komentarima koji se ne prikazuju

Za prilagođenu analizu PDF datoteka mogu se koristiti Python biblioteke poput [PeepDF](https://github.com/jesparza/peepdf) za izradu prilagođenih parsing skripti. Pored toga, potencijal PDF-a za čuvanje skrivenih podataka toliko je velik da resursi poput NSA vodiča o rizicima i countermeasures za PDF, iako više nije hostovan na prvobitnoj lokaciji, i dalje pružaju korisne uvide. [Kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) i zbirka [PDF format trikova](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autora Ange Albertinija mogu poslužiti za dodatno čitanje o ovoj temi.<sup>[[4]](#references)[[5]](#references)</sup>

## Uobičajene zlonamerne konstrukcije

Napadači često zloupotrebljavaju određene PDF objekte i akcije koje se automatski izvršavaju kada se dokument otvori ili kada korisnik stupi u interakciju sa njim. Ključne reči koje treba tražiti:

* **/OpenAction, /AA** – automatske akcije koje se izvršavaju pri otvaranju ili tokom određenih događaja.
* **/JS, /JavaScript** – ugrađeni JavaScript (često obfuskiran ili podeljen između objekata).
* **/Launch, /SubmitForm, /URI, /GoToE** – pokretači eksternih procesa / URL-ova.
* **/RichMedia, /Flash, /3D** – multimedijalni objekti koji mogu sakrivati payloads.
* **/EmbeddedFile /Filespec** – priložene datoteke (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – tokovi objekata ili obrasci koji se često zloupotrebljavaju za skrivanje shell-code-a.
* **Inkrementalna ažuriranja** – više %%EOF oznaka ili veoma veliki **/Prev** offset mogu ukazivati na podatke dodate nakon potpisivanja radi zaobilaženja AV-a.

Kada se neki od prethodnih tokena pojavi zajedno sa sumnjivim stringovima (powershell, cmd.exe, calc.exe, base64 itd.), PDF zahteva detaljniju analizu.

---

## Podsetnik za statičku analizu

Primeri u nastavku koriste dokumentovane interfejse komandne linije `pdf-parser.py`, qpdf i pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Dodatni korisni projekti (aktivno održavani 2023–2025):
* **pdfcpu** – Go biblioteka/CLI alat koji može da validira, dešifruje, izdvaja, optimizuje i manipuliše PDF datotekama.<sup>[[9]](#references)</sup>
* **pdf-inspector** – vizuelizator zasnovan na browseru koji prikazuje graf objekata i streams.
* **PyMuPDF** – Python bindings koji podržavaju scripting za inspekciju PDF datoteka i renderovanje stranica u raster slike. Parser/renderer tretirajte kao attack surface za nepouzdane datoteke i pokrenite ga unutar odgovarajuće izolovanog analysis environment-a.<sup>[[8]](#references)</sup>

---

## Nove attack techniques (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC je prijavio tehniku koja dodaje MHT datoteku kreiranu u Wordu, sa VBA macros, u PDF, pri čemu PDF magic ostaje očuvan, a datoteka se istovremeno otvara i u Wordu. PDF-only analysis tools, sandbox-i ili antivirus mogu da previde macro zato što se malicious behavior izvršava kada se datoteka otvori kao Word; potražite marker `<w:WordDocument>` zajedno sa drugim MHT indikatorima.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – napadači mogu da postave skriveni sadržaj u PDF pre nego što se on potpiše, a zatim dodaju incremental update koji menja catalog ili object references tako da viewer-i prikazuju skriveni sadržaj, dok originalni potpis ostaje validan. Ova tehnika može da zaobiđe viewer-e koji takve update-e klasifikuju kao bezopasne.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe ovu kritičnu ranjivost ocenjuje kao use-after-free, koja može dovesti do arbitrary code execution; APSB24-29 je objavljen 14. maja 2024.<sup>[[3]](#references)</sup>

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

## Saveti za odbranu

1. **Brzo instalirajte zakrpe** – održavajte Acrobat/Reader na najnovijoj Continuous verziji; većina RCE lanaca uočenih u wild koristi n-day ranjivosti koje su ispravljene nekoliko meseci ranije.
2. **Uklonite aktivni sadržaj na gateway-u** – koristite namenski sanitizer sa kontrolom pravila ili CDR proizvod koji eksplicitno uklanja JavaScript, ugrađene datoteke, launch actions, forms i multimedia. `qpdf --qdf` olakšava pregled PDF objekata, dok pdfcpu pruža funkcije za validaciju i manipulaciju; nijedna od ovih komandi sama po sebi nije dokaz da je aktivni sadržaj uklonjen.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – konvertujte PDF-ove u slike (ili PDF/A) na sandbox hostu kako biste očuvali vizuelnu vernost i istovremeno odbacili aktivne objekte.
4. **Blokirajte retko korišćene funkcije** – enterprise „Enhanced Security“ podešavanja u Reader-u omogućavaju onemogućavanje JavaScript-a, multimedia i 3D renderovanja.
5. **Edukacija korisnika** – social engineering (mamci sa fakturama i biografijama) i dalje predstavlja početni vektor; obučite zaposlene da prosleđuju sumnjive priloge timu za IR.

## References

- [1] [Vodič kroz forenziku za CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Zaobilaženje detekcije ugrađivanjem zlonamerne Word datoteke u PDF datoteku](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Dostupno je bezbednosno ažuriranje za Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trikovi PDF formata](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Sakrivanje i zamena sadržaja u potpisanim PDF-ovima](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF vodič](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf opcije komandne linije](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
