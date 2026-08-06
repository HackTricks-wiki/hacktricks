# Analiza PDF datoteka

{{#include ../../../banners/hacktricks-training.md}}

**Za dodatne detalje pogledajte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

PDF format je poznat po svojoj složenosti i mogućnosti skrivanja podataka, zbog čega predstavlja čestu temu CTF forensics izazova. Kombinuje elemente običnog teksta sa binarnim objektima, koji mogu biti kompresovani ili šifrovani, a može da sadrži i skripte napisane u jezicima kao što su JavaScript ili Flash. Za razumevanje strukture PDF-a možete pogledati [uvodni materijal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa ili koristiti alate kao što su text editor ili editor namenjen PDF-u, poput alata Origami.

Za detaljno istraživanje ili izmenu PDF-ova dostupni su alati kao što su [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Skriveni podaci u PDF-ovima mogu se nalaziti u:

- Nevidljivim slojevima
- XMP metadata formatu kompanije Adobe
- Inkrementalnim generacijama
- Tekstu iste boje kao pozadina
- Tekstu iza slika ili slikama koje se preklapaju
- Komentarima koji se ne prikazuju

Za prilagođenu analizu PDF-ova mogu se koristiti Python biblioteke kao što je [PeepDF](https://github.com/jesparza/peepdf), za izradu prilagođenih parsing skripti. Pored toga, mogućnosti PDF-a za čuvanje skrivenih podataka toliko su široke da resursi poput NSA vodiča o rizicima i countermeasures za PDF, iako više nije hostovan na originalnoj lokaciji, i dalje pružaju korisne uvide. [Kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) i zbirka [trikova za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md) autora Angea Albertinija mogu poslužiti za dalje čitanje o ovoj temi.<sup>[[4]](#references)[[5]](#references)</sup>

## Uobičajene zlonamerne konstrukcije

Napadači često zloupotrebljavaju određene PDF objekte i actions koji se automatski izvršavaju kada se dokument otvori ili kada korisnik stupi u interakciju sa njim. Ključne reči koje treba tražiti:

* **/OpenAction, /AA** – automatske actions koje se izvršavaju pri otvaranju ili tokom određenih događaja.
* **/JS, /JavaScript** – ugrađeni JavaScript (često obfuskovan ili podeljen između objekata).
* **/Launch, /SubmitForm, /URI, /GoToE** – pokretači eksternih procesa / URL-ova.
* **/RichMedia, /Flash, /3D** – multimedijalni objekti koji mogu skrivati payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – object streams ili forms koji se često zloupotrebljavaju za skrivanje shell-code-a.
* **Incremental updates** – više `%%EOF` markera ili veoma veliki **/Prev** offset mogu ukazivati na podatke dodate nakon potpisivanja radi zaobilaženja AV-a.

Kada se bilo koji od prethodnih tokena pojavi zajedno sa sumnjivim stringovima (powershell, cmd.exe, calc.exe, base64 itd.), PDF zaslužuje detaljniju analizu.

---

## Cheat-sheet za static analysis
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
Dodatni korisni projekti (aktivno održavani 2023–2025):
* **pdfcpu** – Go biblioteka/CLI koja može da izvršava *lint*, *decrypt*, *extract*, *compress* i *sanitize* nad PDF dokumentima.
* **pdf-inspector** – vizuelizator zasnovan na browseru koji prikazuje graf objekata i stream-ove.
* **PyMuPDF (fitz)** – skriptabilni Python engine koji može bezbedno da renderuje stranice u slike radi aktiviranja ugrađenog JS-a u ojačanom sandbox-u.

---

## Nove attack tehnike (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC je uočio aktere pretnji koji dodaju Word dokument zasnovan na MHT-u, sa VBA macro-ima, nakon poslednjeg **%%EOF**, čime nastaje fajl koji je istovremeno validan PDF i validan DOC. AV engine-i koji parsiraju samo PDF sloj propuštaju macro. Statičke PDF ključne reči izgledaju čisto, ali `file` i dalje ispisuje `%PDF`. Svaki PDF koji takođe sadrži string `<w:WordDocument>` treba smatrati veoma sumnjivim.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – adversaries zloupotrebljavaju funkciju incremental update da ubace drugi **/Catalog** sa malicioznim `/OpenAction`, dok benigni prvi revision ostaje potpisan. Alati koji proveravaju samo prvu xref tabelu mogu biti zaobiđeni.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – ranjiva funkcija u **CoolType.dll** može biti pozvana iz ugrađenih CIDType2 fontova, što omogućava remote code execution sa privilegijama korisnika nakon otvaranja posebno izrađenog dokumenta. Ispravljeno u APSB24-29, u maju 2024.<sup>[[3]](#references)</sup>

---

## Brzi šablon YARA pravila
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

## Odbrambeni saveti

1. **Brzo primenjujte zakrpe** – održavajte Acrobat/Reader na najnovijem Continuous track-u; većina RCE lanaca primećenih u divljini koristi n-day ranjivosti zakrpene pre više meseci.
2. **Uklonite aktivni sadržaj na gateway-u** – koristite `pdfcpu sanitize` ili `qpdf --qdf --remove-unreferenced` da biste iz dolaznih PDF-ova uklonili JavaScript, ugrađene datoteke i launch actions.
3. **Content Disarm & Reconstruction (CDR)** – konvertujte PDF-ove u slike (ili PDF/A) na sandbox hostu kako biste očuvali vizuelnu vernost i istovremeno odbacili aktivne objekte.
4. **Blokirajte retko korišćene funkcije** – enterprise postavke „Enhanced Security“ u Reader-u omogućavaju onemogućavanje JavaScript-a, multimedije i 3D rendering-a.
5. **Edukacija korisnika** – social engineering (mamci u obliku faktura i biografija) i dalje predstavlja početni vektor; obučite zaposlene da proslede sumnjive priloge IR timu.

## Reference

- [1] [Vodič kroz Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – zaobilaženje detekcije ugrađivanjem zlonamerne Word datoteke u PDF datoteku](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – dostupno je bezbednosno ažuriranje za Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trikovi PDF formata](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
