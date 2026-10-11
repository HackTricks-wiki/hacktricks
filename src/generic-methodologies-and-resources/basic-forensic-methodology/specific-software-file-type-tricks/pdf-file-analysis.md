# Analiza PDF datoteka

{{#include ../../../banners/hacktricks-training.md}}

**Za više detalja pogledajte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

PDF format je poznat po složenosti i mogućnosti skrivanja podataka, zbog čega je često u fokusu forenzičkih CTF izazova. Kombinuje elemente običnog teksta sa binarnim objektima, koji mogu biti kompresovani ili šifrovani, a može sadržati i skripte na jezicima kao što su JavaScript ili Flash. Da biste razumeli strukturu PDF-a, možete pogledati [uvodni materijal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa ili koristiti alate poput uređivača teksta ili uređivača namenjenog PDF-u, kao što je Origami.

Za detaljno istraživanje ili menjanje PDF-ova dostupni su alati kao što su [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Skriveni podaci u PDF-ovima mogu se nalaziti u:

- Nevidljivim slojevima
- XMP formatu metapodataka kompanije Adobe
- Inkrementalnim generacijama
- Tekstu iste boje kao pozadina
- Tekstu iza slika ili slikama koje se preklapaju
- Komentarima koji se ne prikazuju

Za prilagođenu analizu PDF-a mogu se koristiti Python biblioteke kao što je [PeepDF](https://github.com/jesparza/peepdf) za izradu namenskih skripti za parsiranje. Osim toga, potencijal PDF-a za skrivanje podataka toliko je velik da resursi poput NSA vodiča o rizicima i protivmerama za PDF, iako više nije dostupan na prvobitnoj lokaciji, i dalje pružaju korisne uvide. [Kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) i zbirka [trikova za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md) Angea Albertinija mogu poslužiti za dodatno čitanje o ovoj temi.<sup>[[4]](#references)[[5]](#references)</sup>

## Uobičajene zlonamerne konstrukcije

Napadači često zloupotrebljavaju određene PDF objekte i radnje koje se automatski izvršavaju kada se dokument otvori ili kada se stupi u interakciju s njim. Ključne reči koje vredi tražiti:

* **/OpenAction, /AA** – automatske radnje koje se izvršavaju pri otvaranju ili tokom određenih događaja.
* **/JS, /JavaScript** – ugrađeni JavaScript (često zamaskiran ili podeljen između objekata).
* **/Launch, /SubmitForm, /URI, /GoToE** – pokretači spoljašnjih procesa ili URL-ova.
* **/RichMedia, /Flash, /3D** – multimedijalni objekti koji mogu skrivati payload.
* **/EmbeddedFile /Filespec** – priložene datoteke (EXE, DLL, OLE itd.).
* **/ObjStm, /XFA, /AcroForm** – tokovi objekata ili obrasci koji se često zloupotrebljavaju za skrivanje shell-code-a.
* **Inkrementalna ažuriranja** – više oznaka %%EOF ili veoma veliki pomak **/Prev** mogu ukazivati na to da su podaci dodati nakon potpisivanja radi zaobilaženja AV-a.

Kada se bilo koji od prethodnih tokena pojavi zajedno sa sumnjivim stringovima (powershell, cmd.exe, calc.exe, base64 itd.), PDF treba detaljnije analizirati.

---

## Podsetnik za statičku analizu

Primeri u nastavku koriste dokumentovane komandne interfejse `pdf-parser.py`, qpdf i pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Pikselizovanje slike unutar PDF-a ne uklanja piksele koji se nalaze ispod nje. Ako se čini da čitljiv dokument na ovaj način skriva akreditive, izdvojite ugrađenu sliku radi ovlašćene offline provere; rezultat zavisi od slike i odgovarajuće reference, a vizuelna rekonstrukcija nije zagarantovana. I dalje je potrebno zasebno proveriti da li oporavljena lozinka važi za nalog čije su privilegije bitne. Nemojte uključivati izdvajanje iz PDF-a ili oporavak slike u rutinsko skeniranje hostova.

Dodatni korisni projekti (aktivno održavani 2023–2025):
* **pdfcpu** – Go biblioteka/CLI za validaciju, dešifrovanje, izdvajanje, optimizaciju i izmenu PDF-ova.<sup>[[9]](#references)</sup>
* **pdf-inspector** – vizuelizator u pregledaču koji prikazuje graf objekata i stream-ove.
* **PyMuPDF** – Python binding-i pogodni za skriptovanje, za pregled PDF-ova i renderovanje stranica u rasterske slike. Parser/renderer tretirajte kao površinu za napad putem nepouzdanih datoteka i pokrećite ga u odgovarajuće izolovanom okruženju za analizu.<sup>[[8]](#references)</sup>

---

## Novije tehnike napada (2023–2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC je prijavio tehniku kojom se na PDF dodaje MHT datoteka napravljena u Word-u, sa VBA makroima, uz zadržavanje PDF magic vrednosti i mogućnost otvaranja u Word-u. Alati za analizu koji obrađuju samo PDF-ove, sandbox-i ili antivirus mogu da previde makro jer se zlonamerno ponašanje ispoljava kada se datoteka otvori kao Word dokument; potražite marker `<w:WordDocument>` zajedno sa drugim MHT indikatorima.<sup>[[2]](#references)</sup>
* **Shadow attacks na potpisane PDF-ove** – napadači mogu da smeste skriveni sadržaj u PDF pre potpisivanja, a zatim dodaju inkrementalno ažuriranje koje menja reference ka katalogu ili objektima, tako da čitači prikazuju skriveni sadržaj dok originalni potpis ostaje važeći. Ova tehnika može da zaobiđe čitače koji takva ažuriranja klasifikuju kao bezopasna.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe ovu kritičnu ranjivost ocenjuje kao use-after-free koja može da dovede do proizvoljnog izvršavanja koda; APSB24-29 je objavljen 14. maja 2024.<sup>[[3]](#references)</sup>

---

## Brzi predložak YARA pravila

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

1. **Brzo instalirajte zakrpe** – koristite najnoviju Continuous verziju Acrobat/Reader-a; većina RCE lanaca primećenih u praksi iskorišćava n-day ranjivosti koje su zakrpljene mesecima ranije.
2. **Uklonite aktivni sadržaj na gateway-u** – koristite namenski sanitizer ili CDR proizvod sa kontrolisanim pravilima koji izričito uklanja JavaScript, ugrađene datoteke, launch akcije, formulare i multimediju. `qpdf --qdf` olakšava pregled PDF objekata, dok pdfcpu pruža funkcije za validaciju i manipulaciju; nijedna od tih komandi sama po sebi ne dokazuje da je aktivni sadržaj uklonjen.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – konvertujte PDF-ove u slike (ili PDF/A) na sandbox hostu kako biste sačuvali vizuelnu vernost i odbacili aktivne objekte.
4. **Blokirajte retko korišćene funkcije** – poslovna podešavanja „Enhanced Security“ u Reader-u omogućavaju onemogućavanje JavaScript-a, multimedije i 3D renderovanja.
5. **Edukacija korisnika** – social engineering (mamci u vidu faktura i biografija) i dalje je početni vektor; naučite zaposlene da prosleđuju sumnjive priloge IR timu.

## References

- [1] [Terenski vodič za forenziku na CTF takmičenjima](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Zaobilaženje detekcije ugrađivanjem zlonamerne Word datoteke u PDF datoteku](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe bezbednosni bilten – Dostupna je bezbednosna ispravka za Adobe Acrobat i Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trikovi PDF formata](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Skrivanje i zamena sadržaja u potpisanim PDF-ovima](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF vodič](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opcije komandne linije za qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
