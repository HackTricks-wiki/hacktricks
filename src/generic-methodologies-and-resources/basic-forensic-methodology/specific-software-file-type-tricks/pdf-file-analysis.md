# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**Za više detalja pogledajte:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF format je poznat po svojoj složenosti i potencijalu za prikrivanje podataka, što ga čini centralnom tačkom za CTF forenzičke izazove. Kombinuje elemente običnog teksta sa binarnim objektima, koji mogu biti kompresovani ili enkriptovani, i može uključivati skripte u jezicima kao što su JavaScript ili Flash. Da bi se razumeo PDF struktura, može se konsultovati [uvodni materijal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didijea Stivensa, ili koristiti alate poput tekstualnog editora ili PDF-specifičnog editora kao što je Origami.

Za dubinsko istraživanje ili manipulaciju PDF-ova, dostupni su alati poput [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Sakriveni podaci unutar PDF-ova mogu biti prikriveni u:

- Nevidljivim slojevima
- XMP metapodacima formata od Adobe-a
- Inkrementalnim generacijama
- Tekstu iste boje kao pozadina
- Tekstu iza slika ili preklapajućih slika
- Neprikazanim komentarima

Za prilagođenu analizu PDF-a, mogu se koristiti Python biblioteke poput [PeepDF](https://github.com/jesparza/peepdf) za kreiranje prilagođenih skripti za parsiranje. Pored toga, potencijal PDF-a za skladištenje skrivenih podataka je toliko veliki da resursi poput NSA vodiča o rizicima i protivmera vezanih za PDF, iako više nisu dostupni na svojoj originalnoj lokaciji, i dalje nude dragocene uvide. [Kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) i kolekcija [trikova za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md) od Anže Albertinija mogu pružiti dodatno čitanje na ovu temu.

## Common Malicious Constructs

Napadači često zloupotrebljavaju specifične PDF objekte i akcije koje se automatski izvršavaju kada se dokument otvori ili interaguje s njim. Ključne reči koje vredi tražiti:

* **/OpenAction, /AA** – automatske akcije izvršene prilikom otvaranja ili na specifičnim događajima.
* **/JS, /JavaScript** – ugrađeni JavaScript (često obfuskovan ili podeljen između objekata).
* **/Launch, /SubmitForm, /URI, /GoToE** – pokretači spoljnog procesa / URL-a.
* **/RichMedia, /Flash, /3D** – multimedijalni objekti koji mogu sakriti payload-e.
* **/EmbeddedFile /Filespec** – privitci fajlova (EXE, DLL, OLE, itd.).
* **/ObjStm, /XFA, /AcroForm** – tokovi objekata ili forme koje se često zloupotrebljavaju za skrivanje shell-koda.
* **Inkrementalne nadogradnje** – više %%EOF oznaka ili veoma veliki **/Prev** offset može ukazivati na podatke dodate nakon potpisivanja kako bi se zaobišao AV.

Kada se bilo koji od prethodnih tokena pojavi zajedno sa sumnjivim stringovima (powershell, cmd.exe, calc.exe, base64, itd.), PDF zaslužuje dublju analizu.

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
Dodatni korisni projekti (aktivno održavani 2023-2025):
* **pdfcpu** – Go biblioteka/CLI koja može da *lintuje*, *dekriptuje*, *izvlači*, *kompresuje* i *sanitizuje* PDF-ove.
* **pdf-inspector** – vizualizator zasnovan na pretraživaču koji prikazuje graf objekata i tokove.
* **PyMuPDF (fitz)** – skriptabilni Python motor koji može sigurno da prikazuje stranice kao slike kako bi aktivirao ugrađeni JS u zaštićenoj sandučici.

---

## Nedavne tehnike napada (2023-2025)

* **MalDoc u PDF poliglotu (2023)** – JPCERT/CC je primetio pretnje koje dodaju MHT-bazirani Word dokument sa VBA makroima nakon konačnog **%%EOF**, proizvodeći datoteku koja je i validan PDF i validan DOC. AV motori koji analiziraju samo PDF sloj propuštaju makro. Statične PDF ključne reči su čiste, ali `file` i dalje ispisuje `%PDF`. Svaki PDF koji takođe sadrži string `<w:WordDocument>` tretirati kao veoma sumnjiv.
* **Shadow-incremental ažuriranja (2024)** – protivnici zloupotrebljavaju funkciju inkrementalnog ažuriranja da umetnu drugi **/Catalog** sa zloćudnim `/OpenAction` dok zadržavaju benignu prvu reviziju potpisanu. Alati koji inspektuju samo prvu xref tabelu su zaobiđeni.
* **Lanac UAF za parsiranje fontova – CVE-2024-30284 (Acrobat/Reader)** – ranjiva funkcija **CoolType.dll** može se dostići iz ugrađenih CIDType2 fontova, omogućavajući daljinsko izvršavanje koda sa privilegijama korisnika kada se otvori kreirani dokument. Zakrpljeno u APSB24-29, maj 2024.

---

## YARA brza pravila šablon
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

1. **Brzo zakrpite** – održavajte Acrobat/Reader na najnovijem kontinuiranom traku; većina RCE lanaca zabeleženih u prirodi koristi n-dnevne ranjivosti koje su ispravljene mesecima ranije.
2. **Uklonite aktivni sadržaj na ulazu** – koristite `pdfcpu sanitize` ili `qpdf --qdf --remove-unreferenced` da biste uklonili JavaScript, ugrađene datoteke i akcije pokretanja iz dolaznih PDF-ova.
3. **Deaktivacija sadržaja i rekonstrukcija (CDR)** – konvertujte PDF-ove u slike (ili PDF/A) na sandbox hostu kako biste sačuvali vizuelnu vernost dok odbacujete aktivne objekte.
4. **Blokirajte retko korišćene funkcije** – preduzeća “Poboljšana sigurnost” podešavanja u Reader-u omogućavaju onemogućavanje JavaScript-a, multimedije i 3D renderovanja.
5. **Obrazovanje korisnika** – socijalni inženjering (mamci sa fakturama i rezimeima) ostaje inicijalni vektor; podučite zaposlene da proslede sumnjive priloge IR-u.

## Reference

* JPCERT/CC – “MalDoc u PDF-u – Zaobilaženje detekcije ugrađivanjem zlonamerne Word datoteke u PDF datoteku” (avgust 2023)
* Adobe – Bezbednosno ažuriranje za Acrobat i Reader (APSB24-29, maj 2024)

{{#include ../../../banners/hacktricks-training.md}}
