# Ανάλυση αρχείων PDF

{{#include ../../../banners/hacktricks-training.md}}

**Για περισσότερες λεπτομέρειες, δείτε:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Η μορφή PDF είναι γνωστή για την πολυπλοκότητά της και τη δυνατότητα απόκρυψης δεδομένων, γεγονός που την καθιστά βασικό πεδίο για challenges ψηφιακής εγκληματολογίας σε CTF. Συνδυάζει στοιχεία plain-text με δυαδικά objects, τα οποία μπορεί να είναι συμπιεσμένα ή κρυπτογραφημένα, και μπορεί να περιλαμβάνει scripts σε γλώσσες όπως JavaScript ή Flash. Για την κατανόηση της δομής των PDF, μπορείτε να ανατρέξετε στο [εισαγωγικό υλικό](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) του Didier Stevens ή να χρησιμοποιήσετε εργαλεία όπως έναν text editor ή έναν ειδικό editor για PDF, όπως το Origami.

Για λεπτομερή εξερεύνηση ή τροποποίηση PDF, είναι διαθέσιμα εργαλεία όπως τα [qpdf](https://github.com/qpdf/qpdf) και [Origami](https://github.com/mobmewireless/origami-pdf). Τα κρυφά δεδομένα σε PDF μπορεί να είναι κρυμμένα σε:

- Αόρατα layers
- Μορφή μεταδεδομένων XMP της Adobe
- Incremental generations
- Κείμενο με το ίδιο χρώμα με το background
- Κείμενο πίσω από images ή images που επικαλύπτονται
- Σχόλια που δεν εμφανίζονται

Για custom ανάλυση PDF, μπορούν να χρησιμοποιηθούν Python libraries όπως το [PeepDF](https://github.com/jesparza/peepdf), ώστε να δημιουργηθούν bespoke parsing scripts. Επιπλέον, η δυνατότητα των PDF για αποθήκευση κρυφών δεδομένων είναι τόσο μεγάλη, ώστε πηγές όπως ο οδηγός της NSA για τους κινδύνους και τα αντίμετρα των PDF, παρότι δεν φιλοξενείται πλέον στην αρχική του τοποθεσία, εξακολουθούν να προσφέρουν πολύτιμες πληροφορίες. Ένα [αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) και μια συλλογή από [tricks για τη μορφή PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) του Ange Albertini μπορούν να προσφέρουν περαιτέρω μελέτη του θέματος.<sup>[[4]](#references)[[5]](#references)</sup>

## Συνήθεις κακόβουλες κατασκευές

Οι attackers συχνά κάνουν abuse σε συγκεκριμένα PDF objects και actions που εκτελούνται αυτόματα όταν το έγγραφο ανοίγει ή όταν ο χρήστης αλληλεπιδρά με αυτό. Λέξεις-κλειδιά που αξίζει να αναζητήσετε:

* **/OpenAction, /AA** – automatic actions που εκτελούνται κατά το άνοιγμα ή σε συγκεκριμένα events.
* **/JS, /JavaScript** – ενσωματωμένο JavaScript (συχνά obfuscated ή διαχωρισμένο σε πολλά objects).
* **/Launch, /SubmitForm, /URI, /GoToE** – launchers για εξωτερικές processes / URLs.
* **/RichMedia, /Flash, /3D** – multimedia objects που μπορούν να κρύβουν payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE κ.λπ.).
* **/ObjStm, /XFA, /AcroForm** – object streams ή forms που συχνά χρησιμοποιούνται για την απόκρυψη shell-code.
* **Incremental updates** – πολλαπλοί markers %%EOF ή ένα πολύ μεγάλο offset **/Prev** μπορεί να υποδεικνύουν δεδομένα που προσαρτήθηκαν μετά την υπογραφή, ώστε να παρακαμφθεί το AV.

Όταν οποιαδήποτε από τα προηγούμενα tokens εμφανίζεται μαζί με ύποπτα strings (powershell, cmd.exe, calc.exe, base64 κ.λπ.), το PDF απαιτεί βαθύτερη ανάλυση.

---

## Cheat-sheet στατικής ανάλυσης

Τα παρακάτω παραδείγματα χρησιμοποιούν τα τεκμηριωμένα command-line interfaces των `pdf-parser.py`, qpdf και pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
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
Πρόσθετα χρήσιμα projects (actively maintained 2023-2025):
* **pdfcpu** – Go library/CLI με δυνατότητα επικύρωσης, αποκρυπτογράφησης, εξαγωγής, βελτιστοποίησης και χειρισμού PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizer βασισμένο σε browser, που αποδίδει το object graph και τα streams.
* **PyMuPDF** – scriptable Python bindings για επιθεώρηση PDF και απόδοση σελίδων σε raster images. Αντιμετωπίστε τον parser/renderer ως untrusted-file attack surface και εκτελέστε τον μέσα σε appropriately isolated analysis environment.<sup>[[8]](#references)</sup>

---

## Πρόσφατες attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – Η JPCERT/CC ανέφερε μια technique που προσθέτει σε ένα PDF ένα MHT file που δημιουργήθηκε από το Word και περιέχει VBA macros, διατηρώντας το PDF magic ενώ παράλληλα ανοίγει στο Word. Τα PDF-only analysis tools, τα sandboxes ή το antivirus ενδέχεται να μην εντοπίσουν το macro, επειδή η malicious behavior εκδηλώνεται όταν ανοίγει ως Word· αναζητήστε τον marker `<w:WordDocument>` μαζί με άλλους MHT indicators.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – Οι attackers μπορούν να τοποθετήσουν hidden content σε ένα PDF πριν υπογραφεί και στη συνέχεια να προσθέσουν ένα incremental update που αλλάζει τις catalog ή object references, ώστε οι viewers να εμφανίζουν το hidden content ενώ η original signature παραμένει valid. Η technique μπορεί να παρακάμψει viewers που ταξινομούν τέτοιες ενημερώσεις ως harmless.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Η Adobe αξιολογεί αυτή την critical vulnerability ως use-after-free, η οποία μπορεί να οδηγήσει σε arbitrary code execution· το APSB24-29 δημοσιεύτηκε στις 14 Μαΐου 2024.<sup>[[3]](#references)</sup>

---

## Πρότυπο γρήγορου κανόνα YARA
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

## Αμυντικές συμβουλές

1. **Άμεση εγκατάσταση patches** – διατηρείτε το Acrobat/Reader στο πιο πρόσφατο Continuous track· οι περισσότερες αλυσίδες RCE που έχουν παρατηρηθεί στη φύση εκμεταλλεύονται n-day vulnerabilities που είχαν διορθωθεί μήνες νωρίτερα.
2. **Αφαίρεση active content στην πύλη** – χρησιμοποιήστε έναν ειδικά σχεδιασμένο, ελεγχόμενο βάσει πολιτικής sanitizer ή προϊόν CDR που αφαιρεί ρητά JavaScript, embedded files, launch actions, forms και multimedia. Το `qpdf --qdf` διευκολύνει την επιθεώρηση των PDF objects, ενώ το pdfcpu παρέχει δυνατότητες validation και manipulation· καμία από τις δύο εντολές από μόνη της δεν αποδεικνύει ότι το active content αφαιρέθηκε.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – μετατρέπετε τα PDFs σε images (ή PDF/A) σε sandbox host, ώστε να διατηρείται η οπτική πιστότητα και να απορρίπτονται τα active objects.
4. **Αποκλεισμός χαρακτηριστικών που χρησιμοποιούνται σπάνια** – οι ρυθμίσεις enterprise “Enhanced Security” στο Reader επιτρέπουν την απενεργοποίηση των JavaScript, multimedia και 3D rendering.
5. **Εκπαίδευση χρηστών** – το social engineering (παγίδες με τιμολόγια και βιογραφικά) παραμένει το αρχικό vector· εκπαιδεύστε τους εργαζομένους να προωθούν ύποπτα attachments στην ομάδα IR.

## References

- [1] [Οδηγός πεδίου Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Παράκαμψη ανίχνευσης με ενσωμάτωση κακόβουλου αρχείου Word σε αρχείο PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Δελτίο ασφαλείας της Adobe – Διαθέσιμη ενημέρωση ασφαλείας για τα Adobe Acrobat και Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - τεχνάσματα μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Απόκρυψη και αντικατάσταση περιεχομένου σε υπογεγραμμένα PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Οδηγός PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Επιλογές γραμμής εντολών qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
