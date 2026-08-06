# Ανάλυση αρχείων PDF

{{#include ../../../banners/hacktricks-training.md}}

**Για περισσότερες λεπτομέρειες, δείτε:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

Η μορφή PDF είναι γνωστή για την πολυπλοκότητά της και τη δυνατότητα απόκρυψης δεδομένων, γεγονός που την καθιστά βασικό αντικείμενο σε challenges forensics του CTF. Συνδυάζει στοιχεία απλού κειμένου με binary objects, τα οποία μπορεί να είναι συμπιεσμένα ή κρυπτογραφημένα, και μπορεί να περιλαμβάνει scripts σε γλώσσες όπως JavaScript ή Flash. Για την κατανόηση της δομής των PDF, μπορείτε να ανατρέξετε στο [εισαγωγικό υλικό](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) του Didier Stevens ή να χρησιμοποιήσετε εργαλεία όπως έναν text editor ή έναν ειδικό PDF editor, όπως το Origami.

Για λεπτομερή εξερεύνηση ή τροποποίηση PDF, είναι διαθέσιμα εργαλεία όπως τα [qpdf](https://github.com/qpdf/qpdf) και [Origami](https://github.com/mobmewireless/origami-pdf). Τα κρυφά δεδομένα μέσα σε PDF μπορεί να βρίσκονται κρυμμένα σε:

- Αόρατα layers
- Μορφή XMP metadata της Adobe
- Incremental generations
- Κείμενο με το ίδιο χρώμα με το background
- Κείμενο πίσω από images ή overlapping images
- Comments που δεν εμφανίζονται

Για custom PDF analysis, μπορούν να χρησιμοποιηθούν Python libraries όπως το [PeepDF](https://github.com/jesparza/peepdf), ώστε να δημιουργηθούν bespoke parsing scripts. Επιπλέον, η δυνατότητα των PDF να αποθηκεύουν κρυφά δεδομένα είναι τόσο μεγάλη, ώστε resources όπως ο οδηγός της NSA για τους κινδύνους και τα countermeasures των PDF, παρότι δεν φιλοξενείται πλέον στην αρχική του τοποθεσία, εξακολουθούν να προσφέρουν χρήσιμες πληροφορίες. Ένα [αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) και μια συλλογή από [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) του Ange Albertini μπορούν να προσφέρουν περαιτέρω υλικό για το θέμα.<sup>[[4]](#references)[[5]](#references)</sup>

## Συνήθεις κακόβουλες κατασκευές

Οι attackers συχνά κάνουν abuse συγκεκριμένων PDF objects και actions που εκτελούνται αυτόματα όταν το document ανοίγει ή όταν ο χρήστης αλληλεπιδρά με αυτό. Keywords που αξίζει να αναζητήσετε:

* **/OpenAction, /AA** – automatic actions που εκτελούνται κατά το άνοιγμα ή σε συγκεκριμένα events.
* **/JS, /JavaScript** – ενσωματωμένο JavaScript (συχνά obfuscated ή διαμοιρασμένο σε πολλά objects).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects που μπορούν να κρύβουν payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE κ.λπ.).
* **/ObjStm, /XFA, /AcroForm** – object streams ή forms που συχνά γίνονται abuse για την απόκρυψη shell-code.
* **Incremental updates** – πολλαπλοί markers `%%EOF` ή ένα πολύ μεγάλο offset **/Prev** μπορεί να υποδεικνύουν δεδομένα που προστέθηκαν μετά το signing, ώστε να παρακαμφθεί το AV.

Όταν οποιαδήποτε από τα προηγούμενα tokens εμφανίζεται μαζί με ύποπτα strings (powershell, cmd.exe, calc.exe, base64 κ.λπ.), το PDF χρήζει βαθύτερης ανάλυσης.

---

## Cheat-sheet στατικής ανάλυσης
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
Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – Go library/CLI με δυνατότητα για *lint*, *decrypt*, *extract*, *compress* και *sanitize* PDFs.
* **pdf-inspector** – visualizer βασισμένο σε browser που αποδίδει το object graph και τα streams.
* **PyMuPDF (fitz)** – scriptable Python engine που μπορεί να αποδίδει με ασφάλεια σελίδες ως images, ώστε να εκτελεί embedded JS σε hardened sandbox.

---

## Πρόσφατες attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – η JPCERT/CC παρατήρησε threat actors να προσαρτούν ένα MHT-based Word document με VBA macros μετά το τελευταίο **%%EOF**, δημιουργώντας ένα αρχείο που είναι ταυτόχρονα έγκυρο PDF και έγκυρο DOC. Τα AV engines που αναλύουν μόνο το PDF layer δεν εντοπίζουν το macro. Τα static PDF keywords είναι καθαρά, αλλά η `file` εξακολουθεί να εμφανίζει `%PDF`. Αντιμετωπίστε κάθε PDF που περιέχει επίσης το string `<w:WordDocument>` ως εξαιρετικά ύποπτο.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – οι adversaries κάνουν abuse το incremental update feature για να εισαγάγουν ένα δεύτερο **/Catalog** με κακόβουλο `/OpenAction`, διατηρώντας παράλληλα υπογεγραμμένη την benign πρώτη revision. Τα tools που επιθεωρούν μόνο το πρώτο xref table παρακάμπτονται.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – μια ευάλωτη συνάρτηση στο **CoolType.dll** μπορεί να προσπελαστεί μέσω embedded CIDType2 fonts, επιτρέποντας remote code execution με τα privileges του χρήστη μόλις ανοίξει ένα crafted document. Διορθώθηκε στο APSB24-29, τον Μάιο του 2024.<sup>[[3]](#references)</sup>

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

1. **Γρήγορο patching** – διατηρείτε τα Acrobat/Reader στην πιο πρόσφατη Continuous έκδοση· οι περισσότερες αλυσίδες RCE που έχουν παρατηρηθεί στη φύση εκμεταλλεύονται n-day ευπάθειες που διορθώθηκαν μήνες νωρίτερα.
2. **Αφαίρεση active content στην πύλη** – χρησιμοποιήστε `pdfcpu sanitize` ή `qpdf --qdf --remove-unreferenced` για να αφαιρείτε JavaScript, embedded files και launch actions από τα εισερχόμενα PDFs.
3. **Content Disarm & Reconstruction (CDR)** – μετατρέπετε τα PDFs σε εικόνες (ή PDF/A) σε έναν sandbox host, ώστε να διατηρείται η οπτική πιστότητα και να απορρίπτονται τα active objects.
4. **Αποκλεισμός features που χρησιμοποιούνται σπάνια** – οι ρυθμίσεις “Enhanced Security” enterprise στο Reader επιτρέπουν την απενεργοποίηση των JavaScript, multimedia και 3D rendering.
5. **Εκπαίδευση χρηστών** – το social engineering (παγίδες με invoices και resumes) παραμένει το αρχικό vector· εκπαιδεύστε τους εργαζομένους να προωθούν τα ύποπτα attachments στο IR.

## Αναφορές

- [1] [Οδηγός πεδίου Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Παράκαμψη detection με ενσωμάτωση κακόβουλου αρχείου Word σε αρχείο PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Διαθέσιμη ενημέρωση ασφαλείας για τα Adobe Acrobat και Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - tricks μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)

{{#include ../../../banners/hacktricks-training.md}}
