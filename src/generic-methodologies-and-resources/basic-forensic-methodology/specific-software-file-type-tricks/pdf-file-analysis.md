# Ανάλυση αρχείων PDF

{{#include ../../../banners/hacktricks-training.md}}

**Για περισσότερες λεπτομέρειες ελέγξτε:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

Η μορφή PDF είναι γνωστή για την πολυπλοκότητά της και την ικανότητά της να αποκρύπτει δεδομένα, καθιστώντας την κεντρικό σημείο για προκλήσεις ψηφιακής εγκληματολογίας CTF. Συνδυάζει στοιχεία απλού κειμένου με δυαδικά αντικείμενα, τα οποία μπορεί να είναι συμπιεσμένα ή κρυπτογραφημένα, και μπορεί να περιλαμβάνει σενάρια σε γλώσσες όπως JavaScript ή Flash. Για να κατανοήσετε τη δομή του PDF, μπορείτε να ανατρέξετε στο [εισαγωγικό υλικό](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) του Didier Stevens ή να χρησιμοποιήσετε εργαλεία όπως ένας επεξεργαστής κειμένου ή ένας ειδικός επεξεργαστής PDF όπως το Origami.

Για σε βάθος εξερεύνηση ή χειρισμό PDF, είναι διαθέσιμα εργαλεία όπως το [qpdf](https://github.com/qpdf/qpdf) και το [Origami](https://github.com/mobmewireless/origami-pdf). Κρυφά δεδομένα μέσα σε PDF μπορεί να είναι κρυμμένα σε:

- Αόρατα επίπεδα
- Μορφή μεταδεδομένων XMP από την Adobe
- Σταδιακές γενιές
- Κείμενο με το ίδιο χρώμα με το φόντο
- Κείμενο πίσω από εικόνες ή επικαλυπτόμενες εικόνες
- Μη εμφανιζόμενα σχόλια

Για προσαρμοσμένη ανάλυση PDF, μπορούν να χρησιμοποιηθούν βιβλιοθήκες Python όπως το [PeepDF](https://github.com/jesparza/peepdf) για τη δημιουργία ειδικών σεναρίων ανάλυσης. Επιπλέον, η δυνατότητα του PDF για αποθήκευση κρυφών δεδομένων είναι τόσο εκτενής που πόροι όπως ο οδηγός της NSA για τους κινδύνους και τα μέτρα κατά των PDF, αν και δεν φιλοξενούνται πλέον στην αρχική τους τοποθεσία, προσφέρουν ακόμα πολύτιμες πληροφορίες. Ένας [αντίγραφος του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) και μια συλλογή από [κόλπα μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) από τον Ange Albertini μπορούν να προσφέρουν περαιτέρω ανάγνωση στο θέμα.

## Κοινές Κακόβουλες Κατασκευές

Οι επιτιθέμενοι συχνά κακοποιούν συγκεκριμένα αντικείμενα και ενέργειες PDF που εκτελούνται αυτόματα όταν ανοίγει ή αλληλεπιδρά με το έγγραφο. Λέξεις-κλειδιά που αξίζει να αναζητήσετε:

* **/OpenAction, /AA** – αυτόματες ενέργειες που εκτελούνται κατά το άνοιγμα ή σε συγκεκριμένα γεγονότα.
* **/JS, /JavaScript** – ενσωματωμένο JavaScript (συχνά συγκεχυμένο ή διασπασμένο σε αντικείμενα).
* **/Launch, /SubmitForm, /URI, /GoToE** – εκκινητές εξωτερικών διαδικασιών / URL.
* **/RichMedia, /Flash, /3D** – πολυμεσικά αντικείμενα που μπορούν να κρύβουν payloads.
* **/EmbeddedFile /Filespec** – συνημμένα αρχεία (EXE, DLL, OLE, κ.λπ.).
* **/ObjStm, /XFA, /AcroForm** – ροές αντικειμένων ή φόρμες που κακοποιούνται συχνά για να κρύψουν shell-code.
* **Σταδιακές ενημερώσεις** – πολλαπλοί %%EOF δείκτες ή μια πολύ μεγάλη **/Prev** μετατόπιση μπορεί να υποδεικνύουν δεδομένα που προστέθηκαν μετά την υπογραφή για να παρακαμφθεί το AV.

Όταν οποιοί από τους προηγούμενους δείκτες εμφανίζονται μαζί με ύποπτες αλυσίδες (powershell, cmd.exe, calc.exe, base64, κ.λπ.) το PDF αξίζει μια πιο βαθιά ανάλυση.

---

## Φύλλο συμβουλών στατικής ανάλυσης
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
Επιπλέον χρήσιμα έργα (ενεργά συντηρούμενα 2023-2025):
* **pdfcpu** – Βιβλιοθήκη/CLI Go που μπορεί να *lint*, *decrypt*, *extract*, *compress* και *sanitize* PDFs.
* **pdf-inspector** – Οπτικοποιητής βασισμένος σε πρόγραμμα περιήγησης που αποδίδει το γράφημα αντικειμένων και τα ρεύματα.
* **PyMuPDF (fitz)** – Σενάριο Python που μπορεί να αποδώσει με ασφάλεια σελίδες σε εικόνες για να εκραγούν ενσωματωμένα JS σε ένα σκληρυμένο sandbox.

---

## Πρόσφατες τεχνικές επιθέσεων (2023-2025)

* **MalDoc σε PDF polyglot (2023)** – Η JPCERT/CC παρατήρησε απειλητικούς παράγοντες να προσθέτουν ένα έγγραφο Word βασισμένο σε MHT με VBA macros μετά το τελικό **%%EOF**, παράγοντας ένα αρχείο που είναι και έγκυρο PDF και έγκυρο DOC. Οι μηχανές AV που αναλύουν μόνο το επίπεδο PDF χάνουν τη μακροεντολή. Οι στατικές λέξεις-κλειδιά PDF είναι καθαρές, αλλά το `file` εκτυπώνει ακόμα `%PDF`. Αντιμετωπίστε οποιοδήποτε PDF που περιέχει επίσης τη συμβολοσειρά `<w:WordDocument>` ως εξαιρετικά ύποπτο.
* **Shadow-incremental updates (2024)** – Οι αντίπαλοι εκμεταλλεύονται τη δυνατότητα αυξημένης ενημέρωσης για να εισάγουν ένα δεύτερο **/Catalog** με κακόβουλο `/OpenAction` ενώ διατηρούν την καλοήθη πρώτη αναθεώρηση υπογεγραμμένη. Τα εργαλεία που επιθεωρούν μόνο τον πρώτο πίνακα xref παρακάμπτονται.
* **Αλυσίδα UAF ανάλυσης γραμματοσειρών – CVE-2024-30284 (Acrobat/Reader)** – Μια ευάλωτη λειτουργία **CoolType.dll** μπορεί να προσεγγιστεί από ενσωματωμένες γραμματοσειρές CIDType2, επιτρέποντας την απομακρυσμένη εκτέλεση κώδικα με τα δικαιώματα του χρήστη μόλις ανοίξει ένα κατεργασμένο έγγραφο. Διορθώθηκε στο APSB24-29, Μάιος 2024.

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

1. **Επιδιόρθωση γρήγορα** – διατηρήστε το Acrobat/Reader στην τελευταία συνεχή έκδοση; οι περισσότερες αλυσίδες RCE που παρατηρήθηκαν στην άγρια φύση εκμεταλλεύονται ευπάθειες n-day που έχουν διορθωθεί μήνες νωρίτερα.
2. **Αφαίρεση ενεργού περιεχομένου στην πύλη** – χρησιμοποιήστε `pdfcpu sanitize` ή `qpdf --qdf --remove-unreferenced` για να αφαιρέσετε JavaScript, ενσωματωμένα αρχεία και ενέργειες εκκίνησης από τα εισερχόμενα PDFs.
3. **Αφοπλισμός και Ανακατασκευή Περιεχομένου (CDR)** – μετατρέψτε τα PDFs σε εικόνες (ή PDF/A) σε έναν sandbox host για να διατηρήσετε την οπτική πιστότητα ενώ απορρίπτετε ενεργά αντικείμενα.
4. **Αποκλεισμός σπάνια χρησιμοποιούμενων χαρακτηριστικών** – οι ρυθμίσεις “Enhanced Security” στην Reader επιτρέπουν την απενεργοποίηση του JavaScript, πολυμέσων και 3D rendering.
5. **Εκπαίδευση χρηστών** – η κοινωνική μηχανική (παγίδες τιμολογίων και βιογραφικών) παραμένει ο αρχικός φορέας· διδάξτε στους υπαλλήλους να προωθούν ύποπτες συνημμένες σε IR.

## Αναφορές

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (Αυγ 2023)
* Adobe – Ενημέρωση ασφαλείας για το Acrobat και Reader (APSB24-29, Μάιος 2024)


{{#include ../../../banners/hacktricks-training.md}}
