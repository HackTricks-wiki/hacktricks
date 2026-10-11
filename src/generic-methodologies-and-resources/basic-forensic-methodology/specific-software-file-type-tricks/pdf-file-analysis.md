# Ανάλυση αρχείων PDF

{{#include ../../../banners/hacktricks-training.md}}

**Για περισσότερες λεπτομέρειες, δείτε:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

Η μορφή PDF είναι γνωστή για την πολυπλοκότητά της και τη δυνατότητα απόκρυψης δεδομένων, γεγονός που την καθιστά κεντρικό θέμα στις προκλήσεις ψηφιακής εγκληματολογίας CTF. Συνδυάζει στοιχεία απλού κειμένου με δυαδικά αντικείμενα, τα οποία ενδέχεται να είναι συμπιεσμένα ή κρυπτογραφημένα, και μπορεί να περιλαμβάνει scripts σε γλώσσες όπως η JavaScript ή η Flash. Για να κατανοήσετε τη δομή των PDF, μπορείτε να ανατρέξετε στο [εισαγωγικό υλικό](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) του Didier Stevens ή να χρησιμοποιήσετε εργαλεία όπως έναν επεξεργαστή κειμένου ή έναν ειδικό επεξεργαστή PDF, όπως το Origami.

Για εις βάθος διερεύνηση ή τροποποίηση PDF, υπάρχουν εργαλεία όπως το [qpdf](https://github.com/qpdf/qpdf) και το [Origami](https://github.com/mobmewireless/origami-pdf). Τα κρυφά δεδομένα σε PDF μπορεί να βρίσκονται σε:

- Αόρατα επίπεδα
- Μορφή μεταδεδομένων XMP της Adobe
- Επαυξητικές γενιές
- Κείμενο με το ίδιο χρώμα με το φόντο
- Κείμενο πίσω από εικόνες ή εικόνες που επικαλύπτονται
- Σχόλια που δεν εμφανίζονται

Για προσαρμοσμένη ανάλυση PDF, μπορούν να χρησιμοποιηθούν βιβλιοθήκες Python όπως η [PeepDF](https://github.com/jesparza/peepdf), ώστε να δημιουργηθούν εξειδικευμένα scripts ανάλυσης. Επιπλέον, οι δυνατότητες των PDF για αποθήκευση κρυφών δεδομένων είναι τόσο εκτεταμένες, που πόροι όπως ο οδηγός της NSA για τους κινδύνους των PDF και τα αντίμετρα, παρότι δεν φιλοξενείται πλέον στην αρχική του τοποθεσία, εξακολουθούν να προσφέρουν χρήσιμες πληροφορίες. Ένα [αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) και μια συλλογή από [κόλπα της μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) του Ange Albertini αποτελούν χρήσιμες πηγές για περαιτέρω μελέτη του θέματος.<sup>[[4]](#references)[[5]](#references)</sup>

## Συνήθεις κακόβουλες κατασκευές

Οι επιτιθέμενοι συχνά καταχρώνται συγκεκριμένα αντικείμενα και ενέργειες PDF, τα οποία εκτελούνται αυτόματα όταν ανοίγει το έγγραφο ή όταν ο χρήστης αλληλεπιδρά με αυτό. Λέξεις-κλειδιά που αξίζει να αναζητήσετε:

* **/OpenAction, /AA** – αυτόματες ενέργειες που εκτελούνται κατά το άνοιγμα ή σε συγκεκριμένα συμβάντα.
* **/JS, /JavaScript** – ενσωματωμένη JavaScript (συχνά συγκαλυμμένη ή κατανεμημένη σε πολλά αντικείμενα).
* **/Launch, /SubmitForm, /URI, /GoToE** – μηχανισμοί εκκίνησης εξωτερικών διεργασιών ή URL.
* **/RichMedia, /Flash, /3D** – αντικείμενα πολυμέσων που μπορούν να κρύβουν payloads.
* **/EmbeddedFile /Filespec** – συνημμένα αρχεία (EXE, DLL, OLE κ.λπ.).
* **/ObjStm, /XFA, /AcroForm** – ροές αντικειμένων ή φόρμες που συχνά καταχρώνται για την απόκρυψη shell-code.
* **Επαυξητικές ενημερώσεις** – πολλαπλοί δείκτες %%EOF ή πολύ μεγάλη τιμή μετατόπισης **/Prev** ενδέχεται να υποδεικνύουν δεδομένα που προσαρτήθηκαν μετά την υπογραφή, με σκοπό την παράκαμψη του AV.

Όταν κάποιο από τα παραπάνω tokens εμφανίζεται μαζί με ύποπτες συμβολοσειρές (powershell, cmd.exe, calc.exe, base64 κ.λπ.), το PDF χρήζει βαθύτερης ανάλυσης.

---

## Συνοπτικός οδηγός στατικής ανάλυσης

Τα παρακάτω παραδείγματα χρησιμοποιούν τις τεκμηριωμένες διεπαφές γραμμής εντολών των `pdf-parser.py`, qpdf και pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Η πιξελοποίηση μιας εικόνας μέσα σε ένα PDF δεν αφαιρεί τα υποκείμενα pixel της. Αν ένα ευανάγνωστο έγγραφο φαίνεται να κρύβει με αυτόν τον τρόπο ένα διαπιστευτήριο, εξαγάγετε την ενσωματωμένη εικόνα για εξουσιοδοτημένη επιθεώρηση εκτός σύνδεσης· το αποτέλεσμα εξαρτάται από την εικόνα και την ύπαρξη κατάλληλου δείγματος αναφοράς, και η οπτική ανάκτηση δεν είναι εγγυημένη. Ένας κωδικός πρόσβασης που ανακτήθηκε πρέπει και πάλι να επαληθευτεί χωριστά ως προς τον λογαριασμό του οποίου τα δικαιώματα έχουν σημασία. Μην εντάσσετε την εξαγωγή PDF ή την ανάκτηση εικόνων σε συνήθη σάρωση απαρίθμησης host.

Πρόσθετα χρήσιμα project (συντηρούνται ενεργά το 2023-2025):
* **pdfcpu** – βιβλιοθήκη/CLI για Go που μπορεί να επικυρώνει, να αποκρυπτογραφεί, να εξάγει, να βελτιστοποιεί και να χειρίζεται PDF.<sup>[[9]](#references)</sup>
* **pdf-inspector** – οπτικοποιητής μέσω browser που αποδίδει το γράφημα αντικειμένων και τις ροές.
* **PyMuPDF** – προγραμματιζόμενες δεσμεύσεις Python για επιθεώρηση PDF και απόδοση σελίδων ως εικόνες raster. Θεωρήστε τον parser/renderer επιφάνεια επίθεσης από μη έμπιστα αρχεία και εκτελέστε τον σε κατάλληλα απομονωμένο περιβάλλον ανάλυσης.<sup>[[8]](#references)</sup>

---

## Πρόσφατες τεχνικές επίθεσης (2023-2025)

* **Πολυγλωσσικό αρχείο MalDoc in PDF (2023)** – η JPCERT/CC ανέφερε μια τεχνική που προσαρτά σε PDF ένα αρχείο MHT που δημιουργήθηκε με Word και περιέχει μακροεντολές VBA, διατηρώντας την υπογραφή magic του PDF ενώ παράλληλα ανοίγει στο Word. Εργαλεία ανάλυσης PDF, sandbox ή antivirus μπορεί να μην εντοπίσουν τη μακροεντολή, επειδή η κακόβουλη συμπεριφορά εκδηλώνεται όταν το αρχείο ανοίγει ως Word· αναζητήστε τον δείκτη `<w:WordDocument>` μαζί με άλλες ενδείξεις MHT.<sup>[[2]](#references)</sup>
* **Επιθέσεις Shadow σε υπογεγραμμένα PDF** – οι επιτιθέμενοι μπορούν να τοποθετήσουν κρυφό περιεχόμενο σε ένα PDF πριν αυτό υπογραφεί και, στη συνέχεια, να προσαρτήσουν μια σταδιακή ενημέρωση που αλλάζει τον κατάλογο ή τις αναφορές αντικειμένων, ώστε τα προγράμματα προβολής να εμφανίζουν το κρυφό περιεχόμενο ενώ η αρχική υπογραφή παραμένει έγκυρη. Η τεχνική μπορεί να παρακάμψει προγράμματα προβολής που χαρακτηρίζουν τέτοιες ενημερώσεις ως ακίνδυνες.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – η Adobe βαθμολογεί αυτήν την κρίσιμη ευπάθεια ως use-after-free, η οποία μπορεί να οδηγήσει σε αυθαίρετη εκτέλεση κώδικα· το APSB24-29 δημοσιεύτηκε στις 14 Μαΐου 2024.<sup>[[3]](#references)</sup>

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

1. **Εγκαταστήστε γρήγορα τις ενημερώσεις** – διατηρείτε το Acrobat/Reader στην πιο πρόσφατη έκδοση του Continuous track· οι περισσότερες αλυσίδες RCE που έχουν παρατηρηθεί στην πράξη εκμεταλλεύονται n-day ευπάθειες που είχαν διορθωθεί μήνες νωρίτερα.
2. **Αφαιρείτε το ενεργό περιεχόμενο στην πύλη** – χρησιμοποιείτε ένα εξειδικευμένο προϊόν απολύμανσης ή CDR με ελεγχόμενες από πολιτικές ρυθμίσεις, το οποίο αφαιρεί ρητά JavaScript, ενσωματωμένα αρχεία, ενέργειες εκκίνησης, φόρμες και πολυμέσα. Το `qpdf --qdf` διευκολύνει την επιθεώρηση αντικειμένων PDF, ενώ το pdfcpu παρέχει δυνατότητες επικύρωσης και τροποποίησης· καμία από τις δύο εντολές από μόνη της δεν αποδεικνύει ότι αφαιρέθηκε το ενεργό περιεχόμενο.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – μετατρέπετε τα PDF σε εικόνες (ή PDF/A) σε έναν host sandbox, ώστε να διατηρείται η οπτική πιστότητα και να απορρίπτονται τα ενεργά αντικείμενα.
4. **Αποκλείετε λειτουργίες που χρησιμοποιούνται σπάνια** – οι ρυθμίσεις «Enhanced Security» για επιχειρήσεις στο Reader επιτρέπουν την απενεργοποίηση JavaScript, πολυμέσων και απόδοσης 3D.
5. **Εκπαίδευση χρηστών** – η κοινωνική μηχανική (παγίδες με τιμολόγια και βιογραφικά) εξακολουθεί να αποτελεί το αρχικό διάνυσμα επίθεσης· μάθετε στους εργαζομένους να προωθούν ύποπτα συνημμένα στην ομάδα IR.

## References

- [1] [Οδηγός πεδίου Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Παράκαμψη ανίχνευσης με ενσωμάτωση κακόβουλου αρχείου Word σε αρχείο PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Δελτίο ασφαλείας της Adobe – Διαθέσιμη ενημέρωση ασφαλείας για το Adobe Acrobat και το Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - αντίγραφο του οδηγού](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - τεχνάσματα της μορφής PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Επιθέσεις Shadow: Απόκρυψη και αντικατάσταση περιεχομένου σε υπογεγραμμένα PDF](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Εκμάθηση του PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Επιλογές γραμμής εντολών του qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
