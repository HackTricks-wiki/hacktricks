# Στεγανογραφία εγγράφων

{{#include ../../banners/hacktricks-training.md}}

Πολλές μορφές εγγράφων είναι δομημένα κοντέινερ και όχι μεμονωμένες ροές δεδομένων:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (ενσωματωμένα αρχεία, ροές)
- Office OOXML (`.docx/.xlsx/.pptx` είναι ZIP)
- Έγγραφα παλαιού τύπου RTF και OLE/Compound File Binary. Το RTF αποθηκεύει λέξεις ελέγχου και ομάδες σε μορφή προσανατολισμένη στο κείμενο, ενώ τα σύνθετα αρχεία OLE εμφανίζουν μια ιεραρχία αντικειμένων αποθήκευσης και ροών παρόμοια με σύστημα αρχείων· και τα δύο απαιτούν έλεγχο ειδικό για τη μορφή, ώστε να εντοπιστούν κρυφά ή ενσωματωμένα δεδομένα.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Τεχνική

Τα αρχεία PDF μπορούν να περιέχουν αντικείμενα, ροές, JavaScript και ενσωματωμένα αρχεία. Κατά την ανάλυση, συνήθεις εργασίες είναι:

- Εξαγωγή ενσωματωμένων συνημμένων.
- Ανάπτυξη ροών αντικειμένων, ώστε να είναι ευκολότερος ο έλεγχος των αντικειμένων.
- Εντοπισμός JavaScript, ενσωματωμένων εικόνων και ασυνήθιστων ροών.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Γρήγοροι έλεγχοι

```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```

Ο συνδυασμός `--qdf --object-streams=disable` παράγει μια πιο ευανάγνωστη αναπαράσταση και αφαιρεί τα object streams, διευκολύνοντας τη μη αυτόματη επιθεώρηση.<sup>[[2]](#references)</sup> Στη συνέχεια, αναζητήστε ύποπτα αντικείμενα και συμβολοσειρές στο `out.pdf`.

## Office OOXML

### Τεχνική

Τα αρχεία Office Open XML (`.docx`, `.xlsx` και `.pptx`) χρησιμοποιούν το Open Packaging Conventions: ένα πακέτο βασισμένο σε ZIP, το οποίο αποτελείται από parts και αρχεία XML σχέσεων.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Αντιμετωπίστε το πακέτο ως γράφο σχέσεων και επιθεωρήστε τα media, τις εξωτερικές σχέσεις και τα ασυνήθιστα προσαρμοσμένα parts.

Στην πράξη:

- Το έγγραφο είναι ένα δέντρο καταλόγων με XML και αρχεία πόρων.
- Τα αρχεία σχέσεων `_rels/` μπορούν να παραπέμπουν σε εξωτερικούς πόρους ή κρυφά parts.
- Τα ενσωματωμένα δεδομένα βρίσκονται συχνά στο `word/media/`, σε προσαρμοσμένα XML parts ή σε ασυνήθιστες σχέσεις.

### Γρήγοροι έλεγχοι

```bash
7z l file.docx
7z x file.docx -oout
```

Στη συνέχεια, επιθεωρήστε:

- `word/document.xml`
- `word/_rels/` για εξωτερικές σχέσεις
- ενσωματωμένα μέσα στο `word/media/`

## References

- [1] [Εγχειρίδιο του Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Τεκμηρίωση του qpdf - λειτουργία QDF και ροές αντικειμένων](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - Βασικές αρχές του Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - Μορφές αρχείων Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - Εισαγωγή στη μορφή αρχείου Compound File Binary](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - Αναφορά προδιαγραφών RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
