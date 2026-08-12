# Steganography εγγράφων

{{#include ../../banners/hacktricks-training.md}}

Πολλές μορφές εγγράφων είναι δομημένα containers και όχι μεμονωμένα data streams:<sup>[[1]](#references)</sup><sup>[[3]](#references)</sup>

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` είναι ZIPs)
- Legacy RTF και OLE/Compound File Binary documents. Το RTF αποθηκεύει control words και groups σε text-oriented format, ενώ τα OLE compound files εκθέτουν μια ιεραρχία storage objects και streams παρόμοια με file system· και τα δύο απαιτούν format-specific inspection για κρυφά ή embedded data.<sup>[[5]](#references)</sup><sup>[[6]](#references)</sup>

## PDF

### Τεχνική

Τα αρχεία PDF μπορούν να περιέχουν objects, streams, JavaScript και embedded files. Κατά την ανάλυση, οι συνήθεις εργασίες περιλαμβάνουν:

- Εξαγωγή embedded attachments.
- Ανάπτυξη object streams, ώστε τα objects να επιθεωρούνται ευκολότερα.
- Εντοπισμός JavaScript, embedded images και ασυνήθιστων streams.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

### Γρήγοροι έλεγχοι
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Ο συνδυασμός `--qdf --object-streams=disable` παράγει μια πιο ευανάγνωστη αναπαράσταση και αφαιρεί τα object streams, διευκολύνοντας τη χειροκίνητη επιθεώρηση.<sup>[[2]](#references)</sup> Στη συνέχεια, αναζητήστε στο `out.pdf` ύποπτα objects και strings.

## Office OOXML

### Τεχνική

Τα αρχεία Office Open XML (`.docx`, `.xlsx` και `.pptx`) χρησιμοποιούν τα Open Packaging Conventions: ένα πακέτο βασισμένο σε ZIP, αποτελούμενο από parts και XML relationship files.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup> Αντιμετωπίστε το πακέτο ως relationship graph και επιθεωρήστε τα media, τα external relationships και τα ασυνήθιστα custom parts.

Στην πράξη:

- Το document είναι ένα directory tree από XML και assets.
- Τα relationship files στον κατάλογο `_rels/` μπορούν να παραπέμπουν σε external resources ή κρυφά parts.
- Ενσωματωμένα δεδομένα βρίσκονται συχνά στο `word/media/`, σε custom XML parts ή σε ασυνήθιστα relationships.

### Γρήγοροι έλεγχοι
```bash
7z l file.docx
7z x file.docx -oout
```
Στη συνέχεια, εξετάστε:

- `word/document.xml`
- `word/_rels/` για εξωτερικές σχέσεις
- ενσωματωμένα media στο `word/media/`

## References

- [1] [Εγχειρίδιο Poppler pdfdetach](https://manpages.debian.org/trixie/poppler-utils/pdfdetach.1.en.html)
- [2] [Τεκμηρίωση qpdf - λειτουργία QDF και streams αντικειμένων](https://qpdf.readthedocs.io/en/stable/cli.html#qdf-mode)
- [3] [Microsoft Learn - βασικές αρχές Open Packaging Conventions](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/opc/open-packaging-conventions-overview)
- [4] [ECMA-376 - μορφές αρχείων Office Open XML](https://ecma-international.org/publications-and-standards/standards/ecma-376/)
- [5] [Microsoft Open Specifications - εισαγωγή στη μορφή Compound File Binary File](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/50708a61-81d9-49c8-ab9c-43c98a795242)
- [6] [Microsoft Open Specifications - αναφορά προδιαγραφών RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/85c0b884-a960-4d1a-874e-53eeee527ca6)
{{#include ../../banners/hacktricks-training.md}}
