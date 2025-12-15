# Document Steganography

{{#include ../../banners/hacktricks-training.md}}

Τα έγγραφα είναι συχνά απλά δοχεία:

- PDF (ενσωματωμένα αρχεία, ροές)
- Office OOXML (`.docx/.xlsx/.pptx` είναι ZIPs)
- RTF / OLE παρωχημένες μορφές

## PDF

### Τεχνική

Το PDF είναι ένα δομημένο δοχείο με αντικείμενα, ροές και προαιρετικά ενσωματωμένα αρχεία. Σε CTFs συχνά χρειάζεται να:

- Εξαγάγετε ενσωματωμένα συνημμένα
- Αποσυμπιέσετε/επιπεδώσετε τις ροές αντικειμένων ώστε να μπορείτε να αναζητήσετε το περιεχόμενο
- Εντοπίσετε κρυφά αντικείμενα (JS, ενσωματωμένες εικόνες, περίεργες ροές)

### Γρήγοροι έλεγχοι
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Στη συνέχεια, αναζήτησε μέσα στο `out.pdf` για ύποπτα αντικείμενα/συμβολοσειρές.

## Office OOXML

### Τεχνική

Θεώρησε το OOXML ως γράφο σχέσεων ZIP + XML· τα payloads συχνά κρύβονται σε media, relationships ή σε ασυνήθιστα custom μέρη.

Τα αρχεία OOXML είναι ZIP containers. Αυτό σημαίνει:

- Το έγγραφο είναι δέντρο καταλόγων από XML και assets.
- Τα αρχεία `_rels/` μπορούν να δείχνουν σε εξωτερικούς πόρους ή σε κρυμμένα μέρη.
- Ενσωματωμένα δεδομένα συχνά βρίσκονται στο `word/media/`, σε custom XML parts ή σε ασυνήθιστες relationships.

### Γρήγοροι έλεγχοι
```bash
7z l file.docx
7z x file.docx -oout
```
Στη συνέχεια, ελέγξτε:

- `word/document.xml`
- `word/_rels/` για εξωτερικές σχέσεις
- ενσωματωμένα μέσα στο `word/media/`

{{#include ../../banners/hacktricks-training.md}}
