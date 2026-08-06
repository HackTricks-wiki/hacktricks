# Steganography Εγγράφων

{{#include ../../banners/hacktricks-training.md}}

Τα έγγραφα συχνά είναι απλώς containers:

- PDF (embedded files, streams)
- Office OOXML (`.docx/.xlsx/.pptx` είναι ZIPs)
- RTF / OLE legacy formats

## PDF

### Technique

Το PDF είναι ένα structured container με objects, streams και προαιρετικά embedded files. Στα CTFs συχνά χρειάζεται να:

- Κάνετε extract τα embedded attachments
- Κάνετε decompress/flatten τα object streams ώστε να μπορείτε να αναζητήσετε περιεχόμενο
- Εντοπίσετε hidden objects (JS, embedded images, odd streams)

### Γρήγοροι έλεγχοι
```bash
pdfinfo file.pdf
pdfdetach -list file.pdf
pdfdetach -saveall file.pdf
qpdf --qdf --object-streams=disable file.pdf out.pdf
```
Στη συνέχεια, αναζητήστε μέσα στο `out.pdf` ύποπτα objects/strings.

## Office OOXML

### Τεχνική

Αντιμετωπίστε το OOXML ως ένα γράφημα σχέσεων ZIP + XML· τα payloads συχνά κρύβονται σε media, relationships ή ασυνήθιστα custom parts.

Τα αρχεία OOXML είναι ZIP containers. Αυτό σημαίνει ότι:

- Το document είναι ένα directory tree από XML και assets.
- Τα αρχεία relationships του `_rels/` μπορούν να παραπέμπουν σε external resources ή hidden parts.
- Τα embedded data βρίσκονται συχνά στο `word/media/`, σε custom XML parts ή σε ασυνήθιστα relationships.

### Γρήγοροι έλεγχοι
```bash
7z l file.docx
7z x file.docx -oout
```
Στη συνέχεια, ελέγξτε:

- `word/document.xml`
- `word/_rels/` για εξωτερικές σχέσεις
- ενσωματωμένα αρχεία πολυμέσων στο `word/media/`


{{#include ../../banners/hacktricks-training.md}}
