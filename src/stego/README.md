# Stego

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην **εύρεση και εξαγωγή κρυφών δεδομένων** από αρχεία (εικόνες/ήχος/βίντεο/έγγραφα/αρχεία) και από text-based steganography.

Αν ψάχνετε για κρυπτογραφικές επιθέσεις, πηγαίνετε στην ενότητα **Crypto**.

## Σημείο Εισόδου

Προσεγγίστε τη steganography ως πρόβλημα forensics: εντοπίστε τον πραγματικό container, απαριθμήστε τις τοποθεσίες υψηλού σήματος (metadata, appended data, embedded files), και μόνο τότε εφαρμόστε τεχνικές εξαγωγής σε επίπεδο περιεχομένου.

### Workflow & triage

Μια δομημένη ροή εργασίας που προτεραιοποιεί τον εντοπισμό του container, την επιθεώρηση metadata/strings, το carving, και διακλαδώσεις ανά format.
{{#ref}}
workflow/README.md
{{#endref}}

### Εικόνες

Εκεί που βρίσκεται το μεγαλύτερο μέρος του CTF stego: LSB/bit-planes (PNG/BMP), παραξενιές σε chunk/file-format, JPEG tooling, και κόλπα με multi-frame GIF.
{{#ref}}
images/README.md
{{#endref}}

### Ήχος

Μηνύματα σε spectrogram, sample LSB embedding, και τόνοι τηλεφωνικού πληκτρολογίου (DTMF) είναι επαναλαμβανόμενα μοτίβα.
{{#ref}}
audio/README.md
{{#endref}}

### Κείμενο

Αν το κείμενο εμφανίζεται κανονικά αλλά συμπεριφέρεται απροσδόκητα, σκεφτείτε Unicode homoglyphs, zero-width characters, ή whitespace-based encoding.
{{#ref}}
text/README.md
{{#endref}}

### Έγγραφα

Τα PDFs και Office αρχεία είναι πρώτα containers· οι επιθέσεις συνήθως περιστρέφονται γύρω από embedded files/streams, object/relationship graphs, και ZIP extraction.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Η παράδοση payload συχνά χρησιμοποιεί αρχεία που φαίνονται έγκυρα (π.χ., GIF/PNG) που φέρουν marker-delimited text payloads, αντί για απόκρυψη σε επίπεδο pixel.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
