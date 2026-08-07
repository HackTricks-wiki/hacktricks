# Stego

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην **εύρεση και εξαγωγή κρυφών δεδομένων** από αρχεία (εικόνες/audio/video/έγγραφα/αρχεία) και σε steganography βασισμένη σε κείμενο.

Αν βρίσκεστε εδώ για cryptographic attacks, μεταβείτε στην ενότητα **Crypto**.

## Σημείο εκκίνησης

Αντιμετωπίστε τη steganography ως πρόβλημα forensics: εντοπίστε το πραγματικό container, εξετάστε τις τοποθεσίες υψηλού σήματος (metadata, appended data, embedded files) και μόνο έπειτα εφαρμόστε τεχνικές εξαγωγής σε επίπεδο περιεχομένου.

### Workflow & triage

Ένα δομημένο workflow που δίνει προτεραιότητα στην αναγνώριση του container, την επιθεώρηση metadata/strings, το carving και τη διακλάδωση ανά format.

{{#ref}}
workflow/README.md
{{#endref}}

### Εικόνες

Εδώ βρίσκεται το μεγαλύτερο μέρος του CTF stego: LSB/bit-planes (PNG/BMP), ιδιομορφίες chunk/file-format, εργαλεία JPEG και τεχνικές πολλαπλών frames σε GIF.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Μηνύματα σε spectrogram, embedding μέσω sample LSB και ήχοι telephone keypad (DTMF) είναι επαναλαμβανόμενα μοτίβα.

{{#ref}}
audio/README.md
{{#endref}}

### Κείμενο

Αν το κείμενο εμφανίζεται κανονικά αλλά συμπεριφέρεται απροσδόκητα, εξετάστε Unicode homoglyphs, zero-width characters ή encoding βασισμένο σε whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Έγγραφα

Τα PDF και τα Office αρχεία είναι πρώτα containers· οι επιθέσεις συνήθως περιστρέφονται γύρω από embedded files/streams, object/relationship graphs και ZIP extraction.

{{#ref}}
documents/README.md
{{#endref}}

### Malware και steganography τύπου delivery

Η παράδοση Payload χρησιμοποιεί συχνά αρχεία που φαίνονται έγκυρα (π.χ. GIF/PNG) και περιέχουν text payloads οριοθετημένα με markers, αντί για απόκρυψη σε επίπεδο pixel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
