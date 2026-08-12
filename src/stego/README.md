# Stego

{{#include ../banners/hacktricks-training.md}}

Αυτή η ενότητα εστιάζει στην **εύρεση και εξαγωγή κρυφών δεδομένων** από εικόνες, ήχο, βίντεο, έγγραφα, αρχεία και κείμενο. Η Steganography αποκρύπτει την ύπαρξη μιας επικοινωνίας ενσωματώνοντας δεδομένα μέσα σε άλλα δεδομένα.<sup>[[1]](#references)</sup>

Αν αναζητάτε cryptographic attacks, μεταβείτε στην ενότητα **Crypto**.

## Σημείο εισόδου

Προσεγγίστε τη steganography ως πρόβλημα forensics: εντοπίστε τον πραγματικό container, απαριθμήστε τις τοποθεσίες με υψηλό σήμα (metadata, appended data, embedded files) και μόνο κατόπιν εφαρμόστε τεχνικές εξαγωγής σε επίπεδο περιεχομένου.

### Ροή εργασίας και triage

Μια δομημένη ροή εργασίας που δίνει προτεραιότητα στην αναγνώριση του container, την επιθεώρηση metadata/strings, το carving και τη διακλάδωση ανάλογα με το format.

{{#ref}}
workflow/README.md
{{#endref}}

### Εικόνες

Εδώ βρίσκεται το μεγαλύτερο μέρος του CTF stego: LSB/bit-planes (PNG/BMP), ιδιομορφίες chunk/file-format, εργαλεία JPEG και τεχνικές multi-frame GIF.

{{#ref}}
images/README.md
{{#endref}}

### Ήχος

Μηνύματα σε spectrogram, ενσωμάτωση sample LSB και τόνοι τηλεφωνικού πληκτρολογίου (DTMF) είναι επαναλαμβανόμενα μοτίβα.

{{#ref}}
audio/README.md
{{#endref}}

### Κείμενο

Αν το κείμενο εμφανίζεται κανονικά αλλά συμπεριφέρεται απροσδόκητα, εξετάστε Unicode homoglyphs, zero-width characters ή encoding βασισμένο σε whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Έγγραφα

Τα PDF και τα Office files είναι πρώτα απ' όλα containers· οι επιθέσεις συνήθως περιστρέφονται γύρω από embedded files/streams, object/relationship graphs και ZIP extraction.

{{#ref}}
documents/README.md
{{#endref}}

### Steganography σε malware και delivery

Η παράδοση payload μπορεί να χρησιμοποιεί αρχεία που φαίνονται έγκυρα, όπως εικόνες GIF ή PNG, τα οποία περιέχουν text payloads οριοθετημένα με markers αντί να αποκρύπτουν δεδομένα στα pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
