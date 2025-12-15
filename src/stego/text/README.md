# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Ψάξτε για:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Πρακτική προσέγγιση

Αν το απλό κείμενο συμπεριφέρεται απρόσμενα, ελέγξτε τα codepoints και κανονικοποιήστε προσεκτικά (μην καταστρέψετε αποδεικτικά στοιχεία).

### Τεχνική

Text stego συχνά βασίζεται σε χαρακτήρες που εμφανίζονται πανομοιότυπα (ή αόρατα):

- Homoglyphs: διαφορετικά Unicode codepoints που μοιάζουν (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Επιπλέον περιπτώσεις με υψηλό σήμα:

- Bidirectional override/control characters (μπορεί να αναδιατάξουν οπτικά το κείμενο)
- Variation selectors and combining characters που χρησιμοποιούνται ως κρυφός δίαυλος

### Βοηθήματα αποκωδικοποίησης

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Επιθεώρηση codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
{{#include ../../banners/hacktricks-training.md}}
