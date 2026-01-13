# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Αναζητήστε:

- Unicode homoglyphs
- Zero-width characters
- Whitespace patterns (spaces vs tabs)

## Πρακτική πορεία

Αν το plain text συμπεριφέρεται απρόσμενα, εξετάστε τα codepoints και κάντε normalize προσεκτικά (μην καταστρέψετε αποδεικτικά στοιχεία).

### Τεχνική

Text stego συχνά βασίζεται σε χαρακτήρες που αποδίδονται πανομοιότυπα (ή αόρατα):

- Homoglyphs: different Unicode codepoints that look the same (Latin `a` vs Cyrillic `а`)
- Zero-width characters: joiners, non-joiners, zero-width spaces
- Whitespace encodings: spaces vs tabs, trailing spaces, line-length patterns

Επιπλέον περιπτώσεις υψηλού σήματος:

- Bidirectional override/control characters (μπορούν οπτικά να αναδιατάξουν το κείμενο)
- Variation selectors and combining characters χρησιμοποιούνται ως κρυφό κανάλι

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
## CSS `unicode-range` κανάλια

`@font-face` κανόνες μπορούν να κωδικοποιήσουν bytes σε καταχωρήσεις `unicode-range: U+..`. Εξάγετε τα codepoints, συνενώστε τα hex και αποκωδικοποιήστε:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Αν οι ranges περιέχουν πολλαπλά bytes ανά δήλωση, χωρίστε πρώτα με κόμματα και κανονικοποιήστε (`tr ',+' '\n'`). Το Python διευκολύνει το parsing και την εκπομπή bytes αν η μορφοποίηση είναι ασυνεπής.

## Αναφορές

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
