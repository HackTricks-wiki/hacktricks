# Στεγανογραφία κειμένου

{{#include ../../banners/hacktricks-training.md}}

Αναζητήστε:

- Unicode homoglyphs
- Χαρακτήρες μηδενικού πλάτους
- Μοτίβα κενών διαστημάτων (κενά έναντι tab)

## Πρακτική προσέγγιση

Αν το απλό κείμενο συμπεριφέρεται απροσδόκητα, επιθεωρήστε τα codepoints και κάντε προσεκτικά normalize (μην καταστρέψετε τα στοιχεία).

### Τεχνική

Το Text stego βασίζεται συχνά σε χαρακτήρες που εμφανίζονται πανομοιότυπα (ή είναι αόρατοι):

- Homoglyphs: διαφορετικά Unicode codepoints που φαίνονται ίδια (Latin `a` έναντι Cyrillic `а`)
- Χαρακτήρες μηδενικού πλάτους: joiners, non-joiners, κενά μηδενικού πλάτους
- Κωδικοποιήσεις κενών διαστημάτων: κενά έναντι tab, κενά στο τέλος, μοτίβα μήκους γραμμών<sup>[[1]](#references)</sup>

Επιπλέον περιπτώσεις υψηλής ενδεικτικότητας:

- Χαρακτήρες ελέγχου/παράκαμψης αμφίδρομης κατεύθυνσης (μπορούν να αναδιατάξουν οπτικά το κείμενο)
- Variation selectors και combining characters που χρησιμοποιούνται ως covert channel

### Βοηθήματα αποκωδικοποίησης

- Playground για Unicode homoglyph/zero-width: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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
## Κανάλια CSS `unicode-range`

Οι κανόνες `@font-face` μπορούν να κωδικοποιούν bytes σε καταχωρίσεις `unicode-range: U+..`. Εξαγάγετε τα codepoints, ενώστε τα hex και αποκωδικοποιήστε:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Αν τα ranges περιέχουν πολλά bytes ανά δήλωση, διαχωρίστε τα πρώτα στα κόμματα και κανονικοποιήστε τα (`tr ',+' '\n'`). Η Python διευκολύνει την ανάλυση και την έξοδο bytes όταν η μορφοποίηση δεν είναι συνεπής.

## Αναφορές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
