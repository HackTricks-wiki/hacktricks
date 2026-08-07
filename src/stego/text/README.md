# Στεγανογραφία κειμένου

{{#include ../../banners/hacktricks-training.md}}

Αναζητήστε:

- Unicode homoglyphs
- Χαρακτήρες μηδενικού πλάτους
- Μοτίβα κενών διαστημάτων (κενά έναντι tab)

## Πρακτική προσέγγιση

Αν το απλό κείμενο συμπεριφέρεται απροσδόκητα, επιθεωρήστε τα codepoints και κανονικοποιήστε το προσεκτικά (μην καταστρέψετε τα στοιχεία).

### Τεχνική

Η stego κειμένου βασίζεται συχνά σε χαρακτήρες που αποδίδονται με τον ίδιο τρόπο (ή είναι αόρατοι):

- Homoglyphs: διαφορετικά Unicode codepoints που μοιάζουν ίδια (Latin `a` έναντι Cyrillic `а`)
- Χαρακτήρες μηδενικού πλάτους: joiners, non-joiners, κενά μηδενικού πλάτους
- Κωδικοποιήσεις κενών διαστημάτων: κενά έναντι tab, τελικά κενά, μοτίβα μήκους γραμμών<sup>[[1]](#references)</sup>

Πρόσθετες περιπτώσεις υψηλού σήματος:

- Χαρακτήρες παράκαμψης/ελέγχου διπλής κατεύθυνσης (μπορούν να αναδιατάξουν οπτικά το κείμενο)
- Variation selectors και combining characters που χρησιμοποιούνται ως covert channel

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
## Κανάλια CSS `unicode-range`

Οι κανόνες `@font-face` μπορούν να κωδικοποιούν bytes σε καταχωρίσεις `unicode-range: U+..`. Εξαγάγετε τα codepoints, ενώστε τα hex και κάντε decode:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Αν τα ranges περιέχουν πολλά bytes ανά δήλωση, διαχωρίστε τα πρώτα με κόμματα και κανονικοποιήστε τα (`tr ',+' '\n'`). Η Python διευκολύνει την ανάλυση και την έξοδο bytes όταν η μορφοποίηση δεν είναι συνεπής.<sup>[[1]](#references)</sup>

## Αναφορές

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}
