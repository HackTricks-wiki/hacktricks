# Στεγανογραφία κειμένου

{{#include ../../banners/hacktricks-training.md}}

## Πρακτική διαδρομή

Αν το plain text συμπεριφέρεται απροσδόκητα, διατηρήστε τα αρχικά στοιχεία ως αποδεικτικά, εξετάστε τα codepoints και κανονικοποιήστε μόνο ένα αντίγραφο.

### Τεχνική

Η text steganography βασίζεται συχνά σε χαρακτήρες που αποδίδονται οπτικά με τον ίδιο τρόπο ή είναι αόρατοι:

- Homoglyphs: διαφορετικά Unicode codepoints που μοιάζουν μεταξύ τους (για παράδειγμα, το λατινικό `a` και το κυριλλικό `а`)<sup>[[1]](#references)</sup>
- Χαρακτήρες μηδενικού πλάτους: joiners, non-joiners και κενά μηδενικού πλάτους<sup>[[2]](#references)</sup>
- Κωδικοποιήσεις whitespace: κενά έναντι tabs, μοτίβα trailing-space και σκόπιμα μοτίβα μήκους γραμμών<sup>[[3]](#references)[[4]](#references)</sup>

Πρόσθετες περιπτώσεις υψηλού σήματος:

- Bidirectional controls, που μπορούν να αναδιατάξουν οπτικά το κείμενο<sup>[[1]](#references)</sup>
- Variation selectors και combining characters, που μπορούν να μεταφέρουν κρυφή κατάσταση ενώ αφήνουν το ορατό κείμενο σχεδόν αμετάβλητο<sup>[[1]](#references)</sup>

### Βοηθήματα αποκωδικοποίησης

- [Unicode homoglyph and zero-width-character encoder/decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

Οι κανόνες `@font-face` μπορούν να χρησιμοποιηθούν καταχρηστικά για την κωδικοποίηση bytes σε καταχωρίσεις `unicode-range: U+..`. Εξαγάγετε τα codepoints, συνενώστε τις δεκαεξαδικές τιμές και αποκωδικοποιήστε τα:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Αν οι ranges περιέχουν πολλαπλές τιμές ανά δήλωση, διαχωρίστε πρώτα με κόμματα και κανονικοποιήστε (`tr ',+' '\n'`). Η Python μπορεί να αναλύσει και να εξάγει τα bytes όταν η μορφοποίηση είναι ασυνεπής.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Ζητήματα ασφάλειας του Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganography Unicode με χαρακτήρες μηδενικού πλάτους και Homoglyphs](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Wishlist του Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Εγχειρίδιο Debian: stegsnow steganography με whitespace](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
