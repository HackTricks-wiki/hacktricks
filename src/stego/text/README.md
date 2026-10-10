# Στεγανογραφία κειμένου

{{#include ../../banners/hacktricks-training.md}}

## Πρακτική διαδρομή

Αν το απλό κείμενο συμπεριφέρεται απροσδόκητα, διατηρήστε τα αρχικά στοιχεία, εξετάστε τα codepoints του και κανονικοποιήστε μόνο ένα αντίγραφο.

### Τεχνική

Η στεγανογραφία κειμένου συχνά βασίζεται σε χαρακτήρες που εμφανίζονται πανομοιότυποι ή είναι αόρατοι:

- Ομόγλυφα: διαφορετικά Unicode codepoints που μοιάζουν (για παράδειγμα, το λατινικό `a` και το κυριλλικό `а`)<sup>[[1]](#references)</sup>
- Χαρακτήρες μηδενικού πλάτους: χαρακτήρες σύνδεσης, μη σύνδεσης και κενά μηδενικού πλάτους<sup>[[2]](#references)</sup>
- Κωδικοποιήσεις λευκού διαστήματος: κενά έναντι στηλοθετών, μοτίβα κενών στο τέλος γραμμής και σκόπιμα μοτίβα μήκους γραμμών<sup>[[3]](#references)[[4]](#references)</sup>

Πρόσθετες περιπτώσεις με ισχυρές ενδείξεις:

- Αμφίδρομα στοιχεία ελέγχου, τα οποία μπορούν να αναδιατάξουν οπτικά το κείμενο<sup>[[1]](#references)</sup>
- Επιλογείς παραλλαγών και συνδυαστικοί χαρακτήρες, οι οποίοι μπορούν να μεταφέρουν κρυφή κατάσταση, αφήνοντας το ορατό κείμενο σχεδόν αμετάβλητο<sup>[[1]](#references)</sup>

### Βοηθητικά εργαλεία αποκωδικοποίησης

- [Κωδικοποιητής/αποκωδικοποιητής Unicode για ομόγλυφα και χαρακτήρες μηδενικού πλάτους](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Εξέταση codepoints

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

Οι κανόνες `@font-face` μπορούν να χρησιμοποιηθούν καταχρηστικά για την κωδικοποίηση byte σε καταχωρίσεις `unicode-range: U+..`. Εξαγάγετε τα codepoint, συνενώστε τις δεκαεξαδικές τιμές και αποκωδικοποιήστε τις:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Αν τα ranges περιέχουν πολλαπλές τιμές ανά δήλωση, διαχωρίστε πρώτα με κόμματα και κανονικοποιήστε (`tr ',+' '\n'`). Η Python μπορεί να αναλύσει και να εξαγάγει τα bytes όταν η μορφοποίηση είναι ασυνεπής.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Τεχνική Έκθεση #36: Ζητήματα ασφάλειας Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode Steganography με χαρακτήρες μηδενικού πλάτους και ομόγλυφα](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Η λίστα επιθυμιών του Santa](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Εγχειρίδιο Debian: στεγανογραφία κενού διαστήματος με `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
