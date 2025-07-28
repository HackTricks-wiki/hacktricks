# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Overview

Μια επίθεση homograph (γνωστή και ως homoglyph) εκμεταλλεύεται το γεγονός ότι πολλά **Unicode code points από μη λατινικά σενάρια είναι οπτικά ταυτόσημα ή εξαιρετικά παρόμοια με χαρακτήρες ASCII**. Αντικαθιστώντας έναν ή περισσότερους λατινικούς χαρακτήρες με τους οπτικά παρόμοιους ομολόγους τους, ένας επιτιθέμενος μπορεί να δημιουργήσει:

* Ονόματα εμφάνισης, θέματα ή σώματα μηνυμάτων που φαίνονται νόμιμα στο ανθρώπινο μάτι αλλά παρακάμπτουν τις ανιχνεύσεις βασισμένες σε λέξεις-κλειδιά.
* Τομείς, υποτομείς ή διαδρομές URL που παραπλανούν τα θύματα να πιστεύουν ότι επισκέπτονται έναν αξιόπιστο ιστότοπο.

Επειδή κάθε γλυφικό αναγνωρίζεται εσωτερικά από το **Unicode code point** του, ένας μόνο αντικατεστημένος χαρακτήρας είναι αρκετός για να νικήσει τις απλές συγκρίσεις συμβολοσειρών (π.χ., `"Παypal.com"` vs. `"Paypal.com"`).

## Typical Phishing Workflow

1. **Craft message content** – Αντικαταστήστε συγκεκριμένα λατινικά γράμματα στην προσποιούμενη μάρκα / λέξη-κλειδί με οπτικά αδιάκριτους χαρακτήρες από άλλο σενάριο (Ελληνικά, Κυριλλικά, Αρμενικά, Τσερόκι, κ.λπ.).
2. **Register supporting infrastructure** – Προαιρετικά, καταχωρήστε έναν τομέα homoglyph και αποκτήστε ένα πιστοποιητικό TLS (οι περισσότερες CA δεν κάνουν οπτικούς ελέγχους ομοιότητας).
3. **Send email / SMS** – Το μήνυμα περιέχει homoglyphs σε μία ή περισσότερες από τις παρακάτω τοποθεσίες:
* Όνομα αποστολέα (π.χ., `Ηеlрdеѕk`)
* Θέμα (`Urgеnt Аctіon Rеquіrеd`)
* Κείμενο υπερσύνδεσης ή πλήρως προσδιορισμένο όνομα τομέα
4. **Redirect chain** – Το θύμα ανακατευθύνεται μέσω φαινομενικά αθώων ιστότοπων ή συντομευτών URL πριν προσγειωθεί στον κακόβουλο διακομιστή που συλλέγει διαπιστευτήρια / παραδίδει κακόβουλο λογισμικό.

## Unicode Ranges Commonly Abused

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Full Unicode charts are available at [unicode.org](https://home.unicode.org/).

## Detection Techniques

### 1. Mixed-Script Inspection

Τα phishing emails που στοχεύουν σε μια αγγλόφωνη οργάνωση θα πρέπει σπάνια να αναμειγνύουν χαρακτήρες από πολλαπλά σενάρια. Μια απλή αλλά αποτελεσματική ευρετική μέθοδος είναι να:

1. Διατρέξετε κάθε χαρακτήρα της εξεταζόμενης συμβολοσειράς.
2. Χαρτογραφήστε το code point στο Unicode block του.
3. Ενεργοποιήστε μια ειδοποίηση αν υπάρχει περισσότερα από ένα σενάριο **ή** αν εμφανίζονται μη λατινικά σενάρια όπου δεν αναμένονται (όνομα εμφάνισης, τομέας, θέμα, URL, κ.λπ.).

Python proof-of-concept:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Κανονικοποίηση Punycode (Τομείς)

Τα Διεθνοποιημένα Ονόματα Τομέων (IDNs) κωδικοποιούνται με **punycode** (`xn--`). Η μετατροπή κάθε ονόματος υποδομής σε punycode και στη συνέχεια πίσω σε Unicode επιτρέπει την αντιστοίχιση με μια λευκή λίστα ή την εκτέλεση ελέγχων ομοιότητας (π.χ., απόσταση Levenshtein) **μετά** την κανονικοποίηση της συμβολοσειράς.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Ομογράμματα Λεξικά / Αλγόριθμοι

Εργαλεία όπως το **dnstwist** (`--homoglyph`) ή το **urlcrazy** μπορούν να απαριθμήσουν οπτικά παρόμοιες παραλλαγές τομέων και είναι χρήσιμα για προληπτική κατάργηση / παρακολούθηση.

## Πρόληψη & Ελάφρυνση

* Επιβολή αυστηρών πολιτικών DMARC/DKIM/SPF – αποτροπή παραποίησης από μη εξουσιοδοτημένους τομείς.
* Υλοποίηση της λογικής ανίχνευσης παραπάνω σε **Secure Email Gateways** και **SIEM/XSOAR** playbooks.
* Σημείωση ή καραντίνα μηνυμάτων όπου το domain του εμφανιζόμενου ονόματος ≠ το domain του αποστολέα.
* Εκπαίδευση χρηστών: αντιγραφή-επικόλληση ύποπτου κειμένου σε έναν επιθεωρητή Unicode, αιωρούμενοι σύνδεσμοι, ποτέ μην εμπιστεύεστε τους συντομευτές URL.

## Παραδείγματα από τον Πραγματικό Κόσμο

* Εμφανιζόμενο όνομα: `Сonfidеntiаl Ꭲiꮯkеt` (Κυριλλικό `С`, `е`, `а`; Τσερόκι `Ꭲ`; Λατινικό μικρό κεφαλαίο `ꮯ`).
* Αλυσίδα τομέα: `bestseoservices.com` ➜ δημοτικός κατάλογος `/templates` ➜ `kig.skyvaulyt.ru` ➜ ψεύτικη είσοδος Microsoft στο `mlcorsftpsswddprotcct.approaches.it.com` προστατευμένη από προσαρμοσμένο OTP CAPTCHA.
* Υποκλοπή Spotify: αποστολέας `Sρօtifւ` με σύνδεσμο κρυμμένο πίσω από `redirects.ca`.

Αυτά τα δείγματα προέρχονται από την έρευνα της Unit 42 (Ιούλιος 2025) και απεικονίζουν πώς η κακοποίηση ομογραμμάτων συνδυάζεται με ανακατεύθυνση URL και αποφυγή CAPTCHA για να παρακάμψει την αυτοματοποιημένη ανάλυση.

## Αναφορές

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
