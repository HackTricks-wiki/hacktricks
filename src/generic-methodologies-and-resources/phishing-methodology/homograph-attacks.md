# Επιθέσεις Homograph / Homoglyph στο Phishing

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια επίθεση homograph (γνωστή και ως homoglyph) εκμεταλλεύεται το γεγονός ότι πολλά **Unicode code points από non-Latin scripts είναι οπτικά πανομοιότυπα ή εξαιρετικά παρόμοια με ASCII characters**. Αντικαθιστώντας έναν ή περισσότερους Latin χαρακτήρες με τα οπτικά παρόμοια αντίστοιχά τους, ένας attacker μπορεί να δημιουργήσει:

* Display names, subjects ή message bodies που φαίνονται νόμιμα στο ανθρώπινο μάτι, αλλά παρακάμπτουν detections που βασίζονται σε keywords.
* Domains, sub-domains ή URL paths που παραπλανούν τα victims, κάνοντάς τα να πιστεύουν ότι επισκέπτονται ένα trusted site.

Επειδή κάθε glyph αναγνωρίζεται εσωτερικά από το **Unicode code point** του, ένας μόνο αντικατασταθείς χαρακτήρας αρκεί για να νικήσει naïve string comparisons (π.χ., `"Παypal.com"` έναντι `"Paypal.com"`).

## Τυπικό Phishing Workflow

1. **Δημιουργία message content** – Αντικαταστήστε συγκεκριμένα Latin γράμματα στο impersonated brand / keyword με οπτικά δυσδιάκριτους χαρακτήρες από άλλο script (Greek, Cyrillic, Armenian, Cherokee κ.λπ.).
2. **Καταχώριση supporting infrastructure** – Προαιρετικά καταχωρίστε ένα homoglyph domain και αποκτήστε ένα TLS certificate (οι περισσότερες CAs δεν πραγματοποιούν visual similarity checks).
3. **Αποστολή email / SMS** – Το message περιέχει homoglyphs σε μία ή περισσότερες από τις ακόλουθες τοποθεσίες:
* Sender display name (π.χ., `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text ή fully qualified domain name
4. **Redirect chain** – Το victim περνά μέσω φαινομενικά benign websites ή URL shorteners πριν καταλήξει στον malicious host που πραγματοποιεί credential harvesting / delivers malware.

## Unicode Ranges που Συχνά Γίνονται Abuse

| Script | Range | Example glyph | Μοιάζει με |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Συμβουλή: Πλήρη Unicode charts είναι διαθέσιμα στο [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Τεχνικές Detection

### 1. Mixed-Script Inspection

Τα Phishing emails που στοχεύουν έναν English-speaking organisation σπάνια θα πρέπει να αναμειγνύουν characters από multiple scripts. Ένα απλό αλλά αποτελεσματικό heuristic είναι:

1. Επαναλάβετε κάθε character του inspected string.
2. Αντιστοιχίστε το code point στο Unicode block του.
3. Δημιουργήστε alert αν υπάρχει περισσότερα από ένα scripts **ή** αν εμφανίζονται non-Latin scripts σε σημεία όπου δεν αναμένονται (display name, domain, subject, URL κ.λπ.).

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
### 2. Κανονικοποίηση Punycode (Domains)

Τα Διεθνοποιημένα Domain Names (IDNs) κωδικοποιούνται με **punycode** (`xn--`). Η μετατροπή κάθε hostname σε punycode και, στη συνέχεια, ξανά σε Unicode επιτρέπει την αντιστοίχιση με μια whitelist ή την εκτέλεση ελέγχων ομοιότητας (π.χ. απόσταση Levenshtein) **αφού** η συμβολοσειρά έχει κανονικοποιηθεί.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[3]](#references)</sup>

## Prevention & Mitigation

* Εφαρμόστε αυστηρές πολιτικές DMARC/DKIM/SPF – αποτρέψτε το spoofing από μη εξουσιοδοτημένα domains.
* Υλοποιήστε την παραπάνω λογική detection σε **Secure Email Gateways** και playbooks SIEM/XSOAR.
* Επισημάνετε ή θέστε σε καραντίνα μηνύματα όπου το domain του display name ≠ το domain του sender.
* Εκπαιδεύστε τους χρήστες: να κάνουν copy-paste ύποπτο κείμενο σε έναν Unicode inspector, να περνούν τον δείκτη πάνω από τα links και να μην εμπιστεύονται ποτέ URL shorteners.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Spotify impersonation: `Sρօtifս` sender with link hidden behind `redirects.ca`.

Αυτά τα δείγματα προέρχονται από έρευνα της Unit 42 (Ιούλιος 2025) και δείχνουν πώς η κατάχρηση homograph συνδυάζεται με URL redirection και CAPTCHA evasion για την παράκαμψη της αυτοματοποιημένης ανάλυσης.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
