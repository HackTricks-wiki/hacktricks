# Homograph / Homoglyph Attacks in Phishing

{{#include ../../banners/hacktricks-training.md}}

## Επισκόπηση

Μια επίθεση homograph (γνωστή και ως homoglyph) εκμεταλλεύεται το γεγονός ότι πολλά **Unicode code points από μη λατινικά scripts είναι οπτικά πανομοιότυπα ή εξαιρετικά παρόμοια με χαρακτήρες ASCII**. Αντικαθιστώντας έναν ή περισσότερους λατινικούς χαρακτήρες με τα αντίστοιχα οπτικά παρόμοια σύμβολα, ένας attacker μπορεί να δημιουργήσει:

* Display names, subjects ή message bodies που φαίνονται νόμιμα στο ανθρώπινο μάτι, αλλά παρακάμπτουν detections που βασίζονται σε keywords.
* Domains, sub-domains ή URL paths που ξεγελούν τα victims ώστε να πιστέψουν ότι επισκέπτονται ένα trusted site.<sup>[[1]](#references)</sup>

Επειδή κάθε glyph αναγνωρίζεται εσωτερικά από το **Unicode code point** του, ένας μόνο αντικαταστημένος χαρακτήρας αρκεί για να παρακάμψει naïve string comparisons (π.χ. `"Παypal.com"` έναντι `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Τυπικό Phishing Workflow

1. **Craft message content** – Αντικαταστήστε συγκεκριμένα λατινικά γράμματα στο impersonated brand / keyword με οπτικά δυσδιάκριτους χαρακτήρες από άλλο script (Greek, Cyrillic, Armenian, Cherokee κ.λπ.).
2. **Register supporting infrastructure** – Προαιρετικά, κάντε register ένα homoglyph domain και αποκτήστε ένα TLS certificate (τα περισσότερα CAs δεν πραγματοποιούν visual similarity checks).
3. **Send email / SMS** – Το message περιέχει homoglyphs σε μία ή περισσότερες από τις ακόλουθες τοποθεσίες:
* Sender display name (π.χ. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text ή fully qualified domain name
4. **Redirect chain** – Το victim περνά διαδοχικά από φαινομενικά benign websites ή URL shorteners, προτού καταλήξει στον malicious host που συλλέγει credentials / παραδίδει malware.<sup>[[1]](#references)</sup>

## Unicode Ranges που χρησιμοποιούνται συχνά καταχρηστικά

Τα ακόλουθα παραδείγματα είναι Unicode blocks που περιέχουν χαρακτήρες οι οποίοι χρησιμοποιούνται συχνά για τη δημιουργία cross-script look-alikes.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Tip: Χρησιμοποιήστε τα Unicode code charts για να αναζητήσετε blocks και code points.

## Τεχνικές Detection

### 1. Mixed-Script Inspection

Τα Phishing emails που στοχεύουν έναν organisation με αγγλόφωνους χρήστες σπάνια θα πρέπει να συνδυάζουν χαρακτήρες από πολλά scripts. Ένα απλό αλλά αποτελεσματικό heuristic είναι να:

1. Επαναλάβετε κάθε χαρακτήρα του string που επιθεωρείται.
2. Αντιστοιχίσετε το code point στο όνομα του script ή στο Unicode block.
3. Δημιουργήσετε alert αν υπάρχει περισσότερα από ένα scripts **ή** αν εμφανίζονται μη λατινικά scripts σε σημεία όπου δεν αναμένονται (display name, domain, subject, URL κ.λπ.).<sup>[[3]](#references)</sup>

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
### 2. Punycode Normalisation (Domains)

Τα Internationalised Domain Names (IDNs) έχουν μορφή Unicode και μορφή **Punycode** συμβατή με ASCII, με πρόθεμα `xn--`. Μετατρέπετε τα hostnames στη μορφή IDNA/Punycode πριν από την προσθήκη τους σε allow-list ή τη σύγκρισή τους, διατηρώντας τη μορφή Unicode για εμφάνιση.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Dictionaries / Algorithms

Tools such as **dnstwist** (`--fuzzers homoglyph`) or **urlcrazy** can enumerate visually-similar domain permutations and are useful for proactive takedown / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Πρόληψη & Μετριασμός

* Επιβάλετε αυστηρές πολιτικές DMARC/DKIM/SPF – αποτρέψτε spoofing από μη εξουσιοδοτημένα domains.
* Υλοποιήστε την παραπάνω λογική detection σε **Secure Email Gateways** και playbooks του **SIEM/XSOAR**.
* Επισημάνετε ή θέστε σε quarantine μηνύματα όπου το domain του display name ≠ το domain του sender.
* Εκπαιδεύστε τους χρήστες: επικολλήστε ύποπτο κείμενο σε έναν Unicode inspector, κάντε hover πάνω από links, μην εμπιστεύεστε ποτέ URL shorteners.

## Παραδείγματα από τον Πραγματικό Κόσμο

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login at `mlcorsftpsswddprotcct.approaches.it.com` protected by custom OTP CAPTCHA.
* Impersonation του Spotify: sender `Sρօtifս` με link κρυμμένο πίσω από το `redirects.ca`.

Αυτά τα δείγματα προέρχονται από έρευνα της Unit 42 (Ιούλιος 2025) και δείχνουν πώς η κατάχρηση homograph συνδυάζεται με URL redirection και CAPTCHA evasion για την παράκαμψη αυτοματοποιημένης ανάλυσης.<sup>[[1]](#references)</sup>

## References

- [1] [Η ψευδαίσθηση του Homograph: Δεν είναι όλα όπως φαίνονται](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Πίνακες κωδικών χαρακτήρων Unicode](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Μηχανισμοί ασφάλειας Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – μηχανή permutations domain](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator για domain typos και variations](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Ορισμοί και πλαίσιο εγγράφου](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
