# Homograph / Homoglyph Attacks in Phishing

## Επισκόπηση

Μια επίθεση homograph (γνωστή και ως επίθεση homoglyph) εκμεταλλεύεται το γεγονός ότι πολλά **Unicode code points από μη λατινικά αλφάβητα είναι οπτικά πανομοιότυπα ή εξαιρετικά παρόμοια με χαρακτήρες ASCII**. Αντικαθιστώντας έναν ή περισσότερους λατινικούς χαρακτήρες με τα αντίστοιχα οπτικά παρόμοια στοιχεία, ένας attacker μπορεί να δημιουργήσει:

* Display names, subjects ή message bodies που φαίνονται νόμιμα στο ανθρώπινο μάτι, αλλά παρακάμπτουν detections που βασίζονται σε keywords.
* Domains, sub-domains ή URL paths που κάνουν τα victims να πιστεύουν ότι επισκέπτονται ένα trusted site.<sup>[[1]](#references)</sup>

Επειδή κάθε glyph αναγνωρίζεται εσωτερικά από το **Unicode code point** του, ένας μόνο αντικατασταθείς χαρακτήρας αρκεί για να παρακάμψει naïve string comparisons (π.χ. `"Παypal.com"` έναντι `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Συνήθης Ροή Phishing

1. **Craft message content** – Αντικατάσταση συγκεκριμένων λατινικών γραμμάτων στο impersonated brand / keyword με οπτικά μη διακριτούς χαρακτήρες από άλλο script (Greek, Cyrillic, Armenian, Cherokee κ.λπ.).
2. **Register supporting infrastructure** – Προαιρετική καταχώριση ενός homoglyph domain και απόκτηση TLS certificate (οι περισσότερες CAs δεν πραγματοποιούν visual similarity checks).
3. **Send email / SMS** – Το message περιέχει homoglyphs σε μία ή περισσότερες από τις ακόλουθες τοποθεσίες:
* Sender display name (π.χ. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text ή fully qualified domain name
4. **Redirect chain** – Το victim ανακατευθύνεται μέσω φαινομενικά benign websites ή URL shorteners, πριν καταλήξει στον malicious host που συλλέγει credentials / παραδίδει malware.<sup>[[1]](#references)</sup>

## Unicode Ranges που Χρησιμοποιούνται Συχνά

Τα ακόλουθα παραδείγματα είναι Unicode blocks που περιέχουν χαρακτήρες οι οποίοι χρησιμοποιούνται συχνά για τη δημιουργία cross-script look-alikes.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> Συμβουλή: Χρησιμοποιήστε τα Unicode code charts για να εντοπίσετε blocks και code points.

## Τεχνικές Detection

### 1. Mixed-Script Inspection

Τα phishing emails που στοχεύουν έναν αγγλόφωνο οργανισμό σπάνια θα πρέπει να αναμειγνύουν χαρακτήρες από πολλά scripts. Ένα απλό αλλά αποτελεσματικό heuristic είναι να:

1. Επαναλάβετε κάθε χαρακτήρα του inspected string.
2. Αντιστοιχίσετε το code point στο όνομα του script ή στο Unicode block.
3. Ενεργοποιήσετε alert αν υπάρχει περισσότερα από ένα scripts **ή** αν εμφανίζονται μη λατινικά scripts σε σημεία όπου δεν αναμένονται (display name, domain, subject, URL κ.λπ.).<sup>[[3]](#references)</sup>

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

Τα Internationalised Domain Names (IDNs) έχουν μορφή Unicode και μορφή **Punycode** συμβατή με ASCII, με πρόθεμα `xn--`. Μετατρέψτε τα hostnames στη μορφή IDNA/Punycode πριν από την προσθήκη τους σε allow-list ή τη σύγκρισή τους, διατηρώντας τη μορφή Unicode για εμφάνιση.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Λεξικά / Αλγόριθμοι Homoglyph

Tools όπως το **dnstwist** (`--fuzzers homoglyph`) ή το **urlcrazy** μπορούν να απαριθμήσουν οπτικά παρόμοιες παραλλαγές domain και είναι χρήσιμα για προληπτικό takedown / monitoring.<sup>[[4]](#references)[[5]](#references)</sup>

## Πρόληψη & Μετριασμός

* Επιβάλετε αυστηρές πολιτικές DMARC/DKIM/SPF – αποτρέψτε το spoofing από μη εξουσιοδοτημένα domains.
* Υλοποιήστε την παραπάνω λογική detection σε **Secure Email Gateways** και playbooks του **SIEM/XSOAR**.
* Επισημάνετε ή θέστε σε καραντίνα μηνύματα όπου το domain του display name ≠ το domain του sender.
* Εκπαιδεύστε τους χρήστες: να κάνουν copy-paste ύποπτο κείμενο σε έναν Unicode inspector, να κάνουν hover πάνω από links και να μην εμπιστεύονται ποτέ URL shorteners.

## Παραδείγματα από τον Πραγματικό Κόσμο

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Αλυσίδα domain: `bestseoservices.com` ➜ δημοτικός κατάλογος `/templates` ➜ `kig.skyvaulyt.ru` ➜ fake Microsoft login στο `mlcorsftpsswddprotcct.approaches.it.com`, προστατευμένο από custom OTP CAPTCHA.
* Impersonation του Spotify: sender `Sρօtifս` με link κρυμμένο πίσω από το `redirects.ca`.

Αυτά τα δείγματα προέρχονται από έρευνα της Unit 42 (Ιούλιος 2025) και δείχνουν πώς η κατάχρηση homograph συνδυάζεται με URL redirection και CAPTCHA evasion για την παράκαμψη αυτοματοποιημένης ανάλυσης.<sup>[[1]](#references)</sup>

## References

- [1] [Η ψευδαίσθηση Homograph: Δεν είναι όλα όπως φαίνονται](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Πίνακες κωδικών χαρακτήρων Unicode](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Μηχανισμοί ασφάλειας Unicode](https://unicode.org/reports/tr39/)
- [4] [dnstwist – μηχανή παραλλαγών domain](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – generator για domain typo και παραλλαγές](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Ορισμοί και πλαίσιο εγγράφου](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
