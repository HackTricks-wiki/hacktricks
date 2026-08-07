# Εντοπισμός Phishing

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Για να εντοπίσετε μια απόπειρα phishing, είναι σημαντικό να **κατανοείτε τις τεχνικές phishing που χρησιμοποιούνται σήμερα**. Στη γονική σελίδα αυτής της ανάρτησης μπορείτε να βρείτε αυτές τις πληροφορίες, επομένως, αν δεν γνωρίζετε ποιες τεχνικές χρησιμοποιούνται σήμερα, σας συνιστώ να μεταβείτε στη γονική σελίδα και να διαβάσετε τουλάχιστον εκείνη την ενότητα.

Αυτή η ανάρτηση βασίζεται στην ιδέα ότι οι **attackers θα προσπαθήσουν με κάποιον τρόπο να μιμηθούν ή να χρησιμοποιήσουν το όνομα domain του θύματος**. Αν το domain σας ονομάζεται `example.com` και πέσετε θύμα phishing μέσω ενός εντελώς διαφορετικού domain για κάποιον λόγο, όπως το `youwonthelottery.com`, αυτές οι τεχνικές δεν πρόκειται να το αποκαλύψουν.

## Παραλλαγές ονομάτων domain

Είναι σχετικά **εύκολο** να **εντοπίσετε** εκείνες τις απόπειρες **phishing** που θα χρησιμοποιήσουν ένα **παρόμοιο domain** μέσα στο email.\
Αρκεί να **δημιουργήσετε μια λίστα με τα πιο πιθανά ονόματα phishing** που μπορεί να χρησιμοποιήσει ένας attacker και να **ελέγξετε** αν είναι **καταχωρισμένα** ή απλώς να ελέγξετε αν υπάρχει κάποια **IP** που τα χρησιμοποιεί.

### Εύρεση ύποπτων domains

Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε οποιοδήποτε από τα παρακάτω εργαλεία. Σημειώστε ότι αυτά τα εργαλεία θα εκτελέσουν επίσης αυτόματα DNS requests για να ελέγξουν αν το domain έχει αντιστοιχισμένη IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Συμβουλή: Αν δημιουργήσετε μια λίστα υποψηφίων, τροφοδοτήστε την επίσης στα DNS resolver logs σας, ώστε να εντοπίζετε **NXDOMAIN lookups από το εσωτερικό του org** (χρήστες που προσπαθούν να μεταβούν σε ένα typo πριν το καταχωρίσει πράγματι ο attacker). Κάντε sinkhole ή προ-αποκλεισμό αυτών των domains, αν το επιτρέπει η policy.

### Bitflipping

**Μπορείτε να βρείτε μια σύντομη εξήγηση αυτής της technique στη γονική σελίδα. Ή να διαβάσετε την αρχική έρευνα στο** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup>

Για παράδειγμα, μια τροποποίηση 1 bit στο domain microsoft.com μπορεί να το μετατρέψει σε _windnws.com._\
**Οι attackers μπορεί να καταχωρίσουν όσο το δυνατόν περισσότερα bit-flipping domains που σχετίζονται με το θύμα, ώστε να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους**.<sup>[[1]](#references)</sup>

**Όλα τα πιθανά bit-flipping domain names θα πρέπει επίσης να παρακολουθούνται.**

Αν χρειάζεται επίσης να λάβετε υπόψη homoglyph/IDN lookalikes (π.χ. ανάμειξη χαρακτήρων Latin/Cyrillic), ελέγξτε:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Βασικοί έλεγχοι

Μόλις αποκτήσετε μια λίστα με πιθανά ύποπτα domain names, θα πρέπει να τα **ελέγξετε** (κυρίως τις θύρες HTTP και HTTPS), για να **δείτε αν χρησιμοποιούν κάποια φόρμα login παρόμοια** με εκείνη του domain του θύματος.\
Μπορείτε επίσης να ελέγξετε τη θύρα 3333, για να δείτε αν είναι ανοιχτή και εκτελεί ένα instance του `gophish`.\
Είναι επίσης ενδιαφέρον να γνωρίζετε **πόσο παλιό είναι κάθε ύποπτο domain που εντοπίστηκε**· όσο νεότερο είναι, τόσο μεγαλύτερος είναι ο κίνδυνος.\
Μπορείτε επίσης να λάβετε **screenshots** της ύποπτης ιστοσελίδας HTTP ή/και HTTPS, για να δείτε αν είναι ύποπτη και, σε αυτή την περίπτωση, να **αποκτήσετε πρόσβαση για να την εξετάσετε λεπτομερέστερα**.

### Προηγμένοι έλεγχοι

Αν θέλετε να προχωρήσετε ένα βήμα παραπέρα, θα σας συνιστούσα να **παρακολουθείτε αυτά τα ύποπτα domains και να αναζητάτε περισσότερα** ανά διαστήματα (κάθε μέρα; χρειάζονται μόνο λίγα δευτερόλεπτα/λεπτά). Θα πρέπει επίσης να **ελέγχετε** τις ανοιχτές **θύρες** των σχετικών IP και να **αναζητάτε instances του `gophish` ή παρόμοιων εργαλείων** (ναι, οι attackers κάνουν επίσης λάθη), καθώς και να **παρακολουθείτε τις ιστοσελίδες HTTP και HTTPS των ύποπτων domains και subdomains**, για να δείτε αν έχουν αντιγράψει κάποια φόρμα login από τις ιστοσελίδες του θύματος.\
Για να **αυτοματοποιήσετε αυτή τη διαδικασία**, θα σας συνιστούσα να έχετε μια λίστα με τις φόρμες login των domains του θύματος, να κάνετε spidering στις ύποπτες ιστοσελίδες και να συγκρίνετε κάθε φόρμα login που εντοπίζεται μέσα στα ύποπτα domains με κάθε φόρμα login του domain του θύματος, χρησιμοποιώντας κάτι όπως το `ssdeep`.\
Αν έχετε εντοπίσει τις φόρμες login των ύποπτων domains, μπορείτε να δοκιμάσετε να **στείλετε junk credentials** και να **ελέγξετε αν σας ανακατευθύνει στο domain του θύματος**.

---

### Hunting με favicon και web fingerprints (Shodan/ZoomEye/Censys)

Πολλά phishing kits επαναχρησιμοποιούν favicons από το brand που υποδύονται. Οι scanners που καλύπτουν ολόκληρο το Internet υπολογίζουν ένα MurmurHash3 του favicon που έχει κωδικοποιηθεί σε base64. Μπορείτε να δημιουργήσετε το hash και να κάνετε pivot σε αυτό:

Παράδειγμα Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query Shodan: `http.favicon.hash:309020573`
- Με tooling: εξετάστε community tools όπως το favfreak για τη δημιουργία hashes και dorks για Shodan/ZoomEye/Censys.

Σημειώσεις
- Τα favicons επαναχρησιμοποιούνται· αντιμετωπίστε τα matches ως ενδείξεις και επικυρώστε το περιεχόμενο και τα certs πριν ενεργήσετε.
- Συνδυάστε τα με heuristics για την ηλικία του domain και keywords για καλύτερη ακρίβεια.

### Hunting τηλεμετρίας URL (urlscan.io)

Το `urlscan.io` αποθηκεύει ιστορικά screenshots, DOM, requests και TLS metadata των URLs που υποβάλλονται. Μπορείτε να κάνετε hunting για κατάχρηση brand και clones:<sup>[[2]](#references)</sup>

Παραδείγματα queries (UI ή API):
- Εύρεση lookalikes με εξαίρεση των νόμιμων domains σας: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Εύρεση sites που κάνουν hotlinking στα assets σας: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Περιορισμός στα πρόσφατα αποτελέσματα: προσθέστε `AND date:>now-7d`

Παράδειγμα API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Από το JSON, κάντε pivot στα:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` για να εντοπίσετε πολύ νέα certificates σε lookalikes
- τιμές του `task.source`, όπως `certstream-suspicious`, για να συνδέσετε τα findings με το CT monitoring

### Ηλικία domain μέσω RDAP (scriptable)

Το RDAP επιστρέφει machine-readable events δημιουργίας. Χρήσιμο για τον εντοπισμό **newly registered domains (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Εμπλούτισε το pipeline σου προσθέτοντας tags στα domains με buckets ηλικίας καταχώρισης (π.χ. <7 ημέρες, <30 ημέρες) και δώσε αντίστοιχη προτεραιότητα στο triage.

### TLS/JAx fingerprints για τον εντοπισμό AiTM infrastructure

Το σύγχρονο credential-phishing χρησιμοποιεί ολοένα και περισσότερο **Adversary-in-the-Middle (AiTM)** reverse proxies (π.χ. Evilginx) για την κλοπή session tokens. Μπορείς να προσθέσεις detections από την πλευρά του δικτύου:

- Κατέγραψε TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) στο egress. Σε ορισμένα Evilginx builds έχουν παρατηρηθεί σταθερές τιμές JA4 client/server. Δημιούργησε alert μόνο για γνωστά κακόβουλα fingerprints, καθώς αποτελούν weak signal, και επιβεβαίωσέ τα πάντα με content και domain intel.<sup>[[3]](#references)</sup>
- Κατέγραψε προληπτικά metadata των TLS certificates (issuer, αριθμό SAN, χρήση wildcard, validity) για lookalike hosts που εντοπίζονται μέσω CT ή urlscan και συσχέτισέ τα με την ηλικία DNS και τη geolocation.

> Σημείωση: Αντιμετώπισε τα fingerprints ως enrichment και όχι ως sole blockers· τα frameworks εξελίσσονται και ενδέχεται να κάνουν randomise ή obfuscate τα fingerprints.

### Domain names που χρησιμοποιούν keywords

Η parent page αναφέρει επίσης μια τεχνική variation domain name, η οποία συνίσταται στην τοποθέτηση του **domain name του θύματος μέσα σε ένα μεγαλύτερο domain** (π.χ. paypal-financial.com για το paypal.com).

#### Certificate Transparency

Δεν είναι δυνατό να εφαρμοστεί η προηγούμενη προσέγγιση "Brute-Force", αλλά είναι στην πραγματικότητα **δυνατό να εντοπιστούν τέτοιες phishing attempts** χάρη και στο certificate transparency. Κάθε φορά που ένα certificate εκδίδεται από μια CA, τα στοιχεία του δημοσιοποιούνται. Αυτό σημαίνει ότι, διαβάζοντας ή ακόμη και παρακολουθώντας το certificate transparency, είναι **δυνατό να βρεθούν domains που χρησιμοποιούν ένα keyword στο όνομά τους**. Για παράδειγμα, αν ένας attacker δημιουργήσει ένα certificate για το [https://paypal-financial.com](https://paypal-financial.com), εξετάζοντας το certificate είναι δυνατό να βρεθεί το keyword "paypal" και να γίνει γνωστό ότι χρησιμοποιείται ύποπτο email.

Το post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) προτείνει τη χρήση του Censys για αναζήτηση certificates που αφορούν ένα συγκεκριμένο keyword και φιλτράρισμα βάσει ημερομηνίας (μόνο "νέα" certificates) και του CA issuer "Let's Encrypt":<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Ωστόσο, μπορείς να κάνεις "το ίδιο" χρησιμοποιώντας το δωρεάν web [**crt.sh**](https://crt.sh). Μπορείς να **αναζητήσεις το keyword** και να **φιλτράρεις** τα αποτελέσματα **βάσει ημερομηνίας και CA**, αν το επιθυμείς.

![Domain names using keywords - Certificate Transparency: Ωστόσο, μπορείς να κάνεις "το ίδιο" χρησιμοποιώντας το δωρεάν web crt.sh . Μπορείς να αναζητήσεις το keyword και να φιλτράρεις τα αποτελέσματα βάσει ημερομηνίας και...](<../../images/image (519).png>)

Χρησιμοποιώντας αυτή την τελευταία επιλογή, μπορείς ακόμη και να χρησιμοποιήσεις το πεδίο Matching Identities για να δεις αν κάποια identity από το πραγματικό domain αντιστοιχεί σε κάποιο από τα suspicious domains (σημείωσε ότι ένα suspicious domain μπορεί να είναι false positive).

**Μια ακόμη εναλλακτική** είναι το εξαιρετικό project που ονομάζεται [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). Το CertStream παρέχει ένα real-time stream από newly generated certificates, το οποίο μπορείς να χρησιμοποιήσεις για να ανιχνεύεις συγκεκριμένα keywords σε (σχεδόν) real-time. Στην πραγματικότητα, υπάρχει ένα project που ονομάζεται [**phishing_catcher**](https://github.com/x0rz/phishing_catcher), το οποίο κάνει ακριβώς αυτό.

Πρακτική συμβουλή: κατά το triaging των CT hits, δώσε προτεραιότητα σε NRDs, untrusted/unknown registrars, privacy-proxy WHOIS και certificates με πολύ πρόσφατους χρόνους `NotBefore`. Διατήρησε allowlist για τα domains/brands που σου ανήκουν, ώστε να μειώσεις τον θόρυβο.

#### **New domains**

**Μια τελευταία εναλλακτική** είναι να συγκεντρώσεις μια λίστα με **newly registered domains** για ορισμένα TLDs (το [Whoxy](https://www.whoxy.com/newly-registered-domains/) παρέχει αυτή την υπηρεσία) και να **ελέγξεις τα keywords σε αυτά τα domains**. Ωστόσο, τα μεγάλα domains συνήθως χρησιμοποιούν ένα ή περισσότερα subdomains· επομένως, το keyword δεν θα εμφανίζεται μέσα στο FLD και δεν θα μπορείς να βρεις το phishing subdomain.

Additional heuristic: αντιμετώπισε ορισμένα **file-extension TLDs** (π.χ. `.zip`, `.mov`) με αυξημένη καχυποψία κατά το alerting. Συχνά συγχέονται με filenames σε lures· συνδύασε το TLD signal με brand keywords και την ηλικία NRD για μεγαλύτερη ακρίβεια.

## References

- [1] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
