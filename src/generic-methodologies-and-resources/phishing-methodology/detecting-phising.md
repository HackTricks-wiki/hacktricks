# Εντοπισμός Phishing

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Για να εντοπίσετε μια προσπάθεια phishing είναι σημαντικό να **κατανοείτε τις τεχνικές phishing που χρησιμοποιούνται σήμερα**. Στην γονική σελίδα αυτού του άρθρου μπορείτε να βρείτε αυτές τις πληροφορίες, οπότε αν δεν είστε εξοικειωμένοι με το ποιες τεχνικές χρησιμοποιούνται σήμερα, σας προτείνω να μεταβείτε στη γονική σελίδα και να διαβάσετε τουλάχιστον εκείνη την ενότητα.

Αυτό το άρθρο βασίζεται στην ιδέα ότι οι **επιτιθέμενοι θα προσπαθήσουν με κάποιον τρόπο να μιμηθούν ή να χρησιμοποιήσουν το domain του θύματος**. Αν το domain σας ονομάζεται `example.com` και σας κάνει phishing χρησιμοποιώντας εντελώς διαφορετικό domain για κάποιο λόγο όπως `youwonthelottery.com`, αυτές οι τεχνικές δεν πρόκειται να το αποκαλύψουν.

## Παραλλαγές ονομάτων domain

Είναι κάπως **εύκολο** να **αποκαλύψετε** αυτές τις **phishing** προσπάθειες που θα χρησιμοποιήσουν ένα **παρόμοιο domain** μέσα στο email.\
Αρκεί να **δημιουργήσετε μια λίστα με τα πιο πιθανά phishing ονόματα** που μπορεί να χρησιμοποιήσει ένας επιτιθέμενος και να **ελέγξετε** αν είναι **καταχωρημένα** ή απλώς να ελέγξετε αν υπάρχει κάποια **IP** που τα χρησιμοποιεί.

### Εύρεση ύποπτων domains

Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε οποιοδήποτε από τα παρακάτω εργαλεία. Σημειώστε ότι αυτά τα εργαλεία θα πραγματοποιήσουν και αυτόματα αιτήσεις DNS για να ελέγξουν αν το domain έχει κάποια IP αντιστοιχισμένη σε αυτό:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: Εάν δημιουργήσετε μια λίστα υποψήφιων, τροφοδοτήστε την επίσης στα DNS resolver logs σας για να εντοπίσετε **NXDOMAIN lookups from inside your org** (χρήστες που προσπαθούν να φτάσουν ένα typo πριν ο επιτιθέμενος το καταχωρήσει πραγματικά). Sinkhole ή pre-block αυτά τα domains αν το policy το επιτρέπει.

### Bitflipping

**Μπορείτε να βρείτε μια σύντομη εξήγηση αυτής της τεχνικής στη γονική σελίδα. Ή διαβάστε την αρχική έρευνα στο** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Για παράδειγμα, μια 1 bit τροποποίηση στο domain microsoft.com μπορεί να το μετατρέψει σε _windnws.com._\
**Οι επιτιθέμενοι μπορεί να καταχωρήσουν όσο το δυνατόν περισσότερα bit-flipping domains σχετικά με το θύμα για να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους**.

**Όλα τα πιθανά bit-flipping ονόματα domain θα πρέπει επίσης να παρακολουθούνται.**

Αν χρειάζεται επίσης να λάβετε υπόψη homoglyph/IDN lookalikes (π.χ., ανάμειξη Latin/Cyrillic χαρακτήρων), ελέγξτε:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Βασικοί έλεγχοι

Μόλις έχετε μια λίστα πιθανών ύποπτων ονομάτων domain θα πρέπει να **τα ελέγξετε** (κυρίως τις θύρες HTTP και HTTPS) για να **δείτε αν χρησιμοποιούν κάποια φόρμα login που μοιάζει** με κάποια από τα domains του θύματος.\
Μπορείτε επίσης να ελέγξετε τη θύρα 3333 για να δείτε αν είναι ανοιχτή και τρέχει μια instance του `gophish`.\
Είναι επίσης ενδιαφέρον να γνωρίζετε **πόσο παλιά είναι κάθε εντοπισμένο ύποπτο domain**, όσο πιο νέο είναι τόσο πιο επικίνδυνο.\
Μπορείτε επίσης να πάρετε **screenshots** της ύποπτης σελίδας HTTP και/ή HTTPS για να δείτε αν είναι ύποπτη και σε αυτήν την περίπτωση **να την επισκεφθείτε για να την διερευνήσετε βαθύτερα**.

### Προχωρημένοι έλεγχοι

Αν θέλετε να πάτε ένα βήμα παραπέρα θα σας πρότεινα να **παρακολουθείτε αυτά τα ύποπτα domains και να ψάχνετε για περισσότερα** περιοδικά (κάθε μέρα; παίρνει μόνο λίγα δευτερόλεπτα/λεπτά). Θα πρέπει επίσης να **ελέγχετε** τις ανοιχτές **θύρες** των σχετικών IPs και να **αναζητάτε instances του `gophish` ή παρόμοιων εργαλείων** (ναι, οι επιτιθέμενοι κάνουν κι αυτοί λάθη) και να **παρακολουθείτε τις HTTP και HTTPS σελίδες των ύποπτων domains και subdomains** για να δείτε αν έχουν αντιγράψει κάποια φόρμα login από τις σελίδες του θύματος.\
Για να **αυτοματοποιήσετε αυτό** θα πρότεινα να έχετε μια λίστα με τις φόρμες login των domains του θύματος, να spiderάρετε τις ύποπτες σελίδες και να συγκρίνετε κάθε φόρμα login που βρέθηκε μέσα στα ύποπτα domains με κάθε φόρμα login του domain του θύματος χρησιμοποιώντας κάτι σαν `ssdeep`.\
Αν έχετε εντοπίσει τις φόρμες login των ύποπτων domains, μπορείτε να δοκιμάσετε να **στείλετε junk credentials** και να **ελέγξετε αν σας ανακατευθύνει στο domain του θύματος**.

---

### Κυνήγι με βάση το favicon και web fingerprints (Shodan/ZoomEye/Censys)

Πολλά phishing kits επαναχρησιμοποιούν favicons από το brand που μιμούνται. Οι σαρωτές στο διαδίκτυο υπολογίζουν ένα MurmurHash3 του base64-encoded favicon. Μπορείτε να δημιουργήσετε το hash και να κάνετε pivot πάνω του:

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Αναζήτηση στο Shodan: `http.favicon.hash:309020573`
- Με εργαλεία: κοιτάξτε community tools όπως favfreak για να δημιουργήσετε hashes και dorks για Shodan/ZoomEye/Censys.

Σημειώσεις
- Τα Favicons επαναχρησιμοποιούνται· θεωρήστε τα matches ως leads και επαληθεύστε το content και τα certs πριν ενεργήσετε.
- Συνδυάστε με domain-age και keyword heuristics για μεγαλύτερη ακρίβεια.

### Αναζήτηση τηλεμετρίας URL (urlscan.io)

`urlscan.io` αποθηκεύει ιστορικά screenshots, DOM, requests και TLS metadata των υποβληθέντων URLs. Μπορείτε να αναζητήσετε brand abuse και clones:

Παραδείγματα queries (UI ή API):
- Βρείτε lookalikes εξαιρώντας τα legit domains σας: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Βρείτε sites που κάνουν hotlinking των assets σας: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Περιορίστε σε πρόσφατα αποτελέσματα: προσθέστε `AND date:>now-7d`

Παράδειγμα API:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
Από το JSON, επικεντρωθείτε σε:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` για να εντοπίζετε πολύ νέα πιστοποιητικά για παραπλανητικά domains
- `task.source` τιμές όπως `certstream-suspicious` για να συνδέετε ευρήματα με CT monitoring

### Ηλικία domain μέσω RDAP (scriptable)

RDAP επιστρέφει μηχανικά αναγνώσιμα γεγονότα δημιουργίας. Χρήσιμο για την επισήμανση **πρόσφατα καταχωρημένων domains (NRDs)**.
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Εμπλουτίστε το pipeline σας επισημαίνοντας domains με buckets ηλικίας εγγραφής (π.χ., <7 days, <30 days) και δώστε προτεραιότητα στη triage ανάλογα.

### TLS/JAx fingerprints to spot AiTM infrastructure

Το σύγχρονο credential-phishing αξιοποιεί όλο και περισσότερο **Adversary-in-the-Middle (AiTM)** reverse proxies (π.χ., Evilginx) για να κλέψει διακριτικά συνεδρίας. Μπορείτε να προσθέσετε ανιχνεύσεις από το δίκτυο:

- Καταγράψτε TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) στο egress. Σε κάποιες builds του Evilginx έχουν παρατηρηθεί σταθερές τιμές JA4 client/server. Δημιουργείτε alerts για γνωστά-κακά fingerprints μόνο ως αδύναμο σήμα και επιβεβαιώστε πάντα με content και domain intel.
- Εγγραφάτε προδραστικά TLS certificate metadata (issuer, SAN count, wildcard use, validity) για lookalike hosts που εντοπίζονται μέσω CT ή urlscan και συσχετίστε με DNS age και geolocation.

> Σημείωση: Αντιμετωπίστε τα fingerprints ως enrichment, όχι ως αποκλειστικούς blockers· τα frameworks εξελίσσονται και μπορεί να randomise ή να obfuscate.

### Domain names using keywords

Η κύρια σελίδα αναφέρει επίσης μια τεχνική παραλλαγής domain που συνίσταται στο να βάλεις το όνομα domain του θύματος μέσα σε ένα μεγαλύτερο domain (π.χ. paypal-financial.com για paypal.com).

#### Certificate Transparency

Δεν είναι δυνατό να ακολουθήσετε την προηγούμενη «Brute-Force» προσέγγιση, αλλά είναι πράγματι **εφικτό να αποκαλύψετε τέτοιες απόπειρες phishing** χάρη στην Certificate Transparency. Κάθε φορά που μια CA εκδίδει ένα certificate, οι λεπτομέρειες γίνονται δημόσιες. Αυτό σημαίνει ότι διαβάζοντας το Certificate Transparency ή παρακολουθώντας το, είναι **εφικτό να βρείτε domains που χρησιμοποιούν μια keyword μέσα στο όνομά τους**. Για παράδειγμα, αν ένας επιτιθέμενος δημιουργήσει ένα certificate για το https://paypal-financial.com, βλέποντας το certificate μπορείτε να εντοπίσετε την keyword "paypal" και να γνωρίζετε ότι χρησιμοποιείται ύποπτο email.

Το post https://0xpatrik.com/phishing-domains/ προτείνει ότι μπορείτε να χρησιμοποιήσετε Censys για να αναζητήσετε certificates που αφορούν μια συγκεκριμένη keyword και να φιλτράρετε κατά ημερομηνία (μόνο "new" certificates) και κατά CA issuer "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Ωστόσο, μπορείτε να κάνετε "το ίδιο" χρησιμοποιώντας την δωρεάν web υπηρεσία crt.sh. Μπορείτε να **αναζητήσετε την keyword** και να **φιλτράρετε** τα αποτελέσματα **κατά ημερομηνία και CA** αν το επιθυμείτε.

![](<../../images/image (519).png>)

Χρησιμοποιώντας αυτή την τελευταία επιλογή μπορείτε ακόμη να χρησιμοποιήσετε το πεδίο Matching Identities για να δείτε αν κάποια identity από το πραγματικό domain ταιριάζει με κάποιο από τα suspicious domains (σημειώστε ότι ένα suspicious domain μπορεί να είναι false positive).

**Another alternative** είναι το εξαιρετικό project CertStream. Το CertStream παρέχει ένα real-time stream από νεογεννηθέντα certificates το οποίο μπορείτε να χρησιμοποιήσετε για να εντοπίσετε καθορισμένες keywords σε (near) real-time. Στην πραγματικότητα υπάρχει ένα project που λέγεται phishing_catcher που κάνει ακριβώς αυτό.

Πρακτική συμβουλή: όταν κάνετε triaging σε CT hits, δώστε προτεραιότητα σε NRDs, untrusted/unknown registrars, privacy-proxy WHOIS, και certs με πολύ πρόσφατους χρόνους `NotBefore`. Διατηρήστε μια allowlist των κατεχόμενων domains/brands σας για να μειώσετε τον θόρυβο.

#### **New domains**

**Μια τελευταία εναλλακτική** είναι να συλλέξετε μια λίστα από newly registered domains για κάποια TLDs (Whoxy παρέχει τέτοια υπηρεσία) και να ελέγξετε τις keywords μέσα σε αυτά τα domains. Ωστόσο, τα μακρά domains συνήθως χρησιμοποιούν ένα ή περισσότερα subdomains, οπότε η keyword δεν θα εμφανιστεί μέσα στο FLD και δεν θα μπορείτε να βρείτε το phishing subdomain.

Επιπλέον heuristic: θεωρήστε ορισμένα file-extension TLDs (π.χ., .zip, .mov) με πρόσθετη υποψία κατά τη δημιουργία alerts. Συχνά συγχέονται με ονόματα αρχείων σε lures· συνδυάστε το TLD signal με brand keywords και NRD age για καλύτερη ακρίβεια.

## References

- urlscan.io – Αναφορά Search API: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
