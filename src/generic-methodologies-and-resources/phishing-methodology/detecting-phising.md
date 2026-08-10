# Εντοπισμός Phishing

## Εισαγωγή

Για να εντοπίσετε μια απόπειρα phishing, είναι σημαντικό να **κατανοείτε τις τεχνικές phishing που χρησιμοποιούνται σήμερα**. Στη γονική σελίδα αυτής της ανάρτησης μπορείτε να βρείτε αυτές τις πληροφορίες, επομένως, αν δεν γνωρίζετε ποιες τεχνικές χρησιμοποιούνται σήμερα, σας συνιστώ να μεταβείτε στη γονική σελίδα και να διαβάσετε τουλάχιστον αυτή την ενότητα.

Αυτή η ανάρτηση βασίζεται στην ιδέα ότι οι **attackers θα προσπαθήσουν με κάποιον τρόπο να μιμηθούν ή να χρησιμοποιήσουν το domain name του θύματος**. Αν το domain σας ονομάζεται `example.com` και πέσετε θύμα phishing με τη χρήση ενός εντελώς διαφορετικού domain name, για κάποιον λόγο όπως το `youwonthelottery.com`, αυτές οι τεχνικές δεν πρόκειται να το εντοπίσουν.

## Παραλλαγές domain name

Είναι σχετικά **εύκολο** να **εντοπίσετε** εκείνες τις απόπειρες **phishing** που θα χρησιμοποιήσουν ένα **παρόμοιο domain** name μέσα στο email.\
Αρκεί να **δημιουργήσετε μια λίστα με τα πιο πιθανά ονόματα phishing** που μπορεί να χρησιμοποιήσει ένας attacker και να **ελέγξετε** αν είναι **καταχωρισμένα** ή απλώς να ελέγξετε αν υπάρχει κάποιο **IP** που τα χρησιμοποιεί.

### Εύρεση ύποπτων domains

Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε οποιοδήποτε από τα παρακάτω εργαλεία. Και τα δύο κάνουν resolve τα candidate domains για να ελέγξουν αν χρησιμοποιούνται.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Συμβουλή: Αν δημιουργήσετε μια λίστα υποψηφίων, τροφοδοτήστε την επίσης στα DNS resolver logs σας για να εντοπίσετε **NXDOMAIN lookups από το εσωτερικό του οργανισμού σας** (χρήστες που προσπαθούν να访问σουν ένα typo πριν το καταχωρίσει πραγματικά ο attacker). Κάντε sinkhole ή προ-αποκλεισμό αυτών των domains, αν το επιτρέπει η policy.

### Bitflipping

**Για μια σύντομη εξήγηση, δείτε τη γονική σελίδα· για την κύρια έρευνα σχετικά με το bitsquatting στο Windows.com, δείτε το [write-up του Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) και την [αναφορά του BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Για παράδειγμα, μια τροποποίηση 1 bit στο domain microsoft.com μπορεί να το μετατρέψει σε _windnws.com._\
**Οι attackers μπορεί να καταχωρίσουν όσο το δυνατόν περισσότερα bit-flipping domains που σχετίζονται με το θύμα, ώστε να ανακατευθύνουν νόμιμους χρήστες στη δική τους υποδομή**.<sup>[[1]](#references)[[2]](#references)</sup>

**Πρέπει επίσης να παρακολουθούνται όλα τα πιθανά bit-flipping domain names.**

Αν χρειάζεται επίσης να λάβετε υπόψη homoglyph/IDN lookalikes (π.χ. ανάμειξη χαρακτήρων Latin/Cyrillic), ελέγξτε:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Βασικοί έλεγχοι

Μόλις έχετε μια λίστα με πιθανά ύποπτα domain names, θα πρέπει να τα **ελέγξετε** (κυρίως τις θύρες HTTP και HTTPS), για να **διαπιστώσετε αν χρησιμοποιούν κάποια login form παρόμοια** με κάποια του domain του θύματος.\
Θα μπορούσατε επίσης να ελέγξετε τη θύρα 3333, για να δείτε αν είναι ανοιχτή και εκτελεί ένα instance του `gophish`.\
Είναι επίσης ενδιαφέρον να γνωρίζετε **πόσο παλιό είναι κάθε ύποπτο domain που εντοπίστηκε**· όσο νεότερο είναι, τόσο μεγαλύτερος είναι ο κίνδυνος.\
Μπορείτε επίσης να λάβετε **screenshots** της ύποπτης HTTP και/ή HTTPS web page, για να δείτε αν είναι ύποπτη και, σε αυτή την περίπτωση, να **αποκτήσετε πρόσβαση για να την εξετάσετε πιο διεξοδικά**.

### Προηγμένοι έλεγχοι

Αν θέλετε να προχωρήσετε ένα βήμα παραπέρα, θα σας συνιστούσα να **παρακολουθείτε αυτά τα ύποπτα domains και να αναζητάτε περισσότερα** ανά διαστήματα (κάθε μέρα; χρειάζονται μόνο λίγα δευτερόλεπτα/λεπτά). Θα πρέπει επίσης να **ελέγχετε** τις ανοιχτές **θύρες** των σχετικών IP και να **αναζητάτε instances του `gophish` ή παρόμοιων εργαλείων** (ναι, οι attackers κάνουν επίσης λάθη) και να **παρακολουθείτε τις HTTP και HTTPS web pages των ύποπτων domains και subdomains**, για να δείτε αν έχουν αντιγράψει κάποια login form από τις web pages του θύματος.\
Για να **αυτοματοποιήσετε αυτό**, θα σας συνιστούσα να έχετε μια λίστα με τις login forms των domains του θύματος, να κάνετε spider τις ύποπτες web pages και να συγκρίνετε κάθε login form που εντοπίζεται μέσα στα ύποπτα domains με κάθε login form του domain του θύματος, χρησιμοποιώντας κάτι όπως το `ssdeep`.\
Αν έχετε εντοπίσει τις login forms των ύποπτων domains, μπορείτε να δοκιμάσετε να **στείλετε junk credentials** και να **ελέγξετε αν σας ανακατευθύνει στο domain του θύματος**.

---

### Hunting μέσω favicon και web fingerprints (Shodan/Censys)

Πολλά phishing kits επαναχρησιμοποιούν favicons από το brand που υποδύονται. Το Shodan κατακερματίζει τα base64-encoded δεδομένα favicon με MurmurHash3, ενώ το Censys εκθέτει τα δικά του πεδία favicon hash.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Μπορείτε να δημιουργήσετε ένα συμβατό με το Shodan hash και να κάνετε pivot σε αυτό:

Παράδειγμα Python (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Query στο Shodan: `http.favicon.hash:309020573`
- Με tooling: εξετάστε community tools όπως το favfreak για τον υπολογισμό hashes και τη δημιουργία Shodan dorks.<sup>[[16]](#references)</sup>

Σημειώσεις
- Τα favicons επαναχρησιμοποιούνται· αντιμετωπίζετε τα matches ως ενδείξεις και επικυρώνετε το περιεχόμενο και τα certificates πριν ενεργήσετε.
- Συνδυάστε τα με heuristics για την ηλικία του domain και keywords για μεγαλύτερη ακρίβεια.

### Κυνήγι URL telemetry (urlscan.io)

Το `urlscan.io` αποθηκεύει ιστορικά screenshots, DOM, requests και TLS metadata των URL που υποβάλλονται. Μπορείτε να αναζητήσετε κατάχρηση brand και clones:<sup>[[8]](#references)</sup>

Παραδείγματα queries (UI ή API):
- Εύρεση lookalikes εξαιρώντας τα νόμιμα domains σας: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
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
- Τιμές `task.source` όπως `certstream-suspicious` για να συσχετίσετε τα ευρήματα με το CT monitoring

### Ηλικία domain μέσω RDAP (scriptable)

Το RDAP επιστρέφει machine-readable registration events. Είναι χρήσιμο για τον εντοπισμό **newly registered domains (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Εμπλουτίστε το pipeline σας προσθέτοντας ετικέτες στα domains με buckets ηλικίας registration (π.χ. <7 ημέρες, <30 ημέρες) και ιεραρχήστε ανάλογα το triage.

### TLS/JAx fingerprints για τον εντοπισμό AiTM infrastructure

Το phishing διαπιστευτηρίων μπορεί να χρησιμοποιεί reverse proxies **Adversary-in-the-Middle (AiTM)** (π.χ. Evilginx) για την κλοπή session tokens.<sup>[[11]](#references)</sup> Μπορείτε να προσθέσετε detections από την πλευρά του δικτύου:

- Καταγράφετε TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) στο egress. Ορισμένα Evilginx builds έχουν παρατηρηθεί με σταθερές τιμές JA4 client/server. Δημιουργείτε alert μόνο για γνωστά κακόβουλα fingerprints ως ασθενές σήμα και επιβεβαιώνετε πάντα με content και domain intel.<sup>[[12]](#references)</sup>
- Καταγράφετε προληπτικά metadata των TLS certificates (issuer, αριθμό SAN, χρήση wildcard, validity) για lookalike hosts που εντοπίζονται μέσω CT ή urlscan και συσχετίστε τα με την ηλικία DNS και τη geolocation.

> Σημείωση: Αντιμετωπίζετε τα fingerprints ως enrichment και όχι ως μοναδικά blockers· τα frameworks εξελίσσονται και ενδέχεται να κάνουν randomise ή obfuscate τα fingerprints.

### Domain names που χρησιμοποιούν keywords

Η parent page αναφέρει επίσης μια τεχνική variation ονόματος domain, η οποία συνίσταται στην τοποθέτηση του **ονόματος domain του θύματος μέσα σε ένα μεγαλύτερο domain** (π.χ. paypal-financial.com για το paypal.com).

#### Certificate Transparency

Τα logs του Certificate Transparency (CT) εκθέτουν τις ταυτότητες των certificates, επομένως η αναζήτηση των Subject ή SAN names για brand keywords μπορεί να αποκαλύψει lookalike domains (για παράδειγμα, ένα certificate για το `paypal-financial.com` εκθέτει το keyword `paypal`). Φιλτράρετε τα αποτελέσματα με βάση την ημερομηνία έκδοσης και το CA όταν είναι χρήσιμο και επικυρώνετε τους candidates, επειδή τα keyword matches μπορεί να είναι false positives.<sup>[[13]](#references)</sup>

Το αρχικό [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) του Patrik Hudak παρουσιάζει αυτό το workflow στο Censys, συμπεριλαμβανομένων filters για την ημερομηνία και τον issuer του certificate, όπως το Let's Encrypt.<sup>[[13]](#references)</sup>

Μπορείτε επίσης να χρησιμοποιήσετε τη δωρεάν υπηρεσία [**crt.sh**](https://crt.sh) για αναζήτηση ενός keyword και φιλτράρισμα των αποτελεσμάτων με βάση την ημερομηνία και το CA.<sup>[[13]](#references)</sup>

Το πεδίο Matching Identities μπορεί να βοηθήσει στη σύγκριση identities από το πραγματικό domain με suspicious domains, αλλά αντιμετωπίζετε τα matches ως leads και όχι ως απόδειξη.<sup>[[13]](#references)</sup>

Το [*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) μεταδίδει CT updates σχεδόν σε πραγματικό χρόνο και το [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) καταναλώνει αυτό το stream για να βαθμολογεί suspicious certificate names.<sup>[[14]](#references)[[15]](#references)</sup>

Πρακτική συμβουλή: κατά το triage των CT hits, δώστε προτεραιότητα σε NRDs, untrusted/unknown registrars, privacy-proxy WHOIS και certificates με πολύ πρόσφατες τιμές `NotBefore`. Διατηρείτε allowlist των domains/brands που σας ανήκουν για να μειώσετε τον θόρυβο.

#### **New domains**

Μια δεύτερη επιλογή είναι η συλλογή newly registered domains ανά TLD (για παράδειγμα, μέσω του [Whoxy](https://www.whoxy.com/newly-registered-domains/)) και το φιλτράρισμα για brand keywords. Αυτό δεν εντοπίζει phishing που φιλοξενείται σε subdomains όταν το keyword απουσιάζει από το registered domain.<sup>[[13]](#references)</sup>

Πρόσθετο heuristic: αντιμετωπίζετε ορισμένα **file-extension TLDs** (π.χ. `.zip`, `.mov`) με αυξημένη καχυποψία κατά το alerting. Συχνά συγχέονται με filenames σε lures· συνδυάστε το TLD signal με brand keywords και την ηλικία του NRD για καλύτερη ακρίβεια.

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Hijacking traffic to Microsoft's windows.com with bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: JSON Responses for the Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: How to prevent, detect, and respond to cloud token theft](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Introducing CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
