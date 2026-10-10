# Εντοπισμός phishing

{{#include ../../banners/hacktricks-training.md}}

## Εισαγωγή

Για να εντοπίσετε μια απόπειρα phishing, είναι σημαντικό να **κατανοήσετε τις τεχνικές phishing που χρησιμοποιούνται σήμερα**. Στη γονική σελίδα αυτής της ανάρτησης μπορείτε να βρείτε αυτές τις πληροφορίες. Επομένως, αν δεν γνωρίζετε ποιες τεχνικές χρησιμοποιούνται σήμερα, σας συνιστώ να επισκεφτείτε τη γονική σελίδα και να διαβάσετε τουλάχιστον αυτή την ενότητα.

Αυτή η ανάρτηση βασίζεται στην ιδέα ότι οι **επιτιθέμενοι θα προσπαθήσουν με κάποιον τρόπο να μιμηθούν ή να χρησιμοποιήσουν το όνομα domain του θύματος**. Αν το domain σας ονομάζεται `example.com` και πέσετε θύμα phishing μέσω ενός εντελώς διαφορετικού ονόματος domain, όπως το `youwonthelottery.com`, αυτές οι τεχνικές δεν πρόκειται να το εντοπίσουν.

## Παραλλαγές ονομάτων domain

Είναι σχετικά **εύκολο** να **εντοπίσετε** απόπειρες **phishing** που χρησιμοποιούν ένα **παρόμοιο όνομα domain** μέσα στο email.\
Αρκεί να **δημιουργήσετε μια λίστα με τα πιο πιθανά ονόματα phishing** που μπορεί να χρησιμοποιήσει ένας επιτιθέμενος και να **ελέγξετε** αν είναι **καταχωρισμένα** ή απλώς αν κάποια **IP** τα χρησιμοποιεί.

### Εντοπισμός ύποπτων domains

Για αυτόν τον σκοπό, μπορείτε να χρησιμοποιήσετε οποιοδήποτε από τα παρακάτω εργαλεία. Και τα δύο επιλύουν τα υποψήφια domains για να ελέγξουν αν χρησιμοποιούνται.<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Συμβουλή: Αν δημιουργήσετε μια λίστα υποψήφιων domains, τροφοδοτήστε τη και στα logs του DNS resolver σας, ώστε να εντοπίζετε **NXDOMAIN lookups από το εσωτερικό του οργανισμού σας** (χρήστες που προσπαθούν να επισκεφτούν ένα typo πριν το καταχωρίσει ο επιτιθέμενος). Κάντε sinkhole ή αποκλείστε προληπτικά αυτά τα domains, αν το επιτρέπει η πολιτική σας.

### Bitflipping

**Για μια σύντομη εξήγηση, δείτε τη γονική σελίδα· για πρωτογενή έρευνα σχετικά με το bitsquatting στο Windows.com, δείτε το [άρθρο του Remy Hax](https://remyhax.xyz/posts/bitsquatting-windows/) και την [αναφορά του BleepingComputer](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)**.<sup>[[1]](#references)[[2]](#references)</sup>

Για παράδειγμα, μια τροποποίηση 1 bit στο domain microsoft.com μπορεί να το μετατρέψει σε _windnws.com._\
**Οι επιτιθέμενοι μπορεί να καταχωρίσουν όσο το δυνατόν περισσότερα domains με bit-flipping που σχετίζονται με το θύμα, για να ανακατευθύνουν νόμιμους χρήστες στην υποδομή τους**.<sup>[[1]](#references)[[2]](#references)</sup>

**Θα πρέπει επίσης να παρακολουθούνται όλα τα πιθανά ονόματα domain με bit-flipping.**

Αν χρειάζεται να λάβετε υπόψη και ομογλυφικές/IDN απομιμήσεις (π.χ. ανάμειξη λατινικών και κυριλλικών χαρακτήρων), δείτε:

{{#ref}}
homograph-attacks.md
{{#endref}}

### Βασικοί έλεγχοι

Μόλις έχετε μια λίστα με πιθανά ύποπτα ονόματα domain, θα πρέπει να τα **ελέγξετε** (κυρίως τις θύρες HTTP και HTTPS), για να **δείτε αν χρησιμοποιούν κάποια φόρμα σύνδεσης παρόμοια με εκείνη κάποιου domain του θύματος**.\
Θα μπορούσατε επίσης να ελέγξετε αν η θύρα 3333 είναι ανοιχτή και εκτελεί μια παρουσία του `gophish`.\
Είναι επίσης χρήσιμο να γνωρίζετε **πόσο παλιό είναι κάθε ύποπτο domain που εντοπίστηκε**· όσο πιο πρόσφατο είναι, τόσο μεγαλύτερος είναι ο κίνδυνος.\
Μπορείτε επίσης να τραβήξετε **στιγμιότυπα οθόνης** των ύποπτων ιστοσελίδων HTTP ή/και HTTPS, για να δείτε αν φαίνονται ύποπτες και, αν ναι, να **τις επισκεφτείτε για να τις εξετάσετε πιο προσεκτικά**.

### Προηγμένοι έλεγχοι

Αν θέλετε να προχωρήσετε ένα βήμα παραπέρα, θα σας συνιστούσα να **παρακολουθείτε αυτά τα ύποπτα domains και να αναζητάτε περισσότερα** ανά τακτά διαστήματα (κάθε μέρα; χρειάζονται μόνο λίγα δευτερόλεπτα ή λεπτά). Θα πρέπει επίσης να **ελέγχετε** τις ανοιχτές **θύρες** των σχετικών IP και να **αναζητάτε παρουσίες του `gophish` ή παρόμοιων εργαλείων** (ναι, και οι επιτιθέμενοι κάνουν λάθη), καθώς και να **παρακολουθείτε τις ιστοσελίδες HTTP και HTTPS των ύποπτων domains και subdomains**, για να δείτε αν έχουν αντιγράψει κάποια φόρμα σύνδεσης από τις ιστοσελίδες του θύματος.\
Για να **αυτοματοποιήσετε αυτή τη διαδικασία**, θα σας συνιστούσα να διατηρείτε μια λίστα με τις φόρμες σύνδεσης των domains του θύματος, να κάνετε spider τις ύποπτες ιστοσελίδες και να συγκρίνετε κάθε φόρμα σύνδεσης που εντοπίζεται στα ύποπτα domains με κάθε φόρμα σύνδεσης του domain του θύματος, χρησιμοποιώντας κάτι όπως το `ssdeep`.\
Αν έχετε εντοπίσει τις φόρμες σύνδεσης των ύποπτων domains, μπορείτε να δοκιμάσετε να **στείλετε πλαστά διαπιστευτήρια** και να **ελέγξετε αν σας ανακατευθύνει στο domain του θύματος**.

---

### Αναζήτηση με favicon και web fingerprints (Shodan/Censys)

Πολλά phishing kits επαναχρησιμοποιούν favicons της επωνυμίας που υποδύονται. Το Shodan κατακερματίζει τα δεδομένα του favicon, αφού τα κωδικοποιήσει σε base64, χρησιμοποιώντας MurmurHash3, ενώ το Censys παρέχει τα δικά του πεδία κατακερματισμού favicon.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Μπορείτε να δημιουργήσετε ένα hash συμβατό με το Shodan και να αναζητήσετε σχετικά αποτελέσματα:

Παράδειγμα Python (mmh3):

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Ερώτημα στο Shodan: `http.favicon.hash:309020573`
- Με εργαλεία: εξετάστε εργαλεία της κοινότητας, όπως το favfreak, για τον υπολογισμό hashes και τη δημιουργία Shodan dorks.<sup>[[16]](#references)</sup>

Σημειώσεις
- Τα favicons χρησιμοποιούνται ξανά· αντιμετωπίστε τις αντιστοιχίες ως ενδείξεις και επαληθεύστε το περιεχόμενο και τα πιστοποιητικά πριν ενεργήσετε.
- Συνδυάστε τα με ευρετικές για την ηλικία του domain και τις λέξεις-κλειδιά, για καλύτερη ακρίβεια.

### Αναζήτηση τηλεμετρίας URL (urlscan.io)

Το `urlscan.io` αποθηκεύει ιστορικά στιγμιότυπα οθόνης, DOM, αιτήματα και μεταδεδομένα TLS των URL που έχουν υποβληθεί. Μπορείτε να αναζητήσετε κατάχρηση εμπορικών σημάτων και κλώνους:<sup>[[8]](#references)</sup>

Παραδείγματα ερωτημάτων (UI ή API):
- Εύρεση παρόμοιων domains, εξαιρώντας τα νόμιμα domains σας: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Εύρεση ιστοτόπων που χρησιμοποιούν hotlinking στα assets σας: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Περιορισμός στα πρόσφατα αποτελέσματα: προσθέστε `AND date:>now-7d`

Παράδειγμα API:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

Από το JSON, διερευνήστε βάσει των εξής:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` για να εντοπίσετε πολύ πρόσφατα πιστοποιητικά σε lookalikes
- τιμές του `task.source`, όπως `certstream-suspicious`, για να συσχετίσετε τα ευρήματα με την παρακολούθηση CT

### Ηλικία domain μέσω RDAP (με δυνατότητα χρήσης σε scripts)

Το RDAP επιστρέφει αναγνώσιμα από μηχανές συμβάντα καταχώρισης. Χρήσιμο για τον εντοπισμό **νεοκαταχωρισμένων domains (NRDs)**.<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

Εμπλουτίστε το pipeline σας προσθέτοντας ετικέτες στους τομείς με βάση ηλικιακές κατηγορίες καταχώρισης (π.χ. <7 ημέρες, <30 ημέρες) και ιεραρχήστε ανάλογα το triage.

### Αποτυπώματα TLS/JAx για τον εντοπισμό υποδομών AiTM

Το credential phishing μπορεί να χρησιμοποιεί reverse proxies **Adversary-in-the-Middle (AiTM)** (π.χ. Evilginx) για την κλοπή session tokens.<sup>[[11]](#references)</sup> Μπορείτε να προσθέσετε ανιχνεύσεις στην πλευρά του δικτύου:

- Καταγράφετε αποτυπώματα TLS/HTTP (JA3/JA4/JA4S/JA4H) στην εξερχόμενη κίνηση. Ορισμένες εκδόσεις του Evilginx έχουν παρατηρηθεί με σταθερές τιμές JA4 client/server. Ενεργοποιείτε ειδοποιήσεις μόνο για γνωστά κακόβουλα αποτυπώματα, ως ασθενές σήμα, και επιβεβαιώνετε πάντα με στοιχεία περιεχομένου και πληροφορίες για τους τομείς.<sup>[[12]](#references)</sup>
- Καταγράφετε προληπτικά μεταδεδομένα πιστοποιητικών TLS (εκδότης, αριθμός SAN, χρήση wildcard, περίοδος ισχύος) για παρόμοιους τομείς που εντοπίζονται μέσω CT ή urlscan και συσχετίστε τα με την ηλικία DNS και τη γεωγραφική τοποθεσία.

> Σημείωση: Αντιμετωπίζετε τα αποτυπώματα ως εμπλουτισμό δεδομένων, όχι ως μοναδικά μέσα αποκλεισμού· τα frameworks εξελίσσονται και μπορεί να τυχαιοποιούν ή να αποκρύπτουν τα αποτυπώματα.

### Ονόματα τομέων με λέξεις-κλειδιά

Η γονική σελίδα αναφέρει επίσης μια τεχνική παραλλαγής ονόματος τομέα, κατά την οποία το **όνομα τομέα του θύματος τοποθετείται μέσα σε έναν μεγαλύτερο τομέα** (π.χ. paypal-financial.com για το paypal.com).

#### Certificate Transparency

Τα αρχεία καταγραφής Certificate Transparency (CT) εκθέτουν τις ταυτότητες πιστοποιητικών, επομένως η αναζήτηση ονομάτων Subject ή SAN για λέξεις-κλειδιά επωνυμιών μπορεί να αποκαλύψει παρόμοιους τομείς (για παράδειγμα, ένα πιστοποιητικό για το `paypal-financial.com` εκθέτει τη λέξη-κλειδί `paypal`). Φιλτράρετε τα αποτελέσματα με βάση την ημερομηνία έκδοσης και την CA όπου αυτό είναι χρήσιμο και επαληθεύετε τα ευρήματα, καθώς οι αντιστοιχίες λέξεων-κλειδιών μπορεί να είναι false positives.<sup>[[13]](#references)</sup>

Η αρχική [έρευνα για τον εντοπισμό τομέων phishing](https://0xpatrik.com/phishing-domains/) του Patrik Hudak παρουσιάζει αυτήν τη ροή εργασίας στο Censys, συμπεριλαμβανομένων φίλτρων για την ημερομηνία και τον εκδότη του πιστοποιητικού, όπως το Let's Encrypt.<sup>[[13]](#references)</sup>

![Αποτελέσματα αναζήτησης πιστοποιητικών στο Censys για τον εντοπισμό παρόμοιων τομέων](<../../images/image (1115).png>)

Μπορείτε επίσης να χρησιμοποιήσετε τη δωρεάν υπηρεσία [**crt.sh**](https://crt.sh) για να αναζητήσετε μια λέξη-κλειδί και να φιλτράρετε τα αποτελέσματα με βάση την ημερομηνία και την CA.<sup>[[13]](#references)</sup>

![Αναζήτηση λέξης-κλειδιού στο crt.sh για ύποπτες ταυτότητες πιστοποιητικών](<../../images/image (519).png>)

Το πεδίο Matching Identities μπορεί να βοηθήσει στη σύγκριση ταυτοτήτων από τον πραγματικό τομέα με ύποπτους τομείς, αλλά αντιμετωπίζετε τις αντιστοιχίες ως ενδείξεις και όχι ως αποδείξεις.<sup>[[13]](#references)</sup>

Το [*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) μεταδίδει ενημερώσεις CT σχεδόν σε πραγματικό χρόνο, ενώ το [*phishing_catcher*](https://github.com/x0rz/phishing_catcher) καταναλώνει αυτήν τη ροή για να βαθμολογεί ύποπτα ονόματα πιστοποιητικών.<sup>[[14]](#references)[[15]](#references)</sup>

Πρακτική συμβουλή: κατά το triage ευρημάτων CT, δώστε προτεραιότητα σε NRDs, μη έμπιστους/άγνωστους καταχωρητές, WHOIS με proxy απορρήτου και πιστοποιητικά με πολύ πρόσφατες τιμές `NotBefore`. Διατηρείτε allowlist των τομέων/επωνυμιών που σας ανήκουν για να μειώσετε τον θόρυβο.

#### **Νέοι τομείς**

Μια δεύτερη επιλογή είναι η συλλογή πρόσφατα καταχωρημένων τομέων ανά TLD (για παράδειγμα, μέσω του [Whoxy](https://www.whoxy.com/newly-registered-domains/)) και το φιλτράρισμά τους με βάση λέξεις-κλειδιά επωνυμιών. Με αυτήν την προσέγγιση δεν εντοπίζεται phishing που φιλοξενείται σε subdomains όταν η λέξη-κλειδί απουσιάζει από τον καταχωρημένο τομέα.<sup>[[13]](#references)</sup>

Πρόσθετος ευρετικός κανόνας: αντιμετωπίζετε ορισμένα **TLD επεκτάσεων αρχείων** (π.χ. `.zip`, `.mov`) με αυξημένη υποψία κατά τη δημιουργία ειδοποιήσεων. Συχνά συγχέονται με ονόματα αρχείων σε παραπλανητικά μηνύματα· συνδυάστε το σήμα TLD με λέξεις-κλειδιά επωνυμιών και την ηλικία NRD για μεγαλύτερη ακρίβεια.

## References

- [1] [Remy Hax – Bitsquatting στο Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [Παραβίαση της κίνησης προς το windows.com της Microsoft με bitflipping](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Σε βάθος ανάλυση: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [Τεκμηρίωση mmh3](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Σύνολο δεδομένων ιδιοκτησιών ιστού πλατφορμών](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Αναφορά API αναζήτησης](https://urlscan.io/docs/search/)
- [9] [Βοήθεια για το Registration Data Access Protocol](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Απαντήσεις JSON για το Registration Data Access Protocol](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Τακτικές token: Πώς να αποτρέψετε, να εντοπίσετε και να αντιμετωπίσετε την κλοπή cloud token](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – Αποτυπώματα δικτύου JA4+](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Εντοπισμός phishing: Εργαλεία και τεχνικές](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – Παρουσίαση του CertStream](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
